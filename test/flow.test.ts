import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { openStore } from '../src/store.ts';
import { memoryAccountAdmin, syncPool } from '../src/leases.ts';
import { createGateway } from '../src/server.ts';
import { createShim } from '../src/shim.ts';
import { digest } from '../src/pop.ts';
import { softAuthenticator } from './authenticator.ts';

test('T2 + T4 end to end: only passkey-approved changes take effect, and each token surfaces exactly once', async (t) => {
  const db = openStore();
  syncPool(db, ['ags_ledger_ro_01', 'ags_ledger_ro_02'], Date.now());
  const rp = { rpID: 'localhost', rpName: 'test', origin: '' };
  const accounts = memoryAccountAdmin();
  const server = createGateway({ db, rp, enrollCodeHash: digest('enroll-code'), accounts });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  rp.origin = base;

  // Record every HTTP response body and everything written through console, to search them for tokens afterwards.
  const seen: { url: string; body: string }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const res = await realFetch(input, init);
    seen.push({ url: input instanceof Request ? input.url : String(input), body: await res.clone().text() });
    return res;
  }) as typeof fetch;
  const logged: string[] = [];
  const methods = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const originals = methods.map((m) => console[m]);
  for (const m of methods) console[m] = (...args: unknown[]) => void logged.push(args.map(String).join(' '));

  const shim = createShim(base, { MCP_SESSION_NAME: 'fixture session', CLAUDE_CODE_SESSION_ID: 'fixture-session-1' });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await shim.connect(serverSide);
  const client = new Client({ name: 'claude-code', version: '0.0.0' });
  await client.connect(clientSide);

  t.after(async () => {
    globalThis.fetch = realFetch;
    methods.forEach((m, i) => (console[m] = originals[i]));
    await client.close();
    server.close();
  });

  const outputs: string[] = [];
  async function tool(name: string, args: Record<string, unknown>) {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as { type: string; text: string }[])[0].text;
    outputs.push(text);
    return { isError: r.isError === true, text };
  }

  const authr = softAuthenticator('localhost', () => rp.origin);
  // Trusted fixture: the admin passkey is seeded directly instead of going through enrollment.
  db.prepare('INSERT INTO admin_credentials (id, public_key, counter, transports, created_at) VALUES (?, ?, 0, ?, ?)').run(
    authr.id,
    authr.cose,
    '[]',
    Date.now(),
  );

  type Reply = { status: number; body: Record<string, any>; cookie: string | null };
  async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Reply> {
    const res = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json(), cookie: res.headers.get('set-cookie') };
  }
  async function login(): Promise<string> {
    const start = await post('/admin/login/options', {});
    const done = await post('/admin/login/verify', { challengeId: start.body.challengeId, response: authr.assert(start.body.options.challenge) });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    return String(done.cookie).split(';')[0];
  }
  async function change(cookie: string, action: Record<string, unknown>, opts?: Parameters<typeof authr.assert>[1]) {
    const start = await post('/admin/action/options', action, { cookie });
    assert.equal(start.status, 200, JSON.stringify(start.body));
    const verify = { challengeId: start.body.challengeId, response: authr.assert(start.body.options.challenge, opts) };
    return { reply: await post('/admin/action/verify', verify), resend: () => post('/admin/action/verify', verify) };
  }
  const readA = { op: 'ledger.read_entries', project: 'p1', task: 't1' };
  const statusOf = async () => JSON.parse((await tool('gateway_status', {})).text);

  // T1 through the shim: registered as PENDING, nothing usable yet
  const reg = JSON.parse((await tool('gateway_status', { requestedScopes: [{ project: 'p1', task: 't1', mode: 'READ' }] })).text);
  assert.equal(reg.state, 'PENDING');
  assert.deepEqual(await tool('ledger_call', readA), { isError: true, text: 'refused: AUTHZ_NOT_ACTIVE' });

  // T2: nothing changes without a fresh, user-verified passkey assertion bound to the exact action
  const grant = { action: 'grant', registrationId: reg.id, expectedVersion: 0, scopes: [{ project: 'p1', task: 't1', mode: 'READ' }], expiresInMinutes: 60 };
  assert.equal((await post('/admin/action/options', grant)).body.error, 'AUTHN_NO_ADMIN_VIEW');
  const cookie = await login();
  const cookieOnly = await post('/admin/action/options', grant, { cookie });
  assert.equal((await post('/admin/action/verify', { challengeId: cookieOnly.body.challengeId })).body.error, 'AUTHN_UNKNOWN_CREDENTIAL');
  const late = { challengeId: cookieOnly.body.challengeId, response: authr.assert(cookieOnly.body.options.challenge) };
  assert.equal((await post('/admin/action/verify', late)).body.error, 'AUTHN_BAD_CHALLENGE');
  assert.equal((await change(cookie, grant, { uv: false })).reply.body.error, 'AUTHN_BAD_ASSERTION');
  assert.equal((await change(cookie, grant, { origin: 'http://elsewhere.invalid' })).reply.body.error, 'AUTHN_BAD_ASSERTION');
  assert.equal((await change(cookie, grant, { rpID: 'elsewhere.invalid' })).reply.body.error, 'AUTHN_BAD_ASSERTION');
  const revokeStart = await post('/admin/action/options', { action: 'revoke', registrationId: reg.id }, { cookie });
  const grantStart = await post('/admin/action/options', grant, { cookie });
  const crossed = { challengeId: grantStart.body.challengeId, response: authr.assert(revokeStart.body.options.challenge) };
  assert.equal((await post('/admin/action/verify', crossed)).body.error, 'AUTHN_BAD_ASSERTION');
  assert.equal((await change(cookie, { ...grant, scopes: [{ project: 'p1', task: 't1', mode: 'WRITE' }] })).reply.body.error, 'AUTHZ_HOST_UNVERIFIED');
  assert.equal((await statusOf()).state, 'PENDING');

  const approved = await change(cookie, grant);
  assert.equal(approved.reply.status, 200, JSON.stringify(approved.reply.body));
  assert.equal((await approved.resend()).body.error, 'AUTHN_BAD_CHALLENGE');
  assert.equal((await change(cookie, grant)).reply.body.error, 'CONFLICT_VERSION');
  assert.deepEqual([...accounts.loggedIn], ['ags_ledger_ro_01']);

  db.prepare("INSERT INTO synthetic_ledger (project, task, note, at) VALUES ('p1', 't1', 'hello', 0)").run();
  const first = await tool('ledger_call', readA);
  assert.equal(first.isError, false, first.text);
  assert.equal(JSON.parse(first.text)[0].note, 'hello');

  // change: UV=0 refused, then a real change voids the token and the shim quietly fetches a new one
  const changed = { ...grant, expectedVersion: 1, expiresInMinutes: 30 };
  assert.equal((await change(cookie, changed, { uv: false })).reply.body.error, 'AUTHN_BAD_ASSERTION');
  assert.equal((await change(cookie, changed)).reply.status, 200);
  assert.equal((await tool('ledger_call', readA)).isError, false);

  const page = await (await realFetch(base + '/admin', { headers: { cookie } })).text();
  for (const shown of ['fixture session', 'fixture-session-1', 'claude-code', '(unverified)', 'READ p1/t1', 'ags_ledger_ro_01']) {
    assert.ok(page.includes(shown), shown);
  }

  // revoke: UV=0 refused, then the real revoke stops the session and returns the account
  assert.equal((await change(cookie, { action: 'revoke', registrationId: reg.id }, { uv: false })).reply.body.error, 'AUTHN_BAD_ASSERTION');
  assert.equal((await change(cookie, { action: 'revoke', registrationId: reg.id })).reply.status, 200);
  assert.deepEqual(await tool('ledger_call', readA), { isError: true, text: 'refused: AUTHZ_NOT_ACTIVE' });
  assert.deepEqual([...accounts.loggedIn], []);

  // T4: each token appears in exactly one HTTP response (its own /agent/token reply) and nowhere else
  const tokens = seen
    .filter((s) => s.url.endsWith('/agent/token'))
    .map((s) => JSON.parse(s.body).token)
    .filter((token): token is string => typeof token === 'string');
  assert.equal(tokens.length, 2);
  assert.equal((await post('/admin/action/options', grant, { authorization: `Bearer ${tokens[1]}` })).body.error, 'AUTHN_NO_ADMIN_VIEW');
  const audit = JSON.stringify(db.prepare('SELECT * FROM audit').all());
  for (const token of tokens) {
    assert.equal(seen.filter((s) => s.body.includes(token)).length, 1);
    for (const text of [...outputs, page, audit, ...logged]) assert.ok(!text.includes(token));
  }
});

test.todo('T2b passkey enrollment opens only with the configured code and only while no admin exists');
