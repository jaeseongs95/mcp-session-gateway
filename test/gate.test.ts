import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto';
import { type Db, openStore } from '../src/store.ts';
import { authenticate, register, rename } from '../src/registry.ts';
import { type Scope, currentGrant, revoke, runUnderGrant, setGrant } from '../src/grants.ts';
import { type AccountAdmin, LEASE_STEP_MS, memoryAccountAdmin, restartLeases, settleLeases, syncPool } from '../src/leases.ts';
import { issueToken } from '../src/tokens.ts';
import { invoke, readOnly } from '../src/invoke.ts';
import { MAX_SKEW_MS, type PublicJwk, signProof } from '../src/pop.ts';

const T0 = 1_800_000_000_000;
const HOUR = 3_600_000;
const ADMIN = 'admin:fixture';
const READ_A: Scope = { project: 'p1', task: 't1', mode: 'READ' };
const WRITE_A: Scope = { ...READ_A, mode: 'WRITE' };

function store(path?: string, pool = ['ags_ledger_ro_01', 'ags_ledger_ro_02']): Db {
  const db = path ? openStore(path, 0) : openStore();
  syncPool(db, pool, T0);
  return db;
}

function proofFor(key: KeyObject, method: string, registrationId: string, generation: number, body: string, iat = T0) {
  return signProof(key, { method, registrationId, generation, requestId: randomUUID(), iat, nonce: randomUUID() }, body);
}

// Stands in for one host shim process: its own one-time key, signing every call.
function newShim(db: Db, labels = { displayName: 'session A', sessionLabel: 'local-1', hostClaim: 'claude-code' }) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as PublicJwk;
  const body = JSON.stringify({ ...labels, publicJwk });
  const reg = register(db, body, proofFor(privateKey, 'register', '', 0, body), T0);
  return { reg, privateKey, publicJwk };
}

const call = (db: Db, s: ReturnType<typeof newShim>, method = 'invoke', body = '{}') =>
  authenticate(db, proofFor(s.privateKey, method, s.reg.id, s.reg.generation, body), method, body, T0).reg;

const grantRead = (db: Db, id: string, expectedVersion = 0) =>
  setGrant(db, { registrationId: id, expectedVersion, scopes: [READ_A], expiresAt: T0 + HOUR }, ADMIN, T0);

// node:sqlite rows have a null prototype; copy them so deepStrictEqual compares plain objects.
const plain = (row: unknown) => (row === undefined ? undefined : { ...(row as object) });
const leaseOf = (db: Db, id: string) => plain(db.prepare('SELECT account, state FROM account_leases WHERE registration_id = ?').get(id));

// Trusted fixture writer, test boundary only (D1): the product never grants WRITE, so the race tests seed it directly.
function seedWriteGrant(db: Db, id: string) {
  db.prepare('INSERT INTO grants (registration_id, version, scopes, expires_at, approved_by, approved_at) VALUES (?, 1, ?, ?, ?, ?)').run(
    id,
    JSON.stringify([WRITE_A]),
    T0 + HOUR,
    ADMIN,
    T0,
  );
  db.prepare("UPDATE registrations SET state = 'ACTIVE' WHERE id = ?").run(id);
}

const ledgerWrite = (db: Db, note: string) => () => {
  db.prepare('INSERT INTO synthetic_ledger (project, task, note, at) VALUES (?, ?, ?, ?)').run('p1', 't1', note, T0);
  return note;
};
const ledgerNotes = (db: Db) => db.prepare('SELECT note FROM synthetic_ledger ORDER BY id').all().map((r) => r.note);

test('T1 a pending registration reaches only its own status', () => {
  const db = store();
  const a = newShim(db);
  const b = newShim(db);
  assert.equal(a.reg.state, 'PENDING');
  assert.equal(call(db, a, 'status').id, a.reg.id);
  assert.throws(() => runUnderGrant(db, call(db, a), READ_A, 'r1', T0, () => 'data'), { code: 'AUTHZ_NOT_ACTIVE' });
  assert.throws(() => issueToken(db, call(db, a, 'token'), T0), { code: 'AUTHZ_NOT_ACTIVE' });
  // a signs a call claiming to be b
  assert.throws(() => authenticate(db, proofFor(a.privateKey, 'status', b.reg.id, 1, '{}'), 'status', '{}', T0), {
    code: 'AUTHN_BAD_SIGNATURE',
  });
});

test('T3 names and host labels never grant anything', () => {
  const db = store();
  const a = newShim(db, { displayName: 'Project Lead', sessionLabel: 'someone-else', hostClaim: 'codex' });
  assert.throws(
    () => setGrant(db, { registrationId: a.reg.id, expectedVersion: 0, scopes: [WRITE_A], expiresAt: T0 + HOUR }, ADMIN, T0),
    { code: 'AUTHZ_HOST_UNVERIFIED' },
  );
  const v = grantRead(db, a.reg.id);
  rename(db, a.reg.id, 'renamed', ADMIN, T0);
  assert.equal(currentGrant(db, a.reg.id)?.version, v);
  assert.equal(runUnderGrant(db, call(db, a), READ_A, 'r1', T0, () => 'data'), 'data');
  const history = db.prepare("SELECT detail FROM audit WHERE action = 'rename' AND result = 'ok'").all();
  assert.deepEqual(history.map((r) => r.detail), ['renamed']);
  // bidi override and zero-width characters cannot be used to look like another session
  assert.throws(() => rename(db, a.reg.id, 'Lead‮esrever', ADMIN, T0), { code: 'INVALID_INPUT' });
  assert.throws(() => rename(db, a.reg.id, 'Le​ad', ADMIN, T0), { code: 'INVALID_INPUT' });
});

test('T5 a proof binds key, method, body, time, nonce and generation', () => {
  const db = store();
  const a = newShim(db);
  const b = newShim(db);
  const body = '{"q":1}';
  const p = proofFor(a.privateKey, 'invoke', a.reg.id, 1, body);
  assert.equal(authenticate(db, p, 'invoke', body, T0).claims.requestId.length > 0, true);
  const reject = (proof: unknown, code: string, method = 'invoke', sent = body) =>
    assert.throws(() => authenticate(db, proof, method, sent, T0), { code });
  reject(p, 'AUTHN_REPLAY');
  reject(proofFor(a.privateKey, 'invoke', a.reg.id, 1, body), 'AUTHN_BODY_MISMATCH', 'invoke', '{"q":2}');
  reject(proofFor(a.privateKey, 'invoke', a.reg.id, 1, body, T0 - MAX_SKEW_MS - 1), 'AUTHN_STALE');
  reject(proofFor(b.privateKey, 'invoke', a.reg.id, 1, body), 'AUTHN_BAD_SIGNATURE');
  reject(proofFor(a.privateKey, 'status', a.reg.id, 1, body), 'AUTHN_WRONG_METHOD');
  reject(proofFor(a.privateKey, 'invoke', a.reg.id, 2, body), 'AUTHN_STALE_GENERATION');
  reject({ payload: 'x', sig: 'y' }, 'AUTHN_BAD_PROOF');
  reject(proofFor(a.privateKey, 'invoke', randomUUID(), 1, body), 'AUTHN_UNKNOWN_REGISTRATION');
});

test('T5b a copied token is useless without the key of the registration it was issued to', () => {
  const db = store();
  const a = newShim(db);
  const b = newShim(db);
  grantRead(db, a.reg.id);
  grantRead(db, b.reg.id);
  const tokenA = issueToken(db, call(db, a, 'token'), T0);
  const body = JSON.stringify({ op: 'ledger.read_entries', project: 'p1', task: 't1' });
  assert.throws(() => invoke(db, call(db, b), 'r1', body, tokenA, T0), { code: 'AUTHN_BAD_TOKEN' });
  assert.throws(() => invoke(db, call(db, a), 'r2', body, undefined, T0), { code: 'AUTHN_BAD_TOKEN' });
  // a new token supersedes the old one
  issueToken(db, call(db, a, 'token'), T0);
  assert.throws(() => invoke(db, call(db, a), 'r3', body, tokenA, T0), { code: 'AUTHN_BAD_TOKEN' });
});

test('T5c one key cannot register twice under differently spelled encodings', () => {
  const db = store();
  const a = newShim(db);
  const padded = { ...a.publicJwk, x: `${a.publicJwk.x}=` };
  const body = JSON.stringify({ displayName: 'x', sessionLabel: 'y', hostClaim: 'z', publicJwk: padded });
  assert.throws(() => register(db, body, proofFor(a.privateKey, 'register', '', 0, body), T0), (err: { code?: string }) =>
    ['AUTHN_KEY_IN_USE', 'INVALID_INPUT'].includes(err.code ?? ''),
  );
});

test('T6 a READ grant covers only its own project and task, and never WRITE', () => {
  const db = store();
  const a = newShim(db);
  grantRead(db, a.reg.id);
  const reg = call(db, a);
  assert.equal(runUnderGrant(db, reg, READ_A, 'r1', T0, () => 'ok'), 'ok');
  for (const want of [WRITE_A, { ...READ_A, project: 'p2' }, { ...READ_A, task: 't2' }]) {
    assert.throws(() => runUnderGrant(db, reg, want, 'r2', T0, () => 'x'), { code: 'AUTHZ_SCOPE' });
  }
});

test('T7 expiry, revoke, a new key and a stale admin view never carry a grant over', () => {
  const db = store();
  const a = newShim(db);
  const v1 = grantRead(db, a.reg.id);
  assert.throws(() => grantRead(db, a.reg.id, 0), { code: 'CONFLICT_VERSION' });
  const reg = call(db, a);
  assert.throws(() => runUnderGrant(db, reg, READ_A, 'r1', T0 + HOUR, () => 'x'), { code: 'AUTHZ_EXPIRED' });
  revoke(db, a.reg.id, ADMIN, T0);
  assert.throws(() => runUnderGrant(db, reg, READ_A, 'r2', T0, () => 'x'), { code: 'AUTHZ_NOT_ACTIVE' });
  assert.throws(() => grantRead(db, a.reg.id, v1 + 1), { code: 'AUTHZ_REGISTRATION_CLOSED' });
  // the same session restarted = a new shim key = a new PENDING registration with nothing granted
  const a2 = newShim(db);
  assert.equal(a2.reg.state, 'PENDING');
  assert.equal(currentGrant(db, a2.reg.id), undefined);
  const body = JSON.stringify({ displayName: 'x', sessionLabel: 'y', hostClaim: 'z', publicJwk: a.publicJwk });
  assert.throws(() => register(db, body, proofFor(a.privateKey, 'register', '', 0, body), T0), { code: 'AUTHN_KEY_IN_USE' });
});

test('T8 commit order decides: write-then-revoke stays done, revoke-then-write is refused', () => {
  const db = store();
  const a = newShim(db);
  seedWriteGrant(db, a.reg.id);
  const reg = call(db, a);
  assert.equal(runUnderGrant(db, reg, WRITE_A, 'w1', T0, ledgerWrite(db, 'before')), 'before');
  assert.throws(
    () =>
      runUnderGrant(db, reg, WRITE_A, 'w2', T0, () => {
        ledgerWrite(db, 'partial')();
        throw new Error('backend failed');
      }),
    /backend failed/,
  );
  assert.throws(() => runUnderGrant(db, reg, WRITE_A, 'w3', T0, async () => 'x'), /synchronous/);
  assert.throws(() => runUnderGrant(db, reg, WRITE_A, 'w4', T0, () => Promise.resolve('x')), /synchronous/);
  revoke(db, a.reg.id, ADMIN, T0);
  assert.throws(() => runUnderGrant(db, reg, WRITE_A, 'w5', T0, ledgerWrite(db, 'after')), { code: 'AUTHZ_NOT_ACTIVE' });
  assert.deepEqual(ledgerNotes(db), ['before']);
});

test('T8b a revoke on another connection cannot slip between the grant check and the write', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gateway-'));
  try {
    const path = join(dir, 'gate.db');
    const db = store(path);
    const other = openStore(path, 0);
    const a = newShim(db);
    seedWriteGrant(db, a.reg.id);
    const reg = call(db, a);
    runUnderGrant(db, reg, WRITE_A, 'w1', T0, () => {
      ledgerWrite(db, 'inside')();
      assert.throws(() => revoke(other, a.reg.id, ADMIN, T0), /locked|busy/i);
      return 'done';
    });
    revoke(other, a.reg.id, ADMIN, T0);
    assert.throws(() => runUnderGrant(db, reg, WRITE_A, 'w2', T0, ledgerWrite(db, 'late')), { code: 'AUTHZ_NOT_ACTIVE' });
    assert.deepEqual(ledgerNotes(db), ['inside']);
    db.close();
    other.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('T9 only allowlisted operations run, the READ path cannot write, and rejections are audited without secrets', async () => {
  const db = store();
  const accounts = memoryAccountAdmin();
  const a = newShim(db);
  grantRead(db, a.reg.id);
  const token = issueToken(db, call(db, a, 'token'), T0);
  const run = (op: string, requestId: string) => invoke(db, call(db, a), requestId, JSON.stringify({ op, project: 'p1', task: 't1' }), token, T0);
  // the lease is reserved but not yet live on the database side
  assert.throws(() => run('ledger.read_entries', 'r0'), { code: 'AUTHZ_LEASE_NOT_READY' });
  await settleLeases(db, accounts, T0);
  assert.deepEqual(run('ledger.read_entries', 'r1'), []);
  for (const op of ['schedule.update_task', 'constructor', 'SELECT * FROM registrations', 'ledger.read_entries; DROP TABLE grants']) {
    assert.throws(() => run(op, 'r2'), (err: { code?: string }) => ['AUTHZ_SCOPE', 'AUTHZ_UNKNOWN_OPERATION'].includes(err.code ?? ''));
  }
  assert.throws(() => readOnly(db, ledgerWrite(db, 'sneaky')), /readonly|read-only|query_only/i);
  assert.deepEqual(plain(db.prepare('PRAGMA query_only').get()), { query_only: 0 });
  assert.deepEqual(ledgerNotes(db), []);

  const rows = db.prepare('SELECT * FROM audit').all();
  assert.ok(rows.some((r) => r.action === 'invoke:WRITE' && r.result === 'AUTHZ_SCOPE'));
  const dump = JSON.stringify(rows);
  const privateJwk = a.privateKey.export({ format: 'jwk' });
  assert.ok(privateJwk.d && !dump.includes(privateJwk.d));
  assert.ok(!dump.includes(token));
});

test('T10 exclusive leases: one account per session, returned on revoke and expiry, re-lent after restart', async () => {
  const db = store(undefined, ['ags_ledger_ro_01']);
  const accounts = memoryAccountAdmin();
  const a = newShim(db);
  const b = newShim(db);
  grantRead(db, a.reg.id);
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'LENDING' });
  // the pool has one account, so a second session cannot be approved and nothing of that grant remains
  assert.throws(() => grantRead(db, b.reg.id), { code: 'AUTHZ_POOL_EXHAUSTED' });
  assert.equal(currentGrant(db, b.reg.id), undefined);
  await settleLeases(db, accounts, T0);
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'LENT' });
  assert.deepEqual([...accounts.loggedIn], ['ags_ledger_ro_01']);

  restartLeases(db, T0);
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'LENDING' });
  await settleLeases(db, accounts, T0);

  revoke(db, a.reg.id, ADMIN, T0);
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'RETURNING' });
  await settleLeases(db, accounts, T0);
  assert.equal(leaseOf(db, a.reg.id), undefined);
  assert.deepEqual([...accounts.loggedIn], []);

  // the freed account goes to the next session, and comes back by itself when that grant expires
  grantRead(db, b.reg.id);
  await settleLeases(db, accounts, T0);
  await settleLeases(db, accounts, T0 + HOUR);
  assert.equal(leaseOf(db, b.reg.id), undefined);
  assert.deepEqual([...accounts.loggedIn], []);
  const leaseAudit = db.prepare("SELECT action, target, detail FROM audit WHERE action LIKE 'lease:%' AND result = 'ok'").all();
  assert.ok(leaseAudit.some((r) => r.action === 'lease:lend' && r.detail === b.reg.id));
});

test('T10b a failed or overtaken database step is retried, never overwritten', async () => {
  const db = store(undefined, ['ags_ledger_ro_01']);
  const a = newShim(db);
  let release: () => void = () => {};
  let fail = true;
  const loggedIn = new Set<string>();
  const accounts: AccountAdmin = {
    lend: async (account) => {
      if (fail) throw new Error('database unreachable');
      await new Promise<void>((resolve) => (release = resolve));
      loggedIn.add(account);
    },
    reclaim: async (account) => {
      loggedIn.delete(account);
    },
  };
  grantRead(db, a.reg.id);
  await settleLeases(db, accounts, T0);
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'LENDING' });
  assert.ok(db.prepare("SELECT 1 FROM audit WHERE action = 'lease:lend' AND result = 'ERROR'").get());

  // revoke lands while the lend is in flight: the late lend must not mark the account LENT
  fail = false;
  const pass = settleLeases(db, accounts, T0);
  await new Promise((resolve) => setImmediate(resolve));
  revoke(db, a.reg.id, ADMIN, T0);
  release();
  await pass;
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'RETURNING' });
  await settleLeases(db, accounts, T0);
  assert.equal(leaseOf(db, a.reg.id), undefined);
  assert.deepEqual([...loggedIn], []);
});

test('T10c a hung step times out, and a row revoked mid-pass is reclaimed instead of lent', async (t) => {
  const db = store(undefined, ['ags_ledger_ro_01', 'ags_ledger_ro_02']);
  const a = newShim(db);
  const b = newShim(db);
  const lent: string[] = [];
  const accounts: AccountAdmin = {
    lend: async (account) => {
      if (account === 'ags_ledger_ro_01') return new Promise<void>(() => {});
      lent.push(account);
    },
    reclaim: async () => {},
  };
  grantRead(db, a.reg.id);
  grantRead(db, b.reg.id);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pass = settleLeases(db, accounts, T0);
  await new Promise((resolve) => setImmediate(resolve));
  revoke(db, b.reg.id, ADMIN, T0);
  t.mock.timers.tick(LEASE_STEP_MS);
  await pass;
  assert.deepEqual(leaseOf(db, a.reg.id), { account: 'ags_ledger_ro_01', state: 'LENDING' });
  assert.equal(leaseOf(db, b.reg.id), undefined);
  assert.deepEqual(lent, []);
  assert.ok(db.prepare("SELECT 1 FROM audit WHERE action = 'lease:lend' AND result = 'LEASE_TIMEOUT'").get());
});
