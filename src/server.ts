import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { type Db, GateError, auditRejection, openStore } from './store.ts';
import { authenticate, findRegistration, register, rename } from './registry.ts';
import { currentGrant, revoke, setGrant } from './grants.ts';
import { type AccountAdmin, memoryAccountAdmin, restartLeases, settleLeases, syncPool } from './leases.ts';
import { issueToken } from './tokens.ts';
import { invoke } from './invoke.ts';
import { type RelyingParty, finishAssertion, finishEnrollment, startAssertion, startEnrollment } from './webauthn.ts';
import { ADMIN_SCRIPT, adminPage, loginPage } from './admin-page.ts';
import { digest } from './pop.ts';

export interface GatewayConfig {
  db: Db;
  rp: RelyingParty;
  enrollCodeHash: string;
  accounts: AccountAdmin;
  now?: () => number;
}

const MAX_BODY = 64 * 1024;
const VIEW_TTL_MS = 10 * 60_000;
const MAX_GRANT_MINUTES = 7 * 24 * 60;
const STATUS: Record<string, number> = { AUTHN: 401, AUTHZ: 403, CONFLICT: 409, INVALID: 400 };
const HTML_HEADERS = {
  'content-security-policy': "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new GateError('INVALID_INPUT', 'body');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function parseObject(body: string): Record<string, unknown> {
  try {
    const value = JSON.parse(body);
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch {
    // fall through
  }
  throw new GateError('INVALID_INPUT', 'body');
}

function send(res: ServerResponse, status: number, type: string, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', ...headers });
  res.end(body);
}

const json = (res: ServerResponse, status: number, value: unknown, headers?: Record<string, string>) =>
  send(res, status, 'application/json', JSON.stringify(value), headers);

// The shim sends its proof as "payload.sig"; a missing or malformed header fails proof parsing.
function proofOf(req: IncomingMessage) {
  const [payload, sig] = String(req.headers['x-proof'] ?? '').split('.');
  return { payload, sig };
}

export function createGateway(cfg: GatewayConfig): Server {
  const { db, rp } = cfg;
  const now = cfg.now ?? Date.now;
  // ponytail: in-memory admin view sessions; the admin signs in again after a restart. They only allow viewing and asking
  // for a challenge; every change still needs its own passkey assertion.
  const views = new Map<string, number>();
  let settling: Promise<void> = Promise.resolve();
  // One pass at a time; a failed pass leaves rows for the next one (settleLeases audits each step).
  const settle = () => (settling = settling.then(() => settleLeases(db, cfg.accounts, now())).catch(() => {}));

  function viewCookie(req: IncomingMessage): boolean {
    const value = req.headers.cookie
      ?.split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('gw_admin='))
      ?.slice('gw_admin='.length);
    const expires = value ? views.get(digest(value)) : undefined;
    return expires !== undefined && expires > now();
  }

  function describe(input: Record<string, unknown>, at: number) {
    const reg = findRegistration(db, String(input.registrationId ?? ''));
    if (!reg) throw new GateError('AUTHZ_UNKNOWN_REGISTRATION');
    const who = `"${reg.displayName}" (session ${reg.sessionLabel}, key ${reg.keyThumbprint.slice(0, 8)})`;
    switch (input.action) {
      case 'grant': {
        const minutes = input.expiresInMinutes;
        if (typeof minutes !== 'number' || !Number.isSafeInteger(minutes) || minutes < 1 || minutes > MAX_GRANT_MINUTES) {
          throw new GateError('INVALID_INPUT', 'expiresInMinutes');
        }
        const expiresAt = at + minutes * 60_000;
        const action = { kind: 'grant', registrationId: reg.id, expectedVersion: input.expectedVersion, scopes: input.scopes, expiresAt };
        return { action, summary: `Grant ${JSON.stringify(input.scopes)} to ${who} until ${new Date(expiresAt).toISOString()}` };
      }
      case 'revoke':
        return { action: { kind: 'revoke', registrationId: reg.id }, summary: `Revoke ${who}` };
      case 'rename':
        return {
          action: { kind: 'rename', registrationId: reg.id, displayName: input.displayName },
          summary: `Rename ${who} to "${String(input.displayName)}"`,
        };
    }
    throw new GateError('INVALID_INPUT', 'action');
  }

  function execute(action: unknown, admin: string, at: number): unknown {
    const a = (action ?? {}) as Record<string, unknown>;
    switch (a.kind) {
      case 'grant':
        return { version: setGrant(db, { registrationId: a.registrationId, expectedVersion: a.expectedVersion, scopes: a.scopes, expiresAt: a.expiresAt }, admin, at) };
      case 'revoke':
        revoke(db, a.registrationId, admin, at);
        return {};
      case 'rename':
        rename(db, a.registrationId, a.displayName, admin, at);
        return {};
    }
    throw new GateError('INVALID_INPUT', 'action');
  }

  type Route = (req: IncomingMessage, body: string, at: number, res: ServerResponse) => Promise<unknown> | unknown;
  const routes: Record<string, Route> = {
    '/agent/register': (req, body, at) => {
      const reg = register(db, body, proofOf(req), at);
      return { id: reg.id, generation: reg.generation, state: reg.state, keyFingerprint: reg.keyThumbprint.slice(0, 8) };
    },
    '/agent/status': (req, body, at) => {
      const { reg } = authenticate(db, proofOf(req), 'status', body, at);
      const grant = currentGrant(db, reg.id);
      const expired = reg.state === 'ACTIVE' && grant !== undefined && grant.expiresAt <= at;
      return {
        id: reg.id,
        generation: reg.generation,
        state: expired ? 'EXPIRED' : reg.state,
        scopes: grant?.scopes ?? [],
        expiresAt: grant?.expiresAt ?? null,
        keyFingerprint: reg.keyThumbprint.slice(0, 8),
      };
    },
    // The only response that ever carries a token, and only to the holder of the registration's key.
    '/agent/token': (req, body, at) => {
      const { reg } = authenticate(db, proofOf(req), 'token', body, at);
      return { token: issueToken(db, reg, at) };
    },
    '/agent/invoke': (req, body, at) => {
      const { reg, claims } = authenticate(db, proofOf(req), 'invoke', body, at);
      const auth = req.headers.authorization;
      const token = auth?.startsWith('Bearer ') ? auth.slice('Bearer '.length) : undefined;
      return { result: invoke(db, reg, claims.requestId, body, token, at) };
    },
    '/admin/enroll/options': (_req, body, at) => startEnrollment(db, rp, parseObject(body).code, cfg.enrollCodeHash, at),
    '/admin/enroll/verify': async (_req, body, at) => {
      const input = parseObject(body);
      await finishEnrollment(db, rp, input.challengeId, input.response, at);
      return {};
    },
    '/admin/login/options': (_req, _body, at) => startAssertion(db, rp, 'login', null, at),
    '/admin/login/verify': async (_req, body, at, res) => {
      const input = parseObject(body);
      await finishAssertion(db, rp, 'login', input.challengeId, input.response, at);
      const cookie = randomBytes(32).toString('base64url');
      views.set(digest(cookie), at + VIEW_TTL_MS);
      const secure = rp.origin.startsWith('https:') ? '; Secure' : '';
      res.setHeader('set-cookie', `gw_admin=${cookie}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=${VIEW_TTL_MS / 1000}${secure}`);
      return {};
    },
    '/admin/action/options': async (req, body, at) => {
      if (!viewCookie(req)) throw new GateError('AUTHN_NO_ADMIN_VIEW');
      const { action, summary } = describe(parseObject(body), at);
      return { ...(await startAssertion(db, rp, 'action', action, at)), summary };
    },
    '/admin/action/verify': async (_req, body, at) => {
      const input = parseObject(body);
      const { action, admin } = await finishAssertion(db, rp, 'action', input.challengeId, input.response, at);
      const result = execute(action, admin, now());
      await settle();
      return result;
    },
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://gateway.invalid');
    const at = now();
    try {
      if (req.method === 'GET' && url.pathname === '/admin') {
        const html = viewCookie(req) ? adminPage(db, at) : loginPage(!db.prepare('SELECT 1 FROM admin_credentials LIMIT 1').get());
        return send(res, 200, 'text/html; charset=utf-8', html, HTML_HEADERS);
      }
      if (req.method === 'GET' && url.pathname === '/admin/app.js') return send(res, 200, 'text/javascript; charset=utf-8', ADMIN_SCRIPT);
      const route = req.method === 'POST' ? routes[url.pathname] : undefined;
      if (!route || !Object.hasOwn(routes, url.pathname)) return json(res, 404, { error: 'NOT_FOUND' });
      const body = await readBody(req);
      json(res, 200, await route(req, body, at, res));
    } catch (err) {
      if (err instanceof GateError) {
        if (!err.audited) auditRejection(db, { at, actor: 'unauthenticated', action: url.pathname, target: '-' }, err);
        json(res, STATUS[err.code.split('_')[0]] ?? 400, { error: err.code });
      } else {
        // No message: it could echo request content.
        auditRejection(db, { at, actor: 'unauthenticated', action: url.pathname, target: '-' }, err);
        json(res, 500, { error: 'INTERNAL' });
      }
    }
  });
  server.on('listening', () => {
    restartLeases(db, now());
    void settle();
  });
  const timer = setInterval(() => void settle(), 30_000);
  timer.unref();
  server.on('close', () => clearInterval(timer));
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const env = process.env;
  const origin = env.GATEWAY_ORIGIN ?? 'http://localhost:8787';
  const enrollCodeHash = env.ADMIN_ENROLL_CODE_SHA256;
  if (!enrollCodeHash) throw new Error('ADMIN_ENROLL_CODE_SHA256 (base64url sha256 of the enrollment code) is required');
  const db = openStore(env.GATEWAY_DB ?? 'gateway.db');
  syncPool(db, (env.GATEWAY_POOL_ACCOUNTS ?? '').split(',').filter(Boolean), Date.now());
  // ponytail: synthetic account pool only; the PostgreSQL adapter for real pool roles is not written yet.
  createGateway({
    db,
    rp: { rpID: new URL(origin).hostname, rpName: 'MCP session gateway', origin },
    enrollCodeHash,
    accounts: memoryAccountAdmin(),
  }).listen(Number(env.GATEWAY_PORT ?? 8787), env.GATEWAY_HOST ?? '127.0.0.1');
}
