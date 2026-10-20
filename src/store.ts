import { DatabaseSync } from 'node:sqlite';

// AUTHN_* = caller not proven, AUTHZ_* = proven but not allowed, CONFLICT_* = stale admin view, INVALID_INPUT = bad request.
export class GateError extends Error {
  code: string;
  audited = false;
  constructor(code: string, message = code) {
    super(message);
    this.code = code;
  }
}

export type Db = DatabaseSync;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS registrations (
  id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  display_name TEXT NOT NULL,
  session_label TEXT NOT NULL,
  host_claim TEXT NOT NULL,
  requested_scopes TEXT NOT NULL,
  key_thumbprint TEXT NOT NULL UNIQUE,
  public_jwk TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'REVOKED')),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  registration_id TEXT PRIMARY KEY REFERENCES registrations (id),
  version INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_by TEXT NOT NULL,
  approved_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  hash TEXT PRIMARY KEY,
  registration_id TEXT NOT NULL REFERENCES registrations (id),
  grant_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
  key_thumbprint TEXT NOT NULL,
  nonce TEXT NOT NULL,
  seen_at INTEGER NOT NULL,
  PRIMARY KEY (key_thumbprint, nonce)
);
CREATE TABLE IF NOT EXISTS account_leases (
  account TEXT PRIMARY KEY,
  tier TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('FREE', 'LENDING', 'LENT', 'RETURNING')),
  registration_id TEXT REFERENCES registrations (id),
  valid_until INTEGER,
  changed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_credentials (
  id TEXT PRIMARY KEY,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  purpose TEXT NOT NULL,
  action TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT,
  request_id TEXT,
  generation INTEGER,
  grant_version INTEGER,
  result TEXT NOT NULL
);
-- Synthetic stand-in for the ledger backend (decision D3).
CREATE TABLE IF NOT EXISTS synthetic_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  task TEXT NOT NULL,
  note TEXT NOT NULL,
  at INTEGER NOT NULL
);
`;

// timeout: how long a connection waits for another connection's write lock before failing with "database is locked".
export function openStore(path = ':memory:', timeout = 5_000): Db {
  const db = new DatabaseSync(path, { timeout });
  db.exec('PRAGMA foreign_keys = ON;' + SCHEMA);
  return db;
}

export function one<T>(db: Db, sql: string, ...params: (string | number | null)[]): T | undefined {
  return db.prepare(sql).get(...params) as unknown as T | undefined;
}

// Work after an await would run outside the transaction, after the checks; refuse it before and after the call.
export function assertSync(fn: (...args: never[]) => unknown): void {
  if (fn.constructor.name === 'AsyncFunction') throw new Error('callback must be synchronous');
}

// node:sqlite is synchronous, so a synchronous callback is one atomic step; its COMMIT is the linearization point.
// ponytail: single SQLite file; a multi-process PG store moves this to SELECT ... FOR UPDATE in the same transaction.
export function tx<T>(db: Db, fn: () => T): T {
  assertSync(fn);
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    if (result instanceof Promise) {
      result.catch(() => {});
      throw new Error('callback must be synchronous');
    }
    db.exec('COMMIT');
    return result;
  } catch (err) {
    if (db.isTransaction) db.exec('ROLLBACK');
    throw err;
  }
}

// Never put secrets here: no token, key, proof or password material.
export interface AuditEntry {
  at: number;
  actor: string;
  action: string;
  target: string;
  detail?: string;
  requestId?: string;
  generation?: number;
  grantVersion?: number;
}

export function audit(db: Db, e: AuditEntry, result: string): void {
  db.prepare(
    'INSERT INTO audit (at, actor, action, target, detail, request_id, generation, grant_version, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(e.at, e.actor, e.action, e.target, e.detail ?? null, e.requestId ?? null, e.generation ?? null, e.grantVersion ?? null, result);
}

// Records a rejection without letting a failing audit write hide the original error.
export function auditRejection(db: Db, e: AuditEntry, err: unknown): void {
  if (err instanceof GateError) err.audited = true;
  try {
    audit(db, e, err instanceof GateError ? err.code : 'ERROR');
  } catch {
    // the original error is what the caller needs; the store is already failing
  }
}

// Success is recorded inside the transaction; a rejection is recorded after the rollback so the rollback cannot erase it.
export function auditedTx<T>(db: Db, entry: AuditEntry, fn: (entry: AuditEntry) => T): T {
  const e = { ...entry };
  assertSync(fn);
  try {
    return tx(db, () => {
      const result = fn(e);
      audit(db, e, 'ok');
      return result;
    });
  } catch (err) {
    auditRejection(db, e, err);
    throw err;
  }
}
