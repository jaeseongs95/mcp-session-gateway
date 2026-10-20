import { type Db, GateError, assertSync, auditedTx, one } from './store.ts';
import { type Registration, type Scope, findRegistration, label, readScopes } from './registry.ts';
import { releaseLease, reserveLease } from './leases.ts';

export type { Mode, Scope } from './registry.ts';

export interface Grant {
  registrationId: string;
  version: number;
  scopes: Scope[];
  expiresAt: number;
  approvedBy: string;
  approvedAt: number;
}

interface Row {
  registration_id: string;
  version: number;
  scopes: string;
  expires_at: number;
  approved_by: string;
  approved_at: number;
}

export function currentGrant(db: Db, registrationId: string): Grant | undefined {
  const r = one<Row>(db, 'SELECT * FROM grants WHERE registration_id = ?', registrationId);
  return (
    r && {
      registrationId: r.registration_id,
      version: r.version,
      scopes: JSON.parse(r.scopes),
      expiresAt: r.expires_at,
      approvedBy: r.approved_by,
      approvedAt: r.approved_at,
    }
  );
}

// Approve or change, and reserve one pool account for the whole grant period. The caller must first verify a fresh UP+UV
// WebAuthn assertion bound to exactly this input (webauthn.ts stores the input with the challenge).
export function setGrant(
  db: Db,
  input: { registrationId: unknown; expectedVersion: unknown; scopes: unknown; expiresAt: unknown },
  admin: string,
  now: number,
): number {
  const registrationId = label(input.registrationId, 'registrationId');
  const scopes = readScopes(input.scopes);
  const { expectedVersion, expiresAt } = input;
  if (!Number.isSafeInteger(expectedVersion)) throw new GateError('INVALID_INPUT', 'expectedVersion');
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= now) throw new GateError('INVALID_INPUT', 'expiresAt');
  return auditedTx(db, { at: now, actor: admin, action: 'grant', target: registrationId, detail: JSON.stringify(scopes) }, (entry) => {
    const reg = findRegistration(db, registrationId);
    if (!reg) throw new GateError('AUTHZ_UNKNOWN_REGISTRATION');
    if (reg.state === 'REVOKED') throw new GateError('AUTHZ_REGISTRATION_CLOSED');
    // No host can be proven, so WRITE is never granted (decision D1). There is deliberately no switch to turn this off.
    if (scopes.some((s) => s.mode === 'WRITE')) throw new GateError('AUTHZ_HOST_UNVERIFIED');
    const version = currentGrant(db, reg.id)?.version ?? 0;
    if (version !== expectedVersion) throw new GateError('CONFLICT_VERSION');
    entry.grantVersion = version + 1;
    db.prepare(
      `INSERT INTO grants (registration_id, version, scopes, expires_at, approved_by, approved_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (registration_id) DO UPDATE SET version = excluded.version, scopes = excluded.scopes,
         expires_at = excluded.expires_at, approved_by = excluded.approved_by, approved_at = excluded.approved_at`,
    ).run(reg.id, version + 1, JSON.stringify(scopes), expiresAt, admin, now);
    db.prepare("UPDATE registrations SET state = 'ACTIVE' WHERE id = ?").run(reg.id);
    reserveLease(db, reg.id, expiresAt, now);
    return version + 1;
  });
}

// No version check: revoking only narrows access, so acting on a stale view is still safe. Terminal: a revoked
// registration is never re-approved; the session must come back with a new key as a new PENDING registration.
export function revoke(db: Db, registrationId: unknown, admin: string, now: number): void {
  const target = label(registrationId, 'registrationId');
  auditedTx(db, { at: now, actor: admin, action: 'revoke', target }, (entry) => {
    if (!findRegistration(db, target)) throw new GateError('AUTHZ_UNKNOWN_REGISTRATION');
    db.prepare("UPDATE registrations SET state = 'REVOKED' WHERE id = ?").run(target);
    db.prepare('UPDATE grants SET version = version + 1 WHERE registration_id = ?').run(target);
    releaseLease(db, target, now);
    entry.grantVersion = currentGrant(db, target)?.version;
  });
}

// Must run inside a transaction: re-reads state there, so whichever of the caller and a revoke commits first wins.
export function activeGrant(db: Db, reg: Registration, now: number): Grant {
  const fresh = findRegistration(db, reg.id);
  if (!fresh || fresh.state !== 'ACTIVE' || fresh.generation !== reg.generation) throw new GateError('AUTHZ_NOT_ACTIVE');
  const grant = currentGrant(db, reg.id);
  if (!grant) throw new GateError('AUTHZ_NO_GRANT');
  if (grant.expiresAt <= now) throw new GateError('AUTHZ_EXPIRED');
  return grant;
}

// AUTHZ + the business call in one transaction. A committed call stays committed; it is never reported as cancelled.
// `run` must be synchronous and must only call allowlisted backend operations.
export function runUnderGrant<T>(db: Db, reg: Registration, want: Scope, requestId: string, now: number, run: (grantVersion: number) => T): T {
  assertSync(run);
  return auditedTx(
    db,
    { at: now, actor: reg.keyThumbprint, action: `invoke:${want.mode}`, target: `${want.project}/${want.task}`, requestId, generation: reg.generation },
    (entry) => {
      const grant = activeGrant(db, reg, now);
      entry.grantVersion = grant.version;
      const allowed = grant.scopes.some(
        (s) => s.project === want.project && s.task === want.task && (s.mode === 'WRITE' || want.mode === 'READ'),
      );
      if (!allowed) throw new GateError('AUTHZ_SCOPE');
      return run(grant.version);
    },
  );
}
