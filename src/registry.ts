import { randomUUID } from 'node:crypto';
import { type Db, GateError, auditedTx, one } from './store.ts';
import { type ProofClaims, canonicalJwk, checkProof, peekRegistrationId, publicKeyFromJwk, thumbprint } from './pop.ts';

export type RegistrationState = 'PENDING' | 'ACTIVE' | 'REVOKED';
export type Mode = 'READ' | 'WRITE';

export interface Scope {
  project: string;
  task: string;
  mode: Mode;
}

// Bound unit = server-issued id + generation + the shim's key. Names, session labels, host claims and requested scopes are
// display only; the host claim is always shown as unverified because no host can prove what it is.
export interface Registration {
  id: string;
  generation: number;
  displayName: string;
  sessionLabel: string;
  hostClaim: string;
  requestedScopes: Scope[];
  keyThumbprint: string;
  publicJwk: unknown;
  state: RegistrationState;
  createdAt: number;
}

interface Row {
  id: string;
  generation: number;
  display_name: string;
  session_label: string;
  host_claim: string;
  requested_scopes: string;
  key_thumbprint: string;
  public_jwk: string;
  state: RegistrationState;
  created_at: number;
}

export function findRegistration(db: Db, id: string): Registration | undefined {
  const r = one<Row>(db, 'SELECT * FROM registrations WHERE id = ?', id);
  return (
    r && {
      id: r.id,
      generation: r.generation,
      displayName: r.display_name,
      sessionLabel: r.session_label,
      hostClaim: r.host_claim,
      requestedScopes: JSON.parse(r.requested_scopes),
      keyThumbprint: r.key_thumbprint,
      publicJwk: JSON.parse(r.public_jwk),
      state: r.state,
      createdAt: r.created_at,
    }
  );
}

// Control and invisible format characters (bidi overrides, zero-width) are refused so a label cannot impersonate another on the admin page.
export function label(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 200 || /[\p{Cc}\p{Cf}]/u.test(value)) {
    throw new GateError('INVALID_INPUT', field);
  }
  return value;
}

export function readScopes(value: unknown, allowEmpty = false): Scope[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > 50) throw new GateError('INVALID_INPUT', 'scopes');
  return value.map((s) => {
    if (!s || (s.mode !== 'READ' && s.mode !== 'WRITE')) throw new GateError('INVALID_INPUT', 'scopes');
    return { project: label(s.project, 'project'), task: label(s.task, 'task'), mode: s.mode };
  });
}

// body is the exact JSON string the shim signed: {displayName, sessionLabel, hostClaim, publicJwk, requestedScopes?}.
// A new key always means a new PENDING registration; nothing is inherited from an earlier one.
export function register(db: Db, body: string, proof: unknown, now: number): Registration {
  let input: Record<string, unknown> | null;
  try {
    input = JSON.parse(body);
  } catch {
    throw new GateError('INVALID_INPUT', 'body');
  }
  if (!input || typeof input !== 'object') throw new GateError('INVALID_INPUT', 'body');
  const key = publicKeyFromJwk(input.publicJwk);
  const keyThumbprint = thumbprint(key);
  const displayName = label(input.displayName, 'displayName');
  const sessionLabel = label(input.sessionLabel, 'sessionLabel');
  const hostClaim = label(input.hostClaim, 'hostClaim');
  const requestedScopes = input.requestedScopes === undefined ? [] : readScopes(input.requestedScopes, true);
  const claims = checkProof(db, key, keyThumbprint, proof, { method: 'register', body, now });
  if (claims.registrationId !== '' || claims.generation !== 0) throw new GateError('AUTHN_BAD_PROOF');

  const id = randomUUID();
  return auditedTx(db, { at: now, actor: keyThumbprint, action: 'register', target: id, detail: displayName, requestId: claims.requestId }, () => {
    if (one(db, 'SELECT 1 AS hit FROM registrations WHERE key_thumbprint = ?', keyThumbprint)) throw new GateError('AUTHN_KEY_IN_USE');
    db.prepare(
      `INSERT INTO registrations (id, generation, display_name, session_label, host_claim, requested_scopes, key_thumbprint, public_jwk, state, created_at)
       VALUES (?, 1, ?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
    ).run(id, displayName, sessionLabel, hostClaim, JSON.stringify(requestedScopes), keyThumbprint, JSON.stringify(canonicalJwk(key)), now);
    return findRegistration(db, id)!;
  });
}

// AUTHN only: the proof verifies under the key this registration was created with, at its current generation.
// A REVOKED or PENDING registration still authenticates (it may read its own status); AUTHZ happens in grants.ts.
export function authenticate(db: Db, proof: unknown, method: string, body: string, now: number): { reg: Registration; claims: ProofClaims } {
  const reg = findRegistration(db, peekRegistrationId(proof));
  if (!reg) throw new GateError('AUTHN_UNKNOWN_REGISTRATION');
  const claims = checkProof(db, publicKeyFromJwk(reg.publicJwk), reg.keyThumbprint, proof, { method, body, now });
  if (claims.generation !== reg.generation) throw new GateError('AUTHN_STALE_GENERATION');
  return { reg, claims };
}

// Admin only, after a WebAuthn assertion. Renaming never touches the grant.
export function rename(db: Db, id: unknown, displayName: unknown, admin: string, now: number): void {
  const target = label(id, 'registrationId');
  const name = label(displayName, 'displayName');
  auditedTx(db, { at: now, actor: admin, action: 'rename', target, detail: name }, () => {
    const changed = db.prepare('UPDATE registrations SET display_name = ? WHERE id = ?').run(name, target).changes;
    if (Number(changed) === 0) throw new GateError('AUTHZ_UNKNOWN_REGISTRATION');
  });
}
