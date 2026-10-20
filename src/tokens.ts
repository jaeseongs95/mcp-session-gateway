import { createHash, randomBytes } from 'node:crypto';
import { type Db, GateError, auditedTx, one } from './store.ts';
import { activeGrant } from './grants.ts';
import type { Registration } from './registry.ts';

const hash = (token: string): string => createHash('sha256').update(token).digest('base64url');

// The plaintext exists only in this return value, sent once in the reply to the shim's own signed request; only the hash is
// stored. Every issue replaces the previous token, so a token whose delivery was lost is simply superseded.
export function issueToken(db: Db, reg: Registration, now: number): string {
  return auditedTx(db, { at: now, actor: reg.keyThumbprint, action: 'token', target: reg.id, generation: reg.generation }, (entry) => {
    const grant = activeGrant(db, reg, now);
    entry.grantVersion = grant.version;
    const token = randomBytes(32).toString('base64url');
    db.prepare('DELETE FROM tokens WHERE registration_id = ?').run(reg.id);
    db.prepare('INSERT INTO tokens (hash, registration_id, grant_version, created_at) VALUES (?, ?, ?, ?)').run(hash(token), reg.id, grant.version, now);
    return token;
  });
}

// Valid only for its registration and the grant version it was issued under, so any grant change or revoke voids it.
export function checkToken(db: Db, registrationId: string, grantVersion: number, token: unknown): void {
  const found =
    typeof token === 'string' &&
    one(db, 'SELECT 1 AS hit FROM tokens WHERE hash = ? AND registration_id = ? AND grant_version = ?', hash(token), registrationId, grantVersion);
  if (!found) throw new GateError('AUTHN_BAD_TOKEN');
}
