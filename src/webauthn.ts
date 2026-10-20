import { randomUUID, timingSafeEqual } from 'node:crypto';
import {
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { type Db, GateError, one, tx } from './store.ts';
import { digest } from './pop.ts';

export interface RelyingParty {
  rpID: string;
  rpName: string;
  origin: string;
}

type Purpose = 'enroll' | 'login' | 'action';

interface ChallengeRow {
  challenge: string;
  action: string;
  expires_at: number;
  used_at: number | null;
}

interface CredentialRow {
  id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string;
}

const CHALLENGE_TTL_MS = 120_000;

// Each challenge is stored together with the exact action it authorizes. The browser returns only the challenge id and the
// assertion, so an assertion can never be redirected to another registration, action, scope or version.
function storeChallenge(db: Db, challenge: string, purpose: Purpose, action: unknown, now: number): string {
  const id = randomUUID();
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(now);
  db.prepare('INSERT INTO challenges (id, challenge, purpose, action, expires_at) VALUES (?, ?, ?, ?, ?)').run(
    id,
    challenge,
    purpose,
    JSON.stringify(action ?? null),
    now + CHALLENGE_TTL_MS,
  );
  return id;
}

// Burned before verification, so a challenge is single-use even when the attempt fails.
function takeChallenge(db: Db, id: unknown, purpose: Purpose, now: number): ChallengeRow {
  if (typeof id !== 'string') throw new GateError('AUTHN_BAD_CHALLENGE');
  return tx(db, () => {
    const row = one<ChallengeRow>(db, 'SELECT * FROM challenges WHERE id = ? AND purpose = ?', id, purpose);
    if (!row || row.used_at !== null || row.expires_at <= now) throw new GateError('AUTHN_BAD_CHALLENGE');
    db.prepare('UPDATE challenges SET used_at = ? WHERE id = ?').run(now, id);
    return row;
  });
}

const hasAdmin = (db: Db): boolean => one(db, 'SELECT 1 AS hit FROM admin_credentials LIMIT 1') !== undefined;

// ponytail: one bootstrap path. Enrollment is open only while no admin credential exists and needs a code whose sha256
// (base64url) the operator configured; adding more admins later needs an admin-approved enrollment flow.
export async function startEnrollment(db: Db, rp: RelyingParty, code: unknown, enrollCodeHash: string, now: number) {
  if (hasAdmin(db)) throw new GateError('AUTHZ_ENROLLMENT_CLOSED');
  const given = Buffer.from(typeof code === 'string' ? digest(code) : '');
  const expected = Buffer.from(enrollCodeHash);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new GateError('AUTHN_BAD_ENROLL_CODE');
  const options = await generateRegistrationOptions({
    rpName: rp.rpName,
    rpID: rp.rpID,
    userName: 'admin',
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  return { challengeId: storeChallenge(db, options.challenge, 'enroll', null, now), options };
}

export async function finishEnrollment(db: Db, rp: RelyingParty, challengeId: unknown, response: unknown, now: number): Promise<void> {
  const row = takeChallenge(db, challengeId, 'enroll', now);
  let result;
  try {
    result = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: row.challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      requireUserVerification: true,
    });
  } catch {
    throw new GateError('AUTHN_BAD_ATTESTATION');
  }
  if (!result.verified || !result.registrationInfo) throw new GateError('AUTHN_BAD_ATTESTATION');
  const { credential } = result.registrationInfo;
  tx(db, () => {
    if (hasAdmin(db)) throw new GateError('AUTHZ_ENROLLMENT_CLOSED');
    db.prepare('INSERT INTO admin_credentials (id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?)').run(
      credential.id,
      credential.publicKey,
      credential.counter,
      JSON.stringify(credential.transports ?? []),
      now,
    );
  });
}

export async function startAssertion(db: Db, rp: RelyingParty, purpose: 'login' | 'action', action: unknown, now: number) {
  const creds = db.prepare('SELECT id, transports FROM admin_credentials').all() as unknown as Pick<CredentialRow, 'id' | 'transports'>[];
  if (creds.length === 0) throw new GateError('AUTHN_NO_ADMIN');
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    userVerification: 'required',
    allowCredentials: creds.map((c) => ({ id: c.id, transports: JSON.parse(c.transports) })),
  });
  return { challengeId: storeChallenge(db, options.challenge, purpose, action, now), options };
}

// Returns the stored action only after a fresh assertion with user presence and user verification from an enrolled
// admin credential, for this origin and RP ID, signed over this very challenge.
export async function finishAssertion(db: Db, rp: RelyingParty, purpose: 'login' | 'action', challengeId: unknown, response: unknown, now: number) {
  const row = takeChallenge(db, challengeId, purpose, now);
  const credentialId = (response as { id?: unknown } | null)?.id;
  const cred = typeof credentialId === 'string' ? one<CredentialRow>(db, 'SELECT * FROM admin_credentials WHERE id = ?', credentialId) : undefined;
  if (!cred) throw new GateError('AUTHN_UNKNOWN_CREDENTIAL');
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge: row.challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      requireUserVerification: true,
      credential: { id: cred.id, publicKey: new Uint8Array(cred.public_key), counter: cred.counter, transports: JSON.parse(cred.transports) },
    });
  } catch {
    throw new GateError('AUTHN_BAD_ASSERTION');
  }
  if (!result.verified || !result.authenticationInfo.userVerified) throw new GateError('AUTHN_BAD_ASSERTION');
  db.prepare('UPDATE admin_credentials SET counter = ? WHERE id = ?').run(result.authenticationInfo.newCounter, cred.id);
  return { action: JSON.parse(row.action) as unknown, admin: `admin:${cred.id.slice(0, 8)}` };
}
