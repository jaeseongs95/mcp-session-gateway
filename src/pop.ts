import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { type Db, GateError } from './store.ts';

// Every request carries a proof signed by the shim's one-time Ed25519 key, so a copied token alone is useless.
export interface ProofClaims {
  method: string;
  registrationId: string; // '' for register, which has no id yet
  generation: number; // 0 for register
  requestId: string;
  iat: number; // ms since epoch
  nonce: string;
  bodyDigest: string; // sha256 of the exact request body
}

// payload = base64url(JSON claims); sig = base64url(Ed25519 over the payload string). Signing the sent bytes avoids canonical JSON.
export interface Proof {
  payload: string;
  sig: string;
}

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export const MAX_SKEW_MS = 60_000;

export const digest = (data: string): string => createHash('sha256').update(data).digest('base64url');

export function publicKeyFromJwk(jwk: unknown): KeyObject {
  const j = jwk as Partial<PublicJwk> | null;
  if (!j || j.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.x !== 'string') throw new GateError('INVALID_INPUT', 'publicJwk');
  try {
    return createPublicKey({ key: { kty: j.kty, crv: j.crv, x: j.x }, format: 'jwk' });
  } catch {
    throw new GateError('INVALID_INPUT', 'publicJwk');
  }
}

// Re-exported from the decoded key, so differently spelled encodings of one key collapse to one value.
export const canonicalJwk = (key: KeyObject): PublicJwk => {
  const { x } = key.export({ format: 'jwk' });
  return { kty: 'OKP', crv: 'Ed25519', x: x as string };
};

// RFC 7638 thumbprint of the canonical key: required members in lexicographic order.
export const thumbprint = (key: KeyObject): string => {
  const jwk = canonicalJwk(key);
  return digest(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
};

export function signProof(privateKey: KeyObject, claims: Omit<ProofClaims, 'bodyDigest'>, body: string): Proof {
  const payload = Buffer.from(JSON.stringify({ ...claims, bodyDigest: digest(body) })).toString('base64url');
  return { payload, sig: sign(null, Buffer.from(payload), privateKey).toString('base64url') };
}

function readClaims(proof: unknown): ProofClaims {
  const p = proof as Partial<Proof> | null;
  if (!p || typeof p.payload !== 'string' || typeof p.sig !== 'string') throw new GateError('AUTHN_BAD_PROOF');
  let c: Partial<ProofClaims> | null;
  try {
    c = JSON.parse(Buffer.from(p.payload, 'base64url').toString('utf8'));
  } catch {
    throw new GateError('AUTHN_BAD_PROOF');
  }
  if (
    !c ||
    typeof c.method !== 'string' ||
    typeof c.registrationId !== 'string' ||
    !Number.isSafeInteger(c.generation) ||
    typeof c.requestId !== 'string' ||
    c.requestId.length === 0 ||
    c.requestId.length > 128 ||
    !Number.isSafeInteger(c.iat) ||
    typeof c.nonce !== 'string' ||
    c.nonce.length < 16 ||
    c.nonce.length > 128 ||
    typeof c.bodyDigest !== 'string'
  ) {
    throw new GateError('AUTHN_BAD_PROOF');
  }
  return c as ProofClaims;
}

// Unverified: only used to pick which stored key to verify against.
export const peekRegistrationId = (proof: unknown): string => readClaims(proof).registrationId;

export function checkProof(
  db: Db,
  key: KeyObject,
  keyThumbprint: string,
  proof: unknown,
  expect: { method: string; body: string; now: number },
): ProofClaims {
  const c = readClaims(proof);
  const p = proof as Proof;
  if (!verify(null, Buffer.from(p.payload), key, Buffer.from(p.sig, 'base64url'))) throw new GateError('AUTHN_BAD_SIGNATURE');
  if (c.method !== expect.method) throw new GateError('AUTHN_WRONG_METHOD');
  if (c.bodyDigest !== digest(expect.body)) throw new GateError('AUTHN_BODY_MISMATCH');
  if (Math.abs(expect.now - c.iat) > MAX_SKEW_MS) throw new GateError('AUTHN_STALE');
  // A nonce older than 2 * skew can no longer pass the iat check, so it is safe to forget.
  db.prepare('DELETE FROM nonces WHERE seen_at < ?').run(expect.now - 2 * MAX_SKEW_MS);
  const fresh = db.prepare('INSERT OR IGNORE INTO nonces (key_thumbprint, nonce, seen_at) VALUES (?, ?, ?)').run(keyThumbprint, c.nonce, expect.now);
  if (Number(fresh.changes) === 0) throw new GateError('AUTHN_REPLAY');
  return c;
}
