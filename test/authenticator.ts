import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

// Test-only software passkey (ES256). The CBOR encoding of its public key comes from the WebAuthn library itself.
export function softAuthenticator(rpID: string, origin: () => string) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { x, y } = publicKey.export({ format: 'jwk' });
  const coseKey = new Map<number, number | Uint8Array>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, Buffer.from(x as string, 'base64url')],
    [-3, Buffer.from(y as string, 'base64url')],
  ]);
  const id = randomBytes(16).toString('base64url');
  let counter = 0;
  return {
    id,
    cose: isoCBOR.encode(coseKey as Parameters<typeof isoCBOR.encode>[0]),
    assert(challenge: string, opts: { uv?: boolean; origin?: string; rpID?: string } = {}) {
      const counterBytes = Buffer.alloc(4);
      counterBytes.writeUInt32BE(++counter);
      const flags = 0x01 | (opts.uv === false ? 0 : 0x04); // UP, UV
      const authData = Buffer.concat([createHash('sha256').update(opts.rpID ?? rpID).digest(), Buffer.from([flags]), counterBytes]);
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: opts.origin ?? origin(), crossOrigin: false }));
      const signature = sign('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), privateKey);
      return {
        id,
        rawId: id,
        type: 'public-key',
        response: {
          authenticatorData: authData.toString('base64url'),
          clientDataJSON: clientData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
        clientExtensionResults: {},
      };
    },
  };
}
