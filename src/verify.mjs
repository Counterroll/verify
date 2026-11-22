// Counterroll record verifier: Node.js entry point.
// Supplies the two crypto primitives from Node's built-in crypto module and
// re-exports the shared engine (src/core.mjs). No dependencies.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import * as core from './core.mjs';

export * from './core.mjs';

export function sha256HexSync(text) {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

export const nodeCrypto = {
  async sha256Hex(text) {
    return sha256HexSync(text);
  },
  async ed25519Verify(publicKeyHex, messageBytes, signatureHex) {
    try {
      const key = createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKeyHex, 'hex').toString('base64url') },
        format: 'jwk',
      });
      return cryptoVerify(null, messageBytes, key, Buffer.from(signatureHex, 'hex'));
    } catch {
      return false; // anything malformed never verifies
    }
  },
};

export function verifyRecord(record, opts = {}) {
  return core.verifyRecord(record, { crypto: nodeCrypto, ...opts });
}

export function verifyRecords(records, opts = {}) {
  return core.verifyRecords(records, { crypto: nodeCrypto, ...opts });
}
