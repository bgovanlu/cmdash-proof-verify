// SPDX-License-Identifier: Apache-2.0
/**
 * The Node crypto backend: SHA-256, SHA-512 and the platform Ed25519
 * primitive from node:crypto. Node-only; the browser build uses
 * backend-web.mjs instead.
 *
 * The primitive is only ever called after lib/ed25519.mjs has made the spec
 * section 2.1.1 checks itself. Any exception from it (a Node built without
 * Ed25519, a FIPS provider that refuses it) reads as "unavailable", which is
 * UNVERIFIABLE, never VALID.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';

export const nodeBackend = Object.freeze({
  name: 'node:crypto',
  hashes: true,
  async sha256(bytes) {
    return new Uint8Array(createHash('sha256').update(bytes).digest());
  },
  async sha512(bytes) {
    return new Uint8Array(createHash('sha512').update(bytes).digest());
  },
  async ed25519Verify(spki, message, signature) {
    let key;
    try {
      key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch {
      return null;
    }
    try {
      return verify(null, message, key, signature) === true;
    } catch {
      return null;
    }
  },
});
