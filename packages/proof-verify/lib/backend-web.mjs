// SPDX-License-Identifier: Apache-2.0
/**
 * The WebCrypto backend: the browser path, also usable in Node 22 through
 * globalThis.crypto (node:crypto's webcrypto).
 *
 * WebCrypto exists only in secure contexts: on a plain-HTTP page
 * `crypto.subtle` is undefined. The backend then reports `hashes: false`, and
 * the verifier answers UNVERIFIABLE ("use the CLI or serve this page over
 * HTTPS") instead of throwing or guessing. A runtime whose WebCrypto lacks
 * Ed25519 returns null from ed25519Verify: UNVERIFIABLE, never VALID.
 */

export function webCryptoBackend(cryptoObject) {
  const subtle = cryptoObject && typeof cryptoObject === 'object' ? cryptoObject.subtle : undefined;
  const usable = (name) => Boolean(subtle) && typeof subtle[name] === 'function';
  const hashes = usable('digest');
  return Object.freeze({
    name: 'webcrypto',
    hashes,
    async sha256(bytes) {
      return new Uint8Array(await subtle.digest('SHA-256', bytes));
    },
    async sha512(bytes) {
      return new Uint8Array(await subtle.digest('SHA-512', bytes));
    },
    async ed25519Verify(spki, message, signature) {
      if (!usable('importKey') || !usable('verify')) return null;
      let key;
      try {
        key = await subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
      } catch {
        return null;
      }
      try {
        return (await subtle.verify({ name: 'Ed25519' }, key, signature, message)) === true;
      } catch {
        return null;
      }
    },
  });
}
