// SPDX-License-Identifier: Apache-2.0
/**
 * Byte helpers for the proof-receipt verifier: strict base64url and base64,
 * hex, and UTF-8. Isomorphic on purpose (no Node builtin, no Buffer): the same
 * code runs in the CLI and in browser/verify.js.
 *
 * "Strict" means one spelling per byte string (spec section 2, rule 2): a
 * decoder that also read `...AB` as `...AA` would let one receipt have many
 * spellings, so a value with spare bits set, a wrong length or a stray
 * character decodes to null, never to "the nearest bytes".
 */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function sextetTable(alphabet) {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i += 1) table[alphabet.charCodeAt(i)] = i;
  return table;
}
const B64URL_TABLE = sextetTable(B64URL_ALPHABET);
const B64STD_TABLE = sextetTable(B64STD_ALPHABET);

/** Decodes `s` (no padding characters) with `table`; null unless canonical. */
function decodeSextets(s, table) {
  const n = s.length;
  const rem = n % 4;
  if (rem === 1) return null;
  const out = new Uint8Array(Math.floor(n / 4) * 3 + (rem === 0 ? 0 : rem - 1));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < n; i += 1) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? table[c] : -1;
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o] = (acc >> bits) & 0xff;
      o += 1;
    }
  }
  // Canonical: the bits left over after the last whole byte must all be zero.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null;
  return out;
}

/** Unpadded base64url (RFC 4648 section 5) with zero spare bits, or null. */
export function decodeBase64Url(s) {
  if (typeof s !== 'string') return null;
  return decodeSextets(s, B64URL_TABLE);
}

/** Standard base64 with its padding (RFC 4648 section 4), canonical, or null. */
export function decodeBase64Std(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0) return null;
  let body = s;
  if (body.endsWith('==')) body = body.slice(0, -2);
  else if (body.endsWith('=')) body = body.slice(0, -1);
  if (body.includes('=')) return null;
  // With the padding removed, a complete quartet must not have needed any.
  if (body.length % 4 === 0 && body.length !== s.length) return null;
  return decodeSextets(body, B64STD_TABLE);
}

function encodeSextets(bytes, alphabet, pad) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      alphabet[v >> 18] + alphabet[(v >> 12) & 63] + alphabet[(v >> 6) & 63] + alphabet[v & 63];
  }
  const left = bytes.length - i;
  if (left === 1) {
    const v = bytes[i] << 16;
    out += alphabet[v >> 18] + alphabet[(v >> 12) & 63] + (pad ? '==' : '');
  } else if (left === 2) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      alphabet[v >> 18] + alphabet[(v >> 12) & 63] + alphabet[(v >> 6) & 63] + (pad ? '=' : '');
  }
  return out;
}

export function encodeBase64Url(bytes) {
  return encodeSextets(bytes, B64URL_ALPHABET, false);
}

export function encodeBase64Std(bytes) {
  return encodeSextets(bytes, B64STD_ALPHABET, true);
}

const HEX = '0123456789abcdef';

/** Lowercase hex. */
export function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
  return out;
}

/** Lowercase hex only (the spec's hex32 values are lowercase), even length; null otherwise. */
export function fromHex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

let textEncoder = null;
/** UTF-8 bytes of a well-formed string. */
export function utf8(s) {
  if (textEncoder === null) textEncoder = new TextEncoder();
  return textEncoder.encode(s);
}

let fatalDecoder = null;
/**
 * Fatal UTF-8 decoding that KEEPS a byte-order mark (spec section 3.4): invalid
 * UTF-8 is refused (null), never replaced with U+FFFD, and a leading U+FEFF
 * survives so that the JSON parser refuses it.
 */
export function decodeUtf8Fatal(bytes) {
  if (fatalDecoder === null)
    fatalDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  try {
    return fatalDecoder.decode(bytes);
  } catch {
    return null;
  }
}

/** True when `s` has no lone surrogate, i.e. it is the decoding of some UTF-8 byte string. */
export function isWellFormedUtf16(s) {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) return false;
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** UTF-8 length of a well-formed string, without encoding it. */
export function utf8Length(s) {
  let n = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i += 1;
    } else n += 3;
  }
  return n;
}

/** Number of code points (a lone surrogate counts as one), as JSON Schema counts string length. */
export function codePointLength(s) {
  let n = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i += 1;
    }
    n += 1;
  }
  return n;
}

export function isUint8Array(v) {
  return v instanceof Uint8Array;
}
