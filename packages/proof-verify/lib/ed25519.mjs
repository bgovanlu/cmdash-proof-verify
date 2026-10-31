// SPDX-License-Identifier: Apache-2.0
/**
 * Ed25519 verification as spec section 2.1.1 requires it: the verifier makes
 * the point and scalar checks ITSELF, in BigInt, before any platform
 * primitive is called, because Ed25519 libraries disagree on the edge cases
 * (Node, WebCrypto and Go all accept R = identity, S = 0 under the identity
 * public key, for any message).
 *
 *   1. the public key A: canonical encoding (y < p, and not x = 0 with the
 *      sign bit set), on the curve, not one of the 8 points of small order;
 *   2. the point R (the signature's first 32 bytes): the same three checks;
 *   3. the scalar S (the last 32 bytes, little-endian) below the group order L;
 *   4. the COFACTORLESS equation [S]B = R + [k]A, k = SHA-512(R || A || M) mod L.
 *
 * Step 4 is computed here as well, not left to the platform: a platform whose
 * equation is cofactored ([8][S]B = [8]R + [8][k]A) accepts vector 69, and a
 * verifier running on it must implement the equation itself. After all four
 * pass, the platform primitive must ALSO accept the signature: two
 * implementations have to agree before anything is VALID. A runtime without
 * Ed25519 yields ed25519.unavailable (UNVERIFIABLE), never VALID.
 *
 * "Small order" is decided by arithmetic ([8]P = O), not by comparing against
 * the spec's list of 8 encodings; test/ed25519.test.js proves the two agree.
 *
 * No BigInt literals (`1n`): the browser build is consumed by bundlers whose
 * targets may predate them, and BigInt(...) calls parse everywhere.
 * Not constant-time, and it need not be: every input is public.
 */
import { concatBytes } from './bytes.mjs';

const N0 = BigInt(0);
const N1 = BigInt(1);
const N2 = BigInt(2);
const N8 = BigInt(8);
/** p = 2^255 - 19 */
const FIELD_P = (N1 << BigInt(255)) - BigInt(19);
/** L = 2^252 + 27742317777372353535851937790883648493, the prime order of the base point. */
export const ED25519_L = (N1 << BigInt(252)) + BigInt('27742317777372353535851937790883648493');

function fmod(a) {
  const r = a % FIELD_P;
  return r < N0 ? r + FIELD_P : r;
}

function fpow(base, exponent) {
  let result = N1;
  let x = fmod(base);
  let e = exponent;
  while (e > N0) {
    if ((e & N1) === N1) result = (result * x) % FIELD_P;
    x = (x * x) % FIELD_P;
    e >>= N1;
  }
  return result;
}

/** d = -121665 / 121666 mod p */
const CURVE_D = fmod(-BigInt(121665) * fpow(BigInt(121666), FIELD_P - N2));
const CURVE_2D = fmod(N2 * CURVE_D);
/** sqrt(-1) = 2^((p-1)/4) mod p */
const SQRT_M1 = fpow(N2, (FIELD_P - N1) / BigInt(4));

/** Little-endian bytes to a non-negative BigInt. */
export function leBytesToBigInt(bytes) {
  let n = N0;
  for (let i = bytes.length - 1; i >= 0; i -= 1) n = (n << N8) | BigInt(bytes[i]);
  return n;
}

/**
 * RFC 8032 section 5.1.3 decoding, with the spec's canonicity rule.
 * Returns { point } in extended coordinates [X, Y, Z, T], or { problem }
 * with problem 'noncanonical' or 'off-curve'.
 */
export function decodePoint(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return { problem: 'noncanonical' };
  const sign = bytes[31] >> 7;
  const yBytes = Uint8Array.from(bytes);
  yBytes[31] &= 0x7f;
  const y = leBytesToBigInt(yBytes);
  if (y >= FIELD_P) return { problem: 'noncanonical' };
  const y2 = (y * y) % FIELD_P;
  const u = fmod(y2 - N1);
  const v = fmod(CURVE_D * y2 + N1);
  if (u === N0) {
    // x = 0 (y = 1 or y = p - 1): the sign bit must be clear, or the encoding is a second spelling.
    if (sign === 1) return { problem: 'noncanonical' };
    return { point: [N0, y, N1, N0] };
  }
  // x = u v^3 (u v^7)^((p-5)/8) is a square root of u/v when one exists.
  const v3 = (((v * v) % FIELD_P) * v) % FIELD_P;
  const v7 = (((v3 * v3) % FIELD_P) * v) % FIELD_P;
  let x = (((u * v3) % FIELD_P) * fpow((u * v7) % FIELD_P, (FIELD_P - BigInt(5)) / N8)) % FIELD_P;
  const vx2 = (v * ((x * x) % FIELD_P)) % FIELD_P;
  if (vx2 === u) {
    // x is a root
  } else if (vx2 === fmod(-u)) {
    x = (x * SQRT_M1) % FIELD_P;
  } else {
    return { problem: 'off-curve' };
  }
  if (Number(x & N1) !== sign) x = FIELD_P - x;
  return { point: [x, y, N1, (x * y) % FIELD_P] };
}

const IDENTITY = [N0, N1, N1, N0];

/** Unified addition in extended coordinates (add-2008-hwcd-3, a = -1): complete on this curve. */
function pointAdd(p1, p2) {
  const [X1, Y1, Z1, T1] = p1;
  const [X2, Y2, Z2, T2] = p2;
  const a = fmod((Y1 - X1) * (Y2 - X2));
  const b = fmod((Y1 + X1) * (Y2 + X2));
  const c = fmod(T1 * CURVE_2D * T2);
  const d = fmod(N2 * Z1 * Z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [fmod(e * f), fmod(g * h), fmod(f * g), fmod(e * h)];
}

/** Doubling in extended coordinates (dbl-2008-hwcd, a = -1). */
function pointDouble(p1) {
  const [X1, Y1, Z1] = p1;
  const a = (X1 * X1) % FIELD_P;
  const b = (Y1 * Y1) % FIELD_P;
  const c = (N2 * Z1 * Z1) % FIELD_P;
  const e = fmod((X1 + Y1) * (X1 + Y1) - a - b);
  const g = b - a; // D + B with D = a * A = -A
  const f = g - c;
  const h = -a - b; // D - B
  return [fmod(e * f), fmod(g * h), fmod(f * g), fmod(e * h)];
}

function scalarMultiply(k, point) {
  let acc = IDENTITY;
  let q = point;
  let e = k;
  while (e > N0) {
    if ((e & N1) === N1) acc = pointAdd(acc, q);
    q = pointDouble(q);
    e >>= N1;
  }
  return acc;
}

function pointsEqual(p1, p2) {
  return fmod(p1[0] * p2[2] - p2[0] * p1[2]) === N0 && fmod(p1[1] * p2[2] - p2[1] * p1[2]) === N0;
}

function isIdentityPoint(p1) {
  return fmod(p1[0]) === N0 && fmod(p1[1] - p1[2]) === N0;
}

const BASE_ENCODING = Uint8Array.from([
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);
/** The base point B (y = 4/5, x even). */
export const ED25519_BASE = decodePoint(BASE_ENCODING).point;

/**
 * The first of the three point conditions that fails, or null: 'noncanonical',
 * 'off-curve' or 'small-order'. Small order means [8]P is the identity.
 */
export function pointProblem(bytes) {
  const decoded = decodePoint(bytes);
  if (decoded.problem) return { problem: decoded.problem };
  const p8 = pointDouble(pointDouble(pointDouble(decoded.point)));
  if (isIdentityPoint(p8)) return { problem: 'small-order' };
  return { point: decoded.point };
}

/**
 * The 8 small-order encodings listed in spec section 2.1.1 (lowercase hex,
 * little-endian). Informative here: the check above computes [8]P.
 */
export const SMALL_ORDER_ENCODINGS = Object.freeze([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]);

/** The DER prefix of an Ed25519 SubjectPublicKeyInfo: 302a300506032b6570032100. */
export const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** The 44-byte DER SPKI of a raw 32-byte public key. */
export function spkiOf(publicKey32) {
  return concatBytes(ED25519_SPKI_PREFIX, publicKey32);
}

/** The raw 32 bytes of a 44-byte Ed25519 DER SPKI, or null. */
export function rawPublicKeyOf(spki) {
  if (!(spki instanceof Uint8Array) || spki.length !== 44) return null;
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i += 1)
    if (spki[i] !== ED25519_SPKI_PREFIX[i]) return null;
  return spki.subarray(12);
}

/**
 * Verifies one Ed25519 signature the way spec section 2.1.1 requires.
 * `publicKey` is the 32-byte key, `signature` 64 bytes, `message` the exact
 * signed bytes. `backend` supplies SHA-512 and the platform primitive.
 *
 * Returns { ok: true } | { ok: false, rule, detail } | { ok: null, rule:
 * 'ed25519.unavailable', detail }. `ok: null` is never a pass.
 */
export async function verifyEd25519(publicKey, message, signature, backend) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    return { ok: false, rule: 'ed25519.mismatch', detail: 'the signature is not 64 bytes' };
  }
  const a = pointProblem(publicKey);
  if (a.problem)
    return {
      ok: false,
      rule: `ed25519.key-${a.problem}`,
      detail: describeProblem('the public key', a.problem),
    };
  const rBytes = signature.subarray(0, 32);
  const r = pointProblem(rBytes);
  if (r.problem)
    return {
      ok: false,
      rule: `ed25519.r-${r.problem}`,
      detail: describeProblem("the signature's R", r.problem),
    };
  const s = leBytesToBigInt(signature.subarray(32));
  if (s >= ED25519_L)
    return {
      ok: false,
      rule: 'ed25519.s-not-reduced',
      detail: "the signature's S is not below the group order L",
    };
  const digest = await backend.sha512(concatBytes(rBytes, publicKey, message));
  const k = leBytesToBigInt(digest) % ED25519_L;
  const lhs = scalarMultiply(s, ED25519_BASE);
  const rhs = pointAdd(r.point, scalarMultiply(k, a.point));
  if (!pointsEqual(lhs, rhs)) {
    return {
      ok: false,
      rule: 'ed25519.mismatch',
      detail: 'the cofactorless equation [S]B = R + [k]A does not hold',
    };
  }
  let platform;
  try {
    platform = await backend.ed25519Verify(spkiOf(publicKey), message, signature);
  } catch {
    platform = null; // a primitive that throws has not said "valid"
  }
  if (platform === null) {
    return {
      ok: null,
      rule: 'ed25519.unavailable',
      detail:
        'this runtime cannot verify Ed25519 signatures, so nothing here can be VALID: use the CLI (cmdash-verify)',
    };
  }
  if (platform !== true) {
    return {
      ok: false,
      rule: 'ed25519.mismatch',
      detail:
        "the platform's Ed25519 refused a signature the cofactorless equation accepts; two implementations must agree",
    };
  }
  return { ok: true };
}

function describeProblem(what, problem) {
  if (problem === 'noncanonical')
    return `${what} is not a canonical encoding (y >= p, or x = 0 with the sign bit set)`;
  if (problem === 'off-curve') return `${what} is not on the curve (its y has no x)`;
  return `${what} is one of the 8 points of small order`;
}
