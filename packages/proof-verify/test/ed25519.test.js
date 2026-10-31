// SPDX-License-Identifier: Apache-2.0
/**
 * Point validation and the verification equation (spec section 2.1.1), made
 * by the verifier itself before any platform primitive: small-order,
 * non-canonical and off-curve encodings of A and of R, S >= L, and the
 * cofactorless equation. The expectations come from an INDEPENDENT affine
 * implementation below (Euler's criterion for squareness, the affine Edwards
 * law), not from the code under test.
 */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, test } from 'node:test';
import { nodeBackend } from '../lib/backend-node.mjs';
import {
  ED25519_L,
  SMALL_ORDER_ENCODINGS,
  decodePoint,
  pointProblem,
  verifyEd25519,
} from '../lib/ed25519.mjs';
import { byId, loadVectors, testKey } from './helpers.js';

// --- independent affine arithmetic (BigInt) ----------------------------------
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (x) => ((x % P) + P) % P;
const pow = (b, e) => {
  let r = 1n;
  let x = mod(b);
  for (let k = e; k > 0n; k >>= 1n) {
    if (k & 1n) r = (r * x) % P;
    x = (x * x) % P;
  }
  return r;
};
const inv = (x) => pow(x, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
const le = (bytes) => [...bytes].reverse().reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
const toLe32 = (n) =>
  Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));

/** 'noncanonical' | 'off-curve' | { x, y }, by Euler's criterion (a different method from the library's). */
function decodeAffine(bytes) {
  const sign = bytes[31] >> 7;
  const y = le(Uint8Array.from(bytes, (b, i) => (i === 31 ? b & 0x7f : b)));
  if (y >= P) return 'noncanonical';
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  if (x2 === 0n) return sign ? 'noncanonical' : { x: 0n, y };
  if (pow(x2, (P - 1n) / 2n) !== 1n) return 'off-curve';
  let x = pow(x2, (P + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * SQRT_M1);
  if (Number(x & 1n) !== sign) x = P - x;
  return { x, y };
}
const IDENTITY = { x: 0n, y: 1n };
function addAffine(p, q) {
  const t = mod(D * p.x * q.x * p.y * q.y);
  return {
    x: mod((p.x * q.y + p.y * q.x) * inv(1n + t)),
    y: mod((p.y * q.y + p.x * q.x) * inv(1n - t)),
  };
}
function mulAffine(k, p) {
  let acc = IDENTITY;
  let q = p;
  for (let e = k; e > 0n; e >>= 1n) {
    if (e & 1n) acc = addAffine(acc, q);
    q = addAffine(q, q);
  }
  return acc;
}
const isIdentity = (p) => p.x === 0n && p.y === 1n;
const encodeAffine = (p) => {
  const out = toLe32(p.y);
  out[31] |= Number(p.x & 1n) << 7;
  return out;
};
const BASE = decodeAffine(
  Buffer.from('5866666666666666666666666666666666666666666666666666666666666666', 'hex'),
);
const sha512 = (...parts) => {
  const h = createHash('sha512');
  for (const p of parts) h.update(p);
  return h.digest();
};

/** The independent classification spec section 2.1.1 step 1 asks for. */
function expectedProblem(bytes) {
  const d = decodeAffine(bytes);
  if (typeof d === 'string') return d;
  return isIdentity(mulAffine(8n, d)) ? 'small-order' : null;
}

// --- fixtures ----------------------------------------------------------------
const hex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const MESSAGE = new TextEncoder().encode('cmdash-receipt-v0\n{"a":1}');
const honest = testKey('ed25519 honest');
const honestSig = new Uint8Array(sign(null, MESSAGE, honest.privateKey));
/** y with no x on the curve, found by the independent test, and y = p, p + 1 (non-canonical). */
let OFF_CURVE_Y = null;
for (let y = 2n; OFF_CURVE_Y === null; y += 1n)
  if (decodeAffine(toLe32(y)) === 'off-curve') OFF_CURVE_Y = toLe32(y);
const NONCANONICAL = [
  toLe32(P), // y = p
  toLe32(P + 1n), // y = p + 1: the identity, spelled a second way (vector 65)
  hex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), // y = 2^255 - 1
  hex('0100000000000000000000000000000000000000000000000000000000000080'), // the identity with the sign bit set (x = 0)
  hex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), // y = p - 1 with the sign bit set (x = 0)
  hex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), // y = p with the sign bit set
];
const withR = (sig, r) => Uint8Array.from([...r, ...sig.subarray(32)]);
const withS = (sig, s) => Uint8Array.from([...sig.subarray(0, 32), ...toLe32(s)]);
const backendWith = (ed25519Verify) => ({ ...nodeBackend, ed25519Verify });
const yesMan = backendWith(async () => true); // a platform that accepts anything (the worst cofactored or buggy engine)

describe('point validation, by independent arithmetic', () => {
  test('the 8 encodings of spec section 2.1.1 are canonical curve points of order dividing 8, and are refused as small-order', () => {
    assert.equal(SMALL_ORDER_ENCODINGS.length, 8);
    for (const h of SMALL_ORDER_ENCODINGS) {
      const p = decodeAffine(hex(h));
      assert.equal(typeof p, 'object', `${h} decodes`);
      assert.ok(isIdentity(mulAffine(8n, p)), `[8]P = O for ${h}`);
      assert.equal(pointProblem(hex(h)).problem, 'small-order', h);
    }
  });

  test('on 300 pseudo-random encodings, the verifier classifies exactly as the independent decoder does', () => {
    const tally = { noncanonical: 0, 'off-curve': 0, 'small-order': 0, ok: 0 };
    for (let i = 0; i < 300; i += 1) {
      const b = Uint8Array.from(createHash('sha256').update(`point ${i}`).digest());
      const want = expectedProblem(b);
      assert.equal(pointProblem(b).problem ?? null, want, Buffer.from(b).toString('hex'));
      tally[want ?? 'ok'] += 1;
    }
    assert.ok(tally['off-curve'] > 100 && tally.ok > 100, JSON.stringify(tally));
  });

  test('non-canonical encodings (y >= p, or x = 0 with the sign bit set) are refused as non-canonical', () => {
    for (const b of NONCANONICAL) {
      assert.equal(expectedProblem(b), 'noncanonical', Buffer.from(b).toString('hex'));
      assert.equal(pointProblem(b).problem, 'noncanonical', Buffer.from(b).toString('hex'));
    }
  });

  test('a mixed-order point (prime-order point + a point of order 8) is NOT small-order: the blocklist alone cannot catch it', () => {
    const t8 = decodeAffine(hex(SMALL_ORDER_ENCODINGS[4]));
    const mixed = encodeAffine(addAffine(mulAffine(7n, BASE), t8));
    assert.equal(expectedProblem(mixed), null);
    assert.equal(pointProblem(mixed).problem, undefined);
  });

  test('decodePoint recovers the base point and refuses anything but 32 bytes', () => {
    const b = decodePoint(hex('5866666666666666666666666666666666666666666666666666666666666666'));
    assert.equal(b.point[0], BASE.x);
    assert.equal(b.point[1], BASE.y);
    assert.equal(decodePoint(new Uint8Array(31)).problem, 'noncanonical');
  });
});

describe('verifyEd25519: the checks run in order, before the platform', () => {
  const calls = { n: 0 };
  const counting = backendWith(async (...a) => {
    calls.n += 1;
    return nodeBackend.ed25519Verify(...a);
  });

  test('an honest signature verifies (the equation and the platform agree)', async () => {
    assert.deepEqual(await verifyEd25519(honest.raw, MESSAGE, honestSig, nodeBackend), {
      ok: true,
    });
  });

  test('public key A: small-order, non-canonical, off-curve are named, and the platform is never asked', async () => {
    calls.n = 0;
    for (const h of SMALL_ORDER_ENCODINGS)
      assert.equal(
        (await verifyEd25519(hex(h), MESSAGE, honestSig, counting)).rule,
        'ed25519.key-small-order',
        h,
      );
    for (const b of NONCANONICAL)
      assert.equal(
        (await verifyEd25519(b, MESSAGE, honestSig, counting)).rule,
        'ed25519.key-noncanonical',
      );
    assert.equal(
      (await verifyEd25519(OFF_CURVE_Y, MESSAGE, honestSig, counting)).rule,
      'ed25519.key-off-curve',
    );
    assert.equal(calls.n, 0, 'no platform call for a refused key');
  });

  test('point R: small-order, non-canonical, off-curve are named (under an honest key)', async () => {
    calls.n = 0;
    for (const h of SMALL_ORDER_ENCODINGS)
      assert.equal(
        (await verifyEd25519(honest.raw, MESSAGE, withR(honestSig, hex(h)), counting)).rule,
        'ed25519.r-small-order',
        h,
      );
    for (const b of NONCANONICAL)
      assert.equal(
        (await verifyEd25519(honest.raw, MESSAGE, withR(honestSig, b), counting)).rule,
        'ed25519.r-noncanonical',
      );
    assert.equal(
      (await verifyEd25519(honest.raw, MESSAGE, withR(honestSig, OFF_CURVE_Y), counting)).rule,
      'ed25519.r-off-curve',
    );
    assert.equal(calls.n, 0);
  });

  test('S >= L is refused (S + L is the classic malleation, vector 17)', async () => {
    const s = le(honestSig.subarray(32));
    for (const bad of [L, L + 1n, s + L, 2n ** 256n - 1n]) {
      assert.equal(
        (await verifyEd25519(honest.raw, MESSAGE, withS(honestSig, bad), counting)).rule,
        'ed25519.s-not-reduced',
      );
    }
    assert.equal(ED25519_L, L);
  });

  test('the order of the checks: A before R before S before the equation', async () => {
    const smallA = hex(SMALL_ORDER_ENCODINGS[0]);
    const badAll = withS(withR(honestSig, OFF_CURVE_Y), L);
    assert.equal(
      (await verifyEd25519(smallA, MESSAGE, badAll, nodeBackend)).rule,
      'ed25519.key-small-order',
    );
    assert.equal(
      (await verifyEd25519(honest.raw, MESSAGE, badAll, nodeBackend)).rule,
      'ed25519.r-off-curve',
    );
    assert.equal(
      (await verifyEd25519(honest.raw, MESSAGE, withS(honestSig, L), nodeBackend)).rule,
      'ed25519.s-not-reduced',
    );
    assert.equal(
      (await verifyEd25519(honest.raw, new TextEncoder().encode('other'), honestSig, nodeBackend))
        .rule,
      'ed25519.mismatch',
    );
  });

  test('vector 63: the identity key with R = identity and S = 0 (valid for ANY message in common libraries) is refused', async () => {
    const universal = new Uint8Array(64);
    universal[0] = 1; // R = identity (y = 1), S = 0
    const identity = hex(SMALL_ORDER_ENCODINGS[2]);
    // node:crypto itself accepts it; the verifier must not get that far.
    assert.equal(
      verify(
        null,
        Buffer.from('any message'),
        {
          key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), identity]),
          format: 'der',
          type: 'spki',
        },
        universal,
      ),
      true,
    );
    assert.equal(
      (await verifyEd25519(identity, MESSAGE, universal, yesMan)).rule,
      'ed25519.key-small-order',
    );
  });
});

describe("the cofactorless equation is the verifier's own", () => {
  test('a cofactored-only signature (R = [r]B + T, T of order 8) is refused even by a platform that accepts everything', async () => {
    // RFC 8032 key expansion of a test seed, then a hand-made signature whose R carries an order-8 component.
    const seed = createHash('sha256').update('p4 cofactored-only').digest();
    const h = sha512(seed);
    const aBytes = Uint8Array.from(h.subarray(0, 32));
    aBytes[0] &= 248;
    aBytes[31] &= 127;
    aBytes[31] |= 64;
    const a = le(aBytes);
    const A = mulAffine(a, BASE);
    const aEnc = encodeAffine(A);
    const r = le(sha512('p4 nonce')) % L;
    const t8 = decodeAffine(hex(SMALL_ORDER_ENCODINGS[4]));
    let R = null;
    let k = 0n;
    // Pick a message whose k is not a multiple of 8, or [k]T would vanish and the case be degenerate.
    let message;
    for (let i = 0; ; i += 1) {
      message = new TextEncoder().encode(`cofactored-only ${i}`);
      R = addAffine(mulAffine(r, BASE), t8);
      k = le(sha512(encodeAffine(R), aEnc, message)) % L;
      if (k % 8n !== 0n) break;
    }
    const s = (r + k * a) % L;
    const sig = Uint8Array.from([...encodeAffine(R), ...toLe32(s)]);
    // Independently: the cofactored equation holds and the cofactorless one does not.
    const lhs = mulAffine(s, BASE);
    const rhs = addAffine(R, mulAffine(k, A));
    assert.ok(!(lhs.x === rhs.x && lhs.y === rhs.y), 'cofactorless must fail');
    const l8 = mulAffine(8n, lhs);
    const r8 = mulAffine(8n, rhs);
    assert.ok(l8.x === r8.x && l8.y === r8.y, 'cofactored holds');
    assert.equal(
      pointProblem(encodeAffine(R)).problem,
      undefined,
      'R passes the point checks: only the equation can refuse it',
    );
    assert.equal((await verifyEd25519(aEnc, message, sig, yesMan)).rule, 'ed25519.mismatch');
  });

  test('vector 69 is refused with a platform that accepts everything; its honest twin is not', async () => {
    const vectors = loadVectors();
    const v = byId(vectors, '69-r-mixed-order-cofactored-only');
    const env = v.input.receipt;
    const spki = v.input.trust.keyDocument.keys.find((k) => k.kid === env.sig.kid).publicKey;
    const message = Uint8Array.from([
      ...Buffer.from('cmdash-receipt-v0\n'),
      ...Buffer.from(env.payload, 'base64url'),
    ]);
    const r = await verifyEd25519(
      Uint8Array.from(Buffer.from(spki, 'base64url').subarray(12)),
      message,
      Uint8Array.from(Buffer.from(env.sig.value, 'base64url')),
      yesMan,
    );
    assert.equal(r.rule, 'ed25519.mismatch');
    assert.deepEqual(await verifyEd25519(honest.raw, MESSAGE, honestSig, yesMan), { ok: true });
  });

  test('100 fresh keys: every honest signature verifies, every one-bit flip of the signature or message is refused', async () => {
    for (let i = 0; i < 100; i += 1) {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const raw = Uint8Array.from(publicKey.export({ type: 'spki', format: 'der' }).subarray(12));
      const msg = new TextEncoder().encode(`message ${i}`);
      const sig = Uint8Array.from(sign(null, msg, privateKey));
      assert.equal((await verifyEd25519(raw, msg, sig, yesMan)).ok, true, 'honest');
      const flipped = Uint8Array.from(sig);
      flipped[i % 64] ^= 1 << (i % 8);
      assert.notEqual(
        (await verifyEd25519(raw, msg, flipped, yesMan)).ok,
        true,
        `signature bit ${i}`,
      );
      const other = Uint8Array.from(msg);
      other[0] ^= 1;
      assert.notEqual((await verifyEd25519(raw, other, sig, yesMan)).ok, true, `message bit ${i}`);
    }
  });
});

describe('the platform must agree, and its absence is never VALID', () => {
  test('a platform that refuses an honest signature makes it ed25519.mismatch', async () => {
    const r = await verifyEd25519(
      honest.raw,
      MESSAGE,
      honestSig,
      backendWith(async () => false),
    );
    assert.equal(r.ok, false);
    assert.equal(r.rule, 'ed25519.mismatch');
  });

  test('a runtime without Ed25519 (null, or a throwing primitive) is ed25519.unavailable, never ok', async () => {
    for (const primitive of [
      async () => null,
      async () => Promise.reject(new Error('NotSupportedError')),
      () => {
        throw new Error('boom');
      },
    ]) {
      const r = await verifyEd25519(honest.raw, MESSAGE, honestSig, backendWith(primitive));
      assert.equal(r.ok, null);
      assert.equal(r.rule, 'ed25519.unavailable');
      assert.match(r.detail, /use the CLI/);
    }
  });

  test('without Ed25519 a forged signature is still refused by the equation (INVALID beats "unavailable")', async () => {
    const forged = Uint8Array.from(honestSig);
    forged[40] ^= 4;
    const r = await verifyEd25519(
      honest.raw,
      MESSAGE,
      forged,
      backendWith(async () => null),
    );
    assert.equal(r.rule, 'ed25519.mismatch');
  });

  test('a signature that is not 64 bytes is refused', async () => {
    assert.equal(
      (await verifyEd25519(honest.raw, MESSAGE, honestSig.subarray(0, 63), nodeBackend)).rule,
      'ed25519.mismatch',
    );
  });
});
