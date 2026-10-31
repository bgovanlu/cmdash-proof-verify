// SPDX-License-Identifier: Apache-2.0
/**
 * Checkpoint consistency (spec section 7.7): RFC 9162 section 2.1.4
 * consistency proofs, and verifyCheckpointConsistency over two signed notes.
 *
 * Held three ways:
 *  1. the published RFC 6962 / Certificate Transparency consistency proofs
 *     for the eight standard test leaves;
 *  2. an INDEPENDENT reference written below: the proof generator is the
 *     RFC's SUBPROOF recursion verbatim, and the reference verifier is the
 *     other published formulation (the inner/border decomposition used by
 *     transparency-dev/merkle), not the RFC's step list the library follows;
 *  3. forked-history attacks, each of which must fail.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { nodeBackend } from '../lib/backend-node.mjs';
import { webCryptoBackend } from '../lib/backend-web.mjs';
import { MAX_CONSISTENCY_PROOF, merkleLeafHash, verifyConsistency } from '../lib/merkle.mjs';
import {
  CONSISTENCY_CHECK_NAMES,
  verifyCheckpointConsistency,
  verifyReceipt,
} from '../lib/verify.mjs';
import * as browser from '../browser/verify.js';
import {
  checkpointNote,
  leafHashOf,
  logKeyDocument,
  logKeyEntry,
  nodeHashOf,
  sha256,
  testKey,
  treeHash,
} from './helpers.js';

const u8 = (b) => Uint8Array.from(b);
const hex = (b) => Buffer.from(b).toString('hex');
const EMPTY_ROOT = sha256(Buffer.alloc(0));

// ─── the independent reference ──────────────────────────────────────────────

const splitOf = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** RFC 9162 section 2.1.4.1, verbatim: SUBPROOF(m, D[n], b). */
function subproof(m, leaves, b) {
  const n = leaves.length;
  if (m === n) return b ? [] : [treeHash(leaves)];
  const k = splitOf(n);
  if (m <= k) return [...subproof(m, leaves.slice(0, k), b), treeHash(leaves.slice(k))];
  return [...subproof(m - k, leaves.slice(k), false), treeHash(leaves.slice(0, k))];
}
/** PROOF(m, D[n]) for 0 < m < n; empty for m = n. */
const refProof = (m, leaves) => (m === leaves.length ? [] : subproof(m, leaves, true));

const bitLength = (x) => x.toString(2).replace(/^0+/, '').length;
const popCount = (x) => [...x.toString(2)].filter((c) => c === '1').length;
const trailingZeros = (x) => {
  let z = 0n;
  while (((x >> z) & 1n) === 0n) z += 1n;
  return z;
};

/**
 * The inner/border formulation of consistency verification
 * (transparency-dev/merkle proof.VerifyConsistency), on BigInt, with this
 * spec's stricter size-0 rule (root1 must be MTH({})).
 */
function refVerify(size1, size2, root1, root2, proof) {
  const eq = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
  if (size2 < size1) return false;
  if (size1 === size2) return proof.length === 0 && eq(root1, root2);
  if (size1 === 0) return proof.length === 0 && eq(root1, EMPTY_ROOT);
  if (proof.length === 0) return false;
  const s1 = BigInt(size1);
  const s2 = BigInt(size2);
  const index = s1 - 1n;
  let inner = BigInt(bitLength(index ^ (s2 - 1n)));
  const border = BigInt(popCount(index >> inner));
  const shift = trailingZeros(s1);
  inner -= shift;
  let seed = proof[0];
  let start = 1;
  if (s1 === 1n << shift) {
    seed = root1;
    start = 0;
  }
  if (BigInt(proof.length) !== BigInt(start) + inner + border) return false;
  const rest = proof.slice(start);
  const mask = index >> shift;
  const innerPart = rest.slice(0, Number(inner));
  const borderPart = rest.slice(Number(inner));
  let h1 = seed;
  innerPart.forEach((h, i) => {
    if (((mask >> BigInt(i)) & 1n) === 1n) h1 = nodeHashOf(h, h1);
  });
  for (const h of borderPart) h1 = nodeHashOf(h, h1);
  if (!eq(h1, root1)) return false;
  let h2 = seed;
  innerPart.forEach((h, i) => {
    h2 = ((mask >> BigInt(i)) & 1n) === 0n ? nodeHashOf(h2, h) : nodeHashOf(h, h2);
  });
  for (const h of borderPart) h2 = nodeHashOf(h, h2);
  return eq(h2, root2);
}

const lib = (s1, s2, r1, r2, proof, backend = nodeBackend) =>
  verifyConsistency(s1, s2, u8(r1), u8(r2), proof.map(u8), backend);

// ─── 1. published vectors ───────────────────────────────────────────────────

const RFC_ENTRIES = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
];
const RFC_LEAVES = RFC_ENTRIES.map((h) => leafHashOf(Buffer.from(h, 'hex')));
/** Certificate Transparency's published consistency proofs over the eight RFC 6962 test leaves. */
const PUBLISHED = [
  [1, 1, []],
  [
    1,
    8,
    [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  ],
  [
    6,
    8,
    [
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  ],
  [
    2,
    5,
    [
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  ],
];

describe('RFC 9162 consistency proofs', () => {
  test('the published Certificate Transparency proofs: the reference generates them, both verifiers accept them', async () => {
    for (const [m, n, expected] of PUBLISHED) {
      const leaves = RFC_LEAVES.slice(0, n);
      const proof = refProof(m, leaves);
      assert.deepEqual(proof.map(hex), expected, `PROOF(${m}, D[${n}])`);
      const r1 = treeHash(RFC_LEAVES.slice(0, m));
      const r2 = treeHash(leaves);
      assert.equal(await lib(m, n, r1, r2, proof), true, `${m}->${n}`);
      assert.equal(refVerify(m, n, r1, r2, proof), true, `reference ${m}->${n}`);
    }
  });

  test('every pair of sizes 1..40 (1, powers of two, everything between): the reference proof verifies in both verifiers, and every mutation fails in both', async () => {
    const leaves = Array.from({ length: 40 }, (_, i) => leafHashOf(sha256(`leaf ${i}`)));
    const roots = [EMPTY_ROOT, ...leaves.map((_, i) => treeHash(leaves.slice(0, i + 1)))];
    let checked = 0;
    for (let n = 1; n <= 40; n += 1) {
      for (let m = 1; m <= n; m += 1) {
        const proof = refProof(m, leaves.slice(0, n));
        assert.ok(proof.length <= MAX_CONSISTENCY_PROOF);
        const both = async (s1, s2, r1, r2, p) => {
          const a = await lib(s1, s2, r1, r2, p);
          assert.equal(a, refVerify(s1, s2, r1, r2, p), `verifiers disagree at ${s1}->${s2}`);
          return a;
        };
        assert.equal(await both(m, n, roots[m], roots[n], proof), true, `${m}->${n}`);
        // every one-bit flip of every proof hash
        for (let j = 0; j < proof.length; j += 1) {
          const bad = proof.map((x) => Buffer.from(x));
          bad[j][j % 32] ^= 1 << (j % 8);
          assert.equal(await both(m, n, roots[m], roots[n], bad), false, `flip ${j} ${m}->${n}`);
        }
        // a wrong root on either side
        const flipped = Buffer.from(roots[n]);
        flipped[0] ^= 1;
        assert.equal(await both(m, n, roots[m], flipped, proof), false);
        const flipped1 = Buffer.from(roots[m]);
        flipped1[31] ^= 0x80;
        assert.equal(await both(m, n, flipped1, roots[n], proof), false);
        // a proof one hash too long or too short
        assert.equal(await both(m, n, roots[m], roots[n], [...proof, roots[n]]), false);
        if (proof.length > 0)
          assert.equal(await both(m, n, roots[m], roots[n], proof.slice(0, -1)), false);
        // the proof claimed for other sizes
        if (n < 40 && m < n)
          assert.equal(await both(m, n + 1, roots[m], roots[n + 1], proof), false);
        if (m > 1 && m < n)
          assert.equal(await both(m - 1, n, roots[m - 1], roots[n], proof), false);
        checked += 1;
      }
    }
    assert.equal(checked, 820);
  });

  test('sizes beyond 2^32 (no 32-bit shift anywhere)', async () => {
    const x = sha256('the first 2^33 leaves');
    const [l1, l2] = [leafHashOf(sha256('a')), leafHashOf(sha256('b'))];
    const big = 2 ** 33;
    // PROOF(2^33, D[2^33 + 1]) = [leaf 2^33]
    assert.equal(await lib(big, big + 1, x, nodeHashOf(x, l1), [l1]), true);
    assert.equal(refVerify(big, big + 1, x, nodeHashOf(x, l1), [l1]), true);
    // PROOF(2^33 + 1, D[2^33 + 2]) = [leaf 2^33, leaf 2^33 + 1, MTH(first 2^33)]
    const r1 = nodeHashOf(x, l1);
    const r2 = nodeHashOf(x, nodeHashOf(l1, l2));
    assert.equal(await lib(big + 1, big + 2, r1, r2, [l1, l2, x]), true);
    assert.equal(await lib(big + 1, big + 2, r1, r2, [l2, l1, x]), false);
  });

  test('from = to: an empty proof and equal roots; from = 0: an empty proof and the empty-tree root (RFC 9162: MTH({}) = SHA-256())', async () => {
    const r = sha256('r');
    assert.equal(await lib(5, 5, r, r, []), true);
    assert.equal(await lib(5, 5, r, sha256('other'), []), false);
    assert.equal(await lib(5, 5, r, r, [r]), false);
    assert.equal(await lib(0, 5, EMPTY_ROOT, r, []), true);
    assert.equal(await lib(0, 0, EMPTY_ROOT, EMPTY_ROOT, []), true);
    assert.equal(await lib(0, 5, EMPTY_ROOT, r, [r]), false);
    assert.equal(await lib(0, 5, sha256('not empty'), r, []), false);
    assert.equal(refVerify(0, 5, EMPTY_ROOT, r, []), true);
  });

  test('refused inputs: sizes out of order, unsafe or negative, a short hash, a non-array, an over-long proof, an empty proof', async () => {
    const r = sha256('r');
    assert.equal(await lib(6, 5, r, r, [r]), false);
    assert.equal(await lib(-1, 5, r, r, [r]), false);
    assert.equal(await lib(1, 2 ** 53, r, r, [r]), false);
    assert.equal(await lib(1.5, 2, r, r, [r]), false);
    assert.equal(await lib(1, 2, r, r, [r.subarray(0, 31)]), false);
    assert.equal(await verifyConsistency(1, 2, u8(r), u8(r), 'nope', nodeBackend), false);
    assert.equal(await verifyConsistency(1, 2, u8(r), u8(r), [[1, 2]], nodeBackend), false);
    const long = Array.from({ length: MAX_CONSISTENCY_PROOF + 1 }, () => r);
    assert.equal(await lib(3, 1000, r, r, long), false);
    assert.equal(await lib(3, 4, r, r, []), false);
  });

  test('the WebCrypto backend gives the same answers', async () => {
    const web = webCryptoBackend(globalThis.crypto);
    const leaves = Array.from({ length: 13 }, (_, i) => leafHashOf(sha256(`w ${i}`)));
    for (const m of [1, 4, 5, 13]) {
      const proof = refProof(m, leaves);
      const r1 = treeHash(leaves.slice(0, m));
      const r2 = treeHash(leaves);
      assert.equal(await lib(m, 13, r1, r2, proof, web), true);
    }
    assert.equal(await lib(0, 13, EMPTY_ROOT, treeHash(leaves), [], web), true);
    // the library hashes leaves the same way
    assert.equal(hex(await merkleLeafHash(u8(sha256('w 0')), web)), hex(leaves[0]));
  });
});

// ─── 2. checkpoint consistency ──────────────────────────────────────────────

const ORIGIN = 'cmdash.example/cmdash-proof-log';
const LOG_KEY = testKey('consistency log');
const OTHER_KEY = testKey('consistency other');
const KEYS = logKeyDocument(ORIGIN, [logKeyEntry(LOG_KEY)]);
const honest = Array.from({ length: 21 }, (_, i) => leafHashOf(sha256(`entry ${i}`)));
const rootOf = (leaves, n) => treeHash(leaves.slice(0, n));
const noteOf = (leaves, n, signers = [LOG_KEY], origin = ORIGIN) =>
  checkpointNote(origin, n, rootOf(leaves, n), signers);
const proofHex = (leaves, m, n) => refProof(m, leaves.slice(0, n)).map(hex);

async function judge(input, trust = { logKeys: KEYS }, options) {
  const r = await verifyCheckpointConsistency(input, trust, options);
  assert.deepEqual(
    r.checks.map((c) => c.name),
    CONSISTENCY_CHECK_NAMES,
  );
  for (const c of r.checks) assert.match(`${c.detail}`, /^[\x20-\x7e]*$/);
  return r;
}
const failing = (r) => r.checks.find((c) => c.outcome === 'FAIL');

describe('verifyCheckpointConsistency', () => {
  test('CONSISTENT for honest checkpoints of sizes 1, a power of two and not, and equal sizes', async () => {
    for (const [m, n] of [
      [1, 1],
      [1, 21],
      [4, 16],
      [8, 13],
      [13, 21],
      [21, 21],
    ]) {
      const r = await judge({
        from: noteOf(honest, m),
        to: noteOf(honest, n),
        proof: proofHex(honest, m, n),
      });
      assert.equal(r.verdict, 'CONSISTENT', `${m}->${n}: ${r.summary}`);
      assert.deepEqual(
        r.checks.map((c) => c.outcome),
        ['PASS', 'PASS', 'PASS', 'PASS'],
      );
      assert.deepEqual(r.from, { size: m, rootHash: hex(rootOf(honest, m)) });
      assert.deepEqual(r.to, { size: n, rootHash: hex(rootOf(honest, n)) });
    }
  });

  test('bytes and text for the notes and the log key document; an explicit null trust member reads as absent', async () => {
    const r = await judge(
      {
        from: Buffer.from(noteOf(honest, 3)),
        to: new TextEncoder().encode(noteOf(honest, 7)),
        proof: proofHex(honest, 3, 7),
      },
      { logKeys: JSON.stringify(KEYS) },
    );
    assert.equal(r.verdict, 'CONSISTENT');
    const none = await judge(
      { from: noteOf(honest, 3), to: noteOf(honest, 7), proof: proofHex(honest, 3, 7) },
      { logKeys: null },
    );
    assert.equal(none.verdict, 'UNVERIFIABLE');
    assert.equal(failing(none).rule, 'consistency.no-log-keys');
  });

  describe('forked-history attacks: each MUST fail', () => {
    // The fork: the log shows some relying parties a tree whose leaf 5 differs.
    const forked = honest.map((l, i) => (i === 5 ? leafHashOf(sha256('rewritten entry 5')) : l));

    test('same size, different root (equivocation): INCONSISTENT, whatever the proof', async () => {
      for (const proof of [[], proofHex(honest, 8, 8), [hex(sha256('x'))]]) {
        const r = await judge({ from: noteOf(honest, 8), to: noteOf(forked, 8), proof });
        assert.equal(r.verdict, 'INCONSISTENT');
        assert.equal(failing(r).rule, 'consistency.equivocation');
      }
    });

    test('the from-tree is not a prefix of the to-tree: neither the honest proof nor the forked one verifies', async () => {
      for (const [m, n] of [
        [6, 21],
        [8, 16],
        [7, 9],
      ]) {
        for (const proof of [proofHex(honest, m, n), proofHex(forked, m, n)]) {
          const r = await judge({ from: noteOf(honest, m), to: noteOf(forked, n), proof });
          assert.equal(r.verdict, 'INCONSISTENT', `${m}->${n}`);
          assert.equal(failing(r).rule, 'consistency.proof');
        }
      }
    });

    test('a history rewritten before the from-size, then re-extended: INCONSISTENT', async () => {
      const r = await judge({
        from: noteOf(forked, 12),
        to: noteOf(honest, 20),
        proof: proofHex(honest, 12, 20),
      });
      assert.equal(r.verdict, 'INCONSISTENT');
    });

    test('a tampered proof node: every hash, one bit each', async () => {
      const proof = proofHex(honest, 11, 20);
      for (let j = 0; j < proof.length; j += 1) {
        const bad = [...proof];
        const b = Buffer.from(bad[j], 'hex');
        b[j] ^= 0x01;
        bad[j] = b.toString('hex');
        const r = await judge({ from: noteOf(honest, 11), to: noteOf(honest, 20), proof: bad });
        assert.equal(r.verdict, 'INCONSISTENT', `hash ${j}`);
      }
    });

    test('a proof of the wrong length: truncated, extended, empty, reordered, or the proof for other sizes', async () => {
      const good = proofHex(honest, 11, 20);
      for (const proof of [
        good.slice(0, -1),
        good.slice(1),
        [...good, good[0]],
        [],
        [...good].reverse(),
        proofHex(honest, 10, 20),
        proofHex(honest, 11, 19),
      ]) {
        const r = await judge({ from: noteOf(honest, 11), to: noteOf(honest, 20), proof });
        assert.equal(r.verdict, 'INCONSISTENT');
      }
    });

    test('from = to with different roots is equivocation; with equal roots a non-empty proof is refused', async () => {
      const r = await judge({ from: noteOf(honest, 20), to: noteOf(forked, 20), proof: [] });
      assert.equal(r.verdict, 'INCONSISTENT');
      const extra = await judge({
        from: noteOf(honest, 20),
        to: noteOf(honest, 20),
        proof: [hex(sha256('pad'))],
      });
      assert.equal(extra.verdict, 'INCONSISTENT');
    });

    test('from = 0: consistent only as the empty tree, with an empty proof', async () => {
      const empty = checkpointNote(ORIGIN, 0, EMPTY_ROOT, [LOG_KEY]);
      const ok = await judge({ from: empty, to: noteOf(honest, 9), proof: [] });
      assert.equal(ok.verdict, 'CONSISTENT');
      const withProof = await judge({
        from: empty,
        to: noteOf(honest, 9),
        proof: [hex(sha256('x'))],
      });
      assert.equal(withProof.verdict, 'INCONSISTENT');
      const notEmpty = checkpointNote(ORIGIN, 0, sha256('something'), [LOG_KEY]);
      const lie = await judge({ from: notEmpty, to: noteOf(honest, 9), proof: [] });
      assert.equal(lie.verdict, 'INCONSISTENT');
    });

    test('a forged checkpoint (a key the relying party does not trust, or a bad signature) is UNVERIFIABLE, never CONSISTENT', async () => {
      const forgedTo = noteOf(forked, 20, [OTHER_KEY]);
      const r = await judge({
        from: noteOf(honest, 11),
        to: forgedTo,
        proof: proofHex(forked, 11, 20),
      });
      assert.equal(r.verdict, 'UNVERIFIABLE');
      assert.equal(failing(r).name, 'consistency.to-signed');
      assert.equal(failing(r).rule, 'external.unsigned');
      // a signature line claiming the trusted key over another body
      const good = noteOf(honest, 11);
      const sig = good.slice(good.indexOf('\n\n'));
      const tampered = `${ORIGIN}\n11\n${rootOf(forked, 11).toString('base64')}${sig}`;
      const bad = await judge({ from: tampered, to: noteOf(honest, 20), proof: [] });
      assert.equal(bad.verdict, 'UNVERIFIABLE');
      assert.equal(failing(bad).name, 'consistency.from-signed');
      assert.equal(failing(bad).rule, 'checkpoint.signature');
    });
  });

  test('UNVERIFIABLE inputs: malformed proof, malformed notes, two logs, reversed order', async () => {
    const from = noteOf(honest, 3);
    const to = noteOf(honest, 7);
    const cases = [
      [null, 'consistency.malformed'],
      [{ from, to }, 'consistency.malformed'],
      [{ from, to, proof: ['AB'.repeat(32)] }, 'consistency.malformed'],
      [{ from, to, proof: [7] }, 'consistency.malformed'],
      [
        { from, to, proof: Array.from({ length: 65 }, () => hex(sha256('p'))) },
        'consistency.malformed',
      ],
      [{ from: 'not a note', to, proof: [] }, 'consistency.malformed'],
      [{ from, to: new Uint8Array([0xff, 0xfe]), proof: [] }, 'consistency.malformed'],
      [
        { from, to: noteOf(honest, 7, [LOG_KEY], 'other.example/log'), proof: [] },
        'consistency.other-log',
      ],
      [{ from: to, to: from, proof: [] }, 'consistency.order'],
    ];
    for (const [input, rule] of cases) {
      const r = await judge(input);
      assert.equal(r.verdict, 'UNVERIFIABLE', rule);
      assert.equal(failing(r).name, 'consistency.input');
      assert.equal(failing(r).rule, rule);
      assert.ok(r.checks.slice(1).every((c) => c.outcome === 'SKIP'));
    }
  });

  test('UNVERIFIABLE trust: a malformed log key document, keys of another log, a revoked key, a retired key beyond its last tree size', async () => {
    const input = { from: noteOf(honest, 3), to: noteOf(honest, 7), proof: proofHex(honest, 3, 7) };
    const malformed = await judge(input, { logKeys: '{"format":' });
    assert.equal(failing(malformed).rule, 'log-keys.malformed');
    const schema = await judge(input, { logKeys: { format: 'nope' } });
    assert.equal(failing(schema).rule, 'log-keys.malformed');
    const otherLog = await judge(input, {
      logKeys: logKeyDocument('other.example/log', [logKeyEntry(LOG_KEY)]),
    });
    assert.equal(failing(otherLog).rule, 'consistency.other-log');
    const revoked = await judge(input, {
      logKeys: logKeyDocument(ORIGIN, [
        logKeyEntry(LOG_KEY, 'REVOKED', { validUntil: '2026-09-15T00:00:00.000Z' }),
      ]),
    });
    assert.equal(failing(revoked).rule, 'external.unsigned');
    const retired = await judge(input, {
      logKeys: logKeyDocument(ORIGIN, [
        logKeyEntry(LOG_KEY, 'RETIRED', {
          validUntil: '2026-09-15T00:00:00.000Z',
          lastTreeSize: 5,
        }),
      ]),
    });
    assert.equal(failing(retired).name, 'consistency.to-signed');
    assert.equal(failing(retired).rule, 'log-key.beyond-last-tree-size');
    for (const r of [malformed, schema, otherLog, revoked, retired])
      assert.equal(r.verdict, 'UNVERIFIABLE');
  });

  test('without WebCrypto or without Ed25519: UNVERIFIABLE, never CONSISTENT; a non-backend throws', async () => {
    const input = { from: noteOf(honest, 3), to: noteOf(honest, 7), proof: proofHex(honest, 3, 7) };
    const noCrypto = await judge(
      input,
      { logKeys: KEYS },
      { backend: webCryptoBackend(undefined) },
    );
    assert.equal(noCrypto.verdict, 'UNVERIFIABLE');
    assert.equal(failing(noCrypto).rule, 'ed25519.unavailable');
    const noEd = { ...nodeBackend, ed25519Verify: async () => null };
    const r = await judge(input, { logKeys: KEYS }, { backend: noEd });
    assert.equal(r.verdict, 'UNVERIFIABLE');
    assert.equal(failing(r).rule, 'ed25519.unavailable');
    await assert.rejects(
      () => verifyCheckpointConsistency(input, { logKeys: KEYS }, { backend: {} }),
      TypeError,
    );
  });

  test('the browser build answers the same, with WebCrypto by default', async () => {
    const input = {
      from: noteOf(honest, 5),
      to: noteOf(honest, 17),
      proof: proofHex(honest, 5, 17),
    };
    const ok = await browser.verifyCheckpointConsistency(input, { logKeys: KEYS });
    assert.equal(ok.verdict, 'CONSISTENT');
    const bad = await browser.verifyCheckpointConsistency(
      { ...input, proof: proofHex(honest, 4, 17) },
      { logKeys: KEYS },
    );
    assert.equal(bad.verdict, 'INCONSISTENT');
    assert.deepEqual(browser.CONSISTENCY_CHECK_NAMES, CONSISTENCY_CHECK_NAMES);
    // receipt verification is untouched by the new module
    assert.equal(typeof browser.verifyReceipt, 'function');
    assert.equal(typeof verifyReceipt, 'function');
  });
});
