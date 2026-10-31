// SPDX-License-Identifier: Apache-2.0
/**
 * The transparency log (spec section 7): RFC 9162 hashing and inclusion
 * proofs, C2SP signed-note checkpoints, and how a checkpoint is judged
 * against a trusted log key set.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import { nodeBackend } from '../lib/backend-node.mjs';
import { merkleLeafHash, merkleNodeHash, verifyInclusion } from '../lib/merkle.mjs';
import { judgeCheckpoint, noteKeyHash, parseCheckpoint } from '../lib/note.mjs';
import {
  auditPath,
  byId,
  checkpointNote,
  leafHashOf,
  loadVectors,
  sha256,
  testKey,
  treeHash,
} from './helpers.js';

const vectors = loadVectors();
const u8 = (b) => Uint8Array.from(b);

describe('RFC 9162 Merkle trees', () => {
  test('the RFC 6962 reference roots for its eight standard test leaves', async () => {
    const inputs = [
      '',
      '00',
      '10',
      '2021',
      '3031',
      '40414243',
      '5051525354555657',
      '606162636465666768696a6b6c6d6e6f',
    ];
    const leaves = [];
    for (const h of inputs)
      leaves.push(Buffer.from(await merkleLeafHash(u8(Buffer.from(h, 'hex')), nodeBackend)));
    const roots = [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
      'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
      '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
      '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
      'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
      '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    ];
    roots.forEach((root, i) =>
      assert.equal(treeHash(leaves.slice(0, i + 1)).toString('hex'), root, `size ${i + 1}`),
    );
    assert.deepEqual(
      Buffer.from(await merkleNodeHash(u8(leaves[0]), u8(leaves[1]), nodeBackend)).toString('hex'),
      roots[1],
    );
  });

  test('trees of 1..33 leaves: every proof verifies; a flipped bit, a wrong index, an extra element or an index outside fails', async () => {
    for (let n = 1; n <= 33; n += 1) {
      const leaves = Array.from({ length: n }, (_, i) => leafHashOf(sha256(`leaf ${i}`)));
      const root = u8(treeHash(leaves));
      for (let m = 0; m < n; m += 1) {
        const path = auditPath(m, leaves).map(u8);
        assert.ok(await verifyInclusion(m, n, u8(leaves[m]), path, root, nodeBackend), `${m}/${n}`);
        if (n > 1)
          assert.equal(
            await verifyInclusion((m + 1) % n, n, u8(leaves[m]), path, root, nodeBackend),
            false,
          );
        for (let j = 0; j < path.length; j += 1) {
          const bad = path.map((x) => Uint8Array.from(x));
          bad[j][j % 32] ^= 1 << (j % 8);
          assert.equal(await verifyInclusion(m, n, u8(leaves[m]), bad, root, nodeBackend), false);
        }
        assert.equal(
          await verifyInclusion(m, n, u8(leaves[m]), [...path, root], root, nodeBackend),
          false,
          'an extra element',
        );
      }
      assert.equal(
        await verifyInclusion(n, n, u8(leaves[0]), [], root, nodeBackend),
        false,
        'index outside',
      );
      assert.equal(await verifyInclusion(-1, n, u8(leaves[0]), [], root, nodeBackend), false);
    }
  });

  test('indexes beyond 2^32 work (no 32-bit shift anywhere)', async () => {
    const leaf = u8(leafHashOf(sha256('big')));
    // A one-element path for the last leaf of a tree of 2^40 + 1 leaves: the leaf is the right child of the root.
    const left = u8(sha256('left subtree'));
    const root = u8(
      createHash('sha256')
        .update(Buffer.from([1]))
        .update(left)
        .update(leaf)
        .digest(),
    );
    assert.ok(await verifyInclusion(2 ** 40, 2 ** 40 + 1, leaf, [left], root, nodeBackend));
    assert.equal(
      await verifyInclusion(2 ** 40, 2 ** 40 + 2, leaf, [left], root, nodeBackend),
      false,
    );
  });
});

describe('checkpoints: C2SP signed notes (spec section 7.3)', () => {
  const good = byId(vectors, '06-valid-logged').input.receipt.log.checkpoint;

  test("the key hash and signature match golang.org/x/mod/sumdb/note's published example", async () => {
    // A PUBLIC verifier key from the note package's documentation example (not a secret).
    const vkey = 'PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW'; // gitleaks:allow
    const [name, hash, key] = vkey.split('+');
    const raw = u8(Buffer.from(key, 'base64').subarray(1));
    assert.equal(Buffer.from(await noteKeyHash(name, raw, nodeBackend)).toString('hex'), hash);
  });

  test('a well-formed checkpoint parses; extension lines and unknown signature lines are kept aside', () => {
    const p = parseCheckpoint(good);
    assert.equal(p.ok, true);
    assert.equal(p.origin, 'cmdash.example/cmdash-proof-log');
    assert.equal(p.size, 7);
    assert.equal(p.signatures.length, 1);
    const withExtension = good.replace('=\n\n', '=\nextension line\n\n');
    assert.equal(parseCheckpoint(withExtension).ok, true);
    assert.equal(parseCheckpoint(`${good}\u{2014} someone-else AAAAAAAA\n`).ok, true);
  });

  test("malformed notes are refused: the checker's list, and the spec's printable-ASCII rule", () => {
    const bad = [
      good.replace('\n7\n', '\n07\n'),
      good.replace('\n\n', '\n'),
      good.replace('\u{2014} ', '- '),
      good.replace(/=\n\n/, '\n\n'),
      good.replace('cmdash.example/cmdash-proof-log\n', 'cmdash.example/cmdash proof-log\n'),
      good.replace('cmdash.example', 'cmdash\u{e9}.example'),
      good.replace('cmdash.example', `cmdash${String.fromCharCode(0xd800)}.example`),
      `${good}\n`,
      good.replace('=\n\n', '=\n\u{2014} an em dash in an extension line\n\n'),
      good.replace('=\n\n', '=\n\n\n'),
      good.replace('\n7\n', '\n9007199254740992\n'),
      good.replace('cmdash.example/cmdash-proof-log\n', `${'o'.repeat(256)}\n`),
      good.replace('cmdash.example/cmdash-proof-log\n', 'a+b\n'),
      good.slice(0, -1),
      `${good.slice(0, -1)}\u{2014} x\n`,
      good.replace(/ ([A-Za-z0-9+/]+=*)\n$/, ' AAAA\n'),
      42,
    ];
    for (const note of bad)
      assert.equal(parseCheckpoint(note).ok, false, JSON.stringify(String(note).slice(0, 80)));
  });

  test('a checkpoint is at most 8192 characters (spec section 9.4)', () => {
    const pad = (n) => good.replace('=\n\n', `=\n${'x'.repeat(n)}\n\n`);
    const exact = pad(8192 - good.length - 1);
    assert.equal(exact.length, 8192);
    assert.equal(parseCheckpoint(exact).ok, true);
    assert.equal(parseCheckpoint(pad(8192 - good.length)).ok, false);
  });

  describe('judging a checkpoint against a trusted log key set', () => {
    const origin = 'cmdash.example/cmdash-proof-log';
    const root = sha256('some root');
    const [k7, k20, kA, kR] = ['retired at 7', 'retired at 20', 'active', 'revoked'].map((l) =>
      testKey(`log ${l}`),
    );
    const entry = (k, status, more = {}) => ({ kid: k.logKid, status, raw: u8(k.raw), ...more });
    const r7 = entry(k7, 'RETIRED', { lastTreeSize: 7 });
    const r20 = entry(k20, 'RETIRED', { lastTreeSize: 20 });
    const active = entry(kA, 'ACTIVE');
    const revoked = entry(kR, 'REVOKED');
    const judge = async (signers, keys, size = 15) =>
      (
        await judgeCheckpoint(
          parseCheckpoint(checkpointNote(origin, size, root, signers)),
          { origin, keys },
          nodeBackend,
        )
      ).result;

    test('the outcome does not depend on the order of the lines or of the keys', async () => {
      for (const keys of [
        [r7, r20],
        [r20, r7],
      ]) {
        assert.equal(await judge([k7, k20], keys), 'PASS');
        assert.equal(await judge([k20, k7], keys), 'PASS');
        assert.equal(await judge([k7], keys), 'BEYOND');
      }
      for (const keys of [
        [r7, active],
        [active, r7],
      ]) {
        assert.equal(await judge([k7, kA], keys), 'PASS');
        assert.equal(await judge([kA, k7], keys), 'PASS');
      }
      assert.equal(
        await judge([k7], [r7], 7),
        'PASS',
        'a retired key vouches up to its lastTreeSize',
      );
    });

    test('a REVOKED log key is not trusted at all; an unknown key is ignored; another origin is another log', async () => {
      assert.equal(await judge([kR], [revoked, active]), 'NO_TRUSTED_LINE');
      assert.equal(await judge([kR, kA], [revoked, active]), 'PASS');
      assert.equal(await judge([testKey('stranger')], [active]), 'NO_TRUSTED_LINE');
      const other = await judgeCheckpoint(
        parseCheckpoint(checkpointNote('other.example/log', 15, root, [kA])),
        { origin, keys: [active] },
        nodeBackend,
      );
      assert.equal(other.result, 'OTHER_ORIGIN');
    });

    test('one failing line that claims a trusted key fails the note, even beside a good one', async () => {
      const note = checkpointNote(origin, 15, root, [kA, k20]);
      // Re-sign the second line's slot with the wrong key but keep k20's key hash: it claims k20 and does not verify.
      const lines = note.split('\n');
      const forged = checkpointNote(origin, 15, root, [kR]).split('\n')[4].split(' ')[2];
      const k20Hash = Buffer.from(lines[5].split(' ')[2], 'base64').subarray(0, 4);
      lines[5] = `\u{2014} ${origin} ${Buffer.concat([k20Hash, Buffer.from(forged, 'base64').subarray(4)]).toString('base64')}`;
      const j = await judgeCheckpoint(
        parseCheckpoint(lines.join('\n')),
        { origin, keys: [active, r20] },
        nodeBackend,
      );
      assert.equal(j.result, 'BAD_SIGNATURE');
    });

    test('two trusted keys sharing a key hash make a claiming line ambiguous, and it fails', async () => {
      // Force the collision: every key hash of this origin comes out the same 4 bytes.
      const colliding = {
        ...nodeBackend,
        async sha256(bytes) {
          const prefix = new TextEncoder().encode(`${origin}\n\u{1}`);
          const isKeyHash =
            bytes.length === prefix.length + 32 && prefix.every((b, i) => bytes[i] === b);
          return isKeyHash ? new Uint8Array(32).fill(7) : nodeBackend.sha256(bytes);
        },
      };
      const note = parseCheckpoint(checkpointNote(origin, 15, root, [kA]));
      note.signatures[0].keyHash = new Uint8Array(4).fill(7);
      const j = await judgeCheckpoint(note, { origin, keys: [active, r20] }, colliding);
      assert.equal(j.result, 'BAD_SIGNATURE');
      assert.equal(
        (await judgeCheckpoint(note, { origin, keys: [active] }, colliding)).result,
        'PASS',
      );
    });

    test('without Ed25519 in the runtime, a claiming line is UNAVAILABLE, never PASS', async () => {
      const noEd = { ...nodeBackend, ed25519Verify: async () => null };
      const j = await judgeCheckpoint(
        parseCheckpoint(checkpointNote(origin, 15, root, [kA])),
        { origin, keys: [active] },
        noEd,
      );
      assert.equal(j.result, 'UNAVAILABLE');
    });
  });
});
