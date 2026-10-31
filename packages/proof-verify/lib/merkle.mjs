// SPDX-License-Identifier: Apache-2.0
/**
 * RFC 9162 section 2.1 Merkle tree hashing and inclusion-proof verification,
 * used for the transparency log (spec section 7) and for evidence items
 * under a manifest's itemsRoot (spec section 8.3).
 *
 *   leaf hash = SHA-256(0x00 || entry)      node hash = SHA-256(0x01 || left || right)
 *
 * verifyInclusion is RFC 9162 section 2.1.3.2, step for step. Indexes and
 * sizes go up to 2^53 - 1, so the shifts run on BigInt (a JavaScript `>>`
 * would truncate them to 32 bits).
 */
import { bytesEqual, concatBytes } from './bytes.mjs';

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

export async function merkleLeafHash(entry, backend) {
  return backend.sha256(concatBytes(LEAF_PREFIX, entry));
}

export async function merkleNodeHash(left, right, backend) {
  return backend.sha256(concatBytes(NODE_PREFIX, left, right));
}

/**
 * True when `proof` (an array of 32-byte hashes, leaf level first) leads from
 * `leafHash` at `index` in a tree of `size` leaves to `root`.
 */
export async function verifyInclusion(index, size, leafHash, proof, root, backend) {
  const zero = BigInt(0);
  const one = BigInt(1);
  // 1. leaf_index >= tree_size fails.
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size)
    return false;
  // 2. fn = leaf_index, sn = tree_size - 1.
  let fn = BigInt(index);
  let sn = BigInt(size) - one;
  // 3. r = hash.
  let r = leafHash;
  // 4. for each p in the path:
  for (const p of proof) {
    // a. sn = 0 before the path is used up fails.
    if (sn === zero) return false;
    // b.
    if ((fn & one) === one || fn === sn) {
      r = await merkleNodeHash(p, r, backend);
      if ((fn & one) !== one) {
        while ((fn & one) !== one && fn !== zero) {
          fn >>= one;
          sn >>= one;
        }
      }
    } else {
      r = await merkleNodeHash(r, p, backend);
    }
    // c.
    fn >>= one;
    sn >>= one;
  }
  // 5. sn = 0 and r = root.
  return sn === zero && bytesEqual(r, root);
}

/**
 * The most hashes a consistency proof may carry: the same bound as an audit
 * path (spec section 7.2). A proof between two trees below 2^53 leaves has at
 * most 54 (one seed, and one hash per level of the larger tree).
 */
export const MAX_CONSISTENCY_PROOF = 64;

/**
 * True when `proof` (an array of 32-byte hashes) proves that the tree of
 * `size1` leaves with root `root1` is a prefix of the tree of `size2` leaves
 * with root `root2`: RFC 9162 section 2.1.4.2, step for step, for
 * 0 < size1 < size2. The two edge cases the RFC leaves to the caller:
 *
 *   - size1 = size2: the proof MUST be empty and the roots equal (two
 *     different roots for one size are two different trees, never consistent);
 *   - size1 = 0: the empty tree is a prefix of every tree, so the proof MUST
 *     be empty, and root1 must be MTH({}) = SHA-256() (a caller that claims
 *     another root for the empty tree is not describing one).
 */
export async function verifyConsistency(size1, size2, root1, root2, proof, backend) {
  const zero = BigInt(0);
  const one = BigInt(1);
  if (!Number.isSafeInteger(size1) || !Number.isSafeInteger(size2)) return false;
  if (size1 < 0 || size1 > size2) return false;
  if (!Array.isArray(proof) || proof.length > MAX_CONSISTENCY_PROOF) return false;
  for (const p of [root1, root2, ...proof]) {
    if (!(p instanceof Uint8Array) || p.length !== 32) return false;
  }
  if (size1 === size2) return proof.length === 0 && bytesEqual(root1, root2);
  if (size1 === 0) {
    return proof.length === 0 && bytesEqual(root1, await backend.sha256(new Uint8Array(0)));
  }
  // 1. An empty consistency_path fails.
  if (proof.length === 0) return false;
  // 3. fn = first - 1, sn = second - 1.
  let fn = BigInt(size1) - one;
  let sn = BigInt(size2) - one;
  // 2. If first is an exact power of 2, prepend first_hash to the path.
  const path = (BigInt(size1) & fn) === zero ? [root1, ...proof] : proof;
  // 4. If LSB(fn) is set, right-shift fn and sn equally until it is not.
  while ((fn & one) === one) {
    fn >>= one;
    sn >>= one;
  }
  // 5. fr = sr = the first value of the path.
  let fr = path[0];
  let sr = path[0];
  // 6. For each subsequent value c of the path:
  for (let i = 1; i < path.length; i += 1) {
    const c = path[i];
    // a. sn = 0 before the path is used up fails.
    if (sn === zero) return false;
    // b.
    if ((fn & one) === one || fn === sn) {
      fr = await merkleNodeHash(c, fr, backend);
      sr = await merkleNodeHash(c, sr, backend);
      while ((fn & one) !== one && fn !== zero) {
        fn >>= one;
        sn >>= one;
      }
    } else {
      sr = await merkleNodeHash(sr, c, backend);
    }
    // c.
    fn >>= one;
    sn >>= one;
  }
  // 7. fr = first_hash, sr = second_hash, and sn = 0.
  return sn === zero && bytesEqual(fr, root1) && bytesEqual(sr, root2);
}
