// SPDX-License-Identifier: Apache-2.0
/**
 * Checkpoints: C2SP tlog-checkpoint bodies signed as C2SP signed notes
 * (spec section 7.3).
 *
 *   <origin>\n<tree size>\n<root hash, standard base64 with padding>\n[extension lines]\n
 *   U+2014 <key name> <base64(key hash (4 bytes) || signature)>\n   (one or more)
 *
 * The signed message is the note text: the body lines, each ending in a line
 * feed. The key hash is the first 4 bytes of SHA-256(key name || 0x0A || 0x01
 * || 32-byte public key). The key name MUST be the origin.
 *
 * Deliberately stricter than C2SP, as the spec says:
 *   - printable ASCII only (U+0020..U+007E and line feeds), plus the em dash
 *     that opens each signature line and nowhere else;
 *   - a line that claims a TRUSTED key (its name is the origin and its key
 *     hash is a trusted key's) and does not verify fails the whole note, even
 *     if another trusted line verifies (checkpoint.signature).
 * Extension lines and signatures by keys the verifier does not know are
 * ignored (vector 98). Base64 must be canonical: padded, zero spare bits.
 */
import { bytesEqual, concatBytes, decodeBase64Std, utf8 } from './bytes.mjs';
import { verifyEd25519 } from './ed25519.mjs';
import { SCHEMA_RE } from './schema.mjs';

export const MAX_CHECKPOINT_CHARS = 8192;
const EM_DASH = '\u{2014}';
/** A signed-note key name: printable ASCII without space or "+". */
const KEY_NAME_RE = /^[!-*,-~]+$/;
const TREE_SIZE_RE = /^(?:0|[1-9][0-9]*)$/;

/**
 * Parses a checkpoint note. Returns { ok: true, message, origin, size, root,
 * signatures: [{ name, keyHash, signature }] } or { ok: false, reason }.
 */
export function parseCheckpoint(text) {
  const bad = (reason) => ({ ok: false, reason });
  if (typeof text !== 'string') return bad('it is not text');
  if (Array.from(text).length > MAX_CHECKPOINT_CHARS)
    return bad(`it is longer than ${MAX_CHECKPOINT_CHARS} characters`);
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (!(c === 0x0a || (c >= 0x20 && c <= 0x7e) || c === 0x2014))
      return bad(`it contains a character outside printable ASCII at offset ${i}`);
  }
  const split = text.lastIndexOf('\n\n');
  if (split < 0) return bad('it has no blank line before its signature lines');
  const body = text.slice(0, split + 1);
  const sigBlock = text.slice(split + 2);
  if (body.includes(EM_DASH)) return bad('an em dash appears outside a signature line');
  const lines = body.slice(0, -1).split('\n');
  if (lines.length < 3) return bad('its body has fewer than three lines (origin, size, root)');
  const [origin, sizeText, rootText, ...extensions] = lines;
  // The origin is also the key name: #/$defs/origin, printable ASCII without space or "+", 1..255.
  if (!SCHEMA_RE.origin.test(origin))
    return bad(
      'its origin is not a log origin (1 to 255 printable ASCII characters, no space or "+")',
    );
  if (!TREE_SIZE_RE.test(sizeText) || !Number.isSafeInteger(Number(sizeText))) {
    return bad('its tree size is not a decimal integer without leading zeros below 2^53');
  }
  const root = decodeBase64Std(rootText);
  if (root === null || root.length !== 32)
    return bad('its root hash is not 32 bytes of canonical, padded base64');
  if (extensions.some((l) => l.length === 0)) return bad('it has an empty extension line');
  if (sigBlock.length === 0 || !sigBlock.endsWith('\n'))
    return bad('its signature lines do not end in a line feed');
  const signatures = [];
  for (const line of sigBlock.slice(0, -1).split('\n')) {
    if (!line.startsWith(`${EM_DASH} `))
      return bad('a signature line does not start with an em dash and a space');
    const rest = line.slice(2);
    if (rest.includes(EM_DASH)) return bad('a signature line contains a second em dash');
    const parts = rest.split(' ');
    if (parts.length !== 2 || !KEY_NAME_RE.test(parts[0]))
      return bad('a signature line is not "<name> <base64>"');
    const raw = decodeBase64Std(parts[1]);
    if (raw === null || raw.length < 5)
      return bad('a signature line does not carry canonical base64 of a key hash and a signature');
    signatures.push({ name: parts[0], keyHash: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  return { ok: true, message: utf8(body), origin, size: Number(sizeText), root, signatures };
}

/** The signed-note key hash: SHA-256(name || 0x0A || 0x01 || public key)[0..4]. */
export async function noteKeyHash(name, publicKey32, backend) {
  const digest = await backend.sha256(
    concatBytes(utf8(name), Uint8Array.of(0x0a, 0x01), publicKey32),
  );
  return digest.subarray(0, 4);
}

/**
 * Judges a parsed checkpoint against a trusted log key set: `logKeys` is
 * { origin, keys: [{ kid, status, lastTreeSize?, raw (32 bytes) }] } for a
 * well-formed log key document. REVOKED keys are not trusted at all.
 *
 * Returns one of
 *   { result: 'OTHER_ORIGIN' }                 the note is for another log
 *   { result: 'NO_TRUSTED_LINE' }              no line claims a trusted key
 *   { result: 'UNAVAILABLE', detail }          a claiming line could not be checked (no Ed25519)
 *   { result: 'BAD_SIGNATURE', detail }        a claiming line does not verify
 *   { result: 'BEYOND', detail }               every signer is RETIRED below this size
 *   { result: 'PASS', signers: [kid...] }
 * The outcome does not depend on the order of the lines or of the keys.
 */
export async function judgeCheckpoint(note, logKeys, backend) {
  if (note.origin !== logKeys.origin) return { result: 'OTHER_ORIGIN' };
  const trusted = [];
  for (const key of logKeys.keys) {
    if (key.status === 'REVOKED') continue;
    trusted.push({ key, hash: await noteKeyHash(logKeys.origin, key.raw, backend) });
  }
  const verifiedBy = new Map();
  let claiming = 0;
  let unavailable = null;
  for (const line of note.signatures) {
    if (line.name !== note.origin) continue;
    const candidates = trusted.filter((t) => bytesEqual(t.hash, line.keyHash));
    if (candidates.length === 0) continue;
    claiming += 1;
    // Every trusted key the line claims must verify it. Two trusted keys sharing a 4-byte key hash make
    // the line ambiguous, and an ambiguous line fails (golang's note.Open refuses an ambiguous key too).
    for (const { key } of candidates) {
      const r = await verifyEd25519(key.raw, note.message, line.signature, backend);
      if (r.ok === true) verifiedBy.set(key.kid, key);
      else if (r.ok === null) unavailable = r.detail;
      else {
        return {
          result: 'BAD_SIGNATURE',
          detail: `a signature line claiming the trusted log key ${key.kid} does not verify (${r.rule}: ${r.detail})`,
        };
      }
    }
  }
  if (claiming === 0) return { result: 'NO_TRUSTED_LINE' };
  if (unavailable !== null) return { result: 'UNAVAILABLE', detail: unavailable };
  const signers = [...verifiedBy.values()];
  const vouching = signers.filter((k) => !(k.status === 'RETIRED' && k.lastTreeSize < note.size));
  if (vouching.length === 0) {
    const limits = signers
      .map((k) => `${k.kid} retired at lastTreeSize ${k.lastTreeSize}`)
      .join(', ');
    return {
      result: 'BEYOND',
      detail: `the checkpoint is for a tree of ${note.size}, but its only trusted signers are retired below that size (${limits})`,
    };
  }
  return { result: 'PASS', signers: signers.map((k) => k.kid) };
}
