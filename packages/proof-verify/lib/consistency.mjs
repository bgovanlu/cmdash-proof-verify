// SPDX-License-Identifier: Apache-2.0
/**
 * Checkpoint consistency (spec section 7.9): does the log's newer signed tree
 * extend its older signed tree? RFC 9162 section 2.1.4 consistency proofs,
 * judged against two checkpoints a trusted log key signed.
 *
 *   verifyCheckpointConsistency({ from, to, proof }, { logKeys })
 *
 * `from` is the older checkpoint (signed-note text or bytes), ideally one the
 * relying party saved itself; `to` the newer one; `proof` the array of 64-hex
 * hashes the log's consistency route answered (`proof` of its JSON). `logKeys`
 * is the log key document (object, text or bytes), obtained independently.
 *
 * The verdict:
 *   CONSISTENT    both checkpoints are signed by a trusted log key, and the
 *                 proof shows the older tree is a prefix of the newer one;
 *   INCONSISTENT  both are signed, and the log key signed two different roots
 *                 for one size (equivocation: two signed notes prove it), or
 *                 the proof does not show the older tree to be a prefix of the
 *                 newer. If the log itself served that proof, treat the log's
 *                 history as forked, and keep both notes as evidence;
 *   UNVERIFIABLE  anything that stops the question being asked: a malformed
 *                 input, no trusted log key, a checkpoint no trusted key
 *                 signed (or signed by a retired key beyond its last tree
 *                 size), two different logs, the older checkpoint larger than
 *                 the newer, or no Ed25519 in this runtime.
 *
 * Like verifyReceipt, it performs no network access and reads no clock.
 */
import { fromHex, toHex } from './bytes.mjs';
import { asciiEscape, quoteFull } from './escape.mjs';
import { MAX_CONSISTENCY_PROOF, verifyConsistency } from './merkle.mjs';
import { judgeCheckpoint } from './note.mjs';
import { assertBackend, readExternalCheckpoint, resolveLogKeys } from './core.mjs';

/** The checks of a consistency verification, in order. */
export const CONSISTENCY_CHECK_NAMES = Object.freeze([
  'consistency.input',
  'consistency.from-signed',
  'consistency.to-signed',
  'consistency.proof',
]);

const CONSISTENCY_NO_HASHES =
  'this runtime has no WebCrypto (crypto.subtle is missing, as on a plain-HTTP page); use the CLI (cmdash-verify) or serve this page over HTTPS';

function consistencyInputProblem(input) {
  if (!input || typeof input !== 'object') return 'the input is not { from, to, proof }';
  if (!Array.isArray(input.proof)) return 'proof is not an array of hashes';
  if (input.proof.length > MAX_CONSISTENCY_PROOF)
    return `proof has ${input.proof.length} hashes, more than the ${MAX_CONSISTENCY_PROOF} any consistency proof needs`;
  for (let i = 0; i < input.proof.length; i += 1) {
    const h = input.proof[i];
    if (typeof h !== 'string' || h.length !== 64 || fromHex(h) === null)
      return `proof[${i}] is not 64 lowercase hex characters`;
  }
  return null;
}

/**
 * Verifies that checkpoint `from` is consistent with checkpoint `to`.
 * Resolves to { verdict, checks, from, to, summary }; `from` and `to` are
 * { size, rootHash } once the notes parse (unverified until the checks pass).
 */
export async function verifyCheckpointConsistencyWith(input, trust, backend) {
  assertBackend(backend);
  const checks = new Map(CONSISTENCY_CHECK_NAMES.map((name) => [name, null]));
  const result = { verdict: 'UNVERIFIABLE', checks: [], from: null, to: null, summary: '' };
  const set = (name, outcome, detail, rule) => {
    const c = { name, outcome, detail: asciiEscape(detail) };
    if (rule) c.rule = rule;
    checks.set(name, c);
  };
  const done = (verdict, summary) => {
    for (const name of CONSISTENCY_CHECK_NAMES) {
      if (checks.get(name) === null) set(name, 'SKIP', 'not run: an earlier check did not pass');
    }
    result.verdict = verdict;
    result.checks = CONSISTENCY_CHECK_NAMES.map((name) => checks.get(name));
    result.summary = asciiEscape(summary);
    return result;
  };
  const unverifiable = (name, rule, detail) => {
    set(name, 'FAIL', detail, rule);
    return done('UNVERIFIABLE', `UNVERIFIABLE: ${detail}`);
  };

  // consistency.input
  const problem = consistencyInputProblem(input);
  if (problem !== null) return unverifiable('consistency.input', 'consistency.malformed', problem);
  const notes = {};
  for (const which of ['from', 'to']) {
    const parsed = readExternalCheckpoint(input[which]);
    if (!parsed.ok)
      return unverifiable(
        'consistency.input',
        'consistency.malformed',
        `the ${which} checkpoint is not a well-formed signed note: ${parsed.reason}`,
      );
    notes[which] = parsed;
    result[which] = { size: parsed.size, rootHash: toHex(parsed.root) };
  }
  const { from, to } = notes;
  if (from.origin !== to.origin)
    return unverifiable(
      'consistency.input',
      'consistency.other-log',
      `the checkpoints are for two logs, ${quoteFull(from.origin)} and ${quoteFull(to.origin)}`,
    );
  if (from.size > to.size)
    return unverifiable(
      'consistency.input',
      'consistency.order',
      `the from checkpoint (tree size ${from.size}) is larger than the to checkpoint (${to.size}): pass the older one as from`,
    );
  set(
    'consistency.input',
    'PASS',
    `two checkpoints of ${quoteFull(from.origin)}, tree sizes ${from.size} and ${to.size}, and a proof of ${input.proof.length} hashes`,
  );

  // consistency.from-signed, consistency.to-signed
  if (!backend.hashes)
    return unverifiable('consistency.from-signed', 'ed25519.unavailable', CONSISTENCY_NO_HASHES);
  const t = { logKeys: trust && trust.logKeys !== null ? trust.logKeys : undefined };
  const resolved = await resolveLogKeys(t, null, backend);
  if (resolved === null)
    return unverifiable(
      'consistency.from-signed',
      'consistency.no-log-keys',
      'no log key document was supplied, so neither checkpoint can be tied to the log',
    );
  if (resolved.malformed)
    return unverifiable('consistency.from-signed', 'log-keys.malformed', resolved.malformed);
  const logKeys = resolved.keys;
  for (const which of ['from', 'to']) {
    const name = `consistency.${which}-signed`;
    const note = notes[which];
    const j = await judgeCheckpoint(note, logKeys, backend);
    if (j.result === 'PASS') {
      set(
        name,
        'PASS',
        `the ${which} checkpoint (tree size ${note.size}) is signed by the trusted log key(s) ${j.signers.map(quoteFull).join(', ')}`,
      );
      continue;
    }
    const why = {
      OTHER_ORIGIN: [
        'consistency.other-log',
        `the checkpoints are for ${quoteFull(note.origin)}, and the trusted log keys are for ${quoteFull(logKeys.origin)}`,
      ],
      NO_TRUSTED_LINE: [
        'external.unsigned',
        `no signature line of the ${which} checkpoint claims a trusted log key (a revoked key is not trusted)`,
      ],
      UNAVAILABLE: ['ed25519.unavailable', j.detail],
      BAD_SIGNATURE: ['checkpoint.signature', j.detail],
      BEYOND: ['log-key.beyond-last-tree-size', j.detail],
    }[j.result];
    return unverifiable(name, why[0], why[1]);
  }

  // consistency.proof
  const proof = input.proof.map((h) => fromHex(h));
  if (from.size === to.size && toHex(from.root) !== toHex(to.root)) {
    set(
      'consistency.proof',
      'FAIL',
      `the log key signed two different roots for the tree size ${from.size}: equivocation, and nothing that log attests can be relied on (keep both notes as evidence)`,
      'consistency.equivocation',
    );
    return done(
      'INCONSISTENT',
      `INCONSISTENT: the log signed two different trees of size ${from.size}`,
    );
  }
  if (await verifyConsistency(from.size, to.size, from.root, to.root, proof, backend)) {
    set(
      'consistency.proof',
      'PASS',
      from.size === to.size
        ? `the two checkpoints are the same tree of ${from.size}`
        : `the tree of ${from.size} is a prefix of the tree of ${to.size} (RFC 9162 section 2.1.4.2)`,
    );
    return done(
      'CONSISTENT',
      `CONSISTENT: the log's tree of ${to.size} extends its tree of ${from.size}; nothing signed at ${from.size} was changed or removed`,
    );
  }
  set(
    'consistency.proof',
    'FAIL',
    `the proof does not show the tree of ${from.size} to be a prefix of the tree of ${to.size}; if the log served this proof, its history is forked (keep both notes as evidence)`,
    'consistency.proof',
  );
  return done(
    'INCONSISTENT',
    `INCONSISTENT: the tree of ${to.size} is not shown to extend the tree of ${from.size}`,
  );
}
