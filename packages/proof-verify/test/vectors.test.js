// SPDX-License-Identifier: Apache-2.0
/**
 * Every Z4 vector (docs/specs/proof-receipt-v0/vectors) reproduces every
 * field of its `expect`, in Node (node:crypto) and on the WebCrypto path
 * (Node 22's globalThis.crypto, the library forced onto it), plus the
 * evidence openings and items. The vectors are the contract between this
 * verifier and the reference checker: nothing here imports the checker.
 * The same vectors run through the built browser module in browser.test.js.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  verifyEvidenceItem,
  verifyEvidenceOpening,
  verifyReceipt,
  webCryptoBackend,
} from '../lib/verify.mjs';
import { assertMatchesVector, loadVectors } from './helpers.js';

const vectors = loadVectors();
const SPEC_RULES = new Set([
  'json.too-large',
  'json.syntax',
  'json.duplicate-member',
  'measurement.parts-within-denominator',
  'ALL.denominator-positive',
  'ALL.no-unknown',
  'ALL.complete',
  'AT_LEAST.threshold-below-one',
  'AT_LEAST.denominator-positive',
  'AT_LEAST.threshold-met',
  'SCORE.range-ordered',
  'SCORE.in-range',
  'SCORE.denominator-positive',
  'SCORE.all-unknown-is-min',
  'SCORE.none-met-is-min',
  'SCORE.max-requires-complete',
  'time.observed-before-issued',
  'time.fresh-after-observed',
  'time.window-max-400d',
  'self-attested.at-equals-observedAt',
  'supersedes.not-self',
  'key.deployment-untrusted',
  'key.deployment-plain-http',
  'key.document-malformed',
  'key.document-url',
  'key.document-deployment',
  'key.document-tenant',
  'key.not-in-document',
  'key.supplied-none',
  'key.supplied-deployment',
  'key.supplied-tenant',
  'key.embedded-mismatch',
  'key.embedded-only',
  'key.no-key', // gitleaks:allow (a rule name, not a key)
  'ed25519.key-noncanonical', // gitleaks:allow
  'ed25519.key-off-curve', // gitleaks:allow
  'ed25519.key-small-order', // gitleaks:allow
  'ed25519.r-noncanonical',
  'ed25519.r-off-curve',
  'ed25519.r-small-order',
  'ed25519.s-not-reduced',
  'ed25519.mismatch',
  'ed25519.unavailable',
  'log.section-malformed',
  'log.checkpoint-malformed',
  'log.size-mismatch',
  'log.root-mismatch',
  'log.index-outside',
  'log.proof',
  'log-keys.malformed',
  'checkpoint.signature',
  'log-key.beyond-last-tree-size',
  'external.malformed',
  'external.other-log',
  'external.unsigned',
  'external.equivocation',
  'policy.require-logged',
  'key.revoked',
  'key.not-yet-valid',
  'key.disowned',
  'key.retired',
  'key.retired-unproven',
]);

test('the vector set is the one the spec indexes: 142 vectors, every verdict present', () => {
  assert.equal(vectors.length, 142);
  const verdicts = new Set(vectors.map((v) => v.expect.verdict));
  assert.deepEqual([...verdicts].sort(), ['INVALID', 'STALE_VALID', 'UNVERIFIABLE', 'VALID']);
});

for (const [label, options] of [
  ['node:crypto', undefined],
  ['WebCrypto (globalThis.crypto, forced)', { backend: webCryptoBackend(globalThis.crypto) }],
]) {
  describe(`every vector, ${label}`, () => {
    let checked = 0;
    for (const v of vectors) {
      const e = v.expect;
      test(`${v.id} -> ${e.verdict}${e.failedCheck ? ` at ${e.failedCheck}` : ''}${e.rule ? ` (${e.rule})` : ''}`, async () => {
        const r = await verifyReceipt(v.input.receipt, v.input.trust, options);
        assertMatchesVector(r, v, ` [${label}]`);
        for (const c of r.checks)
          if (c.rule && !c.rule.startsWith('canonical.'))
            assert.ok(SPEC_RULES.has(c.rule), `${c.rule} is a spec rule`);
        if (v.input.evidenceOpening) {
          const o = await verifyEvidenceOpening(v.input.receipt, v.input.evidenceOpening, options);
          assert.deepEqual({ match: o.match, rule: o.rule }, e.evidenceOpening, 'evidence opening');
          assert.match(o.detail, /^[\x20-\x7e]*$/);
        }
        for (const [i, item] of (v.input.evidenceItems ?? []).entries()) {
          const o = await verifyEvidenceItem(
            v.input.receipt,
            v.input.evidenceOpening,
            item,
            options,
          );
          assert.deepEqual(
            { match: o.match, rule: o.rule },
            e.evidenceItems[i],
            `evidence item ${i}`,
          );
        }
        checked += 1;
      });
    }
    test(`all ${vectors.length} vectors were checked`, () => assert.equal(checked, vectors.length));
  });
}

test('the WebCrypto backend really is WebCrypto: a Node-only primitive is never reached', async () => {
  // A WebCrypto object that records each call proves the forced path runs on subtle, not node:crypto.
  const calls = { digest: 0, importKey: 0, verify: 0 };
  const subtle = globalThis.crypto.subtle;
  const spy = {
    subtle: {
      digest: (...a) => ((calls.digest += 1), subtle.digest(...a)),
      importKey: (...a) => ((calls.importKey += 1), subtle.importKey(...a)),
      verify: (...a) => ((calls.verify += 1), subtle.verify(...a)),
    },
  };
  const v = vectors.find((x) => x.id === '06-valid-logged');
  const r = await verifyReceipt(v.input.receipt, v.input.trust, { backend: webCryptoBackend(spy) });
  assert.equal(r.verdict, 'VALID');
  assert.ok(calls.digest > 5 && calls.verify === 2 && calls.importKey === 2, JSON.stringify(calls));
});

test('the injected member names reach no output raw (vectors 58, 59), and the escapes are shown', async () => {
  for (const id of ['58-output-injection-envelope-member', '59-output-injection-key-document']) {
    const v = vectors.find((x) => x.id === id);
    const r = await verifyReceipt(v.input.receipt, v.input.trust);
    const all = [r.summary, ...r.checks.map((c) => c.detail)].join('\n');
    assert.ok(!all.includes('\u001b') && !all.includes('\r') && !all.includes('\u{202e}'), id);
    assert.match(all, /\\u\{1b\}/, `${id}: the ESC is shown escaped`);
  }
});
