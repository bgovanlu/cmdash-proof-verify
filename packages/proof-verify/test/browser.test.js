// SPDX-License-Identifier: Apache-2.0
/**
 * browser/verify.js, the build P5 ships: it is exactly a fresh build of lib/
 * (drift fails here), one ES module with no Node-only construct and no
 * non-ASCII byte, and it reproduces every vector on its default WebCrypto
 * backend. Where the page has no WebCrypto (plain HTTP: crypto.subtle exists
 * only in secure contexts) or WebCrypto lacks Ed25519, it answers
 * UNVERIFIABLE with "use the CLI", never VALID and never an exception.
 * Running the vectors in Chromium, Firefox and WebKit is P5's job.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';
import { BROWSER_MODULES, BROWSER_OUT, buildBrowser } from '../scripts/build-browser.mjs';
import { PKG, assertMatchesVector, byId, loadVectors } from './helpers.js';

const vectors = loadVectors();
const built = readFileSync(BROWSER_OUT, 'utf8');
const browser = await import('../browser/verify.js');

describe('the build', () => {
  test('browser/verify.js is exactly a fresh build of lib/ (run `npm run build:browser` after changing lib/)', () => {
    assert.equal(built, buildBrowser());
  });

  test('one ES module: no import, no Node-only construct, no non-ASCII byte, the documented exports', () => {
    const code = built.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code, /^\s*import\s/m);
    assert.doesNotMatch(code, /['"]node:|\brequire\s*\(|\bprocess\.|\bBuffer\b/);
    assert.match(built, /^[\x09\x0a\x20-\x7e]*$/);
    assert.deepEqual(Object.keys(browser).sort(), [
      'CHECK_NAMES',
      'COLLECTOR_DOES_NOT_PROVE_IDS',
      'COLLECTOR_PROVES_IDS',
      'COLLECTOR_RULES',
      'CONSISTENCY_CHECK_NAMES',
      'DOES_NOT_PROVE_IDS',
      'PROVES_IDS',
      'TRUST_MEMBERS',
      'inspectReceipt',
      'keyDocumentUrlOf',
      'truncatedPercent',
      'verifyCheckpointConsistency',
      'verifyCollectorAttestation',
      'verifyEvidenceItem',
      'verifyEvidenceOpening',
      'verifyReceipt',
      'webCryptoBackend',
    ]);
    assert.doesNotMatch(
      code,
      /\b\d+n\b/,
      'no BigInt literal (a bundler targeting an older engine would choke)',
    );
  });

  test('the builder refuses what would break the concatenation (calibration of its guards)', () => {
    const read = (patch) => (name) => {
      const src = readFileSync(join(PKG, 'lib', name), 'utf8');
      return patch[name] ? patch[name](src) : src;
    };
    const cases = [
      [
        { 'core.mjs': (s) => `import { readFileSync } from 'node:fs';\n${s}` },
        /import the build cannot inline|Node-only/,
      ],
      [{ 'core.mjs': (s) => `${s}\nconst leaked = process.env.HOME;\n` }, /Node-only construct/],
      [{ 'note.mjs': (s) => `${s}\nfunction hasOwn() {}\n` }, /declared in both/],
      [
        { 'bytes.mjs': (s) => `import { quote } from './escape.mjs';\n${s}` },
        /not built before it/,
      ],
      [{ 'merkle.mjs': (s) => `${s}\nexport { merkleLeafHash as leaf };\n` }, /export list/],
    ];
    for (const [patch, error] of cases)
      assert.throws(() => buildBrowser(read(patch)), error, Object.keys(patch)[0]);
    assert.equal(buildBrowser(read({})), built);
    assert.equal(BROWSER_MODULES.at(-1), 'browser-entry.mjs');
  });

  test('the build is laid out as the repo prettier leaves it: one trailing newline, never two blank lines in a row', () => {
    assert.ok(built.endsWith(';\n') || built.endsWith('}\n'));
    assert.doesNotMatch(built, /\n\n\n/);
  });

  test('`build-browser.mjs --check` passes on the committed build', () => {
    const r = spawnSync(process.execPath, [join(PKG, 'scripts', 'build-browser.mjs'), '--check'], {
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /browser\/verify\.js is up to date \(\d+ bytes\)/);
  });
});

describe('every vector through the built module, on its default WebCrypto backend', () => {
  for (const v of vectors) {
    test(v.id, async () => {
      assertMatchesVector(
        await browser.verifyReceipt(v.input.receipt, v.input.trust),
        v,
        ' [browser build]',
      );
      if (v.input.evidenceOpening) {
        const o = await browser.verifyEvidenceOpening(v.input.receipt, v.input.evidenceOpening);
        assert.deepEqual({ match: o.match, rule: o.rule }, v.expect.evidenceOpening);
      }
      for (const [i, item] of (v.input.evidenceItems ?? []).entries()) {
        const o = await browser.verifyEvidenceItem(v.input.receipt, v.input.evidenceOpening, item);
        assert.deepEqual({ match: o.match, rule: o.rule }, v.expect.evidenceItems[i]);
      }
    });
  }

  test('inspectReceipt gives the unverified routing facts for a one-click fetch', async () => {
    const v = byId(vectors, '06-valid-logged');
    const facts = await browser.inspectReceipt(v.input.receipt);
    assert.equal(facts.deployment, 'https://cmdash.example');
    assert.equal(facts.keyDocumentUrl, v.input.trust.keyDocumentUrl);
    assert.equal(facts.digest, v.expect.digest);
    assert.equal(facts.logTreeSize, 7);
    assert.deepEqual(await browser.inspectReceipt('{"v":0}'), { ok: false });
  });
});

describe('a page without WebCrypto, or without Ed25519: UNVERIFIABLE, "use the CLI", never VALID', () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const setCrypto = (value) =>
    Object.defineProperty(globalThis, 'crypto', {
      value,
      configurable: true,
      enumerable: true,
      writable: true,
    });
  after(() => Object.defineProperty(globalThis, 'crypto', original));

  test('crypto.subtle missing (a plain-HTTP self-hosted page): no exception, UNVERIFIABLE with ed25519.unavailable', async () => {
    for (const value of [undefined, {}, { getRandomValues: () => {} }]) {
      setCrypto(value);
      for (const id of [
        '01-valid-measured-all',
        '06-valid-logged',
        '14-stale',
        '63-key-identity-universal-signature',
      ]) {
        const r = await browser.verifyReceipt(
          byId(vectors, id).input.receipt,
          byId(vectors, id).input.trust,
        );
        assert.equal(r.verdict, 'UNVERIFIABLE', `${id} with crypto ${JSON.stringify(value)}`);
        assert.equal(r.rule, 'ed25519.unavailable');
        assert.match(r.summary, /use the CLI \(cmdash-verify\) or serve this page over HTTPS/);
      }
      // What needs no crypto still fails loudly.
      const dup = await browser.verifyReceipt(
        byId(vectors, '77-duplicate-envelope-members').input.receipt,
        { now: '2026-10-12T00:00:00.000Z' },
      );
      assert.equal(dup.rule, 'json.duplicate-member');
    }
    Object.defineProperty(globalThis, 'crypto', original);
  });

  test('WebCrypto without Ed25519 (an older engine): every VALID vector becomes UNVERIFIABLE', async () => {
    const subtle = original.get.call(globalThis).subtle;
    setCrypto({
      subtle: {
        digest: (...a) => subtle.digest(...a),
        importKey: async (format, keyData, algorithm, ...rest) => {
          if (algorithm && algorithm.name === 'Ed25519')
            throw new DOMException('Unrecognized name', 'NotSupportedError');
          return subtle.importKey(format, keyData, algorithm, ...rest);
        },
        verify: (...a) => subtle.verify(...a),
      },
    });
    let n = 0;
    for (const v of vectors) {
      const r = await browser.verifyReceipt(v.input.receipt, v.input.trust);
      assert.ok(r.verdict !== 'VALID' && r.verdict !== 'STALE_VALID', `${v.id}: ${r.verdict}`);
      if (v.expect.verdict === 'VALID' || v.expect.verdict === 'STALE_VALID') {
        assert.equal(r.rule, 'ed25519.unavailable', v.id);
        n += 1;
      }
    }
    const valid = vectors.filter(
      (v) => v.expect.verdict === 'VALID' || v.expect.verdict === 'STALE_VALID',
    ).length;
    assert.equal(n, valid, `all ${valid} VALID and STALE_VALID vectors turned UNVERIFIABLE`);
    Object.defineProperty(globalThis, 'crypto', original);
  });
});
