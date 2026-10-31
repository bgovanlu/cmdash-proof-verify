// SPDX-License-Identifier: Apache-2.0
/**
 * verifyReceipt beyond what the vectors pin: the caller's inputs, the key
 * sources and their precedence, the log policy, key status corner cases,
 * the summary's words, output escaping, the residual attack of spec section
 * 6.5, and the degraded runtimes (no WebCrypto, no Ed25519, a platform that
 * accepts anything). Each one is a place where a verifier could say VALID on
 * a partial check.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { nodeBackend } from '../lib/backend-node.mjs';
import { verifyReceipt, webCryptoBackend } from '../lib/verify.mjs';
import {
  NOW,
  PRINTABLE,
  TENANT,
  assertMatchesVector,
  byId,
  checkpointNote,
  issue,
  keyDocument,
  keyDocumentUrl,
  keyEntry,
  loadVectors,
  logKeyDocument,
  logKeyEntry,
  logSectionFor,
  sha256,
  testKey,
} from './helpers.js';

const vectors = loadVectors();
const v = (id) => byId(vectors, id);
const run = (id, trust = {}, options) =>
  verifyReceipt(v(id).input.receipt, { ...v(id).input.trust, ...trust }, options);
const without = (obj, ...names) =>
  Object.fromEntries(Object.entries(obj).filter(([k]) => !names.includes(k)));

describe("the caller's inputs", () => {
  test('a caller error throws a TypeError; it is never a verdict', async () => {
    const r = v('01-valid-measured-all').input.receipt;
    await assert.rejects(verifyReceipt(r), TypeError);
    await assert.rejects(verifyReceipt(r, 'now'), TypeError);
    await assert.rejects(verifyReceipt(r, {}), /trust\.now is required/);
    await assert.rejects(verifyReceipt(r, { now: '2026-10-12' }), /trust\.now/);
    await assert.rejects(
      verifyReceipt(r, { now: NOW, requireLoged: true }),
      /unknown trust member "requireLoged"/,
    );
    await assert.rejects(verifyReceipt(r, { trust: {}, now: NOW }), /unknown trust member "trust"/);
    await assert.rejects(verifyReceipt(r, { now: NOW }, { backend: {} }), /backend/);
  });

  test('the receipt as bytes, text or an object reads the same; a BOM, a stray byte or a lone surrogate does not read', async () => {
    const x = v('01-valid-measured-all');
    const text = JSON.stringify(x.input.receipt);
    for (const input of [
      x.input.receipt,
      text,
      new TextEncoder().encode(text),
      Buffer.from(text),
    ]) {
      assertMatchesVector(await verifyReceipt(input, x.input.trust), x);
    }
    const bytes = new TextEncoder().encode(text);
    const bom = await verifyReceipt(Uint8Array.from([0xef, 0xbb, 0xbf, ...bytes]), x.input.trust);
    assert.deepEqual([bom.verdict, bom.rule], ['INVALID', 'json.syntax']);
    const stray = Uint8Array.from(bytes);
    stray[text.indexOf('"sig"') + 2] = 0xff;
    assert.equal((await verifyReceipt(stray, x.input.trust)).rule, 'json.syntax');
    assert.equal(
      (
        await verifyReceipt(
          `${text.slice(0, -1)},"x":"${String.fromCharCode(0xd800)}"}`,
          x.input.trust,
        )
      ).rule,
      'json.syntax',
    );
    assert.equal((await verifyReceipt(undefined, x.input.trust)).rule, 'json.syntax');
    const big = await verifyReceipt(`${text}${' '.repeat(65537 - text.length)}`, x.input.trust);
    assert.deepEqual([big.verdict, big.rule, big.digest], ['INVALID', 'json.too-large', null]);
  });

  test('an explicit null reads as "not supplied"', async () => {
    const r = await run('01-valid-measured-all', {
      logKeys: null,
      checkpoint: null,
      logSection: null,
      publicKeys: null,
      requireLogged: null,
    });
    assert.equal(r.verdict, 'VALID');
    const noDoc = await run('01-valid-measured-all', { keyDocument: null, keyDocumentUrl: null });
    assert.equal(noDoc.rule, 'key.no-key');
  });

  test('the result has exactly the members of spec section 9.4, in order', async () => {
    const r = await run('06-valid-logged');
    assert.deepEqual(Object.keys(r), [
      'verdict',
      'failedCheck',
      'rule',
      'keySource',
      'keyStatusAsOf',
      'keyDocumentUrl',
      'plainHttp',
      'checks',
      'proves',
      'doesNotProve',
      'reading',
      'summary',
      'digest',
      'payload',
    ]);
    assert.deepEqual(Object.keys(r.checks[0]), ['name', 'outcome', 'detail']);
    const failed = (await run('15-tampered-payload')).checks.find((c) => c.outcome === 'FAIL');
    assert.deepEqual(Object.keys(failed), ['name', 'outcome', 'detail', 'effect', 'rule']);
  });
});

describe('where the key comes from (spec section 6.6)', () => {
  const x01 = v('01-valid-measured-all');
  const { tenantRef, keys } = x01.input.trust.keyDocument;
  const binding = { deployment: 'https://cmdash.example', tenantRef, publicKey: keys[0].publicKey };

  test('trust.deployments gates every key source once given, and is required with a key document', async () => {
    assert.equal((await run('13-valid-supplied-key-log-unverified')).verdict, 'VALID');
    assert.equal(
      (
        await run('13-valid-supplied-key-log-unverified', {
          deployments: ['https://other.example'],
        })
      ).rule,
      'key.deployment-untrusted',
    );
    assert.equal(
      (await verifyReceipt(x01.input.receipt, without(x01.input.trust, 'deployments'))).rule,
      'key.deployment-untrusted',
    );
    for (const deployments of [
      'https://cmdash.example',
      ['https://CMDASH.example'],
      ['https://cmdash.example/'],
      [],
    ]) {
      assert.equal(
        (await run('01-valid-measured-all', { deployments })).rule,
        'key.deployment-untrusted',
        JSON.stringify(deployments),
      );
    }
    assert.equal((await run('12-embedded-key-only')).rule, 'key.embedded-only');
    assert.equal(
      (await run('12-embedded-key-only', { deployments: ['https://other.example'] })).rule,
      'key.deployment-untrusted',
    );
    assert.equal(
      (await run('12-embedded-key-only', { deployments: ['https://cmdash.example'] })).rule,
      'key.embedded-only',
    );
  });

  test('a supplied key must be bound to a canonical deployment and a tenantRef, or it is no key at all', async () => {
    const trust = { now: NOW };
    const ok = await verifyReceipt(x01.input.receipt, { ...trust, publicKeys: [binding] });
    assert.equal(ok.verdict, 'VALID');
    assert.equal(ok.keySource, 'SUPPLIED');
    assert.ok(ok.doesNotProve.includes('key-status'));
    for (const publicKeys of [
      [{ tenantRef, publicKey: binding.publicKey }],
      [{ ...binding, deployment: 'https://cmdash.example:443' }],
      [{ ...binding, tenantRef: 'tr_1' }],
      [{ ...binding, publicKey: 'not a key' }],
      [binding.publicKey],
      [],
      binding,
    ]) {
      const r = await verifyReceipt(x01.input.receipt, { ...trust, publicKeys });
      assert.equal(r.rule, 'key.supplied-none', JSON.stringify(publicKeys).slice(0, 80));
    }
  });

  test('the first source present is the only one used: no fallback to supplied or embedded keys', async () => {
    const x = v('51-key-not-in-document');
    const r = await verifyReceipt(x.input.receipt, { ...x.input.trust, publicKeys: [binding] });
    assert.equal(r.rule, 'key.not-in-document');
    const withEmbedded = {
      ...x01.input.receipt,
      issuerKey: { kid: keys[0].kid, alg: 'Ed25519', publicKey: keys[0].publicKey },
    };
    const supplied = await verifyReceipt(withEmbedded, {
      now: NOW,
      publicKeys: [{ ...binding, tenantRef: 'tr_ffffffffffffffffffffffffffffffff' }],
    });
    assert.deepEqual([supplied.rule, supplied.keySource], ['key.supplied-tenant', null]);
    const embedded = await verifyReceipt(withEmbedded, { now: NOW });
    assert.deepEqual(
      [embedded.verdict, embedded.rule, embedded.keySource],
      ['UNVERIFIABLE', 'key.embedded-only', 'EMBEDDED'],
    );
  });

  test('a key document is judged as its JSON: text, bytes and an object agree; an unserializable one is malformed', async () => {
    const doc = x01.input.trust.keyDocument;
    for (const keyDocument of [
      doc,
      JSON.stringify(doc),
      new TextEncoder().encode(JSON.stringify(doc)),
    ]) {
      assert.equal((await run('01-valid-measured-all', { keyDocument })).verdict, 'VALID');
    }
    const cyclic = { ...doc };
    cyclic.self = cyclic;
    assert.equal(
      (await run('01-valid-measured-all', { keyDocument: cyclic })).rule,
      'key.document-malformed',
    );
    assert.equal(
      (await run('01-valid-measured-all', { keyDocument: 42 })).rule,
      'key.document-malformed',
    );
    const huge = `${JSON.stringify(doc).slice(0, -1)}${' '.repeat(1048576)}}`;
    assert.equal(
      (await run('01-valid-measured-all', { keyDocument: huge })).rule,
      'key.document-malformed',
    );
  });
});

describe('the log (spec section 7)', () => {
  test('a supplied log section is used only when the envelope has none', async () => {
    const r = await run('06-valid-logged', { logSection: 'not even JSON' });
    assert.equal(r.verdict, 'VALID');
    assert.ok(r.proves.includes('logged'));
    const e0 = v('E0-supplied-log-section');
    assert.equal(
      (
        await run('E0-supplied-log-section', {
          logSection: JSON.stringify(e0.input.trust.logSection),
        })
      ).verdict,
      'VALID',
    );
    assert.equal(
      (await run('E0-supplied-log-section', { logSection: undefined })).rule,
      'key.retired-unproven',
    );
    assert.equal(
      (await run('E0-supplied-log-section', { logSection: '{"index":1}' })).rule,
      'log.section-malformed',
    );
  });

  test('requireLogged: no trusted log key, log keys for another origin, a revoked log key are all UNVERIFIABLE', async () => {
    for (const id of [
      '13-valid-supplied-key-log-unverified',
      '99-trusted-log-keys-for-another-origin',
      '97-checkpoint-by-revoked-log-key',
    ]) {
      const r = await run(id, { requireLogged: true });
      assert.deepEqual(
        [r.verdict, r.failedCheck, r.rule],
        ['UNVERIFIABLE', 'log.checkpoint', 'policy.require-logged'],
        id,
      );
    }
    assert.equal((await run('06-valid-logged', { requireLogged: true })).verdict, 'VALID');
  });

  test('an external checkpoint may be bytes; anything but a signed note is malformed', async () => {
    const x = v('07-valid-logged-external-same-size');
    assert.ok(
      (
        await run(x.id, { checkpoint: new TextEncoder().encode(x.input.trust.checkpoint) })
      ).proves.includes('log-consistent-with-external'),
    );
    for (const checkpoint of [42, 'hello', Uint8Array.of(0xff, 0xfe)])
      assert.equal((await run(x.id, { checkpoint })).rule, 'external.malformed');
  });

  test("a key document that does not list the receipt's key still vouches for its deployment's log keys: a broken checkpoint is INVALID, not hidden behind the missing key", async () => {
    const logKey = testKey('log A');
    const listed = testKey('listed A');
    const stranger = testKey('stranger A');
    const origin = 'cmdash.example/cmdash-proof-log';
    const doc = keyDocument({
      keys: [keyEntry(listed)],
      log: logKeyDocument(origin, [logKeyEntry(logKey)]),
    });
    const receipt = issue(stranger);
    const good = logSectionFor(receipt.digest, { index: 2, size: 5, logKeys: [logKey] });
    const trust = {
      now: NOW,
      deployments: ['https://cmdash.example'],
      keyDocument: doc,
      keyDocumentUrl: keyDocumentUrl(),
    };
    const honest = await verifyReceipt({ ...receipt.envelope, log: good }, trust);
    assert.deepEqual([honest.verdict, honest.rule], ['UNVERIFIABLE', 'key.not-in-document']);
    assert.equal(honest.checks.find((c) => c.name === 'log.checkpoint').outcome, 'PASS');
    const forged = {
      ...good,
      checkpoint: checkpointNote(origin, 5, Buffer.from(good.rootHash, 'hex'), [stranger]).replace(
        / [A-Za-z0-9+/]{6}/,
        (m) => m,
      ),
    };
    // Keep the stranger's signature but claim the log key's key hash: a line claiming a trusted key that does not verify.
    const lines = forged.checkpoint.split('\n');
    const claimed = Buffer.from(good.checkpoint.split('\n')[4].split(' ')[2], 'base64').subarray(
      0,
      4,
    );
    lines[4] = `\u{2014} ${origin} ${Buffer.concat([claimed, Buffer.from(lines[4].split(' ')[2], 'base64').subarray(4)]).toString('base64')}`;
    const broken = await verifyReceipt(
      { ...receipt.envelope, log: { ...good, checkpoint: lines.join('\n') } },
      trust,
    );
    assert.deepEqual(
      [broken.verdict, broken.failedCheck, broken.rule],
      ['INVALID', 'log.checkpoint', 'checkpoint.signature'],
    );
  });
});

describe('key status (spec section 6.5)', () => {
  const issuer = testKey('status issuer');
  const logKey = testKey('status log');
  const origin = 'cmdash.example/cmdash-proof-log';
  const trustWith = (entry, generatedAt = NOW) => ({
    now: NOW,
    deployments: ['https://cmdash.example'],
    keyDocument: keyDocument({
      keys: [entry],
      log: logKeyDocument(origin, [logKeyEntry(logKey)]),
      generatedAt,
    }),
    keyDocumentUrl: keyDocumentUrl(),
  });
  const logged = (receipt, index) => ({
    ...receipt.envelope,
    log: logSectionFor(receipt.digest, { index, size: 8, logKeys: [logKey] }),
  });

  test('a compromised key is INVALID even when the key document predates the receipt (rules before "not proven")', async () => {
    const entry = keyEntry(issuer, 'REVOKED', {
      revokedAt: '2026-09-15T00:00:00.000Z',
      revocationReason: 'KEY_COMPROMISE',
    });
    const r = await verifyReceipt(
      issue(issuer).envelope,
      trustWith(entry, '2026-09-20T00:00:00.000Z'),
    );
    assert.deepEqual(
      [r.verdict, r.rule, r.keyStatusAsOf],
      ['INVALID', 'key.revoked', '2026-09-20T00:00:00.000Z'],
    );
  });

  test("a retired key in an older document still needs its log proof: never VALID on the signer's word", async () => {
    const entry = keyEntry(issuer, 'RETIRED', {
      validUntil: '2026-10-05T00:00:00.000Z',
      lastTreeSize: 4,
    });
    const r = await verifyReceipt(
      issue(issuer).envelope,
      trustWith(entry, '2026-10-06T00:00:00.000Z'),
    );
    assert.equal(r.rule, 'key.retired-unproven');
    const ok = await verifyReceipt(logged(issue(issuer), 3), trustWith(entry));
    assert.equal(ok.verdict, 'VALID');
    assert.match(
      ok.summary,
      /KEY RETIRED AT 2026-10-05T00:00:00\.000Z, after this receipt \(logged at index 3, below lastTreeSize 4\)/,
    );
    assert.equal(
      (await verifyReceipt(logged(issue(issuer), 4), trustWith(entry))).rule,
      'key.retired',
    );
  });

  test('a retired key without a lastTreeSize can never be dated by the log', async () => {
    const entry = keyEntry(issuer, 'RETIRED', { validUntil: '2026-10-05T00:00:00.000Z' });
    assert.equal(
      (await verifyReceipt(logged(issue(issuer), 1), trustWith(entry))).rule,
      'key.retired-unproven',
    );
  });

  test('disowned (ISSUER_REQUEST): its end is min(validUntil, revokedAt); the rule names which one ended it', async () => {
    const retiredThenDisowned = keyEntry(issuer, 'REVOKED', {
      validUntil: '2026-09-20T00:00:00.000Z',
      revokedAt: '2026-09-25T00:00:00.000Z',
      revocationReason: 'ISSUER_REQUEST',
      lastTreeSize: 6,
    });
    const late = issue(issuer, {
      observedAt: '2026-09-21T11:30:00.000Z',
      issuedAt: '2026-09-21T12:00:00.000Z',
    });
    assert.equal(
      (await verifyReceipt(late.envelope, trustWith(retiredThenDisowned))).rule,
      'key.retired',
    );
    const tie = keyEntry(issuer, 'REVOKED', {
      validUntil: '2026-09-20T00:00:00.000Z',
      revokedAt: '2026-09-20T00:00:00.000Z',
      revocationReason: 'ISSUER_REQUEST',
      lastTreeSize: 6,
    });
    assert.equal((await verifyReceipt(late.envelope, trustWith(tie))).rule, 'key.disowned');
    const whileActive = keyEntry(issuer, 'REVOKED', {
      revokedAt: '2026-09-20T00:00:00.000Z',
      revocationReason: 'ISSUER_REQUEST',
      lastTreeSize: 6,
    });
    const early = issue(issuer, {
      observedAt: '2026-09-10T11:30:00.000Z',
      issuedAt: '2026-09-10T12:00:00.000Z',
      freshUntil: '2026-10-30T00:00:00.000Z',
    });
    const r = await verifyReceipt(logged(early, 5), trustWith(whileActive));
    assert.equal(r.verdict, 'VALID');
    assert.match(
      r.summary,
      /KEY DISOWNED BY THE ISSUER AT 2026-09-20T00:00:00\.000Z, after this receipt/,
    );
  });

  test('an unverified log section never dates a retired key: without a trusted log key it stays unproven', async () => {
    const entry = keyEntry(issuer, 'RETIRED', {
      validUntil: '2026-10-05T00:00:00.000Z',
      lastTreeSize: 4,
    });
    const trust = trustWith(entry);
    trust.keyDocument = keyDocument({ keys: [entry] }); // no log keys at all
    const r = await verifyReceipt(logged(issue(issuer), 3), trust);
    assert.equal(r.rule, 'key.retired-unproven');
    assert.equal(r.checks.find((c) => c.name === 'log.inclusion').outcome, 'PASS');
    assert.equal(r.checks.find((c) => c.name === 'log.checkpoint').outcome, 'SKIP');
  });
});

describe('the residual attack of spec section 6.5: a retired issuer key and a trusted log key', () => {
  test('offline it verifies; the log checkpoint of the same size, with another root, makes it INVALID (equivocation)', async () => {
    const retired = testKey('residual retired issuer');
    const activeLog = testKey('residual active log');
    const origin = 'cmdash.example/cmdash-proof-log';
    const entry = keyEntry(retired, 'RETIRED', {
      validFrom: '2026-06-01T00:00:00.000Z',
      validUntil: '2026-09-01T00:00:00.000Z',
      lastTreeSize: 6,
    });
    const trust = {
      now: NOW,
      deployments: ['https://cmdash.example'],
      keyDocument: keyDocument({
        keys: [keyEntry(testKey('residual current issuer')), entry],
        log: logKeyDocument(origin, [logKeyEntry(activeLog)]),
      }),
      keyDocumentUrl: keyDocumentUrl(),
    };
    // Backdated 1 ms before the retirement and fresh for 400 days, in a fake tree the attacker's log key signs.
    const forged = issue(retired, {
      observedAt: '2026-08-31T23:59:59.999Z',
      issuedAt: '2026-08-31T23:59:59.999Z',
      freshUntil: '2027-10-05T23:59:59.999Z',
    });
    const fake = logSectionFor(forged.digest, { index: 2, size: 7, logKeys: [activeLog] });
    const offline = await verifyReceipt({ ...forged.envelope, log: fake }, trust);
    assert.equal(
      offline.verdict,
      'VALID',
      'the documented residual: offline, a fake tree under a trusted log key verifies',
    );
    const realRoot = sha256("the log's real tree of 7");
    const theLogsOwn = checkpointNote(origin, 7, realRoot, [activeLog]);
    const online = await verifyReceipt(
      { ...forged.envelope, log: fake },
      { ...trust, checkpoint: theLogsOwn },
    );
    assert.deepEqual(
      [online.verdict, online.failedCheck, online.rule],
      ['INVALID', 'log.external', 'external.equivocation'],
    );
    // And without the section (the CLI's answer to a 404 for that size), a retired key's receipt is UNVERIFIABLE.
    assert.equal((await verifyReceipt(forged.envelope, trust)).rule, 'key.retired-unproven');
  });
});

describe('the summary and output safety (spec sections 9.3, 9.5)', () => {
  test("the summary's words: stale first, disowned, plain http, not proven, not logged, self-assessed, the structure over the statement", async () => {
    assert.match(
      (await run('14-stale')).summary,
      /^STALE - expired 2026-10-08T11:30:00\.000Z; the signature is valid - /,
    );
    assert.match(
      (await run('81-disowned-key-before-logged')).summary,
      /KEY DISOWNED BY THE ISSUER AT 2026-03-01T00:00:00\.000Z, after this receipt/,
    );
    const d7 = await run('D7-plain-http-deployment-allowed');
    assert.equal(d7.plainHttp, true);
    assert.match(d7.summary, /KEY DOCUMENT FROM A PLAIN-HTTP DEPLOYMENT/);
    assert.doesNotMatch(
      (await run('01-valid-measured-all')).summary,
      /DISOWNED|PLAIN-HTTP|NOT PROVEN/,
    );
    assert.match((await run('01-valid-measured-all')).summary, /NOT LOGGED/);
    assert.match((await run('06-valid-logged')).summary, /LOGGED at index 5 of 7/);
    assert.match(
      (await run('79-key-document-older-than-receipt')).summary,
      /KEY STATUS NOT PROVEN/,
    );
    assert.match(
      (await run('04-valid-score')).summary,
      /SELF-ASSESSED SCORE 74 on a scale from -203 to 110/,
    );
    assert.match((await run('57-valid-statement-overclaims')).summary, /RATIO: 120 of 128 host/);
    assert.match(
      (await run('05-valid-self-attested')).summary,
      /SELF-ATTESTED by a person in role OWNER/,
    );
    assert.match(
      (await run('15-tampered-payload')).summary,
      /^INVALID - signature\.verify \(ed25519\.mismatch\): .*NOT ATTRIBUTABLE/,
    );
    assert.doesNotMatch(
      (await run('41-all-with-unknown')).summary,
      /NOT ATTRIBUTABLE/,
      'a verified signature over an inadmissible claim is attributable',
    );
    assert.match(
      (await run('D3-deployment-untrusted')).summary,
      /^UNVERIFIABLE - issuer\.key \(key\.deployment-untrusted\)/,
    );
  });

  test('a hostile member name can never close its own quotes, and a long one is truncated', async () => {
    const x = v('01-valid-measured-all');
    const name = `x"; VALID ${TENANT.slice(0, 8)} \\ end\u{1b}[2K\r\u{202e}`;
    const r = await verifyReceipt({ ...x.input.receipt, [name]: 1 }, x.input.trust);
    assert.equal(r.verdict, 'INVALID');
    assert.match(r.summary, PRINTABLE);
    assert.ok(
      r.summary.includes(
        `unknown member "x\\"; VALID ${TENANT.slice(0, 8)} \\\\ end\\u{1b}[2K\\u{d}\\u{202e}"`,
      ),
      r.summary,
    );
    const detail = r.checks.find((c) => c.name === 'envelope.shape').detail;
    const inner = /unknown member "((?:[^"\\]|\\.)*)"/.exec(detail);
    assert.ok(inner && inner[1].includes('\\"'), detail);
    const long = await verifyReceipt({ ...x.input.receipt, ['y'.repeat(200)]: 1 }, x.input.trust);
    assert.match(long.summary, new RegExp(`"${'y'.repeat(64)}" \\(truncated\\)`));
  });

  test('every summary and detail of every vector, on every backend used here, is printable ASCII', async () => {
    for (const x of vectors) {
      for (const options of [undefined, { backend: webCryptoBackend(undefined) }]) {
        const r = await verifyReceipt(x.input.receipt, x.input.trust, options);
        assert.match(r.summary, PRINTABLE, x.id);
        for (const c of r.checks) assert.match(c.detail, PRINTABLE, `${x.id} ${c.name}`);
      }
    }
  });
});

describe('the backends: a primitive that fails has not said "valid"', () => {
  const x = v('01-valid-measured-all');
  const spki = Uint8Array.from(
    Buffer.from(x.input.trust.keyDocument.keys[0].publicKey, 'base64url'),
  );
  const msg = new Uint8Array(4);
  const sig = new Uint8Array(64);

  test('node:crypto: an SPKI it cannot import, or a verify that throws, reads as unavailable (null)', async () => {
    assert.equal(await nodeBackend.ed25519Verify(new Uint8Array(3), msg, sig), null);
    assert.equal(await nodeBackend.ed25519Verify(spki, msg, 'not bytes'), null);
    assert.equal(await nodeBackend.ed25519Verify(spki, msg, sig), false);
  });

  test('WebCrypto: no importKey, an import that throws, or a verify that throws, read as unavailable (null)', async () => {
    const real = globalThis.crypto.subtle;
    const cases = [
      { digest: real.digest.bind(real) },
      {
        digest: real.digest.bind(real),
        importKey: async () => Promise.reject(new Error('x')),
        verify: real.verify.bind(real),
      },
      {
        digest: real.digest.bind(real),
        importKey: real.importKey.bind(real),
        verify: async () => Promise.reject(new Error('x')),
      },
    ];
    for (const subtle of cases)
      assert.equal(await webCryptoBackend({ subtle }).ed25519Verify(spki, msg, sig), null);
    assert.equal(webCryptoBackend(null).hashes, false);
    assert.equal(await webCryptoBackend(globalThis.crypto).ed25519Verify(spki, msg, sig), false);
  });

  test('a log key set supplied as text is read strictly; a key that does not hash to its id makes it malformed', async () => {
    const x06 = v('06-valid-logged');
    assert.equal((await run(x06.id, { logKeys: 'not JSON' })).rule, 'log-keys.malformed');
    const logKeys = structuredClone(x06.input.trust.keyDocument.log);
    assert.equal((await run(x06.id, { logKeys: JSON.stringify(logKeys) })).verdict, 'VALID');
    logKeys.keys[0].publicKey = x06.input.trust.keyDocument.keys[0].publicKey;
    const r = await run(x06.id, { logKeys });
    assert.deepEqual([r.verdict, r.rule], ['UNVERIFIABLE', 'log-keys.malformed']);
    assert.match(r.summary, /does not hash to its id/);
  });
});

describe('degraded runtimes: never VALID without both implementations of Ed25519', () => {
  const noEd25519 = {
    subtle: {
      digest: (...a) => globalThis.crypto.subtle.digest(...a),
      importKey: async () => {
        throw new DOMException('Ed25519 is not supported', 'NotSupportedError');
      },
      verify: async () => {
        throw new DOMException('Ed25519 is not supported', 'NotSupportedError');
      },
    },
  };

  test('no WebCrypto at all (a plain-HTTP page): UNVERIFIABLE with ed25519.unavailable and "use the CLI", or INVALID from the checks that need no crypto', async () => {
    let unverifiable = 0;
    for (const x of vectors) {
      const r = await verifyReceipt(x.input.receipt, x.input.trust, {
        backend: webCryptoBackend(undefined),
      });
      assert.ok(r.verdict === 'UNVERIFIABLE' || r.verdict === 'INVALID', `${x.id}: ${r.verdict}`);
      assert.equal(r.digest, null);
      if (r.rule === 'ed25519.unavailable') {
        unverifiable += 1;
        assert.match(r.summary, /use the CLI \(cmdash-verify\) or serve this page over HTTPS/);
      }
    }
    assert.ok(unverifiable > 60, `${unverifiable}`);
    const r = await run('01-valid-measured-all', {}, { backend: webCryptoBackend({}) });
    assert.deepEqual(
      [r.verdict, r.failedCheck, r.rule],
      ['UNVERIFIABLE', 'signature.verify', 'ed25519.unavailable'],
    );
  });

  test('WebCrypto without Ed25519: no vector is VALID or STALE_VALID; what the equation refuses stays INVALID', async () => {
    const backend = webCryptoBackend(noEd25519);
    for (const x of vectors) {
      const r = await verifyReceipt(x.input.receipt, x.input.trust, { backend });
      assert.ok(r.verdict !== 'VALID' && r.verdict !== 'STALE_VALID', `${x.id}: ${r.verdict}`);
      if (x.expect.verdict === 'VALID' || x.expect.verdict === 'STALE_VALID')
        assert.equal(r.rule, 'ed25519.unavailable', x.id);
      if (x.expect.rule === 'ed25519.mismatch' || x.expect.rule === 'ed25519.key-small-order')
        assert.equal(r.rule, x.expect.rule, x.id);
    }
  });

  test('a platform that accepts every signature changes no verdict: the equation is complete on its own', async () => {
    const yesMan = { ...nodeBackend, ed25519Verify: async () => true };
    for (const x of vectors)
      assertMatchesVector(
        await verifyReceipt(x.input.receipt, x.input.trust, { backend: yesMan }),
        x,
        ' [yes-man platform]',
      );
  });

  test('a platform that refuses every signature makes nothing VALID', async () => {
    const noMan = { ...nodeBackend, ed25519Verify: async () => false };
    for (const x of vectors) {
      const r = await verifyReceipt(x.input.receipt, x.input.trust, { backend: noMan });
      assert.ok(r.verdict !== 'VALID' && r.verdict !== 'STALE_VALID', x.id);
    }
  });
});
