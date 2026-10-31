// SPDX-License-Identifier: Apache-2.0
/**
 * The hand-written validators against receipt.schema.json: the patterns are
 * the schema's own (drift fails here), the canonical origin grammar of spec
 * section 6.2, the refused text code points of section 5.5 (the schema's
 * pattern against the spec's table, every code point), the calendar rule of
 * section 4, and the key-document malformation rules of section 6.3.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import {
  SCHEMA_PATTERNS,
  SCHEMA_RE,
  keyDocumentProblems,
  parseTimestamp,
  payloadProblems,
} from '../lib/schema.mjs';
import { verifyReceipt } from '../lib/verify.mjs';
import { SPEC_DIR, byId, loadVectors, payloadOf } from './helpers.js';

const schema = JSON.parse(readFileSync(join(SPEC_DIR, 'receipt.schema.json'), 'utf8'));
const vectors = loadVectors();

test("every embedded pattern is the schema file's own, verbatim, and every schema pattern is embedded", () => {
  const fromSchema = { payloadBase64Url: schema.properties.payload.pattern };
  for (const [name, def] of Object.entries(schema.$defs))
    if (def.pattern) fromSchema[name] = def.pattern;
  assert.deepEqual(Object.keys(SCHEMA_PATTERNS).sort(), Object.keys(fromSchema).sort());
  for (const [name, pattern] of Object.entries(fromSchema))
    assert.equal(SCHEMA_PATTERNS[name], pattern, name);
});

test('the canonical origin grammar (spec section 6.2): one spelling per origin; plain http only on loopback unless allowed', () => {
  const cases = [
    // [origin, a deployment every verifier accepts, a plain-http origin]
    ['https://cmdash.example', true, false],
    ['https://app.cmdash.net:8443', true, false],
    ['https://xn--cmdsh-9ra.example', true, false],
    ['https://intranet', true, false],
    ['https://10.0.0.5', true, false],
    ['https://cmdash.example:65535', true, false],
    [`https://${'a'.repeat(63)}.example`, true, false],
    ['http://localhost:3001', true, true],
    ['http://127.0.0.1', true, true],
    ['http://10.0.0.5', false, true],
    ['http://app.cmdash.net', false, true],
    ['http://127.0.0.2:8080', false, true],
    ['https://cmdash.example.', false, false],
    ['https://cmdash.example:443', false, false],
    ['http://cmdash.example:80', false, false],
    ['http://localhost:80', false, false],
    ['https://cmdash.example:0', false, false],
    ['https://cmdash.example:99999', false, false],
    ['https://cmdash.example:65536', false, false],
    ['https://cmdash.example:0443', false, false],
    ['https://-', false, false],
    ['https://..', false, false],
    ['https://a..b', false, false],
    ['https://a-.example', false, false],
    ['https://-a.example', false, false],
    [`https://${'a'.repeat(64)}.example`, false, false],
    ['https://010.0.0.5', false, false],
    ['https://256.0.0.1', false, false],
    ['https://cmdash.123', false, false],
    ['https://Cmdash.example', false, false],
    ['https://cmdash.example/', false, false],
    ['https://user@cmdash.example', false, false],
    ['https://[::1]', false, false],
    ['ftp://cmdash.example', false, false],
  ];
  for (const [origin, byDefault, plain] of cases) {
    assert.equal(SCHEMA_RE.deployment.test(origin), byDefault, `default: ${origin}`);
    assert.equal(SCHEMA_RE.plainHttpDeployment.test(origin), plain, `plain http: ${origin}`);
  }
});

test('the text pattern refuses exactly the code points of the spec section 5.5 table (every code point checked)', () => {
  // The table of spec section 5.5, transcribed independently of the schema's pattern.
  const refused = [
    [0x0, 0x1f],
    [0x7f, 0x9f],
    [0xad, 0xad],
    [0x34f, 0x34f],
    [0x115f, 0x1160],
    [0x17b4, 0x17b5],
    [0x180b, 0x180f],
    [0x3164, 0x3164],
    [0xffa0, 0xffa0],
    [0x61c, 0x61c],
    [0x200e, 0x200f],
    [0x202a, 0x202e],
    [0x2066, 0x206f],
    [0x200b, 0x200d],
    [0x2060, 0x2065],
    [0xfeff, 0xfeff],
    [0x2028, 0x2029],
    [0xfe00, 0xfe0f],
    [0xe0100, 0xe01ef],
    [0xe0000, 0xe0fff],
    [0xfff0, 0xfffb],
    [0x1bca0, 0x1bca3],
    [0x1d173, 0x1d17a],
    [0xe000, 0xf8ff],
    [0xf0000, 0x10ffff],
  ];
  const isRefused = (cp) => refused.some(([lo, hi]) => cp >= lo && cp <= hi);
  let disagreements = 0;
  for (let cp = 0; cp <= 0x10ffff; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    if (SCHEMA_RE.text.test(`a${String.fromCodePoint(cp)}b`) === isRefused(cp)) disagreements += 1;
  }
  assert.equal(disagreements, 0);
});

test('timestamps: the exact form, years 1970-9999, and a real calendar instant (no 30 February, no leap second)', () => {
  assert.equal(parseTimestamp('2026-10-01T12:00:00.000Z'), Date.UTC(2026, 9, 1, 12));
  assert.equal(parseTimestamp('2028-02-29T00:00:00.000Z'), Date.UTC(2028, 1, 29));
  assert.equal(parseTimestamp('1970-01-01T00:00:00.000Z'), 0);
  assert.equal(parseTimestamp('9999-12-31T23:59:59.999Z'), Date.UTC(9999, 11, 31, 23, 59, 59, 999));
  for (const bad of [
    '2027-02-30T11:30:00.000Z',
    '2027-02-29T00:00:00.000Z',
    '2026-04-31T00:00:00.000Z',
    '2026-10-01T12:00:60.000Z',
    '0000-01-01T00:00:00.000Z',
    '1969-12-31T23:59:59.999Z',
    '2026-10-01T12:00:00Z',
    '2026-10-01t12:00:00.000z',
    '2026-10-01T12:00:00.000+00:00',
    ' 2026-10-01T12:00:00.000Z',
    20261001,
  ]) {
    assert.equal(parseTimestamp(bad), null, String(bad));
  }
});

describe('the payload schema, beyond what the vectors pin', () => {
  const base = payloadOf(byId(vectors, '01-valid-measured-all'));
  const clone = () => structuredClone(base);
  test('the vector 01 payload is valid, and each single defect is a problem', () => {
    assert.deepEqual(payloadProblems(base), []);
    const defects = [
      (p) => delete p.evidence,
      (p) => (p.extra = 1),
      (p) => (p.claim.controls = [p.claim.controls[0], p.claim.controls[0]]),
      (p) => (p.sources = []),
      (p) => (p.sources = [{ kind: 'PERSON', ref: 'self-attestation' }]),
      (p) => (p.measurement.numerator = 1000000001),
      (p) => (p.measurement.method.version = 0),
      (p) => (p.claim.statement = 'x'.repeat(501)),
      (p) => (p.claim.statement = ''),
      (p) =>
        (p.claim.assertion = { kind: 'AT_LEAST', threshold: { numerator: 1, denominator: 1 } }),
      (p) => (p.claim.assertion = { kind: 'SCORE', value: 1, min: 0 }),
      (p) => (p.claim.assertion = { kind: 'MOST' }),
      (p) => (p.selfAttested = { byRole: 'OWNER', at: base.observedAt }),
      (p) => (p.issuer.deployment = 'https://cmdash.example:443'),
      (p) => (p.issuer.tenantRef = 'tr_ABC'),
      (p) => (p.supersedes = 'not-a-ulid'),
      (p) => (p.evidence.algo = 'sha256'),
      (p) => (p.measurement.scope.unit = 'User'),
    ];
    for (const defect of defects) {
      const p = clone();
      defect(p);
      assert.notDeepEqual(payloadProblems(p), [], defect.toString());
    }
    assert.notDeepEqual(payloadProblems([]), []);
    const p = clone();
    p.claim.controls = ['cmmc-l2', p.claim.controls[0]];
    assert.match(
      payloadProblems(p).join('; '),
      /claim\.controls\[0\]: must be an object, not "cmmc-l2"/,
    );
    p.sources = 'okta';
    assert.match(payloadProblems(p).join('; '), /sources: must be an array, not "okta"/);
  });

  test('statement length counts code points, as JSON Schema does: 500 astral characters are admitted', () => {
    const p = clone();
    p.claim.statement = '\u{1f600}'.repeat(500);
    assert.deepEqual(payloadProblems(p), []);
    p.claim.statement += '\u{1f600}';
    assert.notDeepEqual(payloadProblems(p), []);
  });
});

describe('key documents (spec section 6.3): a malformed one is useless for every receipt', () => {
  const v = byId(vectors, '01-valid-measured-all');
  const run = (doc) => verifyReceipt(v.input.receipt, { ...v.input.trust, keyDocument: doc });
  const mutations = [
    ['an ACTIVE key with validUntil', (d) => (d.keys[0].validUntil = '2027-01-01T00:00:00.000Z')],
    ['an ACTIVE key with lastTreeSize', (d) => (d.keys[0].lastTreeSize = 3)],
    ['a RETIRED key without validUntil', (d) => delete d.keys[1].validUntil],
    ['a RETIRED key with revokedAt', (d) => (d.keys[1].revokedAt = '2026-09-02T00:00:00.000Z')],
    ['a REVOKED key without its reason', (d) => delete d.keys[2].revocationReason],
    [
      'a RETIRED log key without lastTreeSize',
      (d) => {
        d.log.keys[0].status = 'RETIRED';
        d.log.keys[0].validUntil = '2026-10-01T00:00:00.000Z';
      },
    ],
    [
      'a public key with spare bits set',
      (d) => (d.keys[0].publicKey = `${d.keys[0].publicKey.slice(0, -1)}B`),
    ],
    ['no deployment', (d) => delete d.deployment],
    ['a non-canonical deployment', (d) => (d.deployment = 'https://CMDASH.example/')],
    ['a key that does not hash to its id', (d) => (d.keys[0].publicKey = d.keys[1].publicKey)],
    ['a repeated key id', (d) => d.keys.push({ ...d.keys[0] })],
    [
      'two ACTIVE keys',
      (d) => {
        d.keys[1].status = 'ACTIVE';
        delete d.keys[1].validUntil;
        delete d.keys[1].lastTreeSize;
      },
    ],
    ['a window that ends when it starts', (d) => (d.keys[1].validUntil = d.keys[1].validFrom)],
    ['revokedAt before validFrom', (d) => (d.keys[2].revokedAt = '2026-01-01T00:00:00.000Z')],
    [
      'an embedded log key set that repeats a key id',
      (d) =>
        d.log.keys.push({
          ...d.log.keys[0],
          status: 'RETIRED',
          validUntil: '2026-09-10T00:00:00.000Z',
          lastTreeSize: 3,
        }),
    ],
    [
      'an embedded log key that does not hash to its id',
      (d) => (d.log.keys[0].publicKey = d.keys[0].publicKey),
    ],
    [
      'more than 1024 keys',
      (d) => {
        while (d.keys.length <= 1024)
          d.keys.push({
            ...d.keys[1],
            kid: `cmdash-proof-${d.keys.length.toString(16).padStart(16, '0')}`,
          });
      },
    ],
  ];
  test('the unmodified document verifies', async () => {
    assert.equal((await run(v.input.trust.keyDocument)).verdict, 'VALID');
  });
  for (const [what, mutate] of mutations) {
    test(`${what} -> key.document-malformed`, async () => {
      const doc = JSON.parse(JSON.stringify(v.input.trust.keyDocument));
      mutate(doc);
      const r = await run(JSON.parse(JSON.stringify(doc)));
      assert.equal(r.verdict, 'UNVERIFIABLE');
      assert.equal(r.rule, 'key.document-malformed', r.summary);
    });
  }
  test('the schema-only validator agrees on the schema-level defects', () => {
    assert.deepEqual(keyDocumentProblems(v.input.trust.keyDocument), []);
    assert.notDeepEqual(keyDocumentProblems({ ...v.input.trust.keyDocument, extra: true }), []);
  });
});
