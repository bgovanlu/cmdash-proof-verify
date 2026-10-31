// SPDX-License-Identifier: Apache-2.0
/**
 * Evidence openings and sampled items (spec section 8), beyond the vectors:
 * each rule of the opening and item tables fires on its own defect, and the
 * attestation record of a self-attested receipt is exactly
 * { statement, userId } with the signed statement.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  canonicalize,
  verifyEvidenceItem,
  verifyEvidenceOpening,
  webCryptoBackend,
} from '../lib/verify.mjs';
import { TENANT, byId, issue, loadVectors, sha256, testKey } from './helpers.js';

const vectors = loadVectors();
const v01 = byId(vectors, '01-valid-measured-all');
const v05 = byId(vectors, '05-valid-self-attested');
const opening = v01.input.evidenceOpening;
const item = v01.input.evidenceItems[0];

describe('openings (spec section 8.2)', () => {
  test('the vector 01 opening matches, as text, as bytes and as an object', async () => {
    for (const o of [
      opening,
      JSON.stringify(opening),
      new TextEncoder().encode(JSON.stringify(opening)),
    ]) {
      const r = await verifyEvidenceOpening(v01.input.receipt, o);
      assert.equal(r.match, true, r.detail);
      assert.equal(r.rule, null);
    }
  });

  test('each rule fires on its own defect, in the order of the table', async () => {
    const cases = [
      ['{}', opening, 'opening.receipt-undecodable'],
      [
        JSON.stringify(v01.input.receipt).replace('"v":0', '"v":1'),
        opening,
        'opening.receipt-undecodable',
      ],
      [
        v01.input.receipt,
        JSON.stringify(opening).replace('"salt":', '"salt":"00","salt":'),
        'opening.malformed',
      ],
      [v01.input.receipt, { ...opening, extra: 1 }, 'opening.malformed'],
      [v01.input.receipt, { ...opening, v: 1 }, 'opening.malformed'],
      [v01.input.receipt, 'not json', 'opening.malformed'],
      [
        v01.input.receipt,
        { ...opening, receiptId: '01M3VNBWG0WWTF65KKAVPE61Y9' },
        'opening.receipt',
      ],
      [v01.input.receipt, { ...opening, salt: '00'.repeat(32) }, 'opening.commitment'],
      [
        v01.input.receipt,
        { ...opening, manifest: { ...opening.manifest, itemCount: 129 } },
        'opening.commitment',
      ],
    ];
    for (const [receipt, o, rule] of cases)
      assert.equal((await verifyEvidenceOpening(receipt, o)).rule, rule, rule);
  });

  test('a manifest with a null, an unknown member or a gap is malformed: every member is typed', async () => {
    const m = opening.manifest;
    const { itemsRoot, ...withoutRoot } = m;
    assert.match(itemsRoot, /^[0-9a-f]{64}$/);
    const bad = [
      { ...m, method: null },
      { ...m, counts: null },
      { ...m, itemsRoot: null },
      { ...m, selfAttested: null },
      { ...m, counts: { ...m.counts, extra: 1 } },
      { ...m, itemCount: -1 },
      { ...m, selfAttested: { byRole: 'OWNER', at: m.observedAt } },
      withoutRoot,
    ];
    for (const manifest of bad)
      assert.equal(
        (await verifyEvidenceOpening(v01.input.receipt, { ...opening, manifest })).rule,
        'opening.malformed',
        JSON.stringify(manifest).slice(0, 60),
      );
  });

  test('an opening whose commitment opens but whose header describes another receipt is refused, field by field', async () => {
    const key = testKey('evidence header');
    const salt = sha256('evidence header salt');
    const receiptId = '01M3VNBWG0WWTF65KKAVPE61ZA';
    const measured = {
      receiptId,
      issuer: { deployment: 'https://cmdash.example', tenantRef: TENANT, keyId: key.kid },
      claimId: 'cmmc-l2.ia.mfa-enrolled',
      observedAt: '2026-10-01T11:30:00.000Z',
      itemCount: 1,
      itemsRoot: sha256('items').toString('hex'),
      counts: { numerator: 10, denominator: 10, unknown: 0 },
      method: { id: 'identity-coverage.mfa-enrolled', version: 1 },
    };
    const attested = {
      ...measured,
      counts: undefined,
      method: undefined,
      selfAttested: { byRole: 'OWNER', at: measured.observedAt },
    };
    const selfAttestedPayload = {
      claim: {
        claimId: measured.claimId,
        statement: 'We review access quarterly.',
        controls: [],
        assertion: { kind: 'SELF_ATTESTED' },
      },
      measurement: undefined,
      selfAttested: { byRole: 'OWNER', at: measured.observedAt },
      sources: [{ kind: 'PERSON', ref: 'self-attestation' }],
    };
    const check = async (manifest, payloadOverrides = {}) => {
      const m = JSON.parse(JSON.stringify(manifest));
      const commitment = sha256(
        Buffer.from('cmdash-receipt-evidence-v0\n'),
        salt,
        Buffer.from(canonicalize(m)),
      ).toString('hex');
      const r = issue(key, {
        receiptId,
        evidence: { algo: 'sha256-salted', commitment },
        ...payloadOverrides,
      });
      return verifyEvidenceOpening(r.envelope, {
        format: 'cmdash-evidence-opening',
        v: 0,
        receiptId,
        salt: salt.toString('hex'),
        manifest: m,
      });
    };
    assert.equal((await check(measured)).match, true);
    assert.equal((await check(attested, selfAttestedPayload)).match, true);
    const defects = [
      [
        {
          ...measured,
          issuer: { ...measured.issuer, tenantRef: 'tr_ffffffffffffffffffffffffffffffff' },
        },
        {},
        /another issuer/,
      ],
      [
        { ...measured, issuer: { ...measured.issuer, keyId: testKey('other').kid } },
        {},
        /another issuer/,
      ],
      [{ ...measured, claimId: 'other.claim' }, {}, /names the claim/],
      [{ ...measured, observedAt: '2026-10-01T11:29:59.999Z' }, {}, /observedAt/],
      [{ ...measured, counts: { numerator: 9, denominator: 10, unknown: 0 } }, {}, /counts/],
      [{ ...measured, method: { id: 'identity-coverage.mfa-enrolled', version: 2 } }, {}, /method/],
      [attested, {}, /self-attestation, and the receipt is measured/],
      [measured, selfAttestedPayload, /measurement, and the receipt is self-attested/],
      [
        { ...attested, selfAttested: { byRole: 'ADMIN', at: measured.observedAt } },
        selfAttestedPayload,
        /role or time/,
      ],
    ];
    for (const [manifest, overrides, why] of defects) {
      const r = await check(manifest, overrides);
      assert.equal(r.rule, 'opening.header', why.source);
      assert.match(r.detail, why);
    }
  });

  test('an opening is at most 65536 bytes', async () => {
    const huge = `${JSON.stringify(opening).slice(0, -1)}${' '.repeat(65536)}}`;
    const r = await verifyEvidenceOpening(v01.input.receipt, huge);
    assert.equal(r.rule, 'opening.malformed');
    assert.match(r.detail, /json\.too-large/);
  });
});

describe('sampled items (spec section 8.3)', () => {
  test('the vector 01 item matches', async () => {
    assert.equal((await verifyEvidenceItem(v01.input.receipt, opening, item)).match, true);
  });

  test('each rule fires on its own defect', async () => {
    const cases = [
      [{ ...opening, salt: '00'.repeat(32) }, item, 'item.opening'],
      [opening, { ...item, extra: 1 }, 'item.malformed'],
      [opening, { ...item, item: [] }, 'item.malformed'],
      [opening, { ...item, item: { ref: 'user-0042', state: null } }, 'item.malformed'],
      [opening, { ...item, item: { ref: 'user-0042', score: 0.5 } }, 'item.malformed'],
      [opening, { ...item, proof: [...item.proof, 'zz'] }, 'item.malformed'],
      [opening, { ...item, receiptId: '01M3VNBWG0WWTF65KKAVPE61Y9' }, 'item.receipt'],
      [opening, { ...item, itemCount: item.itemCount + 1 }, 'item.count'],
      [opening, { ...item, index: 128 }, 'item.count'],
      [opening, { ...item, item: { ...item.item, state: 'NOT_MET' } }, 'item.inclusion'],
      [opening, { ...item, index: item.index + 1 }, 'item.inclusion'],
      [opening, { ...item, salt: '11'.repeat(32) }, 'item.inclusion'],
      [opening, { ...item, proof: item.proof.slice(1) }, 'item.inclusion'],
    ];
    for (const [o, it, rule] of cases)
      assert.equal(
        (await verifyEvidenceItem(v01.input.receipt, o, it)).rule,
        rule,
        `${rule}: ${JSON.stringify(it).slice(0, 60)}`,
      );
    assert.equal(
      (await verifyEvidenceItem(v01.input.receipt, undefined, item)).rule,
      'item.opening',
    );
  });

  test('item 0 of a self-attested receipt must be exactly { statement, userId } with the signed statement', async () => {
    const it = v05.input.evidenceItems[0];
    assert.deepEqual(Object.keys(it.item).sort(), ['statement', 'userId']);
    assert.equal(
      (await verifyEvidenceItem(v05.input.receipt, v05.input.evidenceOpening, it)).match,
      true,
    );
    const e2 = byId(vectors, 'E2-self-attested-item-0-differs');
    const r = await verifyEvidenceItem(
      e2.input.receipt,
      e2.input.evidenceOpening,
      e2.input.evidenceItems[0],
    );
    assert.equal(r.rule, 'item.attestation');
  });

  test('without WebCrypto nothing is checked, and nothing matches', async () => {
    const none = { backend: webCryptoBackend(undefined) };
    const o = await verifyEvidenceOpening(v01.input.receipt, opening, none);
    assert.deepEqual([o.match, o.rule], [false, null]);
    assert.match(o.detail, /use the CLI/);
    const i = await verifyEvidenceItem(v01.input.receipt, opening, item, none);
    assert.deepEqual([i.match, i.rule], [false, null]);
  });
});
