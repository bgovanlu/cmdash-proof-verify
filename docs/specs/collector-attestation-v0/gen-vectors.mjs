#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Licence per owner decision ⚑4 (the receipt spec and its verifier).
/**
 * Regenerates the collector-attestation conformance vectors in ./vectors,
 * deterministically (docs/specs/collector-attestation-v0.md section 7).
 *
 *   node docs/specs/collector-attestation-v0/gen-vectors.mjs
 *   git diff --exit-code docs/specs/collector-attestation-v0/vectors   # nothing may move
 *
 * INDEPENDENCE. Like ../proof-receipt-v0/gen-vectors.mjs, this file imports
 * neither the verifier (packages/proof-verify) nor the collector
 * (packages/connector-runtime): it has its own canonical serializer and signs
 * with node:crypto directly, and every expected status, rule, key source and
 * proves / does-not-prove list below is AUTHORED from the spec, never
 * captured from a verifier run.
 *
 * KEYS. Every private key is derived at run time from a public seed string.
 * These are TEST keys whose private halves are public by construction; none
 * may ever sign a real receipt or measurement. The vectors carry public keys
 * only.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdirSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'vectors');

const sha256 = (b) => createHash('sha256').update(b).digest();
const hex = (b) => b.toString('hex');
const utf8 = (s) => Buffer.from(s, 'utf8');
const b64u = (b) => Buffer.from(b).toString('base64url');

const PKCS8_ED25519_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

function testKey(label, prefix) {
  const seed = sha256(utf8(`cmdash collector-attestation v0 PUBLIC TEST VECTOR KEY, never trust: ${label}`));
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_HEADER, seed]), format: 'der', type: 'pkcs8' });
  const spkiDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return { privateKey, spkiDer, spki: b64u(spkiDer), kid: `${prefix}${hex(sha256(spkiDer)).slice(0, 16)}` };
}

/** The generator's own canonical serializer (receipt spec section 3) for the values it builds. */
function canon(v) {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object' && v !== null) {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
      .join(',')}}`;
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Number.isSafeInteger(v) && !Object.is(v, -0)) return String(v);
  throw new Error(`gen-vectors: ${String(v)} is not canonicalizable`);
}

const NOW = '2026-10-12T00:00:00.000Z';
const DEPLOYMENT = 'https://cmdash.example';
const TENANT_A = 'tr_73513a69a549ad23b7a9075e962f8e1e';
const TENANT_B = 'tr_0c6a4e1f9b2d8a7c5e3f1b0d9c8a7e6f';

const ISSUER = testKey('issuer, tenant A', 'cmdash-proof-');
const COLLECTOR = testKey('collector 1, tenant A', 'cmdash-collector-');
const OTHER_COLLECTOR = testKey('collector 2, tenant A', 'cmdash-collector-');

/** The identity point: order 1, the worst key there is. */
const SMALL_ORDER_SPKI = Buffer.concat([SPKI_ED25519_HEADER, Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex')]);
const SMALL_ORDER = { spkiDer: SMALL_ORDER_SPKI, spki: b64u(SMALL_ORDER_SPKI), kid: `cmdash-collector-${hex(sha256(SMALL_ORDER_SPKI)).slice(0, 16)}` };

const MEASUREMENT_TAG = 'cmdash-collector-measurement-v0\n';
const PUSH_TAG = 'cmdash-collector-push-v2\n';

// ─── receipts (unchanged receipt format v0) ─────────────────────────────────

function receipt({ sources, measurement = { numerator: 47, denominator: 50, unknown: 1 }, observedAt = '2026-10-01T11:30:00.000Z', issuedAt = '2026-10-01T12:00:00.000Z', selfAttested = false, receiptId = '01M3VNBWG0W1F5YERWA2JF9YDY' }) {
  const payload = {
    receiptId,
    issuer: { deployment: DEPLOYMENT, tenantRef: TENANT_A, keyId: ISSUER.kid },
    claim: selfAttested
      ? { claimId: 'collector-attested.si.malicious-code-protection', statement: 'Every host runs an active endpoint-detection agent.', controls: [{ framework: 'cmmc-l2', controlId: 'SI.L2-3.14.2' }], assertion: { kind: 'SELF_ATTESTED' } }
      : { claimId: 'collector-attested.si.malicious-code-protection', statement: 'Runs an active endpoint-detection agent: hosts the supplier collector reported.', controls: [{ framework: 'cmmc-l2', controlId: 'SI.L2-3.14.2' }], assertion: { kind: 'RATIO' } },
    ...(selfAttested
      ? { selfAttested: { byRole: 'OWNER', at: observedAt } }
      : {
          measurement: {
            ...measurement,
            scope: { unit: 'host', description: 'Hosts returned by the supplier collector' },
            method: { id: 'collector-attested.edr-coverage.v1', version: 1 },
          },
        }),
    sources: selfAttested ? [{ kind: 'PERSON', ref: 'self-attestation' }] : sources,
    observedAt,
    issuedAt,
    freshUntil: '2026-10-15T11:30:00.000Z',
    evidence: { algo: 'sha256-salted', commitment: hex(sha256(utf8(`commitment ${receiptId}`))) },
  };
  const payloadBytes = utf8(canon(payload));
  const value = sign(null, Buffer.concat([utf8('cmdash-receipt-v0\n'), payloadBytes]), ISSUER.privateKey);
  return { v: 0, payload: b64u(payloadBytes), sig: { alg: 'Ed25519', kid: ISSUER.kid, value: b64u(value) } };
}

const RECEIPT_TRUST = { now: NOW, publicKeys: [{ deployment: DEPLOYMENT, tenantRef: TENANT_A, publicKey: ISSUER.spki }] };

// ─── attestations ────────────────────────────────────────────────────────────

function statement(over = {}, key = COLLECTOR) {
  return {
    v: 0,
    deployment: DEPLOYMENT,
    tenantRef: TENANT_A,
    collectorKeyId: key.kid,
    metric: 'edr-coverage',
    numerator: 47,
    denominator: 50,
    unknown: 1,
    measuredAt: '2026-10-01T11:30:00.000Z',
    seq: 1790000000000,
    nonce: '00112233445566778899aabbccddeeff',
    ...over,
  };
}

function attestation({ st = statement(), key = COLLECTOR, signer = COLLECTOR, tag = MEASUREMENT_TAG, statementText, extra = {}, kid } = {}) {
  const text = statementText ?? canon(st);
  const bytes = utf8(text);
  const sig = sign(null, Buffer.concat([utf8(tag), bytes]), signer.privateKey);
  return {
    format: 'cmdash-collector-attestation',
    v: 0,
    collectorKey: { kid: kid ?? key.kid, alg: 'Ed25519', publicKey: key.spki },
    statement: b64u(bytes),
    sig: b64u(sig),
    ...extra,
  };
}

const COLLECTOR_SOURCE = [{ kind: 'COLLECTOR', ref: COLLECTOR.kid }];
const BASE_RECEIPT = receipt({ sources: COLLECTOR_SOURCE });
const PIN_A = { deployment: DEPLOYMENT, tenantRef: TENANT_A, publicKey: COLLECTOR.spki };

const ATTESTED_ISSUER_NAMED = {
  status: 'ATTESTED',
  rule: null,
  keySource: 'ISSUER_NAMED',
  revokedAt: null,
  proves: ['collector-signed', 'collector-bound-to-receipt'],
  doesNotProve: ['collector-key-independent', 'collector-source-truth', 'collector-key-not-revoked'],
};
const mismatch = (rule) => ({ status: 'MISMATCH', rule, keySource: null, revokedAt: null, proves: [], doesNotProve: [] });

const vectors = [
  {
    id: 'C01-attested-issuer-named',
    title: 'The collector signed exactly the counts and time the receipt signs; the key is named only by the receipt',
    input: { receipt: BASE_RECEIPT, attestation: attestation() },
    expect: ATTESTED_ISSUER_NAMED,
  },
  {
    id: 'C02-attested-pinned',
    title: 'The same, with the collector key pinned by the relying party (obtained from the supplier)',
    input: { receipt: BASE_RECEIPT, attestation: attestation(), trust: { collectorKeys: [PIN_A] } },
    expect: {
      status: 'ATTESTED',
      rule: null,
      keySource: 'PINNED',
      revokedAt: null,
      proves: ['collector-signed', 'collector-bound-to-receipt', 'collector-key-pinned'],
      doesNotProve: ['collector-source-truth', 'collector-key-not-revoked'],
    },
  },
  {
    id: 'C03-attested-key-revoked-after-issue',
    title: 'The key was revoked after the receipt was issued: still ATTESTED, flagged with the revocation time',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ extra: { revokedAt: '2026-10-05T00:00:00.000Z' } }) },
    expect: {
      status: 'ATTESTED',
      rule: null,
      keySource: 'ISSUER_NAMED',
      revokedAt: '2026-10-05T00:00:00.000Z',
      proves: ['collector-signed', 'collector-bound-to-receipt'],
      doesNotProve: ['collector-key-independent', 'collector-source-truth'],
    },
  },
  {
    id: 'C04-key-revoked-before-issue',
    title: 'The pinned key was revoked before the receipt was issued',
    input: { receipt: BASE_RECEIPT, attestation: attestation(), trust: { collectorKeys: [{ ...PIN_A, revokedAt: '2026-10-01T12:00:00.000Z' }] } },
    expect: { ...mismatch('collector.key-revoked'), revokedAt: '2026-10-01T12:00:00.000Z' },
  },
  {
    id: 'C05-counts-differ',
    title: 'The receipt signs 48 of 50; the collector signed 47 of 50',
    input: { receipt: receipt({ sources: COLLECTOR_SOURCE, measurement: { numerator: 48, denominator: 50, unknown: 1 } }), attestation: attestation() },
    expect: mismatch('collector.counts'),
  },
  {
    id: 'C06-older-measurement-claimed-fresh',
    title: 'The collector measured on 20 September; the receipt says observed on 1 October (a replayed old measurement)',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ st: statement({ measuredAt: '2026-09-20T11:30:00.000Z' }) }) },
    expect: mismatch('collector.measured-at'),
  },
  {
    id: 'C07-measured-for-another-tenant',
    title: "The collector's statement names tenant B; the receipt's issuer is tenant A",
    input: { receipt: BASE_RECEIPT, attestation: attestation({ st: statement({ tenantRef: TENANT_B }) }) },
    expect: mismatch('collector.issuer'),
  },
  {
    id: 'C08-receipt-does-not-name-the-key',
    title: "The receipt's signed sources name another collector key: the issuer did not vouch for this one",
    input: { receipt: receipt({ sources: [{ kind: 'COLLECTOR', ref: OTHER_COLLECTOR.kid }] }), attestation: attestation() },
    expect: mismatch('collector.not-named'),
  },
  {
    id: 'C09-signed-by-another-key',
    title: "The statement and key are collector 1's; the signature is collector 2's",
    input: { receipt: BASE_RECEIPT, attestation: attestation({ signer: OTHER_COLLECTOR }) },
    expect: mismatch('collector.signature'),
  },
  {
    id: 'C10-push-signature-presented-as-measurement',
    title: 'A signature over the same bytes under the push domain tag does not verify as a measurement attestation',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ tag: PUSH_TAG }) },
    expect: mismatch('collector.signature'),
  },
  {
    id: 'C11-key-id-not-derived',
    title: "collectorKey.kid is not the hash of collectorKey.publicKey",
    input: { receipt: BASE_RECEIPT, attestation: attestation({ kid: OTHER_COLLECTOR.kid }) },
    expect: mismatch('collector.key-id'),
  },
  {
    id: 'C12-statement-not-canonical',
    title: 'The signed statement bytes carry a space: signed, but not the one canonical spelling',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ statementText: canon(statement()).replace('{', '{ ') }) },
    expect: mismatch('collector.statement-malformed'),
  },
  {
    id: 'C13-statement-names-another-key',
    title: "The statement names collector 2's key id, signed by collector 1",
    input: { receipt: BASE_RECEIPT, attestation: attestation({ st: statement({ collectorKeyId: OTHER_COLLECTOR.kid }) }) },
    expect: mismatch('collector.statement-key'),
  },
  {
    id: 'C14-self-attested-receipt',
    title: 'A self-attested receipt has no measurement a collector could attest',
    input: { receipt: receipt({ sources: COLLECTOR_SOURCE, selfAttested: true }), attestation: attestation() },
    expect: mismatch('collector.not-measured'),
  },
  {
    id: 'C15-pinned-keys-do-not-include-it',
    title: "The relying party pinned only collector 2's key",
    input: { receipt: BASE_RECEIPT, attestation: attestation(), trust: { collectorKeys: [{ ...PIN_A, publicKey: OTHER_COLLECTOR.spki }] } },
    expect: { status: 'UNVERIFIABLE', rule: 'collector.key-unpinned', keySource: null, revokedAt: null, proves: [], doesNotProve: [] },
  },
  {
    id: 'C16-attestation-unknown-member',
    title: 'The attestation carries a member the format does not define',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ extra: { verdict: 'VALID' } }) },
    expect: mismatch('collector.malformed'),
  },
  {
    id: 'C17-receipt-undecodable',
    title: 'The receipt fails its structural checks',
    input: { receipt: { ...BASE_RECEIPT, v: 0, payload: 'AA' }, attestation: attestation() },
    expect: mismatch('collector.receipt-undecodable'),
  },
  {
    id: 'C18-small-order-collector-key',
    title: 'The collector key is the identity point (order 1): refused by the point checks before any equation',
    input: {
      receipt: receipt({ sources: [{ kind: 'COLLECTOR', ref: SMALL_ORDER.kid }] }),
      attestation: {
        format: 'cmdash-collector-attestation',
        v: 0,
        collectorKey: { kid: SMALL_ORDER.kid, alg: 'Ed25519', publicKey: SMALL_ORDER.spki },
        statement: b64u(utf8(canon(statement({ collectorKeyId: SMALL_ORDER.kid })))),
        // R = identity, S = 0: the universal signature some libraries accept for the identity key.
        sig: b64u(Buffer.concat([Buffer.from('01'.padEnd(64, '0'), 'hex'), Buffer.alloc(32)])),
      },
    },
    expect: mismatch('collector.signature'),
  },
  {
    id: 'C19-metric-differs',
    title: 'The collector signed mfa-enrolled with the same counts and instant; the receipt signs the edr-coverage method',
    input: { receipt: BASE_RECEIPT, attestation: attestation({ st: statement({ metric: 'mfa-enrolled' }) }), trust: { collectorKeys: [PIN_A] } },
    expect: mismatch('collector.metric'),
  },
];

// The receipt of every vector but C17 is an ordinary v0 receipt that verifies VALID under
// the issuer's supplied key: the receipt format is unchanged by K1.
for (const v of vectors) {
  v.input.receiptTrust = RECEIPT_TRUST;
  v.receiptExpect = { verdict: v.id === 'C17-receipt-undecodable' ? 'INVALID' : 'VALID' };
}

mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) if (f.endsWith('.json')) unlinkSync(join(OUT, f));
for (const v of vectors) writeFileSync(join(OUT, `${v.id}.json`), `${JSON.stringify(v, null, 2)}\n`);
console.log(`wrote ${vectors.length} collector-attestation vectors to ${OUT}`);
