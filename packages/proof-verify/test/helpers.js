// SPDX-License-Identifier: Apache-2.0
/**
 * Test helpers: the spec's vectors, the comparison against their `expect`,
 * and a small test-only issuer (keys derived from public seed strings, like
 * the vectors' own) for the cases the vectors do not cover (the CLI's
 * --fetch against a local server, a forged log tree, the degraded runtimes).
 * No private key material is stored in any file.
 */
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonical.mjs';

export const PKG = join(dirname(fileURLToPath(import.meta.url)), '..');
export const REPO = join(PKG, '..', '..');
export const SPEC_DIR = join(REPO, 'docs', 'specs', 'proof-receipt-v0');
export const VECTOR_DIR = join(SPEC_DIR, 'vectors');
export const NOW = '2026-10-12T00:00:00.000Z';
export const PRINTABLE = /^[\x20-\x7e]*$/;

export function loadVectors() {
  return readdirSync(VECTOR_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(VECTOR_DIR, f), 'utf8')));
}

export const byId = (vectors, id) => {
  const v = vectors.find((x) => x.id === id);
  assert.ok(v, `no vector ${id}`);
  return v;
};

/** The payload of a vector's receipt, as JSON.parse reads it (what the result's `payload` must equal). */
export function payloadOf(v) {
  const env = typeof v.input.receipt === 'string' ? JSON.parse(v.input.receipt) : v.input.receipt;
  return JSON.parse(Buffer.from(env.payload, 'base64url').toString('utf8'));
}

/**
 * Asserts a verifier result reproduces every field of the vector's `expect`
 * (spec section 11: "P4 MUST reproduce every field of expect"). `rule` is
 * pinned whenever the vector pins it; where the vector leaves it null, only
 * the informative canonical.* reason of a payload.canonical failure is allowed.
 */
export function assertMatchesVector(r, v, label = '') {
  const e = v.expect;
  const at = (what) => `${v.id}${label}: ${what}`;
  assert.equal(r.verdict, e.verdict, at('verdict'));
  assert.equal(r.failedCheck, e.failedCheck, at('failedCheck'));
  if (e.rule !== null) assert.equal(r.rule, e.rule, at('rule'));
  else
    assert.ok(
      r.rule === null || (r.failedCheck === 'payload.canonical' && r.rule.startsWith('canonical.')),
      at(`rule ${r.rule}`),
    );
  assert.equal(r.keySource, e.keySource, at('keySource'));
  assert.equal(r.keyStatusAsOf, e.keyStatusAsOf, at('keyStatusAsOf'));
  assert.equal(r.keyDocumentUrl, e.keyDocumentUrl, at('keyDocumentUrl'));
  assert.equal(r.plainHttp, e.plainHttp, at('plainHttp'));
  assert.deepEqual(
    r.checks.map((c) => ({
      name: c.name,
      outcome: c.outcome,
      ...(c.effect ? { effect: c.effect } : {}),
    })),
    e.checks,
    at('checks'),
  );
  for (const c of r.checks) {
    if (c.outcome === 'FAIL') assert.ok(c.effect, at(`${c.name} FAIL has an effect`));
    else assert.equal(c.effect, undefined, at(`${c.name} ${c.outcome} has no effect`));
    assert.match(c.detail, PRINTABLE, at(`${c.name} detail is printable ASCII`));
  }
  assert.deepEqual(r.proves, e.proves, at('proves'));
  assert.deepEqual(r.doesNotProve, e.doesNotProve, at('doesNotProve'));
  assert.deepEqual(r.reading, e.reading, at('reading'));
  assert.equal(r.digest, e.digest, at('digest'));
  assert.ok(
    r.summary.startsWith(`${e.summaryPrefix} `),
    at(`summary starts with ${e.summaryPrefix}: ${r.summary}`),
  );
  assert.match(r.summary, PRINTABLE, at('summary is printable ASCII'));
  const valid = e.verdict === 'VALID' || e.verdict === 'STALE_VALID';
  assert.deepEqual(r.payload, valid ? payloadOf(v) : null, at('payload'));
}

// --- a test-only issuer ------------------------------------------------------

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
export const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

/** An Ed25519 key derived from a public label (test keys only: their private halves are public by design). */
export function testKey(label) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, sha256(`p4 test key ${label}`)]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    spki: der.toString('base64url'),
    raw: der.subarray(12),
    pem: publicKey.export({ type: 'spki', format: 'pem' }),
    kid: `cmdash-proof-${sha256(der).toString('hex').slice(0, 16)}`,
    logKid: `cmdash-proof-log-${sha256(der).toString('hex').slice(0, 16)}`,
  };
}

export const TENANT = 'tr_0123456789abcdef0123456789abcdef';
export const OTHER_TENANT = 'tr_fedcba9876543210fedcba9876543210';

/** A signed receipt over a canonical payload (overrides merge into the payload). */
export function issue(
  key,
  {
    deployment = 'https://cmdash.example',
    tenantRef = TENANT,
    receiptId = '01M3VNBWG0WWTF65KKAVPE61Y8',
    ...overrides
  } = {},
) {
  const payload = {
    receiptId,
    issuer: { deployment, tenantRef, keyId: key.kid },
    claim: {
      claimId: 'cmmc-l2.ia.mfa-enrolled',
      statement: 'Every active user account is enrolled in multi-factor authentication.',
      controls: [{ framework: 'cmmc-l2', controlId: 'IA.L2-3.5.3' }],
      assertion: { kind: 'ALL' },
    },
    measurement: {
      numerator: 10,
      denominator: 10,
      unknown: 0,
      scope: { unit: 'user', description: 'Active user accounts' },
      method: { id: 'identity-coverage.mfa-enrolled', version: 1 },
    },
    sources: [{ kind: 'INTEGRATION', ref: 'okta' }],
    observedAt: '2026-10-01T11:30:00.000Z',
    issuedAt: '2026-10-01T12:00:00.000Z',
    freshUntil: '2026-10-31T11:30:00.000Z',
    evidence: {
      algo: 'sha256-salted',
      commitment: sha256(`commitment ${receiptId}`).toString('hex'),
    },
    ...overrides,
  };
  // An override of undefined removes the member (e.g. measurement, for a self-attested receipt).
  for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
  const bytes = Buffer.from(canonicalize(payload), 'utf8');
  const signature = sign(
    null,
    Buffer.concat([Buffer.from('cmdash-receipt-v0\n'), bytes]),
    key.privateKey,
  );
  return {
    payload,
    envelope: {
      v: 0,
      payload: bytes.toString('base64url'),
      sig: { alg: 'Ed25519', kid: key.kid, value: signature.toString('base64url') },
    },
    digest: sha256(Buffer.from('cmdash-receipt-digest-v0\n'), bytes),
  };
}

export const keyEntry = (key, status = 'ACTIVE', more = {}) => ({
  kid: key.kid,
  alg: 'Ed25519',
  publicKey: key.spki,
  status,
  validFrom: '2026-09-01T00:00:00.000Z',
  ...more,
});
export const logKeyEntry = (key, status = 'ACTIVE', more = {}) => ({
  kid: key.logKid,
  alg: 'Ed25519',
  publicKey: key.spki,
  status,
  validFrom: '2026-09-01T00:00:00.000Z',
  ...more,
});

export function logKeyDocument(origin, entries) {
  return { format: 'cmdash-proof-log-keys', v: 0, generatedAt: NOW, origin, keys: entries };
}

export function keyDocument({
  deployment = 'https://cmdash.example',
  tenantRef = TENANT,
  keys,
  log,
  generatedAt = NOW,
}) {
  const doc = { format: 'cmdash-proof-keys', v: 0, deployment, tenantRef, generatedAt, keys };
  if (log) doc.log = log;
  return doc;
}

export const keyDocumentUrl = (deployment = 'https://cmdash.example', tenantRef = TENANT) =>
  `${deployment}/api/.well-known/cmdash-proof-keys/${tenantRef}.json`;

// RFC 9162 tree hash and audit paths (an independent, recursive formulation).
const leafHashOf = (entry) => sha256(Buffer.from([0]), entry);
const nodeHashOf = (l, r) => sha256(Buffer.from([1]), l, r);
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
export function treeHash(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHashOf(treeHash(leaves.slice(0, k)), treeHash(leaves.slice(k)));
}
export function auditPath(m, leaves) {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...auditPath(m, leaves.slice(0, k)), treeHash(leaves.slice(k))]
    : [...auditPath(m - k, leaves.slice(k)), treeHash(leaves.slice(0, k))];
}
export { leafHashOf, nodeHashOf };

/** A C2SP signed-note checkpoint for `root`, signed by each of `signers` (test keys) under `origin`. */
export function checkpointNote(origin, size, root, signers) {
  const text = `${origin}\n${size}\n${root.toString('base64')}\n`;
  const lines = signers.map((k) => {
    const keyHash = sha256(Buffer.from(`${origin}\n`), Buffer.from([1]), k.raw).subarray(0, 4);
    return `\u{2014} ${origin} ${Buffer.concat([keyHash, sign(null, Buffer.from(text), k.privateKey)]).toString('base64')}\n`;
  });
  return `${text}\n${lines.join('')}`;
}

/** A log of `size` entries with `digest` at `index` (the others filler), and its log section signed by `logKey`. */
export function logSectionFor(
  digest,
  { index, size, origin = 'cmdash.example/cmdash-proof-log', logKeys },
) {
  const entries = Array.from({ length: size }, (_, i) =>
    i === index ? digest : sha256(`filler ${i}`),
  );
  const leaves = entries.map(leafHashOf);
  const root = treeHash(leaves);
  return {
    index,
    treeSize: size,
    rootHash: root.toString('hex'),
    proof: auditPath(index, leaves).map((h) => h.toString('hex')),
    checkpoint: checkpointNote(origin, size, root, logKeys),
  };
}
