// SPDX-License-Identifier: Apache-2.0
/**
 * Collector attestation (docs/specs/collector-attestation-v0.md, plan K1):
 * every conformance vector in Node and through the browser build, the receipt
 * of each still an ordinary v0 receipt, the trust input, the degraded
 * runtimes, and the CLI's --collector-attestation, --collector-key and
 * --require-collector-attestation.
 */
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';
import { EXIT_CODES, main, parseArgs, readFileCapped } from '../lib/cli.mjs';
import {
  COLLECTOR_DOES_NOT_PROVE_IDS,
  COLLECTOR_PROVES_IDS,
  COLLECTOR_RULES,
  nodeBackend,
  verifyCollectorAttestation,
  verifyReceipt,
  webCryptoBackend,
} from '../lib/verify.mjs';
import * as browser from '../browser/verify.js';
import { REPO } from './helpers.js';

const SPEC = readFileSync(join(REPO, 'docs', 'specs', 'collector-attestation-v0.md'), 'utf8');
const VECTOR_DIR = join(REPO, 'docs', 'specs', 'collector-attestation-v0', 'vectors');
const vectors = readdirSync(VECTOR_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(VECTOR_DIR, f), 'utf8')));
const byId = (id) => vectors.find((v) => v.id === id);
const dir = mkdtempSync(join(tmpdir(), 'k1-proof-verify-'));
after(() => rmSync(dir, { recursive: true, force: true }));

function assertMatches(r, v, label) {
  const e = v.expect;
  const at = (w) => `${v.id}${label}: ${w} (${r.detail})`;
  assert.equal(r.status, e.status, at('status'));
  assert.equal(r.rule, e.rule, at('rule'));
  assert.equal(r.keySource, e.keySource, at('keySource'));
  assert.equal(r.revokedAt, e.revokedAt, at('revokedAt'));
  assert.deepEqual(r.proves, e.proves, at('proves'));
  assert.deepEqual(r.doesNotProve, e.doesNotProve, at('doesNotProve'));
  assert.match(r.detail, /^[\x20-\x7e]*$/, at('printable'));
}

describe('the spec and the library agree on every name', () => {
  const block = (name) => {
    const m = new RegExp(`<!-- ${name}:begin -->([\\s\\S]*?)<!-- ${name}:end -->`).exec(SPEC);
    assert.ok(m, `no ${name} block in the spec`);
    return [...m[1].matchAll(/^\| `([^`]+)` \|/gm)].map((x) => x[1]);
  };
  test('rules, proves, does-not-prove and the vector index', () => {
    assert.deepEqual(block('collector-rules'), COLLECTOR_RULES);
    assert.deepEqual(block('collector-proves'), COLLECTOR_PROVES_IDS);
    assert.deepEqual(block('collector-does-not-prove'), COLLECTOR_DOES_NOT_PROVE_IDS);
    assert.deepEqual(block('collector-vectors'), vectors.map((v) => v.id));
  });
  test('every rule but receipt-undecodable-by-runtime is pinned by a vector', () => {
    const pinned = new Set(vectors.map((v) => v.expect.rule).filter(Boolean));
    for (const rule of COLLECTOR_RULES) assert.ok(pinned.has(rule), `no vector pins ${rule}`);
  });
});

describe('every vector, in Node and under WebCrypto, and through the browser build', () => {
  for (const v of vectors) {
    test(v.id, async () => {
      // The receipt format is unchanged: each receipt is an ordinary v0 receipt.
      const receipt = await verifyReceipt(v.input.receipt, v.input.receiptTrust);
      assert.equal(receipt.verdict, v.receiptExpect.verdict, `${v.id}: receipt ${receipt.summary}`);
      assertMatches(await verifyCollectorAttestation(v.input.receipt, v.input.attestation, v.input.trust), v, ' [node]');
      assertMatches(
        await verifyCollectorAttestation(v.input.receipt, JSON.stringify(v.input.attestation), v.input.trust, {
          backend: webCryptoBackend(globalThis.crypto),
        }),
        v,
        ' [webcrypto]',
      );
      assertMatches(await browser.verifyCollectorAttestation(v.input.receipt, v.input.attestation, v.input.trust), v, ' [browser]');
    });
  }
});

describe('inputs and degraded runtimes', () => {
  const v = byId('C01-attested-issuer-named');
  const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

  test('bytes, text and objects read alike; bad JSON and duplicates are malformed', async () => {
    const r = await verifyCollectorAttestation(v.input.receipt, enc(v.input.attestation));
    assert.equal(r.status, 'ATTESTED');
    const dup = `{"format":"x",${JSON.stringify(v.input.attestation).slice(1)}`;
    for (const bad of ['{', dup, undefined, 7, '[]', { ...v.input.attestation, collectorKey: 'x' }]) {
      const b = await verifyCollectorAttestation(v.input.receipt, bad);
      assert.equal(b.rule, 'collector.malformed', String(bad));
    }
  });

  test('each member of the attestation is typed', async () => {
    const a = v.input.attestation;
    const variants = [
      { ...a, format: 'other' },
      { ...a, v: 1 },
      { ...a, collectorKey: { ...a.collectorKey, extra: 1 } },
      { ...a, collectorKey: { ...a.collectorKey, kid: 'cmdash-proof-0000000000000000' } },
      { ...a, collectorKey: { ...a.collectorKey, alg: 'EdDSA' } },
      { ...a, collectorKey: { ...a.collectorKey, publicKey: 'AA' } },
      { ...a, statement: '' },
      { ...a, sig: 'AA' },
      { ...a, revokedAt: '2026-02-30T00:00:00.000Z' },
    ];
    const { sig: _s, ...noSig } = a;
    variants.push(noSig);
    for (const bad of variants) {
      const r = await verifyCollectorAttestation(v.input.receipt, bad);
      assert.equal(r.rule, 'collector.malformed', JSON.stringify(bad).slice(0, 120));
    }
  });

  test('a statement that is not UTF-8 JSON, has no canonical form, or breaks its schema is malformed', async () => {
    const a = v.input.attestation;
    const b64 = (s) => Buffer.from(s).toString('base64url');
    const base = JSON.parse(Buffer.from(a.statement, 'base64url').toString('utf8'));
    for (const text of [
      'ÿ',
      '{"a":',
      '{"a":1.5}',
      JSON.stringify({ ...base, extra: 1 }),
    ]) {
      const r = await verifyCollectorAttestation(v.input.receipt, { ...a, statement: b64(text) });
      assert.equal(r.rule, 'collector.statement-malformed', text);
    }
    const bytes = Buffer.from([0xff, 0xfe]);
    const r = await verifyCollectorAttestation(v.input.receipt, { ...a, statement: bytes.toString('base64url') });
    assert.equal(r.rule, 'collector.statement-malformed');
    const canon = (o) => `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${JSON.stringify(o[k])}`).join(',')}}`;
    for (const over of [
      { v: 1 },
      { deployment: 'https://CMDASH.example' },
      { tenantRef: 'tenant' },
      { collectorKeyId: 'x' },
      { metric: 'Bad Metric' },
      { numerator: -1 },
      { numerator: 50, unknown: 1 },
      { measuredAt: '2026-10-01' },
      { seq: 0 },
      { nonce: 'x' },
    ]) {
      const bad = await verifyCollectorAttestation(v.input.receipt, { ...a, statement: b64(canon({ ...base, ...over })) });
      assert.equal(bad.rule, 'collector.statement-malformed', JSON.stringify(over));
    }
  });

  test('the trust input is checked: unknown members and non-arrays are programming errors, malformed keys are not keys', async () => {
    await assert.rejects(verifyCollectorAttestation(v.input.receipt, v.input.attestation, 'x'), TypeError);
    await assert.rejects(verifyCollectorAttestation(v.input.receipt, v.input.attestation, { keys: [] }), TypeError);
    await assert.rejects(verifyCollectorAttestation(v.input.receipt, v.input.attestation, { collectorKeys: {} }), TypeError);
    await assert.rejects(verifyCollectorAttestation(v.input.receipt, v.input.attestation, undefined, { backend: {} }), TypeError);
    const junk = await verifyCollectorAttestation(v.input.receipt, v.input.attestation, { collectorKeys: [{ publicKey: 'x' }, null] });
    assert.equal(junk.rule, 'collector.key-unpinned');
    const empty = await verifyCollectorAttestation(v.input.receipt, v.input.attestation, { collectorKeys: null });
    assert.equal(empty.keySource, 'ISSUER_NAMED');
  });

  test('no WebCrypto: UNVERIFIABLE, "use the CLI"; no Ed25519: UNVERIFIABLE, never ATTESTED', async () => {
    const none = await verifyCollectorAttestation(v.input.receipt, v.input.attestation, undefined, { backend: webCryptoBackend(undefined) });
    assert.equal(none.status, 'UNVERIFIABLE');
    assert.match(none.detail, /use the CLI/);
    const noEd = await verifyCollectorAttestation(v.input.receipt, v.input.attestation, undefined, {
      backend: { ...nodeBackend, ed25519Verify: async () => null },
    });
    assert.deepEqual([noEd.status, noEd.rule], ['UNVERIFIABLE', 'collector.signature']);
  });
});

describe('cmdash-verify --collector-attestation', () => {
  const v = byId('C01-attested-issuer-named');
  const write = (name, content) => {
    const p = join(dir, name);
    writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content));
    return p;
  };
  const pem = (spkiB64u) =>
    createPublicKey({ key: Buffer.from(spkiB64u, 'base64url'), format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' });
  const trust = v.input.receiptTrust;
  const issuerKey = write('issuer.pem', pem(trust.publicKeys[0].publicKey));
  const keyArg = `${trust.publicKeys[0].deployment}#${trust.publicKeys[0].tenantRef}=${issuerKey}`;
  async function cli(args) {
    const out = [];
    const err = [];
    const code = await main(args, {
      out: (l) => out.push(l),
      err: (l) => err.push(l),
      readFile: readFileCapped,
      fetch: () => {
        throw new Error('no network in this test');
      },
      now: () => trust.now,
    });
    return { code, out: out.join('\n'), err: err.join('\n') };
  }
  const receiptFor = (id) => write(`${id}.receipt.json`, byId(id).input.receipt);
  const attestationFor = (id) => write(`${id}.attestation.json`, byId(id).input.attestation);

  test('prints ATTESTED next to a VALID receipt, with what it proves; exit 0', async () => {
    const r = await cli([receiptFor(v.id), '--key', keyArg, '--collector-attestation', attestationFor(v.id)]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /collector attestation .*: ATTESTED - ATTESTED by collector key cmdash-collector-[0-9a-f]{16}, named by the issuer/);
    assert.match(r.out, /does not prove {2}collector-key-independent/);
  });

  test('a receipt naming a collector key, verified WITHOUT its attestation, says so (VALID is not ATTESTED)', async () => {
    const r = await cli([receiptFor(v.id), '--key', keyArg]);
    assert.equal(r.code, 0);
    assert.match(r.out, /note: the receipt names collector key cmdash-collector-[0-9a-f]{16} as its source, but no collector attestation was checked/);
    assert.doesNotMatch(r.out, /ATTESTED/);
    const j = JSON.parse((await cli([receiptFor(v.id), '--key', keyArg, '--json'])).out);
    assert.ok(j.notes.some((n) => /no collector attestation was checked/.test(n)));
    assert.equal(j.collectorAttestation, undefined);
    // A metric-swapped statement (same counts, same instant) is MISMATCH, and fails --require.
    const id = 'C19-metric-differs';
    const swapped = await cli([receiptFor(id), '--key', keyArg, '--collector-attestation', attestationFor(id), '--require-collector-attestation']);
    assert.equal(swapped.code, EXIT_CODES.INVALID);
    assert.match(swapped.out, /MISMATCH \(collector\.metric\)/);
  });

  test('--collector-key pins the key; --json carries the result', async () => {
    const pin = write('collector.pem', pem(v.input.attestation.collectorKey.publicKey));
    const r = await cli([
      receiptFor(v.id),
      '--key',
      keyArg,
      '--collector-attestation',
      attestationFor(v.id),
      '--collector-key',
      `${trust.publicKeys[0].deployment}#${trust.publicKeys[0].tenantRef}=${pin}`,
      '--json',
    ]);
    assert.equal(r.code, 0);
    const doc = JSON.parse(r.out);
    assert.equal(doc.collectorAttestation.keySource, 'PINNED');
    const bad = write('not-a-key.pem', 'nope');
    const r2 = await cli([
      receiptFor(v.id),
      '--collector-attestation',
      attestationFor(v.id),
      '--collector-key',
      `${trust.publicKeys[0].deployment}#${trust.publicKeys[0].tenantRef}=${bad}`,
    ]);
    assert.equal(r2.code, 2);
  });

  test('without --require-collector-attestation a MISMATCH never changes the exit code; with it, exit 1', async () => {
    const id = 'C06-older-measurement-claimed-fresh';
    const base = [receiptFor(id), '--key', keyArg, '--collector-attestation', attestationFor(id)];
    const r = await cli(base);
    assert.equal(r.code, 0);
    assert.match(r.out, /MISMATCH \(collector\.measured-at\)/);
    assert.equal((await cli([...base, '--require-collector-attestation'])).code, EXIT_CODES.INVALID);
  });

  test('--require-collector-attestation: UNVERIFIABLE attestation exits 2; a receipt that is not VALID keeps its own code', async () => {
    const id = 'C15-pinned-keys-do-not-include-it';
    const other = write('other.pem', pem(byId(id).input.trust.collectorKeys[0].publicKey));
    const r = await cli([
      receiptFor(id),
      '--key',
      keyArg,
      '--collector-attestation',
      attestationFor(id),
      '--collector-key',
      `${trust.publicKeys[0].deployment}#${trust.publicKeys[0].tenantRef}=${other}`,
      '--require-collector-attestation',
    ]);
    assert.equal(r.code, EXIT_CODES.UNVERIFIABLE);
    const unkeyed = await cli([receiptFor(v.id), '--collector-attestation', attestationFor(v.id), '--require-collector-attestation']);
    assert.equal(unkeyed.code, EXIT_CODES.UNVERIFIABLE);
    assert.match(unkeyed.out, /the receipt itself is not VALID/);
  });

  test('usage: --require-collector-attestation and --collector-key need --collector-attestation', () => {
    assert.throws(() => parseArgs(['r.json', '--require-collector-attestation']), /needs --collector-attestation/);
    assert.throws(() => parseArgs(['r.json', '--collector-key', 'https://a.example#tr_00000000000000000000000000000000=k.pem']), /needs --collector-attestation/);
    assert.throws(() => parseArgs(['r.json', '--collector-attestation', 'a', '--collector-key', 'nonsense']), /--collector-key/);
    assert.equal(parseArgs(['r.json', '--collector-attestation=a.json']).collectorAttestation, 'a.json');
  });
});
