// SPDX-License-Identifier: Apache-2.0
/**
 * cmdash-verify (spec section 9.4): exit codes per verdict, bad usage and
 * unreadable input, the file-size limits, --key with a PEM, evidence
 * openings, escaping of a hostile member name, and --fetch against a local
 * fixture server: a redirect refused, plain http refused unless allowed, the
 * 404 rule for the checkpoint of the receipt's own size, the inclusion route,
 * a failed fetch never replaced by offline verification.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  EXIT_CODES,
  USAGE,
  asciiJson,
  main,
  parseArgs,
  pemToSpkiBase64Url,
  readFileCapped,
} from '../lib/cli.mjs';
import {
  NOW,
  PKG,
  TENANT,
  byId,
  checkpointNote,
  issue,
  keyDocument,
  keyEntry,
  loadVectors,
  logKeyDocument,
  logKeyEntry,
  logSectionFor,
  sha256,
  testKey,
} from './helpers.js';

const BIN = join(PKG, 'bin', 'cmdash-verify.mjs');
const vectors = loadVectors();
const dir = mkdtempSync(join(tmpdir(), 'p4-proof-verify-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const file = (name, content) => {
  const p = join(dir, name);
  writeFileSync(
    p,
    typeof content === 'string' || content instanceof Uint8Array
      ? content
      : JSON.stringify(content),
  );
  return p;
};
/** A vector's receipt and key document as files, with the CLI arguments that pass them. */
function vectorFiles(id) {
  const v = byId(vectors, id);
  const receipt = file(
    `${id}.json`,
    typeof v.input.receipt === 'string' ? v.input.receipt : JSON.stringify(v.input.receipt),
  );
  const args = [receipt, '--now', v.input.trust.now];
  if (v.input.trust.keyDocument) {
    const kd = file(
      `${id}.keys.json`,
      typeof v.input.trust.keyDocument === 'string'
        ? v.input.trust.keyDocument
        : JSON.stringify(v.input.trust.keyDocument),
    );
    args.push('--key-document', kd, '--key-document-url', v.input.trust.keyDocumentUrl);
    for (const d of v.input.trust.deployments ?? []) args.push('--deployment', d);
  }
  return { v, receipt, args };
}

async function cli(args, overrides = {}) {
  const out = [];
  const err = [];
  const io = {
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    readFile: readFileCapped,
    fetch: (u, i) => globalThis.fetch(u, i),
    now: () => NOW,
    ...overrides,
  };
  const code = await main(args, io);
  return { code, out: out.join('\n'), err: err.join('\n') };
}
const printable = (s) => /^[\x20-\x7e\n]*$/.test(s);

describe('exit codes: 0 VALID, 1 INVALID, 2 UNVERIFIABLE, 3 STALE_VALID', () => {
  for (const [id, verdict] of [
    ['01-valid-measured-all', 'VALID'],
    ['15-tampered-payload', 'INVALID'],
    ['12-embedded-key-only', 'UNVERIFIABLE'],
    ['14-stale', 'STALE_VALID'],
  ]) {
    test(`${id} -> exit ${EXIT_CODES[verdict]} (${verdict}), in process and as the real binary`, async () => {
      const { args } = vectorFiles(id);
      const r = await cli(args);
      assert.equal(r.code, EXIT_CODES[verdict], r.out);
      assert.ok(
        r.out.startsWith(verdict === 'STALE_VALID' ? 'STALE - ' : `${verdict} - `),
        r.out.slice(0, 80),
      );
      assert.ok(printable(r.out));
      const spawned = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
      assert.equal(spawned.status, EXIT_CODES[verdict], spawned.stderr);
      assert.equal(spawned.stdout.trimEnd(), r.out);
    });
  }

  test('the independence caveat is stated, and says when the only key came from inside the receipt', async () => {
    const embedded = await cli(vectorFiles('12-embedded-key-only').args);
    assert.match(embedded.out, /independence: the only key came from INSIDE the receipt/);
    const doc = await cli(vectorFiles('01-valid-measured-all').args);
    assert.match(
      doc.out,
      /independence: the issuer key came from the key document at https:\/\/cmdash\.example\/api\/\.well-known\/cmdash-proof-keys\/tr_[0-9a-f]{32}\.json, which you supplied/,
    );
    assert.match(doc.out, /did not ask CMDash, or anyone, whether the receipt is valid/);
  });

  test('--json prints the result object as printable-ASCII JSON; --help exits 0', async () => {
    const { args, v } = vectorFiles('09-valid-unicode-strings');
    const r = await cli([...args, '--json']);
    assert.equal(r.code, 0);
    assert.ok(printable(r.out), 'every non-ASCII character is a \\u escape');
    const parsed = JSON.parse(r.out);
    assert.equal(parsed.verdict, 'VALID');
    assert.equal(
      parsed.payload.claim.statement,
      JSON.parse(Buffer.from(v.input.receipt.payload, 'base64url').toString('utf8')).claim
        .statement,
    );
    assert.deepEqual(parsed.fetched, []);
    assert.equal(asciiJson({ s: '\u{e9}\u{1b}' }), '{\n  "s": "\\u00e9\\u001b"\n}');
    const help = await cli(['--help']);
    assert.equal(help.code, 0);
    assert.equal(help.out, USAGE);
  });
});

describe('bad usage and unreadable input are exit 2', () => {
  const receipt = () => vectorFiles('01-valid-measured-all').receipt;
  test('each misuse is refused with a reason on stderr', async () => {
    const r = receipt();
    for (const [args, reason] of [
      [[], /no receipt file/],
      [[r, r], /exactly one receipt/],
      [[r, '--frobnicate'], /unknown option/],
      [[r, '--fetch'], /--deployment is required/],
      [[r, '--key-document', r], /come together/],
      [[r, '--key-document-url', 'https://x.example/k.json'], /come together/],
      [[r, '--deployment', 'https://CMDASH.example'], /not a canonical origin/],
      [[r, '--deployment', 'https://cmdash.example:443'], /not a canonical origin/],
      [
        [
          r,
          '--deployment',
          'https://cmdash.example',
          '--fetch',
          '--key-document',
          r,
          '--key-document-url',
          'https://cmdash.example/x',
        ],
        /either --fetch or --key-document/,
      ],
      [
        [r, '--key', 'https://cmdash.example=k.pem'],
        /not <deployment>#<tenantRef>=<public-key.pem>/,
      ],
      [[r, '--key', `https://CMDASH.example#${TENANT}=k.pem`], /canonical deployment/],
      [[r, '--key', 'https://cmdash.example#tr_1=k.pem'], /not a tenantRef/],
      [[r, '--key', `https://cmdash.example#${TENANT}=`], /no public key file/],
      [[r, '--item', r], /--item needs --opening/],
      [[r, '--now', '2026-10-12'], /not a timestamp/],
      [[r, '--now', NOW, '--now', NOW], /given twice/],
      [[r, '--json=yes'], /takes no value/],
      [[r, '--checkpoint'], /needs a value/],
    ]) {
      const out = await cli(args);
      assert.equal(out.code, 2, `${args.join(' ')}: ${out.err}`);
      assert.match(out.err, reason, args.join(' '));
      assert.equal(out.out, '');
    }
  });

  test('a missing file, a directory and a non-Ed25519 PEM are unreadable input', async () => {
    const missing = await cli([join(dir, 'nope.json')]);
    assert.equal(missing.code, 2);
    assert.match(missing.err, /unreadable input: ".*nope\.json": ENOENT/);
    const sub = join(dir, 'a-directory');
    mkdirSync(sub, { recursive: true });
    assert.equal((await cli([sub])).code, 2);
    const rsa = file(
      'rsa.pem',
      generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({
        type: 'spki',
        format: 'pem',
      }),
    );
    const r = await cli([receipt(), '--key', `https://cmdash.example#${TENANT}=${rsa}`]);
    assert.equal(r.code, 2);
    assert.match(r.err, /not an Ed25519 public key in PEM/);
    assert.equal(pemToSpkiBase64Url(new TextEncoder().encode('garbage')), null);
  });

  test('parseArgs accepts --flag=value and collects repeatable options', () => {
    const o = parseArgs([
      'r.json',
      '--deployment=https://a.example',
      '--deployment',
      'http://localhost:3001',
      '--item=a',
      '--opening',
      'o',
      '--item',
      'b',
    ]);
    assert.deepEqual(o.deployments, ['https://a.example', 'http://localhost:3001']);
    assert.deepEqual(o.items, ['a', 'b']);
  });
});

describe('the file limits and the hostile member name', () => {
  test('a receipt over 65536 bytes is INVALID (json.too-large), read no further than the limit', async () => {
    const { args } = vectorFiles('C0-envelope-too-large');
    const r = await cli(args);
    assert.equal(r.code, 1);
    assert.match(r.out, /json\.too-large/);
    const huge = file('huge.json', Buffer.alloc(8 * 1024 * 1024, 0x20));
    assert.equal((await readFileCapped(huge, 65536)).length, 65537);
    assert.equal((await cli([huge, '--now', NOW])).code, 1);
  });

  test('vector 58 through the CLI: no ESC, carriage return or bidi override reaches the terminal', async () => {
    const r = await cli(vectorFiles('58-output-injection-envelope-member').args);
    assert.equal(r.code, 1);
    assert.ok(!r.out.includes('\u001b') && !r.out.includes('\r') && !r.out.includes('\u{202e}'));
    assert.match(r.out, /\\u\{1b\}/);
    assert.ok(printable(r.out));
  });

  test('a verified statement with non-ASCII text is printed escaped and quoted, never raw', async () => {
    const r = await cli(vectorFiles('09-valid-unicode-strings').args);
    assert.equal(r.code, 0);
    assert.ok(printable(r.out));
    assert.match(r.out, /statement "[^\n]*\\u\{[0-9a-f]+\}[^\n]*" +\(the issuer's wording/);
  });
});

describe('--key, --log-section, --checkpoint, --opening and --item', () => {
  test('--key <deployment>#<tenantRef>=<pem> verifies with a supplied key; the binding is enforced', async () => {
    const v = byId(vectors, '13-valid-supplied-key-log-unverified');
    const k = v.input.trust.publicKeys[0];
    const der = Buffer.from(k.publicKey, 'base64url');
    const pem = file(
      '13.pem',
      `-----BEGIN PUBLIC KEY-----\n${der.toString('base64')}\n-----END PUBLIC KEY-----\n`,
    );
    assert.equal(
      pemToSpkiBase64Url(
        new TextEncoder().encode(
          `-----BEGIN PUBLIC KEY-----\r\n${der.toString('base64')}\r\n-----END PUBLIC KEY-----\r\n`,
        ),
      ),
      k.publicKey,
    );
    const receipt = file('13.json', v.input.receipt);
    const ok = await cli([receipt, '--now', NOW, '--key', `${k.deployment}#${k.tenantRef}=${pem}`]);
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, /independence: the issuer key is one you supplied/);
    const wrong = await cli([
      receipt,
      '--now',
      NOW,
      '--key',
      `https://other.example#${k.tenantRef}=${pem}`,
    ]);
    assert.equal(wrong.code, 2);
    assert.match(wrong.out, /key\.supplied-deployment/);
  });

  test('--log-section dates a retired key (vector E0), and --checkpoint is the external checkpoint (vector 20)', async () => {
    const e0 = byId(vectors, 'E0-supplied-log-section');
    const { args } = vectorFiles('E0-supplied-log-section');
    assert.equal((await cli(args)).code, 2, 'without the section: key.retired-unproven');
    const withSection = await cli([
      ...args,
      '--log-section',
      file('E0.log.json', e0.input.trust.logSection),
    ]);
    assert.equal(withSection.code, 0, withSection.out);
    const v20 = byId(vectors, '20-equivocating-checkpoint');
    const eq = await cli([
      ...vectorFiles('20-equivocating-checkpoint').args,
      '--checkpoint',
      file('20.note', v20.input.trust.checkpoint),
    ]);
    assert.equal(eq.code, 1);
    assert.match(eq.out, /external\.equivocation/);
  });

  test('--require-logged turns an unlogged receipt UNVERIFIABLE; --log-keys supplies the log key set', async () => {
    assert.equal(
      (await cli([...vectorFiles('01-valid-measured-all').args, '--require-logged'])).code,
      2,
    );
    const b6 = byId(vectors, 'B6-log-keys-malformed');
    const r = await cli([
      ...vectorFiles('B6-log-keys-malformed').args,
      '--log-keys',
      file('B6.logkeys.json', b6.input.trust.logKeys),
    ]);
    assert.equal(r.code, 2);
    assert.match(r.out, /log-keys\.malformed/);
  });

  test('openings and items are reported separately and never change the exit code', async () => {
    const v = byId(vectors, '01-valid-measured-all');
    const { args } = vectorFiles(v.id);
    const opening = file('01.opening.json', v.input.evidenceOpening);
    const good = file('01.item.json', v.input.evidenceItems[0]);
    const bad = file('01.item-bad.json', { ...v.input.evidenceItems[0], index: 40 });
    const r = await cli([...args, '--opening', opening, '--item', good, '--item', bad]);
    assert.equal(r.code, 0);
    assert.match(r.out, /evidence opening ".*01\.opening\.json": MATCH/);
    assert.match(r.out, /evidence item ".*01\.item\.json": MATCH/);
    assert.match(r.out, /evidence item ".*01\.item-bad\.json": MISMATCH \(item\.inclusion\)/);
    const json = JSON.parse(
      (await cli([...args, '--opening', opening, '--item', bad, '--json'])).out,
    );
    assert.equal(json.evidenceOpening.match, true);
    assert.equal(json.evidenceItems[0].rule, 'item.inclusion');
  });
});

// --- --fetch against local fixture servers ---------------------------------

function serve(host, route) {
  return new Promise((resolve) => {
    const requests = [];
    const server = createServer((req, res) => {
      requests.push(req.url);
      const answer = route(req.url);
      if (!answer) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      res.writeHead(answer.status ?? 200, {
        'content-type': answer.type ?? 'application/json',
        ...(answer.headers ?? {}),
      });
      res.end(answer.body ?? '');
    });
    server.listen(0, host, () =>
      resolve({
        origin: `http://${host}:${server.address().port}`,
        requests,
        close: () => new Promise((r) => server.close(r)),
      }),
    );
  });
}

describe('--fetch against a local fixture server', () => {
  const issuerKey = testKey('fetch issuer');
  const logKey = testKey('fetch log');
  const origin = 'fixture.test/cmdash-proof-log';
  const servers = [];
  const routes = new Map(); // origin -> Map(path -> answer)
  const start = async (host) => {
    let table;
    const s = await serve(host, (url) => table.get(url));
    table = new Map();
    routes.set(s.origin, table);
    servers.push(s);
    return s;
  };
  after(async () => {
    for (const s of servers) await s.close();
  });

  /** Publishes, at `deployment`, a key document for `keys` and the log keys; returns the paths. */
  function publish(deployment, keys, extra = {}) {
    const table = routes.get(deployment);
    const doc = keyDocument({
      deployment,
      keys,
      log: logKeyDocument(origin, [logKeyEntry(logKey)]),
    });
    const keyPath = `/api/.well-known/cmdash-proof-keys/${TENANT}.json`;
    table.set(keyPath, extra.keyDocument ?? { body: JSON.stringify(doc) });
    return { keyPath, doc };
  }

  let loop;
  let plain;
  before(async () => {
    loop = await start('127.0.0.1');
    plain = await start('127.0.0.2');
  });

  test('a logged receipt: the key document and the checkpoint of its own size are fetched, marked plain HTTP, and agree', async () => {
    const d = loop.origin;
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z0' });
    const section = logSectionFor(r.digest, { index: 3, size: 6, origin, logKeys: [logKey] });
    publish(d, [keyEntry(issuerKey)]);
    routes.get(d).set('/api/.well-known/cmdash-proof-log/checkpoint/6', {
      type: 'text/plain; charset=utf-8',
      body: section.checkpoint,
    });
    const receipt = file('fetch-logged.json', { ...r.envelope, log: section });
    loop.requests.length = 0;
    const out = await cli([receipt, '--deployment', d, '--fetch', '--json']);
    const result = JSON.parse(out.out);
    assert.equal(out.code, 0, out.out);
    assert.equal(result.verdict, 'VALID');
    assert.ok(result.proves.includes('log-consistent-with-external'));
    assert.deepEqual(loop.requests, [
      `/api/.well-known/cmdash-proof-keys/${TENANT}.json`,
      '/api/.well-known/cmdash-proof-log/checkpoint/6',
    ]);
    assert.deepEqual(
      result.fetched.map((f) => [f.status, f.plainHttp]),
      [
        [200, true],
        [200, true],
      ],
    );
    const human = await cli([receipt, '--deployment', d, '--fetch']);
    assert.match(
      human.out,
      new RegExp(
        `GET ${d}/api/\\.well-known/cmdash-proof-keys/${TENANT}\\.json -> 200  \\(over PLAIN HTTP: in clear\\)`,
      ),
    );
    assert.match(human.out, /fetched just now from a deployment you named/);
  });

  test('an unlogged receipt: the inclusion route gives its log section', async () => {
    const d = loop.origin;
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z1' });
    publish(d, [keyEntry(issuerKey)]);
    const section = logSectionFor(r.digest, { index: 0, size: 3, origin, logKeys: [logKey] });
    routes.get(d).set(`/api/.well-known/cmdash-proof-log/inclusion/${r.digest.toString('hex')}`, {
      body: JSON.stringify(section),
    });
    const out = JSON.parse(
      (await cli([file('fetch-unlogged.json', r.envelope), '--deployment', d, '--fetch', '--json']))
        .out,
    );
    assert.equal(out.verdict, 'VALID');
    assert.ok(out.proves.includes('logged'));
    const other = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z2' });
    const notLogged = await cli([
      file('fetch-unlogged-404.json', other.envelope),
      '--deployment',
      d,
      '--fetch',
    ]);
    assert.equal(notLogged.code, 0);
    assert.match(notLogged.out, /does not hold this receipt's digest \(404\): NOT LOGGED/);
  });

  test('a redirect is a failed fetch: exit 2, nothing verified, and the redirect target is never contacted', async () => {
    const d = loop.origin;
    const target = await start('127.0.0.1');
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z3' });
    publish(d, [keyEntry(issuerKey)], {
      keyDocument: { status: 302, headers: { location: `${target.origin}/elsewhere.json` } },
    });
    const out = await cli([file('fetch-redirect.json', r.envelope), '--deployment', d, '--fetch']);
    assert.equal(out.code, 2);
    assert.match(out.out, /^FETCH FAILED .* 302 \(a redirect\)/);
    assert.match(out.out, /never replaced by offline verification/);
    assert.doesNotMatch(out.out, /^(VALID|INVALID|UNVERIFIABLE|STALE)/m);
    assert.deepEqual(target.requests, []);
  });

  test('any other failed fetch is exit 2, never silently offline: a 500, a missing key document', async () => {
    const d = loop.origin;
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z4' });
    publish(d, [keyEntry(issuerKey)], { keyDocument: { status: 500, body: 'oops' } });
    const five = await cli([
      file('fetch-500.json', r.envelope),
      '--deployment',
      d,
      '--fetch',
      '--json',
    ]);
    assert.equal(five.code, 2);
    assert.equal(JSON.parse(five.out).error, 'fetch-failed');
    routes.get(d).delete(`/api/.well-known/cmdash-proof-keys/${TENANT}.json`);
    assert.equal(
      (await cli([file('fetch-404.json', r.envelope), '--deployment', d, '--fetch'])).code,
      2,
    );
  });

  test('a network error, a timeout, a failing log route are failed fetches; an oversized document is read no further than its limit', async () => {
    const d = loop.origin;
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z8' });
    const receipt = file('fetch-errors.json', r.envelope);
    const failing = (error) => ({ fetch: async () => Promise.reject(error) });
    const network = await cli(
      [receipt, '--deployment', d, '--fetch'],
      failing(new TypeError('fetch failed')),
    );
    assert.equal(network.code, 2);
    assert.match(network.out, /the request failed \(network error\)/);
    const timeout = await cli(
      [receipt, '--deployment', d, '--fetch'],
      failing(Object.assign(new Error('t'), { name: 'TimeoutError' })),
    );
    assert.match(timeout.out, /the request failed \(timed out\)/);
    publish(d, [keyEntry(issuerKey)]);
    routes.get(d).set(`/api/.well-known/cmdash-proof-log/inclusion/${r.digest.toString('hex')}`, {
      status: 500,
    });
    const inclusion = await cli([receipt, '--deployment', d, '--fetch']);
    assert.equal(inclusion.code, 2);
    assert.match(inclusion.out, /FETCH FAILED .*inclusion.* answered 500/);
    const logged = file('fetch-errors-logged.json', {
      ...r.envelope,
      log: logSectionFor(r.digest, { index: 1, size: 4, origin, logKeys: [logKey] }),
    });
    routes.get(d).set('/api/.well-known/cmdash-proof-log/checkpoint/4', { status: 503 });
    const checkpoint = await cli([logged, '--deployment', d, '--fetch']);
    assert.equal(checkpoint.code, 2);
    assert.match(checkpoint.out, /answered 503 for the checkpoint of size 4/);
    publish(d, [keyEntry(issuerKey)], {
      keyDocument: { body: `{"pad":"${'x'.repeat(1048576)}"}` },
    });
    routes.get(d).delete(`/api/.well-known/cmdash-proof-log/inclusion/${r.digest.toString('hex')}`);
    const huge = await cli([receipt, '--deployment', d, '--fetch']);
    assert.equal(huge.code, 2);
    assert.match(huge.out, /key\.document-malformed.*json\.too-large/);
  });

  test('plain http on a non-loopback host is refused unless allowed (--allow-plain-http)', async () => {
    const d = plain.origin; // http://127.0.0.2:<port>: canonical, plain http, and not localhost or 127.0.0.1
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z5' });
    publish(d, [keyEntry(issuerKey)]);
    const receipt = file('fetch-plain.json', r.envelope);
    const refused = await cli([receipt, '--deployment', d, '--fetch']);
    assert.equal(refused.code, 2, refused.out);
    assert.match(refused.out, /^UNVERIFIABLE - issuer\.key \(key\.deployment-plain-http\)/);
    assert.match(refused.out, /over PLAIN HTTP: in clear/);
    const allowed = await cli([receipt, '--deployment', d, '--fetch', '--allow-plain-http']);
    assert.equal(allowed.code, 0, allowed.out);
    assert.match(allowed.out, /KEY DOCUMENT FROM A PLAIN-HTTP DEPLOYMENT/);
  });

  test('a receipt naming a deployment you did not name: nothing is fetched', async () => {
    const d = loop.origin;
    const r = issue(issuerKey, { deployment: d, receiptId: '01M3VNBWG0WWTF65KKAVPE61Z6' });
    loop.requests.length = 0;
    const out = await cli([
      file('fetch-untrusted.json', r.envelope),
      '--deployment',
      'https://cmdash.example',
      '--fetch',
    ]);
    assert.equal(out.code, 2);
    assert.match(out.out, /key\.deployment-untrusted/);
    assert.match(out.out, /nothing fetched: the receipt names the deployment/);
    assert.deepEqual(loop.requests, []);
    const undecodable = await cli([
      file('fetch-undecodable.json', '{"v":0}'),
      '--deployment',
      d,
      '--fetch',
    ]);
    assert.equal(undecodable.code, 1);
    assert.match(undecodable.out, /nothing fetched: the receipt does not decode/);
  });

  test("the residual attack: a retired issuer key in a fake tree is VALID offline, UNVERIFIABLE on a 404 for its size, INVALID on the log's own checkpoint", async () => {
    const d = loop.origin;
    const retired = testKey('fetch retired issuer');
    const entries = [
      keyEntry(issuerKey),
      keyEntry(retired, 'RETIRED', {
        validFrom: '2026-06-01T00:00:00.000Z',
        validUntil: '2026-09-01T00:00:00.000Z',
        lastTreeSize: 6,
      }),
    ];
    const { doc } = publish(d, entries);
    const forged = issue(retired, {
      deployment: d,
      receiptId: '01M3VNBWG0WWTF65KKAVPE61Z7',
      observedAt: '2026-08-31T23:59:59.999Z',
      issuedAt: '2026-08-31T23:59:59.999Z',
      freshUntil: '2027-10-05T23:59:59.999Z',
    });
    const fake = logSectionFor(forged.digest, { index: 2, size: 7, origin, logKeys: [logKey] });
    const receipt = file('fetch-residual.json', { ...forged.envelope, log: fake });
    const offline = await cli([
      receipt,
      '--deployment',
      d,
      '--key-document',
      file('fetch-residual.keys.json', doc),
      '--key-document-url',
      `${d}/api/.well-known/cmdash-proof-keys/${TENANT}.json`,
    ]);
    assert.equal(offline.code, 0, 'offline, the documented residual verifies');
    // The log never signed size 7: 404, then the inclusion route does not know the digest either.
    const unrecognised = await cli([receipt, '--deployment', d, '--fetch']);
    assert.equal(unrecognised.code, 2, unrecognised.out);
    assert.match(unrecognised.out, /^UNVERIFIABLE - issuer\.key-status \(key\.retired-unproven\)/);
    assert.match(
      unrecognised.out,
      /does not recognise the receipt's checkpoint: it never signed a checkpoint of size 7 \(404\)/,
    );
    // The log did sign size 7, with its real root: equivocation.
    routes.get(d).set('/api/.well-known/cmdash-proof-log/checkpoint/7', {
      type: 'text/plain',
      body: checkpointNote(origin, 7, sha256('the real tree of 7'), [logKey]),
    });
    const equivocation = await cli([receipt, '--deployment', d, '--fetch']);
    assert.equal(equivocation.code, 1, equivocation.out);
    assert.match(equivocation.out, /^INVALID - log\.external \(external\.equivocation\)/);
  });
});
