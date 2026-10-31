// SPDX-License-Identifier: Apache-2.0
/**
 * cmdash-verify: the command-line verifier of spec section 9.4.
 *
 * Exit codes: 0 VALID, 1 INVALID, 2 UNVERIFIABLE (also unreadable input, a
 * failed fetch and bad usage), 3 STALE_VALID. STALE_VALID is deliberately not
 * 0: a stale receipt must not pass a shell `&&` chain as if it were current.
 *
 * Everything printed is printable ASCII (spec section 9.5): the library's
 * summary and details already are, and every other string that came from an
 * input (a statement, a URL, a file name, an error) is escaped here.
 *
 * `--fetch` goes only to a deployment named with --deployment, follows no
 * redirect, prints every URL it fetched and marks each one fetched over plain
 * HTTP. A failed fetch is exit 2, never silently replaced by offline
 * verification. The one exception the spec makes (section 7.5): a 404 for the
 * checkpoint of the receipt's own tree size means the log never signed that
 * size, and the receipt is then verified as if it had no log section, which
 * the output says.
 *
 * main(argv, io) takes its effects as `io` so that tests run it in-process;
 * bin/cmdash-verify.mjs wires the real ones.
 */
import { open } from 'node:fs/promises';
import { decodeBase64Std, decodeUtf8Fatal, encodeBase64Url } from './bytes.mjs';
import { ED25519_SPKI_PREFIX } from './ed25519.mjs';
import { asciiEscape, quote, quoteFull } from './escape.mjs';
import { JSON_LIMITS } from './json.mjs';
import { MAX_CHECKPOINT_CHARS } from './note.mjs';
import { SCHEMA_RE, isIssuingDeployment, parseTimestamp } from './schema.mjs';
import {
  inspectReceipt,
  verifyCollectorAttestation,
  verifyEvidenceItem,
  verifyEvidenceOpening,
  verifyReceipt,
} from './verify.mjs';

export const EXIT_CODES = Object.freeze({ VALID: 0, INVALID: 1, UNVERIFIABLE: 2, STALE_VALID: 3 });
export const EXIT_USAGE = 2;
const FETCH_TIMEOUT_MS = 15000;
const PEM_LIMIT = 8192;
const CHECKPOINT_FILE_LIMIT = MAX_CHECKPOINT_CHARS * 4;

export const USAGE = `Usage: cmdash-verify <receipt.json> [options]

Verifies a CMDash proof receipt (docs/specs/proof-receipt-v0.md) on this machine.
It never asks CMDash whether the receipt is valid; with --fetch it only GETs the
public documents named below, from a deployment you trust.

Exit codes: 0 VALID, 1 INVALID, 2 UNVERIFIABLE (also unreadable input, a failed
fetch or bad usage), 3 STALE_VALID (the signature is valid, the claim expired).

Where the issuer key comes from (the first source present is used):
  --deployment <origin>   an issuing deployment you trust, e.g. https://app.cmdash.com
                          (repeatable). Required with --fetch and --key-document.
  --fetch                 GET the issuer key document from the receipt's deployment,
                          then the log checkpoint of the receipt's tree size, or for
                          a receipt without a log section its inclusion proof. Only
                          from a --deployment origin; a redirect is a failed fetch.
  --key-document <file> --key-document-url <url>
                          a key document you fetched yourself, with its URL
  --key <deployment>#<tenantRef>=<public-key.pem>
                          an issuer key you obtained out of band, bound to one
                          issuer (repeatable)
  --allow-plain-http      accept a key document from a plain-http deployment

The transparency log:
  --log-keys <file>       a log key document (default: the key document's own)
  --log-section <file>    a log section for a receipt that has none
  --checkpoint <file>     an independently obtained checkpoint (signed note)
  --require-logged        a missing or unproven log is UNVERIFIABLE

Evidence (checked and printed separately; never changes the exit code):
  --opening <file>        an evidence opening to check against the receipt
  --item <file>           a sampled evidence item (repeatable; needs --opening)

Collector attestation (docs/specs/collector-attestation-v0.md; printed separately):
  --collector-attestation <file>
                          the supplier collector's own signature over the measurement
                          this receipt signs (GET /proof/receipts/:id/collector-attestation)
  --collector-key <deployment>#<tenantRef>=<public-key.pem>
                          a collector key you obtained from the supplier, bound to one
                          issuer (repeatable): the only way the attestation is
                          independent of the issuing deployment
  --require-collector-attestation
                          exit 1 (MISMATCH) or 2 (UNVERIFIABLE) unless the receipt is
                          VALID or STALE_VALID AND the attestation is ATTESTED

Output:
  --now <timestamp>       verify as of YYYY-MM-DDTHH:MM:SS.sssZ (default: the clock)
  --json                  print the result object as JSON (printable ASCII)
  -h, --help              print this text`;

class UsageError extends Error {}
class InputError extends Error {}
class FetchError extends Error {
  constructor(url, message) {
    super(message);
    this.url = url;
  }
}

const VALUE_FLAGS = new Set([
  '--deployment',
  '--key-document',
  '--key-document-url',
  '--key',
  '--log-keys',
  '--log-section',
  '--checkpoint',
  '--opening',
  '--item',
  '--now',
  '--collector-attestation',
  '--collector-key',
]);
const BOOLEAN_FLAGS = new Set([
  '--fetch',
  '--allow-plain-http',
  '--require-logged',
  '--require-collector-attestation',
  '--json',
  '--help',
  '-h',
]);

/** Parses argv; throws UsageError with a message fit for the user. */
export function parseArgs(argv) {
  const o = {
    receipt: null,
    deployments: [],
    keys: [],
    collectorKeys: [],
    items: [],
    collectorAttestation: null,
    requireCollectorAttestation: false,
    fetch: false,
    allowPlainHttp: false,
    requireLogged: false,
    json: false,
    help: false,
    keyDocument: null,
    keyDocumentUrl: null,
    logKeys: null,
    logSection: null,
    checkpoint: null,
    opening: null,
    now: null,
  };
  const single = (name, value) => {
    const key = {
      '--key-document': 'keyDocument',
      '--key-document-url': 'keyDocumentUrl',
      '--log-keys': 'logKeys',
      '--log-section': 'logSection',
      '--checkpoint': 'checkpoint',
      '--opening': 'opening',
      '--now': 'now',
      '--collector-attestation': 'collectorAttestation',
    }[name];
    if (o[key] !== null) throw new UsageError(`${name} given twice`);
    o[key] = value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];
    let value;
    if (arg.startsWith('--') && arg.includes('=')) {
      value = arg.slice(arg.indexOf('=') + 1);
      arg = arg.slice(0, arg.indexOf('='));
      if (!VALUE_FLAGS.has(arg)) throw new UsageError(`${quote(arg)} takes no value`);
    }
    if (BOOLEAN_FLAGS.has(arg)) {
      if (arg === '--fetch') o.fetch = true;
      else if (arg === '--allow-plain-http') o.allowPlainHttp = true;
      else if (arg === '--require-logged') o.requireLogged = true;
      else if (arg === '--require-collector-attestation') o.requireCollectorAttestation = true;
      else if (arg === '--json') o.json = true;
      else o.help = true;
      continue;
    }
    if (VALUE_FLAGS.has(arg)) {
      if (value === undefined) {
        i += 1;
        if (i >= argv.length) throw new UsageError(`${arg} needs a value`);
        value = argv[i];
      }
      if (arg === '--deployment') {
        if (!isIssuingDeployment(value)) {
          throw new UsageError(
            `--deployment ${quote(value)} is not a canonical origin (scheme://host[:port], lowercase, no path, no trailing slash, no default port)`,
          );
        }
        o.deployments.push(value);
      } else if (arg === '--key') o.keys.push(parseKeyBinding(value));
      else if (arg === '--collector-key') o.collectorKeys.push(parseKeyBinding(value, '--collector-key'));
      else if (arg === '--item') o.items.push(value);
      else single(arg, value);
      continue;
    }
    if (arg.startsWith('-') && arg !== '-') throw new UsageError(`unknown option ${quote(arg)}`);
    if (o.receipt !== null) throw new UsageError('give exactly one receipt file');
    o.receipt = arg;
  }
  if (o.help) return o;
  if (o.receipt === null) throw new UsageError('no receipt file given');
  if ((o.keyDocument === null) !== (o.keyDocumentUrl === null)) {
    throw new UsageError(
      '--key-document and --key-document-url come together: a key document means nothing without the URL it came from',
    );
  }
  if ((o.fetch || o.keyDocument !== null) && o.deployments.length === 0) {
    throw new UsageError(
      '--deployment is required with --fetch and --key-document: name the deployments you trust, so that the receipt never chooses where its trust comes from',
    );
  }
  if (o.fetch && o.keyDocument !== null)
    throw new UsageError('use either --fetch or --key-document, not both');
  if (o.items.length > 0 && o.opening === null)
    throw new UsageError('--item needs --opening: an item is checked under the opened manifest');
  if (o.requireCollectorAttestation && o.collectorAttestation === null)
    throw new UsageError('--require-collector-attestation needs --collector-attestation <file>');
  if (o.collectorKeys.length > 0 && o.collectorAttestation === null)
    throw new UsageError('--collector-key needs --collector-attestation <file>');
  if (o.now !== null && parseTimestamp(o.now) === null)
    throw new UsageError(`--now ${quote(o.now)} is not a timestamp YYYY-MM-DDTHH:MM:SS.sssZ`);
  return o;
}

function parseKeyBinding(value, flag = '--key') {
  const hash = value.indexOf('#');
  const eq = value.indexOf('=', hash + 1);
  if (hash < 0 || eq < 0)
    throw new UsageError(`${flag} ${quote(value)} is not <deployment>#<tenantRef>=<public-key.pem>`);
  const deployment = value.slice(0, hash);
  const tenantRef = value.slice(hash + 1, eq);
  const path = value.slice(eq + 1);
  if (!isIssuingDeployment(deployment))
    throw new UsageError(`${flag}: ${quote(deployment)} is not a canonical deployment origin`);
  if (!SCHEMA_RE.tenantRef.test(tenantRef))
    throw new UsageError(
      `${flag}: ${quote(tenantRef)} is not a tenantRef (tr_ and 32 lowercase hex)`,
    );
  if (path.length === 0) throw new UsageError(`${flag}: no public key file`);
  return { deployment, tenantRef, path };
}

/** An Ed25519 public key in PEM (SPKI) to the unpadded base64url of its DER, as trust.publicKeys wants it. */
export function pemToSpkiBase64Url(bytes) {
  const text = decodeUtf8Fatal(bytes);
  const m =
    text === null
      ? null
      : /^\s*-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+?)\r?\n-----END PUBLIC KEY-----\s*$/.exec(
          text,
        );
  const der = m ? decodeBase64Std(m[1].replace(/\r?\n/g, '')) : null;
  if (der === null || der.length !== 44 || ED25519_SPKI_PREFIX.some((b, i) => der[i] !== b))
    return null;
  return encodeBase64Url(der);
}

async function readInput(io, path, limit) {
  try {
    return await io.readFile(path, limit);
  } catch (e) {
    throw new InputError(`${quoteFull(path)}: ${e && e.code ? e.code : 'cannot be read'}`);
  }
}

/** One GET: no redirect, a timeout, and at most limit + 1 body bytes (so the verifier sees "too large"). */
async function httpGet(io, url, limit, fetched) {
  const entry = { url, status: null, plainHttp: url.startsWith('http://') };
  fetched.push(entry);
  let response;
  try {
    response = await io.fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { accept: 'application/json, text/plain' },
    });
  } catch (e) {
    throw new FetchError(
      url,
      `the request failed (${e && e.name === 'TimeoutError' ? 'timed out' : 'network error'})`,
    );
  }
  entry.status = response.status;
  if (
    response.type === 'opaqueredirect' ||
    (response.status >= 300 && response.status < 400) ||
    response.status === 0
  ) {
    throw new FetchError(
      url,
      `the server answered ${response.status} (a redirect): a redirect is a failed fetch, because it would let the deployment, or anyone on the path, move the fetch to an origin you never named`,
    );
  }
  if (response.status !== 200) {
    if (response.body) await response.body.cancel().catch(() => {});
    return { status: response.status };
  }
  const chunks = [];
  let total = 0;
  if (response.body) {
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
  }
  const body = new Uint8Array(Math.min(total, limit + 1));
  let o = 0;
  for (const c of chunks) {
    const take = Math.min(c.length, body.length - o);
    body.set(c.subarray(0, take), o);
    o += take;
    if (o >= body.length) break;
  }
  return { status: 200, body };
}

/**
 * --fetch (spec sections 7.4, 7.5, 9.4): the key document, then the checkpoint
 * of the receipt's tree size, or the inclusion proof of a receipt that has no
 * log section. Returns the receipt to verify (the same bytes, or the envelope
 * without its log section when the log never signed that size).
 */
async function fetchTrust(receiptBytes, trust, opts, io, fetched, notes) {
  const facts = await inspectReceipt(receiptBytes);
  if (!facts.ok) {
    notes.push(
      'nothing fetched: the receipt does not decode, so it names no deployment to fetch from',
    );
    return receiptBytes;
  }
  const deployment = facts.deployment;
  if (!opts.deployments.includes(deployment)) {
    notes.push(
      `nothing fetched: the receipt names the deployment ${quoteFull(deployment)}, which is not a --deployment you trust`,
    );
    return receiptBytes;
  }
  const keyDocument = await httpGet(io, facts.keyDocumentUrl, JSON_LIMITS.keyDocument, fetched);
  if (keyDocument.status !== 200) {
    throw new FetchError(
      facts.keyDocumentUrl,
      `the deployment answered ${keyDocument.status} for the issuer key document (it is published only when the tenant opts in)`,
    );
  }
  trust.keyDocument = keyDocument.body;
  trust.keyDocumentUrl = facts.keyDocumentUrl;

  let receipt = receiptBytes;
  const logBase = `${deployment}/api/.well-known/cmdash-proof-log`;
  let unlogged = facts.logTreeSize === null;
  if (!unlogged && trust.checkpoint === undefined) {
    const url = `${logBase}/checkpoint/${facts.logTreeSize}`;
    const r = await httpGet(io, url, CHECKPOINT_FILE_LIMIT, fetched);
    if (r.status === 200) {
      trust.checkpoint = r.body;
    } else if (r.status === 404) {
      notes.push(
        `the log at ${quoteFull(deployment)} does not recognise the receipt's checkpoint: it never signed a checkpoint of size ${facts.logTreeSize} (404). The receipt is verified as if it had no log section.`,
      );
      // The same envelope (it was read strictly, so no duplicate can hide in it) without its log member.
      const withoutLog = { ...facts.envelope };
      delete withoutLog.log;
      receipt = JSON.stringify(withoutLog);
      unlogged = true;
    } else {
      throw new FetchError(
        url,
        `the deployment answered ${r.status} for the checkpoint of size ${facts.logTreeSize}`,
      );
    }
  }
  if (unlogged && trust.logSection === undefined) {
    const url = `${logBase}/inclusion/${facts.digest}`;
    const r = await httpGet(io, url, JSON_LIMITS.logSection, fetched);
    if (r.status === 200) trust.logSection = r.body;
    else if (r.status === 404)
      notes.push(
        `the log at ${quoteFull(deployment)} does not hold this receipt's digest (404): NOT LOGGED`,
      );
    else throw new FetchError(url, `the deployment answered ${r.status} for the inclusion proof`);
  }
  return receipt;
}

function independenceLines(result, opts) {
  const lines = [];
  if (result.keySource === 'KEY_DOCUMENT') {
    lines.push(
      `the issuer key came from the key document at ${asciiEscape(result.keyDocumentUrl)}, ${
        opts.fetch ? 'fetched just now from a deployment you named' : 'which you supplied'
      }. The verdict is only as independent as that document: one that travelled with the receipt proves nothing.`,
    );
  } else if (result.keySource === 'SUPPLIED') {
    lines.push(
      'the issuer key is one you supplied (--key). The verdict is only as independent as the channel you got that key from.',
    );
  } else if (result.keySource === 'EMBEDDED') {
    lines.push(
      `the only key came from INSIDE the receipt: that proves only that whoever made the receipt holds the matching private key, not who the issuer is. Fetch the key document from ${asciiEscape(result.keyDocumentUrl)} (with --deployment and --fetch) or supply a key bound to the issuer (--key).`,
    );
  } else {
    lines.push('no issuer key was used, so nothing about the issuer is proven.');
  }
  lines.push(
    'This verifier did not ask CMDash, or anyone, whether the receipt is valid; it contacted only the URLs listed under "fetched".',
  );
  return lines;
}

function printHuman(io, run) {
  const { result, opts, fetched, notes, opening, items, collector } = run;
  const out = (line = '') => io.out(asciiEscape(line));
  out(result.summary);
  out();
  out(`receipt   ${quoteFull(opts.receipt)}${result.digest ? `  digest ${result.digest}` : ''}`);
  const p = result.payload;
  if (p) {
    out(`claim     ${p.claim.claimId}`);
    out(
      `statement ${quoteFull(p.claim.statement)}  (the issuer's wording: the reading above is the claim)`,
    );
    if (p.measurement)
      out(
        `scope     ${quoteFull(p.measurement.scope.description)}  (method ${p.measurement.method.id} v${p.measurement.method.version})`,
      );
    if (p.claim.controls.length > 0)
      out(`controls  ${p.claim.controls.map((c) => `${c.framework} ${c.controlId}`).join(', ')}`);
    out(`sources   ${p.sources.map((s) => `${s.kind} ${s.ref}`).join(', ')}`);
    out(`times     observed ${p.observedAt}, issued ${p.issuedAt}, fresh until ${p.freshUntil}`);
    if (p.supersedes) out(`supersedes ${p.supersedes}`);
  }
  out();
  out('checks');
  for (const c of result.checks) {
    const tag = c.outcome === 'FAIL' ? `FAIL ${c.effect}${c.rule ? ` ${c.rule}` : ''}` : c.outcome;
    out(`  ${c.name.padEnd(21)} ${tag}: ${c.detail}`);
  }
  if (result.proves.length > 0 || result.doesNotProve.length > 0) {
    out();
    out(`proves          ${result.proves.join(', ')}`);
    out(`does not prove  ${result.doesNotProve.join(', ')}`);
  }
  if (fetched.length > 0) {
    out();
    out('fetched');
    for (const f of fetched)
      out(
        `  GET ${f.url} -> ${f.status === null ? 'no answer' : f.status}${f.plainHttp ? '  (over PLAIN HTTP: in clear)' : ''}`,
      );
  }
  for (const n of notes) out(`note: ${n}`);
  if (opening) {
    out();
    out(
      `evidence opening ${quoteFull(opts.opening)}: ${opening.match ? 'MATCH' : `MISMATCH${opening.rule ? ` (${opening.rule})` : ''}`} - ${opening.detail}`,
    );
    for (const it of items)
      out(
        `evidence item ${quoteFull(it.path)}: ${it.match ? 'MATCH' : `MISMATCH${it.rule ? ` (${it.rule})` : ''}`} - ${it.detail}`,
      );
  }
  if (collector) {
    out();
    out(
      `collector attestation ${quoteFull(opts.collectorAttestation)}: ${collector.status}${collector.rule ? ` (${collector.rule})` : ''} - ${collector.detail}`,
    );
    if (collector.status === 'ATTESTED') {
      out(`  proves          ${collector.proves.join(', ')}`);
      out(`  does not prove  ${collector.doesNotProve.join(', ')}`);
    }
    if (result.verdict !== 'VALID' && result.verdict !== 'STALE_VALID')
      out(
        '  the receipt itself is not VALID: an attestation means something only next to a valid receipt',
      );
  }
  out();
  for (const line of independenceLines(result, opts)) out(`independence: ${line}`);
}

/** JSON whose text is printable ASCII: every other code unit is written as a \\uXXXX escape (still the same JSON). */
export function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(
    /[^\x20-\x7e\n]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
}

async function run(opts, io) {
  const now = opts.now ?? io.now();
  const receiptBytes = await readInput(io, opts.receipt, JSON_LIMITS.receipt);
  const trust = { now };
  if (opts.deployments.length > 0) trust.deployments = opts.deployments;
  if (opts.allowPlainHttp) trust.allowPlainHttp = true;
  if (opts.requireLogged) trust.requireLogged = true;
  if (opts.keyDocument !== null) {
    trust.keyDocument = await readInput(io, opts.keyDocument, JSON_LIMITS.keyDocument);
    trust.keyDocumentUrl = opts.keyDocumentUrl;
  }
  if (opts.keys.length > 0) {
    trust.publicKeys = [];
    for (const k of opts.keys) {
      const spki = pemToSpkiBase64Url(await readInput(io, k.path, PEM_LIMIT));
      if (spki === null)
        throw new InputError(
          `${quoteFull(k.path)} is not an Ed25519 public key in PEM (-----BEGIN PUBLIC KEY-----)`,
        );
      trust.publicKeys.push({ deployment: k.deployment, tenantRef: k.tenantRef, publicKey: spki });
    }
  }
  if (opts.logKeys !== null)
    trust.logKeys = await readInput(io, opts.logKeys, JSON_LIMITS.logKeyDocument);
  if (opts.logSection !== null)
    trust.logSection = await readInput(io, opts.logSection, JSON_LIMITS.logSection);
  if (opts.checkpoint !== null)
    trust.checkpoint = await readInput(io, opts.checkpoint, CHECKPOINT_FILE_LIMIT);
  const openingBytes =
    opts.opening !== null ? await readInput(io, opts.opening, JSON_LIMITS.opening) : null;
  const collectorBytes =
    opts.collectorAttestation !== null
      ? await readInput(io, opts.collectorAttestation, JSON_LIMITS.opening)
      : null;
  let collectorTrust;
  if (opts.collectorKeys.length > 0) {
    collectorTrust = { collectorKeys: [] };
    for (const k of opts.collectorKeys) {
      const spki = pemToSpkiBase64Url(await readInput(io, k.path, PEM_LIMIT));
      if (spki === null)
        throw new InputError(
          `${quoteFull(k.path)} is not an Ed25519 public key in PEM (-----BEGIN PUBLIC KEY-----)`,
        );
      collectorTrust.collectorKeys.push({
        deployment: k.deployment,
        tenantRef: k.tenantRef,
        publicKey: spki,
      });
    }
  }
  const itemBytes = [];
  for (const path of opts.items)
    itemBytes.push({ path, bytes: await readInput(io, path, JSON_LIMITS.item) });

  const fetched = [];
  const notes = [];
  let receipt = receiptBytes;
  if (opts.fetch) {
    try {
      receipt = await fetchTrust(receiptBytes, trust, opts, io, fetched, notes);
    } catch (e) {
      if (!(e instanceof FetchError)) throw e;
      const message = `FETCH FAILED ${e.url}: ${e.message}. Nothing was verified: a failed fetch is never replaced by offline verification.`;
      if (opts.json)
        io.out(
          asciiJson({
            verdict: null,
            error: 'fetch-failed',
            url: e.url,
            detail: e.message,
            fetched,
            notes,
          }),
        );
      else {
        io.out(asciiEscape(message));
        for (const f of fetched)
          io.out(
            asciiEscape(
              `  GET ${f.url} -> ${f.status === null ? 'no answer' : f.status}${f.plainHttp ? '  (over PLAIN HTTP: in clear)' : ''}`,
            ),
          );
      }
      return EXIT_USAGE;
    }
  }

  const result = await verifyReceipt(receipt, trust);
  let opening = null;
  const items = [];
  if (openingBytes !== null) {
    opening = await verifyEvidenceOpening(receiptBytes, openingBytes);
    for (const it of itemBytes)
      items.push({
        path: it.path,
        ...(await verifyEvidenceItem(receiptBytes, openingBytes, it.bytes)),
      });
  }
  const collector =
    collectorBytes !== null
      ? await verifyCollectorAttestation(receiptBytes, collectorBytes, collectorTrust)
      : null;
  // A receipt whose signed sources name a collector key is VALID on its own,
  // exactly like any v0 receipt; say plainly that the collector's own
  // signature was NOT checked, so VALID is never read as "collector-attested".
  const collectorRefs =
    collector === null && result.payload && Array.isArray(result.payload.sources)
      ? result.payload.sources.filter(
          (s) => s && s.kind === 'COLLECTOR' && /^cmdash-collector-[0-9a-f]{16}$/.test(s.ref),
        )
      : [];
  if (collectorRefs.length > 0)
    notes.push(
      `the receipt names collector key ${collectorRefs[0].ref} as its source, but no collector attestation was checked: this result does not say the collector signed the measurement (pass --collector-attestation <file>)`,
    );
  if (opts.json) {
    const doc = { ...result, fetched, notes };
    if (opening) {
      doc.evidenceOpening = opening;
      doc.evidenceItems = items.map(({ path, ...r }) => ({ file: path, ...r }));
    }
    if (collector) doc.collectorAttestation = collector;
    io.out(asciiJson(doc));
  } else {
    printHuman(io, { result, opts, fetched, notes, opening, items, collector });
  }
  const code = EXIT_CODES[result.verdict];
  // --require-collector-attestation: a receipt that verifies but whose
  // measurement the supplier's collector did not attest does not pass.
  if (opts.requireCollectorAttestation && (code === 0 || code === 3) && collector.status !== 'ATTESTED')
    return collector.status === 'MISMATCH' ? EXIT_CODES.INVALID : EXIT_CODES.UNVERIFIABLE;
  return code;
}

/**
 * Reads at most limit + 1 bytes of a file: enough for the verifier to say
 * "too large" (spec section 3.4) without ever loading a huge file.
 */
export async function readFileCapped(path, limit) {
  const handle = await open(path, 'r');
  try {
    const buf = new Uint8Array(limit + 1);
    let total = 0;
    while (total < buf.length) {
      const { bytesRead } = await handle.read(buf, total, buf.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    return buf.subarray(0, total);
  } finally {
    await handle.close();
  }
}

/** The real effects: stdout, stderr, capped file reads, the platform fetch and the clock. */
export function createNodeIo() {
  return {
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
    readFile: readFileCapped,
    fetch: (url, init) => globalThis.fetch(url, init),
    now: () => new Date().toISOString(),
  };
}

/** Runs the CLI. Resolves to the exit code; never throws for bad input, only for a bug. */
export async function main(argv, io) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    io.err(asciiEscape(`cmdash-verify: ${e.message}`));
    io.err('Run cmdash-verify --help for the options.');
    return EXIT_USAGE;
  }
  if (opts.help) {
    for (const line of USAGE.split('\n')) io.out(line);
    return 0;
  }
  try {
    return await run(opts, io);
  } catch (e) {
    if (!(e instanceof InputError)) throw e;
    io.err(asciiEscape(`cmdash-verify: unreadable input: ${e.message}`));
    return EXIT_USAGE;
  }
}
