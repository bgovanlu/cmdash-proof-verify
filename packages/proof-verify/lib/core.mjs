// SPDX-License-Identifier: Apache-2.0
/**
 * CMDash Proof Receipt v0 verification (spec docs/specs/proof-receipt-v0.md,
 * section 9), independent of the reference checker: the test vectors are the
 * contract between the two, never a shared import.
 *
 * The verifier performs no network access and reads no clock: `trust.now` is
 * an input, and fetching is the caller's step (spec section 9.1). Crypto comes
 * from a backend (node:crypto in Node, WebCrypto in a browser); every Ed25519
 * signature is checked by lib/ed25519.mjs first and by the platform second.
 *
 * Isomorphic: no Node builtin is imported here, so scripts/build-browser.mjs
 * can concatenate this module into browser/verify.js.
 */
import {
  bytesEqual,
  concatBytes,
  decodeBase64Url,
  decodeUtf8Fatal,
  fromHex,
  isUint8Array,
  toHex,
  utf8,
} from './bytes.mjs';
import { CanonicalError, canonicalize, hasOwn, isPlainObject } from './canonical.mjs';
import { rawPublicKeyOf, verifyEd25519 } from './ed25519.mjs';
import { asciiEscape, quote, quoteFull } from './escape.mjs';
import { JSON_LIMITS, StrictJsonError, readJsonDocument } from './json.mjs';
import { merkleLeafHash, verifyInclusion } from './merkle.mjs';
import { MAX_CHECKPOINT_CHARS, judgeCheckpoint, parseCheckpoint } from './note.mjs';
import {
  SCHEMA_RE,
  attestationItemProblems,
  envelopeProblems,
  isIssuingDeployment,
  isPlainHttpNonLoopback,
  itemProblems,
  keyDocumentProblems,
  keyListRuleProblems,
  logKeyDocumentProblems,
  logSectionProblems,
  openingProblems,
  parseTimestamp,
  payloadProblems,
} from './schema.mjs';

/** The checks of spec section 9.2, in order. */
export const CHECK_NAMES = Object.freeze([
  'envelope.json',
  'envelope.version',
  'envelope.shape',
  'payload.decode',
  'payload.canonical',
  'payload.schema',
  'signature.kid',
  'issuer.key',
  'signature.verify',
  'log.inclusion',
  'log.checkpoint',
  'log.external',
  'issuer.key-status',
  'payload.consistency',
  'assertion.admissible',
  'time.future',
  'freshness',
]);

/** Spec section 10, in output order. */
export const PROVES_IDS = Object.freeze([
  'signed-by-key',
  'issuer-key-published',
  'unaltered',
  'observed-at',
  'measurement-stated',
  'attestation-stated',
  'logged',
  'log-consistent-with-external',
  'fresh',
]);
export const DOES_NOT_PROVE_IDS = Object.freeze([
  'source-truth',
  'attestation-truth',
  'inputs-measured',
  'scope-completeness',
  'score-derivation',
  'control-effectiveness',
  'not-superseded',
  'currently-fresh',
  'key-status',
  'not-logged',
  'split-view',
]);

/** The trust inputs of spec section 9.1. Anything else is a caller's typo and throws. */
export const TRUST_MEMBERS = Object.freeze([
  'now',
  'deployments',
  'allowPlainHttp',
  'keyDocument',
  'keyDocumentUrl',
  'publicKeys',
  'logKeys',
  'logSection',
  'checkpoint',
  'requireLogged',
]);

const STRUCTURAL = CHECK_NAMES.slice(0, 6);
const RECEIPT_SIGNING_TAG = utf8('cmdash-receipt-v0\n');
const RECEIPT_DIGEST_TAG = utf8('cmdash-receipt-digest-v0\n');
const EVIDENCE_TAG = utf8('cmdash-receipt-evidence-v0\n');
const EVIDENCE_ITEM_TAG = utf8('cmdash-receipt-evidence-item-v0\n');
const MAX_PAYLOAD_BYTES = 16384;
const FUTURE_ALLOWANCE_MS = 300 * 1000;
const MAX_FRESH_WINDOW_MS = 400 * 86400 * 1000;
const ISSUER_KID_PREFIX = 'cmdash-proof-';
const LOG_KID_PREFIX = 'cmdash-proof-log-';
const NO_WEBCRYPTO =
  'not run: this runtime has no WebCrypto (crypto.subtle is missing, as on a plain-HTTP page); use the CLI (cmdash-verify) or serve this page over HTTPS';

/** `<deployment>/api/.well-known/cmdash-proof-keys/<tenantRef>.json` (spec section 6.3). */
export function keyDocumentUrlOf(deployment, tenantRef) {
  return `${deployment}/api/.well-known/cmdash-proof-keys/${tenantRef}.json`;
}

/** A key id: prefix + the first 16 lowercase hex of SHA-256 over the DER SPKI (spec section 6.1). */
async function keyIdOf(spki, prefix, backend) {
  return prefix + toHex(await backend.sha256(spki)).slice(0, 16);
}

export function assertBackend(backend) {
  const ok =
    backend &&
    typeof backend === 'object' &&
    typeof backend.hashes === 'boolean' &&
    typeof backend.sha256 === 'function' &&
    typeof backend.sha512 === 'function' &&
    typeof backend.ed25519Verify === 'function';
  if (!ok)
    throw new TypeError(
      'proof-verify: options.backend must be a crypto backend (nodeBackend or webCryptoBackend(crypto))',
    );
}

function normalizeTrust(trust) {
  if (!isPlainObject(trust))
    throw new TypeError('verifyReceipt: trust must be an object carrying at least { now }');
  for (const name of Object.keys(trust)) {
    if (!TRUST_MEMBERS.includes(name)) {
      throw new TypeError(
        `verifyReceipt: unknown trust member ${quote(name)}; the trust inputs are ${TRUST_MEMBERS.join(', ')}`,
      );
    }
  }
  const nowMs = parseTimestamp(trust.now);
  if (nowMs === null)
    throw new TypeError(
      'verifyReceipt: trust.now is required, as a timestamp YYYY-MM-DDTHH:MM:SS.sssZ',
    );
  const t = { nowMs };
  // An explicit null reads as "not supplied", like an absent member.
  for (const name of TRUST_MEMBERS) t[name] = trust[name] === null ? undefined : trust[name];
  return t;
}

/**
 * The checks of one verification. Every detail is passed through asciiEscape
 * on the way in (spec section 9.5): the details are built from the
 * verifier's own ASCII words and quote()d input already, so this is the
 * belt to that pair of braces, and it is idempotent on printable ASCII.
 */
class CheckLog {
  constructor() {
    this.map = new Map();
  }

  pass(name, detail) {
    this.map.set(name, { name, outcome: 'PASS', detail: asciiEscape(detail) });
  }

  skip(name, detail) {
    this.map.set(name, { name, outcome: 'SKIP', detail: asciiEscape(detail) });
  }

  fail(name, effect, rule, detail) {
    const c = { name, outcome: 'FAIL', detail: asciiEscape(detail), effect };
    if (rule) c.rule = rule;
    this.map.set(name, c);
  }

  outcome(name) {
    const c = this.map.get(name);
    return c ? c.outcome : undefined;
  }

  get(name) {
    return this.map.get(name);
  }

  list() {
    return CHECK_NAMES.map(
      (name) => this.map.get(name) || { name, outcome: 'SKIP', detail: 'not run' },
    );
  }
}

/**
 * Reads a supplied document (spec section 3.4): bytes or text strictly; an
 * object is serialized first and read back the same way, so that an object is
 * judged exactly as its JSON text would be (the size limit included) and
 * nothing that is not plain JSON (a getter, a prototype, undefined) survives.
 */
function readSuppliedDocument(input, limit) {
  if (isUint8Array(input) || typeof input === 'string') return readJsonDocument(input, limit);
  let text;
  try {
    text = JSON.stringify(input);
  } catch {
    throw new StrictJsonError('json.syntax', 'the document cannot be serialized as JSON');
  }
  if (typeof text !== 'string') throw new StrictJsonError('json.syntax', 'not a JSON document');
  return readJsonDocument(text, limit);
}

function firstProblem(problems) {
  return `${problems[0]}${problems.length > 1 ? ` (and ${problems.length - 1} more)` : ''}`;
}

/**
 * The six structural checks (spec section 9.2): envelope.json through
 * payload.schema. Needs no crypto. Records into `checks` and returns what it
 * decoded; `ok` is false once one of them failed.
 */
function readStructure(input, checks) {
  const out = {
    ok: false,
    envelope: undefined,
    payloadBytes: undefined,
    payloadText: undefined,
    payload: undefined,
  };
  const skipRest = (from) => {
    for (const name of STRUCTURAL.slice(STRUCTURAL.indexOf(from)))
      checks.skip(name, 'not run: an earlier structural check failed');
  };

  let envelope;
  try {
    // Bytes or text strictly; an object (a caller that parsed already) is serialized first (spec section 9.1).
    envelope = readSuppliedDocument(input, JSON_LIMITS.receipt);
  } catch (e) {
    if (!(e instanceof StrictJsonError)) throw e;
    checks.fail(
      'envelope.json',
      'INVALID',
      e.rule,
      `the receipt file is not acceptable JSON: ${e.message}`,
    );
    skipRest('envelope.version');
    return out;
  }
  checks.pass(
    'envelope.json',
    'the receipt file is strict JSON: UTF-8, no duplicate member, within 65536 bytes',
  );
  out.envelope = envelope;

  const v = isPlainObject(envelope) ? envelope.v : undefined;
  if (!isPlainObject(envelope) || typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    checks.fail(
      'envelope.version',
      'INVALID',
      null,
      'the receipt is not an object with a non-negative integer "v"',
    );
    skipRest('envelope.shape');
    return out;
  }
  if (v !== 0) {
    checks.fail(
      'envelope.version',
      'UNVERIFIABLE',
      null,
      `the envelope is version ${v}; this verifier implements version 0 only`,
    );
    skipRest('envelope.shape');
    return out;
  }
  checks.pass('envelope.version', 'version 0');

  const shape = envelopeProblems(envelope);
  if (shape.length > 0) {
    checks.fail(
      'envelope.shape',
      'INVALID',
      null,
      `the envelope breaks spec section 2: ${firstProblem(shape)}`,
    );
    skipRest('payload.decode');
    return out;
  }
  checks.pass(
    'envelope.shape',
    'the envelope has exactly the members of spec section 2, with canonical base64url',
  );

  const bytes = decodeBase64Url(envelope.payload);
  out.payloadBytes = bytes;
  const decodeFail = (why) => {
    checks.fail('payload.decode', 'INVALID', null, why);
    skipRest('payload.canonical');
    return out;
  };
  if (bytes === null) return decodeFail('the payload is not canonical base64url');
  if (bytes.length > MAX_PAYLOAD_BYTES)
    return decodeFail(`the payload is ${bytes.length} bytes; the limit is ${MAX_PAYLOAD_BYTES}`);
  const text = decodeUtf8Fatal(bytes);
  if (text === null) return decodeFail('the payload bytes are not valid UTF-8');
  let value;
  try {
    // Any conformant parser (spec section 3.1 step 2): a duplicate member is caught by the byte comparison.
    value = JSON.parse(text);
  } catch {
    return decodeFail('the payload is not JSON (a byte-order mark, or a syntax error)');
  }
  if (!isPlainObject(value)) return decodeFail('the payload is not a JSON object');
  checks.pass('payload.decode', `${bytes.length} bytes of UTF-8 JSON, an object`);
  out.payloadText = text;

  let canonical;
  try {
    canonical = canonicalize(value);
  } catch (e) {
    if (!(e instanceof CanonicalError)) throw e;
    checks.fail(
      'payload.canonical',
      'INVALID',
      e.rule,
      `the payload holds a value outside the canonical subset: ${e.message}`,
    );
    skipRest('payload.schema');
    return out;
  }
  if (canonical !== text) {
    checks.fail(
      'payload.canonical',
      'INVALID',
      'canonical.bytes-differ',
      'the payload bytes are not their canonical form (member order, whitespace, number form, escaping or a duplicate member)',
    );
    skipRest('payload.schema');
    return out;
  }
  checks.pass(
    'payload.canonical',
    'the payload bytes are exactly their canonical form (spec section 3)',
  );

  const problems = payloadProblems(value);
  if (problems.length > 0) {
    checks.fail(
      'payload.schema',
      'INVALID',
      null,
      `the payload breaks #/$defs/payload: ${firstProblem(problems)}`,
    );
    return out;
  }
  checks.pass(
    'payload.schema',
    'the payload matches #/$defs/payload, and every timestamp is a real instant',
  );
  out.payload = value;
  out.ok = true;
  return out;
}

/** Validates a key document (spec section 6.3): acceptable JSON, the schema, the malformation rules. */
async function readKeyDocument(input, backend) {
  let doc;
  try {
    doc = readSuppliedDocument(input, JSON_LIMITS.keyDocument);
  } catch (e) {
    if (!(e instanceof StrictJsonError)) throw e;
    return {
      ok: false,
      detail: `the key document is not acceptable JSON (${e.rule}): ${e.message}`,
    };
  }
  const problems = keyDocumentProblems(doc);
  if (problems.length > 0)
    return { ok: false, detail: `the key document fails the schema: ${firstProblem(problems)}` };
  // The document is malformed, and useless for every receipt, when its keys OR the log key document it
  // embeds break a rule (spec sections 6.3, 7.4): a broken deployment is never half-trusted.
  const lists = [['keys', doc.keys, ISSUER_KID_PREFIX]];
  if (doc.log !== undefined) lists.push(['log.keys', doc.log.keys, LOG_KID_PREFIX]);
  for (const [what, keys, prefix] of lists) {
    const rules = keyListRuleProblems(keys, what);
    if (rules.length > 0)
      return { ok: false, detail: `the key document is malformed: ${firstProblem(rules)}` };
    for (let i = 0; i < keys.length; i += 1) {
      const derived = await keyIdOf(decodeBase64Url(keys[i].publicKey), prefix, backend);
      if (derived !== keys[i].kid)
        return {
          ok: false,
          detail: `the key document is malformed: ${what}[${i}] does not hash to its id ${quoteFull(keys[i].kid)}`,
        };
    }
  }
  return { ok: true, doc };
}

/**
 * The issuer key (spec section 6.6): first the deployment the relying party
 * trusts, then the first key source present (key document, supplied keys,
 * the envelope's own copy). Never falls back to the embedded key when an
 * independent source was supplied.
 */
async function resolveIssuerKey(payload, envelope, t, backend) {
  const { deployment, tenantRef, keyId } = payload.issuer;
  const unverifiable = (rule, detail, extra = {}) => ({
    outcome: 'FAIL',
    effect: 'UNVERIFIABLE',
    rule,
    detail,
    ...extra,
  });
  const hasKeyDocument = t.keyDocument !== undefined;

  if (t.deployments !== undefined) {
    if (!Array.isArray(t.deployments) || !t.deployments.includes(deployment)) {
      return unverifiable(
        'key.deployment-untrusted',
        `the receipt names the deployment ${quoteFull(deployment)}, which is not one you trust (trust.deployments)`,
      );
    }
  } else if (hasKeyDocument) {
    return unverifiable(
      'key.deployment-untrusted',
      'a key document proves only what its deployment says, and no trusted deployment was named (trust.deployments is required with a key document)',
    );
  }

  if (hasKeyDocument) {
    if (isPlainHttpNonLoopback(deployment) && t.allowPlainHttp !== true) {
      return unverifiable(
        'key.deployment-plain-http',
        `the deployment ${quoteFull(deployment)} is plain http: its key document is only as trustworthy as the network path, and plain http was not explicitly allowed`,
      );
    }
    const read = await readKeyDocument(t.keyDocument, backend);
    if (!read.ok) return unverifiable('key.document-malformed', read.detail);
    const doc = read.doc;
    const expectedUrl = keyDocumentUrlOf(deployment, tenantRef);
    if (t.keyDocumentUrl !== expectedUrl) {
      return unverifiable(
        'key.document-url',
        t.keyDocumentUrl === undefined
          ? `the key document came without the URL it was fetched from; this receipt's is ${quoteFull(expectedUrl)}`
          : `the key document was fetched from ${quote(t.keyDocumentUrl)}, not from this receipt's ${quoteFull(expectedUrl)}`,
      );
    }
    if (doc.deployment !== deployment) {
      return unverifiable(
        'key.document-deployment',
        `the key document names the deployment ${quoteFull(doc.deployment)}, not ${quoteFull(deployment)}`,
      );
    }
    if (doc.tenantRef !== tenantRef) {
      return unverifiable(
        'key.document-tenant',
        `the key document names the tenantRef ${quoteFull(doc.tenantRef)}, not ${quoteFull(tenantRef)}`,
      );
    }
    const entry = doc.keys.find((k) => k.kid === keyId);
    if (!entry) {
      return unverifiable(
        'key.not-in-document',
        `the key document at ${quoteFull(expectedUrl)} does not list the key ${quoteFull(keyId)}`,
        {
          acceptedDocument: doc,
        },
      );
    }
    return {
      outcome: 'PASS',
      detail: `key ${quoteFull(keyId)} from the key document at ${quoteFull(expectedUrl)} (listed ${entry.status})`,
      key: {
        source: 'KEY_DOCUMENT',
        raw: rawPublicKeyOf(decodeBase64Url(entry.publicKey)),
        entry,
        document: doc,
      },
      acceptedDocument: doc,
    };
  }

  if (t.publicKeys !== undefined) {
    const entries = Array.isArray(t.publicKeys) ? t.publicKeys : [];
    const usable = [];
    for (const e of entries) {
      if (!isPlainObject(e) || !isIssuingDeployment(e.deployment)) continue;
      if (typeof e.tenantRef !== 'string' || !SCHEMA_RE.tenantRef.test(e.tenantRef)) continue;
      if (typeof e.publicKey !== 'string' || !SCHEMA_RE.spki.test(e.publicKey)) continue;
      const spki = decodeBase64Url(e.publicKey);
      if (spki === null) continue;
      usable.push({
        deployment: e.deployment,
        tenantRef: e.tenantRef,
        spki,
        kid: await keyIdOf(spki, ISSUER_KID_PREFIX, backend),
      });
    }
    const notKeys = entries.length - usable.length;
    const withId = usable.filter((u) => u.kid === keyId);
    if (withId.length === 0) {
      return unverifiable(
        'key.supplied-none',
        `none of the ${usable.length} supplied key(s) has the key id ${quoteFull(keyId)}` +
          (notKeys > 0
            ? `; ${notKeys} supplied entr${notKeys === 1 ? 'y is' : 'ies are'} not a key (each needs a canonical deployment, a tenantRef and an Ed25519 SPKI)`
            : ''),
      );
    }
    const atDeployment = withId.filter((u) => u.deployment === deployment);
    if (atDeployment.length === 0) {
      return unverifiable(
        'key.supplied-deployment',
        `the supplied key ${quoteFull(keyId)} is bound to ${withId.map((u) => quoteFull(u.deployment)).join(', ')}, not to the receipt's deployment ${quoteFull(deployment)}`,
      );
    }
    const match = atDeployment.find((u) => u.tenantRef === tenantRef);
    if (!match) {
      return unverifiable(
        'key.supplied-tenant',
        `the supplied key ${quoteFull(keyId)} at ${quoteFull(deployment)} is bound to ${atDeployment.map((u) => quoteFull(u.tenantRef)).join(', ')}, not to the receipt's tenantRef ${quoteFull(tenantRef)}`,
      );
    }
    return {
      outcome: 'PASS',
      detail: `key ${quoteFull(keyId)} supplied out of band, bound to ${quoteFull(`${deployment}#${tenantRef}`)}`,
      key: { source: 'SUPPLIED', raw: rawPublicKeyOf(match.spki) },
    };
  }

  if (hasOwn(envelope, 'issuerKey')) {
    const ik = envelope.issuerKey;
    const spki = decodeBase64Url(ik.publicKey);
    const derived = await keyIdOf(spki, ISSUER_KID_PREFIX, backend);
    if (ik.kid !== keyId || derived !== keyId) {
      return unverifiable(
        'key.embedded-mismatch',
        ik.kid !== keyId
          ? `the embedded key is ${quoteFull(ik.kid)}, not the receipt's ${quoteFull(keyId)}`
          : `the embedded key hashes to ${quoteFull(derived)}, not to its id ${quoteFull(ik.kid)}`,
      );
    }
    return unverifiable(
      'key.embedded-only',
      'the only key came from inside the receipt: it proves only that whoever made the receipt holds the matching private key (the signature is still checked)',
      { key: { source: 'EMBEDDED', raw: rawPublicKeyOf(spki) } },
    );
  }

  return unverifiable(
    'key.no-key',
    'no key document, no supplied key, and no key embedded in the receipt',
  );
}

/**
 * The trusted log keys (spec sections 7.4, 9.1): trust.logKeys when given,
 * else the `log` member of a key document that passed its document-level
 * checks (a key document refused for its deployment, URL or tenant vouches
 * for nothing, its log keys included).
 */
export async function resolveLogKeys(t, acceptedDocument, backend) {
  let doc;
  let from;
  if (t.logKeys !== undefined) {
    from = 'the supplied log key document';
    try {
      doc = readSuppliedDocument(t.logKeys, JSON_LIMITS.logKeyDocument);
    } catch (e) {
      if (!(e instanceof StrictJsonError)) throw e;
      return { malformed: `${from} is not acceptable JSON (${e.rule}): ${e.message}` };
    }
  } else if (acceptedDocument && acceptedDocument.log !== undefined) {
    from = "the key document's log key document";
    doc = acceptedDocument.log;
  } else {
    return null;
  }
  const problems = logKeyDocumentProblems(doc);
  if (problems.length > 0)
    return { malformed: `${from} fails the schema: ${firstProblem(problems)}` };
  const rules = keyListRuleProblems(doc.keys, 'keys');
  if (rules.length > 0) return { malformed: `${from} is malformed: ${firstProblem(rules)}` };
  const keys = [];
  for (let i = 0; i < doc.keys.length; i += 1) {
    const k = doc.keys[i];
    const spki = decodeBase64Url(k.publicKey);
    if ((await keyIdOf(spki, LOG_KID_PREFIX, backend)) !== k.kid) {
      return {
        malformed: `${from} is malformed: keys[${i}] does not hash to its id ${quoteFull(k.kid)}`,
      };
    }
    keys.push({
      kid: k.kid,
      status: k.status,
      lastTreeSize: k.lastTreeSize,
      raw: rawPublicKeyOf(spki),
    });
  }
  return { keys: { origin: doc.origin, keys }, from };
}

export function readExternalCheckpoint(input) {
  let text = input;
  if (isUint8Array(input)) {
    if (input.length > MAX_CHECKPOINT_CHARS * 4)
      return { ok: false, reason: `it is larger than ${MAX_CHECKPOINT_CHARS} characters` };
    text = decodeUtf8Fatal(input);
    if (text === null) return { ok: false, reason: 'it is not valid UTF-8' };
  }
  return parseCheckpoint(text);
}

/** Spec section 6.5. `logged` is { index } when log.inclusion and log.checkpoint both passed, else null. */
function evaluateKeyStatus(entry, document, payload, logged) {
  const issuedAt = parseTimestamp(payload.issuedAt);
  const fail = (effect, rule, detail) => ({ outcome: 'FAIL', effect, rule, detail });
  if (entry.status === 'REVOKED' && entry.revocationReason === 'KEY_COMPROMISE') {
    return fail(
      'INVALID',
      'key.revoked',
      `the key was revoked for KEY_COMPROMISE at ${entry.revokedAt}: every receipt it ever signed is INVALID`,
    );
  }
  if (issuedAt < parseTimestamp(entry.validFrom)) {
    return fail(
      'INVALID',
      'key.not-yet-valid',
      `issued at ${payload.issuedAt}, before the key became valid at ${entry.validFrom}`,
    );
  }
  let note = null;
  const retired = entry.status === 'RETIRED';
  const disowned = entry.status === 'REVOKED' && entry.revocationReason === 'ISSUER_REQUEST';
  if (retired || disowned) {
    let end;
    let endText;
    let rule;
    let what;
    if (retired) {
      end = parseTimestamp(entry.validUntil);
      endText = entry.validUntil;
      rule = 'key.retired';
      what = 'retired';
    } else {
      const revokedAt = parseTimestamp(entry.revokedAt);
      const until = entry.validUntil !== undefined ? parseTimestamp(entry.validUntil) : null;
      if (until !== null && until < revokedAt) {
        end = until;
        endText = entry.validUntil;
        rule = 'key.retired';
        what = 'retired (and later disowned by the issuer)';
      } else {
        end = revokedAt;
        endText = entry.revokedAt;
        rule = 'key.disowned';
        what = 'disowned by the issuer';
      }
    }
    const lts = entry.lastTreeSize;
    if (issuedAt >= end)
      return fail(
        'INVALID',
        rule,
        `issued at ${payload.issuedAt}, at or after the key was ${what} at ${endText}`,
      );
    if (logged && lts !== undefined && logged.index >= lts) {
      return fail(
        'INVALID',
        rule,
        `logged at index ${logged.index}, at or above the key's lastTreeSize ${lts}: after the key was ${what} at ${endText}`,
      );
    }
    if (!(logged && lts !== undefined && logged.index < lts)) {
      return fail(
        'UNVERIFIABLE',
        'key.retired-unproven',
        `the key was ${what} at ${endText}, and nothing but the signer's own issuedAt says this receipt came first: no verified log proof below the key's lastTreeSize${lts === undefined ? ' (the key has none)' : ` ${lts}`}`,
      );
    }
    note = `KEY ${disowned && rule === 'key.disowned' ? 'DISOWNED BY THE ISSUER' : 'RETIRED'} AT ${endText}, after this receipt (logged at index ${logged.index}, below lastTreeSize ${lts})`;
  }
  if (parseTimestamp(document.generatedAt) < issuedAt) {
    return {
      outcome: 'SKIP',
      detail: `key status NOT PROVEN: the key document was generated at ${document.generatedAt}, before the receipt was issued at ${payload.issuedAt}, so it cannot know what happened to the key since`,
      note,
    };
  }
  return {
    outcome: 'PASS',
    detail: `the key is ${entry.status}${note ? ` (${note})` : ''}, as of ${document.generatedAt}`,
    note,
  };
}

function consistencyProblem(payload) {
  const observed = parseTimestamp(payload.observedAt);
  const issued = parseTimestamp(payload.issuedAt);
  const fresh = parseTimestamp(payload.freshUntil);
  if (observed > issued)
    return [
      'time.observed-before-issued',
      `observedAt ${payload.observedAt} is after issuedAt ${payload.issuedAt}`,
    ];
  if (fresh <= observed)
    return [
      'time.fresh-after-observed',
      `freshUntil ${payload.freshUntil} is not after observedAt ${payload.observedAt}`,
    ];
  if (fresh - observed > MAX_FRESH_WINDOW_MS)
    return ['time.window-max-400d', 'freshUntil is more than 400 days after observedAt'];
  if (payload.selfAttested !== undefined && payload.selfAttested.at !== payload.observedAt) {
    return [
      'self-attested.at-equals-observedAt',
      `selfAttested.at ${payload.selfAttested.at} is not observedAt ${payload.observedAt}`,
    ];
  }
  if (payload.supersedes !== undefined && payload.supersedes === payload.receiptId)
    return ['supersedes.not-self', 'the receipt supersedes itself'];
  return null;
}

/** Spec section 5.3, rules in table order. Returns [rule, detail] or null. */
function assertionProblem(payload) {
  const a = payload.claim.assertion;
  if (a.kind === 'SELF_ATTESTED') return null;
  const { numerator: n, denominator: d, unknown: u } = payload.measurement;
  if (n + u > d)
    return [
      'measurement.parts-within-denominator',
      `numerator ${n} + unknown ${u} exceeds the denominator ${d}`,
    ];
  if (a.kind === 'ALL') {
    if (d === 0) return ['ALL.denominator-positive', 'an ALL claim over an empty population'];
    if (u > 0) return ['ALL.no-unknown', `an ALL claim with ${u} unknown: unknown is never pass`];
    if (n !== d) return ['ALL.complete', `an ALL claim with ${n} of ${d} met`];
  } else if (a.kind === 'AT_LEAST') {
    const { numerator: tn, denominator: td } = a.threshold;
    if (tn >= td)
      return ['AT_LEAST.threshold-below-one', `a threshold of ${tn}/${td} is an ALL claim`];
    if (d === 0)
      return ['AT_LEAST.denominator-positive', 'an AT_LEAST claim over an empty population'];
    if (n * td < tn * d)
      return [
        'AT_LEAST.threshold-met',
        `${n} of ${d} is below the threshold ${tn}/${td} (unknown items count against it)`,
      ];
  } else if (a.kind === 'SCORE') {
    if (a.min >= a.max)
      return ['SCORE.range-ordered', `the scale ${a.min}..${a.max} is empty or inverted`];
    if (a.value < a.min || a.value > a.max)
      return ['SCORE.in-range', `the score ${a.value} is outside ${a.min}..${a.max}`];
    if (d === 0)
      return ['SCORE.denominator-positive', 'a score over an empty population says nothing'];
    if (u === d && a.value !== a.min)
      return [
        'SCORE.all-unknown-is-min',
        `every item is unknown, so only the minimum ${a.min} is admissible, not ${a.value}`,
      ];
    if (n === 0 && a.value !== a.min)
      return [
        'SCORE.none-met-is-min',
        `no item is met, so only the minimum ${a.min} is admissible, not ${a.value}`,
      ];
    if (a.value === a.max && !(u === 0 && n === d))
      return [
        'SCORE.max-requires-complete',
        `the maximum score ${a.max} needs every item met and none unknown (${n} of ${d}, ${u} unknown)`,
      ];
  }
  return null;
}

/** floor(10000 n / d) as "NN.NN", or null when d = 0 (spec section 5.5). Truncates; never rounds up to 100.00. */
export function truncatedPercent(n, d) {
  if (d === 0) return null;
  const scaled = 10000 * n;
  const q = (scaled - (scaled % d)) / d;
  return `${Math.floor(q / 100)}.${String(q % 100).padStart(2, '0')}`;
}

function basisOf(payload) {
  if (payload.claim.assertion.kind === 'SELF_ATTESTED') return 'SELF_ATTESTED';
  return payload.sources.some((s) => s.kind === 'TENANT_RECORD') ? 'SELF_ASSESSED' : 'MEASURED';
}

/** The structured reading a verifier displays as the claim (spec section 9.4). */
function readingOf(payload) {
  const a = payload.claim.assertion;
  if (a.kind === 'SELF_ATTESTED') {
    return {
      kind: 'SELF_ATTESTED',
      basis: 'SELF_ATTESTED',
      byRole: payload.selfAttested.byRole,
      at: payload.selfAttested.at,
    };
  }
  const m = payload.measurement;
  const reading = {
    kind: a.kind,
    basis: basisOf(payload),
    unit: m.scope.unit,
    numerator: m.numerator,
    denominator: m.denominator,
    unknown: m.unknown,
    percent: a.kind === 'SCORE' ? null : truncatedPercent(m.numerator, m.denominator),
  };
  if (a.kind === 'AT_LEAST') {
    reading.threshold = {
      numerator: a.threshold.numerator,
      denominator: a.threshold.denominator,
      percent: truncatedPercent(a.threshold.numerator, a.threshold.denominator),
    };
  }
  if (a.kind === 'SCORE') reading.score = { value: a.value, min: a.min, max: a.max };
  return reading;
}

/** One line of plain ASCII for the reading. The statement is never the claim (spec section 5.3). */
function readingText(reading) {
  if (reading.kind === 'SELF_ATTESTED')
    return `SELF-ATTESTED by a person in role ${reading.byRole} at ${reading.at}; nothing was measured`;
  const prefix = reading.basis === 'SELF_ASSESSED' ? 'SELF-ASSESSED ' : '';
  const counts = `${reading.numerator} of ${reading.denominator} ${reading.unit}${reading.percent !== null ? ` (${reading.percent}%)` : ''}, ${reading.unknown} unknown`;
  if (reading.kind === 'AT_LEAST') {
    return `${prefix}AT_LEAST ${reading.threshold.numerator}/${reading.threshold.denominator} (${reading.threshold.percent}%): ${counts}`;
  }
  if (reading.kind === 'SCORE') {
    return `${prefix}SCORE ${reading.score.value} on a scale from ${reading.score.min} to ${reading.score.max} (${reading.numerator} of ${reading.denominator} ${reading.unit} met, ${reading.unknown} unknown)`;
  }
  return `${prefix}${reading.kind}: ${counts}`;
}

function provesOf(verdict, payload, keySource, checks) {
  const kind = payload.claim.assertion.kind;
  const measured = kind !== 'SELF_ATTESTED';
  const logged =
    checks.outcome('log.inclusion') === 'PASS' && checks.outcome('log.checkpoint') === 'PASS';
  const proves = ['signed-by-key'];
  if (keySource === 'KEY_DOCUMENT') proves.push('issuer-key-published');
  proves.push('unaltered', 'observed-at', measured ? 'measurement-stated' : 'attestation-stated');
  if (logged) proves.push('logged');
  if (checks.outcome('log.external') === 'PASS') proves.push('log-consistent-with-external');
  if (verdict === 'VALID') proves.push('fresh');
  const doesNotProve = [measured ? 'source-truth' : 'attestation-truth'];
  if (basisOf(payload) === 'SELF_ASSESSED') doesNotProve.push('inputs-measured');
  if (measured) doesNotProve.push('scope-completeness');
  if (kind === 'SCORE') doesNotProve.push('score-derivation');
  doesNotProve.push('control-effectiveness', 'not-superseded');
  if (verdict === 'STALE_VALID') doesNotProve.push('currently-fresh');
  if (checks.outcome('issuer.key-status') !== 'PASS') doesNotProve.push('key-status');
  doesNotProve.push(logged ? 'split-view' : 'not-logged');
  return { proves, doesNotProve, logged };
}

/**
 * Verifies one receipt (spec section 9). `receipt` is the file's bytes
 * (Uint8Array), its text, or an already-parsed object (which loses the
 * duplicate-member check, so pass bytes when you have them). `trust` is the
 * spec section 9.1 input, `now` required. Resolves to the spec section 9.4
 * result; never throws on a hostile receipt, only on a caller's error.
 */
export async function verifyReceiptWith(receipt, trust, backend) {
  assertBackend(backend);
  const t = normalizeTrust(trust);
  const checks = new CheckLog();
  const result = {
    verdict: 'INVALID',
    failedCheck: null,
    rule: null,
    keySource: null,
    keyStatusAsOf: null,
    keyDocumentUrl: null,
    plainHttp: false,
    checks: [],
    proves: [],
    doesNotProve: [],
    reading: null,
    summary: '',
    digest: null,
    payload: null,
  };

  const structure = readStructure(receipt, checks);
  let digestBytes = null;
  if (structure.payloadBytes && backend.hashes) {
    digestBytes = await backend.sha256(concatBytes(RECEIPT_DIGEST_TAG, structure.payloadBytes));
    result.digest = toHex(digestBytes);
  }
  const ctx = {
    signatureVerified: false,
    keyStatusNote: null,
    logged: null,
    checkpointSigners: [],
    keyInfo: null,
  };

  if (!structure.ok) {
    for (const name of CHECK_NAMES.slice(6))
      checks.skip(name, 'not run: a structural check failed');
    return finish(result, checks, null, t, ctx);
  }

  const { envelope, payload, payloadBytes } = structure;
  const { deployment, tenantRef, keyId } = payload.issuer;
  result.keyDocumentUrl = keyDocumentUrlOf(deployment, tenantRef);
  result.plainHttp = deployment.startsWith('http://');

  // signature.kid
  const kidOk = envelope.sig.kid === keyId;
  if (kidOk)
    checks.pass('signature.kid', `sig.kid is the payload's issuer.keyId ${quoteFull(keyId)}`);
  else
    checks.fail(
      'signature.kid',
      'INVALID',
      null,
      `sig.kid ${quoteFull(envelope.sig.kid)} is not the payload's issuer.keyId ${quoteFull(keyId)}`,
    );

  // issuer.key
  let acceptedDocument = null;
  if (!kidOk) {
    checks.skip('issuer.key', 'not run: signature.kid did not pass');
  } else if (!backend.hashes) {
    checks.skip('issuer.key', NO_WEBCRYPTO);
  } else {
    const r = await resolveIssuerKey(payload, envelope, t, backend);
    if (r.outcome === 'PASS') checks.pass('issuer.key', r.detail);
    else checks.fail('issuer.key', r.effect, r.rule, r.detail);
    if (r.key) {
      ctx.keyInfo = r.key;
      result.keySource = r.key.source;
    }
    acceptedDocument = r.acceptedDocument || null;
  }

  // signature.verify
  if (!kidOk) {
    checks.skip('signature.verify', 'not run: signature.kid did not pass');
  } else if (!backend.hashes) {
    checks.fail(
      'signature.verify',
      'UNVERIFIABLE',
      'ed25519.unavailable',
      NO_WEBCRYPTO.replace('not run: ', ''),
    );
  } else if (!ctx.keyInfo) {
    checks.skip('signature.verify', 'not run: no key was found');
  } else {
    const sig = decodeBase64Url(envelope.sig.value);
    const v = await verifyEd25519(
      ctx.keyInfo.raw,
      concatBytes(RECEIPT_SIGNING_TAG, payloadBytes),
      sig,
      backend,
    );
    if (v.ok === true) {
      ctx.signatureVerified = true;
      checks.pass(
        'signature.verify',
        `the Ed25519 signature verifies under ${quoteFull(keyId)}${ctx.keyInfo.source === 'EMBEDDED' ? ' (the embedded key)' : ''}: point checks, the cofactorless equation and the platform agree`,
      );
    } else if (v.ok === null) {
      checks.fail('signature.verify', 'UNVERIFIABLE', v.rule, v.detail);
    } else {
      checks.fail('signature.verify', 'INVALID', v.rule, v.detail);
    }
  }

  // log.inclusion, log.checkpoint, log.external
  let section = null;
  let sectionSource = null;
  let note = null;
  let logKeys = null;
  if (!backend.hashes) {
    for (const name of ['log.inclusion', 'log.checkpoint', 'log.external'])
      checks.skip(name, NO_WEBCRYPTO);
  } else {
    if (hasOwn(envelope, 'log')) {
      section = envelope.log;
      sectionSource = 'the envelope';
    } else if (t.logSection !== undefined) {
      let supplied;
      let problem = null;
      try {
        supplied = readSuppliedDocument(t.logSection, JSON_LIMITS.logSection);
        const problems = logSectionProblems(supplied);
        if (problems.length > 0)
          problem = `the supplied log section fails #/$defs/logSection: ${firstProblem(problems)}`;
      } catch (e) {
        if (!(e instanceof StrictJsonError)) throw e;
        problem = `the supplied log section is not acceptable JSON (${e.rule}): ${e.message}`;
      }
      if (problem !== null)
        checks.fail('log.inclusion', 'UNVERIFIABLE', 'log.section-malformed', problem);
      else {
        section = supplied;
        sectionSource = 'the supplied log section';
      }
    }

    if (checks.outcome('log.inclusion') === undefined && section === null) {
      if (t.requireLogged === true) {
        checks.fail(
          'log.inclusion',
          'UNVERIFIABLE',
          'policy.require-logged',
          'publication is required (requireLogged), and the receipt has no log section and none was supplied',
        );
      } else {
        checks.skip(
          'log.inclusion',
          'NOT LOGGED: the receipt has no log section, and none was supplied',
        );
      }
    } else if (section !== null) {
      const parsed = parseCheckpoint(section.checkpoint);
      if (!parsed.ok) {
        checks.fail(
          'log.inclusion',
          'INVALID',
          'log.checkpoint-malformed',
          `the checkpoint in ${sectionSource} is not a well-formed signed note: ${parsed.reason}`,
        );
      } else if (section.treeSize !== parsed.size) {
        checks.fail(
          'log.inclusion',
          'INVALID',
          'log.size-mismatch',
          `log.treeSize ${section.treeSize} is not the checkpoint's size ${parsed.size}`,
        );
      } else if (!bytesEqual(fromHex(section.rootHash), parsed.root)) {
        checks.fail(
          'log.inclusion',
          'INVALID',
          'log.root-mismatch',
          "log.rootHash is not the checkpoint's root hash",
        );
      } else if (section.index >= section.treeSize) {
        checks.fail(
          'log.inclusion',
          'INVALID',
          'log.index-outside',
          `log.index ${section.index} is outside a tree of ${section.treeSize}`,
        );
      } else {
        const leaf = await merkleLeafHash(digestBytes, backend);
        const proof = section.proof.map((h) => fromHex(h));
        if (
          await verifyInclusion(section.index, section.treeSize, leaf, proof, parsed.root, backend)
        ) {
          note = parsed;
          checks.pass(
            'log.inclusion',
            `the receipt digest is leaf ${section.index} of a tree of ${section.treeSize} (${sectionSource}), under the checkpoint's root`,
          );
        } else {
          checks.fail(
            'log.inclusion',
            'INVALID',
            'log.proof',
            "the audit path does not lead from the receipt's leaf to the checkpoint's root",
          );
        }
      }
    }

    const policyOrSkip = (name, why) => {
      if (t.requireLogged === true)
        checks.fail(
          name,
          'UNVERIFIABLE',
          'policy.require-logged',
          `publication is required (requireLogged), and ${why}`,
        );
      else checks.skip(name, `NOT LOGGED: ${why}`);
    };
    if (checks.outcome('log.inclusion') !== 'PASS') {
      checks.skip('log.checkpoint', 'not run: log.inclusion did not pass');
    } else {
      const resolved = await resolveLogKeys(t, acceptedDocument, backend);
      if (resolved === null) {
        policyOrSkip(
          'log.checkpoint',
          'no trusted log key: none was supplied, and no accepted key document embeds one',
        );
      } else if (resolved.malformed) {
        checks.fail('log.checkpoint', 'UNVERIFIABLE', 'log-keys.malformed', resolved.malformed);
      } else {
        logKeys = resolved.keys;
        const j = await judgeCheckpoint(note, logKeys, backend);
        if (j.result === 'OTHER_ORIGIN') {
          policyOrSkip(
            'log.checkpoint',
            `the checkpoint is for the log ${quoteFull(note.origin)}, and the trusted log keys are for ${quoteFull(logKeys.origin)}`,
          );
        } else if (j.result === 'NO_TRUSTED_LINE') {
          policyOrSkip(
            'log.checkpoint',
            'no signature line of the checkpoint claims a trusted log key (a revoked key is not trusted)',
          );
        } else if (j.result === 'UNAVAILABLE') {
          policyOrSkip('log.checkpoint', j.detail);
        } else if (j.result === 'BAD_SIGNATURE') {
          checks.fail('log.checkpoint', 'INVALID', 'checkpoint.signature', j.detail);
        } else if (j.result === 'BEYOND') {
          checks.fail('log.checkpoint', 'INVALID', 'log-key.beyond-last-tree-size', j.detail);
        } else {
          ctx.logged = { index: section.index, treeSize: section.treeSize };
          ctx.checkpointSigners = j.signers;
          checks.pass(
            'log.checkpoint',
            `the checkpoint for ${quoteFull(note.origin)} is signed by the trusted log key(s) ${j.signers.map(quoteFull).join(', ')} (from ${resolved.from})`,
          );
        }
      }
    }

    if (t.checkpoint === undefined) {
      checks.skip('log.external', 'no external checkpoint was supplied');
    } else if (checks.outcome('log.checkpoint') !== 'PASS') {
      checks.skip('log.external', 'not run: log.checkpoint did not pass');
    } else {
      const ext = readExternalCheckpoint(t.checkpoint);
      if (!ext.ok) {
        checks.fail(
          'log.external',
          'UNVERIFIABLE',
          'external.malformed',
          `the external checkpoint is not a well-formed signed note: ${ext.reason}`,
        );
      } else if (ext.origin !== logKeys.origin) {
        checks.fail(
          'log.external',
          'UNVERIFIABLE',
          'external.other-log',
          `the external checkpoint is for the log ${quoteFull(ext.origin)}, not ${quoteFull(logKeys.origin)}`,
        );
      } else {
        const j = await judgeCheckpoint(ext, logKeys, backend);
        if (j.result === 'UNAVAILABLE') {
          checks.skip('log.external', j.detail);
        } else if (j.result !== 'PASS') {
          const why = {
            NO_TRUSTED_LINE: 'no trusted log key signed it',
            BAD_SIGNATURE: j.detail,
            BEYOND: j.detail,
          }[j.result];
          checks.fail(
            'log.external',
            'UNVERIFIABLE',
            'external.unsigned',
            `the external checkpoint does not pass the tests the receipt's own checkpoint passed: ${why}`,
          );
        } else if (ext.size !== note.size) {
          checks.skip(
            'log.external',
            `the external checkpoint is for a tree of ${ext.size}, the receipt's for ${note.size}: v0 has no consistency proofs, so the two cannot be related`,
          );
        } else if (!bytesEqual(ext.root, note.root)) {
          checks.fail(
            'log.external',
            'INVALID',
            'external.equivocation',
            `the log key signed two different roots for the tree size ${note.size}: equivocation, and nothing that log attests can be relied on (keep both notes as evidence)`,
          );
        } else {
          checks.pass(
            'log.external',
            `a separately supplied checkpoint of size ${note.size} has the same root (this does not exclude a split view)`,
          );
        }
      }
    }
  }

  // issuer.key-status
  if (!ctx.signatureVerified) {
    checks.skip('issuer.key-status', 'not run: the signature was not verified');
  } else if (ctx.keyInfo.source !== 'KEY_DOCUMENT') {
    checks.skip(
      'issuer.key-status',
      ctx.keyInfo.source === 'SUPPLIED'
        ? 'key status NOT PROVEN: a supplied key carries no status (it may since have been revoked)'
        : 'key status NOT PROVEN: the key came from inside the receipt',
    );
  } else {
    const s = evaluateKeyStatus(ctx.keyInfo.entry, ctx.keyInfo.document, payload, ctx.logged);
    result.keyStatusAsOf = ctx.keyInfo.document.generatedAt;
    ctx.keyStatusNote = s.note || null;
    if (s.outcome === 'PASS') checks.pass('issuer.key-status', s.detail);
    else if (s.outcome === 'SKIP') checks.skip('issuer.key-status', s.detail);
    else checks.fail('issuer.key-status', s.effect, s.rule, s.detail);
  }

  // payload.consistency, assertion.admissible, time.future, freshness
  const consistency = consistencyProblem(payload);
  if (consistency) checks.fail('payload.consistency', 'INVALID', consistency[0], consistency[1]);
  else
    checks.pass(
      'payload.consistency',
      'observedAt <= issuedAt, and freshUntil is after observedAt by at most 400 days',
    );

  const admissible = assertionProblem(payload);
  if (admissible) checks.fail('assertion.admissible', 'INVALID', admissible[0], admissible[1]);
  else
    checks.pass(
      'assertion.admissible',
      `the ${payload.claim.assertion.kind} assertion is admissible for its counts (spec section 5.3)`,
    );

  const issuedAt = parseTimestamp(payload.issuedAt);
  if (issuedAt > t.nowMs + FUTURE_ALLOWANCE_MS) {
    checks.fail(
      'time.future',
      'UNVERIFIABLE',
      null,
      `issued at ${payload.issuedAt}, more than 300 s after the verifier's time ${t.now}: the clocks disagree`,
    );
  } else {
    checks.pass(
      'time.future',
      `issued at ${payload.issuedAt}, not after the verifier's time ${t.now} plus 300 s`,
    );
  }

  if (t.nowMs > parseTimestamp(payload.freshUntil)) {
    checks.fail('freshness', 'STALE', null, `STALE: the claim expired at ${payload.freshUntil}`);
  } else {
    checks.pass('freshness', `fresh until ${payload.freshUntil}`);
  }

  return finish(result, checks, payload, t, ctx);
}

function finish(result, checks, payload, t, ctx) {
  const list = checks.list();
  result.checks = list;
  const invalid = list.find((c) => c.outcome === 'FAIL' && c.effect === 'INVALID');
  const unverifiable = list.find((c) => c.outcome === 'FAIL' && c.effect === 'UNVERIFIABLE');
  const stale = list.find((c) => c.name === 'freshness' && c.outcome === 'FAIL');
  const decisive = invalid || unverifiable || stale || null;
  result.verdict = invalid
    ? 'INVALID'
    : unverifiable
      ? 'UNVERIFIABLE'
      : stale
        ? 'STALE_VALID'
        : 'VALID';
  result.failedCheck = decisive ? decisive.name : null;
  result.rule = decisive && decisive.rule ? decisive.rule : null;

  if (result.verdict === 'VALID' || result.verdict === 'STALE_VALID') {
    const { proves, doesNotProve, logged } = provesOf(
      result.verdict,
      payload,
      result.keySource,
      checks,
    );
    result.proves = proves;
    result.doesNotProve = doesNotProve;
    result.reading = readingOf(payload);
    result.payload = payload;
    result.summary = validSummary(result, payload, checks, ctx, logged, t);
  } else {
    const failed = checks.get(result.failedCheck);
    let s = `${result.verdict} - ${result.failedCheck}${result.rule ? ` (${result.rule})` : ''}: ${failed.detail}`;
    if (result.verdict === 'INVALID' && !ctx.signatureVerified)
      s += '. NOT ATTRIBUTABLE to the named issuer: no signature was verified';
    result.summary = asciiEscape(s);
  }
  return result;
}

function validSummary(result, payload, checks, ctx, logged, t) {
  const { deployment, tenantRef, keyId } = payload.issuer;
  const parts = [readingText(result.reading)];
  parts.push(`issued by tenantRef ${tenantRef} at ${deployment}`);
  if (result.keySource === 'KEY_DOCUMENT') {
    const status =
      checks.outcome('issuer.key-status') === 'PASS'
        ? `key status as of ${result.keyStatusAsOf}`
        : `KEY STATUS NOT PROVEN (the key document is from ${result.keyStatusAsOf}, before the receipt)`;
    parts.push(`key ${keyId} from the key document at ${result.keyDocumentUrl}, ${status}`);
    // Loopback included (spec section 9.4): whatever came from an http origin travelled in clear.
    if (result.plainHttp) parts.push('KEY DOCUMENT FROM A PLAIN-HTTP DEPLOYMENT');
  } else {
    parts.push(`key ${keyId} supplied by you, KEY STATUS NOT PROVEN`);
  }
  if (ctx.keyStatusNote) parts.push(ctx.keyStatusNote);
  if (logged) {
    const external =
      checks.outcome('log.external') === 'PASS'
        ? ', and a separately supplied checkpoint agrees'
        : '';
    parts.push(`LOGGED at index ${ctx.logged.index} of ${ctx.logged.treeSize}${external}`);
  } else {
    parts.push('NOT LOGGED');
  }
  if (result.verdict === 'VALID')
    parts.push(`fresh until ${payload.freshUntil} (verified at ${t.now})`);
  const head =
    result.verdict === 'STALE_VALID'
      ? `STALE - expired ${payload.freshUntil}; the signature is valid - `
      : 'VALID - ';
  return asciiEscape(head + parts.join('; '));
}

/**
 * What a caller needs to FETCH trust inputs for a receipt (the CLI's --fetch,
 * P5's one-click fetch): the issuing deployment, the key document URL, the
 * receipt digest and the log section's tree size. Every one of these is
 * UNVERIFIED (read before any signature check): route requests by them, never
 * display them as verified. `ok` is false when the six structural checks fail.
 */
export async function inspectReceiptWith(receipt, backend) {
  assertBackend(backend);
  const s = readStructure(receipt, new CheckLog());
  if (!s.ok) return { ok: false };
  const { deployment, tenantRef, keyId } = s.payload.issuer;
  const digest = backend.hashes
    ? toHex(await backend.sha256(concatBytes(RECEIPT_DIGEST_TAG, s.payloadBytes)))
    : null;
  return {
    ok: true,
    deployment,
    tenantRef,
    keyId,
    keyDocumentUrl: keyDocumentUrlOf(deployment, tenantRef),
    digest,
    logTreeSize: hasOwn(s.envelope, 'log') ? s.envelope.log.treeSize : null,
    envelope: s.envelope,
  };
}

/**
 * The receipt's decoded payload for the evidence checks: the six structural
 * checks must pass (spec section 8.2: "decode to a v0 payload").
 */
function decodeForEvidence(receipt) {
  const checks = new CheckLog();
  const s = readStructure(receipt, checks);
  if (s.ok) return { payload: s.payload };
  const failed = checks.list().find((c) => c.outcome === 'FAIL');
  return {
    problem: `the receipt's payload does not decode to a v0 payload (${failed.name}: ${failed.detail})`,
  };
}

/**
 * The receipt's decoded payload for a companion check (lib/collector.mjs):
 * the same rule as the evidence checks, the six structural checks must pass.
 */
export function decodeReceiptPayload(receipt) {
  return decodeForEvidence(receipt);
}

function readEvidenceDocument(input, limit, schemaProblems, what) {
  let doc;
  try {
    doc = readSuppliedDocument(input, limit);
  } catch (e) {
    if (!(e instanceof StrictJsonError)) throw e;
    return { problem: `the ${what} is not acceptable JSON (${e.rule}): ${e.message}` };
  }
  const problems = schemaProblems(doc);
  if (problems.length > 0)
    return { problem: `the ${what} fails its schema: ${firstProblem(problems)}` };
  return { doc };
}

function headerProblem(manifest, payload) {
  const i = payload.issuer;
  if (manifest.receiptId !== payload.receiptId)
    return `the committed header names the receipt ${quoteFull(manifest.receiptId)}, not ${quoteFull(payload.receiptId)}`;
  if (
    manifest.issuer.deployment !== i.deployment ||
    manifest.issuer.tenantRef !== i.tenantRef ||
    manifest.issuer.keyId !== i.keyId
  ) {
    return "the committed header names another issuer than the payload's";
  }
  if (manifest.claimId !== payload.claim.claimId)
    return `the committed header names the claim ${quoteFull(manifest.claimId)}, not ${quoteFull(payload.claim.claimId)}`;
  if (manifest.observedAt !== payload.observedAt)
    return `the committed header says observedAt ${quoteFull(manifest.observedAt)}, not ${quoteFull(payload.observedAt)}`;
  if (payload.measurement !== undefined) {
    if (manifest.counts === undefined)
      return 'the committed header is a self-attestation, and the receipt is measured';
    const m = payload.measurement;
    const c = manifest.counts;
    if (c.numerator !== m.numerator || c.denominator !== m.denominator || c.unknown !== m.unknown)
      return "the committed counts are not the receipt's";
    if (manifest.method.id !== m.method.id || manifest.method.version !== m.method.version)
      return "the committed method is not the receipt's";
  } else {
    if (manifest.selfAttested === undefined)
      return 'the committed header is a measurement, and the receipt is self-attested';
    if (
      manifest.selfAttested.byRole !== payload.selfAttested.byRole ||
      manifest.selfAttested.at !== payload.selfAttested.at
    ) {
      return "the committed attestation role or time is not the receipt's";
    }
  }
  return null;
}

async function openingInner(receipt, opening, backend) {
  const decoded = decodeForEvidence(receipt);
  if (decoded.problem)
    return { match: false, rule: 'opening.receipt-undecodable', detail: decoded.problem };
  const payload = decoded.payload;
  const read = readEvidenceDocument(opening, JSON_LIMITS.opening, openingProblems, 'opening');
  if (read.problem) return { match: false, rule: 'opening.malformed', detail: read.problem };
  const o = read.doc;
  if (o.receiptId !== payload.receiptId) {
    return {
      match: false,
      rule: 'opening.receipt',
      detail: `the opening names the receipt ${quoteFull(o.receiptId)}, not ${quoteFull(payload.receiptId)}`,
    };
  }
  let manifestText;
  try {
    manifestText = canonicalize(o.manifest);
  } catch (e) {
    // Unreachable for a schema-valid manifest (every member is typed); kept so that nothing else can pass.
    if (!(e instanceof CanonicalError)) throw e;
    return {
      match: false,
      rule: 'opening.malformed',
      detail: `the manifest has no canonical form (${e.rule})`,
    };
  }
  const commitment = toHex(
    await backend.sha256(concatBytes(EVIDENCE_TAG, fromHex(o.salt), utf8(manifestText))),
  );
  if (commitment !== payload.evidence.commitment) {
    return {
      match: false,
      rule: 'opening.commitment',
      detail: "the salt and manifest do not hash to the receipt's evidence commitment",
    };
  }
  const header = headerProblem(o.manifest, payload);
  if (header)
    return { match: false, rule: 'opening.header', detail: `the commitment opens, but ${header}` };
  return {
    match: true,
    rule: null,
    detail: `the salt and manifest open the commitment, and the manifest header describes this receipt (${o.manifest.itemCount} committed item(s))`,
    payload,
    manifest: o.manifest,
  };
}

const EVIDENCE_NO_WEBCRYPTO = {
  match: false,
  rule: null,
  detail:
    'not checked: this runtime has no WebCrypto (crypto.subtle is missing); use the CLI (cmdash-verify) or serve this page over HTTPS',
};

/**
 * Checks an evidence opening against a receipt (spec section 8.2). Separate
 * from the receipt's verdict: MATCH ({ match: true }) or MISMATCH with the
 * first rule that fails. `rule` is null with match false only when this
 * runtime cannot hash at all.
 */
export async function verifyEvidenceOpeningWith(receipt, opening, backend) {
  assertBackend(backend);
  if (!backend.hashes) return { ...EVIDENCE_NO_WEBCRYPTO };
  const r = await openingInner(receipt, opening, backend);
  return { match: r.match, rule: r.rule, detail: asciiEscape(r.detail) };
}

/** Checks one sampled evidence item (spec section 8.3) against a receipt and the opening it relies on. */
export async function verifyEvidenceItemWith(receipt, opening, item, backend) {
  assertBackend(backend);
  if (!backend.hashes) return { ...EVIDENCE_NO_WEBCRYPTO };
  const o = await openingInner(receipt, opening, backend);
  const done = (match, rule, detail) => ({ match, rule, detail: asciiEscape(detail) });
  if (!o.match)
    return done(
      false,
      'item.opening',
      `the opening it relies on does not match (${o.rule}: ${o.detail})`,
    );
  const { payload, manifest } = o;
  const read = readEvidenceDocument(item, JSON_LIMITS.item, itemProblems, 'item disclosure');
  if (read.problem) return done(false, 'item.malformed', read.problem);
  const it = read.doc;
  if (it.receiptId !== payload.receiptId)
    return done(
      false,
      'item.receipt',
      `the item names the receipt ${quoteFull(it.receiptId)}, not ${quoteFull(payload.receiptId)}`,
    );
  if (it.itemCount !== manifest.itemCount)
    return done(
      false,
      'item.count',
      `the item says ${it.itemCount} items; the manifest commits to ${manifest.itemCount}`,
    );
  if (it.index >= it.itemCount)
    return done(false, 'item.count', `index ${it.index} is outside ${it.itemCount} items`);
  let itemText;
  try {
    itemText = canonicalize(it.item);
  } catch (e) {
    // Every committed item is one canonical JSON object (spec section 8.1): a null, a boolean or a float
    // inside it makes the disclosure malformed, not merely absent from the tree.
    if (!(e instanceof CanonicalError)) throw e;
    return done(
      false,
      'item.malformed',
      `the item has no canonical form (${e.rule}), so it cannot be a committed item`,
    );
  }
  const entry = concatBytes(EVIDENCE_ITEM_TAG, fromHex(it.salt), utf8(itemText));
  const leaf = await merkleLeafHash(entry, backend);
  const included = await verifyInclusion(
    it.index,
    it.itemCount,
    leaf,
    it.proof.map((h) => fromHex(h)),
    fromHex(manifest.itemsRoot),
    backend,
  );
  if (!included)
    return done(
      false,
      'item.inclusion',
      `the item is not at index ${it.index} under the manifest's itemsRoot`,
    );
  if (payload.claim.assertion.kind === 'SELF_ATTESTED' && it.index === 0) {
    const problems = attestationItemProblems(it.item);
    if (problems.length > 0)
      return done(
        false,
        'item.attestation',
        `item 0 of a self-attested receipt must be exactly { statement, userId }: ${firstProblem(problems)}`,
      );
    if (it.item.statement !== payload.claim.statement) {
      return done(
        false,
        'item.attestation',
        "item 0's statement is not the receipt's claim.statement: the issuer committed to an attestation other than the one the receipt signs",
      );
    }
  }
  return done(true, null, `item ${it.index} of ${it.itemCount} is under the committed itemsRoot`);
}
