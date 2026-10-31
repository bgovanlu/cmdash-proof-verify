// SPDX-License-Identifier: Apache-2.0
// Licence per owner decision ⚑4 (the receipt spec and its verifier).
/**
 * CMDash Proof Receipt v0: the reference checker.
 *
 * The normative text is docs/specs/proof-receipt-v0.md. Where this file and
 * the spec disagree, the spec wins and this file has a bug. checker.test.mjs
 * pins the two together: it reads the check list, the statement ids and every
 * rule list out of the spec and fails when the names or their order differ.
 *
 * Node built-ins only (`node:crypto`). That is the rule
 * scripts/audit-chain-verify.mjs states in its header: if verifying needed
 * anything from the issuer's code base, "verified" would mean "the issuer
 * agrees with itself". Plan item P4 (the proof-verify package) re-implements
 * this file independently; the vectors in ./vectors are the contract between
 * the two, and P2 (issuance) must produce byte-identical payloads for them.
 *
 * Exports:
 *   verifyReceipt(receipt, trust)                     the verdict, every check, proves/doesNotProve
 *   verifyEvidenceOpening(receipt, opening)           does a disclosed opening match the commitment?
 *   verifyEvidenceItem(receipt, opening, disclosure)  is a sampled item inside the opened manifest?
 *   canonicalize(value)                               the v0 canonical form (throws CanonicalError)
 *   parseJsonStrict(text)                             RFC 8259 JSON that refuses duplicate member names
 *   pointProblem(bytes32)                             Ed25519 point validation (spec §2.1.1)
 *   checkEnvelopeShape / checkPayloadSchema / checkKeyDocument / checkLogKeyDocument /
 *   checkLogSection / checkEvidenceOpening / checkEvidenceItem /
 *   checkAttestationItem                              hand-written twins of receipt.schema.json
 *   printable(s)                                      the output rule of spec §9.5
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

// ─── constants (spec §2, §3, §6, §7, §8) ─────────────────────────────────────

export const RECEIPT_DOMAIN = 'cmdash-receipt-v0';
export const DIGEST_DOMAIN = 'cmdash-receipt-digest-v0';
export const EVIDENCE_DOMAIN = 'cmdash-receipt-evidence-v0';
export const EVIDENCE_ITEM_DOMAIN = 'cmdash-receipt-evidence-item-v0';
/** Spec §7.1.1: the registered log entry types. Every leaf entry is a 32-byte digest under one of these tags. */
export const LOG_ENTRY_TYPES = ['cmdash-receipt-digest-v0', 'cmdash-signer-file-digest-v0'];
export const ISSUER_KID_PREFIX = 'cmdash-proof-';
export const LOG_KID_PREFIX = 'cmdash-proof-log-';
export const KEY_DOCUMENT_PATH = '/api/.well-known/cmdash-proof-keys/';
export const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
export const MAX_RECEIPT_BYTES = 65536;
export const MAX_PAYLOAD_BYTES = 16384;
export const MAX_PAYLOAD_B64 = 21846; // ceil(16384 * 4 / 3)
export const MAX_KEY_DOCUMENT_BYTES = 1048576;
export const MAX_OPENING_BYTES = 65536;
export const MAX_LOG_SECTION_BYTES = 65536;
export const MAX_CHECKPOINT_CHARS = 8192;
export const MAX_ISSUER_KEYS = 1024;
export const MAX_LOG_KEYS = 64;
export const MAX_DEPTH = 64;
export const COUNT_MAX = 1_000_000_000;
export const THRESHOLD_MAX = 1_000_000;
export const SCORE_LIMIT = 1_000_000_000;
export const METHOD_VERSION_MAX = 1_000_000;
export const MAX_FRESH_WINDOW_MS = 400 * 86_400_000;
export const FUTURE_ALLOWANCE_MS = 300_000;

// Ed25519 field and group constants (RFC 8032 §5.1).
const P = (1n << 255n) - 19n;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

/** Spec §9.2: the ordered checks. P4's `checks[].name` values, in this order. */
export const CHECK_NAMES = [
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
];
const STRUCTURAL = CHECK_NAMES.slice(0, 6);

/** Spec §10: what a VALID or STALE_VALID receipt proves, in output order. */
export const PROVES_IDS = [
  'signed-by-key',
  'issuer-key-published',
  'unaltered',
  'observed-at',
  'measurement-stated',
  'attestation-stated',
  'logged',
  'log-consistent-with-external',
  'fresh',
];

/** Spec §10: what it does not prove, in output order. */
export const DOES_NOT_PROVE_IDS = [
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
];

/** Spec §3.4: json.* rules of envelope.json (and of every other document the verifier parses). */
export const JSON_RULES = ['json.too-large', 'json.syntax', 'json.duplicate-member'];

/** Spec §5.3: the admissibility rules, in evaluation order. */
export const ASSERTION_RULES = [
  'measurement.parts-within-denominator',
  'ALL.denominator-positive',
  'ALL.no-unknown',
  'ALL.complete',
  'AT_LEAST.threshold-below-one',
  'AT_LEAST.denominator-positive',
  'AT_LEAST.threshold-met',
  'SCORE.range-ordered',
  'SCORE.in-range',
  'SCORE.denominator-positive',
  'SCORE.all-unknown-is-min',
  'SCORE.none-met-is-min',
  'SCORE.max-requires-complete',
];

/** Spec §5.4: the payload consistency rules, in evaluation order. */
export const CONSISTENCY_RULES = [
  'time.observed-before-issued',
  'time.fresh-after-observed',
  'time.window-max-400d',
  'self-attested.at-equals-observedAt',
  'supersedes.not-self',
];

/** Spec §6.6: the issuer.key rules, in evaluation order. */
export const ISSUER_KEY_RULES = [
  'key.deployment-untrusted',
  'key.deployment-plain-http',
  'key.document-malformed',
  'key.document-url',
  'key.document-deployment',
  'key.document-tenant',
  'key.not-in-document',
  'key.supplied-none',
  'key.supplied-deployment',
  'key.supplied-tenant',
  'key.embedded-mismatch',
  'key.embedded-only',
  'key.no-key',
];

/**
 * Spec §2.1.1: the signature.verify rules, in evaluation order. The allow markers silence gitleaks'
 * generic-api-key rule, which reads `key-...',` followed by a quoted rule name as an assignment.
 */
export const SIGNATURE_RULES = [
  'ed25519.key-noncanonical', // gitleaks:allow
  'ed25519.key-off-curve', // gitleaks:allow
  'ed25519.key-small-order', // gitleaks:allow
  'ed25519.r-noncanonical',
  'ed25519.r-off-curve',
  'ed25519.r-small-order',
  'ed25519.s-not-reduced',
  'ed25519.mismatch',
  'ed25519.unavailable',
];

/** Spec §7.7: the rules of the three log checks, and the require-logged policy. */
export const LOG_RULES = [
  'log.section-malformed',
  'log.checkpoint-malformed',
  'log.size-mismatch',
  'log.root-mismatch',
  'log.index-outside',
  'log.proof',
  'log-keys.malformed',
  'checkpoint.signature',
  'log-key.beyond-last-tree-size',
  'external.malformed',
  'external.other-log',
  'external.unsigned',
  'external.equivocation',
  'policy.require-logged',
];

/** Spec §6.5: the key-status rules, in evaluation order. */
export const KEY_STATUS_RULES = ['key.revoked', 'key.not-yet-valid', 'key.disowned', 'key.retired', 'key.retired-unproven'];

/** Spec §8.3: evidence opening and item rules. */
export const OPENING_RULES = ['opening.receipt-undecodable', 'opening.malformed', 'opening.receipt', 'opening.commitment', 'opening.header'];
export const ITEM_RULES = ['item.opening', 'item.malformed', 'item.receipt', 'item.count', 'item.inclusion', 'item.attestation'];

// ─── patterns: identical strings live in receipt.schema.json (the test compares) ─

// Human text (spec §5.5): no C0/C1 controls, no bidi or line separators, and none of
// the default-ignorable code points (zero-width, fillers, tags, variation selectors),
// nor private use. Listed explicitly, never through \p{...}, so that every
// implementation refuses the same set whatever Unicode version it ships.
const TEXT_REFUSED =
  '\\u{0}-\\u{1F}\\u{7F}-\\u{9F}\\u{AD}\\u{34F}\\u{61C}\\u{115F}\\u{1160}\\u{17B4}\\u{17B5}' +
  '\\u{180B}-\\u{180F}\\u{200B}-\\u{200F}\\u{2028}-\\u{202E}\\u{2060}-\\u{206F}\\u{3164}' +
  '\\u{E000}-\\u{F8FF}\\u{FE00}-\\u{FE0F}\\u{FEFF}\\u{FFA0}\\u{FFF0}-\\u{FFFB}\\u{1BCA0}-\\u{1BCA3}' +
  '\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E0FFF}\\u{F0000}-\\u{10FFFF}';

// The canonical origin grammar (spec §6.2). One spelling per origin: lowercase LDH labels, no empty
// label, no trailing dot, no label that starts or ends with a hyphen, a last label that starts with a
// letter (an all-numeric host must be a canonical IPv4 address, whose octets have no leading zeros),
// 253 characters at most, and a port of 1..65535 without leading zeros that is never the scheme's
// default. `deployment` admits https, and http on a loopback host (development); plain http on any
// other host is `plainHttpDeployment`, accepted only when the relying party explicitly allows it.
const ORIGIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const ORIGIN_TOP_LABEL = '[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?';
const ORIGIN_OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const ORIGIN_HOST = `(?=[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$)(?:(?:${ORIGIN_LABEL}\\.)*${ORIGIN_TOP_LABEL}|(?:${ORIGIN_OCTET}\\.){3}${ORIGIN_OCTET})`;
const ORIGIN_PORT = '(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])';

export const PATTERNS = {
  ulid: '^[0-7][0-9A-HJKMNP-TV-Z]{25}$',
  tenantRef: '^tr_[0-9a-f]{32}$',
  deployment: `^(?:https://${ORIGIN_HOST}(?::(?!443$)${ORIGIN_PORT})?|http://(?:localhost|127\\.0\\.0\\.1)(?::(?!80$)${ORIGIN_PORT})?)$`,
  plainHttpDeployment: `^http://${ORIGIN_HOST}(?::(?!80$)${ORIGIN_PORT})?$`,
  userId: '^[!-~]{1,128}$',
  issuerKid: '^cmdash-proof-[0-9a-f]{16}$',
  logKid: '^cmdash-proof-log-[0-9a-f]{16}$',
  hex32: '^[0-9a-f]{64}$',
  timestamp:
    '^(19[7-9][0-9]|[2-9][0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}Z$',
  claimId: '^[a-z0-9][a-z0-9._-]{0,127}$',
  framework: '^[a-z0-9][a-z0-9.-]{0,63}$',
  controlId: '^[!-~]{1,64}$',
  sourceRef: '^[a-z0-9][a-z0-9._-]{0,63}$',
  methodId: '^[a-z0-9][a-z0-9._-]{0,127}$',
  unit: '^[a-z][a-z0-9-]{0,31}$',
  role: '^[A-Z][A-Z0-9_]{0,31}$',
  text: `^[^${TEXT_REFUSED}]+$`,
  spki: '^MCowBQYDK2VwAyEA[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$',
  signature: '^[A-Za-z0-9_-]{85}[AQgw]$',
  payload:
    '^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$',
  origin: '^[!-*,-~]{1,255}$',
};
const RX = Object.fromEntries(Object.entries(PATTERNS).map(([k, v]) => [k, new RegExp(v, 'u')]));

// ─── small helpers ───────────────────────────────────────────────────────────

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const has = (o, k) => Object.hasOwn(o, k);
const cpLength = (s) => [...s].length; // JSON Schema lengths count code points
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const intIn = (v, lo, hi) => isInt(v) && v >= lo && v <= hi;
const ms = (ts) => Date.parse(ts);

/** A timestamp in the one v0 format (spec §4): shape AND a real calendar instant. */
export function isTimestamp(s) {
  if (typeof s !== 'string' || !RX.timestamp.test(s)) return false;
  const t = Date.parse(s);
  // V8 rolls 2026-02-30 over to March 2 instead of rejecting it; the round
  // trip is what makes "a real calendar date" a checkable rule.
  return Number.isFinite(t) && new Date(t).toISOString() === s;
}

// ─── output safety (spec §9.5) ───────────────────────────────────────────────

/**
 * Every code point outside U+0020..U+007E becomes `\u{hex}`. Applied to every
 * `detail` and to the summary, so no receipt, key document or checkpoint can
 * put an ANSI escape, a bidi override or a line break into a verifier's output.
 */
export function printable(s) {
  return String(s).replace(/[^\u{20}-\u{7E}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);
}

/**
 * An unverified value for a detail string: at most 64 code points, its backslashes and double quotes
 * escaped (so it can never close its own quotes and pose as the verifier's words), quoted, then made
 * printable.
 */
function q(v) {
  let s;
  try {
    s = typeof v === 'string' ? v : String(JSON.stringify(v));
  } catch {
    s = '(unprintable)';
  }
  const cps = [...s];
  const cut = cps.length > 64 ? `${cps.slice(0, 64).join('')}...` : s;
  return `"${printable(cut.replace(/\\/g, '\\\\').replace(/"/g, '\\"'))}"`;
}

// ─── strict JSON (spec §3.4) ─────────────────────────────────────────────────

export class JsonInputError extends Error {
  constructor(rule, message) {
    super(message);
    this.rule = rule;
  }
}

/**
 * RFC 8259 JSON, producing exactly what JSON.parse produces, except that a
 * duplicate member name anywhere is an error instead of "last one wins". One
 * receipt file must never be read as two different receipts by two parsers.
 */
export function parseJsonStrict(text, maxDepth = MAX_DEPTH) {
  if (typeof text !== 'string') throw new JsonInputError('json.syntax', 'not text');
  const n = text.length;
  let i = 0;
  const fail = (msg) => {
    throw new JsonInputError('json.syntax', `${msg} at offset ${i}`);
  };
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i += 1;
      else break;
    }
  };
  const string = () => {
    const start = i;
    i += 1;
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i += 1;
        break;
      }
      if (c < 0x20) fail('control character in a string');
      if (c === 0x5c) {
        const e = text[i + 1];
        if (e === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) fail('bad unicode escape');
          i += 6;
        } else if (e !== undefined && '"\\/bfnrt'.includes(e)) i += 2;
        else fail('bad escape');
      } else i += 1;
    }
    return JSON.parse(text.slice(start, i));
  };
  const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const number = () => {
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) fail('bad number');
    i += m[0].length;
    return Number(m[0]);
  };
  const value = (depth) => {
    if (depth > maxDepth) fail('nested too deeply');
    ws();
    const c = text[i];
    if (c === '{') {
      i += 1;
      const out = {};
      const seen = new Set();
      ws();
      if (text[i] === '}') {
        i += 1;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected a member name');
        const key = string();
        if (seen.has(key)) throw new JsonInputError('json.duplicate-member', `duplicate member name ${q(key)}`);
        seen.add(key);
        ws();
        if (text[i] !== ':') fail('expected ":"');
        i += 1;
        // defineProperty, as JSON.parse does: "__proto__" becomes an own member.
        Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') i += 1;
        else if (text[i] === '}') {
          i += 1;
          return out;
        } else fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i += 1;
      const out = [];
      ws();
      if (text[i] === ']') {
        i += 1;
        return out;
      }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ',') i += 1;
        else if (text[i] === ']') {
          i += 1;
          return out;
        } else fail('expected "," or "]"');
      }
    }
    if (c === '"') return string();
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    for (const [word, v] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    return fail('unexpected character');
  };
  const v = value(0);
  ws();
  if (i !== n) fail('trailing characters');
  return v;
}

/** A document handed to the verifier as text (parsed strictly) or as an already-parsed value. */
function readDocument(input, maxBytes) {
  let text = input;
  if (input instanceof Uint8Array) {
    // A file's bytes (spec §3.4): fatal UTF-8, and a byte-order mark is kept, so the parser refuses it.
    if (input.length > maxBytes) return { ok: false, rule: 'json.too-large', detail: `larger than ${maxBytes} bytes` };
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      return { ok: false, rule: 'json.syntax', detail: 'not UTF-8' };
    }
  } else if (typeof input !== 'string') {
    try {
      text = JSON.stringify(input);
    } catch {
      text = undefined;
    }
  }
  if (typeof text !== 'string') return { ok: false, rule: 'json.syntax', detail: 'not a JSON document' };
  if (Buffer.byteLength(text, 'utf8') > maxBytes) return { ok: false, rule: 'json.too-large', detail: `larger than ${maxBytes} bytes` };
  try {
    return { ok: true, value: parseJsonStrict(text) };
  } catch (err) {
    if (!(err instanceof JsonInputError)) throw err;
    return { ok: false, rule: err.rule, detail: err.message };
  }
}

// ─── canonical form (spec §3) ────────────────────────────────────────────────

export class CanonicalError extends Error {
  constructor(rule, message) {
    super(message);
    this.rule = rule;
  }
}

const isNoncharacter = (cp) => (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe;

function assertCleanString(s) {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) {
        throw new CanonicalError('canonical.lone-surrogate', `lone high surrogate at UTF-16 index ${i}`);
      }
      const cp = ((c - 0xd800) << 10) + (d - 0xdc00) + 0x10000;
      if (isNoncharacter(cp)) throw new CanonicalError('canonical.noncharacter', `noncharacter U+${cp.toString(16)}`);
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonicalError('canonical.lone-surrogate', `lone low surrogate at UTF-16 index ${i}`);
    } else if (isNoncharacter(c)) {
      throw new CanonicalError('canonical.noncharacter', `noncharacter U+${c.toString(16)}`);
    }
  }
}

/**
 * The v0 canonical form of a JSON value (spec §3). Admits plain objects,
 * arrays, strings and safe integers only: a Date, a Buffer, a Map or any other
 * class instance is refused rather than silently serialized as `{}`.
 */
export function canonicalize(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new CanonicalError('canonical.depth', `nested deeper than ${MAX_DEPTH}`);
  if (value === null) throw new CanonicalError('canonical.null', 'null is not admitted in v0');
  switch (typeof value) {
    case 'string':
      assertCleanString(value);
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalError('canonical.non-finite', `${value}`);
      if (!Number.isInteger(value)) throw new CanonicalError('canonical.float', `${value}`);
      if (!Number.isSafeInteger(value)) throw new CanonicalError('canonical.unsafe-integer', `${value}`);
      if (Object.is(value, -0)) throw new CanonicalError('canonical.negative-zero', '-0');
      return String(value);
    case 'boolean':
      throw new CanonicalError('canonical.boolean', 'booleans are not admitted in v0');
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v, depth + 1)).join(',')}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalError('canonical.type', 'only plain objects are admitted (no Date, Buffer, Map or class instance)');
      }
      // Array#sort with no comparator compares UTF-16 code units: RFC 8785 §3.2.3.
      const keys = Object.keys(value).sort();
      for (const k of keys) assertCleanString(k);
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k], depth + 1)}`).join(',')}}`;
    }
    default:
      throw new CanonicalError('canonical.type', `${typeof value} is not a JSON value`);
  }
}

// ─── digests, keys, Merkle (spec §2.2, §6, §7, §8) ───────────────────────────

/** SHA-256("cmdash-receipt-digest-v0\n" || payloadBytes), lowercase hex. Names the payload, not the file. */
export function receiptDigest(payloadBytes) {
  return sha256(Buffer.from(`${DIGEST_DOMAIN}\n`, 'utf8'), payloadBytes).toString('hex');
}

/** RFC 9162 §2.1.1: leaf hash = SHA-256(0x00 || entry). */
export const leafHash = (entry) => sha256(Buffer.from([0x00]), entry);
/** RFC 9162 §2.1.1: node hash = SHA-256(0x01 || left || right). */
export const nodeHash = (left, right) => sha256(Buffer.from([0x01]), left, right);

/** `prefix` + first 16 hex of SHA-256 over the DER SPKI (spec §6.1). */
export function deriveKid(spkiB64url, prefix = ISSUER_KID_PREFIX) {
  return `${prefix}${sha256(Buffer.from(spkiB64url, 'base64url')).toString('hex').slice(0, 16)}`;
}

/** The only URL a key document may be supplied from (spec §6.3). */
export const keyDocumentUrlFor = (issuer) => `${issuer.deployment}${KEY_DOCUMENT_PATH}${issuer.tenantRef}.json`;

function importSpki(spkiB64url) {
  const der = Buffer.from(spkiB64url, 'base64url');
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) return null;
  try {
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

// Ed25519 point validation in plain BigInt: the same ~20 lines run in browsers.
const modp = (x) => ((x % P) + P) % P;
function powp(b, e) {
  let r = 1n;
  let x = modp(b);
  let k = e;
  while (k > 0n) {
    if (k & 1n) r = (r * x) % P;
    x = (x * x) % P;
    k >>= 1n;
  }
  return r;
}
const D = modp(-121665n * powp(121666n, P - 2n));
/** The 8 canonical encodings of the points of small order (the 8-torsion subgroup), lowercase hex. */
export const SMALL_ORDER_ENCODINGS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];
const SMALL_ORDER = new Set(SMALL_ORDER_ENCODINGS);

/**
 * Spec §2.1.1. null for a canonical, on-curve point that is not of small
 * order; otherwise 'noncanonical', 'off-curve' or 'small-order'.
 */
export function pointProblem(bytes) {
  if (!bytes || bytes.length !== 32) return 'noncanonical';
  const sign = bytes[31] >> 7;
  let y = 0n;
  for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  if (y >= P) return 'noncanonical';
  const y2 = (y * y) % P;
  const x2 = (modp(y2 - 1n) * powp(modp(D * y2 + 1n), P - 2n)) % P; // d*y^2 + 1 is never 0 on this curve
  if (x2 === 0n) {
    if (sign === 1) return 'noncanonical'; // x = 0 has no negative encoding (RFC 8032 §5.1.3 step 4)
  } else if (powp(x2, (P - 1n) / 2n) !== 1n) return 'off-curve';
  if (SMALL_ORDER.has(Buffer.from(bytes).toString('hex'))) return 'small-order';
  return null;
}

/** RFC 8032 §5.1.7 step 1: S (the last 32 bytes, little-endian) must be < L. */
function scalarReduced(sig) {
  let s = 0n;
  for (let i = 63; i >= 32; i -= 1) s = (s << 8n) | BigInt(sig[i]);
  return s < ED25519_L;
}

/**
 * Spec §2.1.1: the whole signature check, pre-checks first. Returns null when
 * the signature verifies, else the rule name.
 */
export function ed25519Problem(spkiB64url, message, sig) {
  const a = Buffer.from(spkiB64url, 'base64url').subarray(12);
  const aProblem = pointProblem(a);
  if (aProblem) return `ed25519.key-${aProblem}`;
  if (sig.length !== 64) return 'ed25519.mismatch';
  const rProblem = pointProblem(sig.subarray(0, 32));
  if (rProblem) return `ed25519.r-${rProblem}`;
  if (!scalarReduced(sig)) return 'ed25519.s-not-reduced';
  const pub = importSpki(spkiB64url);
  if (!pub) return 'ed25519.unavailable';
  try {
    return cryptoVerify(null, message, pub, sig) ? null : 'ed25519.mismatch';
  } catch {
    return 'ed25519.mismatch';
  }
}

/**
 * RFC 9162 §2.1.3.2, verbatim. Arithmetic, not bit operators: JS bit
 * operators truncate to 32 bits and tree sizes run to 2^53 - 1.
 */
export function verifyInclusion(index, treeSize, leaf, path, root) {
  if (!(index < treeSize)) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

// ─── signed notes / checkpoints (spec §7.3) ──────────────────────────────────

const B64STD = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const strictBase64 = (s) => {
  if (!B64STD.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  return b.toString('base64') === s ? b : null;
};

/**
 * Parse a C2SP signed note carrying a tlog checkpoint. Stricter than C2SP on
 * purpose (spec §7.3): printable ASCII, line feeds and the em dash only.
 */
export function parseNote(note) {
  if (typeof note !== 'string') return { ok: false, error: 'not a string' };
  if (/[^\u{20}-\u{7E}\n\u{2014}]/u.test(note)) return { ok: false, error: 'a character outside printable ASCII' };
  const split = note.lastIndexOf('\n\n');
  if (split < 0) return { ok: false, error: 'no blank line between text and signatures' };
  const text = note.slice(0, split + 1);
  const sigBlock = note.slice(split + 2);
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 3 || lines.some((l) => l.length === 0)) {
    return { ok: false, error: 'checkpoint body needs origin, size and root hash lines' };
  }
  const [origin, sizeLine, rootLine, ...extensions] = lines;
  if (!RX.origin.test(origin)) return { ok: false, error: 'origin line is not a key name' };
  if (!/^(0|[1-9][0-9]{0,15})$/.test(sizeLine) || !Number.isSafeInteger(Number(sizeLine))) {
    return { ok: false, error: 'tree size is not a decimal integer without leading zeros' };
  }
  const rootHash = strictBase64(rootLine);
  if (!rootHash || rootHash.length !== 32) return { ok: false, error: 'root hash is not base64 of 32 bytes' };
  if (!sigBlock.endsWith('\n') || sigBlock.length < 2) return { ok: false, error: 'no signature lines' };
  const signatures = [];
  for (const line of sigBlock.slice(0, -1).split('\n')) {
    const m = /^\u{2014} ([^\s+]+) ([A-Za-z0-9+/=]+)$/u.exec(line);
    const raw = m ? strictBase64(m[2]) : null;
    if (!m || !raw || raw.length < 5) return { ok: false, error: 'malformed signature line' };
    signatures.push({ name: m[1], keyHash: raw.subarray(0, 4), sig: raw.subarray(4) });
  }
  return { ok: true, text, origin, treeSize: Number(sizeLine), rootHash, extensions, signatures };
}

/** signed-note key hash for Ed25519: SHA-256(name || 0x0A || 0x01 || pub32)[0:4]. */
export function noteKeyHash(name, spkiB64url) {
  const pub = Buffer.from(spkiB64url, 'base64url').subarray(12);
  return sha256(Buffer.from(`${name}\n`, 'utf8'), Buffer.from([0x01]), pub).subarray(0, 4);
}

/**
 * Check a parsed note against a trusted log key set (spec §7.3, §7.4).
 *   PASS    a trusted key's signature verifies, and that key may sign this size (ACTIVE, or RETIRED at or
 *           below its lastTreeSize)
 *   BEYOND  trusted keys' signatures verify, but every one is RETIRED below this size
 *   FAIL    a line claims a trusted key and does not verify (any such line fails the note)
 *   NONE    no line claims a trusted key (unknown keys are ignored; REVOKED keys are not trusted)
 * The outcome does not depend on the order of the signature lines or of the keys.
 */
export function verifyNote(parsed, logKeys) {
  const trusted = logKeys.keys.filter((k) => k.status !== 'REVOKED' && deriveKid(k.publicKey, LOG_KID_PREFIX) === k.kid);
  const mayVouch = (k) => k.status !== 'RETIRED' || parsed.treeSize <= k.lastTreeSize;
  let permitted = null;
  let beyond = null;
  let failed = false;
  for (const line of parsed.signatures) {
    if (line.name !== logKeys.origin) continue;
    for (const k of trusted) {
      if (!line.keyHash.equals(noteKeyHash(logKeys.origin, k.publicKey))) continue;
      if (ed25519Problem(k.publicKey, Buffer.from(parsed.text, 'utf8'), line.sig) === null) {
        if (mayVouch(k)) permitted ??= k;
        else beyond ??= k;
      } else failed = true;
    }
  }
  if (failed) return { result: 'FAIL' };
  if (permitted) return { result: 'PASS', kid: permitted.kid };
  if (beyond) return { result: 'BEYOND', kid: beyond.kid };
  return { result: 'NONE' };
}

// ─── hand-written twins of receipt.schema.json ───────────────────────────────

function exactKeys(obj, allowed, required, path, errors) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) errors.push(`${path}: unknown member ${q(k)}`);
  for (const k of required) if (!has(obj, k)) errors.push(`${path}: missing member "${k}"`);
}
const want = (cond, msg, errors) => {
  if (!cond) errors.push(msg);
};
const str = (v, rx) => typeof v === 'string' && RX[rx].test(v);
const text = (v, max) => typeof v === 'string' && RX.text.test(v) && cpLength(v) <= max;

/** Envelope rules of receipt.schema.json (the root schema). */
export function checkEnvelopeShape(env) {
  const e = [];
  if (!isObject(env)) return ['receipt is not a JSON object'];
  exactKeys(env, ['v', 'payload', 'sig', 'log', 'issuerKey'], ['v', 'payload', 'sig'], 'receipt', e);
  want(env.v === 0, 'v must be 0', e);
  want(
    typeof env.payload === 'string' && env.payload.length >= 2 && env.payload.length <= MAX_PAYLOAD_B64 && RX.payload.test(env.payload),
    'payload must be canonical unpadded base64url of 1..16384 bytes',
    e,
  );
  if (!isObject(env.sig)) e.push('sig must be an object');
  else {
    exactKeys(env.sig, ['alg', 'kid', 'value'], ['alg', 'kid', 'value'], 'sig', e);
    want(env.sig.alg === 'Ed25519', 'sig.alg must be "Ed25519"', e);
    want(str(env.sig.kid, 'issuerKid'), 'sig.kid is not an issuer key id', e);
    want(str(env.sig.value, 'signature'), 'sig.value is not canonical base64url of 64 bytes', e);
  }
  if (has(env, 'log')) e.push(...checkLogSection(env.log, 'log'));
  if (has(env, 'issuerKey')) {
    const k = env.issuerKey;
    if (!isObject(k)) e.push('issuerKey must be an object');
    else {
      exactKeys(k, ['kid', 'alg', 'publicKey'], ['kid', 'alg', 'publicKey'], 'issuerKey', e);
      want(str(k.kid, 'issuerKid'), 'issuerKey.kid is not an issuer key id', e);
      want(k.alg === 'Ed25519', 'issuerKey.alg must be "Ed25519"', e);
      want(str(k.publicKey, 'spki'), 'issuerKey.publicKey is not an Ed25519 SPKI in base64url', e);
    }
  }
  return e;
}

/**
 * #/$defs/logSection (spec §7.2): the envelope's `log` member, and a log section a relying party
 * supplies as trust.logSection (spec §7.6), which the inclusion route of spec §7.4 returns.
 */
export function checkLogSection(l, where = 'log') {
  const e = [];
  if (!isObject(l)) return [`${where} must be an object`];
  const all = ['index', 'treeSize', 'rootHash', 'proof', 'checkpoint'];
  exactKeys(l, all, all, where, e);
  want(intIn(l.index, 0, Number.MAX_SAFE_INTEGER), `${where}.index must be an integer >= 0`, e);
  want(intIn(l.treeSize, 1, Number.MAX_SAFE_INTEGER), `${where}.treeSize must be an integer >= 1`, e);
  want(str(l.rootHash, 'hex32'), `${where}.rootHash must be 64 lowercase hex`, e);
  want(Array.isArray(l.proof) && l.proof.length <= 64 && l.proof.every((p) => str(p, 'hex32')), `${where}.proof must be at most 64 lowercase-hex hashes`, e);
  want(
    typeof l.checkpoint === 'string' && l.checkpoint.length >= 1 && cpLength(l.checkpoint) <= MAX_CHECKPOINT_CHARS,
    `${where}.checkpoint must be a string of 1..8192 characters`,
    e,
  );
  return e;
}

/** #/$defs/issuingDeployment (spec §6.2): a canonical origin, https or loopback http, or plain http. */
const isIssuingDeployment = (v) => typeof v === 'string' && (RX.deployment.test(v) || RX.plainHttpDeployment.test(v));
/** Plain http on a host other than loopback: trusted only when the relying party allows it (spec §6.2). */
const isPlainHttpOnly = (v) => RX.plainHttpDeployment.test(v) && !RX.deployment.test(v);

/** #/$defs/issuer: who signed, as the payload and the evidence manifest both name it (spec §5.1, §8.1). */
function checkIssuer(i, where, e) {
  if (!isObject(i)) return e.push(`${where} must be an object`);
  exactKeys(i, ['deployment', 'tenantRef', 'keyId'], ['deployment', 'tenantRef', 'keyId'], where, e);
  want(isIssuingDeployment(i.deployment), `${where}.deployment is not a canonical deployment origin (spec section 6.2)`, e);
  want(str(i.tenantRef, 'tenantRef'), `${where}.tenantRef is not a tenantRef`, e);
  want(str(i.keyId, 'issuerKid'), `${where}.keyId is not an issuer key id`, e);
  return undefined;
}

function uniqueByCanonical(items) {
  const seen = new Set();
  for (const it of items) {
    let c;
    try {
      c = canonicalize(it);
    } catch {
      c = JSON.stringify(it);
    }
    if (seen.has(c)) return false;
    seen.add(c);
  }
  return true;
}

const SOURCE_KINDS = ['INTEGRATION', 'COLLECTOR', 'TENANT_RECORD', 'PERSON'];

/** Payload rules of receipt.schema.json (#/$defs/payload). */
export function checkPayloadSchema(p) {
  const e = [];
  if (!isObject(p)) return ['payload is not a JSON object'];
  exactKeys(
    p,
    ['receiptId', 'issuer', 'claim', 'measurement', 'selfAttested', 'sources', 'observedAt', 'issuedAt', 'freshUntil', 'evidence', 'supersedes'],
    ['receiptId', 'issuer', 'claim', 'sources', 'observedAt', 'issuedAt', 'freshUntil', 'evidence'],
    'payload',
    e,
  );
  want(str(p.receiptId, 'ulid'), 'receiptId is not a ULID', e);
  checkIssuer(p.issuer, 'issuer', e);
  if (!isObject(p.claim)) e.push('claim must be an object');
  else {
    const c = p.claim;
    exactKeys(c, ['claimId', 'statement', 'controls', 'assertion'], ['claimId', 'statement', 'controls', 'assertion'], 'claim', e);
    want(str(c.claimId, 'claimId'), 'claim.claimId is not a claim id', e);
    want(text(c.statement, 500), 'claim.statement must be 1..500 characters of plain text (spec section 5.5)', e);
    if (!Array.isArray(c.controls) || c.controls.length > 64) e.push('claim.controls must be an array of at most 64');
    else {
      c.controls.forEach((ctl, i) => {
        if (!isObject(ctl)) return e.push(`claim.controls[${i}] must be an object`);
        exactKeys(ctl, ['framework', 'controlId'], ['framework', 'controlId'], `claim.controls[${i}]`, e);
        want(str(ctl.framework, 'framework'), `claim.controls[${i}].framework is not a framework slug`, e);
        want(str(ctl.controlId, 'controlId'), `claim.controls[${i}].controlId is not printable ASCII`, e);
        return undefined;
      });
      want(uniqueByCanonical(c.controls), 'claim.controls has duplicates', e);
    }
    checkAssertionShape(c.assertion, e);
  }
  if (has(p, 'measurement')) {
    const m = p.measurement;
    if (!isObject(m)) e.push('measurement must be an object');
    else {
      const all = ['numerator', 'denominator', 'unknown', 'scope', 'method'];
      exactKeys(m, all, all, 'measurement', e);
      for (const f of ['numerator', 'denominator', 'unknown']) want(intIn(m[f], 0, COUNT_MAX), `measurement.${f} must be an integer 0..${COUNT_MAX}`, e);
      if (!isObject(m.scope)) e.push('measurement.scope must be an object');
      else {
        exactKeys(m.scope, ['unit', 'description'], ['unit', 'description'], 'measurement.scope', e);
        want(str(m.scope.unit, 'unit'), 'measurement.scope.unit is not a unit slug', e);
        want(text(m.scope.description, 300), 'measurement.scope.description must be 1..300 characters of plain text', e);
      }
      if (!isObject(m.method)) e.push('measurement.method must be an object');
      else {
        exactKeys(m.method, ['id', 'version'], ['id', 'version'], 'measurement.method', e);
        want(str(m.method.id, 'methodId'), 'measurement.method.id is not a method slug', e);
        want(intIn(m.method.version, 1, METHOD_VERSION_MAX), 'measurement.method.version must be 1..1000000', e);
      }
    }
  }
  if (has(p, 'selfAttested')) {
    const s = p.selfAttested;
    if (!isObject(s)) e.push('selfAttested must be an object');
    else {
      exactKeys(s, ['byRole', 'at'], ['byRole', 'at'], 'selfAttested', e);
      want(str(s.byRole, 'role'), 'selfAttested.byRole is not a role name', e);
      want(isTimestamp(s.at), 'selfAttested.at is not a v0 timestamp', e);
    }
  }
  if (!Array.isArray(p.sources) || p.sources.length < 1 || p.sources.length > 16) e.push('sources must be an array of 1..16');
  else {
    p.sources.forEach((s, i) => {
      if (!isObject(s)) return e.push(`sources[${i}] must be an object`);
      exactKeys(s, ['kind', 'ref'], ['kind', 'ref'], `sources[${i}]`, e);
      want(SOURCE_KINDS.includes(s.kind), `sources[${i}].kind is unknown`, e);
      want(str(s.ref, 'sourceRef'), `sources[${i}].ref is not a source slug`, e);
      return undefined;
    });
    want(uniqueByCanonical(p.sources), 'sources has duplicates', e);
  }
  for (const f of ['observedAt', 'issuedAt', 'freshUntil']) want(isTimestamp(p[f]), `${f} is not a v0 timestamp`, e);
  if (!isObject(p.evidence)) e.push('evidence must be an object');
  else {
    exactKeys(p.evidence, ['algo', 'commitment'], ['algo', 'commitment'], 'evidence', e);
    want(p.evidence.algo === 'sha256-salted', 'evidence.algo must be "sha256-salted"', e);
    want(str(p.evidence.commitment, 'hex32'), 'evidence.commitment must be 64 lowercase hex', e);
  }
  if (has(p, 'supersedes')) want(str(p.supersedes, 'ulid'), 'supersedes is not a ULID', e);

  // The if/then/else of the JSON Schema: SELF_ATTESTED <=> selfAttested, and
  // only a self-attestation names a PERSON source, whose ref is "self-attestation".
  const selfKind = isObject(p.claim) && isObject(p.claim.assertion) && p.claim.assertion.kind === 'SELF_ATTESTED';
  const sources = Array.isArray(p.sources) ? p.sources.filter(isObject) : [];
  if (selfKind) {
    want(has(p, 'selfAttested'), 'a SELF_ATTESTED claim needs selfAttested', e);
    want(!has(p, 'measurement'), 'a SELF_ATTESTED claim must not carry a measurement', e);
    want(sources.every((s) => !has(s, 'kind') || s.kind === 'PERSON'), 'a SELF_ATTESTED claim names PERSON sources only', e);
    want(sources.every((s) => !has(s, 'ref') || s.ref === 'self-attestation'), 'a PERSON source has ref "self-attestation"', e);
  } else {
    want(has(p, 'measurement'), 'a measured claim needs measurement', e);
    want(!has(p, 'selfAttested'), 'a measured claim must not carry selfAttested', e);
    want(sources.every((s) => s.kind !== 'PERSON'), 'a measured claim must not name a PERSON source', e);
  }
  return e;
}

function checkAssertionShape(a, e) {
  if (!isObject(a)) return e.push('claim.assertion must be an object');
  switch (a.kind) {
    case 'ALL':
    case 'RATIO':
    case 'SELF_ATTESTED':
      return exactKeys(a, ['kind'], ['kind'], 'claim.assertion', e);
    case 'AT_LEAST': {
      exactKeys(a, ['kind', 'threshold'], ['kind', 'threshold'], 'claim.assertion', e);
      const t = a.threshold;
      if (!isObject(t)) return e.push('claim.assertion.threshold must be an object');
      exactKeys(t, ['numerator', 'denominator'], ['numerator', 'denominator'], 'claim.assertion.threshold', e);
      want(intIn(t.numerator, 1, THRESHOLD_MAX), 'threshold.numerator must be 1..1000000', e);
      want(intIn(t.denominator, 2, THRESHOLD_MAX), 'threshold.denominator must be 2..1000000', e);
      return undefined;
    }
    case 'SCORE':
      exactKeys(a, ['kind', 'value', 'min', 'max'], ['kind', 'value', 'min', 'max'], 'claim.assertion', e);
      for (const f of ['value', 'min', 'max']) want(intIn(a[f], -SCORE_LIMIT, SCORE_LIMIT), `claim.assertion.${f} must be an integer within +-${SCORE_LIMIT}`, e);
      return undefined;
    default:
      return e.push('claim.assertion.kind is not ALL, AT_LEAST, RATIO, SCORE or SELF_ATTESTED');
  }
}

const REVOCATION_REASONS = ['KEY_COMPROMISE', 'ISSUER_REQUEST'];
const KEY_STATUSES = ['ACTIVE', 'RETIRED', 'REVOKED'];

/** #/$defs/issuerKeyEntry (spec §6.3, §6.5). */
function checkIssuerKeyEntry(k, where, e) {
  if (!isObject(k)) return e.push(`${where} must be an object`);
  exactKeys(k, ['kid', 'alg', 'publicKey', 'status', 'validFrom', 'validUntil', 'revokedAt', 'revocationReason', 'lastTreeSize'], ['kid', 'alg', 'publicKey', 'status', 'validFrom'], where, e);
  want(str(k.kid, 'issuerKid'), `${where}.kid is not an issuer key id`, e);
  want(k.alg === 'Ed25519', `${where}.alg must be "Ed25519"`, e);
  want(str(k.publicKey, 'spki'), `${where}.publicKey is not an Ed25519 SPKI`, e);
  want(KEY_STATUSES.includes(k.status), `${where}.status is not ACTIVE, RETIRED or REVOKED`, e);
  want(isTimestamp(k.validFrom), `${where}.validFrom is not a timestamp`, e);
  if (has(k, 'validUntil')) want(isTimestamp(k.validUntil), `${where}.validUntil is not a timestamp`, e);
  if (has(k, 'revokedAt')) want(isTimestamp(k.revokedAt), `${where}.revokedAt is not a timestamp`, e);
  if (has(k, 'revocationReason')) want(REVOCATION_REASONS.includes(k.revocationReason), `${where}.revocationReason is unknown`, e);
  if (has(k, 'lastTreeSize')) want(intIn(k.lastTreeSize, 0, Number.MAX_SAFE_INTEGER), `${where}.lastTreeSize must be an integer >= 0`, e);
  if (k.status === 'ACTIVE') {
    want(!has(k, 'validUntil') && !has(k, 'revokedAt') && !has(k, 'revocationReason') && !has(k, 'lastTreeSize'), `${where}: an ACTIVE key has no end`, e);
  } else if (k.status === 'RETIRED') {
    want(has(k, 'validUntil'), `${where}: a RETIRED key needs validUntil`, e);
    want(!has(k, 'revokedAt') && !has(k, 'revocationReason'), `${where}: a RETIRED key is not revoked`, e);
  } else if (k.status === 'REVOKED') {
    want(has(k, 'revokedAt') && has(k, 'revocationReason'), `${where}: a REVOKED key needs revokedAt and revocationReason`, e);
  }
  return undefined;
}

/** #/$defs/logKeyEntry (spec §7.4): a RETIRED log key names its lastTreeSize; a REVOKED one is not trusted. */
function checkLogKeyEntry(k, where, e) {
  if (!isObject(k)) return e.push(`${where} must be an object`);
  exactKeys(k, ['kid', 'alg', 'publicKey', 'status', 'validFrom', 'validUntil', 'lastTreeSize'], ['kid', 'alg', 'publicKey', 'status', 'validFrom'], where, e);
  want(str(k.kid, 'logKid'), `${where}.kid is not a log key id`, e);
  want(k.alg === 'Ed25519', `${where}.alg must be "Ed25519"`, e);
  want(str(k.publicKey, 'spki'), `${where}.publicKey is not an Ed25519 SPKI`, e);
  want(KEY_STATUSES.includes(k.status), `${where}.status is not ACTIVE, RETIRED or REVOKED`, e);
  want(isTimestamp(k.validFrom), `${where}.validFrom is not a timestamp`, e);
  if (has(k, 'validUntil')) want(isTimestamp(k.validUntil), `${where}.validUntil is not a timestamp`, e);
  if (has(k, 'lastTreeSize')) want(intIn(k.lastTreeSize, 0, Number.MAX_SAFE_INTEGER), `${where}.lastTreeSize must be an integer >= 0`, e);
  if (k.status === 'ACTIVE') want(!has(k, 'validUntil') && !has(k, 'lastTreeSize'), `${where}: an ACTIVE key has no end`, e);
  else if (k.status === 'RETIRED') want(has(k, 'validUntil') && has(k, 'lastTreeSize'), `${where}: a RETIRED log key needs validUntil and lastTreeSize`, e);
  else if (k.status === 'REVOKED') want(has(k, 'validUntil'), `${where}: a REVOKED log key needs validUntil`, e);
  return undefined;
}

/** #/$defs/logKeyDocument: the deployment's log keys (spec §7.4). */
export function checkLogKeyDocument(d) {
  const e = [];
  if (!isObject(d)) return ['log key document is not an object'];
  const all = ['format', 'v', 'generatedAt', 'origin', 'keys'];
  exactKeys(d, all, all, 'logKeys', e);
  want(d.format === 'cmdash-proof-log-keys', 'logKeys.format must be "cmdash-proof-log-keys"', e);
  want(d.v === 0, 'logKeys.v must be 0', e);
  want(isTimestamp(d.generatedAt), 'logKeys.generatedAt is not a timestamp', e);
  want(str(d.origin, 'origin'), 'logKeys.origin is not a log origin', e);
  if (!Array.isArray(d.keys) || d.keys.length < 1 || d.keys.length > MAX_LOG_KEYS) e.push(`logKeys.keys must be 1..${MAX_LOG_KEYS} keys`);
  else d.keys.forEach((k, i) => checkLogKeyEntry(k, `logKeys.keys[${i}]`, e));
  return e;
}

/** #/$defs/keyDocument: /api/.well-known/cmdash-proof-keys/<tenantRef>.json (spec §6.3). */
export function checkKeyDocument(d) {
  const e = [];
  if (!isObject(d)) return ['key document is not an object'];
  exactKeys(d, ['format', 'v', 'deployment', 'tenantRef', 'generatedAt', 'keys', 'log'], ['format', 'v', 'deployment', 'tenantRef', 'generatedAt', 'keys'], 'keyDocument', e);
  want(d.format === 'cmdash-proof-keys', 'keyDocument.format must be "cmdash-proof-keys"', e);
  want(d.v === 0, 'keyDocument.v must be 0', e);
  want(isIssuingDeployment(d.deployment), 'keyDocument.deployment is not a canonical deployment origin', e);
  want(str(d.tenantRef, 'tenantRef'), 'keyDocument.tenantRef is not a tenantRef', e);
  want(isTimestamp(d.generatedAt), 'keyDocument.generatedAt is not a timestamp', e);
  if (!Array.isArray(d.keys) || d.keys.length < 1 || d.keys.length > MAX_ISSUER_KEYS) e.push(`keyDocument.keys must be 1..${MAX_ISSUER_KEYS} keys`);
  else d.keys.forEach((k, i) => checkIssuerKeyEntry(k, `keyDocument.keys[${i}]`, e));
  if (has(d, 'log')) e.push(...checkLogKeyDocument(d.log).map((m) => `keyDocument.log: ${m}`));
  return e;
}

/**
 * Rules beyond the schema that make a key set unusable (spec §6.3, §7.4):
 * duplicate key ids, a key that does not hash to its id, two ACTIVE keys,
 * and a window that ends before it starts.
 */
export function keySetProblem(keys, prefix) {
  const kids = new Set();
  let active = 0;
  for (const k of keys) {
    if (kids.has(k.kid)) return `key id ${k.kid} is listed twice`;
    kids.add(k.kid);
    if (deriveKid(k.publicKey, prefix) !== k.kid) return `published key ${k.kid} does not hash to its key id`;
    if (k.status === 'ACTIVE') active += 1;
    if (has(k, 'validUntil') && !(ms(k.validUntil) > ms(k.validFrom))) return `key ${k.kid}: validUntil is not after validFrom`;
    if (has(k, 'revokedAt') && ms(k.revokedAt) < ms(k.validFrom)) return `key ${k.kid}: revokedAt is before validFrom`;
  }
  if (active > 1) return `${active} keys are ACTIVE; at most one may be`;
  return null;
}

/** #/$defs/evidenceOpening (spec §8.2). */
export function checkEvidenceOpening(o) {
  const e = [];
  if (!isObject(o)) return ['opening is not an object'];
  const all = ['format', 'v', 'receiptId', 'salt', 'manifest'];
  exactKeys(o, all, all, 'opening', e);
  want(o.format === 'cmdash-evidence-opening', 'opening.format must be "cmdash-evidence-opening"', e);
  want(o.v === 0, 'opening.v must be 0', e);
  want(str(o.receiptId, 'ulid'), 'opening.receiptId is not a ULID', e);
  want(str(o.salt, 'hex32'), 'opening.salt must be 64 lowercase hex', e);
  const m = o.manifest;
  if (!isObject(m)) return [...e, 'opening.manifest must be an object'];
  exactKeys(
    m,
    ['receiptId', 'issuer', 'claimId', 'observedAt', 'itemCount', 'itemsRoot', 'counts', 'method', 'selfAttested'],
    ['receiptId', 'issuer', 'claimId', 'observedAt', 'itemCount', 'itemsRoot'],
    'manifest',
    e,
  );
  want(str(m.receiptId, 'ulid'), 'manifest.receiptId is not a ULID', e);
  if (has(m, 'issuer')) checkIssuer(m.issuer, 'manifest.issuer', e);
  want(str(m.claimId, 'claimId'), 'manifest.claimId is not a claim id', e);
  want(isTimestamp(m.observedAt), 'manifest.observedAt is not a timestamp', e);
  want(intIn(m.itemCount, 0, Number.MAX_SAFE_INTEGER), 'manifest.itemCount must be an integer >= 0', e);
  want(str(m.itemsRoot, 'hex32'), 'manifest.itemsRoot must be 64 lowercase hex', e);
  const measured = has(m, 'counts') || has(m, 'method');
  if (measured) {
    want(has(m, 'counts') && has(m, 'method') && !has(m, 'selfAttested'), 'manifest: counts and method go together, without selfAttested', e);
    if (isObject(m.counts)) {
      const all3 = ['numerator', 'denominator', 'unknown'];
      exactKeys(m.counts, all3, all3, 'manifest.counts', e);
      for (const f of all3) want(intIn(m.counts[f], 0, COUNT_MAX), `manifest.counts.${f} must be an integer 0..${COUNT_MAX}`, e);
    } else if (has(m, 'counts')) e.push('manifest.counts must be an object');
    if (isObject(m.method)) {
      exactKeys(m.method, ['id', 'version'], ['id', 'version'], 'manifest.method', e);
      want(str(m.method.id, 'methodId'), 'manifest.method.id is not a method slug', e);
      want(intIn(m.method.version, 1, METHOD_VERSION_MAX), 'manifest.method.version must be 1..1000000', e);
    } else if (has(m, 'method')) e.push('manifest.method must be an object');
  } else {
    want(isObject(m.selfAttested), 'manifest: a self-attested manifest carries selfAttested', e);
    if (isObject(m.selfAttested)) {
      exactKeys(m.selfAttested, ['byRole', 'at'], ['byRole', 'at'], 'manifest.selfAttested', e);
      want(str(m.selfAttested.byRole, 'role'), 'manifest.selfAttested.byRole is not a role name', e);
      want(isTimestamp(m.selfAttested.at), 'manifest.selfAttested.at is not a timestamp', e);
    }
  }
  return e;
}

/** #/$defs/evidenceItem (spec §8.3). */
export function checkEvidenceItem(d) {
  const e = [];
  if (!isObject(d)) return ['item disclosure is not an object'];
  const all = ['format', 'v', 'receiptId', 'index', 'itemCount', 'salt', 'item', 'proof'];
  exactKeys(d, all, all, 'item', e);
  want(d.format === 'cmdash-evidence-item', 'item.format must be "cmdash-evidence-item"', e);
  want(d.v === 0, 'item.v must be 0', e);
  want(str(d.receiptId, 'ulid'), 'item.receiptId is not a ULID', e);
  want(intIn(d.index, 0, Number.MAX_SAFE_INTEGER), 'item.index must be an integer >= 0', e);
  want(intIn(d.itemCount, 1, Number.MAX_SAFE_INTEGER), 'item.itemCount must be an integer >= 1', e);
  want(str(d.salt, 'hex32'), 'item.salt must be 64 lowercase hex', e);
  want(isObject(d.item), 'item.item must be an object', e);
  want(Array.isArray(d.proof) && d.proof.length <= 64 && d.proof.every((p) => str(p, 'hex32')), 'item.proof must be at most 64 lowercase-hex hashes', e);
  return e;
}

/** #/$defs/attestationItem (spec §5.2): item 0 of a self-attested receipt is exactly { statement, userId }. */
export function checkAttestationItem(it) {
  const e = [];
  if (!isObject(it)) return ['the attestation item is not an object'];
  exactKeys(it, ['statement', 'userId'], ['statement', 'userId'], 'attestation item', e);
  want(text(it.statement, 500), 'attestation item statement must be 1..500 characters of plain text', e);
  want(str(it.userId, 'userId'), 'attestation item userId must be 1..128 printable ASCII characters', e);
  return e;
}

// ─── the rules the schema cannot express (spec §5.3, §5.4) ───────────────────

export function consistencyRule(p) {
  const observed = ms(p.observedAt);
  const issued = ms(p.issuedAt);
  const until = ms(p.freshUntil);
  if (observed > issued) return ['time.observed-before-issued', `observedAt ${p.observedAt} is after issuedAt ${p.issuedAt}`];
  if (!(until > observed)) return ['time.fresh-after-observed', 'freshUntil must be after observedAt'];
  if (until - observed > MAX_FRESH_WINDOW_MS) return ['time.window-max-400d', 'freshUntil is more than 400 days after observedAt'];
  if (p.selfAttested && p.selfAttested.at !== p.observedAt) return ['self-attested.at-equals-observedAt', 'selfAttested.at must equal observedAt'];
  if (p.supersedes === p.receiptId) return ['supersedes.not-self', 'a receipt cannot supersede itself'];
  return null;
}

export function assertionRule(p) {
  const a = p.claim.assertion;
  if (a.kind === 'SELF_ATTESTED') return null;
  const { numerator: n, denominator: d, unknown: u } = p.measurement;
  if (n + u > d) return ['measurement.parts-within-denominator', `numerator ${n} + unknown ${u} exceeds denominator ${d}`];
  if (a.kind === 'ALL') {
    if (d < 1) return ['ALL.denominator-positive', 'ALL over an empty population says nothing'];
    if (u !== 0) return ['ALL.no-unknown', `ALL with ${u} unknown: unknown is never pass`];
    if (n !== d) return ['ALL.complete', `ALL but only ${n} of ${d}`];
  } else if (a.kind === 'AT_LEAST') {
    const { numerator: tn, denominator: td } = a.threshold;
    if (!(tn < td)) return ['AT_LEAST.threshold-below-one', 'a threshold of 1 or more is an ALL claim'];
    if (d < 1) return ['AT_LEAST.denominator-positive', 'AT_LEAST over an empty population says nothing'];
    // Exact in doubles: n*td <= 1e9*1e6 = 1e15 < 2^53.
    if (n * td < tn * d) return ['AT_LEAST.threshold-met', `${n}/${d} is below ${tn}/${td}`];
  } else if (a.kind === 'SCORE') {
    if (!(a.min < a.max)) return ['SCORE.range-ordered', 'min must be below max'];
    if (a.value < a.min || a.value > a.max) return ['SCORE.in-range', `score ${a.value} is outside ${a.min}..${a.max}`];
    if (d < 1) return ['SCORE.denominator-positive', 'a score over an empty population says nothing'];
    if (u === d && a.value !== a.min) return ['SCORE.all-unknown-is-min', `all ${d} items are unknown, so the score must be the minimum ${a.min}`];
    if (n === 0 && a.value !== a.min) return ['SCORE.none-met-is-min', `no item is met (${u} unknown, ${d - u} failed), so the score must be the minimum ${a.min}`];
    if (a.value === a.max && !(u === 0 && n === d)) return ['SCORE.max-requires-complete', 'a maximum score is an ALL claim: it needs every item known and met'];
  }
  return null;
}

/** floor(10000 * n / d) rendered with two decimals; never rounds up to 100.00 (spec §5.5). null when d = 0. */
export function truncatedPercent(n, d) {
  if (d === 0) return null;
  const qv = Math.floor((n * 10000) / d);
  return `${Math.floor(qv / 100)}.${String(qv % 100).padStart(2, '0')}`;
}

/** Spec §5.6: MEASURED, SELF_ASSESSED (any TENANT_RECORD source) or SELF_ATTESTED. */
export function basisOf(p) {
  if (p.claim.assertion.kind === 'SELF_ATTESTED') return 'SELF_ATTESTED';
  return p.sources.some((s) => s.kind === 'TENANT_RECORD') ? 'SELF_ASSESSED' : 'MEASURED';
}

/** The structured reading of a verified payload (spec §9.4): what a verifier displays as the claim. */
export function readingOf(p) {
  const a = p.claim.assertion;
  const basis = basisOf(p);
  if (a.kind === 'SELF_ATTESTED') return { kind: a.kind, basis, byRole: p.selfAttested.byRole, at: p.selfAttested.at };
  const { numerator: n, denominator: d, unknown: u, scope } = p.measurement;
  const r = { kind: a.kind, basis, unit: scope.unit, numerator: n, denominator: d, unknown: u, percent: a.kind === 'SCORE' ? null : truncatedPercent(n, d) };
  if (a.kind === 'AT_LEAST') r.threshold = { numerator: a.threshold.numerator, denominator: a.threshold.denominator, percent: truncatedPercent(a.threshold.numerator, a.threshold.denominator) };
  if (a.kind === 'SCORE') r.score = { value: a.value, min: a.min, max: a.max };
  return r;
}

// ─── the verifier (spec §9) ──────────────────────────────────────────────────

function newRun() {
  const results = new Map();
  const set = (name, outcome, detail, extra = {}) => results.set(name, { name, outcome, detail: printable(detail), ...extra });
  return {
    results,
    pass: (name, detail = 'ok') => set(name, 'PASS', detail),
    skip: (name, detail) => set(name, 'SKIP', detail),
    fail: (name, effect, detail, rule) => set(name, 'FAIL', detail, rule ? { effect, rule } : { effect }),
    skipRest(from, detail) {
      for (const n of CHECK_NAMES.slice(CHECK_NAMES.indexOf(from))) if (!results.has(n)) this.skip(n, detail);
    },
    outcome: (name) => results.get(name)?.outcome,
  };
}

/** Checks 1-6 (the structural checks). Shared by verifyReceipt and the evidence functions. */
function decodeStructure(receipt, run) {
  const out = { env: null, payload: null, payloadBytes: null, digest: null };
  // 1 envelope.json
  const doc = readDocument(receipt, MAX_RECEIPT_BYTES);
  if (!doc.ok) {
    run.fail('envelope.json', 'INVALID', `the receipt file is not acceptable JSON: ${doc.detail}`, doc.rule);
    run.skipRest('envelope.version', 'the receipt file could not be read');
    return out;
  }
  run.pass('envelope.json');
  const env = doc.value;
  // 2 envelope.version
  if (!isObject(env) || !isInt(env.v) || env.v < 0) run.fail('envelope.version', 'INVALID', 'not a receipt: no integer version "v"');
  else if (env.v !== 0) run.fail('envelope.version', 'UNVERIFIABLE', `receipt version ${env.v} is not implemented by this v0 verifier`);
  else run.pass('envelope.version', 'v0');
  if (run.outcome('envelope.version') !== 'PASS') {
    run.skipRest('envelope.shape', 'the version check did not pass');
    return out;
  }
  // 3 envelope.shape
  const shape = checkEnvelopeShape(env);
  if (shape.length) {
    run.fail('envelope.shape', 'INVALID', shape.join('; '));
    run.skipRest('payload.decode', 'the envelope is malformed');
    return out;
  }
  run.pass('envelope.shape');
  out.env = env;
  // 4 payload.decode
  const bytes = Buffer.from(env.payload, 'base64url');
  out.payloadBytes = bytes;
  out.digest = receiptDigest(bytes);
  let textValue = null;
  try {
    textValue = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    textValue = null;
  }
  let value;
  let parsed = false;
  if (textValue !== null) {
    try {
      value = JSON.parse(textValue);
      parsed = true;
    } catch {
      parsed = false;
    }
  }
  if (bytes.length > MAX_PAYLOAD_BYTES) run.fail('payload.decode', 'INVALID', 'payload exceeds 16384 bytes');
  else if (textValue === null) run.fail('payload.decode', 'INVALID', 'payload bytes are not valid UTF-8');
  else if (!parsed) run.fail('payload.decode', 'INVALID', 'payload bytes are not JSON (a byte-order mark is not stripped)');
  else if (!isObject(value)) run.fail('payload.decode', 'INVALID', 'payload is not a JSON object');
  else run.pass('payload.decode', `${bytes.length} bytes`);
  if (run.outcome('payload.decode') !== 'PASS') {
    run.skipRest('payload.canonical', 'the payload could not be decoded');
    return out;
  }
  // 5 payload.canonical
  try {
    const canon = Buffer.from(canonicalize(value), 'utf8');
    if (canon.equals(bytes)) run.pass('payload.canonical');
    else run.fail('payload.canonical', 'INVALID', 'the payload bytes are not the canonical form of the value they encode', 'canonical.bytes-differ');
  } catch (err) {
    if (!(err instanceof CanonicalError)) throw err;
    run.fail('payload.canonical', 'INVALID', err.message, err.rule);
  }
  if (run.outcome('payload.canonical') !== 'PASS') {
    run.skipRest('payload.schema', 'the payload is not canonical');
    return out;
  }
  // 6 payload.schema
  const errs = checkPayloadSchema(value);
  if (errs.length) {
    run.fail('payload.schema', 'INVALID', errs.join('; '));
    run.skipRest('signature.kid', 'the payload does not match the schema');
    return out;
  }
  run.pass('payload.schema');
  out.payload = value;
  return out;
}

/**
 * Verify one receipt.
 *
 * receipt: the receipt file's bytes (decoded as fatal UTF-8) or TEXT, parsed strictly
 *   (duplicate member names are refused), or an already-parsed object, serialized first.
 * trust = {
 *   now: '<timestamp>'                         required: the verifier never reads a clock itself
 *   deployments?: ['<origin>', ...]            the issuing deployments the relying party trusts;
 *                                              required with keyDocument (spec §6.6)
 *   allowPlainHttp?: true                      accept a plain-http deployment's key document (spec §6.2)
 *   keyDocument?: <doc or its text>            fetched independently from a trusted deployment
 *   keyDocumentUrl?: '<url>'                   the URL it was fetched from (required with keyDocument)
 *   publicKeys?: [{ deployment, tenantRef, publicKey }]   supplied out of band, each bound to an issuer
 *   logKeys?: <log key doc or its text>        else keyDocument.log
 *   logSection?: <log section or its text>     used only when the envelope has none (spec §7.6)
 *   checkpoint?: '<signed note>'               an externally fetched checkpoint
 *   requireLogged?: true                       a missing or unproven log is UNVERIFIABLE
 * }
 */
export function verifyReceipt(receipt, trust = {}) {
  if (!isTimestamp(trust.now)) throw new TypeError('trust.now must be a v0 timestamp; the checker never reads a clock');
  const run = newRun();
  const { env, payload, payloadBytes, digest } = decodeStructure(receipt, run);
  const policy = trust.requireLogged === true;
  let keySource = null;
  let resolved = null;
  let parsedNote = null;
  let logKeySet = null;
  let keyStatusAsOf = null;
  let logSec = null;

  if (payload) {
    // 7 signature.kid
    if (env.sig.kid !== payload.issuer.keyId) run.fail('signature.kid', 'INVALID', `sig.kid ${q(env.sig.kid)} is not the signed issuer.keyId ${q(payload.issuer.keyId)}`);
    else run.pass('signature.kid');

    // 8 issuer.key
    if (run.outcome('signature.kid') !== 'PASS') run.skip('issuer.key', 'the key id binding failed');
    else {
      const r = resolveKey(env, payload, trust);
      if (r.rule && !r.source) run.fail('issuer.key', 'UNVERIFIABLE', r.detail, r.rule);
      else {
        resolved = r;
        keySource = r.source;
        if (r.source === 'EMBEDDED') run.fail('issuer.key', 'UNVERIFIABLE', r.detail, 'key.embedded-only');
        else run.pass('issuer.key', `${r.source}: ${env.sig.kid}`);
      }
    }

    // 9 signature.verify (runs against an embedded key too: an inconsistent receipt is still INVALID)
    if (!resolved) run.skip('signature.verify', 'no usable key');
    else {
      const sig = Buffer.from(env.sig.value, 'base64url');
      const message = Buffer.concat([Buffer.from(`${RECEIPT_DOMAIN}\n`, 'utf8'), payloadBytes]);
      const problem = ed25519Problem(resolved.spki, message, sig);
      if (problem === null) run.pass('signature.verify', `verifies under ${env.sig.kid}`);
      else if (problem === 'ed25519.unavailable') run.fail('signature.verify', 'UNVERIFIABLE', 'this runtime cannot verify Ed25519: use the CLI', problem);
      else run.fail('signature.verify', 'INVALID', `the signature does not verify under ${env.sig.kid} (${problem})`, problem);
    }

    // 10 log.inclusion (a relying party may supply the section the envelope lacks: spec §7.6)
    const suppliedSection = !env.log && trust.logSection !== undefined;
    if (suppliedSection) {
      const read = readDocument(trust.logSection, MAX_LOG_SECTION_BYTES);
      const problems = read.ok ? checkLogSection(read.value, 'logSection') : [read.detail];
      if (problems.length) run.fail('log.inclusion', 'UNVERIFIABLE', `the supplied log section is malformed: ${problems.join('; ')}`, 'log.section-malformed');
      else logSec = read.value;
    } else logSec = env.log ?? null;
    if (run.results.has('log.inclusion')) {
      // the supplied section was malformed
    } else if (!logSec) {
      if (policy) run.fail('log.inclusion', 'UNVERIFIABLE', 'the receipt has no log section and the policy requires one', 'policy.require-logged');
      else run.skip('log.inclusion', 'no log section: the receipt was issued without a transparency log, or before its first checkpoint');
    } else {
      const l = logSec;
      parsedNote = parseNote(l.checkpoint);
      if (!parsedNote.ok) run.fail('log.inclusion', 'INVALID', `the checkpoint is not a well-formed signed note: ${parsedNote.error}`, 'log.checkpoint-malformed');
      else if (parsedNote.treeSize !== l.treeSize) run.fail('log.inclusion', 'INVALID', 'log.treeSize differs from the checkpoint', 'log.size-mismatch');
      else if (!parsedNote.rootHash.equals(Buffer.from(l.rootHash, 'hex'))) run.fail('log.inclusion', 'INVALID', 'log.rootHash differs from the checkpoint', 'log.root-mismatch');
      else if (!(l.index < l.treeSize)) run.fail('log.inclusion', 'INVALID', 'log.index is not inside the tree', 'log.index-outside');
      else {
        const leaf = leafHash(Buffer.from(digest, 'hex'));
        const ok = verifyInclusion(l.index, l.treeSize, leaf, l.proof.map((h) => Buffer.from(h, 'hex')), parsedNote.rootHash);
        if (ok) run.pass('log.inclusion', `leaf ${l.index} of ${l.treeSize}${suppliedSection ? ' (a log section the relying party supplied)' : ''}`);
        else run.fail('log.inclusion', 'INVALID', 'the inclusion proof does not lead from this receipt to the checkpoint root', 'log.proof');
      }
    }

    // 11 log.checkpoint
    const unproven = (detail) =>
      policy ? run.fail('log.checkpoint', 'UNVERIFIABLE', `${detail}, and the policy requires a proven log`, 'policy.require-logged') : run.skip('log.checkpoint', detail);
    if (run.outcome('log.inclusion') !== 'PASS') run.skip('log.checkpoint', 'no verified inclusion proof');
    else {
      const source = trust.logKeys !== undefined ? trust.logKeys : trust.keyDocument !== undefined ? 'FROM_KEY_DOCUMENT' : undefined;
      let keys;
      let problem = null;
      if (source === 'FROM_KEY_DOCUMENT') keys = resolved?.doc?.log;
      else if (source !== undefined) {
        const read = readDocument(source, MAX_KEY_DOCUMENT_BYTES);
        if (!read.ok) problem = read.detail;
        else {
          const errs = checkLogKeyDocument(read.value);
          problem = errs.length ? errs.join('; ') : keySetProblem(read.value.keys, LOG_KID_PREFIX);
          keys = read.value;
        }
      }
      if (problem) run.fail('log.checkpoint', 'UNVERIFIABLE', `the log key set is malformed: ${problem}`, 'log-keys.malformed');
      else if (!keys) unproven('no trusted log key supplied');
      else if (parsedNote.origin !== keys.origin) unproven(`the checkpoint origin ${q(parsedNote.origin)} is not the log whose keys were supplied`);
      else {
        logKeySet = keys;
        const v = verifyNote(parsedNote, keys);
        if (v.result === 'PASS') run.pass('log.checkpoint', `signed by ${v.kid}`);
        else if (v.result === 'FAIL') run.fail('log.checkpoint', 'INVALID', 'a signature line claims a trusted log key and does not verify', 'checkpoint.signature');
        else if (v.result === 'BEYOND') {
          run.fail('log.checkpoint', 'INVALID', `retired log key ${v.kid} signed a tree larger than its lastTreeSize`, 'log-key.beyond-last-tree-size');
        } else unproven('the checkpoint is not signed by any log key you trust');
      }
    }

    // 12 log.external
    if (trust.checkpoint === undefined) run.skip('log.external', 'no external checkpoint supplied');
    else if (run.outcome('log.checkpoint') !== 'PASS') run.skip('log.external', "the receipt's own checkpoint was not verified");
    else {
      const ext = parseNote(trust.checkpoint);
      if (!ext.ok) run.fail('log.external', 'UNVERIFIABLE', `the external checkpoint is malformed: ${ext.error}`, 'external.malformed');
      else if (ext.origin !== logKeySet.origin) run.fail('log.external', 'UNVERIFIABLE', 'the external checkpoint is for another log', 'external.other-log');
      else if (verifyNote(ext, logKeySet).result !== 'PASS') run.fail('log.external', 'UNVERIFIABLE', 'the external checkpoint is not validly signed by a trusted log key', 'external.unsigned');
      else if (ext.treeSize !== logSec.treeSize) {
        run.skip('log.external', `the external checkpoint is for size ${ext.treeSize}, the receipt's for ${logSec.treeSize}; v0 has no consistency proofs (P10)`);
      } else if (!ext.rootHash.equals(parsedNote.rootHash)) {
        run.fail('log.external', 'INVALID', `the log signed two different roots for tree size ${ext.treeSize}: equivocation`, 'external.equivocation');
      } else run.pass('log.external', `same root at size ${ext.treeSize}`);
    }

    // 13 issuer.key-status
    const logged = run.outcome('log.inclusion') === 'PASS' && run.outcome('log.checkpoint') === 'PASS';
    if (run.outcome('signature.verify') !== 'PASS') run.skip('issuer.key-status', 'the signature was not verified');
    else if (keySource !== 'KEY_DOCUMENT') run.skip('issuer.key-status', 'no key document: revocation status unknown');
    else {
      const k = resolved.entry;
      keyStatusAsOf = resolved.doc.generatedAt;
      keyStatus(run, k, payload, logged ? logSec.index : null, resolved.doc.generatedAt);
    }

    // 14 payload.consistency
    const c = consistencyRule(payload);
    if (c) run.fail('payload.consistency', 'INVALID', c[1], c[0]);
    else run.pass('payload.consistency');

    // 15 assertion.admissible
    const a = assertionRule(payload);
    if (a) run.fail('assertion.admissible', 'INVALID', a[1], a[0]);
    else run.pass('assertion.admissible', payload.claim.assertion.kind);

    // 16 time.future
    if (ms(payload.issuedAt) > ms(trust.now) + FUTURE_ALLOWANCE_MS) {
      run.fail('time.future', 'UNVERIFIABLE', `issued ${payload.issuedAt}, after this verifier's time ${trust.now} (+300 s)`);
    } else run.pass('time.future');

    // 17 freshness
    if (ms(trust.now) > ms(payload.freshUntil)) run.fail('freshness', 'STALE', `stale since ${payload.freshUntil}`);
    else run.pass('freshness', `fresh until ${payload.freshUntil}`);
  }

  const checks = CHECK_NAMES.map((n) => run.results.get(n));
  const firstFail = (effect) => checks.find((c) => c.outcome === 'FAIL' && c.effect === effect);
  const failed = firstFail('INVALID') ?? firstFail('UNVERIFIABLE') ?? firstFail('STALE') ?? null;
  const verdict = !failed ? 'VALID' : failed.effect === 'STALE' ? 'STALE_VALID' : failed.effect;
  const valid = verdict === 'VALID' || verdict === 'STALE_VALID';
  const outcome = (n) => run.results.get(n).outcome;

  const proves = [];
  const doesNotProve = [];
  let reading = null;
  if (valid) {
    reading = readingOf(payload);
    const kind = payload.claim.assertion.kind;
    const selfAttested = kind === 'SELF_ATTESTED';
    const logged = outcome('log.inclusion') === 'PASS' && outcome('log.checkpoint') === 'PASS';
    proves.push('signed-by-key');
    if (keySource === 'KEY_DOCUMENT') proves.push('issuer-key-published');
    proves.push('unaltered', 'observed-at', selfAttested ? 'attestation-stated' : 'measurement-stated');
    if (logged) proves.push('logged');
    if (outcome('log.external') === 'PASS') proves.push('log-consistent-with-external');
    if (verdict === 'VALID') proves.push('fresh');

    doesNotProve.push(selfAttested ? 'attestation-truth' : 'source-truth');
    if (reading.basis === 'SELF_ASSESSED') doesNotProve.push('inputs-measured');
    if (!selfAttested) doesNotProve.push('scope-completeness');
    if (kind === 'SCORE') doesNotProve.push('score-derivation');
    doesNotProve.push('control-effectiveness', 'not-superseded');
    if (verdict === 'STALE_VALID') doesNotProve.push('currently-fresh');
    if (outcome('issuer.key-status') !== 'PASS') doesNotProve.push('key-status');
    doesNotProve.push(logged ? 'split-view' : 'not-logged');
  }

  const keyDocumentUrl = payload ? keyDocumentUrlFor(payload.issuer) : null;
  // Spec §6.2, §9.4: the issuer's deployment is http, so whatever is fetched from it travels in clear.
  const plainHttp = payload ? payload.issuer.deployment.startsWith('http://') : false;
  const entry = resolved?.entry;
  const disownedAt = valid && entry && entry.status === 'REVOKED' && entry.revocationReason === 'ISSUER_REQUEST' ? entry.revokedAt : null;
  return {
    verdict,
    failedCheck: failed ? failed.name : null,
    rule: failed?.rule ?? null,
    keySource,
    keyStatusAsOf,
    keyDocumentUrl,
    plainHttp,
    checks,
    proves,
    doesNotProve,
    reading,
    summary: printable(summarize({ verdict, failed, payload, keySource, reading, doesNotProve, keyStatusAsOf, outcome, plainHttp, disownedAt })),
    digest,
    payload: valid ? payload : null,
  };
}

/** issuer.key-status (spec §6.5). */
function keyStatus(run, k, payload, loggedIndex, generatedAt) {
  const issued = ms(payload.issuedAt);
  if (k.status === 'REVOKED' && k.revocationReason === 'KEY_COMPROMISE') {
    return run.fail('issuer.key-status', 'INVALID', `key compromised: revoked at ${k.revokedAt}; every receipt it ever signed is invalid`, 'key.revoked');
  }
  if (issued < ms(k.validFrom)) {
    return run.fail('issuer.key-status', 'INVALID', `issued ${payload.issuedAt}, before the key became valid at ${k.validFrom}`, 'key.not-yet-valid');
  }
  const disowned = k.status === 'REVOKED'; // ISSUER_REQUEST: acts as retirement at revokedAt
  if (k.status === 'RETIRED' || disowned) {
    const ends = [k.validUntil, disowned ? k.revokedAt : undefined].filter(Boolean).map(ms);
    const end = Math.min(...ends);
    const endsAt = new Date(end).toISOString();
    const rule = disowned && end === ms(k.revokedAt) ? 'key.disowned' : 'key.retired';
    const what = rule === 'key.disowned' ? `disowned by the issuer at ${endsAt}` : `retired at ${endsAt}`;
    if (issued >= end) return run.fail('issuer.key-status', 'INVALID', `issued ${payload.issuedAt}, but the key was ${what}`, rule);
    if (loggedIndex !== null && has(k, 'lastTreeSize') && loggedIndex >= k.lastTreeSize) {
      return run.fail('issuer.key-status', 'INVALID', `logged at index ${loggedIndex}, after the key was ${what} (lastTreeSize ${k.lastTreeSize})`, rule);
    }
    if (!(loggedIndex !== null && has(k, 'lastTreeSize') && loggedIndex < k.lastTreeSize)) {
      return run.fail(
        'issuer.key-status',
        'UNVERIFIABLE',
        `the key was ${what}; only the signer's own issuedAt says this receipt came first, and no verified log proof below lastTreeSize confirms it`,
        'key.retired-unproven',
      );
    }
  }
  if (ms(generatedAt) < issued) {
    return run.skip('issuer.key-status', `key status as of ${generatedAt}, before this receipt was issued: not proven`);
  }
  return run.pass('issuer.key-status', `${disowned ? `disowned by the issuer at ${k.revokedAt}, after this receipt was logged` : k.status} as of ${generatedAt}`);
}

function resolveKey(env, payload, trust) {
  const kid = env.sig.kid;
  const deployment = payload.issuer.deployment;
  const failWith = (rule, detail) => ({ rule, detail });
  // Spec §6.6: the relying party names the deployments it trusts, and a key document is only
  // meaningful relative to one of them. The receipt never chooses where trust is fetched from.
  if (trust.deployments !== undefined || trust.keyDocument !== undefined) {
    const trusted = Array.isArray(trust.deployments) ? trust.deployments : [];
    if (!trusted.includes(deployment)) {
      return failWith(
        'key.deployment-untrusted',
        trusted.length
          ? `the receipt names deployment ${deployment}, which is not one you trust (${trusted.map(q).join(', ')})`
          : `the receipt names deployment ${deployment}, and you named no deployment you trust (the CLI's --deployment)`,
      );
    }
  }
  if (trust.keyDocument !== undefined && isPlainHttpOnly(deployment) && trust.allowPlainHttp !== true) {
    return failWith(
      'key.deployment-plain-http',
      `deployment ${deployment} is plain http, so its key document is only as trustworthy as the network path; allow plain http explicitly (the CLI's --allow-plain-http) to use it`,
    );
  }
  if (trust.keyDocument !== undefined) {
    const read = readDocument(trust.keyDocument, MAX_KEY_DOCUMENT_BYTES);
    if (!read.ok) return failWith('key.document-malformed', `the key document is not acceptable JSON: ${read.detail}`);
    const doc = read.value;
    const errs = checkKeyDocument(doc);
    if (errs.length) return failWith('key.document-malformed', `the key document is malformed: ${errs.join('; ')}`);
    const problem = keySetProblem(doc.keys, ISSUER_KID_PREFIX) ?? (doc.log ? keySetProblem(doc.log.keys, LOG_KID_PREFIX) : null);
    if (problem) return failWith('key.document-malformed', `the key document is unusable: ${problem}`);
    const expected = keyDocumentUrlFor(payload.issuer);
    if (trust.keyDocumentUrl !== expected) {
      return failWith(
        'key.document-url',
        trust.keyDocumentUrl === undefined
          ? `a key document must come with the URL it was fetched from; this receipt's is ${expected}`
          : `the key document was fetched from ${q(trust.keyDocumentUrl)}; this receipt's is ${expected}`,
      );
    }
    if (doc.deployment !== payload.issuer.deployment) {
      return failWith('key.document-deployment', `the key document names deployment ${q(doc.deployment)}; the receipt names ${payload.issuer.deployment}`);
    }
    if (doc.tenantRef !== payload.issuer.tenantRef) {
      return failWith('key.document-tenant', `the key document is for ${q(doc.tenantRef)}; the receipt names issuer ${payload.issuer.tenantRef}`);
    }
    const entry = doc.keys.find((k) => k.kid === kid);
    if (!entry) return failWith('key.not-in-document', `key ${kid} is not in the key document for ${doc.tenantRef}`);
    return { source: 'KEY_DOCUMENT', entry, spki: entry.publicKey, doc };
  }
  if (trust.publicKeys !== undefined) {
    // Each supplied key is bound to one issuer, the pair (deployment, tenantRef) (spec §6.2, §6.6).
    const list = Array.isArray(trust.publicKeys) ? trust.publicKeys : [];
    const candidates = list.filter(
      (e) => isObject(e) && isIssuingDeployment(e.deployment) && str(e.tenantRef, 'tenantRef') && str(e.publicKey, 'spki') && deriveKid(e.publicKey) === kid,
    );
    if (!candidates.length) return failWith('key.supplied-none', `none of the supplied public keys (each { deployment, tenantRef, publicKey }) has key id ${kid}`);
    const here = candidates.filter((e) => e.deployment === deployment);
    if (!here.length) {
      return failWith('key.supplied-deployment', `the supplied key ${kid} is bound to ${candidates.map((e) => e.deployment).join(', ')}; the receipt names deployment ${deployment}`);
    }
    const bound = here.find((e) => e.tenantRef === payload.issuer.tenantRef);
    if (!bound) {
      return failWith('key.supplied-tenant', `the supplied key ${kid} is bound to ${here.map((e) => e.tenantRef).join(', ')} at ${deployment}; the receipt names ${payload.issuer.tenantRef}`);
    }
    return { source: 'SUPPLIED', spki: bound.publicKey };
  }
  if (env.issuerKey) {
    const k = env.issuerKey;
    if (k.kid !== kid || deriveKid(k.publicKey) !== kid) return failWith('key.embedded-mismatch', 'the key embedded in the receipt does not match its key id');
    return {
      source: 'EMBEDDED',
      spki: k.publicKey,
      detail: `the only key came from inside the receipt, which proves nothing about who issued it; if you trust deployment ${deployment}, fetch the issuer key document from ${keyDocumentUrlFor(payload.issuer)}`,
    };
  }
  return failWith('key.no-key', `no key: if you trust deployment ${deployment}, fetch the issuer key document from ${keyDocumentUrlFor(payload.issuer)}, or supply a key bound to this deployment and tenantRef`);
}

function readingText(r) {
  if (r.kind === 'SELF_ATTESTED') return `SELF-ATTESTED by ${r.byRole} at ${r.at}; nothing was measured`;
  const prefix = r.basis === 'SELF_ASSESSED' ? 'SELF-ASSESSED ' : '';
  const counts = `${r.numerator} of ${r.denominator} ${r.unit}, ${r.unknown} unknown${r.percent === null ? '' : ` (${r.percent}%)`}`;
  if (r.kind === 'ALL') return `${prefix}ALL: ${counts}`;
  if (r.kind === 'AT_LEAST') return `${prefix}AT LEAST ${r.threshold.numerator}/${r.threshold.denominator} (${r.threshold.percent}%): ${counts}`;
  if (r.kind === 'SCORE') return `${prefix}SCORE ${r.score.value} on a scale from ${r.score.min} to ${r.score.max}: ${r.numerator} of ${r.denominator} ${r.unit} met, ${r.unknown} unknown`;
  return `${prefix}RATIO: ${counts}`;
}

function summarize({ verdict, failed, payload, keySource, reading, doesNotProve, keyStatusAsOf, outcome, plainHttp, disownedAt }) {
  if (verdict === 'INVALID') {
    const unattributed = outcome('signature.verify') !== 'PASS' && failed.name !== 'signature.verify';
    return `INVALID - ${failed.name}: ${failed.detail}${unattributed ? '; the signature was not verified, so this is not attributable to the named issuer' : ''}`;
  }
  if (verdict === 'UNVERIFIABLE') {
    // issuer.key details that call for a fetch already name keyDocumentUrl (the P5 one-click fetch).
    return `UNVERIFIABLE - ${failed.name}: ${failed.detail}`;
  }
  const head = verdict === 'STALE_VALID' ? `STALE - expired ${payload.freshUntil}; the signature is valid` : 'VALID';
  const issuer = `issued by ${payload.issuer.tenantRef} at ${payload.issuer.deployment} (key ${payload.issuer.keyId})`;
  const notes = [];
  if (doesNotProve.includes('key-status')) {
    notes.push(keySource === 'KEY_DOCUMENT' ? `KEY STATUS NOT PROVEN: the key document is as of ${keyStatusAsOf}, before this receipt` : 'KEY STATUS NOT PROVEN: no key document');
  } else notes.push(`key status as of ${keyStatusAsOf}`);
  if (disownedAt) notes.push(`KEY DISOWNED BY THE ISSUER AT ${disownedAt}, after this receipt`);
  if (plainHttp && keySource === 'KEY_DOCUMENT') notes.push('KEY DOCUMENT FROM A PLAIN-HTTP DEPLOYMENT');
  if (doesNotProve.includes('not-logged')) notes.push('NOT LOGGED');
  return [`${head} - ${issuer} - ${readingText(reading)}`, ...notes].join('; ');
}

// ─── evidence openings and items (spec §8) ───────────────────────────────────

/** The canonical manifest header a receipt implies (spec §8.1): what an opening must match. */
function expectedHeader(p) {
  const issuer = { deployment: p.issuer.deployment, tenantRef: p.issuer.tenantRef, keyId: p.issuer.keyId };
  const h = { receiptId: p.receiptId, issuer, claimId: p.claim.claimId, observedAt: p.observedAt };
  if (p.measurement) {
    const { numerator, denominator, unknown } = p.measurement;
    h.counts = { numerator, denominator, unknown };
    h.method = { id: p.measurement.method.id, version: p.measurement.method.version };
  } else h.selfAttested = { byRole: p.selfAttested.byRole, at: p.selfAttested.at };
  return h;
}

/** Opens the commitment (spec §8.2): the result, and on a match the decoded payload and the manifest. */
function openEvidence(receipt, opening) {
  const run = newRun();
  const { payload } = decodeStructure(receipt, run);
  const miss = (rule, detail) => ({ result: { match: false, rule, detail: printable(detail) } });
  if (!payload) return miss('opening.receipt-undecodable', 'the receipt does not decode to a v0 payload');
  const read = readDocument(opening, MAX_OPENING_BYTES);
  if (!read.ok) return miss('opening.malformed', `the opening is not acceptable JSON: ${read.detail}`);
  const o = read.value;
  const errs = checkEvidenceOpening(o);
  if (errs.length) return miss('opening.malformed', errs.join('; '));
  if (o.receiptId !== payload.receiptId) return miss('opening.receipt', 'the opening is for another receipt');
  let manifest;
  try {
    manifest = Buffer.from(canonicalize(o.manifest), 'utf8');
  } catch (err) {
    return miss('opening.malformed', `the manifest is not canonicalizable: ${err.message}`);
  }
  const got = sha256(Buffer.from(`${EVIDENCE_DOMAIN}\n`, 'utf8'), Buffer.from(o.salt, 'hex'), manifest).toString('hex');
  if (got !== payload.evidence.commitment) return miss('opening.commitment', 'the disclosed salt and manifest do not hash to the commitment');
  const { itemCount, itemsRoot, ...header } = o.manifest;
  if (canonicalize(header) !== canonicalize(expectedHeader(payload))) {
    return miss('opening.header', 'the manifest header does not describe this receipt (receiptId, issuer, claimId, observedAt, counts, method or attestation differ)');
  }
  return { result: { match: true, rule: null, detail: `the commitment opens to a manifest of ${itemCount} item(s) for this receipt` }, payload, manifest: o.manifest };
}

/** Does a disclosed opening { format, v, receiptId, salt, manifest } match the receipt's commitment and header? */
export function verifyEvidenceOpening(receipt, opening) {
  return openEvidence(receipt, opening).result;
}

/**
 * Is a sampled item { format, v, receiptId, index, itemCount, salt, item, proof } inside the opened
 * manifest? For a self-attested receipt, item 0 must also be the attestation record the receipt
 * signs: exactly { statement, userId }, with the statement of claim.statement (spec §5.2).
 */
export function verifyEvidenceItem(receipt, opening, disclosure) {
  const miss = (rule, detail) => ({ match: false, rule, detail: printable(detail) });
  const opened = openEvidence(receipt, opening);
  if (!opened.result.match) return miss('item.opening', `the opening does not match: ${opened.result.rule}`);
  const { payload, manifest } = opened;
  const read = readDocument(disclosure, MAX_OPENING_BYTES);
  if (!read.ok) return miss('item.malformed', `the item disclosure is not acceptable JSON: ${read.detail}`);
  const d = read.value;
  const errs = checkEvidenceItem(d);
  if (errs.length) return miss('item.malformed', errs.join('; '));
  if (d.receiptId !== manifest.receiptId) return miss('item.receipt', 'the item is for another receipt');
  if (d.itemCount !== manifest.itemCount || !(d.index < d.itemCount)) return miss('item.count', 'the item count or index does not fit the manifest');
  let bytes;
  try {
    bytes = Buffer.from(canonicalize(d.item), 'utf8');
  } catch (err) {
    return miss('item.malformed', `the item is not canonicalizable: ${err.message}`);
  }
  const entry = Buffer.concat([Buffer.from(`${EVIDENCE_ITEM_DOMAIN}\n`, 'utf8'), Buffer.from(d.salt, 'hex'), bytes]);
  const ok = verifyInclusion(d.index, d.itemCount, leafHash(entry), d.proof.map((h) => Buffer.from(h, 'hex')), Buffer.from(manifest.itemsRoot, 'hex'));
  if (!ok) return miss('item.inclusion', 'the item is not under the manifest itemsRoot');
  if (payload.claim.assertion.kind === 'SELF_ATTESTED' && d.index === 0) {
    const problems = checkAttestationItem(d.item);
    if (problems.length) return miss('item.attestation', `item 0 of a self-attested receipt is not the attestation record: ${problems.join('; ')}`);
    if (d.item.statement !== payload.claim.statement) {
      return miss('item.attestation', 'item 0 records a statement other than the one this receipt signs: the person did not attest to claim.statement');
    }
  }
  return { match: true, rule: null, detail: `item ${d.index} of ${d.itemCount} is in the committed manifest` };
}
