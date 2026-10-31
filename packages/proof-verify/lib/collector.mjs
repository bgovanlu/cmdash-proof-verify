// SPDX-License-Identifier: Apache-2.0
/**
 * Collector attestation (docs/specs/collector-attestation-v0.md, plan item
 * K1): does the supplier's own collector, with its own Ed25519 key, vouch
 * for exactly the measurement this receipt signs?
 *
 * The attestation is a COMPANION document, checked next to a receipt the way
 * an evidence opening is (spec proof-receipt-v0 section 8.2): the receipt
 * format is unchanged, every v0 receipt and vector verifies exactly as
 * before, and the result is separate from the receipt's verdict. It binds to
 * the receipt through fields the issuer already signs:
 *
 *   - the receipt's `sources` name `{ kind: COLLECTOR, ref: <collector key id> }`
 *     (the issuer vouches that this key produced the measurement);
 *   - the collector's statement names the receipt's issuer (deployment and
 *     tenantRef: the tenant is inside the collector's signed message), its
 *     counts, and `measuredAt` equal to the receipt's `observedAt` (a receipt
 *     can claim no more freshness than the collector signed).
 *
 * The collector key is either PINNED by the relying party (obtained from the
 * supplier out of band: the only way the result is independent of the
 * issuing deployment) or ISSUER_NAMED (only the signed receipt names it).
 * A revocation (`revokedAt`, from the document or a pinned key) at or before
 * the receipt's `issuedAt` is a MISMATCH; a later one leaves the receipt
 * ATTESTED and reports the revocation time.
 *
 * Isomorphic, like core.mjs: no Node builtin, so scripts/build-browser.mjs can
 * concatenate it into browser/verify.js.
 */
import { concatBytes, decodeBase64Url, decodeUtf8Fatal, toHex, utf8 } from './bytes.mjs';
import { CanonicalError, canonicalize, hasOwn, isPlainObject } from './canonical.mjs';
import { rawPublicKeyOf, verifyEd25519 } from './ed25519.mjs';
import { asciiEscape, quoteFull } from './escape.mjs';
import { StrictJsonError, parseStrictJson, readJsonDocument } from './json.mjs';
import { isIssuingDeployment, parseTimestamp } from './schema.mjs';
import { decodeReceiptPayload } from './core.mjs';

/** The rules of a collector attestation check, in the order they are tried (spec section 5). */
export const COLLECTOR_RULES = Object.freeze([
  'collector.receipt-undecodable',
  'collector.malformed',
  'collector.key-id',
  'collector.statement-malformed',
  'collector.statement-key',
  'collector.signature',
  'collector.not-measured',
  'collector.issuer',
  'collector.not-named',
  'collector.metric',
  'collector.counts',
  'collector.measured-at',
  'collector.key-revoked',
  'collector.key-unpinned',
]);

/** Spec section 6: what an ATTESTED result proves and does not prove. */
export const COLLECTOR_PROVES_IDS = Object.freeze([
  'collector-signed',
  'collector-bound-to-receipt',
  'collector-key-pinned',
]);
export const COLLECTOR_DOES_NOT_PROVE_IDS = Object.freeze([
  'collector-key-independent',
  'collector-source-truth',
  'collector-key-not-revoked',
]);

/** The companion document's file limit (spec section 3.4's rule, 64 KiB). */
export const COLLECTOR_ATTESTATION_LIMIT = 65536;

const COLLECTOR_MEASUREMENT_DOMAIN = utf8('cmdash-collector-measurement-v0\n');
const COLLECTOR_KID_PREFIX = 'cmdash-collector-';
const COLLECTOR_KID_RE = /^cmdash-collector-[0-9a-f]{16}$/;
const COLLECTOR_SPKI_RE = /^MCowBQYDK2VwAyEA[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const COLLECTOR_SIG_RE = /^[A-Za-z0-9_-]{85}[AQgw]$/;
const COLLECTOR_B64_RE = /^[A-Za-z0-9_-]{2,5462}$/;
const COLLECTOR_TENANT_REF_RE = /^tr_[0-9a-f]{32}$/;
const COLLECTOR_METRIC_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const COLLECTOR_NONCE_RE = /^[0-9a-f]{32}$/;
/** The measurement method a collector-attested receipt signs: `collector-attested.<metric>.v<N>` (spec section 5). */
const COLLECTOR_METHOD_RE = /^collector-attested\.([a-z0-9][a-z0-9._-]{0,63})\.v[1-9][0-9]*$/;
const COLLECTOR_STATEMENT_MEMBERS = Object.freeze([
  'collectorKeyId',
  'denominator',
  'deployment',
  'measuredAt',
  'metric',
  'nonce',
  'numerator',
  'seq',
  'tenantRef',
  'unknown',
  'v',
]);
const COLLECTOR_TRUST_MEMBERS = Object.freeze(['collectorKeys']);

const isCollectorCount = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 1000000000;

/** Why a parsed companion document is not one (spec section 3), or null. */
export function collectorAttestationProblem(v) {
  if (!isPlainObject(v)) return 'the attestation must be a JSON object';
  const allowed = ['format', 'v', 'collectorKey', 'statement', 'sig', 'revokedAt'];
  for (const k of Object.keys(v)) if (!allowed.includes(k)) return `unknown member ${quoteFull(k)}`;
  for (const k of ['format', 'v', 'collectorKey', 'statement', 'sig'])
    if (!hasOwn(v, k)) return `missing member "${k}"`;
  if (v.format !== 'cmdash-collector-attestation')
    return 'format must be "cmdash-collector-attestation"';
  if (v.v !== 0) return 'v must be 0';
  const key = v.collectorKey;
  if (!isPlainObject(key)) return 'collectorKey must be an object';
  const keyMembers = Object.keys(key).sort().join(',');
  if (keyMembers !== 'alg,kid,publicKey')
    return 'collectorKey must have exactly the members kid, alg, publicKey';
  if (typeof key.kid !== 'string' || !COLLECTOR_KID_RE.test(key.kid))
    return 'collectorKey.kid must be cmdash-collector- and 16 lowercase hex';
  if (key.alg !== 'Ed25519') return 'collectorKey.alg must be "Ed25519"';
  if (typeof key.publicKey !== 'string' || !COLLECTOR_SPKI_RE.test(key.publicKey))
    return 'collectorKey.publicKey must be the base64url of an Ed25519 DER SPKI';
  if (typeof v.statement !== 'string' || !COLLECTOR_B64_RE.test(v.statement))
    return 'statement must be base64url of 1 to 4096 bytes';
  if (typeof v.sig !== 'string' || !COLLECTOR_SIG_RE.test(v.sig))
    return 'sig must be the base64url of a 64-byte signature';
  if (hasOwn(v, 'revokedAt') && parseTimestamp(v.revokedAt) === null)
    return 'revokedAt must be a timestamp YYYY-MM-DDTHH:MM:SS.sssZ';
  return null;
}

/** Why a decoded statement is not a measurement statement (spec section 2), or null. */
export function collectorStatementProblem(s) {
  if (!isPlainObject(s)) return 'the statement must be a JSON object';
  const members = Object.keys(s).sort();
  if (
    members.length !== COLLECTOR_STATEMENT_MEMBERS.length ||
    members.some((m, i) => m !== COLLECTOR_STATEMENT_MEMBERS[i])
  )
    return `the statement must have exactly the members ${COLLECTOR_STATEMENT_MEMBERS.join(', ')}`;
  if (s.v !== 0) return 'the statement v must be 0';
  if (!isIssuingDeployment(s.deployment)) return 'the statement deployment is not a canonical origin';
  if (typeof s.tenantRef !== 'string' || !COLLECTOR_TENANT_REF_RE.test(s.tenantRef))
    return 'the statement tenantRef is not tr_ and 32 lowercase hex';
  if (typeof s.collectorKeyId !== 'string' || !COLLECTOR_KID_RE.test(s.collectorKeyId))
    return 'the statement collectorKeyId is not a collector key id';
  if (typeof s.metric !== 'string' || !COLLECTOR_METRIC_RE.test(s.metric))
    return 'the statement metric is not a slug';
  if (!isCollectorCount(s.numerator) || !isCollectorCount(s.denominator) || !isCollectorCount(s.unknown))
    return 'the statement counts must be integers from 0 to 10^9';
  if (s.numerator + s.unknown > s.denominator)
    return 'the statement numerator plus unknown exceeds its denominator';
  if (parseTimestamp(s.measuredAt) === null)
    return 'the statement measuredAt is not a timestamp YYYY-MM-DDTHH:MM:SS.sssZ';
  if (!Number.isSafeInteger(s.seq) || s.seq < 1) return 'the statement seq must be a positive integer';
  if (typeof s.nonce !== 'string' || !COLLECTOR_NONCE_RE.test(s.nonce))
    return 'the statement nonce must be 32 lowercase hex';
  return null;
}

/** trust.collectorKeys: [{ deployment, tenantRef, publicKey, revokedAt? }], each bound to one issuer. */
function pinnedCollectorKeys(trust) {
  if (trust === undefined || trust === null) return null;
  if (!isPlainObject(trust))
    throw new TypeError('verifyCollectorAttestation: trust must be an object ({ collectorKeys })');
  for (const name of Object.keys(trust))
    if (!COLLECTOR_TRUST_MEMBERS.includes(name))
      throw new TypeError(
        `verifyCollectorAttestation: unknown trust member ${quoteFull(name)}; the trust input is collectorKeys`,
      );
  if (trust.collectorKeys === undefined || trust.collectorKeys === null) return null;
  if (!Array.isArray(trust.collectorKeys))
    throw new TypeError('verifyCollectorAttestation: trust.collectorKeys must be an array');
  // A malformed entry is not a key at all (the section 6.6 rule for supplied issuer keys).
  return trust.collectorKeys.filter(
    (k) =>
      isPlainObject(k) &&
      isIssuingDeployment(k.deployment) &&
      typeof k.tenantRef === 'string' &&
      COLLECTOR_TENANT_REF_RE.test(k.tenantRef) &&
      typeof k.publicKey === 'string' &&
      COLLECTOR_SPKI_RE.test(k.publicKey) &&
      (!hasOwn(k, 'revokedAt') || parseTimestamp(k.revokedAt) !== null),
  );
}

function collectorResult(status, rule, detail, extra = {}) {
  return {
    status,
    rule,
    detail: asciiEscape(detail),
    keySource: null,
    collectorKeyId: null,
    metric: null,
    measuredAt: null,
    revokedAt: null,
    proves: [],
    doesNotProve: [],
    ...extra,
  };
}

/**
 * Checks a collector attestation against a receipt. Resolves to
 * { status: ATTESTED | MISMATCH | UNVERIFIABLE, rule, detail, keySource,
 *   collectorKeyId, metric, measuredAt, revokedAt, proves, doesNotProve }.
 * Separate from the receipt's verdict: ATTESTED means something only next to
 * a VALID (or STALE_VALID) receipt.
 */
export async function verifyCollectorAttestationWith(receipt, attestation, trust, backend) {
  const pinned = pinnedCollectorKeys(trust);
  if (!backend || typeof backend.sha256 !== 'function' || typeof backend.sha512 !== 'function')
    throw new TypeError('proof-verify: options.backend must be a crypto backend');
  if (!backend.hashes)
    return collectorResult(
      'UNVERIFIABLE',
      null,
      'not checked: this runtime has no WebCrypto (crypto.subtle is missing); use the CLI (cmdash-verify) or serve this page over HTTPS',
    );
  const decoded = decodeReceiptPayload(receipt);
  if (decoded.problem)
    return collectorResult('MISMATCH', 'collector.receipt-undecodable', decoded.problem);
  const payload = decoded.payload;

  let doc;
  try {
    doc =
      attestation instanceof Uint8Array || typeof attestation === 'string'
        ? readJsonDocument(attestation, COLLECTOR_ATTESTATION_LIMIT)
        : readJsonDocument(JSON.stringify(attestation) ?? '', COLLECTOR_ATTESTATION_LIMIT);
  } catch (e) {
    if (!(e instanceof StrictJsonError)) throw e;
    return collectorResult(
      'MISMATCH',
      'collector.malformed',
      `the attestation is not acceptable JSON (${e.rule}): ${e.message}`,
    );
  }
  const shape = collectorAttestationProblem(doc);
  if (shape) return collectorResult('MISMATCH', 'collector.malformed', shape);

  const spki = decodeBase64Url(doc.collectorKey.publicKey);
  const kid = COLLECTOR_KID_PREFIX + toHex(await backend.sha256(spki)).slice(0, 16);
  if (kid !== doc.collectorKey.kid)
    return collectorResult(
      'MISMATCH',
      'collector.key-id',
      `the collector key hashes to ${kid}, not ${quoteFull(doc.collectorKey.kid)}`,
    );

  const statementBytes = decodeBase64Url(doc.statement);
  const statementText = statementBytes === null ? null : decodeUtf8Fatal(statementBytes);
  if (statementText === null)
    return collectorResult(
      'MISMATCH',
      'collector.statement-malformed',
      'the statement is not canonical base64url of UTF-8',
    );
  let statement;
  try {
    statement = parseStrictJson(statementText);
  } catch (e) {
    if (!(e instanceof StrictJsonError)) throw e;
    return collectorResult(
      'MISMATCH',
      'collector.statement-malformed',
      `the statement is not JSON (${e.rule})`,
    );
  }
  let canonicalText;
  try {
    canonicalText = canonicalize(statement);
  } catch (e) {
    if (!(e instanceof CanonicalError)) throw e;
    return collectorResult(
      'MISMATCH',
      'collector.statement-malformed',
      `the statement has no canonical form (${e.rule})`,
    );
  }
  if (canonicalText !== statementText)
    return collectorResult(
      'MISMATCH',
      'collector.statement-malformed',
      'the statement bytes are not canonical (the signature covers bytes, so they must have exactly one spelling)',
    );
  const statementProblem = collectorStatementProblem(statement);
  if (statementProblem)
    return collectorResult('MISMATCH', 'collector.statement-malformed', statementProblem);
  if (statement.collectorKeyId !== kid)
    return collectorResult(
      'MISMATCH',
      'collector.statement-key',
      `the statement names the collector key ${statement.collectorKeyId}, not ${kid}`,
    );

  const sig = await verifyEd25519(
    rawPublicKeyOf(spki),
    concatBytes(COLLECTOR_MEASUREMENT_DOMAIN, statementBytes),
    decodeBase64Url(doc.sig),
    backend,
  );
  if (sig.ok === null)
    return collectorResult('UNVERIFIABLE', 'collector.signature', `${sig.rule}: ${sig.detail}`);
  if (!sig.ok)
    return collectorResult(
      'MISMATCH',
      'collector.signature',
      `the collector's signature does not verify (${sig.rule}: ${sig.detail})`,
    );

  const common = { collectorKeyId: kid, metric: statement.metric, measuredAt: statement.measuredAt };
  if (payload.measurement === undefined)
    return collectorResult(
      'MISMATCH',
      'collector.not-measured',
      'the receipt is self-attested: a collector attests measurements only',
      common,
    );
  if (
    statement.deployment !== payload.issuer.deployment ||
    statement.tenantRef !== payload.issuer.tenantRef
  )
    return collectorResult(
      'MISMATCH',
      'collector.issuer',
      `the collector measured for ${quoteFull(statement.tenantRef)} at ${quoteFull(statement.deployment)}, not for this receipt's issuer`,
      common,
    );
  if (!payload.sources.some((s) => s.kind === 'COLLECTOR' && s.ref === kid))
    return collectorResult(
      'MISMATCH',
      'collector.not-named',
      `the receipt's signed sources do not name the collector key ${kid}: the issuer did not vouch that this collector made the measurement`,
      common,
    );
  const m = payload.measurement;
  // The metric is bound too: without it, a statement counting one thing (say
  // mfa-enrolled, 50 of 50) would attest a receipt about another (edr-coverage,
  // 50 of 50) whenever the counts and the instant coincide.
  const method = COLLECTOR_METHOD_RE.exec(m.method.id);
  if (method === null || method[1] !== statement.metric)
    return collectorResult(
      'MISMATCH',
      'collector.metric',
      `the collector measured ${quoteFull(statement.metric)}; the receipt's signed method is ${quoteFull(m.method.id)}, not collector-attested.${statement.metric}.v<N>`,
      common,
    );
  if (
    statement.numerator !== m.numerator ||
    statement.denominator !== m.denominator ||
    statement.unknown !== m.unknown
  )
    return collectorResult(
      'MISMATCH',
      'collector.counts',
      `the collector signed ${statement.numerator} of ${statement.denominator} (${statement.unknown} unknown); the receipt signs ${m.numerator} of ${m.denominator} (${m.unknown} unknown)`,
      common,
    );
  if (statement.measuredAt !== payload.observedAt)
    return collectorResult(
      'MISMATCH',
      'collector.measured-at',
      `the collector measured at ${statement.measuredAt}; the receipt says observed at ${payload.observedAt}. A receipt cannot claim a fresher measurement than the collector signed`,
      common,
    );

  const bound = pinned
    ? pinned.filter(
        (k) =>
          k.publicKey === doc.collectorKey.publicKey &&
          k.deployment === payload.issuer.deployment &&
          k.tenantRef === payload.issuer.tenantRef,
      )
    : [];
  const revocations = [
    ...(hasOwn(doc, 'revokedAt') ? [doc.revokedAt] : []),
    ...bound.filter((k) => hasOwn(k, 'revokedAt')).map((k) => k.revokedAt),
  ].sort();
  const revokedAt = revocations.length > 0 ? revocations[0] : null;
  if (revokedAt !== null && parseTimestamp(revokedAt) <= parseTimestamp(payload.issuedAt))
    return collectorResult(
      'MISMATCH',
      'collector.key-revoked',
      `the collector key was revoked at ${revokedAt}, at or before the receipt was issued (${payload.issuedAt})`,
      { ...common, revokedAt },
    );
  if (pinned !== null && bound.length === 0)
    return collectorResult(
      'UNVERIFIABLE',
      'collector.key-unpinned',
      `none of the collector keys you pinned for this issuer is ${kid}`,
      { ...common, revokedAt },
    );

  const keySource = pinned !== null ? 'PINNED' : 'ISSUER_NAMED';
  const proves = ['collector-signed', 'collector-bound-to-receipt'];
  if (keySource === 'PINNED') proves.push('collector-key-pinned');
  const doesNotProve = [];
  if (keySource === 'ISSUER_NAMED') doesNotProve.push('collector-key-independent');
  doesNotProve.push('collector-source-truth');
  if (revokedAt === null) doesNotProve.push('collector-key-not-revoked');
  const revokedNote =
    revokedAt !== null ? ` The key was REVOKED at ${revokedAt}, after this receipt was issued.` : '';
  return collectorResult(
    'ATTESTED',
    null,
    keySource === 'PINNED'
      ? `ATTESTED by collector key ${kid} (pinned by you): the supplier's collector signed ${statement.numerator} of ${statement.denominator} (${statement.unknown} unknown) for ${statement.metric} at ${statement.measuredAt}.${revokedNote}`
      : `ATTESTED by collector key ${kid}, named by the issuer's signed receipt only (not pinned by you): the collector signed ${statement.numerator} of ${statement.denominator} (${statement.unknown} unknown) for ${statement.metric} at ${statement.measuredAt}.${revokedNote}`,
    { ...common, keySource, revokedAt, proves, doesNotProve },
  );
}
