// SPDX-License-Identifier: Apache-2.0
/**
 * Hand-written structural validators for docs/specs/proof-receipt-v0/
 * receipt.schema.json (JSON Schema 2020-12), with no validator dependency.
 * The patterns below are the schema's own, copied verbatim;
 * test/schema.test.js fails if they drift from the schema file.
 *
 * Every validator returns a list of problems (empty when the value is valid).
 * A problem is ASCII text: member names that came from the input are quoted
 * and escaped (spec section 9.5).
 *
 * Semantics followed where the schema language is subtle:
 *   - string lengths count code points, as JSON Schema does;
 *   - "integer" is a number with no fractional part (so -0 is one);
 *   - uniqueItems compares items by value.
 *
 * What a schema cannot check (duplicate member names, the canonical bytes, a
 * signature, the arithmetic, key status, the log, time) is checked elsewhere;
 * the calendar rule of spec section 4 (no 30 February) is checked here,
 * because a timestamp that is not a real instant is a structural defect.
 */
import { codePointLength } from './bytes.mjs';
import { hasOwn, isPlainObject } from './canonical.mjs';
import { describeValue, quote } from './escape.mjs';

export const SCHEMA_PATTERNS = Object.freeze({
  payloadBase64Url:
    '^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$',
  ulid: '^[0-7][0-9A-HJKMNP-TV-Z]{25}$',
  tenantRef: '^tr_[0-9a-f]{32}$',
  deployment:
    '^(?:https://(?=[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$)(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(?::(?!443$)(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?|http://(?:localhost|127\\.0\\.0\\.1)(?::(?!80$)(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?)$',
  plainHttpDeployment:
    '^http://(?=[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$)(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(?::(?!80$)(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$',
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
  text: '^[^\\u{0}-\\u{1F}\\u{7F}-\\u{9F}\\u{AD}\\u{34F}\\u{61C}\\u{115F}\\u{1160}\\u{17B4}\\u{17B5}\\u{180B}-\\u{180F}\\u{200B}-\\u{200F}\\u{2028}-\\u{202E}\\u{2060}-\\u{206F}\\u{3164}\\u{E000}-\\u{F8FF}\\u{FE00}-\\u{FE0F}\\u{FEFF}\\u{FFA0}\\u{FFF0}-\\u{FFFB}\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E0FFF}\\u{F0000}-\\u{10FFFF}]+$',
  spki: '^MCowBQYDK2VwAyEA[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$',
  signature: '^[A-Za-z0-9_-]{85}[AQgw]$',
  origin: '^[!-*,-~]{1,255}$',
});

/** The compiled patterns (Unicode mode, as ajv applies them). */
export const SCHEMA_RE = Object.freeze(
  Object.fromEntries(Object.entries(SCHEMA_PATTERNS).map(([k, v]) => [k, new RegExp(v, 'u')])),
);

const MAX_SAFE = 9007199254740991;
const ORDINAL_OF = (i) => `[${i}]`;

/** Milliseconds since the epoch for a spec section 4 timestamp that is a real calendar instant, else null. */
export function parseTimestamp(s) {
  if (typeof s !== 'string' || !SCHEMA_RE.timestamp.test(s)) return null;
  const t = Date.UTC(
    Number(s.slice(0, 4)),
    Number(s.slice(5, 7)) - 1,
    Number(s.slice(8, 10)),
    Number(s.slice(11, 13)),
    Number(s.slice(14, 16)),
    Number(s.slice(17, 19)),
    Number(s.slice(20, 23)),
  );
  // The round trip is the calendar rule: 30 February rolls over to March and comes back different.
  if (!Number.isFinite(t) || new Date(t).toISOString() !== s) return null;
  return t;
}

/** A canonical origin (spec section 6.2) of either kind: https, loopback http, or plain http. */
export function isIssuingDeployment(s) {
  return (
    typeof s === 'string' && (SCHEMA_RE.deployment.test(s) || SCHEMA_RE.plainHttpDeployment.test(s))
  );
}

/** A plain-http origin on a host other than localhost or 127.0.0.1. */
export function isPlainHttpNonLoopback(s) {
  return (
    typeof s === 'string' && SCHEMA_RE.plainHttpDeployment.test(s) && !SCHEMA_RE.deployment.test(s)
  );
}

class ProblemList {
  constructor() {
    this.list = [];
  }

  add(path, message) {
    this.list.push(`${path}: ${message}`);
  }

  /** An object with exactly the required members and, optionally, the optional ones. */
  object(path, v, required, optional = []) {
    if (!isPlainObject(v)) {
      this.add(path, `must be an object, not ${describeValue(v)}`);
      return false;
    }
    for (const name of Object.keys(v)) {
      if (!required.includes(name) && !optional.includes(name))
        this.add(path, `unknown member ${quote(name)}`);
    }
    for (const name of required) if (!hasOwn(v, name)) this.add(path, `missing member "${name}"`);
    return true;
  }

  string(path, v, pattern, { min = 0, max = Infinity } = {}) {
    if (typeof v !== 'string') return this.add(path, `must be a string, not ${describeValue(v)}`);
    const len = codePointLength(v);
    if (len < min) this.add(path, `must have at least ${min} character(s)`);
    if (len > max) this.add(path, `must have at most ${max} characters, not ${len}`);
    if (pattern && !SCHEMA_RE[pattern].test(v))
      this.add(path, `${quote(v)} does not match the ${pattern} pattern`);
    return undefined;
  }

  integer(path, v, min, max) {
    if (typeof v !== 'number' || !Number.isInteger(v))
      return this.add(path, `must be an integer, not ${describeValue(v)}`);
    if (v < min || v > max) this.add(path, `${v} is outside ${min}..${max}`);
    return undefined;
  }

  constant(path, v, c) {
    if (v !== c)
      this.add(path, `must be ${typeof c === 'string' ? `"${c}"` : c}, not ${describeValue(v)}`);
  }

  oneOf(path, v, values) {
    if (!values.includes(v))
      this.add(path, `must be one of ${values.join(', ')}, not ${describeValue(v)}`);
  }

  timestamp(path, v) {
    if (typeof v !== 'string' || !SCHEMA_RE.timestamp.test(v)) {
      return this.add(
        path,
        `must be a timestamp YYYY-MM-DDTHH:MM:SS.sssZ (years 1970-9999), not ${describeValue(v)}`,
      );
    }
    if (parseTimestamp(v) === null) this.add(path, `${quote(v)} is not a real calendar instant`);
    return undefined;
  }

  array(path, v, { min = 0, max = Infinity } = {}) {
    if (!Array.isArray(v)) {
      this.add(path, `must be an array, not ${describeValue(v)}`);
      return false;
    }
    if (v.length < min) this.add(path, `must have at least ${min} item(s)`);
    if (v.length > max) this.add(path, `must have at most ${max} items, not ${v.length}`);
    return true;
  }

  /** uniqueItems over items already shaped as objects of string members. */
  unique(path, items, fields) {
    const seen = new Set();
    items.forEach((item, i) => {
      if (!isPlainObject(item)) return;
      const key = JSON.stringify(fields.map((f) => item[f]).concat(Object.keys(item).length));
      if (seen.has(key))
        this.add(`${path}${ORDINAL_OF(i)}`, 'repeats an earlier item (uniqueItems)');
      seen.add(key);
    });
  }
}

function issuerInto(p, path, v) {
  if (!p.object(path, v, ['deployment', 'tenantRef', 'keyId'])) return;
  if (hasOwn(v, 'deployment') && !isIssuingDeployment(v.deployment)) {
    p.add(
      `${path}.deployment`,
      `${describeValue(v.deployment)} is not a canonical origin (spec section 6.2)`,
    );
  }
  if (hasOwn(v, 'tenantRef')) p.string(`${path}.tenantRef`, v.tenantRef, 'tenantRef');
  if (hasOwn(v, 'keyId')) p.string(`${path}.keyId`, v.keyId, 'issuerKid');
}

function methodInto(p, path, v) {
  if (!p.object(path, v, ['id', 'version'])) return;
  if (hasOwn(v, 'id')) p.string(`${path}.id`, v.id, 'methodId');
  if (hasOwn(v, 'version')) p.integer(`${path}.version`, v.version, 1, 1000000);
}

function selfAttestedInto(p, path, v) {
  if (!p.object(path, v, ['byRole', 'at'])) return;
  if (hasOwn(v, 'byRole')) p.string(`${path}.byRole`, v.byRole, 'role');
  if (hasOwn(v, 'at')) p.timestamp(`${path}.at`, v.at);
}

function countsInto(p, path, v) {
  if (!p.object(path, v, ['numerator', 'denominator', 'unknown'])) return;
  for (const f of ['numerator', 'denominator', 'unknown'])
    if (hasOwn(v, f)) p.integer(`${path}.${f}`, v[f], 0, 1000000000);
}

function assertionInto(p, path, v) {
  if (!isPlainObject(v)) return p.add(path, `must be an object, not ${describeValue(v)}`);
  const kind = v.kind;
  if (kind === 'ALL' || kind === 'RATIO' || kind === 'SELF_ATTESTED')
    return p.object(path, v, ['kind']);
  if (kind === 'AT_LEAST') {
    if (!p.object(path, v, ['kind', 'threshold'])) return undefined;
    const t = v.threshold;
    if (hasOwn(v, 'threshold') && p.object(`${path}.threshold`, t, ['numerator', 'denominator'])) {
      if (hasOwn(t, 'numerator')) p.integer(`${path}.threshold.numerator`, t.numerator, 1, 1000000);
      if (hasOwn(t, 'denominator'))
        p.integer(`${path}.threshold.denominator`, t.denominator, 2, 1000000);
    }
    return undefined;
  }
  if (kind === 'SCORE') {
    if (!p.object(path, v, ['kind', 'value', 'min', 'max'])) return undefined;
    for (const f of ['value', 'min', 'max'])
      if (hasOwn(v, f)) p.integer(`${path}.${f}`, v[f], -1000000000, 1000000000);
    return undefined;
  }
  return p.add(
    `${path}.kind`,
    `must be one of ALL, AT_LEAST, RATIO, SCORE, SELF_ATTESTED, not ${describeValue(kind)}`,
  );
}

function logSectionInto(p, path, v) {
  if (!p.object(path, v, ['index', 'treeSize', 'rootHash', 'proof', 'checkpoint'])) return;
  if (hasOwn(v, 'index')) p.integer(`${path}.index`, v.index, 0, MAX_SAFE);
  if (hasOwn(v, 'treeSize')) p.integer(`${path}.treeSize`, v.treeSize, 1, MAX_SAFE);
  if (hasOwn(v, 'rootHash')) p.string(`${path}.rootHash`, v.rootHash, 'hex32');
  if (hasOwn(v, 'proof') && p.array(`${path}.proof`, v.proof, { max: 64 })) {
    v.proof.forEach((h, i) => p.string(`${path}.proof${ORDINAL_OF(i)}`, h, 'hex32'));
  }
  if (hasOwn(v, 'checkpoint'))
    p.string(`${path}.checkpoint`, v.checkpoint, null, { min: 1, max: 8192 });
}

/** The schema's root: the envelope (spec section 2). */
export function envelopeProblems(env) {
  const p = new ProblemList();
  if (!p.object('the envelope', env, ['v', 'payload', 'sig'], ['log', 'issuerKey'])) return p.list;
  if (hasOwn(env, 'v')) p.constant('v', env.v, 0);
  if (hasOwn(env, 'payload'))
    p.string('payload', env.payload, 'payloadBase64Url', { min: 2, max: 21846 });
  if (hasOwn(env, 'sig') && p.object('sig', env.sig, ['alg', 'kid', 'value'])) {
    const s = env.sig;
    if (hasOwn(s, 'alg')) p.constant('sig.alg', s.alg, 'Ed25519');
    if (hasOwn(s, 'kid')) p.string('sig.kid', s.kid, 'issuerKid');
    if (hasOwn(s, 'value')) p.string('sig.value', s.value, 'signature');
  }
  if (hasOwn(env, 'log')) logSectionInto(p, 'log', env.log);
  if (
    hasOwn(env, 'issuerKey') &&
    p.object('issuerKey', env.issuerKey, ['kid', 'alg', 'publicKey'])
  ) {
    const k = env.issuerKey;
    if (hasOwn(k, 'kid')) p.string('issuerKey.kid', k.kid, 'issuerKid');
    if (hasOwn(k, 'alg')) p.constant('issuerKey.alg', k.alg, 'Ed25519');
    if (hasOwn(k, 'publicKey')) p.string('issuerKey.publicKey', k.publicKey, 'spki');
  }
  return p.list;
}

/** #/$defs/logSection: a log section the relying party supplies (spec section 7.6). */
export function logSectionProblems(v) {
  const p = new ProblemList();
  logSectionInto(p, 'the log section', v);
  return p.list;
}

/** #/$defs/payload (spec section 5), with the calendar rule for its timestamps. */
export function payloadProblems(pl) {
  const p = new ProblemList();
  const required = [
    'receiptId',
    'issuer',
    'claim',
    'sources',
    'observedAt',
    'issuedAt',
    'freshUntil',
    'evidence',
  ];
  if (!p.object('the payload', pl, required, ['measurement', 'selfAttested', 'supersedes']))
    return p.list;
  if (hasOwn(pl, 'receiptId')) p.string('receiptId', pl.receiptId, 'ulid');
  if (hasOwn(pl, 'issuer')) issuerInto(p, 'issuer', pl.issuer);
  if (
    hasOwn(pl, 'claim') &&
    p.object('claim', pl.claim, ['claimId', 'statement', 'controls', 'assertion'])
  ) {
    const c = pl.claim;
    if (hasOwn(c, 'claimId')) p.string('claim.claimId', c.claimId, 'claimId');
    if (hasOwn(c, 'statement'))
      p.string('claim.statement', c.statement, 'text', { min: 1, max: 500 });
    if (hasOwn(c, 'controls') && p.array('claim.controls', c.controls, { max: 64 })) {
      c.controls.forEach((ctl, i) => {
        const at = `claim.controls${ORDINAL_OF(i)}`;
        if (!p.object(at, ctl, ['framework', 'controlId'])) return;
        if (hasOwn(ctl, 'framework')) p.string(`${at}.framework`, ctl.framework, 'framework');
        if (hasOwn(ctl, 'controlId')) p.string(`${at}.controlId`, ctl.controlId, 'controlId');
      });
      p.unique('claim.controls', c.controls, ['framework', 'controlId']);
    }
    if (hasOwn(c, 'assertion')) assertionInto(p, 'claim.assertion', c.assertion);
  }
  if (
    hasOwn(pl, 'measurement') &&
    p.object('measurement', pl.measurement, [
      'numerator',
      'denominator',
      'unknown',
      'scope',
      'method',
    ])
  ) {
    const m = pl.measurement;
    for (const f of ['numerator', 'denominator', 'unknown'])
      if (hasOwn(m, f)) p.integer(`measurement.${f}`, m[f], 0, 1000000000);
    if (hasOwn(m, 'scope') && p.object('measurement.scope', m.scope, ['unit', 'description'])) {
      if (hasOwn(m.scope, 'unit')) p.string('measurement.scope.unit', m.scope.unit, 'unit');
      if (hasOwn(m.scope, 'description'))
        p.string('measurement.scope.description', m.scope.description, 'text', {
          min: 1,
          max: 300,
        });
    }
    if (hasOwn(m, 'method')) methodInto(p, 'measurement.method', m.method);
  }
  if (hasOwn(pl, 'selfAttested')) selfAttestedInto(p, 'selfAttested', pl.selfAttested);
  if (hasOwn(pl, 'sources') && p.array('sources', pl.sources, { min: 1, max: 16 })) {
    pl.sources.forEach((s, i) => {
      const at = `sources${ORDINAL_OF(i)}`;
      if (!p.object(at, s, ['kind', 'ref'])) return;
      if (hasOwn(s, 'kind'))
        p.oneOf(`${at}.kind`, s.kind, ['INTEGRATION', 'COLLECTOR', 'TENANT_RECORD', 'PERSON']);
      if (hasOwn(s, 'ref')) p.string(`${at}.ref`, s.ref, 'sourceRef');
    });
    p.unique('sources', pl.sources, ['kind', 'ref']);
  }
  for (const f of ['observedAt', 'issuedAt', 'freshUntil'])
    if (hasOwn(pl, f)) p.timestamp(f, pl[f]);
  if (hasOwn(pl, 'evidence') && p.object('evidence', pl.evidence, ['algo', 'commitment'])) {
    if (hasOwn(pl.evidence, 'algo')) p.constant('evidence.algo', pl.evidence.algo, 'sha256-salted');
    if (hasOwn(pl.evidence, 'commitment'))
      p.string('evidence.commitment', pl.evidence.commitment, 'hex32');
  }
  if (hasOwn(pl, 'supersedes')) p.string('supersedes', pl.supersedes, 'ulid');

  // The schema's if/then/else on the assertion kind.
  const assertion = isPlainObject(pl.claim) ? pl.claim.assertion : undefined;
  const selfAttestedKind =
    !isPlainObject(assertion) || !hasOwn(assertion, 'kind') || assertion.kind === 'SELF_ATTESTED';
  const sources = Array.isArray(pl.sources) ? pl.sources : [];
  if (selfAttestedKind) {
    if (!hasOwn(pl, 'selfAttested'))
      p.add('the payload', 'a SELF_ATTESTED claim needs "selfAttested"');
    if (hasOwn(pl, 'measurement'))
      p.add('the payload', 'a SELF_ATTESTED claim must not carry "measurement"');
    sources.forEach((s, i) => {
      if (isPlainObject(s) && hasOwn(s, 'kind') && s.kind !== 'PERSON')
        p.add(
          `sources${ORDINAL_OF(i)}.kind`,
          'a SELF_ATTESTED receipt names only the PERSON source',
        );
      if (isPlainObject(s) && hasOwn(s, 'ref') && s.ref !== 'self-attestation')
        p.add(`sources${ORDINAL_OF(i)}.ref`, 'must be "self-attestation"');
    });
  } else {
    if (!hasOwn(pl, 'measurement')) p.add('the payload', 'a measured claim needs "measurement"');
    if (hasOwn(pl, 'selfAttested'))
      p.add('the payload', 'a measured claim must not carry "selfAttested"');
    sources.forEach((s, i) => {
      if (isPlainObject(s) && s.kind === 'PERSON')
        p.add(`sources${ORDINAL_OF(i)}.kind`, 'a measured receipt never names a PERSON source');
    });
  }
  return p.list;
}

function issuerKeyEntryInto(p, path, v) {
  if (
    !p.object(
      path,
      v,
      ['kid', 'alg', 'publicKey', 'status', 'validFrom'],
      ['validUntil', 'revokedAt', 'revocationReason', 'lastTreeSize'],
    )
  )
    return;
  if (hasOwn(v, 'kid')) p.string(`${path}.kid`, v.kid, 'issuerKid');
  if (hasOwn(v, 'alg')) p.constant(`${path}.alg`, v.alg, 'Ed25519');
  if (hasOwn(v, 'publicKey')) p.string(`${path}.publicKey`, v.publicKey, 'spki');
  if (hasOwn(v, 'status')) p.oneOf(`${path}.status`, v.status, ['ACTIVE', 'RETIRED', 'REVOKED']);
  if (hasOwn(v, 'validFrom')) p.timestamp(`${path}.validFrom`, v.validFrom);
  if (hasOwn(v, 'validUntil')) p.timestamp(`${path}.validUntil`, v.validUntil);
  if (hasOwn(v, 'revokedAt')) p.timestamp(`${path}.revokedAt`, v.revokedAt);
  if (hasOwn(v, 'revocationReason'))
    p.oneOf(`${path}.revocationReason`, v.revocationReason, ['KEY_COMPROMISE', 'ISSUER_REQUEST']);
  if (hasOwn(v, 'lastTreeSize')) p.integer(`${path}.lastTreeSize`, v.lastTreeSize, 0, MAX_SAFE);
  const forbid = (names) =>
    names.forEach((n) => hasOwn(v, n) && p.add(path, `a ${v.status} key must not carry "${n}"`));
  const need = (names) =>
    names.forEach((n) => !hasOwn(v, n) && p.add(path, `a ${v.status} key needs "${n}"`));
  if (v.status === 'ACTIVE')
    forbid(['validUntil', 'revokedAt', 'revocationReason', 'lastTreeSize']);
  if (v.status === 'RETIRED') {
    need(['validUntil']);
    forbid(['revokedAt', 'revocationReason']);
  }
  if (v.status === 'REVOKED') need(['revokedAt', 'revocationReason']);
}

function logKeyEntryInto(p, path, v) {
  if (
    !p.object(
      path,
      v,
      ['kid', 'alg', 'publicKey', 'status', 'validFrom'],
      ['validUntil', 'lastTreeSize'],
    )
  )
    return;
  if (hasOwn(v, 'kid')) p.string(`${path}.kid`, v.kid, 'logKid');
  if (hasOwn(v, 'alg')) p.constant(`${path}.alg`, v.alg, 'Ed25519');
  if (hasOwn(v, 'publicKey')) p.string(`${path}.publicKey`, v.publicKey, 'spki');
  if (hasOwn(v, 'status')) p.oneOf(`${path}.status`, v.status, ['ACTIVE', 'RETIRED', 'REVOKED']);
  if (hasOwn(v, 'validFrom')) p.timestamp(`${path}.validFrom`, v.validFrom);
  if (hasOwn(v, 'validUntil')) p.timestamp(`${path}.validUntil`, v.validUntil);
  if (hasOwn(v, 'lastTreeSize')) p.integer(`${path}.lastTreeSize`, v.lastTreeSize, 0, MAX_SAFE);
  const forbid = (names) =>
    names.forEach(
      (n) => hasOwn(v, n) && p.add(path, `a ${v.status} log key must not carry "${n}"`),
    );
  const need = (names) =>
    names.forEach((n) => !hasOwn(v, n) && p.add(path, `a ${v.status} log key needs "${n}"`));
  if (v.status === 'ACTIVE') forbid(['validUntil', 'lastTreeSize']);
  if (v.status === 'RETIRED') need(['validUntil', 'lastTreeSize']);
  if (v.status === 'REVOKED') need(['validUntil']);
}

function logKeyDocumentInto(p, path, v) {
  if (!p.object(path, v, ['format', 'v', 'generatedAt', 'origin', 'keys'])) return;
  if (hasOwn(v, 'format')) p.constant(`${path}.format`, v.format, 'cmdash-proof-log-keys');
  if (hasOwn(v, 'v')) p.constant(`${path}.v`, v.v, 0);
  if (hasOwn(v, 'generatedAt')) p.timestamp(`${path}.generatedAt`, v.generatedAt);
  if (hasOwn(v, 'origin')) p.string(`${path}.origin`, v.origin, 'origin');
  if (hasOwn(v, 'keys') && p.array(`${path}.keys`, v.keys, { min: 1, max: 64 })) {
    v.keys.forEach((k, i) => logKeyEntryInto(p, `${path}.keys${ORDINAL_OF(i)}`, k));
  }
}

/** #/$defs/logKeyDocument (spec section 7.4). */
export function logKeyDocumentProblems(v) {
  const p = new ProblemList();
  logKeyDocumentInto(p, 'the log key document', v);
  return p.list;
}

/** #/$defs/keyDocument (spec section 6.3), its embedded log key document included. */
export function keyDocumentProblems(v) {
  const p = new ProblemList();
  if (
    !p.object(
      'the key document',
      v,
      ['format', 'v', 'deployment', 'tenantRef', 'generatedAt', 'keys'],
      ['log'],
    )
  )
    return p.list;
  if (hasOwn(v, 'format')) p.constant('format', v.format, 'cmdash-proof-keys');
  if (hasOwn(v, 'v')) p.constant('v', v.v, 0);
  if (hasOwn(v, 'deployment') && !isIssuingDeployment(v.deployment)) {
    p.add(
      'deployment',
      `${describeValue(v.deployment)} is not a canonical origin (spec section 6.2)`,
    );
  }
  if (hasOwn(v, 'tenantRef')) p.string('tenantRef', v.tenantRef, 'tenantRef');
  if (hasOwn(v, 'generatedAt')) p.timestamp('generatedAt', v.generatedAt);
  if (hasOwn(v, 'keys') && p.array('keys', v.keys, { min: 1, max: 1024 })) {
    v.keys.forEach((k, i) => issuerKeyEntryInto(p, `keys${ORDINAL_OF(i)}`, k));
  }
  if (hasOwn(v, 'log')) logKeyDocumentInto(p, 'log', v.log);
  return p.list;
}

/**
 * The malformation rules of spec section 6.3 that a schema cannot express,
 * for a schema-valid key list: a repeated key id, more than one ACTIVE key,
 * a window that ends before it starts. (The rule "a key that does not hash to
 * its id" needs SHA-256 and is checked by the caller.)
 */
export function keyListRuleProblems(keys, what) {
  const p = new ProblemList();
  const seen = new Set();
  let active = 0;
  keys.forEach((k, i) => {
    const at = `${what}${ORDINAL_OF(i)}`;
    if (seen.has(k.kid)) p.add(at, `repeats the key id ${quote(k.kid)}`);
    seen.add(k.kid);
    if (k.status === 'ACTIVE') active += 1;
    const from = parseTimestamp(k.validFrom);
    if (k.validUntil !== undefined && parseTimestamp(k.validUntil) <= from)
      p.add(at, 'validUntil is not after validFrom');
    if (k.revokedAt !== undefined && parseTimestamp(k.revokedAt) < from)
      p.add(at, 'revokedAt is before validFrom');
  });
  if (active > 1) p.add(what, `lists ${active} ACTIVE keys; at most one may be ACTIVE`);
  return p.list;
}

function manifestInto(p, path, v) {
  const required = ['receiptId', 'issuer', 'claimId', 'observedAt', 'itemCount', 'itemsRoot'];
  if (!p.object(path, v, required, ['counts', 'method', 'selfAttested'])) return;
  if (hasOwn(v, 'receiptId')) p.string(`${path}.receiptId`, v.receiptId, 'ulid');
  if (hasOwn(v, 'issuer')) issuerInto(p, `${path}.issuer`, v.issuer);
  if (hasOwn(v, 'claimId')) p.string(`${path}.claimId`, v.claimId, 'claimId');
  if (hasOwn(v, 'observedAt')) p.timestamp(`${path}.observedAt`, v.observedAt);
  if (hasOwn(v, 'itemCount')) p.integer(`${path}.itemCount`, v.itemCount, 0, MAX_SAFE);
  if (hasOwn(v, 'itemsRoot')) p.string(`${path}.itemsRoot`, v.itemsRoot, 'hex32');
  if (hasOwn(v, 'counts')) countsInto(p, `${path}.counts`, v.counts);
  if (hasOwn(v, 'method')) methodInto(p, `${path}.method`, v.method);
  if (hasOwn(v, 'selfAttested')) selfAttestedInto(p, `${path}.selfAttested`, v.selfAttested);
  const measured = hasOwn(v, 'counts') && hasOwn(v, 'method') && !hasOwn(v, 'selfAttested');
  const attested = hasOwn(v, 'selfAttested') && !hasOwn(v, 'counts') && !hasOwn(v, 'method');
  if (!measured && !attested)
    p.add(
      path,
      'must carry either "counts" and "method" (measured) or "selfAttested", not both or neither',
    );
}

/** #/$defs/evidenceOpening (spec section 8.2). */
export function openingProblems(v) {
  const p = new ProblemList();
  if (!p.object('the opening', v, ['format', 'v', 'receiptId', 'salt', 'manifest'])) return p.list;
  if (hasOwn(v, 'format')) p.constant('format', v.format, 'cmdash-evidence-opening');
  if (hasOwn(v, 'v')) p.constant('v', v.v, 0);
  if (hasOwn(v, 'receiptId')) p.string('receiptId', v.receiptId, 'ulid');
  if (hasOwn(v, 'salt')) p.string('salt', v.salt, 'hex32');
  if (hasOwn(v, 'manifest')) manifestInto(p, 'manifest', v.manifest);
  return p.list;
}

/** #/$defs/evidenceItem (spec section 8.3). */
export function itemProblems(v) {
  const p = new ProblemList();
  if (
    !p.object('the item disclosure', v, [
      'format',
      'v',
      'receiptId',
      'index',
      'itemCount',
      'salt',
      'item',
      'proof',
    ])
  )
    return p.list;
  if (hasOwn(v, 'format')) p.constant('format', v.format, 'cmdash-evidence-item');
  if (hasOwn(v, 'v')) p.constant('v', v.v, 0);
  if (hasOwn(v, 'receiptId')) p.string('receiptId', v.receiptId, 'ulid');
  if (hasOwn(v, 'index')) p.integer('index', v.index, 0, MAX_SAFE);
  if (hasOwn(v, 'itemCount')) p.integer('itemCount', v.itemCount, 1, MAX_SAFE);
  if (hasOwn(v, 'salt')) p.string('salt', v.salt, 'hex32');
  if (hasOwn(v, 'item') && !isPlainObject(v.item))
    p.add('item', `must be an object, not ${describeValue(v.item)}`);
  if (hasOwn(v, 'proof') && p.array('proof', v.proof, { max: 64 }))
    v.proof.forEach((h, i) => p.string(`proof${ORDINAL_OF(i)}`, h, 'hex32'));
  return p.list;
}

/** #/$defs/attestationItem: item 0 of a self-attested receipt (spec section 5.2). */
export function attestationItemProblems(v) {
  const p = new ProblemList();
  if (!p.object('item 0', v, ['statement', 'userId'])) return p.list;
  if (hasOwn(v, 'statement'))
    p.string('item 0 statement', v.statement, 'text', { min: 1, max: 500 });
  if (hasOwn(v, 'userId')) p.string('item 0 userId', v.userId, 'userId');
  return p.list;
}
