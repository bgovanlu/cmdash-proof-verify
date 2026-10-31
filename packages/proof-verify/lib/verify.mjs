// SPDX-License-Identifier: Apache-2.0
/**
 * @cmdash/proof-verify: the independent verifier for CMDash proof receipts
 * (docs/specs/proof-receipt-v0.md). Verification never needs CMDash: this
 * library performs no network access and reads no clock.
 *
 *   import { verifyReceipt } from '@cmdash/proof-verify';
 *   const result = await verifyReceipt(receiptBytes, {
 *     now: new Date().toISOString(),
 *     deployments: ['https://app.cmdash.com'],       // the issuing deployments YOU trust
 *     keyDocument, keyDocumentUrl,                   // fetched independently, with its URL
 *   });
 *   result.verdict; // 'VALID' | 'INVALID' | 'STALE_VALID' | 'UNVERIFIABLE'
 *
 * The second argument is the spec section 9.1 trust input (now, deployments,
 * allowPlainHttp, keyDocument, keyDocumentUrl, publicKeys, logKeys,
 * logSection, checkpoint, requireLogged); the result is the section 9.4 shape
 * (packages/shared/src/proof/types.ts: ProofVerification).
 *
 * Node entry: node:crypto by default. `options.backend` selects another crypto
 * backend, e.g. webCryptoBackend(globalThis.crypto), the browser path.
 */
import { nodeBackend } from './backend-node.mjs';
import { webCryptoBackend } from './backend-web.mjs';
import { canonicalize } from './canonical.mjs';
import { CONSISTENCY_CHECK_NAMES, verifyCheckpointConsistencyWith } from './consistency.mjs';
import {
  CHECK_NAMES,
  DOES_NOT_PROVE_IDS,
  PROVES_IDS,
  TRUST_MEMBERS,
  inspectReceiptWith,
  keyDocumentUrlOf,
  truncatedPercent,
  verifyEvidenceItemWith,
  verifyEvidenceOpeningWith,
  verifyReceiptWith,
} from './core.mjs';
import { JSON_LIMITS, StrictJsonError, parseStrictJson, readJsonDocument } from './json.mjs';
import {
  COLLECTOR_DOES_NOT_PROVE_IDS,
  COLLECTOR_PROVES_IDS,
  COLLECTOR_RULES,
  verifyCollectorAttestationWith,
} from './collector.mjs';

function backendOf(options) {
  return options && options.backend !== undefined ? options.backend : nodeBackend;
}

/** Verifies a receipt (spec section 9). Resolves to the section 9.4 result. */
export function verifyReceipt(receipt, trust, options) {
  return verifyReceiptWith(receipt, trust, backendOf(options));
}

/** Checks an evidence opening against a receipt (spec section 8.2): { match, rule, detail }. */
export function verifyEvidenceOpening(receipt, opening, options) {
  return verifyEvidenceOpeningWith(receipt, opening, backendOf(options));
}

/** Checks one sampled evidence item (spec section 8.3): { match, rule, detail }. */
export function verifyEvidenceItem(receipt, opening, item, options) {
  return verifyEvidenceItemWith(receipt, opening, item, backendOf(options));
}

/**
 * Checks a collector attestation against a receipt
 * (docs/specs/collector-attestation-v0.md): { status: ATTESTED | MISMATCH |
 * UNVERIFIABLE, rule, detail, keySource, ... }. `trust` is optional:
 * { collectorKeys: [{ deployment, tenantRef, publicKey, revokedAt? }] }, keys
 * you obtained from the supplier. Separate from the receipt's verdict.
 */
export function verifyCollectorAttestation(receipt, attestation, trust, options) {
  return verifyCollectorAttestationWith(receipt, attestation, trust, backendOf(options));
}

/**
 * Checks that the log's newer signed checkpoint `to` extends its older one
 * `from` (spec section 7.9, RFC 9162 consistency): { verdict: CONSISTENT |
 * INCONSISTENT | UNVERIFIABLE, checks, from, to, summary }.
 */
export function verifyCheckpointConsistency(input, trust, options) {
  return verifyCheckpointConsistencyWith(input, trust, backendOf(options));
}

/**
 * The UNVERIFIED routing facts a caller needs to fetch trust inputs (deployment,
 * key document URL, digest, log tree size). Never display them as verified.
 */
export function inspectReceipt(receipt, options) {
  return inspectReceiptWith(receipt, backendOf(options));
}

export {
  CHECK_NAMES,
  COLLECTOR_DOES_NOT_PROVE_IDS,
  COLLECTOR_PROVES_IDS,
  COLLECTOR_RULES,
  CONSISTENCY_CHECK_NAMES,
  DOES_NOT_PROVE_IDS,
  JSON_LIMITS,
  PROVES_IDS,
  StrictJsonError,
  TRUST_MEMBERS,
  canonicalize,
  keyDocumentUrlOf,
  nodeBackend,
  parseStrictJson,
  readJsonDocument,
  truncatedPercent,
  webCryptoBackend,
};
