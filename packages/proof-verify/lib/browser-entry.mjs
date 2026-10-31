// SPDX-License-Identifier: Apache-2.0
/**
 * The browser build's public API (browser/verify.js is this module with its
 * dependencies concatenated in; see scripts/build-browser.mjs). Same functions
 * as lib/verify.mjs, but WebCrypto is the default backend.
 *
 * Where WebCrypto is missing (a plain-HTTP page: crypto.subtle exists only in
 * secure contexts) or lacks Ed25519, the verdict is UNVERIFIABLE with
 * ed25519.unavailable and "use the CLI", never VALID and never an exception.
 */
import { webCryptoBackend } from './backend-web.mjs';
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
import {
  COLLECTOR_DOES_NOT_PROVE_IDS,
  COLLECTOR_PROVES_IDS,
  COLLECTOR_RULES,
  verifyCollectorAttestationWith,
} from './collector.mjs';

function browserBackendOf(options) {
  if (options && options.backend !== undefined) return options.backend;
  const cryptoObject =
    typeof globalThis === 'object' && globalThis !== null ? globalThis.crypto : undefined;
  return webCryptoBackend(cryptoObject);
}

/** Verifies a receipt (spec section 9) with WebCrypto. Resolves to the section 9.4 result. */
export function verifyReceipt(receipt, trust, options) {
  return verifyReceiptWith(receipt, trust, browserBackendOf(options));
}

/** Checks an evidence opening against a receipt (spec section 8.2). */
export function verifyEvidenceOpening(receipt, opening, options) {
  return verifyEvidenceOpeningWith(receipt, opening, browserBackendOf(options));
}

/** Checks one sampled evidence item (spec section 8.3). */
export function verifyEvidenceItem(receipt, opening, item, options) {
  return verifyEvidenceItemWith(receipt, opening, item, browserBackendOf(options));
}

/** Checks a collector attestation against a receipt (docs/specs/collector-attestation-v0.md). */
export function verifyCollectorAttestation(receipt, attestation, trust, options) {
  return verifyCollectorAttestationWith(receipt, attestation, trust, browserBackendOf(options));
}

/** Checks that the log's checkpoint `to` extends its checkpoint `from` (spec section 7.9). */
export function verifyCheckpointConsistency(input, trust, options) {
  return verifyCheckpointConsistencyWith(input, trust, browserBackendOf(options));
}

/**
 * The UNVERIFIED routing facts for a one-click fetch (P5): the deployment to
 * show the user and ask them to confirm, the key document URL, the digest for
 * the inclusion route, the log section's tree size. Never display as verified.
 */
export function inspectReceipt(receipt, options) {
  return inspectReceiptWith(receipt, browserBackendOf(options));
}

export {
  CHECK_NAMES,
  COLLECTOR_DOES_NOT_PROVE_IDS,
  COLLECTOR_PROVES_IDS,
  COLLECTOR_RULES,
  CONSISTENCY_CHECK_NAMES,
  DOES_NOT_PROVE_IDS,
  PROVES_IDS,
  TRUST_MEMBERS,
  keyDocumentUrlOf,
  truncatedPercent,
  webCryptoBackend,
};
