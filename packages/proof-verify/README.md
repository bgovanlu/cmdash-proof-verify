# CMDash proof verifier

An independent verifier for CMDash proof receipts. It checks a receipt on your
machine and never asks CMDash whether the receipt is valid.

It verifies:

- **Proof receipts**, as specified in [`docs/specs/proof-receipt-v0.md`](../../docs/specs/proof-receipt-v0.md):
  the canonical form, the Ed25519 signature against an issuer key you trust,
  the freshness window, and the transparency log (checkpoint signature, Merkle
  inclusion proof, and consistency between checkpoints).
- **Evidence openings and sampled evidence items** against a receipt.
- **Collector attestations**, as specified in
  [`docs/specs/collector-attestation-v0.md`](../../docs/specs/collector-attestation-v0.md):
  the supplier collector's own signature over the measurement.

The result is one of `VALID`, `INVALID`, `STALE_VALID` or `UNVERIFIABLE`, with
the list of checks that produced it and what the receipt does and does not
prove.

## Properties

- Zero dependencies. Node 22 or later (`node:crypto`), or WebCrypto in a browser.
- The library performs no network access and reads no clock; you pass the
  current time and the trust inputs.
- The command line fetches only when you pass `--fetch`, only from a deployment
  you name with `--deployment`, and follows no redirect.
- Output is printable ASCII: every string that came from an input is escaped.

## Command line

```
node packages/proof-verify/bin/cmdash-verify.mjs receipt.json \
  --deployment https://app.cmdash.com --fetch
```

Exit codes: `0` VALID, `1` INVALID, `2` UNVERIFIABLE (also unreadable input, a
failed fetch or bad usage), `3` STALE_VALID. Run it with no arguments for the
full option list.

## Library

```js
import { verifyReceipt } from '@cmdash/proof-verify';

const result = await verifyReceipt(receiptBytes, {
  now: new Date().toISOString(),
  deployments: ['https://app.cmdash.com'], // the issuing deployments you trust
  keyDocument, // fetched independently
  keyDocumentUrl,
});
result.verdict; // 'VALID' | 'INVALID' | 'STALE_VALID' | 'UNVERIFIABLE'
```

A browser build is at `@cmdash/proof-verify/browser`.

## Tests

The suite runs every vector in `docs/specs/proof-receipt-v0/vectors` and
`docs/specs/collector-attestation-v0/vectors` through the library, the command
line and the browser build:

```
cd packages/proof-verify
node --test "test/*.test.js"
```

## Licence

Apache-2.0. See `LICENSE`.
