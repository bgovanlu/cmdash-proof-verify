# Security policy

## Reporting a vulnerability

Email **security@cmdash.com**. Please do not open a public issue or pull
request for a security problem.

Include the version (`package.json`), the receipt, key document or other input
that triggers it (redact anything private), and what you expected the verifier
to say.

## What counts

The verifier's job is to refuse what it cannot establish. These are
vulnerabilities:

- A forged, altered or unsigned receipt, checkpoint, key document, evidence
  opening or collector attestation that gets `VALID` or `STALE_VALID`.
- An input that makes the verifier read outside what it was given, run for an
  unbounded time or memory, or print a control or non-ASCII character.
- A fetch from an origin that was not named with `--deployment`, or a followed
  redirect.

A receipt that is correctly marked `INVALID` or `UNVERIFIABLE` is not.

## Supported versions

The latest released version.
