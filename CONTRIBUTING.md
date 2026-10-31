# Contributing

## Ground rules

- The verifier has no dependencies and must stay that way. A change that adds
  one is declined.
- The library performs no network access and reads no clock. Anything that
  needs either belongs in the command line, behind an explicit option.
- A verdict is never made more lenient to make a vector pass. An unknown input
  is `UNVERIFIABLE`, not `VALID`.
- No file in this tree may import `@cmdash/*` other than this package naming
  itself, or reach outside the tree with a relative path.

## Changing behaviour

The specs are the source of truth:
[`docs/specs/proof-receipt-v0.md`](docs/specs/proof-receipt-v0.md) and
[`docs/specs/collector-attestation-v0.md`](docs/specs/collector-attestation-v0.md).
A behaviour change starts as a vector in the matching `vectors` directory (each
directory has a `gen-vectors.mjs` that writes them), then the code that
satisfies it. A pull request that changes a verdict without a vector is sent
back.

## Running the tests

```
cd packages/proof-verify
node --test "test/*.test.js"
```

Node 22 or later. The browser build in `browser/verify.js` is generated from
`lib/`; after changing `lib/` run `node scripts/build-browser.mjs`, and
`node scripts/build-browser.mjs --check` fails if it is stale.

## Pull requests

Keep a pull request to one change, include the vector and the test, and say in
the description which section of the spec it implements. Security problems are
not pull requests: see `SECURITY.md`.

By contributing you agree your contribution is licensed under Apache-2.0.
