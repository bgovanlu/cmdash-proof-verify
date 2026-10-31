#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// cmdash-verify: verify a CMDash proof receipt without asking CMDash. See `cmdash-verify --help`
// and lib/cli.mjs. Exit codes: 0 VALID, 1 INVALID, 2 UNVERIFIABLE (or unreadable input, a failed
// fetch, bad usage), 3 STALE_VALID.
import { createNodeIo, main } from '../lib/cli.mjs';

process.exitCode = await main(process.argv.slice(2), createNodeIo());
