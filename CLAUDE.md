# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm test` runs all tests (`node --test "scripts/test/*.test.js"`). There are no tests outside `scripts/test`.
- Single file: `node --test scripts/test/suricata.reportPolicy.test.js`. Single test: add `--test-name-pattern="<name>"`.
- Lint: `eslint .` (ESLint is installed globally, config in `eslint.config.mjs`). The 10 `no-unused-vars` warnings for the `REPORT_COMMENT` parameters in `config.js`/`config.default.js` are intentional: they document which fields are available.
- No build step. The app runs under PM2 (`ecosystem.config.js`, app name `suricata-abuseipdb`) on a Linux host with Suricata. It cannot be meaningfully run on a dev machine.

## Repository layout

- `index.js` is the AbuseIPDB-specific part: single reports, the daily rate-limit handling (buffer + bulk upload after reset), PM2 `ready`/graceful shutdown, startup order.
- `scripts/` is a **git submodule** (`sefinek/IPDB-Integration-Scripts`) shared by all integrations: UFW, T-Pot, Cloudflare WAF, Suricata, for both AbuseIPDB and SniffCat. Each integration has its own checkout of it. Commit and push submodule changes on its `main` first, then commit the updated pointer here.
- Anything in `scripts/` must stay backward compatible with the other integrations' `index.js`. Older installs that had auto-updates enabled pull the submodule's `main` without updating the parent repo, which is why `scripts/services/updates.js` still exists as a stub.
- Suricata-specific shared logic lives in `scripts/suricata/` (`reportPolicy.js`, `createProcessor.js`, `homeNet.js`, `ignoredSignatures.js`), so a future Suricata-To-SniffCat integration can reuse it.

## Alert pipeline

`tailFile(eve.json)` → `createProcessor().processLine` → `reportPolicy.evaluate` → `reportIp` in `index.js`.

- `processLine` does a cheap `includes('"alert"')` prefilter before `JSON.parse`, because eve.json is several GB per day. It deduplicates in-flight IPs, bounds concurrency/queue size, and on shutdown moves queued alerts to the bulk buffer.
- `reportPolicy.evaluate` decides what is reported. Every alert with severity <= `MIN_ALERT_SEVERITY` is reported unless ignored, **but only the external host that opened the connection** (`flow.src_ip`, falling back to the packet source on older Suricata). Hosts contacted from the local network (DNS resolvers, CDNs, P2P peers) must never be reported. "Local" = special-purpose ranges + HOME_NET + current server IPs (`ipFetcher`). Categories come from the alert classtype via `scripts/flags.js`, so they map to both AbuseIPDB and SniffCat IDs.
- The policy is evaluated again right before sending and before a bulk upload, using the minimal `evidence` stored with each entry (no payloads or HTTP bodies are kept).
- HOME_NET is read from `SURICATA_CONFIG_FILE` (`suricata.yaml`). `HOME_NET` in `config.js` is only a fallback if the file cannot be read or parsed; if both fail, startup exits.
- Ignored signatures: built-in list in `scripts/suricata/ignoredSignatures.js` (toggle `USE_BUILT_IN_IGNORED_SIGNATURES`) plus `IGNORED_SIGNATURES` from the config. Built-in entries must exist in the ET Open ruleset and their description must match the rule `msg`.

## Duplicate-report safety

- Report endpoints (`axiosService`, `axiosBulk`) are never retried automatically, other clients are. A retry after an ambiguous failure could report the same IP twice.
- `scripts/services/bulkUpload.js` never resends records once the API answered 2xx, even if the counts in the response do not match.
- An IP is marked in the cooldown cache only after a confirmed `'reported'` result.

## Configuration

- `config.js` is gitignored and created from `config.default.js`. Keep both in sync when adding options. Validation rules live in `scripts/validations/` (`common.js`, `suricata.js`). Removed options go to `deprecated` in `common.js` so users get a warning instead of an error.
- Most `scripts/` modules read `../../config.js` at import time, so configuration cannot change after startup.

## Tests

- `scripts/test/helpers.js` `setup()` must be called at the top of a test file, before requiring the tested module. It replaces `config.js` and `scripts/logger.js` in `require.cache`, so tests never read the real config or send webhooks. The parent project must still have a `config.js` file for module resolution.
- Use real public IPs in tests (e.g. `8.8.8.8`, `2001:4860:4860::8888`). Documentation ranges like `203.0.113.0/24` and `2001:db8::/32` are classified as special-purpose and treated as local.
- `scripts/services/bulk.js` and `whitelist.js` are not unit-tested because their file paths are fixed inside the project (`tmp/bulk-report-buffer.csv`, `whitelist.txt`).
