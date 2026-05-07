# Goals progress

Tracking implementation progress against [`goals/`](goals/). Each entry below
points back to a `§<area>-<index>` anchor; the goals files themselves are the
source of truth — when a task lands, mark it `✅ DONE — sha <sha>` in-place
in the corresponding goals file too.

## Strategy

Working through `goals/11-quick-wins.md` in the README's recommended order.
Twenty cheap tasks > one hard task for closing the benchmark gap. Larger
items (§00 engine, §05 scale) come after the quick wins are exhausted.

## Status legend

- ✅ done & committed
- 🔄 in progress
- ⏸ blocked / deferred (note why)
- ☐ not started

## Quick wins — README priority order

| # | Anchor | Goal | Status | Notes |
|---|--------|------|--------|-------|
| 1 | §QW-12 / §SC-8 | Bounded rule runtime | ✅ | 30s default, configurable via `--rule-timeout`; aborts emit `scanner-internal-error` |
| 2 | §QW-13 / §SC-4 | Bounded file size with warning | ✅ | `--max-file-size`; `report.skippedFiles[]`; default 1 MB; mergeReports preserves cross-root |
| 3 | §QW-1 / §PR-6 | Sink-specific sanitizer applicability | ⏸ | depends on §PR-5 |
| 4 | §QW-21 / §IN-30 | Config schema for `.fshrc.yaml` | ✅ | `schemas/fshrc.schema.json`; VS Code yamlValidation+jsonValidation |
| 5 | §QW-3 / §RC-50 | Dynamic `import(taint)` sink | ✅ | code-class sink (CWE-95); pos+neg tests in taint-engine suite |
| 6 | §QW-4 / §RC-58 | Hardcoded IP literal flag | ✅ | new rule `hardcoded-ip`; IPv4+IPv6; skips RFC 1918, link-local, doc ranges, comments |
| 7 | §QW-5 / §RC-43 | `rejectUnauthorized: false` flag | ✅ | new rule `improper-cert-validation`; covers env opt-out + checkServerIdentity stub |
| 8 | §QW-6 / §RC-13 | Tabnabbing | ✅ | new rule `tabnabbing`; covers anchor + window.open |
| 9 | §QW-7 / §RC-19 | Cleartext `http://` | ✅ | new rule `cleartext-http`; only fires inside known network clients; loopback/RFC1918 suppressed |
| 10 | §QW-8 / §RC-20 | Weak crypto on JS side | ✅ | new rule `weak-crypto-js`; mirrors Dart rule for crypto/CryptoJS/SubtleCrypto |
| 11 | §QW-9 / §RC-21 | Vendor token shapes (Stripe/Twilio/…) | ✅ | 7 vendor regexes (Stripe/Twilio/SendGrid/OpenAI/Anthropic/GitHub/Slack), HIGH conf |
| 12 | §QW-10 / §RC-4 | Header injection (CRLF) | ✅ | new SinkKind `header`; CWE-113; res.setHeader/cookie/location/writeHead/append covered |
| 13 | §QW-11 / §PR-18 | Numeric coercion sanitizers | ✅ | `Number`, unary `+`, `~~`, `| 0`, `>>> 0` clear numeric injection taint |
| 14 | §QW-14 / §IN-10 | Markdown report output | ✅ | `output/markdown.ts`; `--markdown` |
| 15 | §QW-15 / §IN-11 | CSV export | ✅ | `output/csv.ts`; RFC 4180 quoting; `--csv` |
| 16 | §QW-16 / §IN-8 | JUnit XML output | ✅ | `output/junit.ts`; one testcase/finding; `--junit` |
| 17 | §QW-17 / §IN-4 | GitLab Code Quality output | ✅ | `output/gitlab.ts`; sha-1 fingerprints; `--gitlab` |
| 18 | §QW-18 / §IN-6 | Bitbucket Code Insights output | ✅ | `output/bitbucket.ts`; annotations array; `--bitbucket` |
| 19 | §QW-19 / §IN-27 | SARIF baseline diff | ✅ | `--diff-against`; fingerprint matching with rule/path/line fallback |
| 20 | §QW-20 / §IN-28 | Confidence-based fail flag | ✅ | `--fail-confidence`; combines with `--fail-on` |
| 21 | §QW-22 / §PR-15 | Suppression-comment count surfacing | ✅ | `report.suppressionsByRule`; >=5 suppressions warns on stderr; merged across multi-root |
| 22 | §QW-23 / §RC-60 | JWT algorithm confusion | ✅ | `jwt-misuse`; HS256 allowed with public-key-shaped verification material |
| 23 | §QW-24 / §RC-3 | `process.env.SECRET` logging | ✅ | `sensitive-logging`; env secret logging subcase only, full CRLF log injection remains open |
| 24 | §QW-25 / §SC-3 | Eval prefilter / setTimeout audit | ✅ | code sink audit; string-form `setTimeout(taint)` covered, callback false-positive fixed |
| 25 | §QW-26 / §IN-30 | Config schema duplicate | ✅ | already covered by §QW-21 / config schema work |
| 26 | §QW-27 / §RC-24 | JS path traversal | ✅ | new rule `path-traversal-js`; tainted `path.join` / `path.resolve` |
| 27 | §QW-29 / §RC-48 | Deprecated TLS/SSL protocols | ✅ | `weak-crypto-js`; flags SSLv3/TLSv1.0/TLSv1.1 pinning |
| 28 | §QW-30 / §RC-55 | Credentials in web storage | ✅ | new rule `insecure-web-storage`; sensitive keys in local/sessionStorage |
| 29 | §QW-31 / §RC-45 | Broad cookie domain | ✅ | `insecure-cookie`; leading-dot domain blast-radius warning |
| 30 | §QW-32 / §RC-44 | `crypto.createCipher` insecure mode | ✅ | `weak-crypto-js`; deprecated no-IV/EVP_BytesToKey API |
| 31 | §QW-37 / §RC-35 | Dependency typosquats | ✅ | new `dependency-confusion` rule for package.json dependency maps |
| 32 | §QW-42 / §SC-16 | Scan duration telemetry | ✅ | per-stage durations in report JSON and local telemetry |
| 33 | §QW-43 / §RC-18 | Error information disclosure | ✅ | new rule `error-info-disclosure`; stack/raw error HIGH, message MEDIUM |
| 34 | §QW-45 | `setTimeout(taint)` audit | ✅ | string-form code execution verified; callback form stays clean |
| 35 | §QW-46 / §RC-56 | JS clipboard exposure | ✅ | new rule `clipboard-exposure`; sensitive identifiers copied to clipboard |
| 36 | §QW-48 / §IN-22 | pre-commit docs | ✅ | README includes local pre-commit snippet |
| 37 | §QW-49 / §IN-24 | GitHub Actions workflow | ✅ | `.github/workflows/sast.yml`; SARIF upload + confidence-gated failure |
| 38 | §QW-50 / §IN-19 | Slack notification | ✅ | `--notify slack:<webhook>` posts scan summary; failures warn only |

## Session log

### 2026-05-07 — kickoff + quick-wins sweep

Reset local main to `origin/main` (recoverable backup in `stash@{0}`).
Implemented the README's recommended quick-win order — 17 of the 18 ran
to completion; §QW-1 (sink-specific sanitizers) is left blocked on
§PR-5 per the goals doc.

Commit:

| SHA | Task batch |
|-----|------------|
| `f2d31ad` | §QW-12/13/21/3/4/5/6/7/8/9/10/14/15/16/17/18/22 — runtime/file-size bounds, schema, rule coverage, output formats, suppression stats |

Net effect:
- 5 new top-level engine knobs (rule timeout, file-size cap, suppression
  stats, schema, output formats).
- 7 new rules (`hardcoded-ip`, `improper-cert-validation`, `tabnabbing`,
  `cleartext-http`, `weak-crypto-js`, plus `import` and `header` sink
  kinds threaded through `injection-flaw`, plus 7 vendor-specific
  secrets in `generic-secret`).
- 5 new output formats wired to dedicated `--markdown`/`--csv`/`--junit`/
  `--gitlab`/`--bitbucket` flags and a generic `--format=<name>`.
- 4 new self-test scripts wired into `npm test`
  (rule-timeout, file-size-budget, output-formats, suppression-stats).

`npm test` ends green: 26 → 60+ taint-engine tests, plus the new suites,
plus precision/IFDS/AST self-tests.

### 2026-05-07 — continuation quick-win batch

Continued the independent S-effort tranche after the first sweep. The clean
push commit `f2d31ad` also lands six more rule-coverage wins:

| SHA | Task |
|-----|------|
| `f2d31ad` | §QW-29 / §RC-48 — deprecated TLS / SSL protocols |
| `f2d31ad` | §QW-30 / §RC-55 — credentials in localStorage / sessionStorage |
| `f2d31ad` | §QW-31 / §RC-45 — broad cookie Domain option |
| `f2d31ad` | §QW-32 / §RC-44 — Node `crypto.createCipher` insecure mode |
| `f2d31ad` | §QW-43 / §RC-18 — error information disclosure |
| `f2d31ad` | §QW-46 / §RC-56 — JS-side clipboard exposure |

Verification:
- `npm run test:taint` passes: 73/73 taint-engine tests.
- `npm test` passes: compile, precision, taint-engine, AST, IFDS,
  rule-timeout, file-size, output-format, and suppression-stat suites.
- `git diff --check` passes before commit.

Next obvious moves:
- §QW-1 once §PR-5 lands.
- Remaining unblocked quick wins: §QW-28, §QW-33, §QW-34, §QW-35,
  §QW-36, §QW-38, §QW-39, §QW-40, §QW-44, §QW-47.
- Move into §00-engine.md (cross-file taint, async tracking) after the
  quick-win backlog is exhausted — these are the L/XL items the
  differentiation strategy turns on.

### 2026-05-07 — integration + coverage quick-win batch

Pushed the prior clean state first, then landed the next independent batch in
`e330ed4`:

| SHA | Task |
|-----|------|
| `e330ed4` | §QW-11 / §PR-18 — numeric coercion sanitizers |
| `e330ed4` | §QW-19 / §IN-27 — SARIF baseline diff with `--diff-against` |
| `e330ed4` | §QW-20 / §IN-28 — confidence-gated CI failure |
| `e330ed4` | §QW-23 / §RC-60 — JWT algorithm confusion |
| `e330ed4` | §QW-24 / §RC-3 — `process.env.SECRET` logging subcase |
| `e330ed4` | §QW-25 / §QW-45 — code-sink audit for eval / `setTimeout` |
| `e330ed4` | §QW-27 / §RC-24 — JS path traversal |
| `e330ed4` | §QW-37 / §RC-35 — npm typosquat dependency names |
| `e330ed4` | §QW-42 / §SC-16 — scan duration telemetry |
| `e330ed4` | §QW-48 / §IN-22 — pre-commit README snippet |
| `e330ed4` | §QW-49 / §IN-24 — GitHub Actions SAST workflow |
| `e330ed4` | §QW-50 / §IN-19 — Slack notification |

Verification:
- `npm test` passes.
- `HOME=/tmp dart run tool/smoke_test.dart` passes.
- `dart analyze lib bin tool` exits 0 with existing info-level lints only.
- `git diff --check` passes before commit.
