# Goals progress

Tracking implementation progress against [`goals/`](goals/). Each entry below
points back to a `§<area>-<index>` anchor; the goals files themselves are the
source of truth — when a task lands, mark it `✅ DONE — sha <sha>` in-place
in the corresponding goals file too.

## Strategy

The original `goals/11-quick-wins.md` list is marked complete. Current work
should use the parent goals files and live code/tests as the source of truth;
do not infer CodeQL parity from this progress log.

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
| 3 | §QW-1 / §PR-6 | Sink-specific sanitizer applicability | ✅ | per-kind `SINK_SPECIFIC_SANITIZERS` registry; `state.sanitizedFor` partial coverage; sink-time leaf walk |
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
| 39 | §QW-28 / §RC-25 | Symlink-following sink | ✅ | new `symlink-following`; user-controlled fs paths without realpath/lstat/O_NOFOLLOW guard |
| 40 | §QW-33 / §SF-2 | Unscoped Realtime channel | ✅ | new `unscoped-realtime-channel`; channel subscriptions need ownership filters |
| 41 | §QW-34 / §SF-25 | Realtime subscription cleanup | ✅ | new `realtime-subscription-leak`; assigned subscriptions need unsubscribe/removeChannel |
| 42 | §QW-35 / §SF-12 | secure storage then logging | ✅ | new `secure-storage-logging`; flags logged `flutter_secure_storage` values |
| 43 | §QW-36 / §SF-13 | Android JS bridge exposure | ✅ | new `android-webview-js-interface`; Java/Kotlin `addJavascriptInterface` |
| 44 | §QW-38 / §EN-14 | `String.replace` sanitizer model | ✅ | allowlist-stripping `.replace(..., '')` forms clear taint |
| 45 | §QW-39 / §EN-14 | `JSON.parse` propagation | ✅ | `JSON.parse` / `JSON.stringify` / `Buffer.from` propagate taint |
| 46 | §QW-40 / §EN-14 | `URLSearchParams.get` source | ✅ | treated as user-controlled query input and routed through taint prefilter |
| 47 | §QW-44 / §RC-27 | Python format-string injection | ✅ | new `python-format-injection`; `%` / f-string request data in sinks |
| 48 | §QW-47 / §IN-9 | Standalone HTML report | ✅ | `--html` / `--format html`; self-contained filters by severity/rule/file/search |

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
- §QW-2 and §QW-41 once §EN-4 lands.
- Move into §00-engine.md (cross-file taint, async tracking) for the L/XL
  items the differentiation strategy turns on.

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

### 2026-05-07 — remaining unblocked quick wins

Finished the rest of the unblocked quick-win file in `d0af6b4`:

| SHA | Task |
|-----|------|
| `d0af6b4` | §QW-28 / §RC-25 — symlink-following filesystem paths |
| `d0af6b4` | §QW-33 / §SF-2 — unscoped Realtime channels |
| `d0af6b4` | §QW-34 / §SF-25 — missing Realtime subscription cleanup |
| `d0af6b4` | §QW-35 / §SF-12 — secure-storage values written to logs |
| `d0af6b4` | §QW-36 / §SF-13 — Android `addJavascriptInterface` bridge exposure |
| `d0af6b4` | §QW-38/39/40 / §EN-14 — replace sanitizer, JSON propagation, URLSearchParams source |
| `d0af6b4` | §QW-44 / §RC-27 — Python format-string injection |
| `d0af6b4` | §QW-47 / §IN-9 — standalone HTML report |

Verification:
- `npm test` passes, including taint/rule regression tests and HTML output
  smoke coverage.
- `HOME=/tmp dart run tool/smoke_test.dart` passes.
- `dart analyze lib bin tool` exits 0 with existing unrelated info-level lints.
- `git diff --check` passes before commit.

Quick-win backlog now has only dependency-gated items:
- §QW-1 waits on §PR-5.
- §QW-2 waits on §EN-4.
- §QW-41 waits on §EN-4.

### 2026-05-07 — sink-specific sanitizers + guard narrowing

Closed the three gated quick-win items by shipping minimal versions that
deliver the user-visible precision wins without waiting on the L/XL §PR-5
and §EN-4 dependencies:

| Task | Approach |
|------|----------|
| §QW-1 / §PR-6 | New `SINK_SPECIFIC_SANITIZERS` registry maps `escapeHtml`/`encodeURIComponent`/`escapeSql`/`escapeShell`-shaped calls to per-kind coverage. `ScopeState.sanitizedFor: Map<symbol, Set<SinkKind>>` tracks partial sanitization across assignments. `_isSanitizedSinkCall` walks compound args (e.g. `"WHERE id=" + safe`) and only suppresses when every tainted leaf is sanitized for the actual sink kind, so `escapeHtml(taint)` flowing into SQL still flags HIGH. |
| §QW-2 / §EN-12 | `_findEnclosingInstanceofNarrowings` walks parents of a sink call looking for an `if (x instanceof T)` whose consequent contains the call (and joined `&&` clauses). When the receiver narrows to a DB-shaped class (Pool/PrismaClient/Sequelize/Database/etc.), the SQL sink resolver consults the narrowing in addition to its existing receiver-name and SQL-literal heuristics. |
| §QW-41 / §PR-1 | Pre-pass `_collectNegateGuards` walks each scope's top-level statements for `if (!ALLOW.has(x)) return/throw/continue/break;` (and `.includes`, `.test`, `.indexOf(...)===-1`, `!ALLOW[x]` shapes). `ScopeState.negateGuardedAfter: Map<symbol, line>` records the first guaranteed-clean line; `_expressionTaintStrength` and the sink-call leaf walk treat the symbol as fully sanitized past that line. |

Engine refactors that fall out of QW-1 are load-bearing for the others:
`_expressionTaintStrength` now only short-circuits on FULL sanitization,
so partial sanitizer calls (e.g. `escapeHtml(taint)` inline) propagate
inner taint to the sink, where the per-kind decision happens. Numeric
coercion / generic validators / sanitizing replace stay full-spectrum.

Verification:
- `npm test` passes — taint-engine fixtures across QW-1/QW-2/QW-41,
  plus precision/IFDS/AST/
  rule-timeout/file-size/output-format/suppression/cli-filter suites.
- `HOME=/tmp dart run tool/smoke_test.dart` passes.
- `dart analyze lib bin tool` exits with existing unrelated info-level
  lints.
- `git diff --check` passes before commit.

### 2026-05-08 — Supabase DDL/RPC and JS rule coverage

Landed a focused coverage and precision batch:

| Area | What changed |
|------|--------------|
| Supabase RLS | Committed SQL now feeds table/operation-level RLS enablement and policy coverage into missing-RLS and policy-suggestion rules. |
| Supabase RPC | Client calls to unsafe committed `SECURITY DEFINER` functions are flagged when no auth guard is recognized in the SQL function body. |
| JS/TS rules | Added high-confidence `prototype-pollution` and `redos` rules. |
| JS/TS taint sinks | Added response-body HTML sinks for `res.send`/`res.write`/`res.end`/`reply.send`. |

Verification:
- `dart test` passes.
- `HOME=/tmp dart run tool/smoke_test.dart` passes.
- `dart analyze lib bin tool test` exits 0 with existing unrelated info
  lints only.
- `npm test` passes.
- `git diff --check` passes before commit.
