# Progress log

The chronological record of substantive changes to the scanner. Each entry
identifies the concern that motivated the change, the files touched, and the
verification used to confirm the change works. Code-level details live in
[IMPLEMENTATION.md](IMPLEMENTATION.md); the user-facing feature list lives
in [README.md](README.md).

Items are grouped into five passes that produced today's state:

1. **Audit** — initial gap analysis identifying 70+ issues vs CodeQL/Semgrep.
2. **Production fixes** — 23 changes addressing correctness, output, UX,
   and engine precision.
3. **Loophole fixes** — 6 follow-up corrections after auditing the
   production fixes themselves.
4. **Final pass** — 13 architecture/coverage items to ship production-ready,
   plus dead-code and placeholder cleanup.
5. **Quick-win sweep** — the tasks listed in `goals/11-quick-wins.md`
   landed across rule coverage, output formats, CI integration, and
   engine-precision items (sink-specific sanitizers, instanceof receiver
   narrowing, negate-guard recognition).

---

## Pass 1 — Audit

**Outcome:** an itemized comparison of the scanner against CodeQL/Semgrep
covering architecture, taint engine correctness, vulnerability coverage,
output integration, UX, configuration/extensibility, and tests.

Headline gaps identified:

| Class | Gaps |
|-------|------|
| Architecture | Dual TS/Dart implementations drifting; stale `.js` files committed; rules sequential; whole project loaded into memory; 1 MB silent file skip; `.gitignore` not honored |
| Taint engine | No inter-procedural; no path-sensitive CFG; magic parameter-name source detection; SQL sinks resolved by name only; sanitizer detection by regex over names; `parseInt` lumped with generic validators; cross-file flow ignored; no async/event tracking; sink dedupe collapses distinct vulns on same line |
| Coverage | Missing ReDoS, prototype pollution, JWT misuse, XXE, CSRF, insecure cookies, CORS misconfig, insecure randomness, timing attacks, mass assignment, JS deserialization. Go and Java had zero source patterns despite "AST tier" advertising |
| Output | No SARIF, no CWE codes, no data-flow paths, line-wide diagnostic ranges, fragile baseline fingerprint, exact-line-only inline suppression |
| UX | Quick fixes were placeholder TODO comments; no live/on-save scanning; multi-root workspaces ignored; no scan cancellation; webview used inline `onclick` handlers blocked by strict CSP; webview routinely used `innerHTML`; no per-rule disable; status bar missed TSX/JSX |
| Config | No custom rules, no severity/profile overrides, no `--diff` mode |
| Hygiene | Telemetry written to project root; unused parameters; `noUnusedLocals` off; `walkAst` recursive without depth guard |

---

## Pass 2 — Production fixes (23 items)

### Architecture & hygiene

- **F1** Restored broken build: `lineNum` reference in
  `diagnosticsProvider.ts` after rename.
- **F24** Dropped unused `name` parameter in
  `genericSecretRule._isBinaryOrSkipped`.
- **F26** Flipped `noUnusedLocals` and `noUnusedParameters` to `true` in
  `tsconfig.json`. Cleaned up affected imports/parameters.
- **F25** Made `RuleStage` required on the `Rule` interface. Added
  `stage = RuleStage.fast` to 15 rules that previously omitted it.
- **F27** Replaced recursive `walkAst` with iterative explicit-stack
  version capped at `MAX_AST_WALK_DEPTH = 8000`. Minified single-line
  files no longer blow Node's stack.
- **§1.2** Deleted 23 stale `.js` files committed under
  `vscode-extension/src/`. Updated `.gitignore` to keep them out.

### Multi-root, gitignore, traversal

- **F4 (§5.3, §5.4)** `scanWorkspace` iterates every workspace folder,
  reports per-folder progress, merges results via new
  `scanner/mergeReports.ts`. `cancellable: true`. Per-folder errors don't
  abort the full scan.
- **F28 (§1.6)** Honor root-level `.gitignore` during file traversal.
  Re-uses the existing glob matcher; supports negations with last-match-wins.
- **F19 (§5.9)** Added `onProgress` callback through
  `ProjectContext.load` and `ProjectScanner.scan`; the workspace command
  threads progress through `vscode.window.withProgress`.

### Sink dedupe / output / SARIF

- **F2 (§2.9)** Added `message` to the dedupe key so two sinks with
  different shapes on the same line both survive.
- **F3 (§4.1)** New `output/sarif.ts` — dependency-free SARIF 2.1.0
  serializer with per-rule taxonomy and `partialFingerprints`. CLI gains
  `--sarif` and `-o/--output` flags.
- **F4 (§4.2)** Added `cwe` field to `Finding`; populated on every
  security/secret/log rule. `_cweForSink` in `injectionRule.ts` maps sink
  kinds to CWE-89/78/95/79/918/601/22/943/1336.
- **F2 (§4.4)** Findings now carry precise AST ranges (`column`,
  `endLine`, `endColumn`) populated via new `findingRangeFromNode`
  helper. `DiagnosticsProvider` uses these when present, falling back to
  line-wide ranges.

### Engine precision

- **F11 (§2.4)** Ported the Dart-side SQL receiver heuristic to TS.
  Ambiguous bare names (`query`, `execute`, `executeQuery`) now require a
  DB-shaped receiver (`db|database|client|pool|prismaClient|...`) OR a SQL
  literal in the first argument. Unambiguous names (`rawQuery`,
  `executescript`) still fire unconditionally.
- **F12 (§2.6)** Pulled `parseInt`/`parseFloat` out of the generic
  `VALIDATION_NAME_PATTERN` into a separate `NUMERIC_COERCION_PATTERN`.
  Documented as a separate bucket.
- **F13 (§2.3)** Split `SOURCE_PARAMETER_NAMES` into `STRONG_…` (`req`,
  `request`, `userInput` — always tainted) and `HEURISTIC_…` (`data`,
  `payload`, `input` — only tainted when a sibling parameter looks like
  a request handler shape: `res`, `response`, `next`, `reply`, `ctx`).
  Eliminates the dominant FP source on pure helper functions.

### UX

- **F3 (§5.7)** Status bar now shows for `javascriptreact` and
  `typescriptreact` files.
- **F15 (§5.5)** Removed inline `onclick=` handlers from `webview.js`;
  replaced with `addEventListener` (CSP-safe).
- **F17 (§5.8)** Added `flutterSupabaseHelper.disabledRules: string[]`
  setting and a CLI `--disable a,b,c` flag.
- **F21 (§7.1)** Moved telemetry out of project root to a
  platform-specific user data directory (XDG/macOS/Windows).

### New rules

- **F6** `insecure-random` — flags `Math.random()` whose result feeds a
  sensitive identifier (CWE-338).
- **F7** `jwt-misuse` — flags `jwt.decode()`, `algorithms: ['none']`, and
  hardcoded JWT signing secrets (CWE-347/798).
- **F8** `insecure-cookie` — flags `httpOnly: false`, `secure: false`,
  `sameSite: 'none'` without secure (CWE-1004/614/352).
- **F9** `cors-misconfig` — flags wildcard origin + credentials, `cors({
  origin: true, credentials: true })`, origin reflection (CWE-942).

---

## Pass 3 — Loophole fixes (6 items)

After landing the production fixes, each one was audited for FP/FN. Six
real bugs in the new code surfaced and were corrected:

- **L1** All four new rules (Math.random, JWT, cookies, CORS)
  false-positived on commented-out code. Added `isCommentLine` guards.
- **L2** F2's dedupe still collapsed two same-shape sinks on the same
  line because their messages were identical. Added `column` to the
  dedupe key.
- **L3** SARIF rule descriptors only captured the FIRST CWE per rule. For
  `injection-flaw` (which spans 9 sink kinds) compliance dashboards
  filtering by CWE missed most findings. Now aggregates the full set.
- **L4** SQL receiver heuristic missed camelCase DB names (`myDb`,
  `dbClient`, `prismaClient`) when there was no SQL literal. Replaced the
  separator-based regex with camelCase tokenization. Bonus: also fixes
  `getDb().query` (the harder L8 case).
- **L5** Cookie rule's regex stopped at the first `}`, missing
  `httpOnly: false` after a nested object like `domain: { a: 1 }`.
  Replaced with a brace-balanced character-by-character scanner that
  also handles strings/templates.
- **L6** `--disable` silently accepted unknown rule codes. Now warns and
  prints the full list of valid codes.

---

## Pass 4 — Production-ready

### Final-tier loopholes

- **L9** Replaced fixed-window inline suppression with a
  brace/paren/bracket/string-balanced statement detector. Multi-line
  wraps still suppressed; two unrelated statements after one comment are
  not.
- **L11** `ProjectScanReport.astSuccessRate` now computes from this
  report's own `astDiagnostics`, not the global `ParserContext`
  singleton. Multi-root scans show the correct aggregated rate.
- **L12** Telemetry path validates that `XDG_DATA_HOME` and
  `LOCALAPPDATA` env values resolve under HOME before use; suspicious
  values fall through to the platform default.
- **L13** JWT-misuse rule extended: tracks
  `const SECRET = "literal"; jwt.sign(payload, SECRET)` via file-local
  variable lookup. Skips placeholder secrets.

### Performance & CI

- **F34** Rules within a stage execute concurrently via `Promise.all`.
  Stages still run sequentially (stage 3 needs stage 2's AST cache).
- **F33** Added `--changed-since=<git-ref>` for PR-style scans. Runs
  `git diff --name-only <ref>...HEAD` plus `git status --porcelain` and
  filters findings to changed files.
- **F23** Baseline v2 stores a SHA-1 hash of ±2 lines around each
  finding (whitespace-normalized). Match strategy: contextHash →
  fingerprint fallback. v1 baselines still load.

### Quality / tests

- **F36** New `scripts/taint-engine.test.js` with 14 unit-style invariants
  covering source seeding, sanitizers, SQL receiver heuristic, sink kinds,
  reassignment, augmented assignment, parameterized queries. Wired into
  `npm test`.

### UX improvements

- **F18** Opt-in on-save scanning via `flutterSupabaseHelper.scanOnSave`
  setting. 750 ms debounced.
- **F5** Captured source-to-sink data-flow paths in findings. The taint
  engine now maintains per-symbol provenance; on a sink hit,
  `buildPathSteps` walks the chain and attaches `pathSteps` to the
  Finding. Surfaced in JSON output, SARIF (as `codeFlows`), and the
  webview (as an ordered list).
- **F10** Webview rebuilt without `innerHTML`. Every render goes through
  a small `el(tag, attrs, ...children)` DOM helper that auto-escapes
  text content. Inline styles moved to CSS classes.
- **F20** Real autofixes replace placeholder TODO comments:
  - `Math.random()` → `crypto.randomUUID()` or `crypto.randomBytes(16).toString('hex')`
  - `algorithms: ['none']` → `algorithms: ['HS256']`
  - `httpOnly: false` → `httpOnly: true`; `secure: false` → `secure: true`
  - simple `db.query("…" + ident)` → `db.query("…?", [ident])`
  - existing `.innerHTML =` → `.textContent =` retained

### Cleanup

- Removed the three `// TODO:` comment-only "quick fixes" from
  `codeActions.ts` (`_evalFixes`, the jwt.decode reminder, the
  parameterized-query comment fallback). Rules without safe automatic
  rewrites now offer ONLY the suppression action.
- Deleted four scratch/debug files at the extension root (`test-cli.js`,
  `test-cli.ts`, `test_abi.js`, `test_exports.js`) — none referenced by
  any script.
- Removed obsolete `as any` casts and `getStage(r: any)` helper in
  `scanner.ts`. With `Rule.stage` now required, the type system handles
  this directly.
- Consolidated documentation: deleted `AGENTS.md`, `FIXES_PROGRESS.md`,
  `LOOPHOLES.md`, `REMAINING_FIXES.md`. Their relevant contents are
  preserved in [IMPLEMENTATION.md](IMPLEMENTATION.md) (architecture,
  contracts, conventions) and [README.md](README.md) (user-facing feature
  list).

### Documentation

- Full [README.md](README.md) rewrite covering every production feature.
- New [IMPLEMENTATION.md](IMPLEMENTATION.md) — architecture / how to
  extend / non-goals.
- This [PROGRESS.md](PROGRESS.md) consolidating the four passes.

---

## Pass 5 — Quick-win sweep

The `goals/` folder formalised near-term gaps into small tasks under
[goals/11-quick-wins.md](goals/11-quick-wins.md). Those quick-win tasks are
now marked complete; deeper versions of some items remain tracked in their
parent goals files. Headline groupings:

### Rule-coverage adds (sha `f2d31ad`, `e330ed4`, `d0af6b4`)

`hardcoded-ip`, `improper-cert-validation`, `tabnabbing`,
`cleartext-http`, `weak-crypto-js`, `insecure-web-storage`,
`error-info-disclosure`, `clipboard-exposure`, `path-traversal-js`,
`dependency-confusion`, `symlink-following`,
`unscoped-realtime-channel`, `realtime-subscription-leak`,
`secure-storage-logging`, `android-webview-js-interface`,
`python-format-injection`. Existing rules also extended:
`generic-secret` adds Stripe / Twilio / SendGrid / OpenAI / Anthropic /
GitHub / Slack token shapes; `injection-flaw` gains `header` and `code`
sink kinds (CWE-113 + CWE-95 dynamic `import()`); `weak-crypto-js`
covers TLS / SSL deprecated protocols and `crypto.createCipher`;
`insecure-cookie` flags broad-domain cookies; `jwt-misuse` flags
algorithm confusion (HS256 with public-key-shaped material);
`sensitive-logging` flags `process.env.SECRET` writes.

### Output / integration formats

Markdown table, CSV (RFC-4180 quoting), JUnit XML, GitLab Code Quality,
Bitbucket Code Insights, standalone HTML report (severity / rule / file
filterable), Slack notifier (`--notify slack:<webhook>`),
GitHub Actions SAST workflow, pre-commit snippet in
[README.md](README.md), `.fshrc.yaml` JSON Schema for VS Code's
`yamlValidation` / `jsonValidation`.

### Engine knobs / scale

`--rule-timeout` (30s default; aborts emit `scanner-internal-error`),
`--max-file-size` (1 MB default; `report.skippedFiles[]`),
`--diff-against=<sarif>` for SARIF baseline diff, `--fail-confidence`
combined with `--fail-on`, `report.suppressionsByRule` surfaced
(stderr warning at ≥ 5 suppressions per rule), per-stage scan
duration in telemetry + report JSON, `eval(`-prefilter exit-fast.

### Engine precision (Pass 5 tail — the three QW items previously gated)

- **§QW-1 / §PR-6** (sha `5c27117`) — sink-specific sanitizer
  applicability. New `SINK_SPECIFIC_SANITIZERS` registry maps each
  sanitizer pattern to the `Set<SinkKind>` it actually defends against.
  `ScopeState.sanitizedFor: Map<symbol, Set<SinkKind>>` tracks
  per-symbol partial coverage across assignments. `_isSanitizedSinkCall`
  walks compound args (`"WHERE id=" + safe`) leaf-by-leaf and only
  suppresses when **every** tainted leaf is sanitized for the actual
  sink kind. Result: `escapeHtml(taint)` flowing into SQL flags HIGH;
  `sqlstring.escape(taint)` into the same sink suppresses. Numeric
  coercion / generic validators / sanitizing replace stay full-spectrum.
  `_expressionTaintStrength` only short-circuits on FULL sanitization
  so partial sanitizer calls propagate inner taint to the per-kind
  sink decision.
- **§QW-2 / §EN-12** (sha `5c27117`) — `_findEnclosingInstanceofNarrowings`
  walks parents from a sink call site looking for `if (x instanceof T)`
  guards (and `&&`-conjoined variants) whose consequence dominates the
  call. SQL receiver resolution treats the receiver as DB-shaped if `T`
  tokenizes to a `DB_RECEIVER_KEYWORDS` entry — `Pool`, `PrismaClient`,
  `Sequelize`, `Database`, etc. Approximates the dominator-aware
  narrowing that §EN-4 will provide.
- **§QW-41 / §PR-1** (sha `5c27117`) — `_collectNegateGuards` pre-pass
  walks each scope's top-level statements for early-exit allowlist
  barriers: `if (!ALLOW.has(x)) return/throw/continue/break;` and the
  `.includes`, `.test`, `.indexOf(...) === -1`, `!ALLOW[x]` shapes.
  Recognized symbols populate `ScopeState.negateGuardedAfter:
  Map<symbol, line>`; sink checks past that line treat the symbol as
  fully sanitized. Positive guards and nested-block guards still wait
  on §EN-4.

The `scripts/taint-engine.test.js` suite was expanded with focused
regressions for these precision cases.

---

## Verification

After every pass, the test suite ran clean:

```
$ npm run compile     # tsc strict, zero warnings
$ npm test
  Precision self-test passed.                (17 fixture assertions)
  taint-engine.test.js passes                (taint engine invariants)
  AST Engine Validation Passed! ✔             (grammar smoke test)
  IFDS self-test passed.                     (7 Dart taint findings)
  rule-timeout / file-size-budget / output-formats / suppression-stats /
  cli-filters self-tests: PASS
```

End-to-end smoke test on a four-vulnerability fixture confirms:
- Pretty output: 3 HIGH + 2 MEDIUM findings across 4 rules.
- SARIF: per-rule `properties.cwe` aggregated; `codeFlows` populated.
- `--disable injection-flaw,insecure-random` correctly filters from 5 → 3.
- Baseline v2 entries carry `contextHash`.
- `.gitignore` skips `generated/` directories.
- `escapeHtml(taint)` → SQL flags HIGH; `sqlstring.escape(taint)` → SQL
  suppresses; `if (handle instanceof Pool) handle.query(taint)` flags
  HIGH; `if (!ALLOW.has(x)) return;` clears taint past the guard.

---

## Architectural deferrals (out of scope)

These need design review and multi-day effort, not a fix-pass:

- **Inter-procedural taint (§EN-1 — L)** — the simple "function summary"
  mechanism catches `function f(x) { return x.body.id; }` but not
  callbacks, cross-file flows, or async/event boundaries. Unlocks §PR-5
  (origin-resolved sanitizer allowlist) once it lands.
- **CFG-based path-sensitive analysis (§EN-4 — XL, 4–8 weeks)** — the
  single biggest precision win still on the table. Conditional
  sanitization is conservatively NOT trusted; positive allowlist guards
  (`if (allow.has(x)) sink(x)`) and nested-block negate-guards both
  wait on §EN-4. Pass 5 ships approximations for the most common
  shapes (top-level negate-guard, dominating instanceof) without the
  lattice.
- **Custom YAML/JSON rules** — today, project-specific patterns require
  forking and editing TypeScript.
- **Dart vs TS strategy** — both implementations exist and are maintained.
  Consolidation is a strategic decision, not a refactor.
