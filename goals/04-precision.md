# 04 — Precision: guards, sanitizers, barriers, confidence

This file covers the mechanics that turn a "this looks dangerous" finding
into a "this IS dangerous" finding. CodeQL's precision wins come from
guard-aware data flow and barrier nodes; we have heuristics. Closing this
gap is mostly about authoring the guard recognizers — the engine work
that supports them lives in [00-engine.md §EN-4](00-engine.md).

---

## §PR-1 — Allowlist barrier guards

- **Why:** Misses fixture 11 (SSRF allowlist). The single biggest FP
  source on real apps.
- **Current state:** No guard recognition. Tainted variables stay
  tainted regardless of subsequent if-checks.
- **Target state:** Inside the body of `if (allow.has(x))` /
  `if (validHosts.includes(x))` / `if (Object.keys(map).includes(x))`,
  the symbol `x` is treated as not-tainted.
- **Approach:** Hook into §EN-4's CFG. When entering an `if_statement`
  body, evaluate the test expression. Recognize barrier shapes:
  - `<Set>.has(<symbol>)` and `!<Set>.has(<symbol>)`
  - `<Array>.includes(<symbol>)` (and `.indexOf(...) !== -1`)
  - `<Map>.has(<symbol>)` (object literal keys count too)
  - `<Object>.hasOwnProperty(<symbol>)`
  - `<RegExp>.test(<symbol>)` where regex is a literal (anchor-aware)
  Maintain a dominator-aware narrowing map.
- **Dependencies:** §EN-4.
- **Effort:** **M** (5 days post-§EN-4).
- **Tests:**
  - Re-run COMPARISON.md fixture 11 — flips from HIGH FP to no-flag.
  - Per-shape unit tests in `scripts/taint-engine.test.js`.
- **Risks / gotchas:**
  - Negated guards: `if (!allow.has(x)) return;` — barrier applies
    *after* the if-block.
  - Mutated allowlists (`allow.add(taint)`) — barrier doesn't apply.
  - `.includes()` on attacker-controlled arrays — still tainted.

## §PR-2 — Type-narrowing guards (typeof / instanceof)

- **Why:** `typeof x === 'number'` should clear taint for SQL/command
  sinks (not for HTML — a number can still be reflected).
- **Current state:** No typeof / instanceof recognition.
- **Target state:**
  - `typeof x === 'string'` keeps taint
  - `typeof x === 'number'` clears for SQL/command/path/code/redirect
  - `typeof x === 'boolean'` clears for everything
  - `Number.isInteger(x)` / `Number.isFinite(x)` / `Number.isSafeInteger(x)`
    — all clear for SQL/command/path/code (already partial via numeric coercion)
  - `Array.isArray(x)` — clear if used as array-typed argument
  - `instanceof T` — narrow to T
- **Approach:** Same hook as §PR-1. Lattice element gains
  `narrowedType: Map<symbol, Type>`. Sink check consults this when
  deciding if the type is safe.
- **Dependencies:** §EN-4, §EN-12.
- **Effort:** **M** (3 days post §EN-4).
- **Tests:** Per-narrowing unit tests.
- **Risks / gotchas:** Don't over-narrow — `typeof x === 'number'` doesn't
  clear taint for HTML sinks. Per-sink-kind decision required.

## §PR-3 — Range / length barrier guards

- **Why:** `if (x.length < 1024) sink(x)` is a partial barrier — limits
  payload size but not content. Mostly meaningful for resource exhaustion
  (§RC-28).
- **Current state:** None.
- **Target state:** Recognize `length < N`, `length > N` patterns. Don't
  use to clear injection taint (length doesn't sanitize content) but DO
  use to clear DoS-class findings.
- **Effort:** **S** (2 days post §EN-4).

## §PR-4 — Equality narrowing

- **Why:** `if (x === 'admin') sink(x)` should narrow `x` to `'admin'`
  for the body. Then sink(x) is sink('admin') — completely safe.
- **Current state:** None.
- **Target state:** Inside `if (x === literal)` body, replace `x` with
  the literal. Conversely outside, exclude that value.
- **Approach:** Already in §EN-16. Re-listed here so precision agents
  see it.
- **Effort:** **S** post §EN-4.

## §PR-5 — Sanitizer evidence: allowlist of known-good libraries

- **Why:** Misses fixture 15 (function literally named `sanitize` that
  doesn't sanitize). Today we trust any function whose name matches the
  sanitizer regex.
- **Current state:** `SANITIZER_NAME_PATTERN` in
  `vscode-extension/src/taint/dataFlow.ts:211` matches by name only.
- **Target state:** Trust **only** these known-good sanitizers:
  - `dompurify.sanitize` and re-exports
  - `sanitize-html` (npm) `sanitizeHtml(...)` re-exports
  - `validator.escape`, `validator.normalizeEmail`, etc. — by package
  - `sqlstring.escape` (mysql node driver)
  - `mysql.escape` (mysql2)
  - `pg-escape.literal` / `pg-escape.string`
  - `lodash.escape`
  - `he.encode`
  - `xss-filters.inHTMLData`
  - Plus the existing list of "validators" but only trust them for the
    sink kind they actually sanitize for (CodeQL has sink-specific
    barriers).
- **Approach:**
  1. New `vscode-extension/src/taint/sanitizers.ts` registry. Each
     entry: `{ packageOrigin: '@dompurify/...', method: 'sanitize',
     sanitizesFor: Set<SinkKind> }`.
  2. The engine consults import resolution (§EN-1) to verify the
     called function actually originates from the listed package.
  3. If origin can't be verified, downgrade trust to MEDIUM but still
     allow the user to suppress the FP via `// sast-ignore`.
- **Dependencies:** §EN-1.
- **Effort:** **M** (5 days post §EN-1).
- **Tests:**
  - Re-run COMPARISON.md fixture 15 — flips from no-flag to HIGH.
  - User-defined `function sanitize(s) { return s; }` no longer trusted.
  - DOMPurify.sanitize correctly trusted across re-exports.
- **Risks / gotchas:**
  - Many real codebases have their own well-tested sanitizers.
    Provide a way for users to register them via `.fshrc`:
    ```yaml
    trustedSanitizers:
      - { from: './lib/sec', method: 'cleanHtml', forSinks: ['html'] }
    ```

## §PR-6 — Sink-specific sanitizer applicability

- **Why:** `parseInt` sanitizes for SQL/command but is a no-op for
  HTML (numbers can still be reflected). Today we apply sanitizers
  uniformly.
- **Current state:** A sanitized symbol is treated as safe for every
  sink. Most sanitizers don't actually do that.
- **Target state:** Each sanitizer entry carries `sanitizesFor: Set<SinkKind>`.
  A sink check consults this rather than blanket-trusting.
- **Approach:** Builds on §PR-5. Engine change is small once the
  registry has the metadata.
- **Dependencies:** §PR-5.
- **Effort:** **S** (1 day post §PR-5).
- **Tests:** Sink-kind-specific sanitizer fixtures.

## §PR-7 — Per-rule confidence calibration

- **Why:** Today every rule self-assigns `high|medium|low`. There's no
  empirical calibration: a "high" finding for `injection-flaw` is not
  the same likelihood-of-true-positive as a "high" for `jwt-misuse`.
- **Current state:** Rules pick their own confidence.
- **Target state:** Run the scanner against a labeled corpus, derive
  per-rule precision/recall, calibrate the confidence ranges. Future
  HIGH means "confirmed by N% of labeled instances."
- **Approach:** Build the corpus first ([08-quality-evals.md §QE-2](08-quality-evals.md)),
  then add a calibration pass during scan that adjusts `confidence`
  based on per-rule statistics.
- **Dependencies:** §QE-2.
- **Effort:** **M** (1 week post §QE-2).

## §PR-8 — Confidence reasoning surfaced to user

- **Why:** Half-implemented today — `confidenceReason` field exists but
  the messages are templated by rule.
- **Current state:** `Finding.confidenceReason` returns one of three
  hard-coded strings via `confidenceReason()` in
  `vscode-extension/src/models/finding.ts:46`.
- **Target state:** Per-finding reason text that explains:
  - what the source is (with line)
  - what propagation steps occurred (link to pathSteps)
  - why this confidence level
- **Approach:** Compose from `Finding.pathSteps` and the rule's CWE.
  Show in the webview detail row already wired up (see
  `vscode-extension/media/webview.js`).
- **Dependencies:** None.
- **Effort:** **S** (2 days).

## §PR-9 — Detection-method-aware confidence

- **Why:** A taint-confirmed finding is more reliable than an AST
  pattern match. Today both can produce HIGH.
- **Current state:** `DetectionMethod` enum exists (taint, structural,
  regex). Confidence not consistently tied to it.
- **Target state:**
  - taint-confirmed → HIGH
  - structural / AST → MEDIUM (default)
  - regex / heuristic → LOW
  Override only with explicit reason.
- **Approach:** Audit every rule's confidence assignment. Make a
  default mapping in `Finding` constructor; allow per-finding override.
- **Dependencies:** None.
- **Effort:** **M** (3 days).

## §PR-10 — Reachability-based downgrade

- **Why:** A SQL injection in dead code (no caller) is less urgent than
  one on a hot path.
- **Current state:** Not modeled.
- **Target state:** With §EN-1 cross-file summaries we can compute
  callee→caller reachability for each function. Findings inside
  unreachable code downgrade by one severity step.
- **Approach:** Reachability via DFS over the import graph from
  `package.json` `main` and `bin` entries.
- **Dependencies:** §EN-1.
- **Effort:** **M** (4 days post §EN-1).
- **Risks / gotchas:** Test files, examples — already path-filtered via
  `applyNonProductionNoiseReduction`. Don't double-discount.

## §PR-11 — Test-path noise reduction (already done; track)

- **Current state:** ✅ `applyNonProductionNoiseReduction` in
  `vscode-extension/src/noise.ts`.
- **Target state:** Maintained.
- **Effort:** None unless we expand path patterns.

## §PR-12 — User-customizable barriers via config

- **Why:** Every codebase has its own helpers. Force-fitting our
  recognition is unwinnable.
- **Current state:** No user-defined barriers.
- **Target state:** `.fshrc.yaml` supports `barriers`:
  ```yaml
  barriers:
    - { fn: 'lib.security.assertSafeUrl', clearsForSinks: ['url', 'redirect'] }
    - { fn: 'lib.db.escapeSql', clearsForSinks: ['sql'] }
  ```
- **Approach:** Extend `ScannerConfig` (Dart side has it; add JS-side
  equivalent). Engine consults config before applying default
  sanitizer registry.
- **Dependencies:** None.
- **Effort:** **M** (4 days).
- **Tests:** Per-barrier-shape config-test.

## §PR-13 — Inferred sanitizers from explicit annotation

- **Why:** Some teams want to mark "this is sanitized" inline.
- **Current state:** `// sast-ignore <code>` exists, but it suppresses
  a finding rather than asserting a value is clean.
- **Target state:** New comment marker:
  `/* @sast-sanitized */` immediately before / inside an expression
  marks that expression's result as not-tainted. Different from
  ignore: still detected by other rules; just trusted by taint.
- **Approach:** Walk for the comment; mark the next AST node's symbol
  as sanitized.
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Risks / gotchas:** Like all suppression mechanisms — abuseable.
  Track usage in telemetry to detect abuse patterns.

## §PR-14 — Explicit source / sink markers

- **Why:** Some teams use a code generator that produces unusual
  shapes — they want to mark "this IS user input" / "this IS a sink"
  manually.
- **Target state:** `/* @sast-source */ const x = …;`
  `/* @sast-sink-sql */ db.query(...)`.
- **Effort:** **M** (3 days).

## §PR-15 — FP feedback loop via suppression patterns ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** When the same `// sast-ignore <code>` appears N times in a
  codebase, the rule is likely too noisy. Surface this.
- **Current state:** No analytics on suppressions.
- **Target state:** Per-scan: count `// sast-ignore <code>` occurrences
  per rule. Flag rules with > 5 suppressions as candidates for
  precision review. Surface in scan output: `[SAST] Rule X has 12
  suppressions; consider reviewing FP rate.`
- **Approach:** Add to existing suppression context tracking.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - New `applySuppressionWithStats` (suppression.ts) returns
    `{kept, suppressedByRule}`; the legacy `applySuppression` delegates
    to it for backwards compatibility.
  - Threshold: `SUPPRESSION_REVIEW_THRESHOLD = 5`. Rules at-or-above
    that count get a `[SAST] Rule "X" had N findings suppressed —
    consider reviewing its FP rate.` warning on stderr.
  - `ProjectScanReport.suppressionsByRule: ReadonlyMap<string, number>`.
  - `mergeReports` sums per-folder counts so multi-root scans report
    project-wide suppression rates.
  - JSON output (`stats.suppressionsByRule`) carries the map for CI
    dashboards.
  - Counts what was *filtered* (the actual FP signal) rather than raw
    `// sast-ignore` directive occurrences (which may not match any
    finding).
  - Test: `scripts/suppression-stats.test.js` — covers the warn+no-warn
    paths and verifies counts match findings filtered out.

## §PR-16 — Symbolic-execution-lite for simple constants

- **Why:** `const KEY = 'admin'; if (req.body.role === KEY)` — recognize
  the constant.
- **Current state:** Not modeled.
- **Target state:** Track string-literal constants per scope; expand
  references in guard expressions.
- **Approach:** Constants table populated during AST walk;
  consulted by guard recognizers (§PR-1, §PR-4).
- **Dependencies:** §EN-4.
- **Effort:** **M** (3 days).

## §PR-17 — Conservative loop iteration count

- **Why:** Loops introduce taint re-introduction. Today we walk once.
- **Approach:** Already in §EN-13. Re-listed here so precision agents
  see it.
- **Effort:** **M** post §EN-13.

## §PR-18 — Mathematical operations as sanitizers (numeric only)

- **Why:** `x | 0`, `x >>> 0`, `~~x`, `+x`, `Number(x)` are all numeric
  coercion idioms.
- **Current state:** `parseInt`/`parseFloat` recognized.
- **Target state:** Add `Number`, `+`, `~~`, `| 0`, `>>> 0` as numeric
  coercion. All with the same sink-kind applicability as parseInt
  (§PR-6).
- **Effort:** **S** (1 day).

## §PR-19 — Per-finding rationale: cite the code

- **Why:** Users currently see "Detected dynamic value passed into sql
  sink." Better: "Line 5 receives tainted value from req.body.id (line 2)
  via concatenation (line 3) reaching db.query at line 5."
- **Current state:** `pathSteps` in finding model carries this; webview
  renders.
- **Target state:** Always populated; never empty for taint findings.
- **Approach:** Done — see `pathSteps` in
  `vscode-extension/src/taint/dataFlow.ts:35`. Track that all sink emit
  sites populate it consistently.
- **Effort:** **S** maintenance.

## §PR-20 — Cross-rule finding suppression

- **Why:** When `injection-flaw` fires on a line that's already
  flagged by `unsafe-eval`, the second one is redundant. Today we
  dedupe by `code+filePath+line+column+message`.
- **Current state:** Dedupe by exact key.
- **Target state:** Cross-rule suppression: prefer the more-specific
  finding (taint-confirmed > structural > regex) on the same site.
- **Effort:** **S** (1 day).
