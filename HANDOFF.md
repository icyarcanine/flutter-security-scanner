# Handoff — Engine refactor & remaining tasks (2026-05-07)

This is the single document a future engineer or LLM agent should read to
finish the project. It complements [`goals/`](goals/) (the canonical task
list with stable §-anchors) and [`GOALS_PROGRESS.md`](GOALS_PROGRESS.md)
(the running task log). Where any two disagree, **the goals files win** —
they are the source of truth; this doc is the reading order and the
implementation playbook.

Read order:
1. This document.
2. [`goals/README.md`](goals/README.md) — convention.
3. [`COMPARISON.md`](COMPARISON.md) — head-to-head fixtures vs CodeQL.
4. The §-numbered goals file you're picking up.

## Table of contents

- [§ 0. Where we are](#-0-where-we-are)
- [§ 1. Strategic decision the next engineer must make first](#-1-strategic-decision-the-next-engineer-must-make-first)
- [§ 2. Repository map](#-2-repository-map)
- [§ 3. The engine refactor — required for §EN-* / §PR-* / §QW-1,2,41 / §RC-1,2,5,6,11,17,30,31,40,42,46,47](#-3-the-engine-refactor)
  - [3.1. Phase A — Source-of-truth registries (1 week)](#31-phase-a--source-of-truth-registries-1-week)
  - [3.2. Phase B — Cross-file taint summaries §EN-1 (~10 days)](#32-phase-b--cross-file-taint-summaries-en-1-10-days)
  - [3.3. Phase C — CFG + lattice §EN-4 (4–8 weeks)](#33-phase-c--cfg--lattice-en-4-48-weeks)
  - [3.4. Phase D — Async / Promise / callback §EN-2 (~12 days)](#34-phase-d--async--promise--callback-en-2-12-days)
  - [3.5. Phase E — Function pointer / class table §EN-3 (~10 days)](#35-phase-e--function-pointer--class-table-en-3-10-days)
  - [3.6. Phase F — Field-sensitive object tracking §EN-5 (~8 days)](#36-phase-f--field-sensitive-object-tracking-en-5-8-days)
  - [3.7. Phase G — Type-aware sink resolution §EN-6 (~10 days)](#37-phase-g--type-aware-sink-resolution-en-6-10-days)
  - [3.8. Phase H — Whole-program DB §EN-7 + incremental §EN-8 (6–8 weeks)](#38-phase-h--whole-program-db-en-7--incremental-en-8-68-weeks)
  - [3.9. Phase I — IFDS for JS/TS §EN-9 (4–8 weeks)](#39-phase-i--ifds-for-jsts-en-9-48-weeks)
  - [3.10. Phase J — Smaller engine items §EN-10 / 11 / 12 / 13 / 14 / 15 / 16 / 17](#310-phase-j--smaller-engine-items)
- [§ 4. Precision work after the CFG lands (§PR-*)](#-4-precision-work-after-the-cfg-lands)
- [§ 5. Rule coverage backlog (§RC-*)](#-5-rule-coverage-backlog)
- [§ 6. Language coverage (§LC-*) and framework models (§FM-*)](#-6-language-coverage-and-framework-models)
- [§ 7. Scale / DB layer (§SC-*)](#-7-scale--db-layer)
- [§ 8. Integrations remaining (§IN-*)](#-8-integrations-remaining)
- [§ 9. Rule authoring DSL (§RA-*)](#-9-rule-authoring-dsl)
- [§ 10. Quality / evals (§QE-*)](#-10-quality--evals)
- [§ 11. Supabase / Flutter remaining (§SF-*)](#-11-supabase--flutter-remaining)
- [§ 12. Test infrastructure prerequisites](#-12-test-infrastructure-prerequisites)
- [§ 13. Rollout sequencing & scheduling](#-13-rollout-sequencing--scheduling)
- [§ 14. Acceptance criteria — what "fully done" means](#-14-acceptance-criteria)

---

## § 0. Where we are

**Done (tracked in `GOALS_PROGRESS.md` and inline in `goals/`):**

- 47 of 50 quick wins (§QW-3 through §QW-50 except §QW-1, §QW-2, §QW-41).
- All five SARIF emitters (base + GitHub Code Scanning extras: snippets,
  taxonomies, kind/rank, baselineState, automationDetails).
- Five output formats (Markdown, CSV, JUnit, GitLab Code Quality, GitLab
  Security Report, Bitbucket, HTML).
- VS Code: code-action quick fixes, hover provider with CWE links,
  diagnostics with relatedInformation, status bar, scan-on-save, JSON
  schema for `.fshrc.{yaml,yml,json}`.
- Dart-side IFDS taint engine (intra + inter-procedural) wired into
  `IfdsTaintRule` and used at scan time.
- Supabase rule pack: edge-function-secrets, signed-URL TTL, realtime
  filter, RPC injection, service-role key in client (incl. JWT decode),
  unscoped Realtime channel, Realtime subscription leak, RLS-policy
  suggestion, table ownership, missing-RLS awareness.
- Flutter rule pack: biometric-auth, release-hardening, platform-security,
  insecure-storage (sqflite + Hive + flutter_secure_storage logging),
  webview-security, Android `addJavascriptInterface`, deep-link sources,
  clipboard-exposure, public-storage.
- 100+ JS-side rules (cleartext-http, weak-crypto-js, hardcoded-ip,
  improper-cert-validation, tabnabbing, dependency-confusion, JWT alg
  confusion, error-info-disclosure, insecure-web-storage, JS clipboard,
  JS path traversal, symlink-following, Python format-string, header
  injection, …).
- Scale guardrails: bounded rule runtime (`--rule-timeout`), bounded
  file size (`--max-file-size`), suppression-stat surfacing, scan
  duration telemetry.
- Outputs: SARIF 2.1.0 (deep), HTML, Markdown, CSV, JUnit, GitLab
  CQ + Security, Bitbucket; `--diff-against`, `--fail-confidence`,
  `--baseline`, Slack notify, GitHub Actions workflow, pre-commit and
  husky/lint-staged docs.

**Not done (this is the work this handoff is about):**

- The whole **engine refactor** (§EN-1 through §EN-13, §EN-15, §EN-17;
  §EN-14 is partial). This unblocks §QW-1, §QW-2, §QW-41 and most §PR-*.
- ~40 of 60 rule-coverage items in §RC-*.
- All 17 §LC-* language-coverage items (Python ORM/framework models, Go,
  Java, C#, Ruby, Swift, Kotlin, deeper Dart IFDS).
- All 33 §FM-* framework models (Express → ASP.NET Core).
- Most §PR-* precision (gating on §EN-4 CFG).
- Most §SC-* scale (DB layer, streaming, distributed workers).
- Most §IN-* integrations (PR comments, Azure DevOps, IntelliJ, Vim,
  email, Jira/Linear, dashboard, watch mode, cross-tool diff).
- All 18 §RA-* rule-DSL items.
- All 22 §QE-* eval/benchmark items.
- 14 §SF-* Supabase/Flutter items (RLS-from-DDL, MethodChannel taint,
  Dart IFDS sensitivity extensions, project template, auth flow,
  pubspec.lock vuln check, …).

Numbers are intentionally loose — the goals files are precise.

---

## § 1. Strategic decision the next engineer must make first

The plan in [`goals/README.md`](goals/README.md) names two viable
strategies and warns that pursuing both is a non-starter:

> 1. **Head-to-head match** — close every gap in §00–§07. Years of work.
> 2. **Differentiation** — be 10× better on a smaller surface CodeQL
>    doesn't serve well: zero-config setup, mobile (Dart/Flutter/Swift/
>    Kotlin), Supabase/edge platforms, AI-assisted autofixes, real-time
>    IDE feedback, incremental rescan. Months of work. **This is where
>    we can actually win.**

**Pick one before opening any of the §EN files below.** Different
strategies give different priority orders. Specifically:

- **Differentiation:** §EN-1 → §EN-4 (CFG) → §EN-2 → §EN-7/8 (DB +
  incremental) → §SF-5/8/14–19 (Supabase/Flutter depth) → §IN-14/15/32
  (real-time IDE feedback, watch mode). Skip §LC-9..13 (C#/Ruby/Swift/
  Kotlin/C/C++) and §QE-1..3 (OWASP/Juliet/SARD) entirely; lean on the
  CVE corpus (§QE-4) for empirical credibility.
- **Head-to-head:** §EN-1, §EN-2, §EN-3, §EN-4 in parallel feeds; §LC-1
  through §LC-8 second; §FM-* third; §RC-* on top of those; §QE-1/§QE-2
  to prove parity.

Document the decision in [`goals/README.md`](goals/README.md) under
"Strategy locked-in (date)" so future agents don't re-debate it.

The rest of this handoff assumes **differentiation** because that's what
the existing post-2026-05-07 work has been pulling toward (Supabase
rules, GitHub Code Scanning depth, Dart IFDS), but each phase is broken
out so a head-to-head agent can re-order.

---

## § 2. Repository map

```
.
├── bin/
│   └── fluttersupabasehelper.dart         # Dart CLI entry point
├── lib/                                   # Dart-side scanner
│   ├── src/
│   │   ├── config/                        # .fshrc parsing
│   │   ├── models/
│   │   │   ├── finding.dart
│   │   │   ├── project_context.dart
│   │   │   └── scanned_file.dart
│   │   ├── output/
│   │   │   ├── baseline.dart
│   │   │   ├── finding_fingerprint.dart
│   │   │   └── sarif_writer.dart          # IN-2 added fileLines support
│   │   ├── rules/
│   │   │   ├── flutter/                   # biometric_auth_rule.dart
│   │   │   ├── security/                  # 24 Dart-side rules
│   │   │   └── supabase/                  # 8 Supabase rules
│   │   ├── rule.dart                      # Rule abstract class
│   │   ├── rules.dart                     # buildDefaultRules() Dart side
│   │   ├── scanner.dart                   # ProjectScanner Dart side
│   │   └── taint/
│   │       └── taint_engine.dart          # Dart's intra-proc taint
│   └── fluttersupabasehelper.dart         # public exports
├── vscode-extension/                      # JS/TS scanner + VS Code ext
│   ├── package.json                       # engines + scripts
│   ├── schemas/
│   │   └── fshrc.schema.json
│   ├── scripts/                           # node-only self-tests
│   │   ├── adversarial-suite.js
│   │   ├── cli-filters.test.js
│   │   ├── file-size-budget.test.js
│   │   ├── hover-provider.test.js         # IN-16 (mocks vscode)
│   │   ├── ifds-self-test.js
│   │   ├── output-formats.test.js         # SARIF / GitLab Sec / HTML / …
│   │   ├── precision-self-test.js
│   │   ├── rule-timeout.test.js
│   │   ├── suppression-stats.test.js
│   │   ├── taint-engine.test.js           # MAIN unit test surface
│   │   └── test-ast.js
│   └── src/
│       ├── ast/
│       │   ├── parser.ts                  # ParserContext (web-tree-sitter)
│       │   ├── traversal.ts               # walkAst, getCallName, ...
│       │   └── semanticResolver.ts        # used by ifdsBuilder
│       ├── baseline.ts
│       ├── codeActions.ts                 # quick-fix authoring
│       ├── cli.ts                         # node CLI entry
│       ├── commands/                      # VS Code command handlers
│       ├── diagnostics/
│       │   ├── diagnosticsProvider.ts     # vscode.DiagnosticCollection + line index
│       │   └── hoverProvider.ts           # IN-16
│       ├── extension.ts                   # VS Code activation
│       ├── models/
│       │   ├── finding.ts                 # Finding type + path steps
│       │   └── graph.ts                   # CodeGraph (used by IFDS)
│       ├── noise.ts                       # test-path noise reduction
│       ├── output/
│       │   ├── sarif.ts                   # IN-1 + IN-2 (deepest output)
│       │   ├── markdown.ts
│       │   ├── csv.ts
│       │   ├── junit.ts
│       │   ├── gitlab.ts                  # Code Quality
│       │   ├── gitlabSecurity.ts          # IN-5
│       │   ├── bitbucket.ts
│       │   └── html.ts
│       ├── rules/
│       │   ├── bugs/                      # unsafeEvalRule
│       │   ├── config/                    # debugCodeRule, environmentVariablesRule, ...
│       │   ├── secrets/genericSecretRule.ts
│       │   ├── security/                  # 25+ rules
│       │   ├── supabase/                  # 5 rules
│       │   ├── index.ts                   # buildDefaultRules
│       │   ├── rule.ts                    # Rule + RuleStage
│       │   └── ruleHelpers.ts
│       ├── scanner/
│       │   ├── projectContext.ts          # 844 LOC — load + skip + aggregations
│       │   ├── scannedFile.ts             # AST cache + lines / context helpers
│       │   ├── scanner.ts                 # ProjectScanner + stages
│       │   └── mergeReports.ts            # multi-root scan merge
│       ├── suppression.ts                 # // sast-ignore handling
│       ├── taint/
│       │   ├── dataFlow.ts                # 1945 LOC — intra-proc tracker
│       │   ├── ifdsBuilder.ts             # 815 LOC — Dart AST → CodeGraph
│       │   ├── ifdsEngine.ts              # orchestrator
│       │   └── ifdsSolver.ts              # 431 LOC — Reps-Horwitz-Sagiv
│       ├── utils/pathUtils.ts
│       └── webview/panelProvider.ts       # in-VS Code report panel
├── goals/
│   ├── 00-engine.md … 11-quick-wins.md
│   └── README.md
├── test/
│   ├── fixtures/                          # Dart fixture apps
│   ├── scanner_test.dart                  # Dart-side end-to-end
│   └── sarif_writer_test.dart             # IN-2 unit test
├── COMPARISON.md                          # 15-fixture head-to-head
├── GOALS_PROGRESS.md                      # task table
├── HANDOFF.md                             # this file
├── IMPLEMENTATION.md                      # design notes
├── PROGRESS.md                            # historical progress log
├── README.md                              # user-facing docs
├── SECURITY.md
├── analysis_options.yaml
└── pubspec.yaml
```

The two scanners (`lib/` Dart, `vscode-extension/src/` JS/TS) **share
findings shape and SARIF emitters' philosophy but have separate engines**.
Cross-language rules currently live in both trees — that's a known
duplication and §EN-9 (IFDS for JS/TS) would converge them.

---

## § 3. The engine refactor

This is the hardest, most-rewarding work in the project. Without it,
§QW-1/2/41 and most of §PR-* and §RC-1/2/5/6/11/17/30/31/40/42/46/47
cannot land. Conservatively budget **6 engineer-months** for the full
refactor, **2 engineer-months** for a "minimum viable" version
(Phases A + B + C only).

The current intra-procedural tracker is
[`vscode-extension/src/taint/dataFlow.ts`](vscode-extension/src/taint/dataFlow.ts)
(1945 LOC). The class to extend is `IntraProceduralTaintTracker`. Read
it cover-to-cover before opening any phase below — every refactor step
references functions that are already there.

### 3.1. Phase A — Source-of-truth registries (1 week)

**Why first:** Today, sources / sinks / sanitizers are inlined into
`dataFlow.ts` (Node "intra-proc" tracker) and `ifdsBuilder.ts`
(Dart IFDS builder). Two sources of truth means every new framework
model has to be added twice. Centralize before extending.

**Steps:**

1. Create `vscode-extension/src/taint/registry.ts`. Export:
   ```ts
   export type SinkKind =
     | 'sql' | 'command' | 'code' | 'html' | 'template'
     | 'url' | 'path' | 'redirect' | 'nosql' | 'header'
     | 'log' | 'native-channel' | 'dynamic-property-write';
   export interface SourceEntry { match: RegExp; lang?: 'js'|'ts'|'dart'|'py'|'go'|'java'; framework?: string; }
   export interface SinkEntry { name: string; kind: SinkKind; receiverHint?: string; argIndex?: number; lang?: ...; }
   export interface SanitizerEntry { name: string; sanitizesFor: Set<SinkKind>; lang?: ...; }
   export const REGISTRY = { sources: SourceEntry[], sinks: SinkEntry[], sanitizers: SanitizerEntry[] };
   ```
2. Move every regex / set in `dataFlow.ts:_isDirectSourceExpression`,
   `dataFlow.ts:_sinkForCall`, `SANITIZER_NAME_PATTERN` into the
   registry. Replace the call sites with registry lookups. The
   `dataFlow.ts` lattice logic stays — only the data moves.
3. Repeat for `ifdsBuilder.ts:DEFAULT_BUILDER_CONFIG` (lines 41-52).
   Drop the inline `sources` / `sinks` / `sanitizers` Sets. Build
   them from the registry filtered by `lang === 'dart'`.
4. Add a per-framework filter so registry entries with a
   `framework: 'express'` tag only contribute when Express is detected
   (sets up Phase 6 = §FM-*).
5. Tests: every test in `scripts/taint-engine.test.js` must still pass
   without changes. Add one test that asserts a registry entry is the
   single source of truth (regex test on the registry array length).

**Touch points:** `dataFlow.ts:200-260` (source patterns),
`dataFlow.ts:780-1100` (`_sinkForCall`), `ifdsBuilder.ts:41-52`
(`DEFAULT_BUILDER_CONFIG`).

**Done when:** All existing tests pass; the registry is the only place
that knows the source/sink/sanitizer set; both engines consume from it.

### 3.2. Phase B — Cross-file taint summaries §EN-1 (~10 days)

**Why:** Real Node apps split sources/sinks across files. Today, a
source defined in `helpers.js` and consumed in `routes.js` is
downgraded to MEDIUM (dynamic-only) because the engine doesn't trace
across the module boundary. **Closes COMPARISON.md fixture 04.**

**Steps:**

1. **Extend the existing `FunctionSummary`** in
   `dataFlow.ts:55-58`:
   ```ts
   interface FunctionSummary {
     returnsDirectSource: boolean;
     returnsParameterIndex: number | null;       // NEW — passthrough
     returnsTaintedThroughOtherCall: { name: string; argIndex: number } | null;
   }
   ```
2. **Create `vscode-extension/src/taint/projectSummaryCache.ts`:**
   ```ts
   export class ProjectSummaryCache {
     private byFile = new Map<string, FileSummary>();
     populate(files: ScannedFile[], parser: ParserContext): void;
     resolve(localImportName: string, importingFile: string): FunctionSummary | null;
     clear(): void;
   }
   interface FileSummary {
     exports: Map<string, FunctionSummary>;       // local export table
     reExports: Map<string, { fromFile: string; exportedAs: string }>;
   }
   ```
   `populate` runs once before the rule schedule (call from
   `scanner.ts:scan` between `loadStart` and `runStage(RuleStage.taint)`).
3. **Resolve imports** in `projectSummaryCache.ts`. Walk every file's AST
   for these node types:
   - `import_statement` (ES) — pull `source` text + named/namespace specs
   - `import_declaration` (TypeScript) — same
   - `call_expression` whose callee is `require` — CommonJS
   - `assignment_expression` LHS = `module.exports` or `exports.X`
   - `export_statement` (ES) — including `export * from` (re-export chains)

   Resolve specifiers to absolute file paths via:
   - relative resolution first (`./helpers` → `./helpers.{ts,tsx,js,jsx}`)
   - `tsconfig.json` `paths` second (parse it; don't invoke the TS
     compiler — too heavy)
   - bail out (return null) on bare specifiers (`import 'lodash'`)
4. **Plug into the existing tracker.** In `dataFlow.ts`, find the call
   site `_expressionTaintStrength` (~line 950 — the function that
   evaluates a syntactic expression's taint state). Where it falls
   through "unknown call → return false", before falling through:
   - If the called identifier resolves through `ProjectSummaryCache` to
     an exported `FunctionSummary` whose `returnsDirectSource` is true,
     return strength = `direct`.
   - Else if the summary's `returnsParameterIndex` is N, recursively
     check argument N for taint.
   - Else fall through unchanged.
5. **Cache invalidation:** `cache.clear()` at the start of every scan.
   For `--changed-since` scans, only re-summarise the changed files
   plus their *one-hop* importers (look up importers via a reverse
   index built during `populate`).

**Tests:**
- `scripts/taint-engine.test.js` — new section "cross-file taint":
  - direct source through cross-file passthrough
  - re-export chain (`export * from './a'`)
  - default CJS export (`module.exports = function (req) {...}`)
  - circular re-exports — must not infinite-loop
  - `tsconfig.paths` alias
- COMPARISON.md fixture 04 should flip from MEDIUM to HIGH.

**Risks / gotchas (from goals/00-engine.md):**
- Re-export chains common; transitively resolve until you hit a real
  declaration or detect a cycle.
- Default CJS exports look like the whole file; treat them as a single
  `default` export.
- `tsconfig.paths` may not resolve; fall back to relative.

### 3.3. Phase C — CFG + lattice §EN-4 (4–8 weeks)

**The single biggest precision win in the file. Read carefully.**

**Why:** Today, conditional sanitization is conservatively NOT trusted
(`_collectConditionallyAssigned` in `dataFlow.ts:551`). Real codebases
that sanitize inside an if-branch are reported as still tainted.
Without a CFG we cannot reason about guards. Closes COMPARISON.md
fixtures 11 (SSRF allowlist) and unblocks §QW-2, §QW-41, and every
§PR-* item that touches guards.

**Steps:**

1. **Build a per-function CFG.** Add `vscode-extension/src/taint/cfg.ts`:
   ```ts
   export interface CfgNode {
     id: number;
     statement: SyntaxNode;
     successors: CfgEdge[];
   }
   export interface CfgEdge {
     to: number;
     kind: 'true' | 'false' | 'fall' | 'loop-back' | 'exception' | 'return';
   }
   export function buildCfg(funcRoot: SyntaxNode): { nodes: CfgNode[]; entry: number; exit: number };
   ```
   Edge cases to handle (bake as test fixtures):
   - `if`/`else if`/`else` with and without else
   - `switch` with fall-through (you must NOT collapse cases)
   - `for`, `for...of`, `for...in`, `while`, `do…while` (loop-back edge)
   - `try`/`catch`/`finally` (exception edge to catch; fall-through
     out of finally)
   - `return`, `throw`, `break`, `continue`
   - JSX — punt; treat as straight-line for now (document)
   - `&&`, `||`, `?:` — punt to follow-up; treat as straight-line in
     the first cut.

2. **Replace the flat tainted/sanitized Sets with a `TaintLattice`.**
   In `dataFlow.ts`, the existing `ScopeState` (lines 71-108) is the
   per-scope lattice today. Convert it to per-CFG-node:
   ```ts
   export interface TaintLattice {
     tainted: Set<string>;                     // direct
     weakTainted: Set<string>;                 // indirect
     sanitized: Set<string>;
     barriers: Map<string, BarrierKind>;       // §PR-1 barriers
     narrowedTypes: Map<string, string>;       // §EN-12 / §PR-2
     equalToLiterals: Map<string, string>;     // §EN-16 / §PR-4
     literalProperties: Map<string, Set<string>>;
     taintedProperties: Map<string, Set<string>>;
     provenance: Map<string, TaintProvenanceStep[]>;
     conditionallyAssigned: Set<string>;       // kept for compat
   }
   export function joinLattice(a: TaintLattice, b: TaintLattice): TaintLattice;
   export function bottomLattice(): TaintLattice;
   ```
   `join` is element-wise: `tainted = a.tainted ∪ b.tainted`,
   `sanitized = a.sanitized ∩ b.sanitized` (must hold on every path).

3. **Worklist solver** over the CFG. Walk in reverse-postorder. At each
   node, apply the existing flow function (`_propagateAssignment`,
   `_expressionTaintStrength`, etc.) then propagate to successors.
   Fixed-point on backedges or cap iterations at 3 (§EN-13).

4. **Guard recognition** at `if_statement`-shaped CFG splits. In
   `dataFlow.ts`, add `_recognizeGuard(testExpr) → BarrierFact[]` that
   returns one fact per recognized shape:
   - `Set.has(x)` / `Map.has(x)` / `Object.hasOwnProperty(x)`
   - `Array.includes(x)` / `Array.indexOf(x) !== -1`
   - `RegExp.test(x)` (only when regex is a literal — anchor-aware)
   - `typeof x === 'string'` / `'number'` / `'boolean'`
   - `Number.isInteger(x)` / `Number.isFinite(x)`
   - `Array.isArray(x)`
   - `x === literal` / `x !== literal` (§EN-16)
   - `x instanceof T` (§EN-12)

   On the **true-branch successor**, apply the barrier to `x`. On the
   **false-branch successor**, apply the negation. Crucially, this
   makes negate-guards (§QW-41 / `if (!allow.has(x)) return;`) work
   for free: the `return` short-circuits, so the post-if region is
   dominated by the *false* branch fact.

5. **Sink-specific narrowing.** When a barrier is `typeof x === 'number'`
   the SAFE-FOR set is `{sql, command, path, code, redirect}`, not
   `html` (a number can still be reflected). Encode in
   `BarrierKind`:
   ```ts
   export type BarrierKind = { kind: 'allowlist'; clearsForSinks: 'all' }
                           | { kind: 'numeric'; clearsForSinks: SinkKind[] }
                           | { kind: 'literal-equality'; value: string };
   ```
   When evaluating a sink, intersect the relevant `clearsForSinks` with
   the sink's kind.

6. **Path-dominated read in the existing tracker.** Currently
   `walkAst(scope, ...)` traverses in source order; replace the visit
   inside `_collectFindings` with "walk the CFG in reverse-postorder,
   apply flow, look at sinks." Gate behind a feature flag
   `flutterSupabaseHelper.useCfg: false` (default off) until precision
   is validated.

7. **Migration:** Run BOTH engines side-by-side for one release.
   Telemetry (§EN-17) reports per-finding which engine produced it.
   Once CFG matches or beats flat-walk on `precision-self-test`, flip
   the default and remove the old code.

**Tests:**
- New `scripts/cfg.test.js` — 30+ unit tests covering each guard shape
  and CFG construction edge case.
- COMPARISON.md fixture 11 must flip from HIGH FP to no-flag.
- `parseInt-on-every-path.js` (fixture 06) regression — must remain
  no-flag.
- All existing `scripts/taint-engine.test.js` tests pass under both
  engines (parameterize the test to run twice).

**Risks / gotchas:**
- Switch fall-through is a footgun. Add explicit fall-through edges
  per case.
- Try/catch/finally exception edges aren't always derivable from AST
  alone (any expression can throw). Conservative model: every
  statement has an exception edge to the nearest enclosing `catch`.
- JSX conditional rendering — too complex for first cut, document
  as a known limitation.
- IFDS solver is exponential in worst case. Cap path-edges at 100k
  per procedure; emit a `scanner-internal-error` finding when capped.

### 3.4. Phase D — Async / Promise / callback §EN-2 (~12 days)

**Why:** Most modern Node code lives inside `.then()`, `await`, and
callback functions. Today the engine misses everything past
`Promise.resolve(x).then(y => …)` because the callback runs in its own
scope. Closes COMPARISON.md fixture 05.

**Steps:**

1. Extend `ScopeState` with `resolvedValueTaint: Map<symbol, TaintProvenanceStep[]>`.
   Populated by:
   - `Promise.resolve(x)` — record `x`'s taint chain under the
     receiver's symbol
   - `Promise.reject(x)` — same
   - `await someExpr` — evaluate `_expressionTaintStrength(someExpr)`;
     if tainted, the `await` result is tainted with the same chain
   - `Promise.all([…])` — array element taints tracked component-wise
     via existing `taintedProperties`
2. **Detect "thenable-shaped" calls** in `dataFlow.ts:walkAst`:
   - call expression with callee name in `{then, catch, finally}` AND
     argument is a function expression / arrow function
   - in the new function's scope, seed the first parameter with the
     receiver's `resolvedValueTaint`
3. **Array iteration callbacks:** `arr.map/forEach/filter/find/some/every/reduce`
   — first param of callback inherits `taintedProperties[arr]` element
   taint.
4. **Callback-passed sinks:** `app.get('/u', (req, res) => …)` — the
   existing `_seedScope` should already handle this via
   `STRONG_SOURCE_PARAMETER_NAMES`. **Verify** for arrow functions
   nested under `call_expression` — the parser shape may differ from
   plain `function_expression`.
5. **`setTimeout(callback, ms)`** — first param is undefined (no taint
   to propagate), but the callback's body runs in a fresh scope. Make
   sure `walkAst` doesn't lose enclosing-scope taint when crossing into
   `arrow_function` here.
6. **Top-level await** — `await x` at module scope. Make sure
   `_inheritFromEnclosing` handles `program`-level scope.

**Tests:**
- `Promise.then propagates taint`
- `await on tainted Promise`
- `array.map element taint`
- `setTimeout function arg seeds taint`
- `Promise.all preserves component taint`
- COMPARISON.md fixture 05 should flip HIGH.

**Risks / gotchas:**
- `Promise.all([])` returns an array; preserve element taints
  component-wise.
- RxJS Observables look thenable but aren't; document as a gap.

### 3.5. Phase E — Function pointer / class table §EN-3 (~10 days)

**Why:** §EN-1 (cross-file summaries) doesn't help when the call goes
through a variable: `const fn = getInput; fn(req)`. We need a coarse
flow-insensitive model: "which function values does this symbol refer
to."

**Steps:**

1. **Pre-pass:** walk the AST collecting function-value assignments.
   New file `vscode-extension/src/taint/functionPointers.ts`:
   ```ts
   export class FunctionPointerTable {
     // symbol → { fileId, functionId } it can point to (1+)
     private byFile = new Map<string, Map<string, FunctionId[]>>();
     populate(file: ScannedFile, root: SyntaxNode): void;
     resolve(filePath: string, symbol: string): FunctionId[];
   }
   ```
   Sources of bindings:
   - `assignment_expression` / `variable_declarator` whose RHS is
     `function_declaration`, `function_expression`, `arrow_function`
   - same shape where RHS is an `identifier` referencing another known
     function (chain)
2. **Resolution at call sites.** In `_expressionTaintStrength`, when
   the callee is a plain identifier with no in-scope binding, consult
   `FunctionPointerTable.resolve(currentFile, identifier)`. If a
   single resolution exists, treat the call as if it were a call to
   the resolved function (drop into Phase B summary lookup).
3. **Class methods via allocation.** Build a per-file
   `Map<className, Map<methodName, FunctionId>>`. Resolve `obj.method(…)`
   when `obj` was allocated via `new MyClass()` (track in the
   intermediate symbol table).

**Tests:**
- `function-pointer-via-variable.js` — `const fn = source; sink(fn(req))`
  flags HIGH.
- `class-method-resolved-by-allocation.js` —
  `new UnsafeDb().query(req.body.x)` flags eval inside `query`.

**Risks:**
- Don't try dynamic dispatch (`x[name]()`) — undecidable.
- Limit to literal `class X { m() {} }` shapes — skip prototype-based
  inheritance.

### 3.6. Phase F — Field-sensitive object tracking §EN-5 (~8 days)

**Why:** Current model degrades to weak after `MAX_TAINT_DEPTH=3`. Real
apps build deep objects (`req.body.address.line1`); we lose the chain.

**Steps:**

1. Replace `taintedProperties: Map<symbol, Set<string>>` with
   `taintedPaths: Map<symbol, Trie>`. Trie node carries per-step
   provenance.
2. On `obj.a.b.c = src`, record path `[a,b,c]` as tainted with the
   provenance from `src`.
3. On `obj.a.b.c` access, look up. Partial prefix hits propagate as
   `weakTainted` (indirect).
4. Computed-property writes (`obj[expr] = src`):
   - if `expr` resolves to a literal, treat as that literal
   - else mark `obj` fully tainted (every prop) — this is the
     prototype-pollution path that §RC-1 hooks into
5. Spread (`{ ...src, x: 1 }`) copies all of `src`'s paths into the
   new literal.

**Tests:**
- `obj.body.x` assignment then read
- `nested-write` then `nested-read` 5-deep
- computed-property with literal key
- computed-property with dynamic key — pessimizes obj
- spread copies tainted paths

### 3.7. Phase G — Type-aware sink resolution §EN-6 (~10 days)

**Why:** `analytics.query(event)` and `db.query(sql)` are syntactically
identical. The current `_receiverLooksLikeDb` heuristic
(`dataFlow.ts:91`'s `DB_RECEIVER_KEYWORDS`) has known FNs.

**Steps:**

1. Add `typescript` as an **optional** peer dependency. No-op when
   missing.
2. New `vscode-extension/src/taint/tsLanguageService.ts`. Lazy-load the
   TS Language Service. One per workspace, cached across scans within
   a VS Code session. CLI runs only with `--type-check` flag (slow).
3. At a SQL-named call site, ask the LS for the type of the receiver
   expression. Match against a known-type registry:
   ```
   pg.Pool, pg.Client, mysql2.Connection, sqlite.Database,
   mongoose.Model, prisma.PrismaClient, knex.Knex, ...
   ```
4. If the type resolves to a known SQL receiver → raise to HIGH.
   If to a known non-SQL type (`AnalyticsClient` etc.) → skip.
   Else fall back to existing heuristic.

**Tests:** `tsconfig-paths-resolved.ts`, `pg-pool-types-resolved.ts`,
`mysql2-connection-types-resolved.ts`, `analytics.query()-with-known-type.ts`
should NOT flag.

### 3.8. Phase H — Whole-program DB §EN-7 + incremental §EN-8 (6–8 weeks)

**Why:** Avoid re-parsing on every scan. Required for CodeQL-class
performance on monorepos AND unblocks §IN-32 (watch mode), §IN-14
(scan-on-type), §SC-2/6/12.

**Steps:**

1. **DB schema.** SQLite (single file, no daemon). New file
   `vscode-extension/src/db/schema.sql`:
   ```sql
   CREATE TABLE files (
     id INTEGER PRIMARY KEY,
     path TEXT UNIQUE,
     mtime INTEGER,
     content_hash TEXT,
     size_bytes INTEGER
   );
   CREATE TABLE functions (
     id INTEGER PRIMARY KEY,
     file_id INTEGER,
     name TEXT,
     start_line INTEGER, end_line INTEGER,
     FOREIGN KEY(file_id) REFERENCES files(id)
   );
   CREATE TABLE summaries (
     function_id INTEGER PRIMARY KEY,
     returns_direct_source BOOLEAN,
     returns_parameter_index INTEGER NULL
   );
   CREATE TABLE exports (
     file_id INTEGER, exported_name TEXT, function_id INTEGER,
     PRIMARY KEY (file_id, exported_name)
   );
   CREATE TABLE imports (
     from_file INTEGER, to_file INTEGER, name TEXT,
     PRIMARY KEY (from_file, to_file, name)
   );
   CREATE TABLE findings (
     id INTEGER PRIMARY KEY,
     rule TEXT, file_id INTEGER, line INTEGER, column INTEGER,
     message TEXT, severity TEXT, confidence TEXT,
     content_hash TEXT,    -- when this finding was found
     fingerprint TEXT
   );
   CREATE TABLE rule_findings_cache (
     content_hash TEXT, ruleset_hash TEXT, file_id INTEGER,
     findings_json TEXT,
     PRIMARY KEY (content_hash, ruleset_hash, file_id)
   );
   CREATE TABLE schema_version (version INTEGER);
   ```
2. **CLI subcommand:** `flutter-supabase-helper db build .` populates
   the DB. `flutter-supabase-helper db status` shows hit-rate /
   freshness. Stored at `<root>/.fsh-db/db.sqlite`.
3. **WAL mode** (`PRAGMA journal_mode=WAL`) for concurrent reader/writer.
4. **Cache invalidation:** content-hash check per file. If hash matches
   DB, skip parse entirely.
5. **§EN-8 incremental:** on save (or `--changed-since`), the scanner
   computes one-hop transitive importers from the `imports` table and
   re-runs only the affected set.
6. **Schema versioning:** refuse to load a DB whose
   `schema_version != current`; auto-rebuild on mismatch.
7. **Race:** SQLite advisory lock; queue scans against the same DB.

**Tests:**
- `db-build-then-scan-twice.js` — second scan ≥ 5× faster than first
  (relax to 2× for small fixtures).
- `db-stale-after-edit.js` — edit a file, scan, expect new findings
  reflect the edit.
- `db-schema-mismatch-rebuilds.js` — corrupt the version row, re-scan,
  expect auto-rebuild.

**Risks:**
- WAL on Windows can flake under unusual filesystems; document.
- SQLite write-amplification on big monorepos; test with the
  `parallel-scans-share-cross-file-summaries` synthetic fixture.

### 3.9. Phase I — IFDS for JS/TS §EN-9 (4–8 weeks)

**Why:** Phases B + E + F give us "summary-style" inter-procedural
taint. Real IFDS (callee→caller fact propagation through arbitrary
bodies) is more powerful and the solver
(`vscode-extension/src/taint/ifdsSolver.ts`, 431 LOC) is already
AST-agnostic.

**Steps:**

1. **Reuse the solver.** It consumes a `CodeGraph` from `models/graph.ts`
   that's language-neutral. Don't touch it.
2. **Write `ifdsBuilderJs.ts`** mirroring `ifdsBuilder.ts` (~815 LOC)
   for JS/TS AST. Each tree-sitter JS node type maps to one or more
   `Statement` / `Procedure` graph nodes:
   - `function_declaration` / `arrow_function` → `Procedure`
   - `assignment_expression` → `Assign`
   - `call_expression` → `Call` + `ReturnSite`
   - identified source returns → `Source`
   - identified sanitizer returns → `Sanitize`
   - identified sink calls → `Sink`
3. **Build cross-file ICFG** — when a `Call` resolves to a function in
   another file (via Phase B), add an inter-procedural edge.
4. **New rule** `ifds-taint-js` mirroring `IfdsTaintRule` in
   `rules/security/ifdsTaintRule.ts`. Gate behind a setting
   (`flutterSupabaseHelper.ifdsForJs: true`) until the COMPARISON.md
   fixtures land it.
5. **Migration:** keep the flat-walk engine alongside; pick one per
   finding via telemetry; flip default once IFDS matches or beats it.

**Tests:**
- COMPARISON.md fixtures 03, 04, 05, 09 should flip to HIGH.
- All 99 existing `scripts/taint-engine.test.js` tests pass on the
  IFDS path.

**Risks:**
- Worst-case exponential. Cap path-edges per procedure; emit
  `scanner-internal-error` and fall back to flat-walk on cap.
- JS doesn't have Dart's clean `class+method` shape — write the JS
  builder fresh; don't try to share class-resolution code.

### 3.10. Phase J — Smaller engine items

These are independent and small. Order by what unlocks the most §QW
or §RC items.

- **§EN-10 Async / event-loop semantics for Node** (~5 days):
  recognize `EventEmitter.on/once`, `process.on`, `Worker.postMessage`,
  `MessagePort`. Each handler's first parameter is tainted. Depends
  on §EN-2.

- **§EN-11 Field-sensitive class state across constructors** (~10 days):
  build a class hierarchy graph from `extends` clauses; constructors
  analyzed bottom-up; subclasses inherit parent's tainted-this set.
  Depends on §EN-1, §EN-3.

- **§EN-12 Receiver type narrowing via instanceof** (1 day on top of
  §EN-4): `if (x instanceof T) {…}` adds `(x, T)` to `narrowedTypes`
  in the dominated branch. Falls out of Phase C.

- **§EN-13 Loop-bounded analysis** (3 days post §EN-4): each loop body
  computed twice (or until fixed point with depth 3); lattice at exit
  is meet-over-paths. Trivial after Phase C.

- **§EN-14 Precise modeling of common builtins** (2-3 days): centralize
  the existing JSON.parse / String.replace / URLSearchParams.get work
  into `vscode-extension/src/taint/builtins.ts`. Each entry:
  ```ts
  { name: 'JSON.stringify', propagation: 'arg0' }
  { name: 'arr.join', propagation: 'arg0' }
  { name: 'URLSearchParams.get', propagation: 'always-tainted' }
  { name: 'crypto.randomBytes', propagation: 'none' }
  ```
  Pick the top 50 Node + browser builtins by usage. Each lands as one
  registry entry + one test.

- **§EN-15 Dynamic property access tightening** (1 day): new sink kind
  `dynamic-property-write`. Fires when `obj[tainted] = anything` (CWE-1321
  prototype pollution). Add to `_sinkForAssignment` in `dataFlow.ts`.
  Restrict to writes (read variant FPs heavily).

- **§EN-16 Symbolic execution for small expressions** (1 day post §EN-4):
  for `===`, `!==` against literals, true-branch narrows symbol to the
  literal; false-branch excludes it. Falls out of Phase C.

- **§EN-17 Engine telemetry for self-improvement** (1 week incl
  backend): opt-in upload of anonymous stats — rule-fire counts,
  scan duration, sast version. **Strict opt-in; no source code, no
  findings, no file paths.** Add `flutterSupabaseHelper.shareTelemetry`
  setting (default false). Schema:
  `{ runId: hash, ruleCounts: {code: n}, durationMs, sastVersion }`.

---

## § 4. Precision work after the CFG lands

All of these are unlocked by Phase C (§EN-4). Land them in this order:

### §PR-1 — Allowlist barrier guards (5 days post §EN-4)
Specs already in [`goals/04-precision.md`](goals/04-precision.md). The
guard recognizers go in `_recognizeGuard` from Phase C. Test with
COMPARISON.md fixture 11.

### §PR-2 — Type-narrowing guards (3 days post §EN-4)
`typeof x === 'number'` clears for `{sql, command, path, code, redirect}`
but NOT for `html`. Encoded via `BarrierKind.kind === 'numeric'`.
Per-sink-kind decision required.

### §PR-3 — Range / length guards (2 days post §EN-4)
`if (x.length < 1024)` doesn't clear injection taint but DOES clear
DoS-class findings. Add a `BarrierKind = { kind: 'length-bounded'; max: number }`.

### §PR-4 — Equality narrowing (1 day post §EN-4)
Falls out of §EN-16; trivially uses
`equalToLiterals` from the lattice.

### §PR-5 — Sanitizer evidence registry (5 days post §EN-1)
New `vscode-extension/src/taint/sanitizers.ts`. Each entry carries
`{ packageOrigin, method, sanitizesFor: Set<SinkKind> }`. Engine
consults import resolution (Phase B) to verify origin. If origin
unverified, downgrade trust to MEDIUM. **Unblocks §QW-1.**

Default registry to populate with:
- dompurify.sanitize, sanitize-html
- validator.escape / normalizeEmail
- sqlstring.escape, mysql.escape, pg-escape.literal/string
- lodash.escape, he.encode, xss-filters.inHTMLData

User-defined sanitizers via `.fshrc`:
```yaml
trustedSanitizers:
  - { from: './lib/sec', method: 'cleanHtml', forSinks: ['html'] }
```

### §PR-6 — Sink-specific sanitizer applicability (1 day post §PR-5)
The engine change is small: where sink check exists, intersect
`sanitizer.sanitizesFor` with `sink.kind`. This **closes §QW-1**.

### §PR-7 — Per-rule confidence calibration (1 week post §QE-2)
Empirical calibration from a labeled corpus. Run every rule against
the corpus; derive precision; tune confidence thresholds. Don't pursue
until §QE-4 (real CVE corpus) ships.

### §PR-8 — Confidence reasoning surfaced to user (2 days)
Compose `confidenceReason` from `Finding.pathSteps` and the rule's
CWE. Already half-implemented; finish in
[`vscode-extension/src/models/finding.ts`](vscode-extension/src/models/finding.ts).

### §PR-9 — Detection-method-aware confidence (3 days)
`DetectionMethod` enum already exists. Audit every rule's confidence
assignment; default mapping:
- taint-confirmed → HIGH
- structural / AST → MEDIUM
- regex / heuristic → LOW

### §PR-10 — Reachability-based downgrade (4 days post §EN-1)
DFS over the import graph from `package.json` `main` and `bin`.
Findings in unreachable code drop one severity step. Don't double-discount
test paths (`applyNonProductionNoiseReduction` already does that).

### §PR-12 — User-customizable barriers via config (4 days)
`.fshrc.yaml` `barriers` section. Extend `ScannerConfig`. Engine
consults config before applying default sanitizer registry.

### §PR-13 — Inferred sanitizers from inline annotation (3 days)
`/* @sast-sanitized */` comment marks the next AST node as
not-tainted. Different from `// sast-ignore`: still reachable to
other rules, just trusted by taint.

### §PR-14 — Explicit source/sink markers (3 days)
`/* @sast-source */`, `/* @sast-sink-sql */` for code-generated
shapes that don't fit existing patterns.

### §PR-16 — Symbolic-execution-lite for constants (3 days post §EN-4)
Track string-literal constants per scope; expand references in guard
expressions. Powers §QW-41 and §PR-4.

### §PR-17, §PR-19, §PR-20 — already done or trivial follow-ups.

---

## § 5. Rule coverage backlog

**Total: ~40 rules unstarted.** Each is 1-5 days. The big rocks:

| Anchor | Rule | Effort | Depends on |
|--------|------|--------|-----------|
| §RC-1 | Prototype pollution (CWE-1321) | M (3d) | §EN-15 |
| §RC-2 | ReDoS / catastrophic backtracking | M (4d) | — |
| §RC-3 | Log injection (CRLF) — full | S (1d) | §EN-2 |
| §RC-5 | Open redirect deepening | S (1d) | §EN-4 |
| §RC-6 | XML external entity (XXE) | M (3d) | — |
| §RC-7..§RC-9 | XPath / LDAP / command injection variants | S each | — |
| §RC-10 | Insecure deserialization variants | M (2d) | — |
| §RC-11 | SSRF cloud-metadata-aware | S (1d) | — |
| §RC-12 | XSSI | M (2d) | — |
| §RC-14 | Insecure file upload variants | M (2d) | — |
| §RC-15 | TOCTOU file race | S (1d) | — |
| §RC-16 | Improper authentication | L (~1w) | §EN-1 |
| §RC-17 | IDOR | L (~1w) | §EN-1 |
| §RC-26 | Type confusion | M (3d) | §EN-6 |
| §RC-28 | Resource exhaustion | L (~1w) | — |
| §RC-29 | Privilege escalation via SQL | M (3d) | §EN-1 |
| §RC-30 | Timing attack (`password === userInput`) | S (1d) | — |
| §RC-31 | Stored XSS (read-then-render) | L (~2w) | §EN-1 + DB-as-source models |
| §RC-32 | JNDI injection (Java) | S | §LC-7 |
| §RC-33 | JWT signature key confusion (extension) | M (3d) | — |
| §RC-34 | Per-route CORS | S (1d) | §EN-4 |
| §RC-36 | SSTI variants (EJS / Handlebars / Pug / Mustache / Nunjucks) | M (3d) | — |
| §RC-37 | WebView / iframe HTML | S (1d) | — |
| §RC-38 | IPC / message channel taint | M (3d) | — |
| §RC-40 | Second-order SQL injection | L (~2w) | stored-source modeling |
| §RC-41 | Attacker-controlled regex | S (1d) | §RC-2 |
| §RC-42 | Cache poisoning | L (~1w) | — |
| §RC-46 | CSRF token absence | L (~1w) | route-handler analysis |
| §RC-47 | Cloud-SDK over-permission | L (~1w) | — |
| §RC-49 | Improper input validation in crypto ops | L (~1w) | — |
| §RC-51 | WebSocket SSRF | M (2d) | — |
| §RC-52 | Insecure DNS | S (1d) | — |
| §RC-53 | Plain HTTP in mobile (NSAllowsArbitraryLoads, etc.) | S (1d) | — |
| §RC-54 | Eval template-literal injection — verify | S (1d) | — |
| §RC-57 | Insecure default permissions (chmod 0777) | S (1d) | — |
| §RC-59 | Login fixation (cookie TOCTOU) | L (~1w) | — |
| §RC-61 / §RC-62 | (assigned for future CVE classes) | — | — |

For each: mirror an existing rule's shape under
[`vscode-extension/src/rules/security/`](vscode-extension/src/rules/security/),
register in `rules/index.ts`, write the test in
`scripts/taint-engine.test.js`, mark §RC-N done in
`goals/03-rule-coverage.md` and the parent §QW-N if any.

---

## § 6. Language coverage and framework models

**The single largest absolute backlog.** All 17 §LC-* and 25 §FM-* items
are unstarted.

If pursuing **differentiation strategy:** skip all of §LC-9..13
(C#/Ruby/Swift/Kotlin/C/C++) and most of §FM-* except where they
serve mobile or Supabase.

### Per-language priority order (for either strategy)

1. **§LC-1 Python sources** (3 days) — Flask/Django/FastAPI/aiohttp/
   Tornado/Quart/Pyramid `request.X` patterns. Append regexes to
   `_isDirectSourceExpression`.
2. **§LC-2 Python ORM sinks** (3 days) — SQLAlchemy / Django ORM /
   peewee / asyncpg.
3. **§LC-3 Python framework views** (4 days) — `@app.route` decorator
   walking, return-as-sink modeling.
4. **§LC-4 Go sources** (3 days) — `r.URL.Query()`, gin `c.Query()`, etc.
5. **§LC-5 Go sinks** (4 days) — `db.Query`, `template.HTML`, etc.
6. **§LC-6 Java sources** (4 days) — Servlet, JAX-RS, Spring annotations.
7. **§LC-7 Java sinks** (1 week) — JDBC, JPA, JNDI, Hibernate.
8. **§LC-8 Java Spring framework deep models** (10 days) — depends on §LC-6, §EN-4.
9. **§LC-14 Dart IFDS source extension** (5 days) — Flutter
   `TextEditingController.text`, `MethodChannel.invokeMethod`,
   `getInitialLink`. Extend `ifdsBuilder.ts:DEFAULT_BUILDER_CONFIG`.
10. **§LC-15 Dart virtual dispatch** (2 weeks) — class-hierarchy walk
    in `ifdsBuilder.ts`. Depends on Phase A registry centralization.
11. **§LC-17 JavaScript ES feature audit** (1 day) — fixture corpus
    per ES feature; verify taint through each.
12. **§LC-9..13** (C#/Ruby/Swift/Kotlin/C/C++) — defer or skip per
    strategy.

### §FM-50 Framework auto-detection registry — DO THIS FIRST (3 days)

Without §FM-50, every §FM-N is dead code. Spec is in
[`goals/02-framework-models.md`](goals/02-framework-models.md). Concrete
steps:

1. Create `vscode-extension/src/taint/frameworks/index.ts`. Export
   `FrameworkContext` with `hasDependency(name)`, `hasFile(globPattern)`,
   `hasImport(specifier)`.
2. Each framework model exports a `FrameworkModel` value whose
   `detect(ctx) → boolean` runs once per scan.
3. Detected models' source/sink/sanitizer entries merge into the
   Phase-A registry.
4. Lazy-load: don't `import` every model file until detection passes.

Framework order (each is 1-5 days post §FM-50):

| Anchor | Framework | Effort |
|--------|-----------|--------|
| §FM-1 | Express.js | 3d |
| §FM-2 | Koa | 2d |
| §FM-3 | Fastify | 2d |
| §FM-4 | Hapi | 2d |
| §FM-5 | NestJS | 5d (decorators) |
| §FM-6 | Restify | 1d |
| §FM-7 | Next.js (server) | 1w |
| §FM-8 | Remix | 3d |
| §FM-9 | Astro / SvelteKit | 3d each |
| §FM-10 | AWS Lambda / API Gateway | 2d |
| §FM-11 | Cloudflare Workers / Vercel Edge | 1d |
| §FM-12 | Serverless Framework | 1d |
| §FM-13 | Django | 1w |
| §FM-14 | Flask | 3d |
| §FM-15 | FastAPI (Pydantic-aware) | 4d |
| §FM-16 | aiohttp / Tornado / Quart / Pyramid | 2d each |
| §FM-17..§FM-19 | Spring / JAX-RS / Quarkus / Micronaut | 2w / 1w / 1w |
| §FM-20..§FM-21 | Gin / Echo / Fiber / chi / net/http | 2d each / 3d |
| §FM-24..§FM-25 | React / Vue / Angular / Svelte XSS | 3d / 2d each |
| §FM-30..§FM-33 | Prisma / TypeORM / Sequelize / Drizzle / Mongoose | 2-3d each |

Each model lands as: one file under `taint/frameworks/`, one fixture
set under `test/fixtures/<framework>/`, one test in
`scripts/taint-engine.test.js`.

---

## § 7. Scale / DB layer

The big-rock §SC items are §SC-1 (DB) and §SC-3 (streaming) and §SC-5
(distributed workers). Specs in
[`goals/05-scale.md`](goals/05-scale.md). Order:

1. **§SC-3 streaming file walk** (~2 weeks) — convert `ProjectContext.files`
   from `ScannedFile[]` to `AsyncIterable<ScannedFile>`. Touches every
   rule (~70 rules read `context.files` directly). Have cross-file
   rules opt out via a `requiresFullCorpus: true` rule flag.
   Memory regression test: 10k file synthetic monorepo, peak RSS
   bounded.
2. **§SC-1 / §EN-7 SQLite DB** (6 weeks) — see Phase H above.
3. **§SC-2 / §EN-8 incremental rescan** (3-5 days post §SC-1) — see
   Phase H.
4. **§SC-5 distributed workers** (~3 weeks) — `worker_threads` pool,
   shard files by hash, master concatenates findings. Determinism:
   sort findings before master consumes. Tests: 10× speedup with 8
   workers on 10k-file synthetic.
5. **§SC-6 on-disk rule cache** (5 days post §SC-1) — per-file
   `<contentHash>+<rulesetHash> → Finding[]`. Cache hit-rate stat in
   scan output.
6. **§SC-9 per-rule fan-out** (1 week, ongoing) — opt-in `perFile: true`
   on Rule. Engine fans out via worker pool.
7. **§SC-10 lock-free shared state** (5 days post §SC-5) — audit each
   shared mutable map; replace with per-call return values.
8. **§SC-11 memory-mapped grammar loading** (1 day) — verify
   web-tree-sitter is lazy.
9. **§SC-12 db pre-warm** (1 day post §SC-1) — `db build` subcommand.
10. **§SC-13 sparse-checkout-aware traversal** (1 day) — count + report
    skipped-due-to-sparse files.
11. **§SC-14 auto-detect `.dockerignore`-style ignores** (1 day) —
    common paths (`coverage/`, `*.snap`, `vendor/`, `dist-test/`).
12. **§SC-15 multi-language scan parallelism** (3 days post §SC-5) —
    group rules by language tag; run groups in parallel.
13. **§SC-17 GC-friendly intermediate structures** (1 week) — profile
    the IFDS solver under a 10k-file synthetic; replace top 3 GC
    sources with flat typed arrays.
14. **§SC-18 progress estimation** (1 day) — two-phase: enumerate
    (cheap `readdir`), then load with `n/total`.

---

## § 8. Integrations remaining

[`goals/06-integrations.md`](goals/06-integrations.md) has the specs.

| Anchor | Item | Effort | Depends on |
|--------|------|--------|-----------|
| §IN-3 | GitHub PR review comments (line-level) | 5d | — |
| §IN-7 | Azure DevOps work items | 3d | — |
| §IN-12 | CycloneDX SBOM | ~2w | — |
| §IN-13 | Sigstore attestation | ~2w | — |
| §IN-14 | VS Code scan-on-type | 3d | §SC-3 |
| §IN-15 | VS Code findings tree view | 4d | — |
| §IN-17 | IntelliJ / JetBrains plugin | ~3w | Kotlin proj |
| §IN-18 | Vim / Neovim plugin | 1w | — |
| §IN-20 | Email notification (SMTP) | 1d | — |
| §IN-21 | Issue creation (Jira / Linear / GitHub Issues) | ~1w each | — |
| §IN-25 | Public GitHub Action (`@v1`) | 3d | — |
| §IN-26 | Web-based dashboard | ~6w | SQLite-backed |
| §IN-29 | Configuration file precedence (Dart ↔ JS unify) | 1w | — |
| §IN-31 | Cross-tool SARIF diff (`flutter-supabase-helper diff <ours> <theirs>`) | 4d | — |
| §IN-32 | Watch mode | 3d post §EN-8 | §EN-8 |

**§IN-3 is the highest-leverage one** — inline PR comments are how
adoption multiplies. Specifics:

- New CLI verb `flutter-supabase-helper pr-comment`. Inputs: SARIF
  file, GitHub token, PR number. Output: posted comments + summary.
- Use the GitHub GraphQL API (REST also works; GraphQL gives line
  matching for free).
- Filter findings to lines actually in the PR diff. Unmatched
  fingerprints fall back to a single summary comment.
- Don't double-post on re-runs: track posted comment IDs in a
  `.fsh-pr-comments.json` artifact uploaded to the workflow.

---

## § 9. Rule authoring DSL

[`goals/07-rule-authoring.md`](goals/07-rule-authoring.md). All 18
items unstarted. The umbrella deliverable: users can write
project-specific rules in YAML without recompiling.

Order:

1. **§RA-50** — design the registry. Where does a YAML rule live?
   `.fsh/rules/<name>.yaml`. Loaded at scan start; integrated with
   the existing rule registry.
2. **§RA-2 Pattern syntax: tree-sitter queries** (1 week) — document
   tree-sitter S-expression query syntax. Wire to `parser.query(source)`.
3. **§RA-1 YAML rule format** (3 weeks) — Semgrep-style. Schema
   includes: id, message, severity, cwe, category, patterns,
   pattern-not, where (metavariable constraints).
4. **§RA-3 metavariable binding** (1 week post §RA-2) — `$X`, `$Y`
   capture submatches.
5. **§RA-4 taint-aware constraint** (1 week post §RA-1) —
   `where: { $X: { kind: 'tainted' } }`.
6. **§RA-5 metadata** (2 days) — cwe, owasp, severity, references
   render in webview.
7. **§RA-6 npm-package rule packs** (1 week) — auto-load
   `node_modules/<pkg>` whose `package.json` declares
   `"sast": { "rules": "./rules" }`.
8. **§RA-8 rule unit-test harness** (3 days post §RA-1) —
   `flutter-supabase-helper test-rule` runs fixtures + asserts
   `expected.json`.
9. **§RA-11 JS plugin** (3 days) — `.js` rule file under `.fsh/rules/`
   exporting a `Rule` instance. Sandbox via `vm.runInNewContext`.
10. **§RA-12 fixture format** (3 days) — `tests/{positive,negative}-N.{js,expected}`.
11. **§RA-13 cross-language YAML rules** (3 days post §RA-1).
12. **§RA-14 negation operators** (post §RA-1) — `pattern-not`,
    `pattern-not-inside`.
13. **§RA-15 composition** (post §RA-1) — `pattern-either`, `patterns-and`.
14. **§RA-16 autofix authorship via YAML** (~2 weeks) —
    tree-sitter parse-tree replacement.
15. **§RA-17 backwards-compat** (ongoing) — versioned schema, auto-migration.
16. **§RA-18 inline-comment-driven rules** (2 days) —
    `/* @sast-warn: TODO use prepared statements */` surfaces as
    user-defined finding.
17. **§RA-7 rule pack registry** (~3 weeks).
18. **§RA-9 rule playground** (~3 weeks).
19. **§RA-10 rule deprecation** (1 day).

**This is the biggest moat we could build.** Both Semgrep and CodeQL
ship a DSL; ours would be the only one that's also free, mobile-aware,
and Supabase-aware.

---

## § 10. Quality / evals

[`goals/08-quality-evals.md`](goals/08-quality-evals.md). All 22 items
unstarted. The most important ones for credibility:

- **§QE-15 deterministic scans** (1 day) — audit + sort all output.
  Prerequisite for any benchmark CI.
- **§QE-16 perf regression CI** (1 day) — benchmark on every PR,
  fail >20% regress.
- **§QE-4 real-CVE corpus** (~4 weeks initial) — 100 real CVEs in
  OSS Node packages, vulnerable + patched versions. Pull from GitHub
  Advisory DB. Scanner runs on vulnerable versions; assert it catches
  ≥ N% of them.
- **§QE-10 differential vs CodeQL** (3 days) — `tool/differential.sh`.
  Findings only CodeQL has → coverage gap (high-signal hint of missing
  rule). Findings only we have → wins for COMPARISON.md.
- **§QE-11 differential vs Semgrep** (3 days) — same shape.
- **§QE-17 public leaderboard** (post §QE-10) — auto-updated against
  CodeQL on a shared corpus.
- **§QE-18..§QE-20** — versioned per-rule precision docs, soundness
  statements, CHANGELOG with deltas.
- **§QE-13 / §QE-14 AI-assisted explanation / fix** (1 week each) —
  optional `--explain` / `--fix-with-ai` flags. Off by default
  (privacy). User's configured LLM API; pin the prompt template.
- **§QE-12 ML-ranked findings** (~3 weeks) — depends on §QE-4. Logistic
  regression / GBM on hand-engineered features (path length, barrier
  presence, test-path proximity, file age, CWE-class historical FP rate).
  Use as `rank` in SARIF; don't suppress findings, just rank them.
- **§QE-22 fuzz the engine** (1 week) — jsfuzz / atheris feeding
  random source files.

Defer **§QE-1 (OWASP Benchmark)**, **§QE-2 (Juliet)**, **§QE-3 (SARD)**
unless we explicitly add language coverage that makes them meaningful.

---

## § 11. Supabase / Flutter remaining

[`goals/09-supabase-flutter.md`](goals/09-supabase-flutter.md). The
differentiation lane. **Ship these even if everything else slips.**

| Anchor | Item | Effort |
|--------|------|--------|
| §SF-1 (finish) | Edge-function dedicated rules: `Deno.env.get`, `kv.set`, `console.log(secrets)` | M (1w) |
| §SF-5 | RLS policy generation from DDL — parse `supabase/migrations/*.sql`, build `Map<table, Policy[]>`, cross-reference detected `tableAccesses` | L (~2w) |
| §SF-7 (finish) | Flutter deep-link sinks — `Navigator.pushNamed(deepLinkPath)` modeling | M (4d) |
| §SF-8 | Flutter `MethodChannel` argument taint — sink kind `native-channel`, "review-required" findings | M (3d) |
| §SF-16 | Dart IFDS cascade operator | M (3d) |
| §SF-17 | Dart IFDS named arguments | M (3d) |
| §SF-18 | Dart IFDS field-sensitive class members | L (~2w) |
| §SF-19 | Dart IFDS collection-sensitive (treat collections as a single fact) | L (~2w) |
| §SF-20 | Project template — `flutter-supabase-helper init` adds `.fshrc.yaml`, `.github/workflows/sast.yml`, pre-commit | M (1w) |
| §SF-21 | Best-practices guide — `docs/supabase-security.md`, linked from every Supabase rule's `fix` text | M (1w) |
| §SF-22 | Auto-generate RLS policies — aggregate detected access patterns, emit `migration.sql` | L (~2w) |
| §SF-23 | Migration safety review — `supabase-migration-risk` flagging drop-column / drop-table / break-FK | M (3d) |
| §SF-26 | Auth flow misconfig — missing email-verification, weak password policy, missing MFA, refresh-token reuse | L (~2w) |
| §SF-27 | Form validation gaps — `TextFormField` without `validator` | M (3d) |
| §SF-28 | PII disclosure via `logger` packages | M (3d) |
| §SF-29 | pubspec.lock vuln check — read pubspec.lock, cross-ref OSV | L (~2w) |
| §SF-30 | Cross-platform build artifact security — `.aab` / `.ipa` configs without obfuscation | M (3d) |

**Most-impactful single item: §SF-22 Auto-generated RLS policies.**
That's a feature CodeQL literally cannot offer — Supabase-specific,
real adoption wedge.

---

## § 12. Test infrastructure prerequisites

The test infrastructure is solid but a few things must hold for any
of the work above:

- **`scripts/taint-engine.test.js`** is the main unit test surface.
  Every new feature adds a section here. It runs as part of `npm test`.
- **Self-tests are wired into `vscode-extension/package.json`'s `test`
  script** (line 134). Add new `*.test.js` to the chain.
- **Dart-side tests** live under `test/`. Currently `test/scanner_test.dart`
  has a few pre-existing failures (8 fixtures from before the May
  sweep) — these are NOT caused by recent work; they failed even on
  `bb40237`. Audit and either fix or remove.
- **The `vscode` module is mocked in `scripts/hover-provider.test.js`**.
  Pattern: inject into `require.cache['vscode']` before requiring
  the compiled module. Reuse this for any future VS Code-bound test.
- **Type-checking is via `npx tsc`** from `vscode-extension/`. Run this
  before `npm test` — `npm test` does it automatically, but it's
  faster to fail early.
- **No CI exists yet.** §QE-16 spec has the design (1k-file synthetic
  monorepo + a real OSS repo, fail on >20% regress).

Before tackling any §EN-* phase, ensure:

1. `npm test` passes from a clean checkout.
2. `dart test` (Dart side) — note pre-existing failures.
3. `dart analyze` — should report info-level only.
4. The fixtures in `test/fixtures/` cover the rule you're about to
   touch (positive AND negative).

---

## § 13. Rollout sequencing & scheduling

Two sample roadmaps, depending on the §1 strategic choice.

### A — Differentiation roadmap (recommended; ~6 months)

```
Month 1: Phase A registry centralization (1 week)
         + §SF-1 finish + §SF-7 finish + §SF-8 (MethodChannel)
         + §SF-25 already done
         + §IN-3 GitHub PR comments (high adoption)

Month 2: Phase B (cross-file taint summaries §EN-1)
         + §FM-50 framework registry
         + §FM-1 Express + §FM-7 Next.js (the two biggest Node frameworks)

Month 3: Phase C (CFG + lattice §EN-4) — start
         + §SF-22 auto-generated RLS policies (in parallel; Supabase-specific)
         + §SF-23 migration safety

Month 4: Phase C finish + Phase J small items (§EN-12/13/15/16)
         + §PR-1 / §PR-2 / §PR-4 / §PR-12 (precision wins)
         + §QW-1 / §QW-2 / §QW-41 (the three blocked quick wins)

Month 5: Phase D (async §EN-2)
         + §SF-5 RLS-from-DDL
         + §EN-10 event-loop semantics
         + §SF-29 pubspec.lock vuln check (OSV integration)

Month 6: Phase H §EN-7 / §EN-8 DB + incremental — start
         + §IN-32 watch mode (depends on §EN-8)
         + §IN-15 VS Code findings tree view
         + §QE-4 real-CVE corpus (50 entries, expand later)
         + §QE-10 differential vs CodeQL
```

Outputs after 6 months: full CFG + cross-file taint, full Supabase
edge, watch mode, PR comments, real benchmark — that's a credible
differentiation pitch.

### B — Head-to-head roadmap (~12+ months)

```
Months 1-2: Phase A + Phase B (cross-file)
Months 3-4: Phase C (CFG)
Months 5-6: Phase D + Phase E (async + function pointers)
Months 7-8: §LC-1..§LC-8 (Python deep + Go + Java) + §FM-* batch
Months 9-10: Phase H (DB + incremental) + Phase I (IFDS for JS/TS)
Months 11+:  §QE-1 OWASP Benchmark, §QE-2 Juliet, §QE-3 SARD,
             §QE-12 ML-ranked findings, §RA-1 YAML DSL
```

---

## § 14. Acceptance criteria

"Fully done" is fuzzy. Concrete criteria the next agent should target:

### Engine refactor "done"

- [ ] All §EN-1..§EN-17 ✅ DONE in [`goals/00-engine.md`](goals/00-engine.md).
- [ ] COMPARISON.md has 12+ wins, ≤3 losses, 0 ties on a benchmark
      ≥ 50 fixtures (current is 6 wins / 4 losses / 5 ties on 15 fixtures).
- [ ] `precision-self-test` runs in <30s on 10k-file synthetic.
- [ ] Cache hit-rate on second scan ≥ 80% (§EN-7 / §SC-6).
- [ ] Watch mode (§IN-32) re-runs in < 1s for a single-file edit.

### Rule coverage "done"

- [ ] Every §RC-N marked ✅ DONE except those documented as deliberate
      non-goals in [`goals/10-non-goals.md`](goals/10-non-goals.md).
- [ ] Each rule ships with positive + negative fixtures.
- [ ] Each rule has CWE + confidence matched to its detection method
      (§PR-9).

### Supabase / Flutter "done"

- [ ] Every §SF-N ✅ DONE.
- [ ] `flutter-supabase-helper init` template (§SF-20) exists and is
      documented in README.
- [ ] `docs/supabase-security.md` (§SF-21) lives at root and is linked
      from every Supabase rule's `fix` text.
- [ ] §SF-22 auto-RLS-generation: emit a migration that, when applied,
      makes `missing-rls-awareness` return zero findings.

### Quality / evals "done"

- [ ] §QE-4 real-CVE corpus has ≥ 100 entries; CI runs on every PR.
- [ ] §QE-10 differential-vs-CodeQL runs in CI; report uploaded to
      every release.
- [ ] §QE-15 deterministic-scan check: same input → byte-identical
      SARIF.
- [ ] §QE-16 perf-regression CI; <20% regress threshold enforced.
- [ ] Per-rule precision/recall published (§QE-18 / §QE-5).

### Integrations "done"

- [ ] Every §IN-N ✅ DONE except those scoped out per §1's strategic
      decision.
- [ ] At minimum: §IN-3 (GitHub PR comments), §IN-31 (cross-tool
      diff), §IN-32 (watch mode).

### Final outputs

- [ ] README.md updated with every new feature and CLI flag.
- [ ] CHANGELOG.md per §QE-20 with per-rule precision deltas.
- [ ] `goals/README.md` "Strategy locked-in" section updated for
      whichever path was taken.
- [ ] `GOALS_PROGRESS.md` table 100% green or explicitly deferred.
- [ ] HANDOFF.md (this file) — replaced or annotated as "completed".

---

## How this doc was assembled

Compiled from:
- All twelve `goals/*.md` files (read in full).
- `GOALS_PROGRESS.md` task table.
- Source-grounded by reading
  `vscode-extension/src/taint/dataFlow.ts`,
  `vscode-extension/src/taint/ifdsBuilder.ts`,
  `vscode-extension/src/taint/ifdsEngine.ts`,
  `vscode-extension/src/taint/ifdsSolver.ts`,
  `vscode-extension/src/scanner/scanner.ts`,
  `vscode-extension/src/scanner/projectContext.ts`,
  `vscode-extension/src/rules/index.ts`,
  `vscode-extension/src/rules/rule.ts`.

Effort estimates inherit from the goals files. Multiply by 2-3× for an
LLM agent or new contributor per `goals/README.md`'s calibration table.

When picking up a phase, **always re-read the corresponding goals
file's section first** — line numbers and function names in this
document may drift as the code evolves; the goals files are the
stable spec.
