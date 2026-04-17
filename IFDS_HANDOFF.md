# IFDS Taint Engine — Handoff

Full handoff for another agent (or a future session) to continue the work
without re-discovering context. Read start to finish before editing.

## Repo & ground rules

- Repo: `/Users/icy/Documents/flutter-security-scanner` — a defensive static
  analysis tool for Flutter/Dart. Dart CLI lives in `lib/`, `bin/`. The VS
  Code extension lives in `vscode-extension/` and is meant to be a
  zero-config TypeScript SAST engine (no external SDK required).
- **Work on main. Never create worktrees.** Standing instruction from
  `~/.claude/projects/.../memory/MEMORY.md`.
- **Never add Claude/AI attribution** to commits, PRs, code, or docs.
- **Do not commit unless the user explicitly asks.** Propose the commit
  message and wait.
- **Do not fabricate test output.** Run the command. If it fails, fix the
  root cause.
- Do not add features, error handling, or abstractions beyond what the task
  requires.

## Current status (2026-04-17)

The production IFDS engine is landed on `main` as commit **`9baeca2`**
("Wire production IFDS taint engine into scanner pipeline"). All 10
fixtures in `scripts/ifds-self-test.js` pass. `npx tsc --noEmit -p .`,
`npm run compile`, and `npm test` are all green.

Runtime wiring: `extension.ts → commands/* → ProjectScanner →
buildDefaultRules → IfdsTaintRule (stage 3) → IfdsEngine →
IfdsGraphBuilder (uses SemanticResolver + CodeGraph) → IfdsSolver`.
The previously-orphaned files (`graph.ts`, `ifdsSolver.ts`,
`semanticResolver.ts`) are all transitively imported from the
extension entry point.

### What was delivered in 9baeca2

- Real Reps-Horwitz-Sagiv tabulation IFDS (path-edges, summaries keyed
  by entry fact, `pendingCallers` for late summary propagation,
  additive sources, strong-kill assigns, reach + returnLoc caches).
- tree-sitter-backed Dart CPG builder with real branching CFG:
  - if/else with merge point noop
  - while / do-while / for-in with back-edges
  - try/catch/finally flattened as a chain (sound, over-approximates)
  - method_signature unwrap for class methods
  - sink-with-lhs (always emits Sink; chains clear-assign on lhs)
  - for-in synthetic loop-var assign
  - template_substitution + identifier_dollar_escaped in interpolations
  - positional `sameNode` comparison (tree-sitter JS wrappers aren't
    reference-stable)
  - bare-assignment handling inside `expression_statement` (fixes
    strong-kill and branch-write drops)
- Per-file try/catch in engine so one malformed `.dart` file doesn't
  kill the scan; `locKey`-based fact indexing for clean Finding
  emission.
- 10 fixtures exercising intra / inter / sanitizer-neg / branching /
  reassignment-neg (strong kill) / class method / sink-with-lhs /
  for-each / multi-file ICFG / parse-error robustness.

### Self-test output (verbatim, last run)

```
> flutter-supabase-helper@1.0.0 test
> npm run compile && node scripts/precision-self-test.js && node scripts/test-ast.js && node scripts/ifds-self-test.js

> flutter-supabase-helper@1.0.0 compile
> tsc -p ./

Precision self-test passed.
Setting up temporary test file...
Loading ParserContext...
Parsing file...
Testing Traversal...
Loading Dart ParserContext...
Parsing Dart file...
AST Engine Validation Passed! ✔
IFDS self-test passed. 7 taint finding(s).
  - taint_branch.dart:9 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_class.dart:6 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_for.dart:4 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_inter.dart:7 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_intra.dart:4 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_mf_main.dart:5 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
  - taint_sink_lhs.dart:3 [high/high] Tainted value flows into sink `rawQuery` (IFDS)
```

## Remaining work before shipping to consumers

### Hard blockers

1. **Reconcile unrelated uncommitted work in the tree.** After `9baeca2`,
   `git status` still shows ~29 modified files and several untracked
   paths (`engine/`, `tools/`, `lib/src/output/baseline.dart`,
   `lib/src/output/finding_fingerprint.dart`, edits to every rule file,
   `vscode-extension/src/models/finding.ts`, `vscode-extension/src/taint/dataFlow.ts`,
   `bin/fluttersupabasehelper.dart`, `lib/fluttersupabasehelper.dart`,
   `lib/src/output/sarif_writer.dart`, etc.). Those are from prior work
   unrelated to IFDS. The repo is not in a coherent shippable state
   until the user either commits or reverts them. Do **not** touch
   these as part of the IFDS task.
2. **Smoke-test on a real Flutter repo.** The 10 fixtures are
   synthetic. Before shipping: one full run against a representative
   medium-size Flutter project. Confirm (a) scan time is acceptable —
   IFDS worst-case is O(nodes × facts), real codebases may be slow —
   and (b) false-positive rate is tolerable. If noisy, default the
   rule off or gate it behind a feature flag.
3. **`.fshrc` config integration.** Prior commit `8696f98` added
   `.fshrc.{yaml,yml,json}` with rule disable and severity override.
   Verify the new `ifds-taint` code honors both surfaces: user must be
   able to `disable: [ifds-taint]` or `severity: {ifds-taint: low}`.
   Not verified in this session; add a self-test if missing.
4. **CHANGELOG + README + version bump.** Nothing user-visible
   documents the new rule. Bump `vscode-extension/package.json`
   version, add a CHANGELOG entry, add a README section listing the
   `ifds-taint` code, its message, what sources/sinks/sanitizers it
   recognises, and how to suppress.
5. **Delete `IFDS_HANDOFF.md` OR relocate to `docs/`.** This file
   (the one you are reading) is a development log, not consumer
   documentation. Decide before ship: delete entirely, or move to
   `docs/internals/` if the team wants it kept for maintainers.

### Known limitations — ship with these documented, fix in follow-ups

- **Name-based source heuristic.** Only params named `userInput`,
  `input`, `req`, `request`, `payload`, `data`, `body`, `query`,
  `params` are treated as taint sources. Real sources (HTTP body/query,
  SharedPreferences, file reads, stdin, Supabase query params, incoming
  Realtime events) are not modeled. Expect false negatives.
- **No taint labels.** Any tainted value flowing into any sink fires.
  `escapeHtml` will "sanitize" a SQL sink. Conservative but imprecise.
- **No async/await modeling.** `await` is transparent; `await fut`
  does not cross through the call/returnSite machinery because
  `await_expression` isn't a statement kind we emit.
- **No cascade (`..`) operator.**
- **No named arguments.** `rawQuery(sql: userInput)` will parse, but
  argument extraction may miss the correspondence.
- **No field-sensitivity.** `obj.field = userInput; sink(obj.field);`
  will NOT fire — compound LHS is intentionally skipped in
  `emitAssignmentExpression` (LHS of shape `assignable_expression` with
  >1 named child).
- **No collection taint.** `list.add(userInput); sink(list[0]);`
  untracked.
- **No implicit-`this`.** `db.rawQuery` works because `db` is a local
  identifier in scope. `this.db.rawQuery(x)` may not resolve the same
  way — the builder detects dotted names but the procByName resolution
  is last-name only.
- **Virtual dispatch collision.** Two classes with a same-named method
  share the same summary keyed by last-name; calls resolve to whichever
  procedure was registered last.
- **Try/catch flattened as chain.** Sound but can overshoot (if a
  `finally` reassigns a variable, the flattened chain treats the
  reassignment as always-executed after the try body).
- **No finding trace.** Message is just "Tainted value flows into sink
  `X` (IFDS)" — no source line, no intermediate assigns, no path.
  Consumers will want a trace. Solver already has enough info
  (`reach: Reachability[]` with predecessor chain capability) to
  reconstruct one; currently not surfaced.
- **Dart CLI untouched.** The IFDS engine only runs inside the VS Code
  extension (TypeScript). The Dart CLI (`bin/fluttersupabasehelper.dart`)
  has its own pipeline with a separate, weaker taint module
  (`lib/src/rules/security/injection_rule.dart`). If "consumers"
  includes CLI users, the IFDS engine is not reachable there. Porting
  is a separate project.
- **No VS Code suppress syntax.** Consumers can disable the rule
  globally via `.fshrc` (pending verification per blocker #3) but
  there is no per-line `// ignore: ifds-taint` support unless the
  extension's generic suppression infrastructure already covers it
  (unverified).

### Suggested follow-up commits

Each should be self-contained and independently reviewable:

- **A.** Delete `IFDS_HANDOFF.md` (or move to `docs/internals/`).
- **B.** Verify `.fshrc` disable + severity override apply to
  `ifds-taint`; add a regression test if not covered.
- **C.** README + CHANGELOG entry + `package.json` version bump.
- **D.** Per-line suppression syntax (inline comment) if the
  extension doesn't already provide it.
- **E.** Real-repo smoke benchmark: pick a public Flutter app, run
  the extension against it, record scan time + finding count + first
  5 findings for manual triage. If performance is unacceptable,
  consider moving the rule to off-by-default and add a
  `flutterSupabaseHelper.ifdsTaint.enabled` setting.
- **F.** Finding-trace emission: thread the path-edge predecessor
  chain through `IfdsEngine.analyze` so the Finding's `message` (or
  a new `relatedLocations` field) can report the source line and
  intermediate writes.
- **G.** Expand `BuilderConfig` to be user-overridable via `.fshrc`
  (custom sources, sinks, sanitizers).
- **H.** Model `await_expression` and `cascade_section` in
  `ifdsBuilder.ts`.
- **I.** Field-sensitive assignment: record `obj.field` as a
  qualified Loc instead of dropping it.

## File inventory (post-9baeca2)

### Files committed in 9baeca2

- `vscode-extension/src/models/graph.ts` (new on disk; API-preserving
  rewrite of prior Gemini-authored file)
- `vscode-extension/src/taint/ifdsSolver.ts` (new; full RHS IFDS)
- `vscode-extension/src/taint/ifdsBuilder.ts` (new; tree-sitter CPG)
- `vscode-extension/src/taint/ifdsEngine.ts` (new; orchestrator)
- `vscode-extension/src/rules/security/ifdsTaintRule.ts` (new;
  stage-3 rule)
- `vscode-extension/src/ast/semanticResolver.ts` (new; includes
  `NodeKind.MethodDecl` fix)
- `vscode-extension/src/rules/index.ts` (modified; registers
  `IfdsTaintRule` after `UnsafeEvalRule`)
- `vscode-extension/package.json` (modified; `test` script now runs
  `ifds-self-test.js` after the existing tests)
- `vscode-extension/scripts/ifds-self-test.js` (new; 10 fixtures)

### Files intentionally NOT committed in 9baeca2

These are unrelated prior-session work sitting in the working tree.
Left untouched — the user must decide their fate:

Modified:
- `bin/fluttersupabasehelper.dart`
- `lib/fluttersupabasehelper.dart`
- `lib/src/models/finding.dart`
- `lib/src/output/sarif_writer.dart`
- `lib/src/rules/security/injection_rule.dart`
- `lib/src/rules/security/path_traversal_rule.dart`
- `tool/smoke_test.dart`
- `vscode-extension/src/models/finding.ts`
- `vscode-extension/src/rules/bugs/unsafeEvalRule.ts`
- `vscode-extension/src/rules/config/{debugCode,environmentVariables,improperInitialization,invalidSupabaseUrl,multipleSupabaseClients,placeholderEnvValues}Rule.ts`
- `vscode-extension/src/rules/secrets/genericSecretRule.ts`
- `vscode-extension/src/rules/security/{clientSideTrust,committedEnv,fileUploadValidation,hardcodedSecrets,injection,publicStorage,sensitiveLogging,xss}Rule.ts`
- `vscode-extension/src/rules/supabase/{missingRlsAwareness,rlsPolicySuggestion,tableOwnership}Rule.ts`
- `vscode-extension/src/taint/dataFlow.ts`

Untracked:
- `IFDS_HANDOFF.md` (this file)
- `engine/`
- `lib/src/output/baseline.dart`
- `lib/src/output/finding_fingerprint.dart`
- `test/fixtures/.sast-telemetry.json`
- `test/fixtures/path_traversal_app/.sast-telemetry.json`
- `tools/`

### Files deleted prior to 9baeca2 (not tracked by git; already gone)

- `vscode-extension/test_proof.ts` (never committed)
- `vscode-extension/out_test/` (never committed)
- `vscode-extension/scripts/probe-dart-ast.js` (throwaway debug)
- `vscode-extension/scripts/probe-ifds.js` (throwaway debug)

## How to pick up

```bash
cd /Users/icy/Documents/flutter-security-scanner/vscode-extension
npx tsc --noEmit -p .         # must exit 0
npm run compile               # must succeed
npm test                      # must pass precision + AST + IFDS self-tests
```

If any test fails, fix the engine at root cause — do **not** weaken
the test. Common pitfalls already encountered and fixed (don't
regress):

- Tree-sitter JS wrappers are not reference-stable — use `sameNode(a,b)`
  (by startIndex/endIndex/type), never `===` or `indexOf`.
- Dart grammar emits `identifier_dollar_escaped` inside
  `template_substitution`, not plain `identifier`.
- `method_signature` wraps an inner `function_signature`; unwrap before
  extracting name/params.
- `expression_statement > assignment_expression > assignable_expression
  (identifier), <rhs>` — bare assignments inside blocks are this shape.
  Do not route them through `detectCall` (they have no `argument_part`);
  use `emitAssignmentExpression`.
- Compound LHS (`obj.field = ...`) intentionally skipped — scalar name
  unchanged, no modeling distortion.
- Sinks with LHS (`final rows = db.rawQuery(...)`) must still emit a
  Sink node; chain a clear-assign on lhs to conservatively kill prior
  taint on the lhs name.

### Useful AST probe

`tree-sitter-dart`'s WASM is at
`vscode-extension/node_modules/tree-sitter-dart/tree-sitter-dart.wasm`.
Quick AST dump template:

```js
const WebTreeSitter = require('web-tree-sitter');
const path = require('path');
(async () => {
  await WebTreeSitter.init();
  const wasm = path.resolve('node_modules/tree-sitter-dart/tree-sitter-dart.wasm');
  const lang = await WebTreeSitter.Language.load(wasm);
  const parser = new WebTreeSitter();
  parser.setLanguage(lang);
  const dump = (n, d = 0, max = 10) => {
    if (d > max) return;
    console.log('  '.repeat(d) + n.type + ' [' + n.text.slice(0, 80).replace(/\n/g, ' ') + ']');
    for (let i = 0; i < n.namedChildCount; i++) dump(n.namedChild(i), d + 1, max);
  };
  dump(parser.parse(process.argv[2] ?? '').rootNode);
})();
```

Delete any such probe script before finishing — they're throwaway
debug.

## Ground-truth test commands

```
cd vscode-extension
npx tsc --noEmit -p .
npm run compile
npm test
```

All three must exit 0. Paste raw output in the final report. Do not
fabricate.
