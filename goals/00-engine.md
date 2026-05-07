# 00 — Engine fundamentals

This file lists every architectural improvement the taint engine needs to
match CodeQL's analysis depth on JavaScript / TypeScript. Dart already has
IFDS via `vscode-extension/src/taint/ifdsEngine.ts` — for Dart-specific
engine work see also [09-supabase-flutter.md](09-supabase-flutter.md).

The current intra-procedural tracker lives at
[`vscode-extension/src/taint/dataFlow.ts`](../vscode-extension/src/taint/dataFlow.ts)
(1804 LOC). Read it before working in this file. The class to extend is
`IntraProceduralTaintTracker`.

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

- ✅ Dart-side IFDS engine landed (sha 9baeca2 + 21c9cbb): `ifdsEngine.ts`,
  `ifdsBuilder.ts`, `ifdsSolver.ts` wired into the pipeline + `ifds-taint`
  rule. Out of §EN-* scope (which targets JS/TS) but covers the
  architectural concerns the §SF-14..19 Dart-IFDS tasks build on.
- 🟡 §EN-14 (taint through built-ins) — quick-win subtasks landed:
  `JSON.parse`/`JSON.stringify`/`Buffer.from` propagation (§QW-39),
  `URLSearchParams.get` source (§QW-40), allowlist-stripping
  `.replace(..., '')` sanitizer (§QW-38) — sha d0af6b4. Larger
  built-in registry still pending.
- ⏳ §EN-1, §EN-2, §EN-3, §EN-4, §EN-5..§EN-13, §EN-15, §EN-16 — the
  cross-file, async, CFG, type-narrowing, and decorator engine work
  remains unstarted.

---

## §EN-1 — Cross-file taint summaries (JS/TS) ⏳ REMAINING

- **Why:** Real Node apps split sources and sinks across files. Today, a
  source defined in `helpers.js` and consumed in `routes.js` is downgraded
  to MEDIUM (dynamic-only) because we don't trace the source across the
  module boundary.
- **Current state:** `_computeFunctionSummaries` in `dataFlow.ts:308` only
  records same-file `function f(p) { return <direct-source>; }` patterns.
  Cross-file imports / exports are entirely opaque to the engine.
- **Target state:** A function exported from one module is recognized as a
  source if its body returns a recognized source expression, OR as a
  passthrough if its body returns one of its parameters. Result:
  benchmark fixture 04 (`04-cross-file-source.js` in COMPARISON.md) flips
  from MEDIUM to HIGH.
- **Approach:**
  1. Add a `ProjectSummaryCache` populated **before** any rule runs.
     For every file, record: `Map<{exportedName, file}, FunctionSummary>`.
     `FunctionSummary` already exists in `dataFlow.ts:53` — extend with
     `returnsParameterIndex: number | null` for passthrough.
  2. Resolve imports by walking `import_statement` / `import_declaration`
     / `require_call` AST nodes. CommonJS `module.exports = { foo }` and
     ES `export { foo }` both produce the same `(localName → exportedName)`
     map. Build a `ImportResolver` that, given a call site `helpers.foo(x)`
     in module A and a recognized import of `helpers` from module B,
     returns `summaries.get({ exportedName: 'foo', file: B })`.
  3. Use the summary in `_expressionTaintStrength` when the call's name
     matches an imported symbol. Direct-source returns → strength `direct`.
     Passthrough → recursively check the corresponding argument.
  4. Cache invalidation: a single `clear()` on the cache between scans
     suffices for our in-memory model. For `--changed-since` mode,
     re-summarise only changed files plus their importers (one transitive
     hop usually enough).
- **Dependencies:** none — can land independently.
- **Effort:** **L** (~10 days). The hard part isn't the algorithm; it's
  the import resolution across CommonJS / ESM / TypeScript path aliases /
  `tsconfig.paths`. Use existing `tsconfig.json` parsing only — don't try
  to invoke the TS compiler.
- **Tests:**
  - Add `parallel scans share cross-file summaries` to
    `vscode-extension/scripts/taint-engine.test.js`.
  - Re-run COMPARISON.md fixture 04 — should flip HIGH.
- **Risks / gotchas:**
  - Re-export chains (`export * from './a'`) are common; handle by
    transitively resolving until you hit a definition or hit a cycle.
  - Default exports in CJS look like `module.exports = function(req) {...}`.
    Treat the whole file as a single "default" export.
  - Don't trust `tsconfig.paths` blindly — fall back to relative resolution
    on miss.

## §EN-2 — Async / Promise / callback taint

- **Why:** Most modern Node apps live inside `.then()`, `await`, and
  callback functions. Today we miss everything past `Promise.resolve(x).then(y => …)`.
- **Current state:** `walkAst` in `dataFlow.ts` skips into nested
  `function`/`arrow_function` scopes via `FUNCTION_SCOPE_TYPES` but the
  callback's parameter is not seeded with the calling site's argument's
  taint. The callback runs in its own scope with no inherited taint.
- **Target state:** `Promise.resolve(tainted).then(arg => … sink(arg))`
  flags as direct taint. Same for `Promise.then(cb)`, `array.forEach(cb)`,
  `array.map(cb)`, `setTimeout(cb)` (when `cb` is a function expression),
  `await Promise.resolve(tainted)` returns tainted.
- **Approach:**
  1. Detect "thenable-shaped" calls: any call whose receiver looks like
     a Promise (heuristic: name matches `/then|catch|finally`) AND whose
     argument is a function expression. The first parameter of that
     function inherits the receiver's resolved-value taint.
  2. To track receiver's resolved-value: extend `ScopeState` with a
     `resolvedValueTaint: Map<symbol, TaintProvenanceStep[]>`. Populated by
     `Promise.resolve(x)`, `Promise.reject(x)`, `Promise.all([…])`, and
     `await someExpr`.
  3. For `await x`, evaluate `_expressionTaintStrength(x, state)`. If
     tainted, the await result is tainted with the same chain.
  4. For `array.map/forEach/filter/find` — first param is the array
     element. If the array's element type carries taint
     (`taintedProperties` on the array symbol), seed the callback param.
  5. Detect callback-passed sinks: `app.get('/u', (req, res) => …)` —
     the existing `_seedScope` handles this since `req` is a strong
     parameter name. Verify it works for arrow functions inside method
     calls (arrow_function nodes nested under call_expression).
- **Dependencies:** none.
- **Effort:** **L** (~12 days). The mechanism is mechanical; the long
  tail of "what about this Promise shape" is what eats time.
- **Tests:**
  - Add `Promise.then propagates taint`, `await on tainted Promise`,
    `array.map element taint`, `setTimeout function arg seeds taint` to
    `scripts/taint-engine.test.js`.
  - Re-run COMPARISON.md fixture 05 — should flip HIGH.
- **Risks / gotchas:**
  - `Promise.all([...])` returns an array; element taints must be tracked
    component-wise (use existing `taintedProperties`).
  - Top-level `await` in modules — the await is at module scope, not
    inside a function. Make sure `_inheritFromEnclosing` handles
    program-level scope.
  - Some libraries return Promise-likes without literal "Promise" naming
    (e.g. RxJS Observables). Don't try to model these; document as a gap.

## §EN-3 — Whole-program function pointer / class table

- **Why:** Inter-procedural taint (§EN-1) doesn't help when the call is
  through a variable: `const fn = getInput; fn(req)`. We need a coarse
  flow-insensitive model of "which function values does this symbol
  refer to."
- **Current state:** No model. Function references through variables are
  invisible to the engine.
- **Target state:** A `Map<symbol, Set<functionId>>` per module so that
  `const fn = getInput; fn(req)` is treated as if `getInput(req)` was
  written.
- **Approach:**
  1. Pre-pass: walk the AST collecting `assignment_expression` /
     `variable_declarator` whose RHS is a `function_declaration`,
     `function_expression`, `arrow_function`, or `identifier` referencing
     another known function. Build `functionPointers: Map<symbol, FunctionId>`.
  2. At call sites where the callee is a variable, look up the symbol in
     `functionPointers`. If found, treat the call as if it were the
     resolved function.
  3. For class methods: build a `Map<className, Map<methodName, FunctionId>>`
     during class-declaration walks. At call sites `obj.method(...)`
     where the type of `obj` can be narrowed by allocation
     (`new MyClass()`), resolve the method.
- **Dependencies:** §EN-1 (cross-file imports) for resolving exported
  classes.
- **Effort:** **L** (~10 days).
- **Tests:**
  - `function-pointer-via-variable.js` — `const fn = source; sink(fn(req))`
    should flag HIGH.
  - `class-method-resolved-by-allocation.js` — `new UnsafeDb().query(req.body.x)`
    should flag eval inside that method.
- **Risks / gotchas:**
  - Don't try to resolve dynamic dispatch (`x[name]()`) — it's
    undecidable without runtime info.
  - JavaScript's prototype chain is a rabbit hole. Limit to literal
    `class X { m() {} }` and ES module imports.
  - Method assignment (`X.prototype.method = function …`) is rare in
    modern code — punt to a later iteration.

## §EN-4 — Path-sensitive analysis (CFG + guards)

- **Why:** Today, conditional sanitization is conservatively NOT trusted
  (`_collectConditionallyAssigned` in `dataFlow.ts:551`). This biases
  toward false positives — a real codebase that sanitizes inside an
  if-branch is reported as still tainted.
- **Current state:** No control-flow graph. The engine is flow-sensitive
  intra-procedurally only via the order it walks AST nodes.
- **Target state:** A small CFG built per function. Sanitization on a
  branch updates the join point if the branch dominates the join. An
  allowlist guard like `if (!ALLOWED.has(x)) return null;` clears taint
  on `x` for code dominated by that branch.
- **Approach:**
  1. Build a CFG per function during the per-function walk. Nodes are
     statements; edges are control-flow (true/false branches, loop back-
     edges, exception edges, return edges).
  2. Per-node: maintain a `TaintLattice` rather than a flat `tainted: Set`.
     Lattice element = `{ tainted: Set<symbol>, sanitized: Set<symbol>,
     barriers: Map<symbol, BarrierKind> }`. Join over predecessors at
     CFG merge points.
  3. Guards: detect `if (cond) {…}` patterns where `cond` is a
     "barrier-shape" — `Set.has(x)`, `Map.has(x)`, `Array.includes(x)`,
     `x === LITERAL`, `typeof x === 'string'`, `Number.isInteger(x)`,
     `x instanceof T`. Inside the matching branch, `x` is a barrier;
     outside, no change.
  4. Loop bodies: be conservative — assume zero or many iterations,
     join the body's exit lattice with the pre-loop state. This is
     CodeQL's strategy and it works.
- **Dependencies:** none, but pairs naturally with §EN-2.
- **Effort:** **XL** (4–8 weeks). This is the single biggest precision
  win and the single biggest engineering effort in this file.
- **Tests:**
  - Re-run COMPARISON.md fixture 11 (SSRF allowlist) — should flip from
    HIGH to no-flag.
  - `parseInt-on-every-path.js` — fixture 06 — should remain no-flag
    (regression).
  - 15+ guard-shape unit tests in `scripts/taint-engine.test.js`.
- **Risks / gotchas:**
  - Switch statements with fall-through.
  - try/catch/finally — exception edges to `catch` block aren't always
    drawable from AST alone.
  - JSX: complex conditional rendering. Punt to a later iteration; treat
    JSX as straight-line for now.
  - Don't try to model `&&` / `||` short-circuit barriers in the first
    cut; defer to a follow-up.

## §EN-5 — Field-sensitive object / array tracking

- **Why:** The current model is partial: `taintedProperties` on
  `dataFlow.ts:65` tracks tainted props but degrades to "weak" indirect
  taint after `MAX_TAINT_DEPTH=3`. Real apps build deep objects (e.g.
  `req.body.address.line1`) and we lose the chain.
- **Current state:** Per-object tainted-property set. Three-deep alias
  chain limit. Object literals carry component-wise taint.
- **Target state:** Full path-based field tracking up to 8 deep. After
  that, downgrade gracefully to indirect rather than losing taint.
- **Approach:**
  1. Replace `taintedProperties: Map<symbol, Set<string>>` with
     `taintedPaths: Map<symbol, Trie>` where Trie nodes carry per-step
     provenance.
  2. On `obj.a.b.c = src`, record path `[a, b, c]` as tainted. On
     `obj.a.b.c` access, look up the path. Partial matches (path prefix
     hit) propagate as indirect.
  3. Computed property writes (`obj[expr] = src`) — if `expr` resolves
     to a literal at our analysis time, treat as the literal. Otherwise
     mark `obj` as fully tainted (every prop).
- **Dependencies:** None directly, but works much better with §EN-4
  (path sensitivity).
- **Effort:** **L** (~8 days).
- **Tests:** New section in `scripts/taint-engine.test.js`:
  `obj.body.x assignment then read`, `nested-write nested-read`,
  `computed-property-with-literal-key`, `computed-property-with-dynamic-key
  pessimizes`.
- **Risks / gotchas:**
  - Spread (`{ ...src, x: 1 }`) needs to copy all of `src`'s taint paths
    into the new literal.
  - Array index taint: `arr[0]` vs `arr[i]` — pessimize the latter.

## §EN-6 — Type-aware sink resolution (TypeScript only)

- **Why:** `analytics.query(event)` and `db.query(sql)` are
  syntactically identical. Today we use a name-based receiver heuristic
  (`_receiverLooksLikeDb`) which has known FNs (a variable named `pool`
  could be a thread pool, not a DB pool).
- **Current state:** Tokenized name match against
  `DB_RECEIVER_KEYWORDS` (`dataFlow.ts:91`). Decent precision, real FNs.
- **Target state:** When the file is TypeScript and a `tsconfig.json`
  exists, use the TypeScript Language Service to resolve the type of the
  receiver expression. If type is `Database` / `Pool` / `Connection` from
  `@types/pg` etc., flag with HIGH; otherwise fall back to the heuristic.
- **Approach:**
  1. Lazy-load the TypeScript compiler API (`typescript` package, peer
     dep). Build a `LanguageService` per workspace once per scan.
  2. At a SQL-named call site, ask the LS for the type of the receiver
     expression. Match against a known type registry:
     `pg.Pool`, `pg.Client`, `mysql2.Connection`, `sqlite.Database`,
     `mongoose.Model`, `prisma.PrismaClient`, etc.
  3. If the type resolves, trust it absolutely (raise to HIGH or skip).
     If unresolvable, fall back to the existing heuristic.
- **Dependencies:** Requires the `typescript` peer dep — make it
  optional. No-op gracefully when missing.
- **Effort:** **L** (~10 days). The TS LS is well-documented but
  initialising it correctly across ESM/CJS/path aliases is finicky.
- **Tests:**
  - `tsconfig-paths-resolved.ts`, `pg-pool-types-resolved.ts`,
    `mysql2-connection-types-resolved.ts` — all should flag the SQL.
  - `analytics.query()-with-known-type.ts` should NOT flag.
- **Risks / gotchas:**
  - LS startup is slow. Cache across scans within the same VS Code
    session.
  - Don't run in CLI by default (slow); add `--type-check` flag.

## §EN-7 — Whole-program data-flow database

- **Why:** Re-running the full taint analysis on every scan duplicates
  work. CodeQL builds a database once and queries are fast.
- **Current state:** No persistent state between scans. `--baseline`
  tracks previous findings but the engine starts cold.
- **Target state:** A `flutter-supabase-helper db build .` command
  produces a `.fsh-db/` directory containing per-file ASTs, function
  summaries, import graphs, and index files. Subsequent scans read the
  DB and process only changed files.
- **Approach:**
  1. SQLite (single file, no daemon, no merge headaches). Tables:
     `files(path, mtime, content_hash)`, `functions(file, name, …)`,
     `summaries(function_id, returns_direct_source, returns_param_index)`,
     `exports(file, exported_name, function_id)`,
     `imports(from_file, to_file, name)`,
     `findings(rule, file, line, …)`.
  2. On scan: for each file, hash content; if matches DB, skip. If
     different, re-summarise and update.
  3. For `--changed-since`: use git to identify modified files plus
     their importers (one transitive hop).
- **Dependencies:** Pairs with §EN-1.
- **Effort:** **XL** (~6 weeks).
- **Tests:**
  - `db-build-then-scan-twice.js` — second scan should be 10× faster.
  - `db-stale-after-edit.js` — edit a file, re-scan, must produce the
    correct new findings.
- **Risks / gotchas:**
  - SQLite write-amplification on big monorepos. Use WAL mode.
  - Schema migrations as we evolve the engine. Version the DB; refuse
    to load incompatible versions; auto-rebuild on mismatch.
  - Race on parallel scans against the same DB. Use SQLite advisory
    lock; queue scans.

## §EN-8 — Incremental rescan

- **Why:** On-save scans (already opt-in via `scanOnSave`) re-scan the
  whole workspace. For monorepos this is unacceptable.
- **Current state:** `extension.ts:111-128` debounces saves and runs
  `scanWorkspace` for the entire project.
- **Target state:** On save, only re-analyse the changed file plus its
  immediate transitive importers.
- **Approach:**
  1. Requires §EN-7 (DB) — without persistent summaries, "incremental"
     means nothing.
  2. The save handler computes the changed file's import-fan-in (one
     hop) using `imports` in the DB.
  3. Re-summarise the changed file, re-run rules on it and the fan-in
     set.
- **Dependencies:** §EN-7.
- **Effort:** **M** (3–5 days once §EN-7 is done).
- **Tests:** `incremental-edit-changes-only-affected-files.js`.
- **Risks / gotchas:**
  - Symlinks. Resolve to canonical paths before DB lookup.
  - File rename. Track via mtime + content hash; fall back to full scan
    on mtime/hash mismatch.

## §EN-9 — Inter-procedural taint for JS/TS (full IFDS)

- **Why:** §EN-1 (summary-based) handles direct passthrough. Real
  inter-procedural needs callee→caller fact propagation through
  arbitrary function bodies, not just `return param`.
- **Current state:** `vscode-extension/src/taint/ifdsEngine.ts` is
  Dart-only (3 files: builder/solver/engine for Dart AST). JS/TS uses
  the simpler intra-proc tracker.
- **Target state:** The IFDS solver from `ifdsSolver.ts` is reused for
  JS/TS by writing a `ifdsBuilderJs.ts` that builds the same `CodeGraph`
  shape from JS/TS ASTs.
- **Approach:**
  1. The solver (`ifdsSolver.ts`) is already AST-agnostic — it consumes
     a `CodeGraph`. The builder is the language-specific part.
  2. Mirror `ifdsBuilder.ts` but for JS/TS AST: each tree-sitter node
     type maps to one or more `Statement` / `Procedure` nodes.
  3. Sources / sinks / sanitizers come from a shared registry already in
     `dataFlow.ts` — extract into `taint/registry.ts` so both engines
     consume from one place.
  4. Wire `IfdsTaintRule`-style hookup for JS/TS, gated by a setting
     (`flutterSupabaseHelper.ifdsForJs: true`) until precision is
     validated.
- **Dependencies:** §EN-1, §EN-3, §EN-5 — IFDS gives us all three of
  these "for free" but the registry / class table / cross-file work is
  cleaner to do first.
- **Effort:** **XL** (4–8 weeks).
- **Tests:**
  - All COMPARISON.md fixtures 03, 04, 05, 09 should flip to HIGH.
  - Existing 26 unit tests must continue passing on the IFDS path.
- **Risks / gotchas:**
  - Dart's IFDS handles ~Class+method shapes that JS doesn't have
    cleanly. Don't try to share class-resolution code; let the JS
    builder be its own thing.
  - IFDS is exponential in worst case; cap path-edges and return
    "incomplete" rather than hanging.

## §EN-10 — Async / event-loop semantics for Node

- **Why:** Node's event loop is the source of subtle taint flows
  (`process.on('message', cb)`, `worker.postMessage`, IPC channels).
- **Current state:** Not modeled.
- **Target state:** Recognized event handlers seeded as taint sources;
  recognized message-passing receivers tracked.
- **Approach:** Model `EventEmitter.on/once`, `process.on`,
  `Worker.postMessage`, `worker_threads`, `MessagePort`. Each handler's
  callback first parameter is tainted.
- **Dependencies:** §EN-2.
- **Effort:** **M** (~5 days).
- **Tests:** New fixture set under `test/fixtures/event-loop/`.
- **Risks / gotchas:** Web-worker semantics differ from worker_threads.
  Document scope.

## §EN-11 — Field-sensitive class state across constructors

- **Why:** `_computeClassReceiverStates` (`dataFlow.ts:341`) injects
  constructor-tainted `this.X` props into sibling methods at MEDIUM
  confidence. CodeQL handles this at full confidence with proper class
  hierarchy.
- **Current state:** Indirect-taint only across constructor → method.
  Subclass / inheritance not modeled.
- **Target state:** Class hierarchy walked; tainted `this.X` from a
  parent constructor visible to subclass methods. Override resolution.
- **Approach:**
  1. Pre-pass: build a class hierarchy graph from `class_declaration`
     `extends` clauses. Resolve names through §EN-1.
  2. Constructor analysis runs bottom-up (parents first). Subclass
     constructors see parent's tainted-this set as a baseline.
  3. Method resolution: when resolving `this.method()`, look up the
     class's own table, then walk parents.
- **Dependencies:** §EN-1, §EN-3.
- **Effort:** **L** (~10 days).
- **Tests:** `class-hierarchy-tainted-this.ts`,
  `subclass-overrides-method-with-tainted-arg.ts`.
- **Risks / gotchas:**
  - Mixins and decorators in TypeScript — punt; document as gap.
  - JS class fields (`class X { count = 0; }`) — supported in modern
    Node, must handle in the constructor synthesis.

## §EN-12 — Receiver type narrowing via instanceof / typeof

- **Why:** `if (db instanceof PgPool) db.query(req.body.x)` should be
  narrowed even without TS types.
- **Current state:** No narrowing.
- **Target state:** Inside an `instanceof` true-branch, the symbol's
  effective type is the asserted class. Used both for sink resolution
  and method dispatch.
- **Approach:** Part of §EN-4's guard reasoning. `if (x instanceof T)
  …` adds `(symbol, T)` to a `narrowedTypes` map for the dominated branch.
- **Dependencies:** §EN-4.
- **Effort:** **S** (1 day on top of §EN-4).
- **Tests:** `instanceof-narrows-receiver-type.ts`.
- **Risks / gotchas:** None significant.
- **Progress:** §QW-2 landed at sha pending (2026-05-07). Without the
  full §EN-4 CFG/lattice we approximate the dominated region by walking
  parents from the call site looking for an enclosing `if_statement` whose
  consequence contains the call and whose test is a (possibly &&-conjoined)
  `x instanceof T`. SQL-sink resolution consults this map: if the receiver
  symbol narrows to a DB-shaped class (`Pool`, `PrismaClient`, `Sequelize`,
  `Database`, …) the call resolves as `sql` even when the receiver name
  isn't itself DB-shaped. A full lattice-based narrowing for every
  expression / typeof / arbitrary sink kind still tracks here.

## §EN-13 — Loop-bounded analysis

- **Why:** Loops can both clear and re-introduce taint. Pessimizing
  every loop body destroys precision.
- **Current state:** Loops are walked once (since AST traversal is
  one-pass). The engine doesn't model the iterative effect.
- **Target state:** Each loop body computed twice (or until a fixed-
  point with bounded depth, e.g. 3). The lattice at exit is the
  meet-over-paths.
- **Approach:** With CFG (§EN-4), back-edges are visible. Run worklist
  until no change or 3 iterations.
- **Dependencies:** §EN-4.
- **Effort:** **M** (3 days post §EN-4).
- **Tests:** `for-of-tainted-array-each-element-tainted.ts`,
  `for-loop-sanitization-on-every-iteration.ts`.
- **Risks / gotchas:** Generators / async iterators — defer.

## §EN-14 — Precise modeling of common builtins

- **Why:** `String.prototype.replace`, `JSON.stringify`, `Array.prototype.join`,
  `URLSearchParams.get` — each has well-defined taint behavior. Today
  we treat all of them as opaque calls (returns unknown).
- **Progress:** §QW-38/39/40 landed at sha `d0af6b4` (2026-05-07):
  sanitizer recognition for allowlist-style `String.prototype.replace`,
  `JSON.parse` / `JSON.stringify` / `Buffer.from` taint propagation, and
  `URLSearchParams.get(...)` as user-controlled query input. The broader
  registry of ~30 builtin signatures remains open.
- **Current state:** Partial builtin support exists for the quick-win cases
  above. The engine still lacks a centralized registry for the wider builtin
  set below.
- **Target state:** A registry of ~30 builtin signatures with explicit
  taint behavior:
  - `JSON.stringify(tainted)` → tainted
  - `JSON.parse(tainted)` → tainted (object)
  - `String.replace(tainted, /…/, sanitizer)` → sanitized iff sanitizer
    matches a known sanitizer pattern
  - `arr.join(', ')` with tainted element → tainted result
  - `URLSearchParams.get(literal)` → tainted (always — query strings
    are user-controlled)
  - `Buffer.from(tainted)` → tainted
  - `crypto.randomBytes(n)` → never tainted
  - …
- **Approach:** New `taint/builtins.ts`. Each entry:
  `{ name, propagation: 'arg0'|'all'|'none'|'sanitize'|'always-tainted' }`.
  Consulted in `_expressionTaintStrength` before falling through to
  unknown-call-strips-taint.
- **Dependencies:** None.
- **Effort:** **M** (2–3 days for the first 30 entries; ongoing).
- **Tests:** `builtin-json-stringify-propagates.ts`, etc.
- **Risks / gotchas:** Don't aspire to 100% coverage. Pick the top 50
  Node/browser builtins by usage frequency.

## §EN-15 — Dynamic property access tightening

- **Why:** `obj[userInput]` is a vulnerability surface (prototype
  pollution, lookup attacks). Today we don't track this.
- **Current state:** No detection of `[tainted]`.
- **Target state:** A new sink kind `dynamicPropertyWrite` that fires
  when `obj[tainted] = anything` (CWE-1321 — prototype pollution).
- **Approach:** Add to `_sinkForAssignment`. Also add a rule
  `prototype-pollution` covering common merge / extend / set
  patterns.
- **Dependencies:** None.
- **Effort:** **S** (1 day).
- **Tests:** Re-run COMPARISON.md fixture 07 — should flip HIGH.
- **Risks / gotchas:** Heavy FP risk if applied to every `obj[x]`.
  Restrict to `obj[x] = …` writes initially.

## §EN-16 — Symbolic execution for small expressions

- **Why:** Equality guards (`if (x === 'admin')`) should narrow `x` in
  the true-branch. Today we don't.
- **Current state:** No symbolic execution.
- **Target state:** For `===`, `!==`, `==`, `!=` against literals,
  inside the true-branch the symbol equals the literal; inside the
  false-branch it doesn't.
- **Approach:** Part of §EN-4. When the lattice meets at a branch,
  apply the equality fact.
- **Dependencies:** §EN-4.
- **Effort:** **S** (1 day on top of §EN-4).
- **Tests:** `equality-narrows.ts`.
- **Risks / gotchas:** Don't try `<` / `>` / `>=` ranges in the first cut.

## §EN-17 — Engine telemetry for self-improvement

- **Why:** We don't know which rules over- or under-fire in the wild.
  CodeQL has years of telemetry.
- **Current state:** Local telemetry per scan
  (`_telemetryFilePath`) but no aggregate analysis.
- **Target state:** Opt-in upload of anonymous statistics: rule-fire
  counts, FP/FN rates from suppression patterns, scan duration. Public
  dashboard. **Strict opt-in; no source code, no findings, no file
  paths**.
- **Approach:** Add a setting `flutterSupabaseHelper.shareTelemetry`
  (default false). When true, periodic POST to a public endpoint.
  Schema: `{ runId: hash, ruleCounts: {code → n}, durationMs, sastVersion }`.
- **Dependencies:** None code-side. Requires hosting a backend.
- **Effort:** **M** (1 week including backend).
- **Tests:** Verify nothing leaks even with logging on.
- **Risks / gotchas:** Privacy. Audit the payload; never include
  filePath, message, or finding text.
