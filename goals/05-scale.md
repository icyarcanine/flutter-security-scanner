# 05 — Scale

CodeQL handles enterprise monorepos (100k+ files, gigabytes of source)
via incremental databases and tabulated facts. Today we load every
supported file into RAM and re-run rules from scratch on every scan.
This file covers the work to make us competitive on real-world repos.

Read [00-engine.md §EN-7 / §EN-8](00-engine.md) first — the DB layer
is the underpinning for everything here.

---

## §SC-1 — Whole-program SQLite database

See [00-engine.md §EN-7](00-engine.md). Repeated here for the scale
narrative; the implementation lives there.

- **Why:** Avoid re-parsing every file on every scan.
- **Effort:** **XL** (~6 weeks).

## §SC-2 — Incremental rescan on file change

See [00-engine.md §EN-8](00-engine.md).

- **Effort:** **M** post §EN-7.

## §SC-3 — Memory bounds: streaming file walk

- **Why:** Today `ProjectContext.load` reads every supported file into
  RAM before rules start. For monorepos with thousands of files this
  is a hard upper bound on what we can scan.
- **Current state:**
  `vscode-extension/src/scanner/projectContext.ts:128` walks and reads
  every file synchronously into `files: ScannedFile[]`.
- **Target state:** Stream the file walk; rules consume one
  `ScannedFile` at a time. The `ProjectContext` exposes async
  iterator instead of an array.
- **Approach:**
  1. Change `ProjectContext.files` from `ScannedFile[]` to
     `AsyncIterable<ScannedFile>`.
  2. Rules consume via `for await (const file of context.files())`.
  3. Aggregations (env entries, table accesses, etc.) become lazy:
     compute on first access, store in a Map keyed by file path.
- **Dependencies:** None code-side. Touches every rule though — major
  refactor.
- **Effort:** **L** (~2 weeks).
- **Tests:** Memory regression test: scan a synthetic monorepo with
  10k files; assert peak RSS stays bounded.
- **Risks / gotchas:**
  - Cross-file rules (cross-file taint, multi-file dependency
    detection) need a different model — they require all files visible.
    Have those rules opt out of streaming, falling back to RAM-loaded.
  - The progress callback gets called per-file already; no change
    there.

## §SC-4 — Bounded file size budget ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** A 10 MB minified bundle blocks the scan. Today we skip
  files > 1 MB silently.
- **Current state:** `projectContext.ts:147` skips silently.
- **Target state:** Skip with a logged warning; report skipped count
  in scan stats. Configurable limit via `.fshrc.yaml`:
  `maxFileSize: 5MB`.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - `ProjectContextLoadOptions.maxFileSizeBytes` (0 disables; default
    1 MB via `DEFAULT_MAX_FILE_SIZE_BYTES`).
  - `ProjectContext.skippedFiles: SkippedFile[]` exposes
    `{relativePath, sizeBytes, reason: 'oversize'}`.
  - `ProjectScanReport.skippedFiles` proxies through; `mergeReports`
    absolutizes paths so multi-root scans report unambiguous locations.
  - Console warning lists the largest 5 oversize files on every scan.
  - JSON / pretty / summary outputs all carry a skipped-files line.
  - `--max-file-size <size>` CLI flag accepts `5MB`/`512KB`/`1g`/plain bytes.
  - YAML-driven configurability lands with §IN-30 (config schema).
  - Test: `scripts/file-size-budget.test.js`.

## §SC-5 — Distributed scan workers

- **Why:** A 10-minute scan on a monorepo could be 30 seconds on 20
  workers.
- **Current state:** Single-threaded (Promise.all parallelism within
  rules, but a single Node process).
- **Target state:** Worker pool. Each worker processes a partition of
  the file set. Aggregator merges findings.
- **Approach:**
  1. `worker_threads` based pool. Master shards the file set by
     hashing relative path.
  2. Workers run rules independently; produce per-shard finding
     arrays.
  3. Master concatenates and runs cross-file passes (cross-file taint,
     dedupe).
- **Dependencies:** Pairs naturally with §SC-1 (DB) — workers read DB
  partitions.
- **Effort:** **L** (~3 weeks).
- **Tests:** Performance regression: 10k file synthetic monorepo,
  10× speedup with 8 workers.
- **Risks / gotchas:**
  - WASM grammars don't share across worker_threads; each worker
    re-loads. Acceptable on first scan; cache binary.
  - Determinism: sort findings deterministically before the master
    consumes; don't trust worker ordering.

## §SC-6 — On-disk rule cache (per-file finding cache)

- **Why:** If a file's content didn't change AND no rule's source
  changed, the findings can be served from cache.
- **Current state:** No cache.
- **Target state:** Per-file `<contentHash>+<rulesetHash> → Finding[]`
  cache. On scan, each rule first hits the cache; only re-runs rules
  whose source/version changed.
- **Approach:** Cache key = SHA-1(file content + rule source +
  scanner version). Stored in DB (§SC-1) under `rule_findings_cache`.
- **Dependencies:** §SC-1.
- **Effort:** **M** (~5 days post §SC-1).
- **Tests:** Cache hit rate stat in scan output.

## §SC-7 — Lazy AST parsing across rules (already partial)

- **Current state:** `ScannedFile.astPromise` already de-dupes
  concurrent parses (race fix in `scannedFile.ts`). AST is built once
  per scan per file.
- **Target state:** Maintained; consider caching AST across scans in
  the DB (per §SC-1 and §EN-7).
- **Effort:** Maintenance.

## §SC-8 — Bounded rule runtime ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** A pathological rule (catastrophic regex) shouldn't hang
  the scan.
- **Current state:** Per-rule errors are isolated
  (`scanner.ts:_runStage`'s catch) but no timeout.
- **Target state:** Each rule.evaluate() runs under a 30-second
  budget (configurable). Exceeded → reported as `scanner-internal-error`
  with the rule code.
- **Approach:** `Promise.race([rule.evaluate(ctx), timeout(30000)])`.
- **Dependencies:** None.
- **Effort:** **S** (1 day).
- **Tests:** Inject a deliberately-slow fixture; assert timeout fires.
- **Implementation notes:**
  - `DEFAULT_RULE_TIMEOUT_MS = 30_000` exported from `scanner.ts`.
  - `ProjectScannerOptions.ruleTimeoutMs` (0 disables; default 30s).
  - `--rule-timeout <ms|s|m>` CLI flag accepts plain ms or `30s`/`5m`.
  - Timeout emits a `scanner-internal-error` Finding (low severity, high
    confidence) naming the rule and budget so the abort isn't silent.
  - Test: `scripts/rule-timeout.test.js` — patches the rule registry with
    a synthetic always-pending rule and a fast sibling, asserts the slow
    rule is aborted and the fast rule's findings still come through.

## §SC-9 — Parallelism across files within a single rule

- **Why:** Today F34 parallelizes ACROSS rules in a stage. A
  per-file rule could itself parallelize across files inside one stage.
- **Current state:** Each rule is a single async function consuming
  the whole context.
- **Target state:** Optional per-rule "fan-out" mode. Rule declares
  `perFile: true` and gets called once per file; engine fans out via
  worker pool.
- **Approach:** Extend `Rule` interface with optional `perFile?: boolean`
  + per-file evaluator. Refactor 5–10 rules with the heaviest per-file
  work first.
- **Dependencies:** §SC-5 (workers) for full parallelism.
- **Effort:** **M** (1 week, ongoing as more rules adopt).

## §SC-10 — Lock-free shared state

- **Why:** Concurrent rule execution still mutates shared state
  (telemetry, dedupe maps). With workers (§SC-5), this would be unsafe.
- **Current state:** All shared state is in-process Maps. Single Node
  process keeps mutations safe.
- **Target state:** Shared state moved to immutable per-rule
  results that the master aggregates.
- **Approach:** Audit each shared mutable map. Replace with per-call
  return values.
- **Dependencies:** §SC-5.
- **Effort:** **M** (5 days).

## §SC-11 — Memory-mapped grammar loading

- **Why:** Each WASM grammar is 1–10 MB. Cold-cache scans pay this on
  every file extension's first read.
- **Current state:** WASM loaded once per process via the in-flight
  promise (race fix in `parser.ts`).
- **Target state:** WASMs lazily mmap'd from disk; if the grammar's
  not used in this scan, no memory cost.
- **Approach:** `web-tree-sitter` already supports lazy loading; verify
  we're not eagerly loading grammars the scan doesn't need.
- **Effort:** **S** (1 day).

## §SC-12 — Index pre-warming

- **Why:** First scan of a fresh repo is slow because the DB hasn't
  been built. CI's first run is the slowest.
- **Current state:** No pre-warm.
- **Target state:** A `db build` subcommand pre-builds all indexes;
  subsequent `scan` is fast.
- **Approach:** New CLI verb `flutter-supabase-helper db build .`.
- **Dependencies:** §SC-1.
- **Effort:** **S** (1 day post §SC-1).

## §SC-13 — Sparse-checkout-aware traversal

- **Why:** Monorepos with sparse checkouts have files mentioned in
  config but not present on disk.
- **Current state:** Walker handles missing files via try/catch but
  doesn't surface counts.
- **Target state:** Report skipped-due-to-sparse counts.
- **Effort:** **S** (1 day).

## §SC-14 — `.dockerignore`-style scanner ignore (in addition to
`.gitignore`)

- **Why:** Some monorepos commit large generated assets that ARE
  tracked by git but shouldn't be scanned (e.g. source maps, test
  fixtures).
- **Current state:** `.sastignore` handles this.
- **Target state:** Auto-detect common paths (`*.test.ts.snap`,
  `coverage/`, `dist-test/`, `vendor/`). Configurable.
- **Effort:** **S** (1 day).

## §SC-15 — Multi-language scan parallelism

- **Why:** A scan that touches JS + Python + Go could run those
  language-specific passes in parallel.
- **Current state:** Each rule sees all files; per-rule filtering is
  the only language separation.
- **Target state:** Phase 1 — language-agnostic phase (regex on all
  files). Phase 2 — per-language phase, parallel across languages.
- **Approach:** Group rules by language tag; run groups in parallel.
- **Dependencies:** §SC-5.
- **Effort:** **M** (3 days post §SC-5).

## §SC-16 — Telemetry for scan duration distribution ✅ DONE — sha e330ed4 (2026-05-07)

- **Why:** We don't know if scans are getting slower over time.
- **Target state:** Per-scan: total duration, per-stage duration, per-
  file p50/p95/p99 durations stored in local telemetry.
- **Approach:** Extend `_telemetryFilePath` payload.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - `ProjectScanReport` now exposes `stageDurationsMs`.
  - The scanner records `loading`, `fast`, `ast`, and `taint` stage
    timings and persists the same distribution in local telemetry.
  - JSON output includes the stage timing block under `stats`.

## §SC-17 — GC-friendly intermediate data structures

- **Why:** TypeScript arrays of small objects pressure the GC at scale.
- **Current state:** Plain `Finding[]` arrays.
- **Target state:** Audit hot paths; replace some object patterns with
  flat Float32Array / Uint32Array for IFDS path edges.
- **Approach:** Profile a 10k-file synthetic monorepo. Optimize the
  top 3 GC sources.
- **Effort:** **L** (~1 week including profiling).

## §SC-18 — Scan progress estimation

- **Why:** Today the user sees "Loading files: 234" with no idea how
  many total files there are.
- **Current state:** Per-file count only.
- **Target state:** Two-phase: enumerate first (cheap, just `readdir`),
  then scan with `n/total` progress.
- **Approach:** Already feasible — just add an enumerate pass before
  the load pass.
- **Effort:** **S** (1 day).
