# Rust Engine Resurrection — Implementation Progress

> **Live tracking document for the work specified in
> [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md).**
>
> Format: each phase has a status line, a checklist, and a diary block for
> notes / blockers / deviations. **Update this file as work happens, not in
> retrospect.** If a step deviates from the blueprint, record the why under
> "Deviations".
>
> Status legend: ⬜ pending · 🟡 in progress · ✅ done · ⛔ blocked · ⏭️ skipped

---

## Status summary

| Phase | Status | Started | Completed | Notes |
|-------|--------|---------|-----------|-------|
| P0  Toolchain + un-gitignore | 🟡 | 2026-05-08 | — | Rust 1.85 installed; engine source unignored; git add/commit pending owner direction |
| P1  Make engine-core compile | 🟡 | 2026-05-08 | — | default engine-core build passes; full-feature build pending system deps |
| P2  Workspace + frontends | ✅ | 2026-05-08 | 2026-05-08 | Workspace tests build all four crates and pass |
| P3  CLI binary | 🟡 | 2026-05-08 | — | binary works end-to-end; smoke-test rule produces 0 findings (Semgrep compiler gap, see Risks) |
| P4  CI workflow | ⬜ | — | — | — |
| P5  TS sidecar integration | ⬜ | — | — | — |
| P6  Deprecate TS IFDS | ⬜ | — | — | — |
| P7  Dart sidecar integration | ⬜ | — | — | — |
| P8  Z3 SMT correlator | ⬜ | — | — | (deferrable) |
| P9  Remove TS IFDS | ⬜ | — | — | — |
| P10 Acceptance gates | ⬜ | — | — | — |

---

## Phase 0 — Toolchain + un-gitignore

**Status:** 🟡 mostly done — Rust installed and engine source unignored; staging/commit pending owner direction.

**Goal:** `cargo --version` ≥ 1.85.0 succeeds; `engine/` source is not ignored; source is staged/committed when the owner asks.

### Checklist

- [x] **P0-1** Install rustup + 1.85.0 toolchain + clippy + rustfmt
- [ ] **P0-1** wasm32 target — *deferred until WASM work becomes active*
- [ ] **P0-1** macOS deps via brew (`cmake llvm rocksdb z3`) — *deferred to first compile that needs them*
- [x] **P0-2** Delete `engine/` from `.gitignore` (replaced with narrower `engine/target/` + `engine/Cargo.lock` exclusions)
- [ ] **P0-2** `git add engine/ .gitignore` / commit (deferred until owner approves)

### Diary

- 2026-05-08 09:00: toolchain audit confirms `cargo`, `rustup`, `~/.cargo`, `~/.rustup` all absent. Awaiting user go-ahead on `curl | sh` rustup install.
- 2026-05-08 09:05: P0-2 done — replaced bulk `engine/` ignore with narrower `engine/target/` + `engine/Cargo.lock`. Engine source is now untracked-but-discoverable; commit deferred per global no-autonomous-commit policy.
- 2026-05-08 10:40: Codex verified `cargo 1.85.0` and active toolchain `1.85.0-aarch64-apple-darwin`. `rustup target list --installed` currently lists only `aarch64-apple-darwin`; wasm target is deferred.

### Deviations from blueprint

- **P0-2 narrower than the original blueprint.** The old plan said "delete lines 25-27"; actual state replaces the broad ignore with `engine/target/` and `engine/Cargo.lock` so build artefacts and lockfile churn don't pollute git history. The blueprint has been updated to match this current policy.

---

## Phase 1 — Make `engine-core` compile in isolation

**Status:** 🟡 default path verified — full-feature build still pending system deps.

**Goal:** `cargo build -p engine-core` and `cargo build -p engine-core --features full` both exit 0.

### Checklist

- [x] **P1-1** Rewrite `[features]` block in `engine/crates/engine-core/Cargo.toml`
- [x] **P1-2** Cfg-gate `pub mod dart_analyzer` in `engine-core/src/lib.rs:54`
- [x] **P1-3** Wrap `engine-core/src/supabase/smt.rs` Z3-using parts in `#[cfg(feature = "smt-proofs")]` + stub for the disabled case
- [x] **P1-4** Standardise `rustc-hash` rename in three crate `Cargo.toml`s (CLI Cargo.toml is replaced wholesale in P3-3)
- [x] **P1-5** `cargo build -p engine-core` exits 0
- [ ] **P1-5** `cargo build -p engine-core --features full` exits 0 — *pending brew/system deps*
- [x] **P1-5** `cargo test -p engine-core` ≥ 7 unit tests pass (`cargo test --workspace` ran 14 engine-core tests)

### Diary

- 2026-05-08 09:10: P1-1 done. Renamed `persistence` → `persist` to match the cfg gate at `lib.rs:41`. Added `analyzer-bridge` feature for the dart_analyzer sidecar. Switched `["rocksdb"]` / `["z3"]` to `["dep:rocksdb"]` / `["dep:z3"]` to suppress the implicit-feature lint.
- 2026-05-08 09:12: P1-2 done. Module `dart_analyzer` now gated behind `analyzer-bridge`.
- 2026-05-08 09:18: P1-3 done. **Smaller change than blueprint suggested** — the file already had `#[cfg(target_arch = "wasm32")]` gates around the Z3-using `mod native` and the WASM stub. I just swapped them to `#[cfg(feature = "smt-proofs")]` and `#[cfg(not(feature = "smt-proofs"))]` respectively. Data types (CorrelationQuery, DartClientModel, etc.) live above the gate so they always compile. Far cleaner than the blueprint's `mod imp` wrapping plan.
- 2026-05-08 09:20: P1-4 done. Three `Cargo.toml`s updated. CLI Cargo.toml is rewritten in P3-3 with the canonical form already.
- 2026-05-08 10:41: Codex verified `cargo build -p engine-core` exits 0 with warnings. `cargo test --workspace` exits 0 and runs 14 engine-core tests. Full-feature build still needs the Z3/RocksDB system dependency decision.

### Deviations from blueprint

- **P1-3 simpler than blueprint.** Blueprint suggested wrapping the entire smt.rs body in `mod imp` + writing a parallel stub module duplicating every public type. Reality: the file already had a WASM/native split with both branches compiling, so I only needed to swap the cfg condition from `target_arch` to `feature = "smt-proofs"`. Net change: 4 lines of cfg attributes flipped, no duplicated type definitions.

---

## Phase 2 — Workspace + frontends

**Status:** ✅ verified — workspace tests build all four crates and pass.

**Goal:** `cargo build --workspace` exits 0.

### Checklist

- [x] **P2-1** Add 3 missing crates to `[workspace] members` in `engine/Cargo.toml`
- [x] **P2-2** Replace `engine/crates/engine-frontend-dart/Cargo.toml`
- [x] **P2-3** Replace `engine/crates/engine-frontend-rust/Cargo.toml` (incl. `tree-sitter-rust = "0.21"`)
- [x] **P2-3** Add `tree-sitter-rust = "0.21"` to workspace deps in root Cargo.toml
- [x] **P2-4** Replace `extern "C"` linkage with `tree_sitter_dart::language()` in `engine-frontend-dart/src/lib.rs`
- [x] **P2-4** Same for `engine-frontend-rust/src/lib.rs`
- [x] **P2-5** Rewrite `map_kind` in `engine-frontend-dart/src/ast_builder.rs:68-105`
- [x] **P2-5** Audit and fix NodeKind references in other Dart frontend files (only `pdg_builder.rs` had stale `Param`)
- [x] **P2-6** Add `Unknown` variant to `NodeKind` in `engine-core/src/cpg/graph.rs`
- [x] **P2-7** Fix `crate::engine_core::cpg::AstEdge` → `engine_core::cpg::AstEdge` in `pdg_builder.rs`
- [x] **P2-8** Apply NodeKind cleanup to `engine-frontend-rust/src/ast_builder.rs:59-91`
- [x] **P2-9** `cargo build --workspace` exits 0 (`cargo test --workspace` built all four crates)

### Diary

- 2026-05-08 09:25: P2-1 done. Workspace now lists all four crates.
- 2026-05-08 09:27: P2-2/P2-3 done. Both frontend Cargo.tomls now use `workspace = true` for shared deps. Bumped `tree-sitter-rust` from broken `0.0.1` → `0.21`. Added `tree-sitter-rust` to root workspace deps.
- 2026-05-08 09:30: P2-4 done. Both frontends now use `tree_sitter_*::language()` instead of `extern "C"`. No `unsafe` block needed.
- 2026-05-08 09:32: P2-6 done first (blocking P2-5). Added `NodeKind::Unknown` as the catch-all variant.
- 2026-05-08 09:34: P2-5 done. Mapped CST kinds to actual `NodeKind` variants (no `Block`/`IfStmt`/etc.). Added `getter_signature`/`setter_signature` mappings while I was there. `extension_definition` now maps to `ExtensionDecl` (was incorrectly `MixinDecl`). `switch_statement` now maps to `Switch`.
- 2026-05-08 09:35: Audit found `pdg_builder.rs` still used `NodeKind::Param` in two places — fixed both.
- 2026-05-08 09:36: P2-7 done. Two `crate::engine_core::cpg::AstEdge` → `engine_core::cpg::AstEdge` fixes in `pdg_builder.rs`.
- 2026-05-08 09:38: P2-8 done. Rust frontend's `ast_builder.rs` updated. No stale references in its `cfg_builder.rs`.
- 2026-05-08 10:41: Codex verified `cargo test --workspace` exits 0, including all four crates. Warnings remain and are tracked for the later clippy gate.

### Deviations from blueprint

- **P2-5 added bonus mappings** for `getter_signature` / `setter_signature` (mapped to `GetterDecl`/`SetterDecl`) — variants exist in `NodeKind` and the Dart grammar produces them; no reason to skip.
- **P2-5 corrected `extension_definition`** mapping from `MixinDecl` to `ExtensionDecl`. Original code's "Close enough for CPG" comment was wrong — `ExtensionDecl` is a distinct variant in the enum.
- **P2-8 collapsed Rust loops.** Blueprint left `for_expression`/`while_expression`/`loop_expression` as separate matches; collapsed into a single arm mapping to `NodeKind::Loop`. Same semantic outcome, less code.

---

## Phase 3 — CLI binary

**Status:** 🟡 partial — workspace builds, all 14 tests pass, CLI runs end-to-end, but smoke-test rule doesn't match yet.

**Goal:** End-to-end smoke test from blueprint P3-4 produces the expected finding line.

### Checklist

- [x] **P3-1** Replace entire contents of `engine/crates/engine-cli/src/main.rs`
- [x] **P3-2** Add `pub fn flow(&self) -> &FF` and `pub fn graph(&self) -> &CodeGraph` accessors on `IfdsSolver`
- [x] **P3-2** Add `pub fn source_node_ids/sink_node_ids/sanitizer_node_ids` accessors on `SemgrepFlowFunctions` (returning `impl Iterator<Item = NodeId>` because the underlying storage is `HashMap<NodeId, _>` not `Vec<Match>`)
- [x] **P3-3** Replace `engine/crates/engine-cli/Cargo.toml`
- [⚠️] **P3-4** Smoke test: engine runs (CPG built: 35 nodes/34 edges, IFDS executed in 0.4ms), **but rule produces 0 findings instead of 1**. Pattern matcher does not currently fire on the fixture. Engine binary works; rule semantics don't yet. Tracked as Phase 5+ work.

### Diary

- 2026-05-08 09:42: P3-2 done. **API differs from blueprint** — actual `SemgrepFlowFunctions` stores `source_nodes: FxHashMap<NodeId, MetavarBindings>`, not `sources: Vec<Match>`. Added accessors that yield `impl Iterator<Item = NodeId>`. Also added `IfdsSolver::graph()` since the CLI needs it for byte-offset → line/col conversion.
- 2026-05-08 09:48: P3-1 done. Full rewrite of `main.rs` (116 broken lines → 235 working lines). Adds JSON + SARIF output paths, env-filter tracing, byte-offset → line/column helper, three subcommands implicit through `--format`.
- 2026-05-08 09:50: P3-3 done. CLI Cargo.toml uses `workspace = true` for shared deps, declares the binary explicitly with `[[bin]]`, depends on both frontend crates.

### Deviations from blueprint

- **P3-2 accessor names match storage shape.** Blueprint suggested `sources()`/`sinks()`/`sanitizers()` returning `&[Match]`. Actual storage is `FxHashMap<NodeId, MetavarBindings>` (sources/sinks) and `FxHashSet<NodeId>` (sanitizers) — `Vec<Match>` only exists transiently inside `load_rule()`. Renamed to `source_node_ids()` / `sink_node_ids()` / `sanitizer_node_ids()` returning `impl Iterator<Item = NodeId>` to match what's actually on the struct without forcing an allocation.
- **P3-1 added `IfdsSolver::graph()` accessor.** The CLI needs the graph to look up file paths and byte ranges; the blueprint omitted this dependency. Added as a no-op `#[must_use] pub fn graph(&self) -> &CodeGraph`.
- **P3-1 main.rs is 235 lines, not 116.** Larger than blueprint's snippet because: env-filter tracing init, `emit()` helper for the three output formats, explicit `Finding` struct with `serde::Serialize` derive.

---

## Phase 4 — CI workflow

**Status:** ⬜ pending

**Goal:** PR push to a branch with engine changes triggers green CI.

### Checklist

- [ ] **P4-1** Create `.github/workflows/engine.yml`
- [ ] **P4-2** Create `engine/rust-toolchain.toml`

### Diary

(none yet)

---

## Phase 5 — TS sidecar integration (Path A)

**Status:** ⬜ pending

### Checklist

- [ ] **P5A-1** Create `vscode-extension/src/scanner/rustEngine.ts`
- [ ] **P5A-2** Add `Finding.fromRustEngine` to `vscode-extension/src/models/finding.ts`
- [ ] **P5A-3** Bundle binaries in `.vsix` via `vscode-extension/scripts/bundle-engine.sh`
- [ ] **P5A-3** Add `bin/engine-cli-*` entries to `vscode-extension/package.json` `files` array
- [ ] **P5A-4** Add `resolveEngineBinary` helper to `vscode-extension/src/extension.ts`
- [ ] **P5A-5** Create `vscode-extension/src/rules/security/rustEngineTaintRule.ts`
- [ ] **P5A-5** Register the new rule in `vscode-extension/src/rules/index.ts`
- [ ] **P5A-6** Create `vscode-extension/rules/dart-sql-injection.yaml`
- [ ] **P5A-6** Create `vscode-extension/rules/dart-command-injection.yaml`
- [ ] **P5A-6** Create `vscode-extension/rules/dart-xss.yaml`

### Diary

(none yet)

---

## Phase 6 — Deprecate TS IFDS

**Status:** ⬜ pending

### Checklist

- [ ] **P6-1** Add `@deprecated` JSDoc header to `vscode-extension/src/taint/ifdsEngine.ts`
- [ ] **P6-2** Conditionally register `IfdsTaintRule` only when Rust binary missing
- [ ] **P6-3** Verify `dataFlow.ts` is untouched

### Diary

(none yet)

---

## Phase 7 — Dart sidecar integration

**Status:** ⬜ pending

### Checklist

- [ ] **P7-1** Add `_runRustEngine` to `lib/src/scanner.dart`
- [ ] **P7-1** Add `_resolveEngineBinary` helper
- [ ] **P7-2** Migrate XSS detection to `vscode-extension/rules/dart-xss.yaml`
- [ ] **P7-2** Delete `lib/src/taint/taint_engine.dart`
- [ ] **P7-2** Update or delete `lib/src/rules/security/xss_rule.dart`

### Diary

(none yet)

---

## Phase 8 — Z3 SMT correlator (deferrable)

**Status:** ⬜ pending — explicitly deferred until P5+P6 prove value.

### Checklist

- [ ] **P8-1** Build `DartClientModel` populator from CPG
- [ ] **P8-1** Build `EdgeFunctionModel` populator from CPG (TS subset)
- [ ] **P8-1** Translate Dart-side DDL parser to Rust + extend with USING/WITH CHECK AST
- [ ] **P8-1** Implement `correlate()` Z3 invocation
- [ ] **P8-2** Add `--enable-smt` flag to engine-cli

### Diary

(none yet)

---

## Phase 9 — Remove TS IFDS

**Status:** ⬜ pending — gated on 2 weeks of green CI from P5/P6.

### Checklist

- [ ] Delete `vscode-extension/src/taint/ifdsEngine.ts`
- [ ] Delete `vscode-extension/src/taint/ifdsBuilder.ts`
- [ ] Delete `vscode-extension/src/taint/ifdsSolver.ts`
- [ ] Delete `vscode-extension/src/rules/security/ifdsTaintRule.ts`
- [ ] Remove "ifds-taint" registration from `rules/index.ts:54`
- [ ] Replace `scripts/ifds-self-test.js` with engine-cli equivalent

### Diary

(none yet)

---

## Phase 10 — Acceptance gates

**Status:** ⬜ pending

### Gates (from blueprint)

- [ ] **G1** `cargo build --workspace --release --features "engine-core/full"` succeeds in CI
- [ ] **G2** `cargo test --workspace` passes; ≥ 5 e2e tests
- [ ] **G3** P3-4 smoke test produces expected finding
- [ ] **G4** Zero new FPs on `test/fixtures/adversarial_app/` vs TS engine
- [ ] **G5** ≥ TS engine TP count on `test/fixtures/`
- [ ] **G6** `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] **G7** Linux x64 binary < 30 MB
- [ ] **G8** Three platforms (`darwin-arm64`, `darwin-x64`, `linux-x64`) bundled in .vsix
- [ ] **G9** Real Flutter+Supabase app scans cleanly in < 10 s

---

## Cross-cutting risks tracker

(track risks as they materialise)

| Risk | Phase encountered | Status | Resolution |
|------|-------------------|--------|------------|
| Rust 1.75 too old (indexmap 2.14 needs edition2024) | P1-5 | ✅ resolved | Bumped pin to 1.85.0 (Feb 2025 stable). Updated `engine/Cargo.toml`, all 4 crate Cargo.tomls, bootstrap script, and engine_resolver.dart. |
| `smallvec` const-generic Array trait | P1-5 | ✅ resolved | Enabled `const_generics` + `const_new` features on smallvec; added `where [EdgeId; N]: smallvec::Array<Item = EdgeId>` bound on `filter_adj_bucket`. |
| Missing `hashbrown` dep on engine-core | P1-5 | ✅ resolved | Added to engine-core Cargo.toml (was in workspace root only). |
| `tracing!(%expr.field)` syntax | P1-5 | ✅ resolved | sed-rewrote 12 occurrences from `%sym.0` → `sym_id = sym.0` in reactive_builder.rs. |
| Service-role test fails without smt-proofs | P1-5 | ✅ resolved | Stub now preserves syntactic service_role short-circuit (matches Z3 implementation's fast path). |
| `tree-sitter-dart 0.0.4` may misparse Dart 3 syntax | P3-4 | 🟡 partial | Engine parses fine (35 nodes built), but pattern matcher doesn't fire — **could be tree-sitter grammar OR pattern compiler bug**. Needs investigation. |
| Semgrep compiler vs reality (the big one) | P3-4 | ⛔ active | Smoke test produces 0 findings. **The Semgrep YAML pattern compiler at `semgrep_compiler.rs:526` does not currently match any node on the fixture.** Has to be investigated before Phase 5. Possible causes: (a) source pattern `request.body.$FIELD` doesn't compile to a predicate that matches the Dart `MethodCall` node, (b) the Dart frontend doesn't attach `symbol` to identifier nodes (the pattern compiler relies on `SymbolEndsWith`), (c) AST-child slot indexing differs between compiler expectation and frontend output. |
| `tree-sitter-rust 0.21` API may differ | P2-3 | ✅ resolved | Compiles fine. |
| RocksDB binary bloat | P5A-3 | ⬜ unknown | Measure `engine-cli` size; ship without `persist` if > 30 MB |
| `dart_analyzer` helper script doesn't exist | (P1-2 gated off) | ⏭️ skipped | Build without `analyzer-bridge` for v1 |
| Reactive Dependency Graph "3.4×" claim unverified | P5+ | ⬜ unknown | RDG built 0 anchors on smoke test (expected — no reactive code in the fixture). Benchmark on real Riverpod app needed. |
| Cross-compilation darwin-from-linux | P5A-3 | ⬜ unknown | Use macos-latest CI runners for darwin |

---

## User-facing install/prompt infrastructure (added on top of blueprint)

After Phase 3 (engine compiles + runs), four pieces of user-facing infrastructure ensure end users / contributors actually get the engine working:

| Piece | Location | What it does |
|-------|----------|--------------|
| **Bootstrap script** | [scripts/bootstrap.sh](scripts/bootstrap.sh) | One-shot setup; detects missing Rust/Node/Dart/system-libs and either installs (with `--yes` or interactive confirmation) or prints the exact install command. Has `--check` mode for CI. |
| **Dart engine resolver** | [lib/src/engine/engine_resolver.dart](lib/src/engine/engine_resolver.dart) | Searches 5 candidate locations for `engine-cli`. When missing, returns a structured `EngineResolution.missing(installHint)` with a multi-line install hint covering 3 install options. Callers can show this to the user. |
| **TS engine resolver** | [vscode-extension/src/scanner/engineResolver.ts](vscode-extension/src/scanner/engineResolver.ts) | Mirror of the Dart resolver for the VS Code extension. Same search order, same install hint shape. |
| **CONTRIBUTING.md + README** | [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md) | "Building from source" sections that point at the bootstrap script first, manual steps second. Make it impossible to miss the Rust dependency. |

**Why this matters:** without these, the engine is invisible. Users invoke the scanner, see no IFDS findings, and assume the tool is broken. With the resolver + install hints, the missing engine becomes a visible, actionable error message.

## Open questions for the user

(track decisions that need owner sign-off)

1. ~~OK to install Rust toolchain via official `rustup` script?~~ ✅ Approved + installed. Bumped from blueprint's 1.75 → 1.85 because indexmap 2.14 requires `edition2024` (stabilized in 1.85). All Cargo.tomls + bootstrap script + engine_resolver.dart updated.
2. **OK to install macOS system deps via brew (`cmake llvm rocksdb z3`)?** Needed only for `--features "engine-core/full"` builds. Phase 1 default build doesn't need them.
3. **Which CI provider?** Blueprint assumes GitHub Actions. Confirm before P4.
4. **Commit cadence?** Default assumption: single commit per phase, await user approval before pushing. Currently ~17 files modified across all phases — would form one large commit or several smaller phase-shaped commits.
5. **Smoke-test rule miss is a real gap.** The Semgrep YAML compiler does not currently match the `request.body.$FIELD` → `$DB.rawQuery($ARG)` source/sink pair on the smoke fixture. Three suspects (frontend doesn't attach symbols / pattern compiler bug / AST slot indexing differs). Investigation order TBD — owner should weigh in on whether to debug now (delays Phase 5) or move to Phase 5 first and use the gap as the first real-world Semgrep rule debug case.
