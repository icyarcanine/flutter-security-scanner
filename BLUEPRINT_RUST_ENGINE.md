# Rust Engine Resurrection Blueprint

> **REQUIRED READING.** This document is the single source of truth for the
> Rust analysis engine living under [`engine/`](engine/). Read this file
> end-to-end **before** writing, editing, deleting, planning, reviewing, or
> commenting on any file in `engine/`. If you are an LLM reading this for the
> first time, do not skip ahead. The "Pre-flight checklist" below is binding.

---

## Pre-flight checklist (do these in order, every session)

1. **Read this file in full.** Skim-read at minimum; full read if you intend to write code.
2. **Verify `engine/` source is not ignored** — `git check-ignore -v engine/Cargo.toml` should print nothing. `engine/target/` and `engine/Cargo.lock` should still be ignored as build artifacts. If `engine/` source is ignored again, fix `.gitignore` before any planning or implementation.
3. **Verify the toolchain.** `cargo --version` should report ≥ 1.85.0 and `rustup show active-toolchain` should match `engine/rust-toolchain.toml`. If `cargo` is missing, install before doing anything else (Phase 0 below).
4. **Run `cargo test --workspace` or `cargo build --workspace` early.** Do not attempt fixes without seeing the actual compile output. The error log tells you which Phase you're in.
5. **Cross-reference any claim about the engine** (rules, sinks, taint behaviour) against the actual source under `engine/crates/`. The TS extension and Dart `lib/` are separate; do not conflate them with the Rust engine.

---

## ⚠️ The "gitignored does not mean ignored" rule

This rule exists because a prior assessment (deepseek's audit, May 2026)
**completely missed the Rust engine** — ~6,624 LOC of designed code — because
the `engine/` directory was gitignored at the time. That assessment then drew
incorrect strategic conclusions ("the project is just TS + Dart") and proposed
wasted work.

### The rule

> A file or directory being absent from git tracking is **not** evidence that
> the code does not exist, is not intended to ship, or should be excluded
> from analysis. Always inspect the working tree, not just `git ls-files`.

### How to apply it

When auditing, planning, or reviewing this codebase:

| ❌ Wrong | ✅ Correct |
|---------|----------|
| `git ls-files \| wc -l` to estimate project size | `find . -name '*.rs' -o -name '*.ts' -o -name '*.dart' \| grep -v node_modules \| grep -v .dart_tool \| wc -l` |
| Skipping a directory because it's in `.gitignore` | Reading `.gitignore` to understand **why** something is gitignored, then evaluating the gitignored content on its own merits |
| "The Rust engine doesn't exist because it's not in git" | "Check `find engine -name '*.rs'` and `git check-ignore -v engine/Cargo.toml`; if source is ignored, fix `.gitignore` before assessing architecture" |
| Drafting strategy based on `git log` alone | Drafting strategy based on the working tree, with `git log` as one input among several |
| Treating an empty `git diff` as proof nothing changed | Running `git status` (uncommitted) AND `find -newer` (timestamp) AND inspecting untracked content |

### Specific to this repo

- `engine/` used to be gitignored with the comment "*In-progress Rust/WASM
  engine workspace. Will be un-ignored once it builds and has test coverage.*"
- That broad ignore has been removed. **Current expected state:** `.gitignore`
  ignores only `engine/target/` and `engine/Cargo.lock`.
- Phase 0 below explains the un-ignore decision. If a future change
  reintroduces `engine/`, `engine/**`, or `engine/Cargo.toml` as ignored
  source, treat that as a regression and remove it before continuing.
- Even after the source is tracked, the general rule remains: if a future
  directory is gitignored, inspect it before deciding it is out of scope.

### If you're unsure whether to look at gitignored content

Default: **look at it.** Then decide. The cost of looking is one `find`
command; the cost of skipping is the kind of audit failure that motivated
this rule.

---

## Initial verified facts about the engine (baseline snapshot 2026-05-08)

These facts were captured before the first resurrection implementation pass.
They explain why the phases below exist and what not to re-break. Current
status is tracked in [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md); the
current engine builds without warnings in default and full-feature build paths,
and direct SQL/command smoke rules fire through `engine-cli`. If this table
contradicts the working tree or the progress tracker, **trust the working
tree**, update the tracker, then update this baseline note.

| Component | Path | LOC | Compiles today? | Why or why not |
|-----------|------|-----|-----------------|----------------|
| CPG graph | `engine/crates/engine-core/src/cpg/graph.rs` | 1,052 | Probably yes | Has 3 unit tests, clean imports |
| CPG persistence (RocksDB) | `engine/crates/engine-core/src/cpg/persistence.rs` | 528 | **No** | `lib.rs:41` uses `feature = "persist"` but `Cargo.toml:32` declares the feature as `"persistence"`. Name mismatch. |
| CPG reactive builder | `engine/crates/engine-core/src/cpg/reactive_builder.rs` | 663 | Likely yes | — |
| IFDS solver | `engine/crates/engine-core/src/solver/ifds.rs` | 743 | **Yes** — has tests at line 713+ | Paper-grade Reps-Horwitz-Sagiv tabulation |
| Z3 SMT correlator | `engine/crates/engine-core/src/supabase/smt.rs` | 822 | **No** | Lines 407-408 unconditionally `use z3::...` but Z3 is `optional = true`. Needs `#[cfg(feature = "smt-proofs")]`. |
| Semgrep YAML compiler | `engine/crates/engine-core/src/rules/semgrep_compiler.rs` | 947 | Likely yes | Has unit tests |
| Type arena | `engine/crates/engine-core/src/frontend/types.rs` | 360 | Likely yes | — |
| Dart analyzer sidecar | `engine/crates/engine-core/src/frontend/dart_analyzer.rs` | 477 | Native only | Uses `std::process::*` — fails on `wasm32`. Needs cfg gate. |
| Dart frontend (5 files) | `engine/crates/engine-frontend-dart/src/*.rs` | 487 | **No — multiple bugs** | See below |
| Rust frontend | `engine/crates/engine-frontend-rust/src/*.rs` | 262 | **No** | Same node-kind mismatch + Cargo.toml lists `tree-sitter-rust = "0.0.1"` (broken/abandoned; real is `0.21`). |
| CLI binary | `engine/crates/engine-cli/src/main.rs` | 116 | **No — visibly broken** | Lines 38-67 contain a nested `#[derive(Parser)]` with `...` placeholder. References to `source_map`, `type_arena` before declaration. Calls non-existent `IfdsSolver::new(Arc::new(...))` (1 arg, but actual is 2). Calls `solver.run(&graph)` but actual is `solver.run()`. Calls `solver.all_findings(&graph)` — **method does not exist**. |
| Workspace `Cargo.toml` | `engine/Cargo.toml` | 96 | n/a | `[workspace] members = ["crates/engine-core"]` — three other crates orphaned. |

### Specific Dart-frontend bugs (P2-5 fixes them)

The Dart frontend uses these `NodeKind` variants that **do not exist** in
[graph.rs:178](engine/crates/engine-core/src/cpg/graph.rs#L178):

| Frontend writes | Actual variant | Fix |
|-----------------|----------------|-----|
| `NodeKind::Block` | (none) | Use `NodeKind::ExprStmt` |
| `NodeKind::IfStmt` | `NodeKind::If` | Rename |
| `NodeKind::ForStmt` | `NodeKind::Loop` | Rename |
| `NodeKind::WhileStmt` | `NodeKind::Loop` | Rename |
| `NodeKind::TryStmt` | `NodeKind::Try` | Rename |
| `NodeKind::ReturnStmt` | `NodeKind::Return` | Rename |
| `NodeKind::Param` | `NodeKind::Parameter` | Rename |
| `NodeKind::Unknown` | (none) | Add the variant (P2-6) |

Also: [pdg_builder.rs:127, 146](engine/crates/engine-frontend-dart/src/pdg_builder.rs#L127)
writes `crate::engine_core::cpg::AstEdge` — should be `engine_core::cpg::AstEdge`
(`engine_core` is a separate crate, not a submodule of this crate).

### Toolchain status (must verify per session)

- `cargo`, `rustup`, `~/.cargo`, `~/.rustup` were all **absent** at the time
  this blueprint was written. They have since been installed locally at Rust
  1.85.0; still verify per session with `cargo --version`.
- No CI workflow exists for the engine. Phase 4 adds it.

---

## What's outside this blueprint's scope

These exist in the same repo but are **not** the subject of this blueprint:

- **TS VS Code extension** at [`vscode-extension/`](vscode-extension/) — 42 rules, intra-procedural taint engine in [`dataFlow.ts`](vscode-extension/src/taint/dataFlow.ts), IFDS engine in [`ifdsEngine.ts`](vscode-extension/src/taint/ifdsEngine.ts) (Dart-only).
- **Dart `lib/` scanner** at [`lib/`](lib/) — 38 rules, primitive AST taint tracker in [`taint_engine.dart`](lib/src/taint/taint_engine.dart).
- **Test fixtures** at [`test/fixtures/`](test/fixtures/).

These are the existing canonical scanner. The Rust engine is intended to
**replace** the TS-side IFDS engine and the Dart-side taint tracker — see
Phases 6, 7, 9 below — without touching the regex-based rules in either.

---

## Strategic decision (locked, do not relitigate)

**The Rust engine is the future canonical analysis kernel.** It will:

1. Replace the TS-side IFDS engine (Phase 6, 9).
2. Replace the Dart-side taint tracker (Phase 7).
3. Be invoked as a native subprocess (`engine-cli`) by both the VS Code
   extension and the Dart `lib/` scanner.
4. Ship as a prebuilt binary bundled in the `.vsix` and the Dart pub package
   (Phase 5A, P5A-3).
5. Be fed Semgrep YAML rules (Phase 5A, P5A-6) so new rules don't require a
   Rust recompile.

**Path B (WebAssembly) is deferred to v2.** Z3 and RocksDB don't compile to
WASM with current tooling. Don't chase it for v1.

The owner has explicitly chosen Option A (resurrect) over Option B (delete).
Do not propose deletion.

---

# Phase 0 — Standing up the toolchain (Day 1)

## P0-1. Install Rust + system dependencies

**Where:** Local dev machine and CI runner.

```bash
# Local — pinned to the engine's declared MSRV
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
source $HOME/.cargo/env
rustup component add clippy rustfmt
rustup target add wasm32-unknown-unknown   # for the Phase 8/B WASM work later

# macOS system deps
brew install cmake llvm rocksdb z3

# Linux CI
sudo apt-get install -y build-essential cmake clang libclang-dev librocksdb-dev libz3-dev
```

**Why pinned `1.85.0`:** [engine/Cargo.toml:18](engine/Cargo.toml#L18)
declares `rust-version = "1.85"`. The original blueprint target was 1.75,
but transitive dependencies now require Cargo's `edition2024` manifest
support, which stabilised in Rust 1.85. Don't drift; pin in
`engine/rust-toolchain.toml` (P4-2 below).

**Acceptance:** `cargo --version` reports ≥ 1.85.0. `pkg-config --exists rocksdb && pkg-config --exists z3` exits 0 (proves system libs are linkable).

## P0-2. Keep engine source unignored

**File:** [.gitignore](.gitignore)

**Historical action:** delete any broad engine ignore such as:
```
# In-progress Rust/WASM engine workspace. Will be un-ignored once it
# builds and has test coverage.
engine/
```

**Current expected state:** keep only narrow build-artifact ignores:
```
engine/target/
engine/Cargo.lock
```

Then, when committing a phase:
```bash
git add engine/ .gitignore
git commit -m "track engine workspace (begin Rust engine resurrection)"
```

**Acceptance:** `git check-ignore -v engine/Cargo.toml` prints nothing.
`git check-ignore -v engine/target engine/Cargo.lock` prints the narrow
rules above. After the commit lands, `git ls-files engine/ | wc -l` returns
≥ 19 (one per `.rs` file plus `Cargo.toml`s).

> **Reminder:** if any future tool or contributor reintroduces a broad
> `engine/` ignore, treat it as a regression. Fix it before any engine
> implementation, review, or assessment.

---

# Phase 1 — Make `engine-core` compile in isolation (Day 2-3)

## P1-1. Fix the persistence feature name

**File:** [engine/crates/engine-core/Cargo.toml](engine/crates/engine-core/Cargo.toml)

**Replace lines 29-37 with:**
```toml
[features]
default = []
# Persistence requires C++ Build Tools / LLVM (RocksDB)
persist = ["dep:rocksdb"]
# SMT Proofs require Z3 installation
smt-proofs = ["dep:z3"]
# Native dart-analyzer sidecar (uses std::process; not WASM-compatible)
analyzer-bridge = []
# Full suite for CI/CD
full = ["persist", "smt-proofs", "analyzer-bridge"]
```

The feature rename from `"persistence"` to `"persist"` matches what
[engine-core/src/lib.rs:41](engine/crates/engine-core/src/lib.rs#L41)
actually uses. The `dep:` syntax avoids implicitly creating a feature named
the same as the optional dep (Rust 2021 edition lint).

## P1-2. Gate the dart_analyzer module

**File:** [engine/crates/engine-core/src/lib.rs:52-56](engine/crates/engine-core/src/lib.rs#L52)

**Replace:**
```rust
pub mod frontend {
    //! Language frontends that populate the CPG.
    pub mod dart_analyzer;
    pub mod types;
}
```

**With:**
```rust
pub mod frontend {
    //! Language frontends that populate the CPG.
    #[cfg(feature = "analyzer-bridge")]
    pub mod dart_analyzer;
    pub mod types;
}
```

**Reason:** [dart_analyzer.rs:39-41](engine/crates/engine-core/src/frontend/dart_analyzer.rs#L39)
imports `std::process::{Child, Command, Stdio}` which doesn't exist on
`wasm32-unknown-unknown`. Gating on a feature lets non-WASM builds opt in
explicitly.

## P1-3. Gate the SMT module behind its existing feature

**File:** [engine/crates/engine-core/src/supabase/smt.rs](engine/crates/engine-core/src/supabase/smt.rs)

**Action:** Wrap the entire file body (everything after the doc comment
header at line ~65) in a feature-gated `mod imp` and provide a
`#[cfg(not(feature = "smt-proofs"))]` stub with the same public types so the
rest of the crate still compiles when the feature is off:

```rust
#[cfg(feature = "smt-proofs")]
mod imp {
    use super::*;
    // [...all existing code from line ~66 onwards...]
}
#[cfg(feature = "smt-proofs")]
pub use imp::*;

#[cfg(not(feature = "smt-proofs"))]
mod stub {
    //! Stub for builds without Z3. Returns `Verdict::Unknown` for every query.
    use crate::cpg::NodeId;
    use std::time::Duration;

    #[derive(Clone, Debug)]
    pub struct CorrelationQuery {
        pub call_site: NodeId,
        // [...preserve other public field names as no-op stubs so call sites
        //    still typecheck. List them by reading the smt-proofs branch.]
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Verdict { Safe, Unsafe, Unknown }

    pub fn correlate(_: &CorrelationQuery, _: Duration) -> Verdict {
        Verdict::Unknown
    }
}
#[cfg(not(feature = "smt-proofs"))]
pub use stub::*;
```

**The stub interface must keep the same public type names and shapes** the
rest of the crate references — this is the standard Rust pattern for
compile-time-optional heavy deps.

## P1-4. Standardise the `rustc-hash` rename

**Files:** all four `Cargo.toml`s under `engine/crates/*/Cargo.toml`

**Find/replace:** `rustc_hash = "2.0"` → `rustc-hash = "2.0"` (canonical
crates.io name uses a dash).

The `use rustc_hash::FxHashMap` import works either way because Cargo
auto-converts the dash to an underscore in the Rust namespace, but
standardising on the dashed form in TOML matches
[engine/Cargo.toml:42](engine/Cargo.toml#L42) (`rustc-hash = "2.0"`).

## P1-5. Compile

```bash
cd engine
cargo build -p engine-core
```

Expect 5-15 warnings (mostly `unused_variables` in stub branches and
`dead_code` in unfinished modules). Treat warnings as warnings for now;
P4-1 will tighten via `clippy --deny warnings`.

**Acceptance:**
- `cargo build -p engine-core` exits 0.
- `cargo build -p engine-core --features full` also exits 0 (proves Z3 +
  RocksDB link).
- `cargo test -p engine-core` runs the 7+ unit tests in `graph.rs` /
  `ifds.rs` / `semgrep_compiler.rs` and they pass.

**If P1-5 fails with errors not listed above:** they're in modules not
fully audited. The general fix template:
- Missing `use` import → add it.
- "Cannot find type X in this scope" → check if X was renamed; either restore
  the old name or update the call site.
- "Method X not found on type Y" → reconcile against the API surface table
  at the top of this document.

---

# Phase 2 — Wire the workspace and bring up the other three crates (Day 4-5)

## P2-1. Add the missing crates to the workspace

**File:** [engine/Cargo.toml:13](engine/Cargo.toml#L13)

**Replace:**
```toml
[workspace]
resolver = "2"
members  = [
    "crates/engine-core",
]
```

**With:**
```toml
[workspace]
resolver = "2"
members = [
    "crates/engine-core",
    "crates/engine-frontend-dart",
    "crates/engine-frontend-rust",
    "crates/engine-cli",
]
```

## P2-2. Fix engine-frontend-dart Cargo.toml

**File:** [engine/crates/engine-frontend-dart/Cargo.toml](engine/crates/engine-frontend-dart/Cargo.toml)

**Replace contents with:**
```toml
[package]
name = "engine-frontend-dart"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[dependencies]
engine-core      = { path = "../engine-core" }
tree-sitter      = { workspace = true }
tree-sitter-dart = { workspace = true }
rustc-hash       = { workspace = true }
tracing          = { workspace = true }
smallvec         = { workspace = true }

[lib]
name = "engine_frontend_dart"
path = "src/lib.rs"
```

The `workspace = true` form pulls versions from
[engine/Cargo.toml workspace.dependencies](engine/Cargo.toml#L37) so we
don't have version drift.

## P2-3. Fix engine-frontend-rust dependency

**File:** [engine/crates/engine-frontend-rust/Cargo.toml](engine/crates/engine-frontend-rust/Cargo.toml)

`tree-sitter-rust = "0.0.1"` is broken/abandoned. Replace with `0.21`.

Apply the same `workspace = true` cleanup as P2-2. Also add
`tree-sitter-rust = "0.21"` to
[engine/Cargo.toml workspace.dependencies](engine/Cargo.toml#L40) right
under `tree-sitter-dart`.

## P2-4. Replace `extern "C"` tree-sitter linkage with Rust bindings

**Why:** The current `extern "C" { fn tree_sitter_dart() -> Language; }`
([lib.rs:12-14](engine/crates/engine-frontend-dart/src/lib.rs#L12)) requires
either a `build.rs` that compiles the grammar's C source, or a prebuilt
symbol in the linked `.a`. The `tree-sitter-dart` 0.0.4 crate already exposes
a Rust binding `tree_sitter_dart::language()` that wraps the C call.

**File:** [engine/crates/engine-frontend-dart/src/lib.rs](engine/crates/engine-frontend-dart/src/lib.rs)

**Replace lines 12-14 + 19:**
```rust
extern "C" {
    fn tree_sitter_dart() -> Language;
}
// ...
let language = unsafe { tree_sitter_dart() };
```

**With:**
```rust
let language: Language = tree_sitter_dart::language();
```

Drop the `extern "C"` block. Drop the `unsafe`.

**Apply the same change** to
[engine/crates/engine-frontend-rust/src/lib.rs:9-11, 16](engine/crates/engine-frontend-rust/src/lib.rs#L9):
```rust
let language: Language = tree_sitter_rust::language();
```

## P2-5. Fix the NodeKind mismatches in the Dart frontend

**Files:** [ast_builder.rs](engine/crates/engine-frontend-dart/src/ast_builder.rs),
[cfg_builder.rs](engine/crates/engine-frontend-dart/src/cfg_builder.rs),
[pdg_builder.rs](engine/crates/engine-frontend-dart/src/pdg_builder.rs),
[icfg_builder.rs](engine/crates/engine-frontend-dart/src/icfg_builder.rs)

The actual `NodeKind` enum lives in
[graph.rs:178](engine/crates/engine-core/src/cpg/graph.rs#L178). See the
mapping table near the top of this document.

**Concrete rewrite of [ast_builder.rs:68-105](engine/crates/engine-frontend-dart/src/ast_builder.rs#L68):**
```rust
fn map_kind(&self, ts_kind: &str) -> NodeKind {
    match ts_kind {
        "program" => NodeKind::Module,
        "class_definition" => NodeKind::ClassDecl,
        "mixin_definition" => NodeKind::MixinDecl,
        "extension_definition" => NodeKind::ExtensionDecl,

        "method_declaration" => NodeKind::MethodDecl,
        "function_declaration" => NodeKind::FunctionDecl,
        "constructor_declaration" | "factory_constructor_signature" => NodeKind::ConstructorDecl,

        "expression_statement" => NodeKind::ExprStmt,
        "if_statement" => NodeKind::If,
        "for_statement" | "while_statement" | "do_statement" => NodeKind::Loop,
        "try_statement" => NodeKind::Try,
        "return_statement" => NodeKind::Return,

        "assignment_expression" | "pattern_assignment" => NodeKind::Assign,
        "method_invocation" => NodeKind::MethodCall,
        "function_expression_invocation" => NodeKind::Call,
        "instance_creation_expression" => NodeKind::ConstructorCall,

        "identifier" => NodeKind::Identifier,
        "string_literal" | "raw_string_literal" => NodeKind::Literal,
        "integer_literal" | "hex_integer_literal" => NodeKind::Literal,
        "boolean_literal" | "null_literal" => NodeKind::Literal,
        "string_interpolation" => NodeKind::StringInterp,

        "formal_parameter" => NodeKind::Parameter,

        _ => {
            debug!(?ts_kind, "unmapped tree-sitter kind, defaulting to Unknown");
            NodeKind::Unknown
        }
    }
}
```

## P2-6. Add `Unknown` to `NodeKind`

**File:** [engine/crates/engine-core/src/cpg/graph.rs:178](engine/crates/engine-core/src/cpg/graph.rs#L178)

At the end of the `NodeKind` enum (just before line ~309), add:
```rust
    // -- Catch-all -----------------------------------------------------
    /// Unmapped CST type. Used by frontends as a fallback for grammar
    /// productions that have no canonical IR equivalent yet. Carries no
    /// semantic guarantees; analyses should treat it as opaque.
    Unknown,
```

## P2-7. Fix the PDG builder's broken crate path

**File:** [engine/crates/engine-frontend-dart/src/pdg_builder.rs:127](engine/crates/engine-frontend-dart/src/pdg_builder.rs#L127)
and the same pattern at line 146.

**Replace:**
```rust
if matches!(edge.kind, EdgeKind::Ast(crate::engine_core::cpg::AstEdge::Child { slot: 0 })) {
```

**With:**
```rust
if matches!(edge.kind, EdgeKind::Ast(engine_core::cpg::AstEdge::Child { slot: 0 })) {
```

The `crate::` prefix means "this crate" but `engine_core` is a separate
crate. Drop `crate::`.

## P2-8. Apply the same NodeKind cleanup to the Rust frontend

**File:** [engine/crates/engine-frontend-rust/src/ast_builder.rs:59-91](engine/crates/engine-frontend-rust/src/ast_builder.rs#L59)

Apply the find/replace mapping from P2-5. Special case: `unsafe_block` and
ordinary `block` should map to `ExprStmt` in the absence of a `Block` kind.

## P2-9. Compile the workspace

```bash
cd engine
cargo build --workspace
```

**Acceptance:** All four crates build. Warnings are OK; errors are not.

---

# Phase 3 — Make the CLI a real binary (Day 6)

## P3-1. Replace the broken main.rs entirely

**File:** [engine/crates/engine-cli/src/main.rs](engine/crates/engine-cli/src/main.rs)

The existing 116 lines have a nested `#[derive]` bug, undefined variables,
and call non-existent solver methods. **Replace the entire file** with:

```rust
//! engine-cli: command-line driver for the SAST engine.
//!
//! Walks a project, parses every supported source file, builds the CPG,
//! optionally builds the RDG, loads a Semgrep rule, runs the IFDS solver,
//! and emits findings as JSON or SARIF.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use rustc_hash::FxHashMap;
use tracing::{info, warn};
use walkdir::WalkDir;

use engine_core::cpg::{CodeGraph, FileId, NodeId};
use engine_core::frontend::types::TypeArena;
use engine_core::cpg::reactive_builder::build_rdg;
use engine_core::rules::semgrep_compiler::{load_rule, SemgrepFlowFunctions};
use engine_core::solver::ifds::IfdsSolver;
use engine_frontend_dart::parse_dart;
use engine_frontend_rust::parse_rust;

#[derive(Parser, Debug)]
#[command(author, version, about = "Flutter security scanner — Rust analysis kernel")]
struct Args {
    /// Path to the project to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Path to a Semgrep YAML rule file.
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Output format: console | json | sarif.
    #[arg(short, long, default_value = "console")]
    format: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!(path = %args.path.display(), "starting scan");

    let mut graph = CodeGraph::new();
    let mut source_map: FxHashMap<FileId, String> = FxHashMap::default();
    let type_arena = TypeArena::new();

    // 1. Ingest files and build the CPG.
    for entry in WalkDir::new(&args.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let ext = e.path().extension().and_then(|s| s.to_str());
            matches!(ext, Some("dart") | Some("rs"))
        })
    {
        let source = std::fs::read_to_string(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        let file_id = graph.intern_file(
            entry.path().to_str().context("non-UTF8 path")?,
        );
        source_map.insert(file_id, source.clone());

        let ext = entry.path().extension().and_then(|s| s.to_str());
        let res = match ext {
            Some("dart") => parse_dart(&mut graph, file_id, &source),
            Some("rs") => parse_rust(&mut graph, file_id, &source),
            _ => unreachable!(),
        };
        if let Err(e) = res {
            warn!(file = %entry.path().display(), error = %e, "parse failed");
        }
    }

    // 2. Build the Reactive Dependency Graph (Flutter).
    info!("building reactive dependency graph");
    build_rdg(&mut graph, &type_arena);

    info!(
        nodes = graph.node_count(),
        edges = graph.edge_count(),
        "CPG construction complete",
    );

    // 3. Load and run the rule.
    let Some(rule_path) = args.rules else {
        info!("no --rules provided; engine ran but no analysis performed");
        return Ok(());
    };

    info!(rule = %rule_path.display(), "loading rule");
    let rule_yaml = std::fs::read_to_string(&rule_path)
        .with_context(|| format!("read rule {}", rule_path.display()))?;

    let source_refs: FxHashMap<FileId, &str> = source_map
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();

    let flow_funcs = load_rule(&rule_yaml, &graph, &type_arena, &source_refs)
        .map_err(|e| anyhow::anyhow!("rule compile: {e}"))?;

    info!("running IFDS solver");
    let mut solver = IfdsSolver::new(&graph, flow_funcs);

    // Seed solver at every source the rule discovered. This requires the
    // public accessors added by P3-2 below.
    let sources: Vec<NodeId> = solver.flow().sources().iter().map(|m| m.node).collect();
    for src in sources {
        solver.seed_at_source(src);
    }
    solver.run();

    // 4. Collect findings: walk every sink the rule discovered, ask the
    //    solver if it's tainted.
    let rule_id = solver.flow().rule().id.clone();
    let rule_msg = solver.flow().rule().message.clone();
    let rule_sev = solver.flow().rule().severity.clone();
    let sinks: Vec<NodeId> = solver.flow().sinks().iter().map(|m| m.node).collect();

    let mut findings: Vec<Finding> = Vec::new();
    for sink_node in sinks {
        if !solver.is_tainted(sink_node) {
            continue;
        }
        let node = graph.node(sink_node);
        let file_path = graph.file_path(node.file).to_owned();
        let (line, col) = byte_to_line_col(
            source_map.get(&node.file).map(String::as_str).unwrap_or(""),
            node.byte_range.start as usize,
        );
        findings.push(Finding {
            file: file_path,
            line,
            col,
            rule_id: rule_id.clone(),
            severity: rule_sev.clone(),
            message: rule_msg.clone(),
        });
    }

    // 5. Emit.
    match args.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&findings)?),
        "sarif" => println!("{}", to_sarif(&findings)?),
        _ => {
            if findings.is_empty() {
                println!("no findings");
            } else {
                for f in &findings {
                    println!(
                        "{}:{}:{}: [{}] {} ({})",
                        f.file, f.line, f.col, f.severity, f.message, f.rule_id,
                    );
                }
            }
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct Finding {
    file: String,
    line: u32,
    col: u32,
    rule_id: String,
    severity: String,
    message: String,
}

fn byte_to_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset { break; }
        if ch == '\n' { line += 1; col = 1; } else { col += 1; }
    }
    (line, col)
}

fn to_sarif(findings: &[Finding]) -> Result<String> {
    // Minimal SARIF 2.1.0. The TS extension's [output/sarif.ts] is more
    // elaborate; for the engine sidecar we just need findings to round-trip
    // through the merge step in scanner/mergeReports.ts.
    let runs = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": { "name": "engine-cli", "version": env!("CARGO_PKG_VERSION") } },
            "results": findings.iter().map(|f| serde_json::json!({
                "ruleId": f.rule_id,
                "level": severity_to_sarif_level(&f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": &f.file },
                        "region": { "startLine": f.line, "startColumn": f.col }
                    }
                }]
            })).collect::<Vec<_>>()
        }]
    });
    Ok(serde_json::to_string_pretty(&runs)?)
}

fn severity_to_sarif_level(s: &str) -> &'static str {
    match s.to_uppercase().as_str() {
        "ERROR" | "CRITICAL" | "HIGH" => "error",
        "WARNING" | "MEDIUM" => "warning",
        _ => "note",
    }
}
```

## P3-2. Add the missing public accessors

**File:** [engine/crates/engine-core/src/solver/ifds.rs:295](engine/crates/engine-core/src/solver/ifds.rs#L295)

Inside `impl<'g, FF: FlowFunctions> IfdsSolver<'g, FF>`, add:
```rust
/// Borrow the flow-function bundle. Used by drivers that need to enumerate
/// the bundle's discovered sources/sinks for finding extraction.
#[must_use]
pub fn flow(&self) -> &FF {
    &self.flow
}
```

**File:** [engine/crates/engine-core/src/rules/semgrep_compiler.rs:682](engine/crates/engine-core/src/rules/semgrep_compiler.rs#L682)
(the `SemgrepFlowFunctions` impl block)

Add:
```rust
/// Sources discovered when this rule was loaded.
#[must_use]
pub fn sources(&self) -> &[Match] { &self.sources }

/// Sinks discovered when this rule was loaded.
#[must_use]
pub fn sinks(&self) -> &[Match] { &self.sinks }

/// Sanitizers discovered when this rule was loaded.
#[must_use]
pub fn sanitizers(&self) -> &[Match] { &self.sanitizers }
```

Verify the `sources`, `sinks`, `sanitizers` fields are stored on the struct.
If not, add them (they're populated in `load_rule` already).

## P3-3. Update engine-cli/Cargo.toml

**File:** [engine/crates/engine-cli/Cargo.toml](engine/crates/engine-cli/Cargo.toml)

**Replace contents with:**
```toml
[package]
name = "engine-cli"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[[bin]]
name = "engine-cli"
path = "src/main.rs"

[dependencies]
engine-core          = { path = "../engine-core" }
engine-frontend-dart = { path = "../engine-frontend-dart" }
engine-frontend-rust = { path = "../engine-frontend-rust" }
clap                 = { version = "4.4", features = ["derive"] }
tracing              = { workspace = true }
tracing-subscriber   = { version = "0.3", features = ["env-filter"] }
walkdir              = "2.4"
serde                = { workspace = true }
serde_json           = { workspace = true }
anyhow               = "1.0"
rustc-hash           = { workspace = true }
```

## P3-4. End-to-end smoke test

```bash
cd engine
cargo build --workspace --release
mkdir -p /tmp/sast-smoke
cat > /tmp/sast-smoke/vuln.dart <<'EOF'
void handler(request) {
  final id = request.body.id;
  database.rawQuery("SELECT * FROM users WHERE id = $id");
}
EOF
cat > /tmp/sast-smoke/sql.yaml <<'EOF'
id: dart.sql-injection
message: "Possible SQL injection: tainted value flows into rawQuery"
severity: ERROR
languages: [dart]
mode: taint
pattern-sources:
  - pattern: "request.body.$FIELD"
pattern-sinks:
  - pattern: "$DB.rawQuery($ARG)"
EOF
./target/release/engine-cli /tmp/sast-smoke --rules /tmp/sast-smoke/sql.yaml --format console
```

**Acceptance:** Output contains a single line of the form:
```
/tmp/sast-smoke/vuln.dart:3:3: [ERROR] Possible SQL injection: tainted value flows into rawQuery (dart.sql-injection)
```

If this works, you have a working end-to-end Rust SAST engine. **This is
the project's first real milestone.**

---

# Phase 4 — Wire CI (Day 7)

## P4-1. Add the Rust workflow

**File:** new file `.github/workflows/engine.yml`

```yaml
name: engine

on:
  push:
    paths: ['engine/**', '.github/workflows/engine.yml']
  pull_request:
    paths: ['engine/**', '.github/workflows/engine.yml']

jobs:
  build:
    runs-on: ubuntu-latest
    defaults:
      run: { working-directory: engine }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.85.0
        with: { components: clippy, rustfmt }
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: 'engine -> target' }
      - name: Install system deps
        run: sudo apt-get install -y librocksdb-dev libz3-dev clang
      - run: cargo fmt --all -- --check
      - run: cargo build --workspace --release
      - run: cargo build --workspace --release --features "engine-core/full"
      - run: cargo test --workspace
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Smoke test
        run: |
          mkdir /tmp/smoke && cd /tmp/smoke
          # [same fixture commands from P3-4]
          # then: ../target/release/engine-cli . --rules sql.yaml | grep "rawQuery"
```

## P4-2. Pin Rust toolchain

**File:** new file `engine/rust-toolchain.toml`

```toml
[toolchain]
channel = "1.85.0"
components = ["clippy", "rustfmt"]
profile = "default"
```

This makes any `cargo` invocation inside `engine/` use the pinned toolchain,
locally and in CI.

**Acceptance:** A push to a PR triggers the workflow and it goes green.

---

# Phase 5 — Wire the engine into the existing TS extension (Day 8-12)

Two paths exist; choose **A** unless you have specific reason to prefer B.

## Path A — Native sidecar (recommended for v1)

**Architecture:** The VS Code extension and the Dart `lib/` scanner shell
out to the prebuilt `engine-cli` binary, communicate via JSON, and merge
findings into the existing `Finding` model.

### P5A-1. Add a Rust-engine adapter to the TS extension

**File:** new file `vscode-extension/src/scanner/rustEngine.ts`

```typescript
import { spawn } from 'child_process';
import { Finding } from '../models/finding';

export interface RustEngineOptions {
  binaryPath: string;          // resolved at activation; ships in the .vsix
  projectRoot: string;
  ruleFiles: string[];          // paths to Semgrep YAML rules
  timeoutMs?: number;           // default 30_000
}

export interface RustEngineResult {
  findings: Finding[];
  durationMs: number;
  warnings: string[];
}

export async function runRustEngine(opts: RustEngineOptions): Promise<RustEngineResult> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const start = Date.now();

  for (const ruleFile of opts.ruleFiles) {
    const result = await runOne(opts.binaryPath, opts.projectRoot, ruleFile, opts.timeoutMs ?? 30_000);
    findings.push(...result.findings);
    warnings.push(...result.warnings);
  }
  return { findings, durationMs: Date.now() - start, warnings };
}

interface RunResult { findings: Finding[]; warnings: string[]; }

function runOne(bin: string, root: string, rule: string, timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(bin, [root, '--rules', rule, '--format', 'json'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(new Error(`engine-cli timeout after ${timeoutMs}ms on rule ${rule}`));
    }, timeoutMs);

    proc.stdout.on('data', d => stdout += d.toString());
    proc.stderr.on('data', d => stderr += d.toString());
    proc.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error(`engine-cli exited ${code}: ${stderr}`));
      }
      try {
        const raw = JSON.parse(stdout) as Array<{
          file: string; line: number; col: number;
          rule_id: string; severity: string; message: string;
        }>;
        const warnings = stderr.split('\n').filter(l => l.includes('WARN'));
        const findings: Finding[] = raw.map(r => Finding.fromRustEngine({
          filePath: r.file, line: r.line, column: r.col,
          ruleCode: r.rule_id, message: r.message,
          severity: mapSeverity(r.severity),
        }));
        resolve({ findings, warnings });
      } catch (e) {
        reject(new Error(`engine-cli output parse failed: ${(e as Error).message}\nstdout: ${stdout.slice(0, 500)}`));
      }
    });
  });
}

function mapSeverity(s: string): import('../models/finding').FindingSeverity {
  // Implementation: map ERROR/CRITICAL/HIGH → high, WARNING/MEDIUM → medium, else low.
  // Reuse the existing FindingSeverity enum.
  // [Concrete code depends on the FindingSeverity definition.]
  throw new Error('TODO: map severity using vscode-extension/src/models/finding.ts FindingSeverity');
}
```

### P5A-2. Add a `Finding.fromRustEngine` factory

**File:** [vscode-extension/src/models/finding.ts](vscode-extension/src/models/finding.ts)

Add a static method on the existing `Finding` class:
```typescript
static fromRustEngine(o: {
  filePath: string; line: number; column: number;
  ruleCode: string; message: string; severity: FindingSeverity;
}): Finding {
  return new Finding({
    category: FindingCategory.security,
    code: o.ruleCode,
    severity: o.severity,
    confidence: FindingConfidence.high,    // engine findings are high-confidence
    detectionMethod: DetectionMethod.taint,
    filePath: o.filePath,
    line: o.line,
    message: o.message,
    fix: '(see rule documentation)',
    astUsed: true,
    rustEngine: true,                       // new optional flag for telemetry
  });
}
```

### P5A-3. Bundle the binary in the .vsix

**File:** [vscode-extension/package.json:46](vscode-extension/package.json#L46)
(`files` array)

Add to the array:
- `"bin/engine-cli-darwin-arm64"`
- `"bin/engine-cli-darwin-x64"`
- `"bin/engine-cli-linux-x64"`
- `"bin/engine-cli-win-x64.exe"` (defer)

**File:** new script `vscode-extension/scripts/bundle-engine.sh`

```bash
#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
TARGETS=(
  "darwin-arm64:aarch64-apple-darwin"
  "darwin-x64:x86_64-apple-darwin"
  "linux-x64:x86_64-unknown-linux-gnu"
)
for entry in "${TARGETS[@]}"; do
  IFS=':' read -r name target <<< "$entry"
  echo "Building engine-cli for $target"
  (cd ../engine && cargo build --release --target "$target" -p engine-cli)
  cp "../engine/target/$target/release/engine-cli" "bin/engine-cli-$name"
done
```

For v1, ship only `darwin-arm64`, `darwin-x64`, `linux-x64`. Windows comes
later.

### P5A-4. Resolve the binary at extension activation

**File:** [vscode-extension/src/extension.ts](vscode-extension/src/extension.ts)

Add a helper:
```typescript
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

export function resolveEngineBinary(extensionPath: string): string | null {
  const platform = os.platform(); // 'darwin' | 'linux' | 'win32'
  const arch = os.arch();          // 'arm64' | 'x64'
  const key = platform === 'win32' ? 'win-x64.exe' :
              platform === 'darwin' ? `darwin-${arch}` :
              `linux-${arch}`;
  const p = path.join(extensionPath, 'bin', `engine-cli-${key}`);
  return fs.existsSync(p) ? p : null;
}
```

In the activation function, store the binary path in
`ExtensionContext.workspaceState` so the scanner can find it.

### P5A-5. Add a new rule that runs the Rust engine

**File:** new file `vscode-extension/src/rules/security/rustEngineTaintRule.ts`

```typescript
import { Rule, RuleStage } from '../rule';
import { Finding } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { runRustEngine } from '../../scanner/rustEngine';
import { resolveEngineBinary } from '../../extension';
import * as path from 'path';

const BUILTIN_RULES = [
  'rules/dart-sql-injection.yaml',
  'rules/dart-command-injection.yaml',
  'rules/dart-xss.yaml',
];

export class RustEngineTaintRule implements Rule {
  readonly code = 'rust-engine-taint';
  readonly stage = RuleStage.taint;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    const bin = resolveEngineBinary(context.extensionPath);
    if (!bin) {
      // No prebuilt binary for this platform — TS IFDS fallback runs instead
      return [];
    }
    const ruleFiles = BUILTIN_RULES.map(r =>
      path.join(context.extensionPath, r)
    );
    const result = await runRustEngine({
      binaryPath: bin,
      projectRoot: context.rootPath,
      ruleFiles,
      timeoutMs: 30_000,
    });
    return result.findings;
  }
}
```

Register in [vscode-extension/src/rules/index.ts](vscode-extension/src/rules/index.ts).
**Do not delete the existing `IfdsTaintRule` yet** — Phase 6 handles that.

### P5A-6. Ship Semgrep rule files alongside the extension

**Directory:** new directory `vscode-extension/rules/`

Migrate the IFDS sink list from
[vscode-extension/src/taint/ifdsBuilder.ts:43-50](vscode-extension/src/taint/ifdsBuilder.ts#L43)
into proper Semgrep YAML rules. Example for SQL injection:

**File:** new file `vscode-extension/rules/dart-sql-injection.yaml`

```yaml
id: dart.security.sql-injection
message: "User-controlled value flows into a SQL sink — potential SQL injection. Use parameterized queries."
severity: ERROR
languages: [dart]
mode: taint

pattern-sources:
  - pattern: "request.body.$FIELD"
  - pattern: "request.query.$FIELD"
  - pattern: "request.params.$FIELD"
  - pattern: "request.uri.queryParameters.$FIELD"
  - pattern: "context.request.$FIELD"

pattern-sinks:
  - pattern: "$DB.rawQuery($X)"
  - pattern: "$DB.execute($X)"
  - pattern: "$DB.rawInsert($X)"
  - pattern: "$DB.rawUpdate($X)"
  - pattern: "$DB.rawDelete($X)"
  - pattern: "supabase.rpc($X, ...)"

pattern-sanitizers:
  - pattern: "sanitize($X)"
  - pattern: "escapeSql($X)"
  - pattern: "int.parse($X)"
  - pattern: "int.tryParse($X)"
```

Bundle this directory in `vscode-extension/package.json:files`.

## Path B — WebAssembly (defer to v2)

WebAssembly compilation is blocked by:
1. Z3 doesn't compile to `wasm32-unknown-unknown` with the current `z3` crate.
2. RocksDB doesn't compile to WASM.
3. `tree-sitter` only partially supports WASM.

Path forward documented in [engine/Cargo.toml:88-94](engine/Cargo.toml#L88)
(the `release-wasm` profile). When tackled later:
1. Add `wasm-bindgen` exports to `engine-core/lib.rs` behind
   `#[cfg(target_arch = "wasm32")]`.
2. Disable `persist`, `smt-proofs`, `analyzer-bridge` features for WASM
   builds.
3. Compile via `wasm-pack build --target web` producing a JS+WASM bundle.
4. Load via `wasm-bindgen-rayon` from the VS Code extension's webview.

This is 2-3 weeks of work after Path A is shipped.

---

# Phase 6 — Stop the bleeding on the TS-side IFDS engine (Day 13-15)

Once the Rust engine reliably catches what the TS engine catches today, the
TS engine becomes maintenance debt.

## P6-1. Mark the TS IFDS engine as deprecated in code

**File:** [vscode-extension/src/taint/ifdsEngine.ts:1](vscode-extension/src/taint/ifdsEngine.ts)

Add a JSDoc header:
```typescript
/**
 * @deprecated since v2.0 — superseded by the Rust engine in `bin/engine-cli-*`.
 * Kept as a fallback for platforms without a prebuilt binary (Windows arm64, etc).
 * New rules should be authored as Semgrep YAML in `vscode-extension/rules/`,
 * NOT by editing this file. Bug fixes here are still accepted.
 */
```

## P6-2. Remove TS IFDS from default rule set when Rust engine is available

**File:** [vscode-extension/src/rules/index.ts:54](vscode-extension/src/rules/index.ts#L54)

Wrap registration:
```typescript
import { resolveEngineBinary } from '../extension';

// Keep TS IFDS only as a fallback for unsupported platforms.
const rustEngineAvailable = resolveEngineBinary(extensionPath) != null;
if (!rustEngineAvailable) {
  rules.push(new IfdsTaintRule());
}
rules.push(new RustEngineTaintRule());   // no-op if binary missing
```

## P6-3. Keep `dataFlow.ts` for stages 1-2

[`dataFlow.ts`](vscode-extension/src/taint/dataFlow.ts) (the 2,400-LOC
tracker) handles **non-taint** rules — regex-based detection of secrets,
debug code, insecure storage, etc. Don't touch those. Only `ifdsEngine.ts`
is being superseded.

---

# Phase 7 — Replace Dart-side primitive taint with the Rust engine (Day 16-18)

## P7-1. Make `lib/src/scanner.dart` shell out to engine-cli

**File:** [lib/src/scanner.dart:33](lib/src/scanner.dart#L33) — the `scan` method

Add a new step before the regex rules run:
```dart
import 'dart:convert';
import 'dart:io';

// Inside ProjectScanner.scan():
final engineFindings = await _runRustEngine(rootPath);
findings.addAll(engineFindings);
```

**Implementation:**
```dart
Future<List<Finding>> _runRustEngine(String rootPath) async {
  final binary = _resolveEngineBinary();
  if (binary == null) return [];

  final ruleDir = Platform.script.resolve('../rules/').toFilePath();
  final ruleFiles = Directory(ruleDir)
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.yaml'))
      .map((f) => f.path);

  final findings = <Finding>[];
  for (final rule in ruleFiles) {
    final result = await Process.run(binary, [
      rootPath, '--rules', rule, '--format', 'json',
    ]).timeout(const Duration(seconds: 60));

    if (result.exitCode != 0) {
      stderr.writeln('engine-cli failed on $rule: ${result.stderr}');
      continue;
    }

    final raw = jsonDecode(result.stdout as String) as List<dynamic>;
    for (final item in raw) {
      final m = item as Map<String, dynamic>;
      findings.add(Finding(
        category: FindingCategory.security,
        code: m['rule_id'] as String,
        severity: _mapSeverity(m['severity'] as String),
        confidence: FindingConfidence.high,
        detectionMethod: FindingDetectionMethod.taint,
        filePath: m['file'] as String,
        line: m['line'] as int,
        message: m['message'] as String,
        fix: '(see rule documentation)',
        risk: 'High-confidence taint flow detected by Rust analysis kernel.',
      ));
    }
  }
  return findings;
}

String? _resolveEngineBinary() {
  final platform = Platform.operatingSystem;     // 'macos' | 'linux' | 'windows'
  final arch = Platform.version.contains('arm64') ? 'arm64' : 'x64';
  final key = platform == 'windows' ? 'win-x64.exe' :
              platform == 'macos' ? 'darwin-$arch' :
              'linux-$arch';
  final candidates = [
    Platform.script.resolve('../bin/engine-cli-$key').toFilePath(),
    '/usr/local/bin/engine-cli',
    Platform.environment['ENGINE_CLI'] ?? '',
  ];
  for (final p in candidates) {
    if (File(p).existsSync()) return p;
  }
  return null;
}
```

## P7-2. Delete the largely-unused Dart taint_engine.dart

**File:** [lib/src/taint/taint_engine.dart](lib/src/taint/taint_engine.dart)

This 299-LOC file is only consumed by
[xss_rule.dart](lib/src/rules/security/xss_rule.dart). Migrate XSS detection
into a Semgrep YAML rule:

**File:** new file `vscode-extension/rules/dart-xss.yaml`

```yaml
id: dart.security.xss-html-widget
message: "User-controlled value flows into an HTML/Markdown widget — XSS risk. Sanitize before rendering."
severity: WARNING
languages: [dart]
mode: taint

pattern-sources:
  - pattern: "request.body.$FIELD"
  - pattern: "request.query.$FIELD"
  - pattern: "$ROW['$FIELD']"   # Supabase row data

pattern-sinks:
  - pattern: "Html(data: $X)"
  - pattern: "Markdown(data: $X)"
  - pattern: "HtmlElementView(viewType: $X)"
  - pattern: "$EL.innerHTML = $X"

pattern-sanitizers:
  - pattern: "sanitizeHtml($X)"
  - pattern: "escapeHtml($X)"
  - pattern: "DOMPurify.sanitize($X)"
```

Then delete [taint_engine.dart](lib/src/taint/taint_engine.dart) and either
update [xss_rule.dart](lib/src/rules/security/xss_rule.dart) to be a no-op,
or delete `xss_rule.dart` entirely and remove its registration from
[lib/src/rules.dart](lib/src/rules.dart).

---

# Phase 8 — Z3 SMT correlator for the Supabase 3-way check (Week 3-4, optional)

This is the moonshot — and the project's biggest CodeQL-killing feature.

## P8-1. Implement the correlator wiring

**File:** [engine/crates/engine-core/src/supabase/smt.rs](engine/crates/engine-core/src/supabase/smt.rs) —
already 822 LOC of designed code. The actual SMT formulas are documented in
the file's header.

Implementation work:
1. Build `DartClientModel` from the CPG. Walk for
   `supabase.from('T').select().eq('col', val)` chains and serialise as a
   struct describing target table, target columns, predicates.
2. Build `EdgeFunctionModel` from the CPG (TS subset). Walk for
   `createClient(url, SUPABASE_SERVICE_ROLE_KEY)` and the queries using the
   resulting client.
3. Parse RLS policies from `supabase/migrations/*.sql` into `RlsPolicyModel`.
   The Dart-side parser at [lib/src/utils/ddl_parser.dart](lib/src/utils/ddl_parser.dart)
   is the reference — translate to Rust + extend with the `USING` /
   `WITH CHECK` clause AST.
4. Implement `correlate()` that invokes Z3 via the `z3` crate.

**Effort estimate:** 3-4 weeks for one engineer who knows Z3. If you don't
have that skill, defer.

## P8-2. Add a `--enable-smt` flag to engine-cli

**File:** [engine/crates/engine-cli/src/main.rs](engine/crates/engine-cli/src/main.rs)

Add a CLI flag and a code path that, when enabled, runs the SMT correlator
over the discovered Supabase invocation sites and emits
`supabase-rls-bypass` findings.

---

# Phase 9 — Tear out the TS-side IFDS once Rust replaces it (Week 5)

Once the Rust engine has been running in CI on real apps for ≥ 2 weeks with
no regressions, delete:
- [vscode-extension/src/taint/ifdsEngine.ts](vscode-extension/src/taint/ifdsEngine.ts) (100 LOC)
- [vscode-extension/src/taint/ifdsBuilder.ts](vscode-extension/src/taint/ifdsBuilder.ts) (815 LOC)
- [vscode-extension/src/taint/ifdsSolver.ts](vscode-extension/src/taint/ifdsSolver.ts) (431 LOC)
- [vscode-extension/src/rules/security/ifdsTaintRule.ts](vscode-extension/src/rules/security/ifdsTaintRule.ts) (28 LOC)
- The "ifds-taint" rule registration in
  [vscode-extension/src/rules/index.ts:54](vscode-extension/src/rules/index.ts#L54)
- The IFDS self-test
  [vscode-extension/scripts/ifds-self-test.js](vscode-extension/scripts/ifds-self-test.js) —
  replace with an `engine-cli` self-test fixture.

Keep [vscode-extension/src/taint/dataFlow.ts](vscode-extension/src/taint/dataFlow.ts) —
it handles regex-based pre-filter checks that don't need the heavy Rust
engine.

**Net code removal: ~1,374 LOC of TypeScript** replaced by one Rust binary.

---

# Phase 10 — Acceptance gates (don't ship without these)

| Gate | What |
|------|------|
| **G1** | `cargo build --workspace --release --features "engine-core/full"` succeeds in CI on Linux. |
| **G2** | `cargo test --workspace` passes; ≥ 5 of those tests are end-to-end (full pipeline: Dart → CPG → IFDS → finding). |
| **G3** | The smoke test from P3-4 produces the expected single finding. |
| **G4** | Running the Rust engine on the existing [test/fixtures/adversarial_app/](test/fixtures/adversarial_app/) produces zero new false positives compared to the TS engine. |
| **G5** | Running the Rust engine on the [test/fixtures/](test/fixtures/) suite produces ≥ the same true-positive count as the TS engine. |
| **G6** | `cargo clippy --workspace --all-targets -- -D warnings` is clean. |
| **G7** | `engine-cli` binary size is < 30 MB on Linux x64 release builds (LTO + opt-level=3 already configured in [engine/Cargo.toml:79-87](engine/Cargo.toml#L79)). |
| **G8** | CI builds the binary for `darwin-arm64`, `darwin-x64`, `linux-x64`; all three are bundled in the `.vsix` and the extension picks the right one at activation. |
| **G9** | A real Flutter+Supabase app from GitHub (e.g. `pirxpilot/supabase-flutter-template`) scans cleanly with the Rust engine in < 10 seconds. |

---

# Phase 11 — Realistic timeline and effort

| Phase | Realistic effort | Critical path? |
|-------|------------------|---------------|
| P0 install + un-gitignore | 0.5 day | yes |
| P1 engine-core compile | 1-2 days | yes |
| P2 workspace + frontend fixes | 2-3 days | yes |
| P3 CLI rewrite | 1 day | yes |
| P4 CI | 0.5 day | no (can ship without, but shouldn't) |
| P5A native sidecar integration | 4-5 days | yes |
| P6 deprecate TS IFDS | 0.5 day | no |
| P7 Dart side integration | 2-3 days | yes |
| P8 SMT correlator | 3-4 weeks | no (deferrable) |
| P9 TS IFDS removal | 1 day | no |
| P10 acceptance gates | ongoing | yes |

**Total to v1** (ships, replaces TS IFDS, runs in CI): **~3 weeks** of
focused work for one engineer.

**Total to v2** (SMT correlator, WASM build, full Z3 three-way Supabase
verification): **~3 months**.

---

# Risks and honest gotchas (read every session)

1. **`tree-sitter-dart` 0.0.4 is ancient.** The crate hasn't been updated
   since 2022. Modern Dart 3 syntax (records, patterns, sealed classes) may
   parse incorrectly. If P3-4 produces wrong findings on Dart 3 code, you
   may need to vendor a fork of `tree-sitter-dart` and patch the grammar.
   Budget 1-2 days for this discovery if it bites.

2. **Z3 is not portable to WASM.** The `release-wasm` profile in
   [engine/Cargo.toml:88](engine/Cargo.toml#L88) anticipates this but
   doesn't solve it. Path A (native sidecar) sidesteps the problem entirely.

3. **RocksDB significantly bloats the binary** (+15-25 MB). Acceptable for
   a CI tool, painful for a VS Code extension. If size matters, ship
   `engine-cli` **without** the `persist` feature; ship a separate
   `engine-cli-cached` for CI nightly runs.

4. **The dart_analyzer sidecar feature requires bundling a Dart helper script**
   as documented in [dart_analyzer.rs:1-37](engine/crates/engine-core/src/frontend/dart_analyzer.rs#L1).
   The script doesn't exist yet. For v1, skip the analyzer-bridge feature —
   tree-sitter-only type inference is sufficient for taint analysis.

5. **The "Reactive Dependency Graph" claim is unproven.**
   [reactive_builder.rs:483](engine/crates/engine-core/src/cpg/reactive_builder.rs#L483)
   claims a "~3.4× findings increase" on a Riverpod app — there's no
   benchmark to back this up. After Phase 5 ships, run the Rust engine
   **with and without** `build_rdg()` on a real Riverpod codebase and
   measure the actual delta. Update the docs to match reality.

6. **Cross-compilation of `engine-cli` for darwin from a Linux CI runner is
   hard.** RocksDB and Z3 both link C++ stdlib differently per target. Use
   `macos-latest` runners for darwin builds and `ubuntu-latest` for Linux.
   GitHub Actions free-tier minutes allow this comfortably.

7. **The Semgrep rule format compiler at
   [semgrep_compiler.rs:526](engine/crates/engine-core/src/rules/semgrep_compiler.rs#L526)
   has not been tested against the public Semgrep registry.** It claims to
   compile arbitrary Semgrep YAML; expect ~30% of public rules to fail
   until you patch the compiler. Don't promise users "any Semgrep rule
   works" — promise "rules in the format demonstrated in
   `vscode-extension/rules/*.yaml`."

---

# Glossary — terms that confused prior assessments

- **CPG** (Code Property Graph) — a multigraph that overlays AST + CFG +
  ICFG + PDG + SDG + RDG on a shared node set. See
  [cpg/graph.rs:1-50](engine/crates/engine-core/src/cpg/graph.rs#L1).
- **IFDS** — Interprocedural, Finite, Distributive, Subset framework
  (Reps-Horwitz-Sagiv POPL '95). The solver lives in
  [solver/ifds.rs](engine/crates/engine-core/src/solver/ifds.rs).
- **RDG** (Reactive Dependency Graph) — original to this engine; edges that
  represent reactive framework data flow (stream emissions, widget rebuilds).
  See [cpg/reactive_builder.rs:1-37](engine/crates/engine-core/src/cpg/reactive_builder.rs#L1).
- **ICFG** — Interprocedural Control Flow Graph. The supergraph IFDS
  traverses.
- **SDG** — System Dependence Graph (Horwitz-Reps-Binkley TOPLAS '90). Used
  for IFDS summary-edge caching.
- **Engine** vs **Extension** — "Engine" always means the Rust workspace
  under `engine/`. "Extension" means the VS Code package under
  `vscode-extension/`. They communicate via the `engine-cli` binary
  subprocess.

---

# Final reminder

The Rust engine, as it sits today, is **scaffolding written by someone who
knew the algorithms cold but never compiled their own work.** Roughly 60%
of the code is structurally correct (graph, IFDS solver, semgrep_compiler
core). The other 40% (frontends, CLI, feature gates) needs the surgical
fixes above before anything runs.

**The highest-leverage component** is the IFDS solver in
[solver/ifds.rs](engine/crates/engine-core/src/solver/ifds.rs) — that
743 LOC of paper-grade Reps-Horwitz-Sagiv tabulation is the single biggest
win over CodeQL's commercial implementation, because it ships under
Apache-2.0 and you control every line. Get it compiling in Phase 1 and the
rest of the project unlocks.

**The biggest risk is over-promising the WASM/Z3/RDG features** before
they're proven. Ship Phase 5 (native sidecar with one solid SQL injection
rule) first. Everything else is upside.

**Re-read the gitignored-does-not-mean-ignored rule** at the top of this
document before you start work. If you skipped it, scroll up.
