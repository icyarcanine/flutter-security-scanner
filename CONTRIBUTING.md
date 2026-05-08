# Contributing to flutter-security-scanner

> Before writing any code in `engine/`, **read [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) and [AGENTS.md](AGENTS.md) first**. They contain the architectural plan, gotchas, and the gitignored-does-not-mean-ignored rule that prevents repeating prior audit failures.

## One-shot setup

The fastest way to set up a contributor environment:

```bash
./scripts/bootstrap.sh
```

This script detects what's missing (Rust, Node, Dart, system libs) and either installs it (after asking you) or prints the exact install command. Run it again any time you suspect your environment has drifted.

For CI: `./scripts/bootstrap.sh --check` exits non-zero on any missing tool without installing.

## Manual setup

The repo has three independent codebases. Set up the ones you'll touch:

### Rust analysis kernel (`engine/`)

Required for: building or modifying the `engine-cli` binary, the IFDS solver, the Semgrep YAML compiler, the CPG builder.

```bash
# Install Rust 1.85 (the engine's minimum supported version)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
source $HOME/.cargo/env

# Build and test
cd engine
cargo build --workspace --release
cargo test --workspace
```

Optional system libs (only needed for `--features full` builds with Z3 + RocksDB):

```bash
# macOS
brew install cmake llvm rocksdb z3

# Linux
sudo apt-get install -y librocksdb-dev libz3-dev clang
```

### TypeScript VS Code extension (`vscode-extension/`)

Required for: modifying the editor integration, adding TS-side rules, or shipping a new `.vsix`.

```bash
cd vscode-extension
npm install
npm run compile
npm test
```

### Dart `lib/` scanner (`lib/`)

Required for: modifying the Dart-side scanner or its rules.

```bash
dart pub get
dart test
```

## Running the smoke test

```bash
dart run tool/smoke_test.dart
```

This runs the Dart scanner against `test/fixtures/` to prevent regressions. To smoke-test the Rust engine specifically:

```bash
cd engine
cargo test --workspace
cargo build -p engine-core
```

The end-to-end `engine-cli --rules ...` smoke test is not yet green: the CLI
runs, but the current Semgrep pattern compiler produces 0 findings on the
five-line SQL fixture. See [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md)
Phase 3 before trusting Rust engine findings.

## Adding a rule

Decide which engine the rule should live in:

| Rule kind | Where it lives | Why |
|-----------|----------------|-----|
| Inter-procedural taint flow (sql, command, xss, ssrf) | `vscode-extension/rules/*.yaml` (planned Phase 5A Semgrep YAML, consumed by the Rust engine) | High precision, cross-file capable |
| Regex-based (hardcoded secrets, debug code, file structure) | `vscode-extension/src/rules/` (TS) or `lib/src/rules/` (Dart) | Fast pre-filter, file-local |
| Supabase-specific (RLS, RPC, signed URLs) | `lib/src/rules/supabase/` (Dart) | Cross-references DDL parsed from migrations |

For the YAML format, use the [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) Phase 5A-6 notes until `vscode-extension/rules/` is created.

For Dart/TS regex rules, follow the existing patterns in adjacent rule files. Add a fixture to `test/fixtures/<your_app>/` and register an expectation in `tool/smoke_test.dart`.

## Working on the Rust engine

**Always read [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) first.** It contains:

- The 11-phase resurrection plan with exact file paths and line numbers.
- Verified compile-blocking issues per file.
- The strategic decision (Rust engine = future canonical kernel).
- Acceptance gates (`cargo test --workspace`, smoke test, etc.).

Track progress against the blueprint in [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md). Add diary entries when you deviate from the plan or discover new constraints.

## Pre-commit checklist

- [ ] `cd engine && cargo fmt --all -- --check && cargo test --workspace` (if you touched `engine/`)
- [ ] `cd engine && cargo clippy --workspace -- -D warnings` once the P10/G6 warning cleanup is active
- [ ] `cd vscode-extension && npm test` (if you touched the extension)
- [ ] `dart test` (if you touched `lib/`)
- [ ] `dart run tool/smoke_test.dart` (always)
- [ ] If you added a new dependency to `engine/`, update [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md) Risks tracker if it has unusual install requirements.
