# AGENTS.md — Required Reading for All AI Coding Assistants

> **This is the canonical entrypoint for every AI coding assistant.**
> Tools that follow the AGENTS.md convention read it directly; compatibility
> pointer files such as `CLAUDE.md`, `.cursorrules`, Cursor rules, Copilot
> instructions, and Cline/Gemini/Windsurf-style files should point here. If
> you are an LLM reading this repository for any reason — auditing, planning,
> implementing, refactoring, reviewing, or summarising — read this file in
> full before anything else.

---

## ⚠️ Rule #1 — "Gitignored does not mean ignored"

**Default behaviour:** when surveying or auditing this repository, inspect
the **working tree**, not just `git ls-files`. Files and directories that
are gitignored may still be in-scope, intended to ship, or actively under
development.

### Why this rule exists

A prior assessment (May 2026) **completely missed the Rust analysis engine
under [`engine/`](engine/)** — ~6,624 LOC of designed code — because the
directory was gitignored at the time. That assessment then drew incorrect
strategic conclusions ("the project is just TS + Dart") and proposed wasted
work.

### How to apply it

| ❌ Wrong | ✅ Correct |
|---------|----------|
| `git ls-files \| wc -l` to estimate project size | `find . \( -name '*.rs' -o -name '*.ts' -o -name '*.dart' \) -not -path '*/node_modules/*' -not -path '*/.dart_tool/*' \| wc -l` |
| Skipping a directory because it's in `.gitignore` | Reading `.gitignore` to understand **why**, then evaluating the gitignored content on its own merits |
| "Component X doesn't exist because it's not in git" | "Check whether Component X is gitignored, inspect the working tree directly, and decide from evidence instead of from tracking state" |
| Drafting strategy from `git log` alone | Drafting strategy from working tree, with `git log` as one input among several |
| Treating empty `git diff` as proof nothing changed | Combining `git status`, `find -newer`, and direct inspection |

### Specific to this repo

- [`engine/`](engine/) used to be ignored wholesale. That was the root cause
  of the bad audit above.
- **Current expected state:** engine source is not ignored. `.gitignore`
  should ignore only `engine/target/` and `engine/Cargo.lock`.
- Verify this before any engine work:
  `git check-ignore -v engine/Cargo.toml` should print nothing, while
  `git check-ignore -v engine/target engine/Cargo.lock` should show the
  narrow build-artifact rules.
- If `engine/` or `engine/Cargo.toml` is ignored again, fix `.gitignore`
  immediately before planning, implementing, or reviewing engine work.

### When in doubt

**Look at it, then decide.** The cost of looking is one `find` command;
the cost of skipping is the kind of audit failure that motivated this rule.

---

## Rule #2 — Read the blueprint before touching `engine/`

Before writing, editing, deleting, planning, reviewing, or commenting on
**any file under [`engine/`](engine/)**, read
[BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) end-to-end.

The blueprint contains:

- The 11-phase resurrection plan with exact file paths, line numbers, and
  code diffs.
- The verified compile-blocking issues per file (NodeKind mismatches,
  feature-name typos, broken CLI, etc).
- The strategic decision (Rust engine = future canonical kernel, replacing
  TS-side IFDS).
- Acceptance gates — don't ship without them.
- Honest gotchas (Z3/WASM incompatibility, ancient `tree-sitter-dart`,
  unproven RDG claims).

Skipping the blueprint and improvising in `engine/` will reproduce the
exact bugs the blueprint already identifies and fixes.

---

## Rule #3 — The three codebases in this repo are independent

| Codebase | Path | Purpose | Language |
|----------|------|---------|----------|
| **Rust engine** | [`engine/`](engine/) | Future canonical analysis kernel — IFDS solver, CPG, Semgrep YAML compiler, Z3 SMT correlator. Experimental: workspace tests currently pass, but the smoke-test rule still produces 0 findings; see [`RUST_ENGINE_PROGRESS.md`](RUST_ENGINE_PROGRESS.md). | Rust |
| **TS VS Code extension** | [`vscode-extension/`](vscode-extension/) | Current shipping scanner — 42 rules, intra-procedural taint engine in [`dataFlow.ts`](vscode-extension/src/taint/dataFlow.ts), Dart-only IFDS in [`ifdsEngine.ts`](vscode-extension/src/taint/ifdsEngine.ts). | TypeScript |
| **Dart `lib/` scanner** | [`lib/`](lib/) | Standalone Dart scanner — 38 rules, primitive AST taint tracker in [`taint_engine.dart`](lib/src/taint/taint_engine.dart). | Dart |

**Do not conflate them.** A "rule" in the TS extension is unrelated to a
"rule" in the Dart scanner is unrelated to a "rule" (Semgrep YAML) in the
Rust engine. Each has its own rule registry, test suite, and lifecycle.

The Rust engine is intended to **replace** the TS-side IFDS engine and the
Dart-side taint tracker — see Phases 6, 7, 9 of the blueprint — without
touching the regex-based rules in either.

---

## Rule #4 — Be honest, no sugar-coating

When asked for assessments of this codebase:

- State what is verified vs assumed vs unknown.
- Don't claim coverage that doesn't exist.
- Don't dismiss a component because it's gitignored, broken, or
  undocumented (see Rule #1).
- Specifically: **the Rust engine exists, has ~6,624 LOC, now builds in the
  default workspace path, and is not functionally complete.** Saying "the
  engine is finished" or "the engine doesn't exist" are both wrong.

---

## Quick orientation (before doing anything)

Run this once per session to verify your mental model matches reality:

```bash
# Confirm working tree composition (not git ls-files)
find . -name '*.rs' -not -path '*/target/*' | wc -l            # ~19 Rust files in engine/
find vscode-extension/src -name '*.ts' | wc -l                  # ~80 TS files
find lib -name '*.dart' | wc -l                                 # ~40 Dart files

# Confirm gitignore state of engine source vs build artifacts
git check-ignore -v engine/Cargo.toml || true                    # should print nothing
git check-ignore -v engine/target engine/Cargo.lock              # should show narrow ignore rules

# Confirm Rust toolchain
cargo --version                                                 # need ≥ 1.85.0
```

If any of those don't match expectations, **read AGENTS.md and
BLUEPRINT_RUST_ENGINE.md again before proceeding.**

---

## Other relevant docs

- [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) — the engine resurrection plan (must-read before touching `engine/`).
- [README.md](README.md) — user-facing overview of the shipping scanner.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — implementation notes for the TS/Dart sides.
- [PROGRESS.md](PROGRESS.md) — chronological change log.
- [GOALS_PROGRESS.md](GOALS_PROGRESS.md) — feature progress against the roadmap.
- [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md) — live progress against the Rust blueprint.
- [goals/](goals/) — per-area roadmap (00-engine, 01-language-coverage, etc.).
- [SECURITY.md](SECURITY.md) — security policy.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

---

## TL;DR

1. **Read this file before any implementation or fix in this repository.**
2. **Look at gitignored content** — don't trust `git ls-files` for surveys.
3. **Read [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) before
   editing anything in `engine/`.**
4. Three independent codebases live here — don't conflate them.
5. Be honest about what's broken vs working vs unknown.
