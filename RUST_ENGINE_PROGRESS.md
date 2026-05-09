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
| P0  Toolchain + un-gitignore | ✅ | 2026-05-08 | 2026-05-08 | Rust 1.85 + brew deps (cmake/llvm/rocksdb/z3) installed; engine source committed in `ea074e7` |
| P1  Make engine-core compile | ✅ | 2026-05-08 | 2026-05-08 | Default + full-feature builds both pass |
| P2  Workspace + frontends | ✅ | 2026-05-08 | 2026-05-08 | All 4 crates build; 14/14 tests pass |
| P3  CLI binary | ✅ | 2026-05-08 | 2026-05-08 | Smoke test fires end-to-end (`request.body.id` → `database.rawQuery(...)`); unused-source FP filter added in `a7892cc` |
| P4  CI workflow | ✅ | 2026-05-08 | 2026-05-08 | GitHub Actions engine workflow green on run `25552936823` |
| P5  TS sidecar integration | ✅ | 2026-05-08 | 2026-05-08 | XSS YAML registered, named-argument lowering + bare-call pattern compiler fix landed, tracing→stderr, host darwin binaries built, end-to-end TS adapter verified, release-binaries CI workflow added |
| P6  Deprecate TS IFDS | ✅ | 2026-05-08 | 2026-05-08 | Legacy engine marked deprecated; fallback now skips when Rust runtime is available |
| P7  Dart sidecar integration | ✅ | 2026-05-08 | 2026-05-08 | DeepSeek + Cline landed engine_runner.dart + scanner.dart wiring; xss_rule kept as Option-B fallback |
| P8  Z3 SMT correlator | ✅ | 2026-05-08 | 2026-05-08 | Syntactic v1: extract_dart_clients + extract_rls_policies + missing-RLS finding work end-to-end. Z3 lifting + table-aware client/policy correlation deferred. See "Phase 8 — fixes" below |
| P9  Remove TS IFDS | ✅ | 2026-05-08 | 2026-05-08 | Deleted ifdsEngine.ts, ifdsBuilder.ts, ifdsSolver.ts, ifdsTaintRule.ts, ifds-self-test.js; removed ifds-taint from rules/index.ts; removed ifds-self-test from package.json; TS compiles clean; workspace tests pass |
| P10 Acceptance gates | ✅ | 2026-05-08 | 2026-05-08 | G1-G7 pass (see diary); G8-G9 deferred to release CI |
| P11 Table-aware RLS correlation | ✅ | 2026-05-08 | 2026-05-08 | extract_rls_policies now interns table/column names; correlator matches by table name, not just operation. Policy names also populated. 22/22 tests pass. |

---

## Phase 5 — TS sidecar integration completed (2026-05-08, post-Codex)

Codex's earlier commit (`f773805`) landed the TS-side scaffolding:
`vscode-extension/src/scanner/{engineResolver,rustEngineConfig,rustEngine}.ts`,
`rules/security/rustEngineTaintRule.ts`, `rules/{dart-sql,dart-command,dart-xss}.yaml`,
plus `package.json` entries and a `bundle-engine.sh` skeleton. Three concrete
gaps remained, all closed in the follow-up pass:
