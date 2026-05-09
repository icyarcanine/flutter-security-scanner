# PROGRESS.md — Fixes Applied During Hyper-Deep Scan (08-May-2026)

> **Canonical change log.** Each entry describes what was broken, what the fix was, and which files were touched.

---

## Fix #1: TypeScript Frontend — Engine Can Now Parse Edge Functions

**Problem:** The engine had no TypeScript frontend. `extract_edge_functions()` in `populator.rs` returned an empty `Vec` and emitted a `tracing::warn!` saying "TypeScript frontend is not wired."

**Fix:** Created `engine/crates/engine-frontend-typescript/` with 4 files (~350 LOC):
- `Cargo.toml` — depends on `tree-sitter-typescript = "0.21"`, `tree-sitter = "0.22"`
- `src/lib.rs` — public `parse_typescript()` entry point (`.ts` and `.tsx`)
- `src/ast_builder.rs` — maps tree-sitter CST nodes to CPG `NodeKind`s (30+ mappings: function declarations, class declarations, arrow functions, template strings, JSX elements, etc.)
- `src/cfg_builder.rs` — CFG edges for if/else, loops, return, switch, try/catch, logical operators

**Impact:** Edge functions (`supabase/functions/**/*.ts`) can now be parsed and their `createClient()`, `req.body.*`, `SERVICE_ROLE_KEY` patterns detected.

---

## Fix #2: SQL Frontend — RLS Policies Parsed to AST (Not Regex)

**Problem:** `extract_rls_policies()` used fragile regex to parse SQL DDL. No proper AST, no test coverage for complex policies.

**Fix:** Created `engine/crates/engine-frontend-sql/` with 3 files (~480 LOC):
- `Cargo.toml` — depends on `tree-sitter-sql = "0.1"`
- `src/model.rs` — `SqlExpr` enum: BinaryOp, FunctionCall, ColumnRef, Compound, Subquery, etc.
- `src/parser.rs` — recursive-descent AST parser built on tree-sitter SQL, with policy extraction
- `src/lib.rs` — public `parse_sql_policy()` entry point

**7 unit tests:** simple policies, AND chains, WITH CHECK, function calls, multiple policies, roles.

**Impact:** RLS policy analysis now works on proper SQL ASTs, not regex heuristics.

---

## Fix #3: Real BMC Implementation — Z3 Fallback Does Something

**Problem:** `BoundedModelChecker::run()` in `smt.rs` was a stub that immediately returned `BmcVerdict { conclusion: Inconclusive, depth_explored: 0 }`. The sibling `bmc.rs` had the real BMC code but was never called.

**Fix:**
- Removed stub `BoundedModelChecker` struct from `smt.rs` — replaced with a `bmc_unknown()` helper function
- Fixed `bmc.rs` to have the real `BoundedModelChecker` with `run(query, budget)` that enumerates concrete values
- Added `run_default()` convenience method for stub callers
- Updated `smt.rs` stub correlator to use `bmc_unknown()` instead of `BoundedModelChecker::new().run()`
- Updated `supabase/mod.rs` to include `pub mod bmc;` and re-export

**3 new tests:** no-taint, taint-blocked, run-default-inconclusive.

**Impact:** Non-Z3 builds now actually check counterexamples instead of giving up.

---

## Fix #4: YAML Rules — Dart/Flutter Sources, Not Node.js

**Problem:** All 3 YAML rules (`dart-command-injection.yaml`, `dart-sql-injection.yaml`, `dart-xss.yaml`) had source patterns from Node.js Express.js frameworks (`request.body.NAME`, `req.params.NAME`, `req.query.NAME`) that would never match in Dart/Flutter code.

**Fix:** Rewrote all 3 rule files:

**dart-command-injection.yaml:**
- Sources: `TextEditingController.text`, `SharePreferences.getString()`, `Platform.environment`, `stdin.readLineSync()`, `http.Client.get/post`, `Uri.queryParameters`
- Sinks: `Process.run()`, `Process.start()`, `Runtime.exec()`, `Platform.executable`, `Isolate.spawn()`, `dart:io Process`

**dart-sql-injection.yaml:**
- Sources: Same Dart input sources
- Sinks: `supabase.from().select()`, `supabase.rpc()`, `DatabaseExecutor.rawQuery()`, `sqflite rawQuery/rawInsert/rawUpdate`, `FirebaseFirestore where/arrayContains`
- Patterns: Same-table chain detection

**dart-xss.yaml:**
- Sources: Same Dart input sources
- Sinks: `flutter_inappwebview InAppWebView`, `flutter_html Html.data`, `dart:js context.callMethod('eval')`, `ReactDom.render()`, `innerHtml`
- Patterns: Same-method chain detection

**Impact:** The YAML rules now actually match Dart/Flutter code patterns.

---

## Fix #5: Workspace Wiring — CLI Parses TS/TSX/SQL

**Problem:** `engine/Cargo.toml` didn't list the new frontend crates as workspace members. CLI only parsed `.dart` and `.rs` files.

**Fix:**
- Added `"crates/engine-frontend-typescript"` and `"crates/engine-frontend-sql"` to `[workspace] members`
- Added `tree-sitter-typescript = "0.21"` and `tree-sitter-sql = "0.1"` workspace dependencies
- CLI `main.rs` now:
  - Imports `engine_frontend_typescript::parse_typescript` and `engine_frontend_sql::parse_sql_policy`
  - Walks `.ts`, `.tsx`, `.sql` files alongside `.dart` and `.rs`
  - Calls `extract_edge_functions()` from the SMT correlator (previously commented out / `None`)
  - Edges functions are matched to client queries by table name via `inner_query`

**Impact:** The CLI now handles 5 file types. Edge functions are extracted and correlated.

---

## Summary

| Gap | Status | Files Touched |
|-----|--------|---------------|
| TypeScript frontend | ✅ FIXED | 4 new TS-frontend files + `Cargo.toml` |
| SQL frontend | ✅ FIXED | 3 new SQL-frontend files + `Cargo.toml` |
| BMC stub → real | ✅ FIXED | `smt.rs`, `bmc.rs`, `mod.rs` |
| YAML sources wrong | ✅ FIXED | All 3 `rules/*.yaml` files |
| CLI wiring | ✅ FIXED | `main.rs`, `Cargo.toml` workspace |
| **cdylib WASM** | ❌ Still missing | Need `[lib] crate-type` in `engine-core/Cargo.toml` |
| **Cross-file analysis** | ❌ Not default path | IFDS solver exists but not invoked by default |
| **Custom query language** | ❌ Not planned | Semgrep YAML only |
| **Supply chain scanning** | ❌ Not designed | — |
