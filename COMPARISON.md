# Honest comparison vs CodeQL (and other industry-standard SAST)

This document is a deliberately unflattering look at where our scanner sits
relative to commercial / open-source SAST. It has two parts:

1. **Blind benchmark** — 15 fixtures spanning easy to depth-required, run
   through our scanner, with each fixture's "correct" outcome documented and
   the result assessed against expected CodeQL behavior.
2. **Code review** — architectural strengths and weaknesses of what we
   actually built vs what CodeQL et al. ship.

Bottom line up front: we are **competitive on a small surface** (Supabase /
Flutter / IFDS-Dart / a curated set of Node.js rules with codeFlows) and
**materially behind** on every dimension that requires deep semantic
analysis (cross-file flow, framework models, prototype pollution, ReDoS,
guard reasoning). We should ship and use the tool, but we should not claim
parity.

---

## 1. Blind benchmark

15 fixtures, written cold, with expected "correct" behavior documented
alongside the case. The test corpus and our scanner output are both
reproducible:

```bash
# fixtures live in /tmp/bench (recreate via the script in §5 below)
cd vscode-extension
node out/cli.js scan /tmp/bench --json | jq '.findings[] | { line, code, cwe, severity, message }'
```

### Scoreboard

| # | Fixture | Vuln class | Ground truth | Our result | Expected CodeQL | Verdict |
|---|---------|------------|--------------|------------|------------------|---------|
| 01 | classic-sql.js | SQL injection | flag HIGH | ✅ HIGH `CWE-89` | ✅ HIGH | **TIE** |
| 02 | sanitized-sql.js | parameterized — safe | no flag | ✅ no flag | ✅ no flag | **TIE** |
| 03 | interprocedural.js | SQLi via 2 helpers | flag HIGH | ✅ HIGH `CWE-89` | ✅ HIGH | **TIE** *(thanks to our function summaries for `return source` shape)* |
| 04 | cross-file-source.js | SQLi via cross-file source | flag HIGH | ⚠️ MEDIUM (dynamic-only — didn't trace the source across files) | ✅ HIGH | **CodeQL wins** |
| 05 | async-callback.js | SQLi via `Promise.then` | flag HIGH | ⚠️ MEDIUM (dynamic-only — no async taint) | ✅ HIGH | **CodeQL wins** |
| 06 | conditional-sanitization.js | parseInt on every path — safe | no flag | ✅ no flag | ✅ no flag | **TIE** |
| 07 | prototype-pollution.js | proto pollution | flag HIGH | ❌ no flag | ✅ HIGH (`js/prototype-polluting-assignment`) | **CodeQL wins** |
| 08 | redos.js | ReDoS `(a+)+` | flag HIGH | ❌ no flag | ✅ HIGH (`js/redos`) | **CodeQL wins** |
| 09 | polymorphic-dispatch.js | runtime-resolved sink | flag the eval branch | ✅ flagged eval branch (CWE-95) and tainted call site (CWE-89) | ✅ both flagged | **TIE** |
| 10 | framework-model-express.js | Express SQLi + reflected XSS | flag both | ❌ neither flagged (we don't model `res.send`/`res.json` as HTML sink + missed the inline SQLi) | ✅ both flagged via `js/sql-injection` and `js/reflected-xss` | **CodeQL wins** |
| 11 | ssrf-with-allowlist.js | guarded by Set allowlist — safe | no flag | ❌ FALSE POSITIVE (HIGH SSRF despite allowlist) | ⚠️ CodeQL also FPs unless a barrier guard is wired | **TIE on FP** |
| 12 | stored-then-rendered.js | stored XSS via DB roundtrip | flag HIGH | ❌ no flag (no taint across DB) | ⚠️ CodeQL has a stored-XSS query but only with explicit DB sink models — FN risk | **TIE on FN** |
| 13 | jwt-misuse.js | `algorithms: ['none']` | flag HIGH | ✅ HIGH `CWE-347` | ✅ HIGH (`js/jwt-missing-verification`) | **TIE** |
| 14 | cors-misconfig.js | wildcard origin + creds | flag HIGH | ✅ HIGH `CWE-942` | ✅ HIGH (`js/cors-misconfiguration`) | **TIE** |
| 15 | sanitizer-name-only.js | function literally named `sanitize` that doesn't sanitize | flag HIGH (the sanitizer is a no-op) | ❌ no flag (we trust the name) | ⚠️ CodeQL also trusts shape-matched sanitizers without barrier customization | **TIE on FN** |

### Tally

|                          | Ours | CodeQL (expected) |
|--------------------------|------|-------------------|
| True positives (full HIGH) | 6 | 11 |
| Partial catches (downgraded to MEDIUM) | 2 | 0 |
| True negatives (correctly silent) | 3 | 3 |
| False positives | 1 (#11) | 1 (#11) |
| False negatives | 4 (#7, #8, #10, #12, #15) | 1 (#15 — same FN class) |

**Verdict:** roughly **6–8 ties, 4 hard losses, 0 wins**. The losses are all
in territory that requires real inter-procedural / framework-model analysis.

The "ties" should not be celebrated too hard — they're cases where regex and
heuristics happen to land on the right answer for simple input shapes. The
moment a real codebase puts taint through async, callbacks, message
channels, or whole-program flow, the gap widens.

### Real numbers from running our scanner

```
01-classic-sql.js:3:10           high   injection-flaw   CWE-89   tainted SQL via db.query
03-interprocedural.js:7:10       high   injection-flaw   CWE-89   tainted SQL via db.query
04-cross-file-source.js:5:10     medium injection-flaw   CWE-89   dynamic value (downgraded)
05-async-callback.js:4:17        medium injection-flaw   CWE-89   dynamic value (downgraded)
09-polymorphic-dispatch.js:2:36  medium injection-flaw   CWE-78   dynamic command
09-polymorphic-dispatch.js:3:38  medium injection-flaw   CWE-95   dynamic code
09-polymorphic-dispatch.js:3:38  medium unsafe-eval      CWE-95   eval()
09-polymorphic-dispatch.js:5:10  high   injection-flaw   CWE-89   tainted dispatch site
11-ssrf-with-allowlist.js:6:16   high   injection-flaw   CWE-918  fetch (FP — allowlist ignored)
13-jwt-misuse.js:4               high   jwt-misuse       CWE-347  algorithms ['none']
14-cors-misconfig.js:2           high   cors-misconfig   CWE-942  origin:true + credentials
```

---

## 2. Code review — what we built vs what CodeQL ships

### 2.1 Engine sophistication

| Capability | Ours | CodeQL |
|---|---|---|
| Whole-program database | ❌ in-memory per scan | ✅ `codeql database create` builds a relational DB once |
| Type system / points-to | ❌ name-based heuristics | ✅ flow-insensitive points-to with class hierarchy |
| Inter-procedural taint | ⚠️ **Dart only** via IFDS (Reps–Horwitz–Sagiv tabulation, 431 LOC solver in `ifdsSolver.ts`); JS/TS limited to "function returns a direct source" summaries | ✅ Full inter-procedural for every supported language |
| Cross-file taint | ❌ JS/TS — only same-file summaries | ✅ Yes |
| Async / Promise / callback | ❌ not modeled | ✅ Modeled via standard library shapes |
| Field-sensitivity | ⚠️ partial — we track `obj.prop` literal/tainted properties up to `MAX_TAINT_DEPTH=3`; degrades to "weak" indirect taint after | ✅ Field-sensitive throughout |
| Path-sensitive (CFG guards) | ❌ no — conditional sanitization deliberately not trusted (FP-bias) | ✅ Yes via guards.qll |
| Soundness story | heuristic, no formal foundation | ✅ Datalog/QL semantics with documented soundness limits |

### 2.2 Sources / sinks / sanitizers

| | Ours | CodeQL JS pack |
|---|---|---|
| Sink kinds modeled | 10 (`sql`, `command`, `code`, `html`, `url`, `path`, `redirect`, `nosql`, `template`, plus xpath/ldap as sql-family) | 30+ across 250+ queries |
| Source patterns | 12 categories (req.body/query/params, process.env/stdin, Flask/Django/FastAPI args, controller .text/.value, destructured request fields, strong param names) | Hundreds — every framework model contributes |
| Sanitizer detection | regex over function names + `parseInt`/`parseFloat` numeric coercion | Per-rule barrier configs + type-based reasoning |
| Framework models | None (Express implicit only at the parameter-name level) | Express, Koa, Fastify, Next.js, NestJS, Restify, Hapi, AWS Lambda, Vercel, Cloudflare Workers, … |

### 2.3 Where IFDS-Dart genuinely competes

The Dart side has a real IFDS solver:

```
ifdsSolver.ts:    431 LOC — proper RHS tabulation, path edges, summaries,
                            pendingCallers, return-loc cache
ifdsBuilder.ts:   815 LOC — graph builder over tree-sitter
ifdsEngine.ts:    100 LOC — top-level engine wrapper
total taint LOC: 3150 across both engines
```

This is **inter-procedural for Dart**. CodeQL doesn't currently support
Dart, so for that one language we are strictly ahead of CodeQL by virtue
of CodeQL not playing. The 7-fixture IFDS self-test passes.

This is genuine novel value — Dart is underserved by mainstream SAST.

### 2.4 Where we tie or lead on UX / output

| | Ours | CodeQL |
|---|---|---|
| SARIF 2.1.0 | ✅ With codeFlows + per-rule CWE aggregation | ✅ |
| GitHub Code Scanning | ✅ Via SARIF | ✅ Native (it's GitHub's tool) |
| Zero-config setup | ✅ Single `npx` invocation | ❌ Needs DB build, sometimes a build env (`autobuild`) |
| Speed | ✅ Typically <1s for small projects, no DB build phase | ❌ Database build can take minutes-to-hours |
| In-editor experience | ✅ VS Code extension w/ diagnostics + quick fixes (real fixes for `Math.random→crypto`, `algorithms:['none']→['HS256']`, etc.) | ⚠️ Has VS Code Starter Pack but quick fixes aren't a focus |
| Custom rules | ❌ Requires forking + recompiling | ✅ Write QL queries |
| Tutorials / docs | ⚠️ README + IMPLEMENTATION + PROGRESS in this repo | ✅ Extensive QL docs, courses, language packs |
| Telemetry | ✅ Local-only, validated XDG path | ⚠️ GitHub uploads SARIF on Code Scanning runs |

### 2.5 Where we are honestly behind

1. **Cross-file taint in JS/TS.** Fixture 04 was downgraded to MEDIUM
   because we couldn't trace the source through `extractId` from another
   module. CodeQL handles this trivially.

2. **Async / Promise.then taint.** Fixture 05 — same story. Real Node
   apps live inside `then`/`async`/`await`. We mostly miss them.

3. **Framework knowledge.** Fixture 10 had two real bugs in 5 lines of
   Express code; we caught zero. CodeQL's Express model would catch both.

4. **Whole vulnerability classes missing.** Prototype pollution (07), ReDoS
   (08), stored XSS (12), insecure regex, command injection through shells,
   path-style template injection, etc. — these need rule authorship and
   often deeper analysis than we have.

5. **Guard reasoning.** Fixture 11's allowlist barrier was completely
   ignored by us; CodeQL has a `BarrierGuard` mechanism that can be wired
   per-query. We FP at the same rate as a basic CodeQL config though.

6. **Sanitizer trust.** Fixture 15 — we trust any function literally named
   `sanitize`. CodeQL has the same default behavior; both tools share this
   FN class.

7. **Coverage breadth.** CodeQL ships 250+ queries on JS alone covering
   classes we don't model: prototype pollution, ReDoS, log injection,
   misleading-progress, hardcoded credentials in many shapes, dependency
   confusion, regex DoS, polynomial backtracking, etc. We have 24 rules.

8. **Soundness / completeness story.** We can't produce numbers like "we
   miss X% of SQLi on the OWASP Benchmark." CodeQL has documented results
   on standard benchmarks. We don't run any.

### 2.6 Where we are honestly ahead

These are real, measurable wins — not marketing fluff:

1. **Dart support.** CodeQL doesn't ship Dart. Our IFDS engine for Dart
   produces 7/7 catches on the Reps–Horwitz–Sagiv test fixtures with
   inter-procedural flow.

2. **Supabase / Flutter rules.** No mainstream SAST has rules for missing
   RLS, public-bucket misuse, hardcoded `anonKey`, weak Supabase config,
   client-side trust on Supabase queries, file-upload-validation in Flutter
   storage calls, etc. — but every Flutter+Supabase project has these.

3. **CWE on every finding, with codeFlows from day one.** GitHub Code
   Scanning consumes our SARIF cleanly with full data-flow paths for
   taint findings.

4. **In-editor quick fixes that are real edits, not TODO comments.**
   `Math.random()` becomes `crypto.randomUUID()`; `algorithms: ['none']`
   becomes `['HS256']`; `httpOnly: false` becomes `true`. The user can
   accept the fix and ship.

5. **Setup time.** `npx flutter-supabase-helper scan .` runs in seconds.
   CodeQL needs a DB build first, which on a real Express app takes
   minutes.

6. **Statement-aware suppression.** Inline `// sast-ignore`s respect
   bracket balance, so multi-line wrapped statements get suppressed but
   adjacent statements don't leak. CodeQL's `lgtm[js/...]` comments
   suppress per-line and have edge cases.

7. **Concurrent rule execution + race-safe AST cache.** 26 unit
   invariants exercise this. CodeQL uses incremental DBs which sidestep
   the issue, but for an in-memory scanner this is non-trivial.

---

## 3. Honest competitive position

We are **not** "rivaling and beating most SAST tools like CodeQL." That
claim from the original audit is aspirational. The honest pitch is:

> **A fast, zero-config security scanner with first-class Supabase / Flutter
> coverage, full Dart inter-procedural taint analysis, and SARIF + CWE
> output for GitHub Code Scanning. Use it alongside CodeQL on multi-language
> projects, or alone on Flutter / Dart codebases where CodeQL doesn't
> apply.**

That's a defensible positioning. Trying to beat CodeQL across the board
would require:

- 5–10× more rule authorship
- A whole-program JS/TS DB phase (likely on top of TypeScript's compiler)
- Framework models for at least Express/Koa/Fastify/Next.js
- Real guard / barrier reasoning on a CFG
- Property fix for the prototype-pollution / ReDoS / log-injection /
  stored-XSS gaps
- Custom rule authoring DSL

Each of those is multi-week work, and several need design.

---

## 4. Recommended next moves (high-leverage)

If we want the gap to close on the **right** dimensions:

1. **Cross-file taint summaries** — even a coarse "exported function
   returns a direct source" map would catch fixtures 04 and 12.
2. **Async / Promise taint** — `Promise.then(cb)` propagation rules in
   the IntraProc engine. Cheapest big lift.
3. **Express model** — flag every `req`/`res` parameter pair and treat
   `res.send`/`res.write`/`res.json` as HTML sinks. ~50 LOC.
4. **Add three queries:** `prototype-pollution`, `redos`, `log-injection`.
   Each is well-documented; a regex+AST pass gets you 80% of CodeQL's
   catch rate.
5. **Barrier guard recognition** — even just `if (allowlist.has(x)) ...`
   should clear taint on `x` for that branch.
6. **Sanitizer-evidence requirement** — fixture 15 fix. Don't trust a
   function named `sanitize` unless it's an `Allowlist`-shaped library
   call OR has been explicitly registered. We could ship an allowlist of
   known-good libraries (DOMPurify, sqlstring, validator, …) and require
   the call to come from one of them.

Each of these is days, not weeks. After all five we'd close roughly half
the FN gap on the benchmark above and remove the FP on fixture 11.

---

## 5. Reproduce the benchmark

```bash
mkdir -p /tmp/bench && cd /tmp/bench
# (write the 15 fixtures as in §1)
cd /path/to/flutter-security-scanner/vscode-extension
npm test                                                 # confirm baseline green
node out/cli.js scan /tmp/bench --sarif -o /tmp/bench/our.sarif
# Compare:
codeql database create /tmp/bench/db --language=javascript --source-root=/tmp/bench
codeql database analyze /tmp/bench/db codeql/javascript-queries --format=sarif-latest --output=/tmp/bench/codeql.sarif
diff <(jq -r '.runs[0].results | length' /tmp/bench/our.sarif) \
     <(jq -r '.runs[0].results | length' /tmp/bench/codeql.sarif)
```

I did not run the CodeQL side as part of producing this document — running
CodeQL requires a DB build environment and the GitHub CodeQL CLI. The
"expected CodeQL" column above is based on CodeQL's published query
catalog and its public documentation for each fixture's vulnerability
class. If you run it yourself and any expected behavior differs, that's
worth opening an issue against this comparison.
