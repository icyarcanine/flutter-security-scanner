# Flutter Supabase Helper — Hybrid SAST Engine

A static application security testing (SAST) toolkit for Flutter + Supabase
projects. The repository ships **two separate scanners** that share the same
finding codes but run different engines:

| Component | Location | Engine | When to use it |
|-----------|----------|--------|----------------|
| **VS Code extension** | `vscode-extension/` | Regex **+** tree-sitter AST **+** taint tracking — intra-procedural for JS/TS, **inter-procedural IFDS for Dart** (TypeScript, Node.js, `web-tree-sitter@0.21.0`) | Day-to-day authoring — inline quick fixes, AST/REGEX badges, taint-confirmed findings |
| **Dart CLI** | `bin/fluttersupabasehelper.dart` | Regex/structural Flutter + Supabase rules with committed SQL DDL awareness (Dart) | CI gating on Flutter apps, headless scans, local `dart run` |

The Dart CLI deliberately **does not** use tree-sitter or taint tracking. It is a
fast, zero-dependency lint pass that complements `dart analyze` with Flutter- and
Supabase-specific checks (table/operation-level RLS DDL coverage, committed `.env`, unobscured
password fields, weak platform manifests, etc.). Everything under "Analysis
Pipeline", "Taint Model", and "Confidence Levels" below describes the **VS Code
extension engine**, not the CLI.

**Current shipped features:** SARIF 2.1.0 output, standalone HTML reports, CWE taxonomy, data-flow paths
in findings, AST-aware inline suppressions, content-hash baselines, git diff
mode for PR-style scans, SARIF diff mode, confidence-based CI failure,
parallel rule execution, multi-root workspaces, on-save scanning, per-rule
disable, statement-aware suppression boundary, inter-procedural IFDS for
Dart, and regression-tested taint engine behavior.

## What It Detects

- **Injection flaws** — SQL injection, command injection, code execution,
  XSS, path traversal, SSRF, open-redirect, LDAP/XPath, NoSQL `$where`,
  template injection, Python format-string injection, deserialization
  (source-to-sink taint confirmed where applicable)
- **Hardcoded secrets** — AWS keys, private keys, JWT tokens, hardcoded
  Supabase anon keys, high-entropy strings
- **JWT misuse** — `jwt.decode` without verify, `algorithms: ['none']`,
  hardcoded HMAC secrets (incl. file-local variable tracking), HS* verifier
  configuration with public-key-looking values
- **Insecure cookies** — `httpOnly: false`, `secure: false`,
  `sameSite: 'none'` without secure
- **CORS misconfiguration** — wildcard origin + credentials, `cors({ origin: true, credentials: true })`,
  origin reflection
- **Insecure randomness** — `Math.random()` for security-sensitive values
- **JavaScript platform risks** — cleartext HTTP clients, tabnabbing,
  broad cookie domains, sensitive web storage, clipboard exposure,
  symlink-following filesystem reads, deprecated TLS protocol pinning,
  weak crypto APIs, typosquatted packages, prototype-pollution writes,
  high-confidence ReDoS regex patterns
- **Supabase misconfigurations** — missing table/operation-level RLS DDL,
  policies without enabled RLS, insecure storage rules,
  committed `.env` files, public buckets, unscoped realtime channels,
  leaked realtime subscriptions, multiple clients, improper init
- **Mobile/WebView risks** — Android `addJavascriptInterface` bridges and
  `flutter_secure_storage` values written to logs
- **Unsafe patterns** — sensitive logging, debug artifacts, client-side
  trust violations, missing upload validation

Every security finding carries a CWE identifier (e.g. `CWE-89` SQL injection,
`CWE-78` command, `CWE-918` SSRF, `CWE-79` XSS, `CWE-338` insecure random,
`CWE-347` JWT, `CWE-942` CORS, `CWE-798` hardcoded credentials).

## Supported Languages (VS Code extension)

| Tier | Languages | Analysis |
|------|-----------|----------|
| **Full** | JavaScript, TypeScript, JSX, TSX | Regex + AST + intra-procedural taint tracking |
| **Full (IFDS)** | Dart | Regex + AST + intra-procedural taint tracking + inter-procedural IFDS (`ifds-taint`) |
| **AST** | Python, Go, Java | Regex + AST structural patterns |
| **Regex** | Kotlin, SQL, YAML, JSON, `.env` | Heuristic rules only |

## Analysis Pipeline (VS Code extension)

1. **Regex** — fast heuristic pass across all files
2. **AST** — selective parsing via `web-tree-sitter` WASM grammars
3. **Taint tracking** — intra-procedural data-flow analysis with provenance
   capture (JS/TS), plus inter-procedural IFDS for Dart (`ifds-taint` rule)

Rules within each stage run in **parallel** (`Promise.all`); stages
themselves run sequentially because later stages depend on caches built by
earlier ones.

### Taint Model

The taint tracker performs intra-procedural source-to-sink analysis with the
following properties:

- **Sources**:
  - **Strong** (always tainted): `req`/`request` parameters,
    parameters literally named `userInput`, `req.body/query/params/headers/...`
    member access, `process.env/stdin`, `platform.environment`,
    Flask/Django/FastAPI request fields, controller `.text/.value`.
    `URLSearchParams.get(...)` is treated as user-controlled query input.
  - **Heuristic** (tainted only with handler-shape sibling): `data`,
    `payload`, `input` — flagged as a source only when the function also
    accepts a `res`/`response`/`next`/`reply`/`ctx` parameter (Express
    handler shape).
- **Sinks** (with CWE):
  - SQL (`query`, `execute`, `raw`, `rawQuery`, …) — `CWE-89`. Receiver
    must be DB-shaped (`db`, `database`, `client`, `pool`, `prismaClient`,
    `myDb`, `getDb()`, `pgPool`, …) OR the first argument must contain a
    SQL keyword string. Bare `analytics.query()` is **not** flagged.
  - Command — `exec`, `spawn`, `subprocess.run`, `os.system` — `CWE-78`.
  - Code — `eval`, `Function`, `setTimeout`/`setInterval` (string arg),
    `pickle.loads`, `yaml.load`, `marshal.loads` — `CWE-95`.
  - HTML — `innerHTML`, `outerHTML`, `document.write`,
    `dangerouslySetInnerHTML`, `res.send`/`response.send`/`reply.send`
    response-body sinks — `CWE-79`.
  - URL/SSRF — `fetch`, `axios.*`, `http.get`, `requests.*`,
    `urllib.urlopen` — `CWE-918`.
  - Path — `fs.readFile/writeFile/...` — `CWE-22`.
  - Redirect — `res.redirect`, `res.location` — `CWE-601`.
  - NoSQL — Mongo `find`/`update`/etc. with `$where`/`$function`/
    `$accumulator` operators — `CWE-943`.
  - Template/SSTI — `render_template_string`, Jinja `from_string` — `CWE-1336`.
  - LDAP/XPath — `ldap.search`, `xpath.evaluate` — `CWE-89` family.
- **Sanitizers** (per-sink kind — §QW-1 / §PR-6):
  - **Full-spectrum** (clear taint for every sink kind):
    - Numeric coercion: `parseInt`, `parseFloat`, `Number.parseInt`,
      `Number.parseFloat`, `Number`, unary `+`, `~~`, `| 0`, `>>> 0`.
      Return type is a number — cannot carry payloads.
    - Validators: `validate/assertValid/ensureSafe/schema.parse/safeParse/...`.
    - Generic catch-all: `sanitize/clean/normalize/escape` when no more
      specific name matches.
    - Allowlist-stripping replace: `.replace(/[^A-Za-z0-9_-]/g, '')`,
      `.replace(/\D/g, '')`, etc.
  - **Sink-specific** (only suppress matching sink kinds):
    - HTML: `escapeHtml`, `encodeHTML`, `sanitizeHtml`,
      `dompurify.sanitize`, `validator.escape`.
    - URL / redirect / header: `encodeURI`, `encodeURIComponent`.
    - SQL: `escapeSql`, `sqlstring.escape`, `mysql.escape`, `pg.escape`.
    - Command: `escapeShell`, `shellEscape`.
  - `escapeHtml(taint)` flowing into a SQL sink still flags HIGH;
    `sqlstring.escape(taint)` into a SQL sink correctly suppresses.
  - Parameterized queries recognized at the call level (second arg is
    `[…]`/`{…}`/`(…)` or matches `params/values/bindings/parameters`).
- **Precision controls**:
  - Clean reassignment (`x = 42`) clears taint; augmented assignment
    (`x += value`) preserves it.
  - Conditional sanitization (`if (cond) x = sanitize(...)`) does **not**
    promote a variable to sanitized — the engine refuses to trust a
    sanitization that may not execute on every path.
  - **Negate-guard recognition** (§QW-41 / §PR-1):
    `if (!ALLOW.has(x)) return;` (and `.includes`, `.test`,
    `.indexOf(...) === -1`, `!ALLOW[x]` shapes with early `return` /
    `throw` / `continue` / `break`) clears taint on `x` for code past
    the guard.
  - **`instanceof` receiver narrowing** (§QW-2 / §EN-12): inside an
    `if (handle instanceof Pool) { ... }` branch the SQL receiver check
    treats `handle` as DB-shaped if `Pool` / `PrismaClient` /
    `Sequelize` / `Database` / etc. tokenize to a known DB keyword.
  - Alias chains beyond depth 3 degrade to *weak taint* (reported at MEDIUM
    confidence).
  - `Object.assign(target, src)` marks `target` as weakly tainted —
    property accesses like `target.timeout` are not flagged.
  - Function summaries: same-file functions with `return <direct-source>`
    propagate taint through call sites.
  - Class receiver flow: tainted `this.X` props from a constructor are
    visible to sibling methods at MEDIUM confidence.

### Provenance / data-flow paths

When a taint finding is produced, the engine captures the symbol chain
that connects the source to the sink. This appears in:
- **JSON output** — `pathSteps: [{line, column, label, filePath}, …]`.
- **SARIF output** — emitted as `codeFlows` (compatible with GitHub Code
  Scanning's data-flow viewer).
- **VS Code panel** — rendered under each finding as an ordered list.

Example chain for `db.query("SELECT … " + sql)` where `sql = "…" + id`,
`id = req.body.id`:

```
1. line 1   — tainted source: 'req' parameter (assumed user-controlled)
2. line 2   — propagated: id = req.body.id
3. line 3   — propagated: sql = "SELECT … " + id
4. line 4   — sink: db.query
```

### Inter-procedural IFDS (Dart, `ifds-taint`)

In addition to the intra-procedural tracker above, Dart projects get a
second pass backed by a Reps-Horwitz-Sagiv tabulation IFDS solver. It
runs as stage-3 rule `ifds-taint` and reports `Tainted value flows into
sink '<name>' (IFDS)` at HIGH severity / HIGH confidence.

- **Inter-procedural and context-sensitive** via procedure summaries
  (path-edges keyed by entry fact, `pendingCallers` for late-summary
  propagation).
- **Branching CFG**: if/else, while, do-while, for-in, try/catch/finally
  (flattened — sound, occasionally over-approximates).
- **Strong kills** on clean reassignment; additive (augmented)
  assignment preserves taint.
- **Sources** (name-based heuristic): parameters named `userInput`,
  `input`, `req`, `request`, `payload`, `data`, `body`, `query`,
  `params`. Real HTTP / storage / SharedPreferences / stdin sources are
  not yet modeled — expect false negatives.
- **Sinks** are shared with the intra-procedural tracker (SQL, command,
  code, HTML).
- **Sanitizers** are shared too, and are unlabeled: any recognised
  sanitizer clears taint for any sink (conservative but imprecise).

The existing intra-procedural `InjectionRule` still runs; `ifds-taint`
complements it. Duplicate findings on the same line are de-duped by the
scanner.

### Confidence Levels

| Confidence | Source | Typical FP Rate |
|------------|--------|-----------------|
| **HIGH** | Confirmed taint flow to sink | <5% |
| **MEDIUM** | Structural AST pattern or indirect taint | 10–20% |
| **LOW** | Regex / entropy heuristic | Higher — informational |

## CLI Usage

### Dart CLI (regex-only, ships from the repo root)

The Dart CLI is the recommended path for scanning a Flutter + Supabase app from CI or a terminal without Node.js. It loads the project, runs the rule set in `lib/src/rules/`, and prints human-readable findings.

```bash
dart run fluttersupabasehelper              # scan the current directory
dart run fluttersupabasehelper ./my-project # scan a specific path
dart run fluttersupabasehelper --no-suggestions
```

Exit code `1` when any non-suggestion finding is reported, `0` otherwise — drop it straight into CI.

The Dart CLI does **not** perform AST parsing or taint tracking. It uses targeted regular expressions plus a small amount of statement-level context (nearest `.from(...)` call, nearby filter methods, comment-line heuristics). That keeps it fast (< 1 s on a typical Flutter repo) and hermetic, at the cost of missing data-flow vulnerabilities that only surface across multiple statements. For those, use the VS Code extension.

### Node CLI (ships with the VS Code extension)

```bash
npx flutter-supabase-helper scan ./my-project
npx flutter-supabase-helper scan . --pretty                 # human-readable
npx flutter-supabase-helper scan . --json                   # machine-readable (default)
npx flutter-supabase-helper scan . --summary                # counts only
npx flutter-supabase-helper scan . --sarif -o sast.sarif    # SARIF 2.1.0
```

### Output Formats

| Flag | Format | Use |
|------|--------|-----|
| `--json` (default) | Custom JSON, includes `pathSteps`, `cwe`, full ranges | Machine consumption |
| `--pretty` | Grouped human report with severity icons | Terminal |
| `--summary` | Counts only | Quick CI sanity check |
| `--sarif` | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) with `codeFlows`, per-rule CWE taxonomy, partialFingerprints | GitHub Code Scanning, GitLab, Azure DevOps |
| `--markdown` | Markdown table | PR comments and issues |
| `--csv` | RFC 4180 CSV | Spreadsheets and BI tools |
| `--junit` | JUnit XML | Jenkins, CircleCI, Buildkite |
| `--gitlab` | GitLab Code Quality JSON | GitLab merge request widgets |
| `--bitbucket` | Bitbucket Code Insights annotations | Bitbucket pull requests |
| `--html` | Self-contained HTML with severity/rule/file filters | CI artifacts and shareable reports |

### CI Integration

```yaml
# GitHub Actions — fail build + upload findings to Code Scanning
- name: SAST scan
  run: npx flutter-supabase-helper scan . --sarif -o sast.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: sast.sarif }
```

`--fail-on <level>` exits with code `1` when findings at or above the level
exist (`high|medium|low`).

`--fail-confidence <level>` adds a confidence gate. For example,
`--fail-on high --fail-confidence high` fails only on HIGH-severity,
HIGH-confidence findings, while still reporting lower-confidence results.

### PR-style scans (`--changed-since`)

```bash
npx flutter-supabase-helper scan . --changed-since main --sarif -o pr.sarif
```

Restricts findings to files modified since the given git ref (uses `git diff
--name-only <ref>...HEAD` plus `git status --porcelain` for uncommitted
work). Combine with `--fail-on high` for low-friction PR gating.

### SARIF diff mode (`--diff-against`)

```bash
npx flutter-supabase-helper scan . --sarif -o current.sarif
npx flutter-supabase-helper scan . --json --diff-against previous.sarif
```

Filters out findings whose SARIF partial fingerprint already appeared in an
older scan. This is useful for PR comments that should show only newly
introduced findings, while a full SARIF upload remains available for code
scanning dashboards.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: flutter-supabase-helper-sast
        name: Flutter Supabase Helper SAST
        entry: npx flutter-supabase-helper scan . --changed-since HEAD --fail-on high --fail-confidence high --summary
        language: system
        pass_filenames: false
```

`pass_filenames: false` is intentional: the scanner already computes changed
files via git, which keeps path handling consistent with CI.

### Husky + lint-staged

Same intent as pre-commit, expressed in the npm-native toolchain. After
`npx husky init`, drop this in `.husky/pre-commit`:

```sh
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npx lint-staged
```

…and configure `lint-staged` in `package.json`:

```jsonc
{
  "lint-staged": {
    // Run the SAST scan once per commit, ignoring filenames — the scanner
    // computes changed files itself and bails early when none are touched.
    // The trailing `[]` makes lint-staged skip its default per-file fan-out.
    "*": "bash -c 'npx flutter-supabase-helper scan . --changed-since HEAD --fail-on high --fail-confidence high --summary' --"
  }
}
```

Why `--changed-since HEAD`: lint-staged is invoked once per commit, but the
scanner is a project-wide tool. Letting it ask git for the staged diff
matches both the pre-commit and CI flows above and keeps the answer to
"what changed?" in one place.

### Baseline (suppress known issues)

```bash
npx flutter-supabase-helper baseline .            # snapshot current findings (v2 with content hashes)
npx flutter-supabase-helper scan . --baseline     # report only new findings
```

Baseline saved to `.sast-baseline.json`. v2 baselines store a content hash
of the ±2 lines around each finding so the match survives line shifts from
unrelated edits. v1 baselines (older format) still load — match falls back
to fingerprint.

### Per-rule disable

```bash
# CLI: comma-separated, repeatable
npx flutter-supabase-helper scan . --disable high-entropy-secret,file-upload-validation
```

Unknown rule codes produce a warning listing all valid codes (so typos
surface immediately).

```jsonc
// .vscode/settings.json
{
  "flutterSupabaseHelper.disabledRules": ["high-entropy-secret"],
  "flutterSupabaseHelper.scanOnSave": false
}
```

### Validation Harness

```bash
npx flutter-supabase-helper validate ./test_repos
```

Scans subdirectories and outputs per-rule precision statistics and
confidence distribution.

## Suppression

### Inline (statement-aware)

```js
// sast-ignore-next-line
const secret = "AKIA…";

// sast-ignore injection-flaw
db.query(
  "SELECT * FROM users WHERE id = " + id,   // multi-line wraps still suppressed
);

// Single comment ≠ wholesale silence:
// sast-ignore injection-flaw
db.query("ok"  + req.body.id);
db.query("FN"  + req.body.id);   // NOT suppressed — separate statement

// IFDS-confirmed taint can also be suppressed by code:
// sast-ignore ifds-taint
db.rawQuery(userInput);
```

The window is brace/paren-balanced and terminates at the first `;` or `}`,
so multi-line wraps work but two unrelated statements after one comment do
not get suppressed together.

### `.sastignore`

```
vendor/
*.min.js
fixtures
config/seeds.js
```

### `.gitignore`

The scanner also respects the root-level `.gitignore` during file traversal —
no need to duplicate `node_modules/`, `dist/`, `generated/`, etc. in
`.sastignore`.

## VS Code Extension

Activates automatically on project open.

| Command | Description |
|---------|-------------|
| `Flutter Supabase Helper: Scan Workspace` | Full project scan (multi-root aware) |
| `Flutter Supabase Helper: Scan Active File's Project` | Scan from active file |

**On-save scanning** (off by default) — set
`flutterSupabaseHelper.scanOnSave: true` in your settings to re-run the
scan 750 ms after any supported file is saved.

**Quick fixes** include real autofixes (not just TODO comments):
- `Math.random()` → `crypto.randomUUID()` or `crypto.randomBytes(16).toString('hex')`
- `algorithms: ['none']` → `algorithms: ['HS256']`
- `httpOnly: false` → `httpOnly: true`
- `secure: false` → `secure: true`
- `.innerHTML =` → `.textContent =`
- Simple `db.query("…" + ident)` → `db.query("…?", [ident])`
- Plus suppression comments for any finding

**Results panel** shows findings grouped by file or severity, clickable
file:line locations, AST/REGEX badges, CWE links to mitre.org, full
data-flow paths, scan stats, and an AST health warning if the parse failure
rate exceeds 20%. The webview is constructed via DOM API (zero `innerHTML`)
under a strict CSP (`script-src 'nonce-…'`).

## Performance

- Files > 1 MB skipped
- `.gitignore` honored during traversal (root-level)
- `node_modules`, `dist`, `build`, `.git`, etc. always excluded
- AST parsers cached per language; WASM grammars loaded lazily
- Rules within a stage execute concurrently via `Promise.all`
- Lock files, minified files, and docs excluded from entropy scanning
- Typically <100 ms for projects under 200 files

## Telemetry

Local-only. Stored under your platform's data directory:

| Platform | Path |
|----------|------|
| macOS    | `~/Library/Application Support/flutter-supabase-helper/telemetry.json` |
| Linux    | `$XDG_DATA_HOME/flutter-supabase-helper/telemetry.json` (or `~/.local/share/...`) |
| Windows  | `%LOCALAPPDATA%/flutter-supabase-helper/telemetry.json` |

Env-driven paths are validated to live under your home directory; suspicious
values fall through to a safer default.

## Limitations

- JS/TS taint is mostly intra-procedural. It has limited same-file helper
  summaries, but no whole-program or cross-file flow.
- Dart has an additional inter-procedural IFDS pass (`ifds-taint`), but
  its sources are still heuristic and it does not yet model every Dart
  language feature (`await`, cascade operators, named arguments,
  collection sensitivity, full virtual dispatch, implicit `this`, etc.).
- Python, Go, Java have AST grammars but limited source/sink coverage and
  no taint models.
- Non-Dart languages: no full CFG-based path-sensitive analysis. Top-level
  negate-guard barriers and dominating `instanceof` narrowing are
  recognized via AST pre-passes (§QW-41 / §QW-2); positive
  `if (allow.has(x)) sink(x)` guards and nested-block guards still defer
  to the §EN-4 work. Conditional reassignment to a sanitizer is
  conservatively *not* trusted, which biases toward false positives over
  false negatives.
- Framework modeling is still shallow. Express-style request fields and
  common response-body sinks are modeled, but route registration,
  middleware chains, and framework-specific lifecycle rules are not complete.
- Entropy detection is probabilistic — some benign strings flagged at LOW.
- Comment-based suppression can be added by anyone with commit access;
  CI policies should review/restrict suppression patterns.

## Building from source

This repo ships **three** independent components — each can be built standalone:

### 1. Rust analysis kernel (`engine/`)

The high-precision IFDS taint solver. It is currently experimental: the Rust
workspace builds and tests pass, but the Semgrep smoke-test rule still needs
work before this becomes the default scanner path.

```bash
# One-shot setup (detects + installs missing tools, with confirmation prompts)
./scripts/bootstrap.sh

# Or manually:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
source $HOME/.cargo/env
cd engine && cargo build --workspace --release
```

The binary lands at `engine/target/release/engine-cli`. Resolver helpers for
the TS extension and Dart `lib/` scanner live at
[vscode-extension/src/scanner/engineResolver.ts](vscode-extension/src/scanner/engineResolver.ts)
and [lib/src/engine/engine_resolver.dart](lib/src/engine/engine_resolver.dart);
full sidecar integration is still tracked in
[RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md) Phases 5 and 7.

The intended runtime behavior is a precise install hint when the binary is
missing, rather than a silent failure.

For build-from-source contributors: read [BLUEPRINT_RUST_ENGINE.md](BLUEPRINT_RUST_ENGINE.md) end-to-end before touching `engine/`. Track progress in [RUST_ENGINE_PROGRESS.md](RUST_ENGINE_PROGRESS.md).

### 2. TypeScript VS Code extension (`vscode-extension/`)

```bash
cd vscode-extension
npm install
npm run compile
```

Target release behavior after the Rust sidecar is wired: published `.vsix`
builds will include a prebuilt `engine-cli` binary, so end users do not need a
Rust toolchain. Until Phase 5 lands, contributors should build the engine from
source when testing Rust-backed analysis.

### 3. Dart `lib/` scanner (`lib/`)

```bash
dart pub get
dart run bin/fluttersupabasehelper.dart .
```

## Tests

```bash
npm run compile && npm test
```

Runs in order:
1. `precision-self-test.js` — end-to-end fixture sweep covering 17 rule
   interactions across JS / Dart / Python / test-path noise.
2. `taint-engine.test.js` — unit-style invariants for the
   `IntraProceduralTaintTracker` (source seeding, sink-specific
   sanitizer recognition, receiver heuristic incl. instanceof narrowing,
   sink kinds, reassignment, parameterization, negate-guard, all
   CWE-tagged rule quick wins, comment immunity, git porcelain regression,
   `Promise.all` concurrency stability).
3. `test-ast.js` — AST grammar load smoke test.
4. `ifds-self-test.js` — IFDS Dart taint engine fixtures (sources,
   sinks, sanitizers, inter-procedural propagation).

## Requirements

`web-tree-sitter@0.21.0` paired with `tree-sitter-wasms@0.1.13` (ABI 13).
