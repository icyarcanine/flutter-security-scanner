# Flutter Supabase Helper — Hybrid SAST Engine

A static application security testing (SAST) tool available as a VS Code
extension and a headless CLI. Detects security vulnerabilities, hardcoded
secrets, and misconfigurations across multiple languages using a three-stage
analysis pipeline.

**Production features:** SARIF 2.1.0 output, CWE taxonomy, data-flow paths
in findings, AST-aware inline suppressions, content-hash baselines, git diff
mode for PR-style scans, parallel rule execution, multi-root workspaces,
on-save scanning, per-rule disable, statement-aware suppression boundary,
and 14 unit-tested taint engine invariants.

## What It Detects

- **Injection flaws** — SQL injection, command injection, code execution,
  XSS, path traversal, SSRF, open-redirect, LDAP/XPath, NoSQL `$where`,
  template injection, deserialization (source-to-sink taint confirmed)
- **Hardcoded secrets** — AWS keys, private keys, JWT tokens, hardcoded
  Supabase anon keys, high-entropy strings
- **JWT misuse** — `jwt.decode` without verify, `algorithms: ['none']`,
  hardcoded HMAC secrets (incl. file-local variable tracking)
- **Insecure cookies** — `httpOnly: false`, `secure: false`,
  `sameSite: 'none'` without secure
- **CORS misconfiguration** — wildcard origin + credentials, `cors({ origin: true, credentials: true })`,
  origin reflection
- **Insecure randomness** — `Math.random()` for security-sensitive values
- **Supabase misconfigurations** — missing RLS, insecure storage rules,
  committed `.env` files, public buckets, multiple clients, improper init
- **Unsafe patterns** — sensitive logging, debug artifacts, client-side
  trust violations, missing upload validation

Every finding carries a CWE identifier (e.g. `CWE-89` SQL injection,
`CWE-78` command, `CWE-918` SSRF, `CWE-79` XSS, `CWE-338` insecure random,
`CWE-347` JWT, `CWE-942` CORS, `CWE-798` hardcoded credentials).

## Supported Languages

| Tier | Languages | Analysis |
|------|-----------|----------|
| **Full** | JavaScript, TypeScript, JSX, TSX, Dart | Regex + AST + intra-procedural taint tracking |
| **AST** | Python, Go, Java | Regex + AST structural patterns |
| **Regex** | SQL, YAML, JSON, `.env` | Heuristic rules only |

## Analysis Pipeline

1. **Regex** — fast heuristic pass across all files
2. **AST** — selective parsing via `web-tree-sitter` WASM grammars
3. **Taint tracking** — intra-procedural data-flow analysis with provenance
   capture (JS, TS, Dart)

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
    `dangerouslySetInnerHTML` — `CWE-79`.
  - URL/SSRF — `fetch`, `axios.*`, `http.get`, `requests.*`,
    `urllib.urlopen` — `CWE-918`.
  - Path — `fs.readFile/writeFile/...` — `CWE-22`.
  - Redirect — `res.redirect`, `res.location` — `CWE-601`.
  - NoSQL — Mongo `find`/`update`/etc. with `$where`/`$function`/
    `$accumulator` operators — `CWE-943`.
  - Template/SSTI — `render_template_string`, Jinja `from_string` — `CWE-1336`.
  - LDAP/XPath — `ldap.search`, `xpath.evaluate` — `CWE-89` family.
- **Sanitizers**:
  - Name-pattern: `sanitize/escape*/encodeURI*/dompurify.sanitize/encodeHTML/clean/normalize/validator.escape`.
  - Validators: `validate/assertValid/ensureSafe/schema.parse/safeParse/...`.
  - Numeric coercion: `parseInt`, `parseFloat`, `Number.parseInt`,
    `Number.parseFloat` — separated into a documented bucket because the
    return type (number) cannot carry SQL/shell/template payloads.
  - Parameterized queries — recognized at the call level (second arg is
    `[…]`/`{…}`/`(…)` or matches `params/values/bindings/parameters`).
- **Precision controls**:
  - Clean reassignment (`x = 42`) clears taint; augmented assignment
    (`x += value`) preserves it.
  - Conditional sanitization (`if (cond) x = sanitize(...)`) does **not**
    promote a variable to sanitized — the engine refuses to trust a
    sanitization that may not execute on every path.
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

### Confidence Levels

| Confidence | Source | Typical FP Rate |
|------------|--------|-----------------|
| **HIGH** | Confirmed taint flow to sink | <5% |
| **MEDIUM** | Structural AST pattern or indirect taint | 10–20% |
| **LOW** | Regex / entropy heuristic | Higher — informational |

## CLI Usage

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

### PR-style scans (`--changed-since`)

```bash
npx flutter-supabase-helper scan . --changed-since main --sarif -o pr.sarif
```

Restricts findings to files modified since the given git ref (uses `git diff
--name-only <ref>...HEAD` plus `git status --porcelain` for uncommitted
work). Combine with `--fail-on high` for low-friction PR gating.

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

- Intra-procedural taint only — no cross-function or cross-file tracking
- Python, Go, Java have AST grammars but limited source/sink coverage
- No CFG-based path-sensitive analysis (conditional sanitization is
  conservatively *not* trusted, which biases toward false positives over
  false negatives)
- Comment-based suppression can be added by anyone with commit access; CI
  policies should review/restrict suppression patterns

## Tests

```bash
npm run compile && npm test
```

Runs in order:
1. `precision-self-test.js` — end-to-end fixture sweep covering 17 rule
   interactions across JS / Dart / Python / test-path noise.
2. `taint-engine.test.js` — 14 unit-style invariants for the
   `IntraProceduralTaintTracker` (source seeding, sanitizer recognition,
   receiver heuristic, sink kinds, reassignment, parameterization).
3. `test-ast.js` — AST grammar load smoke test.

## Requirements

`web-tree-sitter@0.21.0` paired with `tree-sitter-wasms@0.1.13` (ABI 13).
