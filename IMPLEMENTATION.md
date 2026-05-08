# Implementation guide

This document describes how the scanner is built, where each piece lives,
and the contracts between layers. It is the canonical reference for anyone
extending the scanner — new rules, new sink kinds, new output formats — and
should be the first file an LLM agent reads after [README.md](README.md).

For the user-facing feature list, see [README.md](README.md).
For the history of changes that produced this state, see [PROGRESS.md](PROGRESS.md).

---

## 1. Repository layout

```
flutter-security-scanner/
├── vscode-extension/          ← canonical TypeScript implementation
│   ├── src/
│   │   ├── cli.ts                ← CLI entry point (`npx flutter-supabase-helper`)
│   │   ├── extension.ts          ← VS Code activation, commands, on-save
│   │   ├── codeActions.ts        ← Quick-fix providers
│   │   ├── baseline.ts           ← v2 baseline with content hashes
│   │   ├── suppression.ts        ← .sastignore + inline `// sast-ignore`
│   │   ├── noise.ts              ← non-production-path noise reduction
│   │   ├── ast/
│   │   │   ├── parser.ts            ← tree-sitter WASM init / per-language cache
│   │   │   └── traversal.ts         ← iterative walkAst, getCallName, etc.
│   │   ├── taint/
│   │   │   └── dataFlow.ts          ← IntraProceduralTaintTracker (1500 LOC)
│   │   ├── rules/
│   │   │   ├── rule.ts              ← Rule interface + RuleStage enum (required)
│   │   │   ├── ruleHelpers.ts       ← findingRangeFromNode, isCommentLine, etc.
│   │   │   ├── index.ts             ← buildDefaultRules() registry
│   │   │   ├── security/            ← 13 security rules
│   │   │   ├── config/              ← 6 config rules
│   │   │   ├── supabase/            ← 3 Supabase-specific rules
│   │   │   ├── secrets/             ← 1 secret-detection rule
│   │   │   └── bugs/                ← 1 bug rule (unsafe-eval)
│   │   ├── scanner/
│   │   │   ├── scanner.ts           ← ProjectScanner + ProjectScanReport
│   │   │   ├── projectContext.ts    ← file walker, .gitignore, lazy AST cache
│   │   │   ├── scannedFile.ts       ← ScannedFile with line offsets, AST status
│   │   │   └── mergeReports.ts      ← multi-root scan aggregation
│   │   ├── output/
│   │   │   └── sarif.ts             ← SARIF 2.1.0 serializer with codeFlows
│   │   ├── models/
│   │   │   └── finding.ts           ← Finding, PathStep, FindingSeverity, etc.
│   │   ├── diagnostics/
│   │   │   └── diagnosticsProvider.ts ← VS Code Diagnostic mapping
│   │   ├── webview/
│   │   │   └── panelProvider.ts     ← Results panel host
│   │   ├── commands/
│   │   │   ├── scanWorkspace.ts     ← Multi-root scan command
│   │   │   └── scanFile.ts          ← Active-file scan command
│   │   └── utils/
│   │       ├── shannon.ts           ← entropy + heuristic filters
│   │       └── pathUtils.ts         ← cross-platform path helpers
│   ├── media/                    ← webview HTML/CSS/JS (no innerHTML)
│   ├── scripts/                  ← test runners (run via `npm test`)
│   └── package.json
├── lib/                       ← Dart implementation (parity work in progress)
│   └── src/                      ← mirrors the TS structure for Dart projects
├── bin/fluttersupabasehelper.dart ← Dart CLI
├── test/                      ← Dart fixtures + integration tests
├── tool/                      ← validation harnesses (Dart + JS)
├── README.md                  ← user-facing
├── IMPLEMENTATION.md          ← THIS FILE
├── PROGRESS.md                ← change log / what landed when
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

The TypeScript path under `vscode-extension/` is **canonical** — the
published CLI and the VS Code extension both run that code. The Dart path
under `lib/` is a parallel implementation maintained for direct Dart
project use; it's behind the TS implementation in feature surface but has
its own taint engine, baseline support, and suppression handling.

---

## 2. Three-stage pipeline

```
┌──────────────────────────┐
│ ProjectContext.load()    │ ← file walk, .gitignore, lazy AST cache
└─────────────┬────────────┘
              │
       ┌──────▼──────────────────────┐
       │ Stage 1: RuleStage.fast    │ ← regex / heuristic, runs on every file
       │   - GenericSecretRule      │   (all stage rules execute concurrently
       │   - HardcodedSecretsRule   │    via Promise.all within the stage)
       │   - SensitiveLoggingRule
       │   - InsecureRandomRule
       │   - JwtMisuseRule
       │   - InsecureCookieRule
       │   - CorsMisconfigRule
       │   - …
       └──────┬─────────────────────┘
              │
       ┌──────▼──────────────────────┐
       │ Stage 2: RuleStage.ast     │ ← Tree-sitter AST patterns
       │   - XssRule                │   (parses each file once on demand;
       │   - UnsafeEvalRule         │    cached on ScannedFile.astNode)
       └──────┬─────────────────────┘
              │
       ┌──────▼──────────────────────┐
       │ Stage 3: RuleStage.taint   │ ← Source-to-sink data flow
       │   - InjectionRule          │   (uses IntraProceduralTaintTracker)
       └──────┬─────────────────────┘
              │
              ▼
     applySuppression → noise reduction → dedupe → sort
              │
              ▼
       ProjectScanReport
              │
       ┌──────┼──────┬───────────┬──────────┐
       │      │      │           │          │
   diagnostics WebView CLI/JSON  CLI/SARIF  Telemetry
                                 + codeFlows
```

Stages run **sequentially** because stage 3 depends on the AST cache
warmed by stage 2. Rules within a stage run **concurrently** via
`Promise.all` — they don't share writable state, and the AST cache is
mutate-on-first-touch with idempotent parsing, so concurrent first-touchers
converge on the same tree.

---

## 3. The Rule interface

```typescript
export enum RuleStage {
  fast = 1,    // regex / heuristic
  ast = 2,     // tree-sitter structural
  taint = 3,   // source-to-sink data flow
}

export interface Rule {
  readonly code: string;
  readonly stage: RuleStage;     // required, not defaulted
  evaluate(context: ProjectContext): Finding[] | Promise<Finding[]>;
}
```

`stage` is **required** at the type level. Rules that previously omitted
it would silently default to `fast`, which mis-bucketed AST-using rules
into the regex stage. The compiler now catches that.

### Adding a new rule

1. Create `src/rules/<category>/<ruleName>.ts`.
2. Implement `Rule`. Pick the right stage; emit `Finding` objects with
   `cwe` set when applicable.
3. Register in `src/rules/index.ts` inside `buildDefaultRules`.
4. Add a unit test in `scripts/taint-engine.test.js` (if taint-related)
   or extend `scripts/precision-self-test.js` (otherwise).

### Finding shape

```typescript
new Finding({
  category: FindingCategory.security,
  code: 'jwt-misuse',
  severity: FindingSeverity.high,
  confidence: FindingConfidence.high,
  message: '…',
  fix: '…',                        // shown to user; should be actionable
  risk: '…',                       // optional; explains *why* it matters
  filePath, line,                  // required for diagnostics
  column, endLine, endColumn,      // optional; from findingRangeFromNode(node)
  cwe: 'CWE-347',                  // single string or array
  pathSteps: [{line, label}, …],   // optional source-to-sink trace
  astUsed: true,                   // distinguishes AST findings from regex fallback
});
```

---

## 4. Taint engine (`taint/dataFlow.ts`)

A 1500-LOC intra-procedural source-to-sink tracker keyed off tree-sitter
ASTs. Reads ASTs that the rule pre-warmed by calling
`ProjectContext.getAst(file)`.

### Source taxonomy

| Tier | Names | When tainted |
|------|-------|--------------|
| **Strong** | `req`, `request`, `userInput` | Always — names that almost no helper function adopts by accident |
| **Heuristic** | `data`, `payload`, `input` | Only when the function also has a `res`/`response`/`next`/`reply`/`ctx` sibling parameter (Express handler shape) |
| **Direct expressions** | `req.body.x`, `request.query.x`, `process.env`, `process.stdin`, `platform.environment`, `request.args/form/values/json/cookies/headers/files/data`, `request.query_params/path_params`, `controller.text/.value` | Always when accessed |
| **Destructured** | `({ query, body, params, headers, cookies, … })` | When destructuring slot exposes a known request field name |

Direct sources match both dot-notation and bracket-notation, with
optional-chaining (`?.`) treated like `.`.

### Sanitizers

Sanitization is split into **full-spectrum** sanitizers (clear taint for
every modeled sink kind) and **sink-specific** sanitizers (clear taint
only for the kinds they actually defend against — §QW-1 / §PR-6).

Full-spectrum, all symbol-side (mark the LHS as sanitized so subsequent
references are clean):

- **`NUMERIC_COERCION_PATTERN`** — `parseInt`, `parseFloat`,
  `Number`, `Number.parseInt`, `Number.parseFloat`, plus the unary `+x`,
  `~~x`, `x | 0`, `x >>> 0` idioms. Output is a `number` and can't carry
  SQL / shell / template / HTML payloads.
- **`VALIDATION_NAME_PATTERN`** — `validate`, `validated`, `assertValid`,
  `assertSafe`, `ensureValid`, `safeParse`, `schema.parse`, etc. Treated
  as full sanitizers because validation typically asserts structure.
- **`SANITIZER_NAME_PATTERN`** generic catch-all — `sanitize`, `escape`,
  `clean`, `normalize` (when none of the more-specific patterns below
  match). Treated conservatively as full coverage to avoid regressing
  user-defined `sanitize` helpers.
- **Sanitizing-replace recognizer** — `x.replace(/[^a-z0-9_-]/g, '')`-shape
  allowlist-stripping calls; output drops any chars outside the literal
  whitelist class.

Sink-specific (`SINK_SPECIFIC_SANITIZERS` registry, ordered most-specific-
first so generic patterns don't shadow them):

| Pattern | `sanitizesFor` |
|---------|----------------|
| `escapeHtml` / `encodeHTML` / `sanitizeHtml` | `html` |
| `dompurify.sanitize` | `html` |
| `validator.escape` | `html` |
| `encodeURI` / `encodeURIComponent` | `url`, `redirect`, `header` |
| `escapeSql` | `sql` |
| `sqlstring.escape` / `mysql.escape` / `pg.escape` | `sql` |
| `escapeShell` / `shellEscape` | `command` |

Two state slots track per-symbol coverage on assignment:

- **`state.sanitized: Set<string>`** — fully sanitized; sink check at any
  kind sees it as clean. `_expressionTaintStrength` short-circuits on
  this set.
- **`state.sanitizedFor: Map<string, Set<SinkKind>>`** — partial coverage.
  Does **not** short-circuit `_expressionTaintStrength` (so a partial
  sanitizer flowing into a mismatched sink still flags); consulted by
  `_isSanitizedSinkCall` at sink time, which walks compound args
  (`"WHERE id=" + safe`) leaf-by-leaf and only suppresses when every
  tainted leaf is sanitized for the actual sink kind. `escapeHtml(taint)`
  flowing into `db.query` flags HIGH; `sqlstring.escape(taint)` flowing
  into the same sink suppresses correctly.

Parameterized SQL queries are recognized at the call level —
`db.query("…", [args])` is treated as sanitized regardless of the
argument's taint state.

### Sinks

| Kind | CWE | Method names / shapes |
|------|-----|------------------------|
| `sql` | CWE-89 | `query`, `execute`, `executequery`, `executemany`, `executescript`, `raw`, `rawquery`. Bare names require **either** a DB-shaped receiver **or** a SQL keyword in a string literal in the first arg. |
| `command` | CWE-78 | `exec`, `execsync`, `execfile`, `spawn`, `system`, `popen`, `os.system`, `os.popen`, `subprocess.run/call/check_output/popen`, `process.run/start` |
| `code` | CWE-95 | `eval`, `Function`, `setTimeout`/`setInterval` (string arg), `pickle.loads`, `marshal.loads`, `yaml.load`/`yaml.unsafe_load`/`yaml.full_load` |
| `html` | CWE-79 | `innerHTML`/`outerHTML` assignment, `document.write`, `dangerouslySetInnerHTML` (JSX) |
| `template` | CWE-1336 | `render_template_string`, Jinja `from_string`/`template` |
| `url` | CWE-918 | `fetch`, `axios.*`, `http(s).get/request`, `requests.*`, `urllib.urlopen` |
| `path` | CWE-22 | `fs.readFile/writeFile/...` (Node) |
| `redirect` | CWE-601 | `res.redirect`, `res.location` |
| `nosql` | CWE-943 | Mongo `find`/`update`/etc. with `$where`/`$function`/`$accumulator` operators |
| `xpath/ldap` | CWE-89-family | `xpath.evaluate`, `selectSingleNode`, `ldap.search`, `*.search_s` |

### SQL receiver heuristic

To avoid flagging every `query()`/`execute()` call, the engine inspects
the receiver:

```typescript
private _receiverLooksLikeDb(fullName: string): boolean {
  // Strip method name and trailing `()`.
  // Tokenize on non-alphanumeric AND camelCase boundaries.
  // Match any token (case-insensitively) against DB_RECEIVER_KEYWORDS.
}
```

`DB_RECEIVER_KEYWORDS` covers: `db`, `database`, `sqlite[3]`, `conn`,
`connection`, `client`, `pool`, `cursor`, `tx`, `txn`, `batch`, `knex`,
`pg`, `postgres[ql]`, `mysql`, `mssql`, `oracle`, `sequelize`, `prisma`,
`drizzle`, `orm`, `stmt`, `statement`, `mariadb`, `sqlserver`, `redshift`,
`cockroach`, `planetscale`, `neon`, `libsql`, `turso`.

Examples that match: `db.query`, `myDb.query`, `dbClient.query`,
`getDb().query`, `pgPool.query`, `prismaClient.query`, `this._db.query`.
Examples that don't (correct rejections): `analytics.query(event)`,
`description.query()`.

When the receiver doesn't match, two fallbacks fire:

1. The first argument is walked looking for a SQL keyword (`SELECT`,
   `INSERT INTO`, `UPDATE`, `DELETE FROM`, `CREATE TABLE`, `DROP TABLE`,
   `ALTER TABLE`, `MERGE`, `TRUNCATE`) — covers `query("SELECT ..." + x)`
   where the receiver is generic but the SQL is unambiguous.
2. **§QW-2 / §EN-12** — `_findEnclosingInstanceofNarrowings` walks
   parents from the call looking for an `if (receiver instanceof T)`
   guard whose consequence contains the call (and joined `&&` clauses).
   When `T` tokenizes to a `DB_RECEIVER_KEYWORDS` entry — `Pool`,
   `PgPool`, `PrismaClient`, `Sequelize`, `Database`, `MariaDBConnection`,
   etc. — the call resolves as `sql` even when the receiver name itself
   doesn't match. Approximates the dominator-aware narrowing §EN-4
   would provide. Else-branch / `||` joinings are intentionally
   excluded — they don't establish the narrowing for the main branch.

### Negate-guard recognition (§QW-41 / §PR-1)

`_collectNegateGuards(scope)` runs as a pre-pass during scope seeding.
It walks the function body's top-level statements (siblings of the body
block; nested blocks defer to §EN-4's CFG) looking for early-exit
allowlist barriers:

- `if (!ALLOW.has(x)) return;` / `throw` / `continue` / `break`
- `if (!validHosts.includes(x)) ...` (and the `.indexOf(x) === -1` shape)
- `if (!regex.test(x)) ...`
- `if (!ALLOW.hasOwnProperty(x)) ...`
- `if (!ALLOW[x]) ...` (object-key negation)

Recognized symbols populate `ScopeState.negateGuardedAfter:
Map<symbol, line>`, where `line` is the first guaranteed-clean line past
the if-statement's end. Both `_expressionTaintStrength` and the sink-call
leaf walk (`_allTaintedLeavesSanitizedForKind`) treat the symbol as
fully sanitized when the consuming node's line is past the guard. Sinks
**before** the guard (or inside the guard's body) still fire.

### Confidence model

A taint chain is `direct` or `indirect`:

- **`direct`** — confirmed source access: symbol in tainted set, recognized
  direct-source expression, or intra-file function summary returning a
  direct source.
- **`indirect`** — taint passes through a wrapper: weakTainted symbol,
  object literal containing tainted values, `Object.assign`-mutated target,
  class receiver flow.

Direct chains produce HIGH severity / HIGH confidence; indirect chains
produce MEDIUM / MEDIUM. Alias chains beyond `MAX_TAINT_DEPTH = 3` degrade
from direct to indirect to keep precision high on long re-assignments.

Conditional sanitization (`if (cond) x = sanitize(...)`) does **not**
promote the symbol to sanitized. The engine refuses to trust a sanitization
that may not execute on every reachable path. Augmented assignment
(`x += y`) preserves taint on the LHS.

### Provenance / data-flow paths

Each tainted symbol carries a `provenance: TaintProvenanceStep[]` chain
populated as taint propagates:

```typescript
// At source seeding (e.g. `function f(req, db)` ):
provenance.set('req', [{
  line: scopeStartLine,
  label: "tainted source: 'req' parameter (assumed user-controlled)",
}]);

// At each tainted assignment:
state.provenance.set(target, [
  ...rhsProvenance,
  { line: assignLine, label: `propagated: ${assignText}` },
]);
```

When a sink fires, `buildPathSteps(node, sinkName, state)` finds the first
tainted argument, copies its chain, and appends the sink as the final step.
The result is attached to the user-visible `Finding.pathSteps` and
serialized to SARIF as `codeFlows[0].threadFlows[0].locations[]` —
GitHub Code Scanning's data-flow viewer renders this directly.

Example for `db.query("SELECT … " + sql)` where `sql = "…" + id`,
`id = req.body.id`:

```
1. line 1 — tainted source: 'req' parameter (assumed user-controlled)
2. line 2 — propagated: id = req.body.id
3. line 3 — propagated: sql = "SELECT … " + id
4. line 4 — sink: db.query
```

---

## 5. ProjectContext

`ProjectContext.load(rootPath, onProgress?)` walks the file tree
producing `ScannedFile[]`:

- **File filter:** extension allowlist (`.dart`, `.yaml`, `.yml`, `.sql`,
  `.md`, `.txt`, `.json`, `.js`, `.jsx`, `.ts`, `.tsx`, `.py`, `.go`,
  `.java`) plus special-case `.gitignore` and `.env*`.
- **Hardcoded ignores:** `.dart_tool`, `.git`, `.idea`, `.vscode`, `build`,
  `coverage`, `dist`, `node_modules`, `Pods`.
- **`.gitignore`:** root-level `.gitignore` is parsed at scan start; matching
  directories AND files are skipped during walk. Negation patterns (`!foo`)
  use last-match-wins, mirroring git semantics.
- **Size cap:** files > 1 MB are silently skipped.
- **Progress:** `onProgress(filesLoaded)` fires every 50 files.
- **AST:** `ScannedFile.astStatus` is `'skipped'` until a rule calls
  `getAst(file)`, which lazily parses on first access. Result is cached on
  `ScannedFile.astNode`.

Lazy properties on `ProjectContext` cache expensive computed sets:
`envEntries`, `tableAccesses`, `storageBucketUses`, `uploadCalls`,
`supabaseClientLocations`, `ddlMetadata`, `rlsEvidenceLevel`. `ddlMetadata`
parses committed SQL migrations for owner columns, per-table RLS enablement,
and `CREATE POLICY ... FOR <operation>` coverage. Each property is computed
once on first read.

---

## 6. Output formats

### JSON (default, `--json` or no flag)

Custom shape with full range info, CWE, pathSteps, AST flag.

```json
{
  "target": "/abs/path",
  "stats": { "totalFiles": 234, "high": 3, "medium": 1, "low": 0,
             "scanDurationMs": 412, "astSuccessRate": 100 },
  "findings": [{
    "severity": "high", "confidence": "high",
    "code": "injection-flaw", "cwe": "CWE-89",
    "message": "…", "fix": "…", "risk": "…",
    "filePath": "src/api.js",
    "line": 5, "column": 10, "endLine": 5, "endColumn": 23,
    "astUsed": true,
    "pathSteps": [
      { "line": 1, "label": "tainted source: 'req' parameter", "filePath": "src/api.js" },
      { "line": 5, "column": 10, "label": "sink: db.query", "filePath": "src/api.js" }
    ]
  }]
}
```

### SARIF 2.1.0 (`--sarif`)

Standard format consumed by GitHub Code Scanning, GitLab, Azure DevOps,
and most enterprise dashboards. Implementation in [`output/sarif.ts`](vscode-extension/src/output/sarif.ts).

Key features:
- **Per-rule descriptors** with `properties.cwe` aggregating ALL CWE codes
  the rule has emitted (sorted, deduped). For `injection-flaw` this often
  includes `["CWE-78", "CWE-89", "CWE-918"]`.
- **`codeFlows`** populated from `Finding.pathSteps` — the data-flow view
  in GitHub Code Scanning renders these directly.
- **`partialFingerprints.primaryLocationLineHash`** for cross-run dedupe
  even when line numbers shift.
- **`originalUriBaseIds.SRCROOT`** so paths are portable (GitHub rewrites
  them relative to the repo root automatically).
- **No external dependency** — the schema is built from plain TypeScript
  interfaces; no `sarif` npm package required.

### Pretty (`--pretty`)

Human-readable terminal output grouped by severity with icons, fix
suggestions, and confidence reasons.

### Summary (`--summary`)

Counts only — useful for quick CI sanity checks.

---

## 7. CI integration

### `--fail-on <level>`

Exits 1 when findings at or above the level (`high|medium|low`) exist.

### `--changed-since <git-ref>` (PR-style)

Restricts findings to files modified since the ref:

```bash
npx flutter-supabase-helper scan . --changed-since main --sarif -o pr.sarif --fail-on high
```

Implementation: runs `git diff --name-only <ref>...HEAD` plus
`git status --porcelain` (for uncommitted work) and filters findings to
files in the resulting set. Falls back to full output with a stderr
warning when git fails.

### Baseline v2

Snapshots current findings; future scans only show NEW findings.

```bash
npx flutter-supabase-helper baseline .       # writes .sast-baseline.json (v2)
npx flutter-supabase-helper scan . --baseline
```

v2 baselines store a SHA-1 hash of the ±2 lines around each finding
(whitespace-normalized). Match strategy: contextHash → fingerprint
fallback. Survives line shifts from unrelated edits but still detects
meaningful local changes.

v1 baselines (older format) still load — they fall back to fingerprint
match transparently.

### Per-rule disable

```bash
# CLI
--disable injection-flaw,high-entropy-secret

# VS Code settings.json
"flutterSupabaseHelper.disabledRules": ["injection-flaw"]
```

Unknown rule codes produce a warning listing all valid codes (typos
surface immediately).

---

## 8. Suppression

### Inline (statement-aware)

```js
// sast-ignore-next-line
db.query("..." + x);

// sast-ignore injection-flaw
db.query(
  "SELECT * FROM users WHERE id = " + id,    // multi-line wraps suppressed
);
```

Window is brace/paren/bracket/string-balanced. Starts at the first
non-blank, non-comment line below the directive; extends through any
continuation lines until brackets balance AND a line ends with `;` or
`}`. Hard-capped at 8 lines. Two unrelated statements on adjacent lines
are NOT both suppressed by a single comment.

### `.sastignore`

```
vendor/
*.min.js
fixtures
config/seeds.js
```

Path patterns evaluated by `applySuppression` in [`suppression.ts`](vscode-extension/src/suppression.ts).

### `.gitignore`

The scanner respects the root-level `.gitignore` during file traversal —
no need to duplicate `node_modules/`, `dist/`, `generated/` in
`.sastignore`.

---

## 9. VS Code extension

### Commands

| Command | Behavior |
|---------|----------|
| `flutter-supabase-helper.scanWorkspace` | Iterates all workspace folders, scans each, merges via `mergeReports.ts`, sets diagnostics, opens results panel. Cancellable through the progress notification. |
| `flutter-supabase-helper.scanFile` | Scans the active file's project root. |

### On-save scanning (opt-in)

Setting `flutterSupabaseHelper.scanOnSave: true` triggers a debounced
(750 ms) scanWorkspace whenever a supported-language file is saved.

### Status bar

`$(shield) Scan` button on the left status bar. Shows for any of:
`dart`, `javascript`, `javascriptreact`, `typescript`, `typescriptreact`,
`python`, `go`, `java`. Click to scan.

### Quick fixes (real edits, not placeholder comments)

| Rule | Quick-fix action |
|------|------------------|
| `injection-flaw` (simple shape) | `db.query("…" + ident)` → `db.query("…?", [ident])` |
| `xss-flaw` | `.innerHTML =` → `.textContent =` |
| `insecure-random` | `Math.random()` → `crypto.randomUUID()` (when chained with `.toString(36).slice(...)`) or `crypto.randomBytes(16).toString('hex')` |
| `insecure-cookie` | `httpOnly: false` → `true`; `secure: false` → `true` |
| `jwt-misuse` | `algorithms: ['none']` → `algorithms: ['HS256']` |
| Any | Add `// sast-ignore <code>` suppression comment |

Rules without a safe automatic rewrite (`unsafe-eval`, complex SQL
concatenation, `jwt.decode`) deliberately offer **no** quick-fix beyond
suppression — the rule's `fix` text already explains the manual
replacement.

### Webview

`media/webview.{html,css,js}`. Built without `innerHTML` — every render
goes through a small `el(tag, attrs, ...children)` DOM helper that
auto-escapes text content and forbids HTML-string concatenation.

CSP: `default-src 'none'; style-src 'nonce-…'; script-src 'nonce-…'`. No
inline event handlers (`onclick=`, `onerror=`, etc.) anywhere — all
listeners attached via `addEventListener`.

Renders for each finding:
- Severity / confidence / category badges
- AST or REGEX detection-source badge
- Clickable `file:line` location (posts `openFile` message back to host)
- Fix, Risk, CWE links to mitre.org, full data-flow path, "Why HIGH?"
  toggle

---

## 10. Telemetry

Local-only. No data ever leaves the machine.

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/flutter-supabase-helper/telemetry.json` |
| Linux | `$XDG_DATA_HOME/flutter-supabase-helper/telemetry.json` (or `~/.local/share/...`) |
| Windows | `%LOCALAPPDATA%/flutter-supabase-helper/telemetry.json` |

`XDG_DATA_HOME` and `LOCALAPPDATA` are validated to live under HOME before
use; suspicious values fall through to the platform default. Containers
without HOME fall through to a cwd-relative hidden dir; failures are
swallowed silently (telemetry is never load-bearing).

The file keeps the last 50 scan summaries (timestamp, file count, finding
counts by severity, duration, AST success rate).

---

## 11. Test plan

Run with `npm test` from `vscode-extension/`:

| Test | Coverage |
|------|----------|
| `scripts/precision-self-test.js` | End-to-end fixture sweep: 17 assertions covering JS injection / Dart taint / dynamic vs confirmed flow / test-path noise reduction / dedupe / placeholder filtering. |
| `scripts/taint-engine.test.js` | 14 unit-style invariants for `IntraProceduralTaintTracker`: source seeding (strong vs heuristic), sanitizers, SQL receiver heuristic (camelCase, getDb(), analytics rejection), sink kinds with CWE, reassignment, augmented assignment, parameterized queries. |
| `scripts/test-ast.js` | Smoke test that JS, Dart, Python, Go, Java grammars load and produce trees. |

Add new assertions to whichever script fits (taint-engine for taint
behavior, precision-self-test for end-to-end rule interactions, test-ast
for new grammars).

The Dart side has its own test fixtures under `test/fixtures/` and a Dart
integration harness (`test/scanner_test.dart`); run via `dart test`.

---

## 12. Performance

- Files > 1 MB skipped at the walker.
- `node_modules`, `dist`, `build`, `.git`, `.dart_tool`, `coverage`,
  `Pods`, `.idea`, `.vscode` always excluded.
- `.gitignore` honored at traversal time.
- AST parsers cached per language; WASM grammars loaded lazily on first
  matching extension.
- Lock files / minified files / docs excluded from entropy scanning.
- `walkAst` is iterative (explicit stack) with `MAX_AST_WALK_DEPTH = 8000`
  cap — minified single-line files no longer blow Node's stack.
- Rules within a stage execute concurrently via `Promise.all`.
- Typical performance: <100 ms for projects under 200 files.

---

## 13. Architectural decisions / non-goals

**No inter-procedural taint.** Function summaries handle the simple case
(`function f(x) { return x.body.id; }`) but cross-function aliases,
callbacks, and closures are explicitly out of scope. Adding this is a
multi-day effort with substantial risk of FP regressions.

**No CFG-based path-sensitive analysis.** Conditional sanitizations are
conservatively NOT trusted (the engine refuses to mark a variable as
sanitized when the sanitization happens inside an if-branch). This biases
toward FPs over FNs — acceptable because users can suppress, but they
can't easily un-miss a vulnerability the tool didn't flag.

**No custom user-defined rules.** Adding YAML/JSON rule loading is a
backlog item. Today, project-specific patterns require forking and
editing TypeScript.

**Two implementations (TS + Dart).** The TS implementation under
`vscode-extension/` is canonical. The Dart one under `lib/` exists for
direct Dart project use and has been brought toward parity with baseline
support, suppression, and its own taint engine — but the TS engine is
ahead in feature surface (10 sink kinds vs 4, codeFlows, SARIF, etc.).
Consolidation is a future strategic decision.

---

## 14. Coding conventions

- **TypeScript strict mode:** `strict`, `noImplicitAny`, `strictNullChecks`,
  `noUnusedLocals`, `noUnusedParameters` all on. Unused parameters that
  must remain (interface signatures, vscode callbacks) get a `_` prefix.
- **Comments:** code comments explain *why*, not *what*. Public functions
  carry JSDoc explaining trade-offs and edge cases.
- **No `innerHTML` in webview:** ever. Use `el(tag, attrs, ...children)`
  from `media/webview.js`.
- **No `// TODO:` placeholders in shipped code.** If a feature isn't
  ready, either ship it or don't include the code path.
- **CWE on every security finding.** Use the table above; fall back to
  `CWE-74` only if no specific CWE applies.
- **Stage marker required on every rule.** Defaulting to `fast` was a
  footgun and is now a compile error.
