# Flutter Supabase Helper — Hybrid SAST Engine

A static application security testing (SAST) toolkit for Flutter + Supabase projects. The repository ships **two separate scanners** that share the same finding codes but run different engines:

| Component | Location | Engine | When to use it |
|-----------|----------|--------|----------------|
| **VS Code extension** | `vscode-extension/` | Regex **+** tree-sitter AST **+** taint tracking — intra-procedural for JS/TS/Dart, **inter-procedural IFDS for Dart** (TypeScript, Node.js, `web-tree-sitter@0.21.0`) | Day-to-day authoring — inline quick fixes, AST/REGEX badges, taint-confirmed findings |
| **Dart CLI** | `bin/fluttersupabasehelper.dart` | Regex-only, Flutter-/Supabase-specific rules (Dart) | CI gating on Flutter apps, headless scans, local `dart run` |

The Dart CLI deliberately **does not** use tree-sitter or taint tracking. It is a fast, zero-dependency lint pass that complements `dart analyze` with Flutter- and Supabase-specific checks (missing RLS awareness, committed `.env`, unobscured password fields, weak platform manifests, etc.). Everything under the "Analysis Pipeline", "Taint Model", and "Confidence Levels" sections below describes the **VS Code extension engine**, not the CLI.

## What It Detects

- **Injection flaws** — SQL injection, command injection, XSS, unsafe eval (source-to-sink taint confirmed, extension only)
- **Hardcoded secrets** — AWS keys, private keys, JWT tokens, high-entropy strings
- **Supabase misconfigurations** — missing RLS, insecure storage rules, committed `.env` files
- **Unsafe patterns** — sensitive logging, debug artifacts, client-side trust violations

## Supported Languages (VS Code extension)

| Tier | Languages | Analysis |
|------|-----------|----------|
| **Full** | JavaScript, TypeScript | Regex + AST + intra-procedural taint tracking |
| **Full (IFDS)** | Dart | Regex + AST + intra-procedural taint tracking + inter-procedural IFDS (`ifds-taint`) |
| **AST** | Python, Go, Java | Regex + AST structural patterns |
| **Regex** | SQL, YAML, JSON, `.env` | Heuristic rules only |

## Analysis Pipeline (VS Code extension)

1. **Regex** — fast heuristic pass across all files
2. **AST** — selective parsing via `web-tree-sitter` WASM grammars
3. **Taint tracking** — intra-procedural data-flow analysis (JS, TS, Dart), plus inter-procedural IFDS for Dart (`ifds-taint` rule)

### Taint Model

The taint tracker performs intra-procedural source-to-sink analysis with the following properties:

- **Sources**: `req.body/query/params`, `process.env/stdin`, `platform.environment`, controller `.text/.value`, seeded parameter names (`req`, `request`, `data`, `payload`, `userInput`)
- **Sinks**: SQL (`query`, `execute`, `raw`, `rawQuery`), command (`exec`, `spawn`, `system`), code (`eval`, `Function`), HTML (`innerHTML`, `outerHTML`, `document.write`)
- **Sanitizers**: escape/sanitize helpers, validation functions, parameterized queries automatically detected
- **Precision controls**:
  - Clean reassignment (`x = 42`) clears taint; augmented assignment (`x += value`) preserves it
  - Alias chains beyond depth 3 degrade to *weak taint* (reported at MEDIUM confidence)
  - `Object.assign(target, src)` marks `target` as weakly tainted — property accesses like `target.timeout` are not flagged
  - Function summaries: functions with bare `return param` propagate taint through call sites

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
npx flutter-supabase-helper scan . --pretty     # human-readable output
npx flutter-supabase-helper scan . --json        # machine-readable (default)
npx flutter-supabase-helper scan . --summary     # counts only
```

### CI Integration

```bash
# Fail build on any HIGH finding
npx flutter-supabase-helper scan . --fail-on high --summary
```

Exit code `1` when findings at or above the threshold exist.

```yaml
# GitHub Actions
- name: Security Scan
  run: npx flutter-supabase-helper scan . --fail-on high --summary
```

### Baseline (Suppress Known Issues)

```bash
npx flutter-supabase-helper baseline .          # snapshot current findings
npx flutter-supabase-helper scan . --baseline   # report only new findings
```

Baseline saved to `.sast-baseline.json`. Commit it to track known debt.

### Validation Harness

```bash
npx flutter-supabase-helper validate ./test_repos
```

Scans subdirectories and outputs per-rule precision statistics and confidence distribution.

## Suppression

### Inline

```js
// sast-ignore-next-line
const secret = "AKIA...";

// sast-ignore injection-flaw
db.query("SELECT * FROM users WHERE id = " + id);

// sast-ignore ifds-taint
db.rawQuery(userInput);
```

Supports `//` (JS/TS/Java/Go/Dart) and `#` (Python).

### .sastignore

```
vendor/
*.min.js
fixtures
config/seeds.js
```

## Extension Usage

Activates automatically on project open.

| Command | Description |
|---------|-------------|
| `Flutter Supabase Helper: Scan Workspace` | Full project scan |
| `Flutter Supabase Helper: Scan Active File's Project` | Scan from active file |

**Quick Fixes** are available for injection findings (parameterize query), `eval` (suggest `JSON.parse`), `innerHTML` (replace with `textContent`), and any finding (add suppression comment).

**Results panel** shows findings grouped by file or severity, clickable locations, AST/REGEX badges, scan stats, and an AST health warning if the parse failure rate exceeds 20%.

## Limitations

- JS/TS taint is intra-procedural only — no cross-function or cross-file
  tracking. Dart has an additional inter-procedural IFDS pass
  (`ifds-taint`).
- IFDS sources are a name-based heuristic; real HTTP / storage /
  SharedPreferences / stdin sources are not modeled yet. No taint
  labels — any sanitizer clears for any sink. No `await` / cascade /
  named arguments / field-sensitive / collection / implicit-`this`
  modeling. Virtual dispatch resolves by last-name only.
- Python, Go, Java have AST grammars but no taint models
- Non-Dart languages: no control flow analysis (branches and loops not
  modeled)
- Framework coverage limited to Express.js (`req.body/query/params`)
- Entropy detection is probabilistic — some benign strings flagged at LOW

## Performance

- Files > 1MB skipped
- `node_modules`, `dist`, `build`, `.git` excluded
- AST parsers cached per language; WASM grammars loaded lazily
- Lock files, minified files, and docs excluded from entropy scanning
- Typically < 100ms for projects under 200 files

## Requirements

`web-tree-sitter@0.21.0` paired with `tree-sitter-wasms@0.1.13` (ABI 13).
