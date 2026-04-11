# Flutter Supabase Helper — Hybrid SAST Engine

A static application security testing (SAST) tool built as a VS Code extension and headless CLI. Detects security vulnerabilities, hardcoded secrets, and misconfigurations across multiple languages.

## Supported Editors

| Editor | Status |
|--------|--------|
| **Visual Studio Code** | ✅ Full support |
| **Antigravity** (VS Code fork) | ✅ Compatible — uses only stable VS Code APIs |
| Any VS Code-compatible fork | ✅ Should work — graceful degradation if APIs missing |

The extension uses only stable, documented VS Code APIs. If a feature is unsupported in a fork (e.g., code actions), it degrades silently without crashing.

## What It Detects

- **Security vulnerabilities** — SQL injection, command injection, XSS, unsafe eval
- **Hardcoded secrets** — AWS keys, private keys, JWT tokens, high-entropy strings
- **Supabase misconfigurations** — missing RLS awareness, insecure storage rules, committed `.env` files
- **Code quality issues** — unsafe patterns and debug artifacts

## Supported Languages

| Tier | Languages | Analysis Depth |
|------|-----------|----------------|
| **1 — Full** | JavaScript, TypeScript | Regex + AST + Taint tracking |
| **2 — AST** | Python, Go, Java | Regex + AST structural patterns |
| **3 — Regex** | Dart, SQL, YAML, JSON, .env | Regex heuristics only |

## CLI Usage

The CLI is the core interface. All detection logic runs headlessly — the extension is a thin UI layer.

### Scan a Project

```bash
npx flutter-supabase-helper scan ./my-project
```

### Output Modes

```bash
npx flutter-supabase-helper scan . --json      # Machine-readable JSON (default)
npx flutter-supabase-helper scan . --pretty     # Human-readable, grouped by file
npx flutter-supabase-helper scan . --summary    # Compact summary only
```

### CI Integration

```bash
# Fail the build if any HIGH severity finding exists
npx flutter-supabase-helper scan . --fail-on high --summary

# Fail on MEDIUM or above
npx flutter-supabase-helper scan . --fail-on medium --json
```

Exit code is `1` if findings at or above the threshold are found. Use in CI pipelines:

```yaml
# GitHub Actions example
- name: Security Scan
  run: npx flutter-supabase-helper scan . --fail-on high --summary
```

### Baseline (Diff-Only Scans)

```bash
# Generate baseline from current findings
npx flutter-supabase-helper baseline .

# Future scans show only NEW findings
npx flutter-supabase-helper scan . --baseline --pretty
```

The baseline is saved to `.sast-baseline.json`. Commit it to your repository to track known issues.

### Validation Harness

```bash
npx flutter-supabase-helper validate ./test_repos
```

Scans all subdirectories and outputs rule performance statistics, per-repo breakdowns, and confidence distribution.

## Workflow Example

The ideal developer workflow integrates this tool from local development to CI/CD:

1. **Develop**: Write code in your editor. The extension provides real-time diagnostics via AST parsing.
2. **Fix**: Use the provided Quick Fixes (Code Actions) to instantly resolve common issues (e.g., parameterizing a SQL query).
3. **Suppress**: If a finding is a false positive, use `// sast-ignore-next-line` to locally suppress it.
4. **Baseline**: Before merging a large legacy codebase, run `npx flutter-supabase-helper baseline .` to acknowledge existing technical debt.
5. **CI Gate**: In your GitHub Actions, run `npx flutter-supabase-helper scan . --baseline --fail-on high` to fail the build *only* if new HIGH severity issues are introduced.
## Extension Usage

### Installation

Install the extension in VS Code or Antigravity. It activates automatically when a project is detected.

### Commands

| Command | Description |
|---------|-------------|
| `Flutter Supabase Helper: Scan Workspace` | Full project scan |
| `Flutter Supabase Helper: Scan Active File's Project` | Scan from active file's workspace |

### Quick Fixes (Code Actions)

When a finding has a diagnostic, you can apply quick fixes:

- **SQL injection** → inserts parameterized query TODO comment
- **eval()** → suggests JSON.parse or safe alternative
- **innerHTML** → replaces with `textContent`
- **Any finding** → inline suppression comment

### Webview Panel

The results panel shows:
- Findings grouped by **file** or **severity** (toggle via sidebar)
- Collapsible sections per group
- Clickable file locations (navigates to exact line)
- AST/REGEX badges per finding
- Scan performance stats (files, duration, AST rate)
- AST health warning banner (if failure rate > 20%)

## Suppression & Baseline

### Inline Suppression

Add a comment on the line before a finding to suppress it:

```js
// sast-ignore-next-line
const secret = "AKIA1234567890ABCDEF"; // suppressed

// sast-ignore injection-flaw
db.query("SELECT * FROM users WHERE id = " + id); // only injection suppressed
```

Supports `//` (JS/TS/Java/Go/Dart) and `#` (Python) comment styles.

### .sastignore File

Create a `.sastignore` file in the project root:

```
# Ignore entire directories
vendor/
generated/

# Ignore specific files
config/seeds.js

# Ignore by extension
*.min.js

# Ignore by directory name (matches anywhere in path)
fixtures
```

### Baseline

The baseline system tracks known findings so you only see new ones. See CLI Usage above.

## Why this tool is trustworthy

Unlike typical regex scanners that overwhelm you with false positives, this tool uses a **Hybrid Analysis Pipeline** (Regex + AST + Taint Tracking) to confirm vulnerabilities before flagging them.

### Confidence Model

Every finding includes a human-readable `confidenceReason` explaining *why* it was flagged.

| Confidence | Meaning | False Positive Rate |
|------------|---------|---------------------|
| **HIGH** | Confirmed source → sink taint flow | <5% |
| **MEDIUM** | Structural AST pattern match | 10-20% |
| **LOW** | Regex or entropy match | Higher — informational |

### Validation Approach
This engine is continuously validated against real-world vulnerable repositories (like OWASP WrongSecrets and Vuln-Bank). The included `validation harness` automatically measures true/false positive rates across thousands of files, ensuring that new rules do not introduce noise.

## Analysis Pipeline

1. **Stage 1 — Fast Scan**: Regex and heuristic rules on all files
2. **Stage 2 — AST Analysis**: Selective parsing via `web-tree-sitter` WASM grammars
3. **Stage 3 — Taint Tracking**: Intra-procedural data flow analysis

Files > 1MB are skipped. `node_modules`, `dist`, `build`, and `.git` directories are ignored. Lock files, documentation, and test fixtures are excluded from entropy scanning.

## AST Failure Handling

If WASM grammar loading or file parsing fails:

- The file is marked `astStatus: "failed"` with a reason
- Analysis continues using regex fallback rules at LOW confidence
- Failure is logged once per language
- AST success rate is displayed in CLI and webview

If `Parser.init()` fails globally, the scan aborts with a clear error.

## Limitations

- **Intra-procedural taint only.** No cross-function or cross-file tracking.
- **Partial multi-language AST.** Python, Go, Java have grammars but no taint models.
- **No control flow analysis.** Branches, loops, and returns not modeled.
- **Framework coverage.** Express.js `req.body/query/params` modeled. Other frameworks not yet.
- **Entropy is probabilistic.** Some non-secret strings may be flagged at LOW confidence.

## Performance

- Files > 1MB skipped
- AST parsers cached per language
- WASM grammars loaded lazily
- Lock files, minified files, docs excluded from entropy
- Rules execute sequentially — no unbounded parallelism
- Scan duration typically < 100ms for projects under 200 files

## Required Versions

The AST engine pairs `web-tree-sitter@0.21.0` with `tree-sitter-wasms@0.1.13` (ABI version 13).
