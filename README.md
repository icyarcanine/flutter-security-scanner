# Flutter Supabase Helper — Hybrid SAST Engine

A static application security testing (SAST) tool available as a VS Code extension and headless CLI. Detects security vulnerabilities, hardcoded secrets, and misconfigurations across multiple languages using a three-stage analysis pipeline.

## What It Detects

- **Injection flaws** — SQL injection, command injection, XSS, unsafe eval (source-to-sink taint confirmed)
- **Hardcoded secrets** — AWS keys, private keys, JWT tokens, high-entropy strings
- **Supabase misconfigurations** — missing RLS, insecure storage rules, committed `.env` files
- **Unsafe patterns** — sensitive logging, debug artifacts, client-side trust violations

## Supported Languages

| Tier | Languages | Analysis |
|------|-----------|----------|
| **Full** | JavaScript, TypeScript, Dart | Regex + AST + intra-procedural taint tracking |
| **AST** | Python, Go, Java | Regex + AST structural patterns |
| **Regex** | SQL, YAML, JSON, `.env` | Heuristic rules only |

## Analysis Pipeline

1. **Regex** — fast heuristic pass across all files
2. **AST** — selective parsing via `web-tree-sitter` WASM grammars
3. **Taint tracking** — intra-procedural data-flow analysis (JS, TS, Dart)

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

### Confidence Levels

| Confidence | Source | Typical FP Rate |
|------------|--------|-----------------|
| **HIGH** | Confirmed taint flow to sink | <5% |
| **MEDIUM** | Structural AST pattern or indirect taint | 10–20% |
| **LOW** | Regex / entropy heuristic | Higher — informational |

## CLI Usage

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

- Intra-procedural taint only — no cross-function or cross-file tracking
- Python, Go, Java have AST grammars but no taint models
- No control flow analysis (branches and loops not modeled)
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
