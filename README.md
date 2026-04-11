Flutter Supabase Helper — Hybrid SAST Engine

A high-performance, hybrid Static Application Security Testing (SAST) engine optimized for Flutter and Supabase** ecosystems. Functioning as a multi-language security analyzer, it is available as a headless Command Line Interface (CLI) and a native VS Code Extension.

How It Works
Unlike traditional security scanners that rely exclusively on noisy regex patterns, this engine utilizes a refined three-stage pipeline to ensure precision:

1.  Regex Pre-filters: Rapidly identifies high-entropy API keys, database secrets, and common Supabase configuration leaks.
2.  AST Parsing: Utilizes `web-tree-sitter` to physically analyze the Abstract Syntax Tree of **Dart**, TypeScript, JavaScript, Python, and Go.
3.  Taint Tracking: Performs intra-procedural flow analysis to verify if risky user inputs reach dangerous execution sinks (e.g., `eval()`, unparameterized queries, or insecure storage).

This hybrid approach drastically reduces false positives. Every finding provides a `HIGH`, `MEDIUM`, or `LOW` confidence metric accompanied by a human-readable explanation of the vulnerability logic.

Key Features
1. Cross-Editor Reliability: Engineered for VS Code and high-performance forks. Missing APIs degrade gracefully to ensure scanning never interrupts the developer workflow.
2. CI/CD Integration: Seamlessly integrates into build gates via `--fail-on high` with support for machine-readable JSON or pretty-printed summaries.
3. Smart Suppressions: Manage legacy codebases using `.sastignore` files, inline `// sast-ignore` flags, and automated diff-scanning via `.sast-baseline.json`.
4. Proactive Remediation: The VS Code extension provides real-time diagnostics, an interactive dashboard, and automated "Quick Fix" code actions.

Quick Start

Run the headless scanner:
```bash
npx flutter-supabase-helper scan ./my-project --pretty
```

Or install the extension to receive real-time security diagnostics and automated fixes directly in your workspace.
