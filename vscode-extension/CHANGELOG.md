# Changelog

All notable changes to the Flutter Supabase Security Scanner VS Code extension are
documented here.

## 1.1.0

### Added

- **Rust engine sidecar rule** — `rust-engine-taint` invokes `engine-cli`
  when a bundled or installed Rust analysis kernel is available. The engine
  runs Semgrep-style Dart taint YAML rules for SQL injection, command
  injection, and HTML rendering/XSS sinks, then merges findings into the
  normal scanner output.
- The legacy TypeScript-side IFDS implementation was removed from the
  default rule set. The JavaScript/TypeScript `dataFlow.ts` taint tracker
  remains the supported non-Rust taint path.
- Release packaging now cleans stale `out/` files before compiling so deleted
  rules cannot leak into a `.vsix`.

### Suppression

- `rust-engine-taint` findings honor the existing suppression surfaces:
  `// sast-ignore rust-engine-taint` (inline) and `.sastignore` (file-level).
  There is no project-wide rule-disable config in the extension; if you
  need to silence the rule globally today, add a broad `.sastignore`
  entry.

### Known limitations

Shipped as-is and tracked for follow-up: the Rust kernel is still
experimental. Direct SQL, command, and HTML rendering taint smoke flows work,
but PDG-aware variable tracking and some Dart syntax coverage are incomplete.
When `engine-cli` is unavailable, the extension falls back to the existing
regex / AST / JavaScript-TypeScript taint rules and skips Rust-backed Dart
taint findings.

## 1.0.0

- Initial public release: regex + tree-sitter AST + intra-procedural
  taint tracking for JavaScript, TypeScript, and Dart. Supabase / RLS /
  secrets / config rule set.
