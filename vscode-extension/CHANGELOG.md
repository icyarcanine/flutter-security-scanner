# Changelog

All notable changes to the Flutter Supabase Helper VS Code extension are
documented here.

## 1.1.0

### Added

- **`ifds-taint` rule** — production IFDS (Reps-Horwitz-Sagiv tabulation)
  taint analysis for Dart. Inter-procedural, context-sensitive via
  procedure summaries, runs as a stage-3 rule after the existing
  intra-procedural `InjectionRule`. Flows into a sink are reported with
  `HIGH` severity / `HIGH` confidence as `Tainted value flows into sink
  '<name>' (IFDS)`.
  - **Sources** (name-based heuristic on parameters): `userInput`,
    `input`, `req`, `request`, `payload`, `data`, `body`, `query`,
    `params`.
  - **Sinks**: `rawQuery`, `query`, `execute`, `exec`, `spawn`, `eval`,
    `Function`, `innerHTML`, `outerHTML`, `document.write` (shared with
    the existing intra-procedural tracker).
  - **Sanitizers**: `escapeHtml`, `sanitize`, `validate`, parameterized
    query builders.
  - Dart-only; tree-sitter CPG covers if/else, while, do-while, for-in,
    try/catch/finally (flattened), class methods, sink-with-lhs,
    template interpolation, bare assignments, strong-kill
    reassignments.
- 10 fixture-based self-tests (`scripts/ifds-self-test.js`) exercising
  intra, inter, sanitizer-neg, branching, reassignment-neg, class
  methods, sink-with-lhs, for-each, multi-file ICFG, and parse-error
  robustness. Wired into `npm test`.

### Suppression

- `ifds-taint` findings honor the existing suppression surfaces:
  `// sast-ignore ifds-taint` (inline) and `.sastignore` (file-level).
  There is no project-wide rule-disable config in the extension; if you
  need to silence the rule globally today, add a broad `.sastignore`
  entry.

### Known limitations

Shipped as-is and tracked for follow-up: name-based source heuristic
(misses real HTTP / storage / SharedPreferences sources), no taint
labels (any sanitizer clears for any sink), no `await` / cascade / named
arguments / field-sensitive assignment / collection taint / implicit
`this`. Virtual dispatch resolves by last-name only (same-named methods
on different classes collide). Try/catch is flattened as a chain
(sound, occasionally over-approximates). Finding message does not yet
include a source-to-sink trace.

## 1.0.0

- Initial public release: regex + tree-sitter AST + intra-procedural
  taint tracking for JavaScript, TypeScript, and Dart. Supabase / RLS /
  secrets / config rule set.
