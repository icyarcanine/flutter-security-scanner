# 07 — Rule authoring DSL

Custom rule authoring is currently a source-editing workflow: rules are
TypeScript and require recompiling. This file tracks work toward a safer
user-authored rule format.

This file specifies what we'd need to build to give users a way to
write their own rules without forking.

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

- ⏳ Every §RA-* task is unstarted. No DSL or external rule format yet.

---

## §RA-1 — YAML rule format (Semgrep-style)

- **Why:** YAML rules are the lowest-friction format. Users can
  write project-specific rules in their own repo without a build step.
- **Current state:** Rules are TypeScript classes registered in
  `vscode-extension/src/rules/index.ts`. No external rule loading.
- **Target state:** A YAML file under `.fsh/rules/<rule-name>.yaml`
  produces a custom rule. Schema:
  ```yaml
  id: my-org-bad-pattern
  message: This pattern is forbidden by company policy
  severity: high
  cwe: CWE-79
  category: security
  patterns:
    - pattern: 'res.send($X.foo)'
      where:
        $X: { kind: 'tainted-source' }
    - pattern-not: 'res.send(escape($X.foo))'
  ```
- **Approach:**
  1. New `vscode-extension/src/rules/dsl/yamlRule.ts`. Reads YAML,
     converts each pattern into an AST-pattern matcher.
  2. Pattern matching: use tree-sitter's query language (it has its
     own pattern syntax — cite docs for users).
  3. `where` clauses bind metavariables to taint state.
  4. Loaded at scan start; integrated into the rule registry.
- **Dependencies:** None code-side; documents the engine's contract.
- **Effort:** **L** (~3 weeks).
- **Tests:**
  - Round-trip a YAML rule and verify it matches an intended fixture.
  - Test that pattern-not correctly excludes safe variants.
- **Risks / gotchas:**
  - Tree-sitter's pattern language doesn't support `pattern-not` — we
    have to layer that ourselves by running pattern + post-filter.
  - YAML schema validation is mandatory; failed parses must give clear
    errors with line numbers.

## §RA-2 — Pattern syntax: tree-sitter queries

- **Why:** §RA-1's `pattern: …` field needs a syntax. Tree-sitter
  ships a query DSL.
- **Current state:** Not exposed.
- **Target state:** Document and use tree-sitter S-expression query
  syntax for patterns. E.g.:
  ```
  patterns:
    - pattern: |
        (call_expression
          function: (member_expression
            object: (identifier) @receiver
            property: (property_identifier) @method
            (#eq? @method "query")))
  ```
- **Approach:** Document the syntax; provide examples per language.
  Wire to `parser.query(source)`.
- **Dependencies:** §RA-1.
- **Effort:** **M** (1 week).
- **Risks / gotchas:** Tree-sitter queries are language-specific.
  YAML rule must specify `language: javascript` so the right grammar
  loads.

## §RA-3 — Metavariable binding

- **Target state:** `$X`, `$Y` capture pattern submatches and can be
  referenced in `where` constraints (`equal`, `not-equal`, `regex`,
  `kind`).
- **Approach:** `metavariable-pattern` and `metavariable-regex` shapes
  per Semgrep convention.
- **Effort:** **M** post §RA-2.

## §RA-4 — Taint-aware pattern: `where: { $X: { kind: 'tainted' } }`

- **Why:** Rules need to express "the bound metavariable is tainted in
  the current scope."
- **Current state:** None.
- **Target state:** A `where: { $X: { kind: 'tainted' | 'sanitized' |
  'literal' | 'numeric' } }` constraint that the engine resolves by
  asking the taint state for `$X`.
- **Effort:** **M** post §RA-1.

## §RA-5 — Rule metadata (cwe, owasp, severity, confidence, references)

- **Target state:** All metadata fields on a YAML rule mapped onto the
  Finding model. `references` list rendered as links in the webview.
- **Effort:** **S** (2 days).

## §RA-6 — Rule sharing via npm packages

- **Why:** Companies want to share internal rule packs. Open-source
  community wants to share queries.
- **Target state:** A YAML rule pack in `node_modules/@my-org/sast-rules`
  is auto-loaded. Discovery via `peerDependencies` containing
  `flutter-supabase-helper`.
- **Approach:** At scan start, walk `node_modules` for packages whose
  `package.json` declares `"sast": { "rules": "./rules" }`. Load
  YAML files from those paths.
- **Dependencies:** §RA-1.
- **Effort:** **M** (1 week).
- **Risks / gotchas:** Trust model — third-party rules can produce
  arbitrary findings. Display rule provenance in the finding ("rule
  from `@my-org/sast-rules` v1.2.0").

## §RA-7 — Rule pack registry / curation

- **Target state:** A central index of community-authored rule packs
  with quality scores (per [08-quality-evals.md §QE-3](08-quality-evals.md)).
- **Effort:** **L** (~3 weeks).

## §RA-8 — Rule unit-test harness

- **Why:** Authors of YAML rules need a way to test their rules
  before shipping.
- **Current state:** No public test API.
- **Target state:** `flutter-supabase-helper test-rule <rule.yaml>
  --fixtures <dir>` runs the rule against fixtures and asserts
  findings match `expected.json`.
- **Effort:** **M** (3 days post §RA-1).

## §RA-9 — Rule playground (web UI)

- **Why:** Lower the friction for trying out a rule.
- **Target state:** A web page where users paste a YAML rule and
  source code, see findings live.
- **Effort:** **L** (~3 weeks).
- **Risks / gotchas:** Run the engine in a worker / sandbox.

## §RA-10 — Rule deprecation / replacement

- **Target state:** `deprecated: { replacedBy: 'newer-rule', sinceVersion: '2.0' }`
  in YAML metadata. Scanner warns when a deprecated rule fires.
- **Effort:** **S** (1 day).

## §RA-11 — JS plugin model (for power users)

- **Why:** YAML covers 80% of patterns; the rest need real code.
- **Target state:** A `.js` rule file under `.fsh/rules/` exporting a
  `Rule` instance. Loaded at scan start.
- **Approach:** Identical to existing TS `Rule` interface; the only
  change is making it discoverable from a directory.
- **Dependencies:** None.
- **Effort:** **M** (3 days).
- **Risks / gotchas:** Trust — same as §RA-6. Sandbox via `vm.runInNewContext`.

## §RA-12 — Rule benchmark fixture format

- **Why:** Every rule should ship with positive/negative fixtures so
  precision can be measured.
- **Target state:** A `tests/` subdir alongside the YAML rule with
  pairs:
  ```
  tests/
    positive-1.js          # expected: findings present
    positive-1.expected    # the SARIF fragment
    negative-1.js          # expected: no findings
  ```
- **Effort:** **M** (3 days).

## §RA-13 — Cross-language YAML rules

- **Target state:** A single YAML rule applies to multiple languages
  by listing `languages: [javascript, typescript]` and providing per-
  language patterns.
- **Effort:** **M** (3 days post §RA-1).

## §RA-14 — Negation: `pattern-not`, `pattern-not-inside`

- **Target state:** Standard Semgrep negation operators.
- **Effort:** **M** post §RA-1.

## §RA-15 — Composition: `pattern-either`, `patterns-and`

- **Target state:** Boolean composition of patterns.
- **Effort:** **M** post §RA-1.

## §RA-16 — Custom autofix authorship via YAML

- **Why:** Today fixes are TypeScript code (`codeActions.ts`). YAML
  rules need a way to specify fixes too.
- **Target state:**
  ```yaml
  fix: 'res.send(escapeHtml($X))'
  ```
  Captured metavariables substituted in the replacement.
- **Approach:** Tree-sitter's parse-tree replacement.
- **Effort:** **L** (~2 weeks).

## §RA-17 — Backwards compatibility for rule formats

- **Target state:** New rule format versions don't break old rules.
  Versioned schema; auto-migration tool.
- **Effort:** **M** ongoing.

## §RA-18 — Inline-comment-driven rules (lightweight)

- **Why:** Sometimes a rule is a single line of intent.
- **Target state:** Inline `/* @sast-warn: TODO use prepared statements */`
  comments in source code surface as user-defined findings.
- **Effort:** **S** (2 days).
