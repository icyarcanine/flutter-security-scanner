# 06 — Integrations: outputs, IDEs, CI

CodeQL is bound to GitHub Code Scanning. Our integration story has to
beat that on portability — same SARIF everywhere, more output formats,
real PR comments on GitLab/Bitbucket/Azure DevOps.

This is **differentiation territory**. Each task here is genuine
upside for adoption.

---

## Status (as of 2026-05-07)

Legend: ✅ DONE | 🟡 PARTIAL | ⏳ REMAINING (default).

- ✅ §IN-1, §IN-2, §IN-4, §IN-5, §IN-6, §IN-8, §IN-9, §IN-10, §IN-11,
  §IN-16, §IN-19, §IN-22, §IN-23, §IN-24, §IN-27, §IN-28, §IN-30
- ⏳ §IN-3, §IN-7, §IN-12, §IN-13, §IN-14, §IN-15, §IN-17, §IN-18, §IN-20,
  §IN-21, §IN-25, §IN-26, §IN-29, §IN-31, §IN-32

---

## §IN-1 — SARIF 2.1.0 — already shipped, deepen ✅ DONE — 2026-05-07

- **Current state:** ✅ `vscode-extension/src/output/sarif.ts` emits
  `codeFlows`, per-rule CWE aggregation, partialFingerprints, SRCROOT
  base IDs.
- **Target state:** Add SARIF features CodeQL ships — DELIVERED:
  - ✅ `taxonomies` block — every CWE referenced by any rule appears in
    `runs[].taxonomies[].taxa`; rules carry `relationships` linking
    rule.id → CWE entry.
  - ✅ `relatedLocations` per result — source + propagation steps from
    the code-flow chain are emitted as related (the sink remains the
    primary location).
  - ✅ `kind` field per result — `fail` for HIGH/MEDIUM-confidence
    findings, `review` for LOW confidence.
  - ✅ `baselineState` field — opt-in via the new
    `toSarif(report, rootPath, { baselineFingerprints })` parameter;
    matched findings get `'unchanged'`, unmatched get `'new'`. Field
    is omitted when no baseline is supplied.
  - ✅ `rank` (0-100) — derived from severity (high=80 / medium=50 /
    low=25) + confidence boost (+15 high, +5 medium).
  - ✅ `automationDetails` — every run carries an `id` (override via the
    `automationId` option) and a `description.text`.
- **Approach:** Extend `output/sarif.ts`. Each addition is small.
- **Dependencies:** None.
- **Effort:** **M** (4 days).
- **Tests:** `testSarifTaxonomyAndAutomation` and `testSarifBaselineState`
  in `vscode-extension/scripts/output-formats.test.js` cover every new
  field.

## §IN-2 — SARIF: include source code snippets in `physicalLocation` ✅ DONE — 2026-05-07

- **Why:** GitHub Code Scanning shows a snippet next to each finding.
  Today our SARIF has no `region.snippet`.
- **Target state:** Each result includes `region.snippet.text` (the
  ±2 lines around the finding).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - TS-side: `vscode-extension/src/output/sarif.ts` builds a
    `Map<relativePath, lines[]>` from `report.context.files` and emits
    `region.snippet.text` (offending line) + `contextRegion` (line ±2,
    with its own snippet) on every result. Taint code-flow steps carry
    snippets too. Snippets are clamped at 320 chars/line so minified
    bundles don't blow up the SARIF payload.
  - Dart-side: `lib/src/output/sarif_writer.dart` accepts a new
    `fileLines: Map<String, List<String>>?` parameter on `encode()`;
    the CLI populates it from `report.context.files` for
    `--format=sarif` runs.
  - Tests: `vscode-extension/scripts/output-formats.test.js`
    `testSarifSnippets`; `test/sarif_writer_test.dart` (3 cases:
    embeds correctly, omits when no fileLines passed, clamps long lines).

## §IN-3 — GitHub PR review comments (line-level)

- **Why:** SARIF + Code Scanning posts on the Security tab. PR-level
  inline comments on changed lines are more visible.
- **Current state:** None.
- **Target state:** A `flutter-supabase-helper pr-comment` subcommand
  that posts review comments on GitHub PRs via the GraphQL API.
  Reads SARIF, filters to changed lines, posts comments.
- **Approach:** Standalone CLI verb. Inputs: SARIF file, GitHub
  token, PR number. Output: posted comments + summary.
- **Dependencies:** None.
- **Effort:** **M** (5 days).
- **Risks / gotchas:**
  - GitHub's PR-comment API is pickier about line numbers than
    Security tab. Handle "line not in diff" by falling back to a
    summary comment.
  - Don't double-post on re-runs; track comment IDs.

## §IN-4 — GitLab Code Quality format ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** GitLab consumes a specific JSON format. SARIF compatibility
  exists but Code Quality is the native pipeline.
- **Current state:** None.
- **Target state:** `--format=gitlab` outputs the GitLab Code Quality
  schema.
- **Approach:** New `output/gitlab.ts`. Schema:
  https://docs.gitlab.com/ee/ci/testing/code_quality.html
- **Effort:** **S** (1 day).
- **Implementation notes:** `output/gitlab.ts` produces an array of
  `{description, check_name, fingerprint, severity, location: {path, lines: {begin}}}`.
  Severity mapping: high+high-conf → blocker, high → critical, medium →
  major, low → minor. Fingerprint is sha-1(code|path|line|message).

## §IN-5 — GitLab Security Report format ✅ DONE — 2026-05-07

- **Target state:** `--format=gitlab-security` outputs the GitLab
  Vulnerability Report schema (different from Code Quality).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - `vscode-extension/src/output/gitlabSecurity.ts` emits the v15 SAST
    schema: top-level `version` + `scan` (analyzer/scanner/type/status/
    timestamps) + `vulnerabilities[]`. Each vulnerability carries a
    deterministic UUIDv4-shaped id (sha-1 over code+path+line+message),
    severity in GitLab's Critical/High/Medium/Low/Info scale, and CWE
    identifiers when available.
  - CLI flags: `--gitlab-security` and `--format=gitlab-security`.
  - Test: `testGitLabSecurity` in scripts/output-formats.test.js — checks
    schema version, required scan fields, UUIDv4 id shape, severity bucket
    membership, and same-input determinism.

## §IN-6 — Bitbucket Code Insights ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `--format=bitbucket` outputs the Code Insights
  Report API JSON.
- **Effort:** **S** (1 day).
- **Implementation notes:** `output/bitbucket.ts` emits the annotations
  array — `{external_id, type: 'VULNERABILITY', severity, summary,
  details, path, line}`. Severity mapping: high+high-conf → CRITICAL,
  high → HIGH, medium → MEDIUM, else LOW. CI scripts upload via
  `curl -X POST` to the report endpoint.

## §IN-7 — Azure DevOps work items

- **Target state:** `--format=azure-devops` outputs WIQL-compatible
  results.
- **Effort:** **M** (3 days).

## §IN-8 — Jenkins / generic JUnit XML output ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** Many Jenkins pipelines consume JUnit XML.
- **Target state:** `--format=junit` outputs a JUnit-shaped XML where
  each finding is a `<failure>`.
- **Effort:** **S** (1 day).
- **Implementation notes:** `output/junit.ts` emits XML 1.0 / UTF-8 with
  a single `<testsuite>` containing one `<testcase>` per finding (with
  `<failure>`) and one `<testcase><skipped/>` per oversize file. `tests`
  / `failures` / `skipped` attributes set from the report.

## §IN-9 — Standalone HTML report ✅ DONE — sha d0af6b4 (2026-05-07)

- **Why:** A self-contained HTML file is the most-shareable output.
- **Current state:** Webview shows results in VS Code; no standalone.
- **Target state:** `--format=html` produces a single HTML file with
  inline CSS and all findings, navigable by file/severity/rule.
- **Approach:** Reuse the webview rendering logic; bake into a
  standalone HTML template.
- **Effort:** **M** (4 days).
- **Implementation notes:**
  - Added `output/html.ts` and CLI `--html` / `--format html` support.
  - Emits one self-contained HTML document with inline CSS/JS, summary stats,
    and severity/rule/file/search filters.
  - Covered by the output-format smoke test.

## §IN-10 — Markdown report ✅ DONE — sha f2d31ad (2026-05-07)

- **Why:** Easy to paste into PR descriptions / issue tickets.
- **Target state:** `--format=markdown` outputs a Markdown summary
  table + per-finding bullets.
- **Effort:** **S** (1 day).
- **Implementation notes:** `output/markdown.ts` — `# SAST scan report`
  header, summary list (files scanned / findings / duration / AST
  success / oversize-skipped count), then a `| Severity | Rule | File | Line | Message |`
  table with severity badges (🔴 / 🟡 / 🔵). Pipes and newlines in
  cells are escaped.

## §IN-11 — CSV export ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** `--format=csv` for spreadsheet consumption.
- **Effort:** **S** (1 day).
- **Implementation notes:** `output/csv.ts` — RFC 4180 quoting (CRLF
  line endings, doubled `""` for embedded quotes). Columns: severity,
  category, confidence, code, cwe, file, line, column, message, fix.

## §IN-12 — CycloneDX SBOM integration

- **Why:** Modern security teams pair findings with SBOMs.
- **Target state:** `--include-sbom` flag generates a CycloneDX SBOM
  alongside SARIF, with linkage between findings and components.
- **Approach:** Read `package-lock.json` / `pnpm-lock.yaml` /
  `pubspec.lock`. Generate CycloneDX JSON.
- **Effort:** **L** (~2 weeks).

## §IN-13 — Sigstore attestation of scan results

- **Why:** Supply chain integrity.
- **Target state:** Optionally sign scan outputs with sigstore;
  consumers verify provenance.
- **Effort:** **L** (~2 weeks).

## §IN-14 — VS Code: scan-on-type (already opt-in scan-on-save; deepen)

- **Why:** Real-time feedback for the actively-edited file.
- **Current state:** Save-debounced (`scanOnSave`).
- **Target state:** Optionally scan only the active file as the user
  types, debounced 500ms. Cheap because it's one file.
- **Approach:** New extension setting `scanOnType`. Wire to
  `vscode.workspace.onDidChangeTextDocument`.
- **Dependencies:** §SC-3 (streaming) so single-file scan is cheap.
- **Effort:** **M** (3 days).
- **Risks / gotchas:** Can be intrusive — keep it opt-in, debounce
  longer than save, and don't show diagnostics for findings that
  vanish < 500 ms later.

## §IN-15 — VS Code: findings tree view

- **Why:** Today findings appear as Diagnostics + the webview report
  panel. A native tree view in the Activity Bar would be more
  navigable.
- **Target state:** Custom Tree Data Provider showing findings
  grouped by severity/file. Click jumps to source.
- **Effort:** **M** (4 days).

## §IN-16 — VS Code: explanation hover provider ✅ DONE — 2026-05-07

- **Why:** When the user hovers over a flagged line, show why it's
  flagged + how to fix.
- **Target state:** Hover shows finding's message + fix + CWE link
  (already partial via diagnostic relatedInformation).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - `vscode-extension/src/diagnostics/hoverProvider.ts` —
    `FindingHoverProvider` registered for every supported language in
    `extension.ts`. Renders a Markdown card per finding with severity
    badge, message, fix, risk, and clickable CWE links to MITRE.
  - Backed by `DiagnosticsProvider.findingsAtLine(uri, line)`, which
    indexes the latest scan's findings by absolute path. Stays in sync
    with the squiggle: `clearDiagnostics()` clears the index too.
  - Tests: `vscode-extension/scripts/hover-provider.test.js` mocks
    `vscode` in the Node module cache and verifies (a) the line index
    handles single + multi-line ranges, (b) the rendered Markdown
    contains rule code / severity / fix / risk / CWE link, (c) clean
    lines return undefined.

## §IN-17 — IntelliJ / JetBrains plugin

- **Why:** IntelliJ is the dominant Java IDE; we have no presence.
- **Target state:** A JetBrains plugin that runs the CLI scanner and
  surfaces findings.
- **Approach:** Kotlin plugin reading SARIF from CLI and converting
  to JetBrains' internal `Inspection` API.
- **Effort:** **L** (~3 weeks).

## §IN-18 — Vim / Neovim plugin

- **Target state:** Lua plugin via nvim-lspconfig that runs the CLI
  on save.
- **Effort:** **M** (1 week).

## §IN-19 — Slack notification on findings ✅ DONE — sha e330ed4 (2026-05-07)

- **Target state:** `--notify=slack:<webhook>` posts a summary
  message after scan.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `--notify slack:<webhook-url>` / `--notify=slack:<webhook-url>`.
  - Posts a Slack-compatible JSON summary after scan output and before CI
    threshold exit.
  - Notification failures warn on stderr but do not fail the scan.

## §IN-20 — Email notification

- **Target state:** `--notify=email:<addr>` via SMTP.
- **Effort:** **S** (1 day).

## §IN-21 — Issue creation in Jira / Linear / GitHub Issues

- **Target state:** `--create-issues=jira:<project>` opens a Jira
  ticket per HIGH finding.
- **Effort:** **L** (~1 week per provider).

## §IN-22 — pre-commit hook integration ✅ DONE — sha e330ed4 (2026-05-07)

- **Why:** Stop bad code at the developer's machine.
- **Target state:** A documented `.pre-commit-config.yaml` snippet that
  runs the scanner against staged files only.
- **Approach:** Document; add `--changed-since=HEAD~0` mode that
  scans only `git diff --staged`.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added a `.pre-commit-config.yaml` local-hook snippet to README using
    `--changed-since HEAD`, `--fail-on high`, and `--fail-confidence high`.

## §IN-23 — Husky / lint-staged integration ✅ DONE — 2026-05-07

- **Effort:** **S** (1 day, mostly docs).
- **Implementation notes:** README "Husky + lint-staged" section
  documents the `.husky/pre-commit` hook + `package.json#lint-staged`
  block. Reuses the same `--changed-since HEAD --fail-on high
  --fail-confidence high --summary` invocation as the pre-commit /
  CI flows so all three entry points stay in sync.

## §IN-24 — GitHub Actions reusable workflow ✅ DONE — sha e330ed4 (2026-05-07)

- **Why:** Drop-in copy-paste workflow for users.
- **Target state:** `.github/workflows/sast.yml` example in the repo
  README, calling our action.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `.github/workflows/sast.yml` with checkout, Node setup, local
    scanner compile, SARIF generation, confidence-gated failure, and SARIF
    upload.

## §IN-25 — Public GitHub Action

- **Why:** Drop-in `uses: flutter-supabase-helper/sast-action@v1`.
- **Target state:** A repo `flutter-supabase-helper/sast-action`
  with `action.yml` that runs the scanner and uploads SARIF.
- **Approach:** Standalone repo, docker-image-based or composite action.
- **Effort:** **M** (3 days).

## §IN-26 — Web-based dashboard for scan history

- **Why:** Trend analysis is a feature only commercial SAST has.
- **Target state:** A self-hostable dashboard
  (`flutter-supabase-helper dashboard`) that ingests SARIF over time
  and shows trends, top-rules, suppression abuse rates.
- **Approach:** SQLite-backed, single-binary, opt-in.
- **Effort:** **XL** (~6 weeks).

## §IN-27 — Compare-with-baseline visual diff ✅ DONE — sha e330ed4 (2026-05-07)

- **Why:** PRs need to show "this PR introduced 3 new findings, fixed 2."
- **Target state:** A `--diff-against=<sarif-file>` mode that emits
  only new findings vs an older SARIF.
- **Approach:** Match by partialFingerprints (already in SARIF output).
- **Effort:** **S** (2 days).
- **Implementation notes:**
  - Added `--diff-against <sarif>` / `--diff-against=<sarif>`.
  - Matches prior SARIF `partialFingerprints` and falls back to
    rule/path/line keys for third-party SARIF.
  - Applies before output formatting so JSON/SARIF/Markdown/etc. all show
    only new findings.

## §IN-28 — Confidence-based filter in CI ✅ DONE — sha e330ed4 (2026-05-07)

- **Why:** Some teams only want HIGH-confidence findings to fail CI.
- **Current state:** `--fail-on=high|medium|low` exists.
- **Target state:** Add `--fail-confidence=high` (separate from
  severity).
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Added `--fail-confidence high|medium|low`.
  - Combines with `--fail-on` when both are present, e.g. HIGH severity and
    HIGH confidence only.

## §IN-29 — Configuration file precedence

- **Current state:** `.fshrc.{yaml,yml,json}` config supported on Dart
  side. JS side has `flutterSupabaseHelper.disabledRules` setting
  + `--disable` flag.
- **Target state:** Unified config across both impls. CLI > env >
  config-file > default.
- **Effort:** **M** (1 week).

## §IN-30 — Config schema + validation ✅ DONE — sha f2d31ad (2026-05-07)

- **Target state:** Publish a JSON Schema for `.fshrc.yaml`. VS Code
  picks it up via `yaml.schemas` for autocomplete.
- **Effort:** **S** (1 day).
- **Implementation notes:**
  - Schema lives at `schemas/fshrc.schema.json` (Draft-07).
  - Covers: `rules` (per-code overrides — bool, string shorthand, or
    object form with `enabled`/`severity`/`exclude`), top-level
    `exclude`, `fail_on`, `include_suggestions`, plus the new
    `max_file_size` (§SC-4) and `rule_timeout` (§SC-8) keys.
  - Severity supports both raw (`high|medium|low`) and SARIF aliases
    (`error|warning|note|info`).
  - VS Code pickup is automatic via the extension's `contributes.yamlValidation`
    (matches `.fshrc.yaml`/`.fshrc.yml`) and `contributes.jsonValidation`
    (matches `.fshrc.json`). Schema is staged into
    `vscode-extension/schemas/` by the existing `stage-docs` script and
    bundled via `package.json` `files`.
  - The Dart-side `lib/src/config/scanner_config.dart` loader stays the
    runtime source of truth; the schema documents the same shape so
    teams can write configs without grepping through the loader.

## §IN-31 — Result diff: cross-tool (SARIF vs SARIF)

- **Why:** Compare our findings to CodeQL's findings on the same
  codebase.
- **Target state:** A `flutter-supabase-helper diff <ours.sarif>
  <theirs.sarif>` subcommand showing per-rule overlap, unique findings,
  agreement rate.
- **Effort:** **M** (4 days).

## §IN-32 — Watch mode for development

- **Target state:** `flutter-supabase-helper watch` keeps a long-lived
  process and re-scans on file change. Useful in TDD-style fix loops.
- **Dependencies:** §EN-8 (incremental).
- **Effort:** **M** (3 days post §EN-8).
