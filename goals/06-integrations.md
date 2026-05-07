# 06 — Integrations: outputs, IDEs, CI

CodeQL is bound to GitHub Code Scanning. Our integration story has to
beat that on portability — same SARIF everywhere, more output formats,
real PR comments on GitLab/Bitbucket/Azure DevOps.

This is **differentiation territory**. Each task here is genuine
upside for adoption.

---

## §IN-1 — SARIF 2.1.0 — already shipped, deepen

- **Current state:** ✅ `vscode-extension/src/output/sarif.ts` emits
  `codeFlows`, per-rule CWE aggregation, partialFingerprints, SRCROOT
  base IDs.
- **Target state:** Add SARIF features CodeQL ships:
  - `taxonomies` block linking each rule to CWE / OWASP / NIST taxonomies
    (we have CWE per-rule but not the formal taxonomy section)
  - `relatedLocations` per result (sources + propagation steps as
    related, not just the sink)
  - `kind` field per result (`fail` / `pass` / `review`)
  - `baselineState` field for findings present in baseline
  - `rank` / `priority` based on severity + confidence
  - `automationDetails` block with run timestamp + scanner version
- **Approach:** Extend `output/sarif.ts`. Each addition is small.
- **Dependencies:** None.
- **Effort:** **M** (4 days).
- **Tests:** Validate output against the official SARIF schema. Use
  `sarif-multitool validate` (Microsoft tool).

## §IN-2 — SARIF: include source code snippets in `physicalLocation`

- **Why:** GitHub Code Scanning shows a snippet next to each finding.
  Today our SARIF has no `region.snippet`.
- **Target state:** Each result includes `region.snippet.text` (the
  ±2 lines around the finding).
- **Effort:** **S** (1 day).

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

## §IN-4 — GitLab Code Quality format

- **Why:** GitLab consumes a specific JSON format. SARIF compatibility
  exists but Code Quality is the native pipeline.
- **Current state:** None.
- **Target state:** `--format=gitlab` outputs the GitLab Code Quality
  schema.
- **Approach:** New `output/gitlab.ts`. Schema:
  https://docs.gitlab.com/ee/ci/testing/code_quality.html
- **Effort:** **S** (1 day).

## §IN-5 — GitLab Security Report format

- **Target state:** `--format=gitlab-security` outputs the GitLab
  Vulnerability Report schema (different from Code Quality).
- **Effort:** **S** (1 day).

## §IN-6 — Bitbucket Code Insights

- **Target state:** `--format=bitbucket` outputs the Code Insights
  Report API JSON.
- **Effort:** **S** (1 day).

## §IN-7 — Azure DevOps work items

- **Target state:** `--format=azure-devops` outputs WIQL-compatible
  results.
- **Effort:** **M** (3 days).

## §IN-8 — Jenkins / generic JUnit XML output

- **Why:** Many Jenkins pipelines consume JUnit XML.
- **Target state:** `--format=junit` outputs a JUnit-shaped XML where
  each finding is a `<failure>`.
- **Effort:** **S** (1 day).

## §IN-9 — Standalone HTML report

- **Why:** A self-contained HTML file is the most-shareable output.
- **Current state:** Webview shows results in VS Code; no standalone.
- **Target state:** `--format=html` produces a single HTML file with
  inline CSS and all findings, navigable by file/severity/rule.
- **Approach:** Reuse the webview rendering logic; bake into a
  standalone HTML template.
- **Effort:** **M** (4 days).

## §IN-10 — Markdown report

- **Why:** Easy to paste into PR descriptions / issue tickets.
- **Target state:** `--format=markdown` outputs a Markdown summary
  table + per-finding bullets.
- **Effort:** **S** (1 day).

## §IN-11 — CSV export

- **Target state:** `--format=csv` for spreadsheet consumption.
- **Effort:** **S** (1 day).

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

## §IN-16 — VS Code: explanation hover provider

- **Why:** When the user hovers over a flagged line, show why it's
  flagged + how to fix.
- **Target state:** Hover shows finding's message + fix + CWE link
  (already partial via diagnostic relatedInformation).
- **Effort:** **S** (1 day).

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

## §IN-19 — Slack notification on findings

- **Target state:** `--notify=slack:<webhook>` posts a summary
  message after scan.
- **Effort:** **S** (1 day).

## §IN-20 — Email notification

- **Target state:** `--notify=email:<addr>` via SMTP.
- **Effort:** **S** (1 day).

## §IN-21 — Issue creation in Jira / Linear / GitHub Issues

- **Target state:** `--create-issues=jira:<project>` opens a Jira
  ticket per HIGH finding.
- **Effort:** **L** (~1 week per provider).

## §IN-22 — pre-commit hook integration

- **Why:** Stop bad code at the developer's machine.
- **Target state:** A documented `.pre-commit-config.yaml` snippet that
  runs the scanner against staged files only.
- **Approach:** Document; add `--changed-since=HEAD~0` mode that
  scans only `git diff --staged`.
- **Effort:** **S** (1 day).

## §IN-23 — Husky / lint-staged integration

- **Effort:** **S** (1 day, mostly docs).

## §IN-24 — GitHub Actions reusable workflow

- **Why:** Drop-in copy-paste workflow for users.
- **Target state:** `.github/workflows/sast.yml` example in the repo
  README, calling our action.
- **Effort:** **S** (1 day).

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

## §IN-27 — Compare-with-baseline visual diff

- **Why:** PRs need to show "this PR introduced 3 new findings, fixed 2."
- **Target state:** A `--diff-against=<sarif-file>` mode that emits
  only new findings vs an older SARIF.
- **Approach:** Match by partialFingerprints (already in SARIF output).
- **Effort:** **S** (2 days).

## §IN-28 — Confidence-based filter in CI

- **Why:** Some teams only want HIGH-confidence findings to fail CI.
- **Current state:** `--fail-on=high|medium|low` exists.
- **Target state:** Add `--fail-confidence=high` (separate from
  severity).
- **Effort:** **S** (1 day).

## §IN-29 — Configuration file precedence

- **Current state:** `.fshrc.{yaml,yml,json}` config supported on Dart
  side. JS side has `flutterSupabaseHelper.disabledRules` setting
  + `--disable` flag.
- **Target state:** Unified config across both impls. CLI > env >
  config-file > default.
- **Effort:** **M** (1 week).

## §IN-30 — Config schema + validation

- **Target state:** Publish a JSON Schema for `.fshrc.yaml`. VS Code
  picks it up via `yaml.schemas` for autocomplete.
- **Effort:** **S** (1 day).

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
