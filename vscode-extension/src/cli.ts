#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import { execSync } from 'child_process';
import { ProjectScanner, ProjectScanReport } from './scanner/scanner';
import { Finding } from './models/finding';
import { generateBaseline, saveBaseline, loadBaseline, applyBaseline, BASELINE_FILENAME } from './baseline';
import { toSarif } from './output/sarif';
import { toMarkdown } from './output/markdown';
import { toCsv } from './output/csv';
import { toJunit } from './output/junit';
import { toGitLabCodeQuality } from './output/gitlab';
import { toGitLabSecurity } from './output/gitlabSecurity';
import { toBitbucketCodeInsights } from './output/bitbucket';
import { toHtmlReport } from './output/html';
import { buildDefaultRules } from './rules/index';

// ── Argument Parsing ────────────────────────────

interface CliArgs {
  command: string;
  target: string;
  format: 'json' | 'pretty' | 'summary' | 'sarif' | 'markdown' | 'csv' | 'junit' | 'gitlab' | 'gitlab-security' | 'bitbucket' | 'html';
  failOn?: 'high' | 'medium' | 'low';
  failConfidence?: 'high' | 'medium' | 'low';
  useBaseline: boolean;
  openInEditor: boolean;
  maxFindings?: number;
  /** When set, write SARIF (or any chosen format) here instead of stdout. */
  outputFile?: string;
  /** Rule codes (comma-separated on the CLI) to skip during this scan. */
  disabledRules: string[];
  /**
   * When set, only emit findings whose file path is listed in
   * `git diff --name-only <ref>...HEAD` (i.e., files modified relative to
   * the ref). Powers PR-style scanning in CI without needing a baseline.
   */
  changedSince?: string;
  /** SARIF file to diff against; matching fingerprints are filtered out. */
  diffAgainst?: string;
  /** Optional notification target, e.g. slack:https://hooks.slack.com/... */
  notify?: string;
  /**
   * Per-rule timeout in milliseconds. Rules exceeding this are aborted and
   * surface a `scanner-internal-error` finding. `0` disables the budget.
   */
  ruleTimeoutMs?: number;
  /** Per-file size cap in bytes. `0` disables the cap. */
  maxFileSizeBytes?: number;
}

function parseArgs(argv: string[]): CliArgs | null {
  const args = argv.slice(2);
  const command = args[0];
  const flags: Record<string, string> = {};
  const disabledRules: string[] = [];
  let target = '';

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--json') { flags.format = 'json'; }
    else if (args[i] === '--pretty') { flags.format = 'pretty'; }
    else if (args[i] === '--summary') { flags.format = 'summary'; }
    else if (args[i] === '--sarif') { flags.format = 'sarif'; }
    else if (args[i] === '--markdown') { flags.format = 'markdown'; }
    else if (args[i] === '--csv') { flags.format = 'csv'; }
    else if (args[i] === '--junit') { flags.format = 'junit'; }
    else if (args[i] === '--gitlab') { flags.format = 'gitlab'; }
    else if (args[i] === '--gitlab-security') { flags.format = 'gitlab-security'; }
    else if (args[i] === '--bitbucket') { flags.format = 'bitbucket'; }
    else if (args[i] === '--html') { flags.format = 'html'; }
    else if ((args[i] === '--format' || args[i].startsWith('--format=')) && (args[i].includes('=') || args[i + 1])) {
      flags.format = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if (args[i] === '--fail-on' && args[i + 1]) { flags.failOn = args[++i]; }
    else if ((args[i] === '--fail-confidence' || args[i].startsWith('--fail-confidence=')) && (args[i].includes('=') || args[i + 1])) {
      flags.failConfidence = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if (args[i] === '--baseline') { flags.baseline = 'true'; }
    else if (args[i] === '--open') { flags.open = 'true'; }
    else if (args[i] === '--max-findings' && args[i + 1]) { flags.maxFindings = args[++i]; }
    else if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) { flags.outputFile = args[++i]; }
    else if (args[i] === '--disable' && args[i + 1]) {
      // Comma-separated list of rule codes (e.g. `--disable high-entropy-secret,file-upload-validation`).
      // Repeatable: `--disable a --disable b` accumulates.
      disabledRules.push(...args[++i].split(',').map(s => s.trim()).filter(Boolean));
    }
    else if ((args[i] === '--changed-since' || args[i].startsWith('--changed-since=')) && (args[i].includes('=') || args[i + 1])) {
      // Accept both `--changed-since main` and `--changed-since=main`.
      flags.changedSince = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if ((args[i] === '--diff-against' || args[i].startsWith('--diff-against=')) && (args[i].includes('=') || args[i + 1])) {
      flags.diffAgainst = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if ((args[i] === '--notify' || args[i].startsWith('--notify=')) && (args[i].includes('=') || args[i + 1])) {
      flags.notify = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if ((args[i] === '--rule-timeout' || args[i].startsWith('--rule-timeout=')) && (args[i].includes('=') || args[i + 1])) {
      flags.ruleTimeoutMs = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if ((args[i] === '--max-file-size' || args[i].startsWith('--max-file-size=')) && (args[i].includes('=') || args[i + 1])) {
      flags.maxFileSize = args[i].includes('=') ? args[i].split('=', 2)[1] : args[++i];
    }
    else if (!args[i].startsWith('-')) { target = args[i]; }
  }

  if (!command) return null;

  return {
    command,
    target: target || '.',
    format: (flags.format as any) || 'json',
    failOn: ['high', 'medium', 'low'].includes(flags.failOn ?? '') ? flags.failOn as any : undefined,
    failConfidence: ['high', 'medium', 'low'].includes(flags.failConfidence ?? '') ? flags.failConfidence as any : undefined,
    useBaseline: flags.baseline === 'true',
    openInEditor: flags.open === 'true',
    maxFindings: flags.maxFindings ? parseInt(flags.maxFindings, 10) : undefined,
    outputFile: flags.outputFile,
    disabledRules,
    changedSince: flags.changedSince,
    diffAgainst: flags.diffAgainst,
    notify: flags.notify,
    ruleTimeoutMs: flags.ruleTimeoutMs != null ? parseTimeoutMs(flags.ruleTimeoutMs) : undefined,
    maxFileSizeBytes: flags.maxFileSize != null ? parseByteSize(flags.maxFileSize) : undefined,
  };
}

/**
 * Parse `--max-file-size` values. Accepts plain bytes (`5242880`) or
 * suffixed forms (`5MB`, `512kb`, `1g`). Returns NaN for unparseable input;
 * the caller treats that as "use default."
 */
function parseByteSize(raw: string): number {
  const trimmed = raw.trim().toLowerCase();
  const m = /^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|k|m|g)?$/.exec(trimmed);
  if (!m) { return NaN; }
  const n = parseFloat(m[1]);
  switch (m[2]) {
    case 'gb':
    case 'g': return Math.round(n * 1024 * 1024 * 1024);
    case 'mb':
    case 'm': return Math.round(n * 1024 * 1024);
    case 'kb':
    case 'k': return Math.round(n * 1024);
    case 'b':
    default: return Math.round(n);
  }
}

/**
 * Parse `--rule-timeout` values. Accepts plain integers (`30000`) and
 * suffixed forms (`30s`, `5m`, `500ms`). Returns NaN for unparseable input;
 * the caller treats that as "use default."
 */
function parseTimeoutMs(raw: string): number {
  const trimmed = raw.trim().toLowerCase();
  const m = /^(\d+(?:\.\d+)?)(ms|s|m)?$/.exec(trimmed);
  if (!m) { return NaN; }
  const n = parseFloat(m[1]);
  switch (m[2]) {
    case 's': return Math.round(n * 1000);
    case 'm': return Math.round(n * 60_000);
    case 'ms':
    default: return Math.round(n);
  }
}

/**
 * Resolve the set of file paths (relative to `rootPath`) modified since
 * `gitRef`. Returns null on git failure (no repo, bad ref, etc.) so the
 * scanner can either fall back to a full scan or fail loudly.
 */
function changedFilesSince(rootPath: string, gitRef: string): Set<string> | null {
  try {
    const out = execSync(`git -C "${rootPath}" diff --name-only ${gitRef}...HEAD`, {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000,
    });
    const set = new Set<string>();
    for (const line of out.split('\n')) {
      const t = line.trim();
      if (t) { set.add(t); }
    }
    // Also include uncommitted changes so PR drafts and dirty trees scan
    // their work-in-progress.
    try {
      const dirty = execSync(`git -C "${rootPath}" status --porcelain`, {
        encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000,
      });
      for (const line of dirty.split('\n')) {
        // git status --porcelain format: "XY path" with a SPACE separator
        // at byte index 2. We slice from index 3 on the raw line — trimming
        // first would eat that space and corrupt the filename.
        if (line.length < 4) { continue; }
        // Renames are " R old -> new" — keep the new path.
        const arrow = line.indexOf(' -> ');
        const raw = arrow !== -1 ? line.substring(arrow + 4) : line.substring(3);
        // Strip surrounding quotes for paths git escaped (e.g. names with spaces).
        const filePath = raw.replace(/^"|"$/g, '').trim();
        if (filePath) { set.add(filePath); }
      }
    } catch { /* dirty check is best-effort */ }
    return set;
  } catch (e) {
    console.error(`[SAST] --changed-since failed: ${e instanceof Error ? e.message : e}`);
    return null;
  }
}

// ── Main ────────────────────────────────────────

async function main() {
  try {
    const cliArgs = parseArgs(process.argv);

    if (!cliArgs || !['scan', 'baseline', 'validate'].includes(cliArgs.command)) {
      printUsage();
      process.exit(1);
    }

    if (cliArgs.command === 'baseline') {
      await runBaseline(cliArgs.target);
      return;
    }

    if (cliArgs.command === 'validate') {
      await runValidation(cliArgs.target);
      return;
    }

    await runScan(cliArgs);
  } catch (err) {
    console.error(`[SAST] Unexpected error:`, err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

// ── Scan ────────────────────────────────────────

async function runScan(args: CliArgs) {
  const rootPath = path.resolve(args.target);
  console.error(`[SAST] Starting analysis on: ${rootPath}`);
  if (args.disabledRules.length > 0) {
    // Validate against the registry so a typo like `--disable injextion-flaw`
    // surfaces as a warning instead of silently doing nothing.
    const known = new Set(buildDefaultRules(true).map(r => r.code));
    const unknown = args.disabledRules.filter(c => !known.has(c));
    if (unknown.length > 0) {
      console.error(`[SAST] Warning: --disable rule code(s) not recognized: ${unknown.join(', ')}`);
      console.error(`[SAST]   Known rules: ${Array.from(known).sort().join(', ')}`);
    }
    console.error(`[SAST] Disabled rules: ${args.disabledRules.join(', ')}`);
  }

  const ruleTimeoutMs = Number.isFinite(args.ruleTimeoutMs) ? args.ruleTimeoutMs : undefined;
  if (args.ruleTimeoutMs != null && !Number.isFinite(args.ruleTimeoutMs)) {
    console.error(`[SAST] Warning: --rule-timeout value not understood; using default.`);
  }
  const maxFileSizeBytes = Number.isFinite(args.maxFileSizeBytes) ? args.maxFileSizeBytes : undefined;
  if (args.maxFileSizeBytes != null && !Number.isFinite(args.maxFileSizeBytes)) {
    console.error(`[SAST] Warning: --max-file-size value not understood; using default.`);
  }
  const scanner = new ProjectScanner({
    includeSuggestions: true,
    disabledRules: args.disabledRules,
    ruleTimeoutMs,
    maxFileSizeBytes,
  });

  try {
    const report = await scanner.scan(rootPath);
    let findings: Finding[] = report.findings;

    // Restrict to files changed vs a git ref (PR-style scan).
    if (args.changedSince) {
      const changed = changedFilesSince(rootPath, args.changedSince);
      if (changed != null) {
        const before = findings.length;
        findings = findings.filter(f => f.filePath && changed.has(f.filePath));
        console.error(`[SAST] --changed-since ${args.changedSince}: kept ${findings.length}/${before} findings (${changed.size} changed files)`);
      } else {
        console.error(`[SAST] --changed-since fell back to full scan output (git failed).`);
      }
    }

    if (args.diffAgainst) {
      const baselineSarifPath = path.resolve(rootPath, args.diffAgainst);
      const oldFingerprints = loadSarifFingerprints(baselineSarifPath);
      const before = findings.length;
      findings = findings.filter(f => !oldFingerprints.has(fingerprintForFinding(f, rootPath)));
      console.error(`[SAST] --diff-against ${args.diffAgainst}: kept ${findings.length}/${before} new findings (${oldFingerprints.size} prior fingerprints)`);
    }

    // Apply baseline if requested. Pass current file contents so v2 baselines
    // can use context-hash matching (line-shift tolerant).
    if (args.useBaseline) {
      const baseline = loadBaseline(rootPath);
      if (baseline) {
        const fileContents = new Map<string, string>();
        for (const f of report.context.files) {
          fileContents.set(f.relativePath, f.content);
        }
        findings = applyBaseline(findings, baseline, fileContents);
        console.error(`[SAST] Baseline (v${baseline.version}) applied: ${baseline.entries.length} known findings filtered`);
      } else {
        console.error(`[SAST] No baseline found. Run 'baseline' first.`);
      }
    }

    // Store full counts before truncation
    const fullCounts = {
      total: findings.length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    };

    // Apply --max-findings (prioritize HIGH → MEDIUM → LOW)
    if (args.maxFindings != null && args.maxFindings > 0 && findings.length > args.maxFindings) {
      findings = truncateFindings(findings, args.maxFindings);
      console.error(`[SAST] Showing top ${args.maxFindings} of ${fullCounts.total} findings (prioritized by severity)`);
    }

    // Output
    switch (args.format) {
      case 'json':
        emitOrWrite(args.outputFile, JSON.stringify(buildJsonReport(report, findings, rootPath, fullCounts), null, 2));
        break;
      case 'pretty':
        outputPretty(report, findings, fullCounts);
        break;
      case 'summary':
        outputSummary(report, fullCounts);
        break;
      case 'sarif': {
        // SARIF respects all baseline / threshold filtering, just like JSON.
        const sarifReport = { ...report, findings } as ProjectScanReport;
        const sarif = toSarif(sarifReport, rootPath);
        emitOrWrite(args.outputFile, JSON.stringify(sarif, null, 2));
        break;
      }
      case 'markdown':
        emitOrWrite(args.outputFile, toMarkdown(filteredReport(report, findings)));
        break;
      case 'csv':
        emitOrWrite(args.outputFile, toCsv(filteredReport(report, findings)));
        break;
      case 'junit':
        emitOrWrite(args.outputFile, toJunit(filteredReport(report, findings)));
        break;
      case 'gitlab':
        emitOrWrite(args.outputFile, toGitLabCodeQuality(filteredReport(report, findings)));
        break;
      case 'gitlab-security':
        emitOrWrite(args.outputFile, toGitLabSecurity(filteredReport(report, findings)));
        break;
      case 'bitbucket':
        emitOrWrite(args.outputFile, toBitbucketCodeInsights(filteredReport(report, findings)));
        break;
      case 'html':
        emitOrWrite(args.outputFile, toHtmlReport(filteredReport(report, findings)));
        break;
    }

    // --open: open HIGH findings in editor
    if (args.openInEditor) {
      openHighFindings(findings, rootPath);
    }

    if (args.notify) {
      await sendNotification(args.notify, rootPath, fullCounts, findings.length);
    }

    // Exit code for CI
    if (args.failOn || args.failConfidence) {
      const shouldFail = checkThreshold(findings, args.failOn, args.failConfidence);
      if (shouldFail) {
        const parts = [
          args.failOn ? `--fail-on ${args.failOn}` : null,
          args.failConfidence ? `--fail-confidence ${args.failConfidence}` : null,
        ].filter(Boolean).join(' ');
        console.error(`[SAST] Threshold exceeded: ${parts}`);
        process.exit(1);
      }
    }

    // Local telemetry (optional, local-only)
    saveTelemetry(rootPath, report, fullCounts);

  } catch (err) {
    console.error(`[SAST] Fatal error during scan:`, err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

/**
 * Wrap a `ProjectScanReport` so emitters that read `.findings` see the
 * post-filter list (after baseline + threshold + truncation). Other report
 * fields (`skippedFiles`, `astSuccessRate`, etc.) pass through unchanged via
 * the original prototype.
 */
function filteredReport(report: ProjectScanReport, findings: Finding[]): ProjectScanReport {
  // Create an object that delegates to the original report but overrides
  // findings. Using `Object.create` preserves prototype methods/getters
  // (e.g. `astSuccessRate`, `highCount`) so emitters can rely on them.
  const view = Object.create(report) as ProjectScanReport;
  Object.defineProperty(view, 'findings', { value: findings, writable: false, enumerable: true });
  return view;
}

// ── Finding truncation ──────────────────────────

function truncateFindings(findings: Finding[], max: number): Finding[] {
  // Already sorted by severity in scanner, but re-sort to be safe
  const sorted = [...findings].sort((a, b) => {
    const order: Record<string, number> = { high: 0, medium: 1, low: 2 };
    return (order[a.severity ?? 'low'] ?? 3) - (order[b.severity ?? 'low'] ?? 3);
  });
  return sorted.slice(0, max);
}

// ── --open: editor integration ──────────────────

function openHighFindings(findings: Finding[], rootPath: string) {
  const highFindings = findings.filter(f => f.severity === 'high' && f.filePath);
  if (highFindings.length === 0) {
    console.error('[SAST] No HIGH findings to open.');
    return;
  }

  for (const f of highFindings) {
    const absPath = path.isAbsolute(f.filePath!) ? f.filePath! : path.join(rootPath, f.filePath!);
    const line = f.line ?? 1;

    // Try vscode:// URI scheme first (works for VS Code, Antigravity, and forks)
    const uri = `vscode://file/${encodeURI(absPath)}:${line}`;
    try {
      const platform = process.platform;
      if (platform === 'darwin') {
        execSync(`open "${uri}"`, { stdio: 'ignore', timeout: 3000 });
      } else if (platform === 'win32') {
        execSync(`start "" "${uri}"`, { stdio: 'ignore', timeout: 3000 });
      } else {
        execSync(`xdg-open "${uri}"`, { stdio: 'ignore', timeout: 3000 });
      }
      console.error(`[SAST] Opened: ${f.filePath}:${line}`);
    } catch {
      // Fallback: print clickable file:line (terminals like iTerm2 and VS Code terminal make these clickable)
      console.error(`[SAST] Open: ${absPath}:${line}`);
    }
  }
}

// ── Output: JSON ────────────────────────────────

interface FullCounts { total: number; high: number; medium: number; low: number }

function buildJsonReport(report: ProjectScanReport, findings: Finding[], rootPath: string, counts: FullCounts) {
  return {
    target: rootPath,
    stats: {
      totalFiles: report.totalFiles,
      totalIssues: counts.total,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      astSuccessRate: report.astSuccessRate,
      astFailuresByLanguage: report.astDiagnostics.failuresByLanguage,
      scanDurationMs: report.scanDurationMs,
      stageDurationsMs: report.stageDurationsMs,
      skippedFiles: report.skippedFiles.map(s => ({
        relativePath: s.relativePath,
        sizeBytes: s.sizeBytes,
        reason: s.reason,
      })),
      suppressionsByRule: Object.fromEntries(report.suppressionsByRule),
    },
    findings: findings.map(f => ({
      severity: f.severity,
      category: f.category,
      confidence: f.confidence,
      confidenceReason: f.confidenceReason,
      code: f.code,
      message: f.message,
      fix: f.fix,
      risk: f.risk,
      cwe: f.cwe,
      filePath: f.filePath,
      line: f.line,
      column: f.column,
      endLine: f.endLine,
      endColumn: f.endColumn,
      astUsed: f.astUsed ?? null,
      pathSteps: f.pathSteps,
    })),
  };
}

/**
 * Write content to a file when `--output` is set, otherwise emit to stdout.
 * Writes to disk go through `console.error` for the success message so that
 * stdout stays empty (CI tools redirecting stdout to a file expect a pristine
 * payload, even when --output handles the writing already).
 */
function emitOrWrite(outputFile: string | undefined, content: string): void {
  if (outputFile) {
    fs.writeFileSync(outputFile, content, 'utf8');
    console.error(`[SAST] Wrote ${content.length} bytes to ${outputFile}`);
  } else {
    console.log(content);
  }
}

// ── Output: Pretty ──────────────────────────────

function outputPretty(report: ProjectScanReport, findings: Finding[], counts: FullCounts) {
  console.log(`\n  Flutter Supabase Security Scanner — SAST Report`);
  console.log(`  ${'─'.repeat(40)}`);
  console.log(`  Files scanned:  ${report.totalFiles}`);
  console.log(`  Scan duration:  ${report.scanDurationMs}ms`);
  if (Object.keys(report.stageDurationsMs).length > 0) {
    console.log(`  Stage timings:  ${formatStageDurations(report.stageDurationsMs)}`);
  }
  console.log(`  AST success:    ${report.astSuccessRate}%`);
  console.log(`  Total findings: ${counts.total}`);
  if (report.skippedFiles.length > 0) {
    console.log(`  Skipped:        ${report.skippedFiles.length} file(s) over size budget`);
  }
  if (findings.length < counts.total) {
    console.log(`  Showing:        ${findings.length} (top by severity)`);
  }
  console.log('');

  if (findings.length === 0) {
    console.log('  ✅ No issues found.\n');
    return;
  }

  // Group by severity
  const groups: Record<string, Finding[]> = { high: [], medium: [], low: [], other: [] };
  for (const f of findings) {
    const sev = f.severity ?? 'other';
    (groups[sev] ?? groups.other).push(f);
  }

  const icons: Record<string, string> = { high: '🔴', medium: '🟡', low: '🔵', other: '⚪' };
  const headers: Record<string, string> = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', other: 'OTHER' };

  for (const sev of ['high', 'medium', 'low', 'other']) {
    const group = groups[sev];
    if (group.length === 0) continue;

    console.log(`  ${icons[sev]}  ${headers[sev]} (${group.length})`);
    console.log(`  ${'─'.repeat(35)}`);

    for (const f of group) {
      const line = f.line ? `:${f.line}` : '';
      const file = f.filePath ?? '';
      const conf = f.confidence ? `[${f.confidence}]` : '';

      console.log(`    ${f.code} ${file}${line} ${conf}`);
      console.log(`      ${f.message}`);
      if (f.fix) console.log(`      → Fix: ${f.fix}`);
      if (f.confidence) console.log(`      → Why ${f.confidence}: ${f.confidenceReason}`);
      console.log('');
    }
  }
}

// ── Output: Summary ─────────────────────────────

function outputSummary(report: ProjectScanReport, counts: FullCounts) {
  console.log(`\n  SAST Summary`);
  console.log(`  ${'─'.repeat(30)}`);
  console.log(`  Files:    ${report.totalFiles}`);
  console.log(`  Duration: ${report.scanDurationMs}ms`);
  if (Object.keys(report.stageDurationsMs).length > 0) {
    console.log(`  Stages:   ${formatStageDurations(report.stageDurationsMs)}`);
  }
  console.log(`  AST:      ${report.astSuccessRate}%`);
  console.log(`  HIGH:     ${counts.high}`);
  console.log(`  MEDIUM:   ${counts.medium}`);
  console.log(`  LOW:      ${counts.low}`);
  console.log(`  Total:    ${counts.total}`);
  if (report.skippedFiles.length > 0) {
    console.log(`  Skipped:  ${report.skippedFiles.length} (oversize)`);
  }
  console.log('');
}

function formatStageDurations(stageDurationsMs: Readonly<Record<string, number>>): string {
  return ['loading', 'fast', 'ast', 'taint']
    .filter(k => stageDurationsMs[k] != null)
    .map(k => `${k}=${stageDurationsMs[k]}ms`)
    .join(', ');
}

// ── Notifications ───────────────────────────────

async function sendNotification(target: string, rootPath: string, counts: FullCounts, shownFindings: number): Promise<void> {
  const [kind, ...rest] = target.split(':');
  const destination = rest.join(':');
  if (kind !== 'slack' || !destination) {
    console.error(`[SAST] Warning: unsupported --notify target "${target}" (expected slack:<webhook-url>).`);
    return;
  }

  const payload = {
    text: `SAST scan for ${path.basename(rootPath)}: ${counts.total} finding(s) ` +
      `(${counts.high} high, ${counts.medium} medium, ${counts.low} low). ` +
      `${shownFindings} shown after filters.`,
  };

  try {
    await postJson(destination, payload);
    console.error('[SAST] Slack notification sent.');
  } catch (err) {
    console.error(`[SAST] Slack notification failed: ${err instanceof Error ? err.message : err}`);
  }
}

function postJson(url: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch (err) {
      reject(err);
      return;
    }

    const body = JSON.stringify(payload);
    const client = parsed.protocol === 'http:' ? http : https;
    const req = client.request(parsed, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body).toString(),
      },
      timeout: 10_000,
    }, res => {
      res.resume();
      res.on('end', () => {
        if (res.statusCode != null && res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`HTTP ${res.statusCode ?? 'unknown'}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('request timed out'));
    });
    req.write(body);
    req.end();
  });
}

// ── SARIF diffing ───────────────────────────────

function loadSarifFingerprints(sarifFile: string): Set<string> {
  try {
    const parsed = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
    const fingerprints = new Set<string>();
    for (const run of parsed?.runs ?? []) {
      for (const result of run?.results ?? []) {
        const partials = result?.partialFingerprints;
        if (partials && typeof partials === 'object') {
          for (const value of Object.values(partials)) {
            if (typeof value === 'string' && value) { fingerprints.add(value); }
          }
        }

        // Fallback for SARIF logs produced by other tools: approximate the
        // same stable key from ruleId + primary location + start line.
        const loc = result?.locations?.[0]?.physicalLocation;
        const uri = loc?.artifactLocation?.uri;
        const line = loc?.region?.startLine;
        if (result?.ruleId && uri && line) {
          fingerprints.add(`${result.ruleId}:${uri}:${line}`);
        }
      }
    }
    return fingerprints;
  } catch (err) {
    console.error(`[SAST] --diff-against failed to read SARIF: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

function fingerprintForFinding(finding: Finding, rootPath: string): string {
  const filePath = finding.filePath ?? '';
  const uri = path.isAbsolute(filePath)
    ? path.relative(rootPath, filePath).split(path.sep).join('/')
    : filePath.split(path.sep).join('/');
  return `${finding.code}:${uri}:${finding.line ?? 1}`;
}

// ── CI threshold ────────────────────────────────

function checkThreshold(
  findings: Finding[],
  severityLevel?: 'high' | 'medium' | 'low',
  confidenceLevel?: 'high' | 'medium' | 'low',
): boolean {
  const severityThresholds: Record<string, string[]> = {
    high: ['high'],
    medium: ['high', 'medium'],
    low: ['high', 'medium', 'low'],
  };
  const confidenceThresholds: Record<string, string[]> = {
    high: ['high'],
    medium: ['high', 'medium'],
    low: ['high', 'medium', 'low'],
  };
  const severities = severityLevel ? severityThresholds[severityLevel] : ['high', 'medium', 'low'];
  const confidences = confidenceLevel ? confidenceThresholds[confidenceLevel] : ['high', 'medium', 'low'];
  return findings.some(f =>
    severities.includes(f.severity ?? '') &&
    confidences.includes(f.confidence ?? ''),
  );
}

// ── Telemetry (local-only) ──────────────────────

/**
 * Resolve the directory we write telemetry into. We prefer (in order):
 *   1. `$XDG_DATA_HOME/flutter-supabase-security-scanner` (only when path is under HOME)
 *   2. `~/Library/Application Support/...`      (macOS)
 *   3. `%LOCALAPPDATA%/flutter-supabase-security-scanner` (Windows; only when under HOME or USERPROFILE)
 *   4. `~/.local/share/flutter-supabase-security-scanner` (XDG default)
 *   5. `~/.flutter-supabase-security-scanner`             (last-resort fallback)
 *
 * NEVER the project root — that pollutes scanned repos with a file the user
 * doesn't expect and that ends up committed by accident.
 *
 * For each env-driven candidate we VALIDATE that the resolved base lives
 * under the user's HOME directory. If the env var points at `/etc` or
 * another sensitive location (e.g., when a malicious shell init has
 * tampered with `XDG_DATA_HOME`), we ignore it and fall through to a safer
 * default. Without this guard we'd be one `mkdir` call from touching
 * arbitrary paths.
 */
function _telemetryFilePath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const isUnderHome = (candidate: string): boolean => {
    if (!home) { return false; }
    const normCandidate = path.resolve(candidate);
    const normHome = path.resolve(home);
    // path.relative returns "" for same dir, "../*" if outside, otherwise
    // a relative path inside. Reject "" (would write *to* HOME directly)
    // and any "../" prefix.
    const rel = path.relative(normHome, normCandidate);
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
  };

  let base = '';
  if (process.env.XDG_DATA_HOME && isUnderHome(process.env.XDG_DATA_HOME)) {
    base = process.env.XDG_DATA_HOME;
  } else if (process.platform === 'darwin' && home) {
    base = path.join(home, 'Library', 'Application Support');
  } else if (process.platform === 'win32' && process.env.LOCALAPPDATA &&
             isUnderHome(process.env.LOCALAPPDATA)) {
    base = process.env.LOCALAPPDATA;
  } else if (home) {
    base = path.join(home, '.local', 'share');
  } else {
    // No HOME at all (containers, restricted shells). Use cwd-relative
    // hidden dir; saveTelemetry's try/catch will swallow failures.
    base = path.join('.', '.flutter-supabase-security-scanner-data');
  }
  const dir = path.join(base, 'flutter-supabase-security-scanner');
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'telemetry.json');
}

function saveTelemetry(_rootPath: string, report: ProjectScanReport, counts: FullCounts) {
  try {
    const telemetryFile = _telemetryFilePath();
    const entry = {
      timestamp: new Date().toISOString(),
      files: report.totalFiles,
      findings: counts.total,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      durationMs: report.scanDurationMs,
      stageDurationsMs: report.stageDurationsMs,
      durationPerFileMs: report.totalFiles > 0 ? report.scanDurationMs / report.totalFiles : report.scanDurationMs,
      astSuccessRate: report.astSuccessRate,
    };

    let history: any[] = [];
    try {
      const existing = fs.readFileSync(telemetryFile, 'utf8');
      const parsed = JSON.parse(existing);
      if (Array.isArray(parsed)) history = parsed;
    } catch { /* no existing file */ }

    // Keep last 50 entries
    history.push(entry);
    if (history.length > 50) history = history.slice(-50);

    const withDistribution = history.map(item => ({
      ...item,
      durationDistributionMs: percentileSummary(history.map(h => Number(h.durationMs)).filter(Number.isFinite)),
      durationPerFileDistributionMs: percentileSummary(history
        .map(h => Number(h.durationPerFileMs ?? (h.files > 0 ? h.durationMs / h.files : h.durationMs)))
        .filter(Number.isFinite)),
    }));

    fs.writeFileSync(telemetryFile, JSON.stringify(withDistribution, null, 2), 'utf8');
  } catch {
    // Non-critical — never crash for telemetry
  }
}

function percentileSummary(values: number[]): { p50: number; p95: number; p99: number } {
  if (values.length === 0) { return { p50: 0, p95: 0, p99: 0 }; }
  const sorted = [...values].sort((a, b) => a - b);
  return {
    p50: percentile(sorted, 0.50),
    p95: percentile(sorted, 0.95),
    p99: percentile(sorted, 0.99),
  };
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * p) - 1));
  return Math.round(sorted[idx]);
}

// ── Baseline ────────────────────────────────────

async function runBaseline(target: string) {
  const rootPath = path.resolve(target);
  console.error(`[SAST] Generating baseline for: ${rootPath}`);

  try {
    const scanner = new ProjectScanner(true);
    const report = await scanner.scan(rootPath);
    // Pass file contents so the baseline carries context hashes — future
    // scans use them to match findings even when line numbers shift.
    const fileContents = new Map<string, string>();
    for (const f of report.context.files) {
      fileContents.set(f.relativePath, f.content);
    }
    const baseline = generateBaseline(report.findings, fileContents);

    saveBaseline(rootPath, baseline);
    console.error(`[SAST] Baseline (v${baseline.version}) saved: ${baseline.entries.length} findings in ${BASELINE_FILENAME}`);
    console.error(`[SAST] Future scans with --baseline will only show NEW findings.`);
  } catch (err) {
    console.error(`[SAST] Baseline generation failed:`, err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

// ── Validation Harness ──────────────────────────

interface RepoResult {
  name: string;
  totalFiles: number;
  totalIssues: number;
  high: number;
  medium: number;
  low: number;
  astSuccessRate: number;
  byCategory: Record<string, number>;
  byRule: Record<string, number>;
  byConfidence: Record<string, number>;
  astFailures: Record<string, number>;
}

async function runValidation(testReposDir: string) {
  const baseDir = path.resolve(testReposDir);

  let repoDirs: string[];
  try {
    const entries = fs.readdirSync(baseDir, { withFileTypes: true });
    repoDirs = entries
      .filter(e => e.isDirectory() && !e.name.startsWith('.'))
      .map(e => path.join(baseDir, e.name));
  } catch {
    console.error(`[SAST] Cannot read directory: ${baseDir}`);
    process.exit(1);
    return;
  }

  if (repoDirs.length === 0) {
    console.error(`[SAST] No subdirectories found in: ${baseDir}`);
    process.exit(1);
    return;
  }

  console.error(`[SAST] Validation harness — scanning ${repoDirs.length} repositories...\n`);

  const results: RepoResult[] = [];
  const scanner = new ProjectScanner(false);

  for (const dir of repoDirs) {
    const name = path.basename(dir);
    console.error(`  Scanning: ${name}...`);
    try {
      const report = await scanner.scan(dir);
      results.push(summarizeReport(name, report));
    } catch (err) {
      console.error(`  ERROR on ${name}: ${(err as Error).message}`);
    }
  }

  const output = {
    timestamp: new Date().toISOString(),
    reposScanned: results.length,
    summary: computeGlobalSummary(results),
    rulePerformance: computeRulePerformance(results),
    repositories: results,
  };

  console.log(JSON.stringify(output, null, 2));
}

function summarizeReport(name: string, report: ProjectScanReport): RepoResult {
  const byCategory: Record<string, number> = {};
  const byRule: Record<string, number> = {};
  const byConfidence: Record<string, number> = {};

  for (const f of report.findings) {
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    byRule[f.code] = (byRule[f.code] || 0) + 1;
    const conf = f.confidence ?? 'unknown';
    byConfidence[conf] = (byConfidence[conf] || 0) + 1;
  }

  return {
    name,
    totalFiles: report.totalFiles,
    totalIssues: report.issueCount,
    high: report.highCount,
    medium: report.mediumCount,
    low: report.lowCount,
    astSuccessRate: report.astSuccessRate,
    byCategory,
    byRule,
    byConfidence,
    astFailures: report.astDiagnostics.failuresByLanguage,
  };
}

function computeGlobalSummary(results: RepoResult[]) {
  let totalFiles = 0, totalIssues = 0, high = 0, medium = 0, low = 0;
  const confidenceDist: Record<string, number> = {};

  for (const r of results) {
    totalFiles += r.totalFiles;
    totalIssues += r.totalIssues;
    high += r.high;
    medium += r.medium;
    low += r.low;
    for (const [conf, count] of Object.entries(r.byConfidence)) {
      confidenceDist[conf] = (confidenceDist[conf] || 0) + count;
    }
  }

  return {
    totalFiles,
    totalIssues,
    high,
    medium,
    low,
    confidenceDistribution: confidenceDist,
    avgIssuesPerRepo: results.length > 0 ? Math.round(totalIssues / results.length) : 0,
  };
}

function computeRulePerformance(results: RepoResult[]) {
  const ruleStats: Record<string, { totalFindings: number; repos: number }> = {};

  for (const r of results) {
    for (const [rule, count] of Object.entries(r.byRule)) {
      if (!ruleStats[rule]) ruleStats[rule] = { totalFindings: 0, repos: 0 };
      ruleStats[rule].totalFindings += count;
      ruleStats[rule].repos++;
    }
  }

  const performance: Record<string, { totalFindings: number; avgPerRepo: number; reposTriggered: number }> = {};
  for (const [rule, stats] of Object.entries(ruleStats)) {
    performance[rule] = {
      totalFindings: stats.totalFindings,
      avgPerRepo: Math.round(stats.totalFindings / results.length * 10) / 10,
      reposTriggered: stats.repos,
    };
  }

  return performance;
}

// ── Usage ───────────────────────────────────────

function printUsage() {
  console.log(`
Flutter Supabase Security Scanner — Hybrid SAST Engine CLI

Usage:
  npx flutter-supabase-security-scanner scan <dir> [options]
  npx flutter-supabase-security-scanner baseline <dir>
  npx flutter-supabase-security-scanner validate <dir>

Options:
  --json                  Output as JSON (default)
  --pretty                Human-readable grouped output
  --summary               Compact summary only
  --sarif                 Output SARIF 2.1.0 (for GitHub Code Scanning, etc.)
  --markdown              Markdown report (PRs / issues / Slack)
  --csv                   RFC 4180 CSV
  --junit                 JUnit XML (Jenkins, CircleCI, Buildkite, …)
  --gitlab                GitLab Code Quality JSON (MR widgets)
  --gitlab-security       GitLab SAST Security Report (Vulnerability Report widget)
  --bitbucket             Bitbucket Code Insights JSON
  --html                  Standalone HTML report
  --format <name>         Same as the per-format flags above
  -o, --output <path>     Write output to a file instead of stdout
  --fail-on <level>       Exit 1 if findings >= level (high|medium|low)
  --fail-confidence <lvl> Exit 1 only for findings at/above confidence (high|medium|low)
  --baseline              Compare against baseline, show only new findings
  --diff-against <sarif>  Show only findings not present in an older SARIF file
  --notify slack:<url>    POST a Slack-compatible JSON summary after scan
  --open                  Open HIGH findings in editor (vscode:// URI)
  --max-findings <n>      Limit output to top N findings (by severity)
  --disable <a,b>         Skip these rule codes (comma-separated, repeatable)
  --changed-since <ref>   Only show findings in files changed vs git <ref>
  --rule-timeout <ms|s|m> Per-rule wall-clock budget (default 30s, 0 to disable)
  --max-file-size <size>  Per-file size cap, e.g. 5MB / 512KB / 1g (default 1MB)

Examples:
  npx flutter-supabase-security-scanner scan ./my-project --pretty
  npx flutter-supabase-security-scanner scan . --fail-on high --json
  npx flutter-supabase-security-scanner scan . --sarif -o sast.sarif
  npx flutter-supabase-security-scanner scan . --html -o sast.html
  npx flutter-supabase-security-scanner scan . --json --diff-against old.sarif
  npx flutter-supabase-security-scanner scan . --summary --notify slack:$SLACK_WEBHOOK_URL
  npx flutter-supabase-security-scanner scan . --pretty --max-findings 10
  npx flutter-supabase-security-scanner scan . --open
  npx flutter-supabase-security-scanner baseline .
  npx flutter-supabase-security-scanner scan . --baseline --summary
  npx flutter-supabase-security-scanner validate ./test_repos
`);
}

main();
