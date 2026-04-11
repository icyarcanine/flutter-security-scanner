#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { ProjectScanner, ProjectScanReport } from './scanner/scanner';
import { Finding, confidenceReason } from './models/finding';
import { generateBaseline, saveBaseline, loadBaseline, applyBaseline, BASELINE_FILENAME } from './baseline';

// ── Argument Parsing ────────────────────────────

interface CliArgs {
  command: string;
  target: string;
  format: 'json' | 'pretty' | 'summary';
  failOn?: 'high' | 'medium' | 'low';
  useBaseline: boolean;
  openInEditor: boolean;
  maxFindings?: number;
}

function parseArgs(argv: string[]): CliArgs | null {
  const args = argv.slice(2);
  const command = args[0];
  const flags: Record<string, string> = {};
  let target = '';

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--json') { flags.format = 'json'; }
    else if (args[i] === '--pretty') { flags.format = 'pretty'; }
    else if (args[i] === '--summary') { flags.format = 'summary'; }
    else if (args[i] === '--fail-on' && args[i + 1]) { flags.failOn = args[++i]; }
    else if (args[i] === '--baseline') { flags.baseline = 'true'; }
    else if (args[i] === '--open') { flags.open = 'true'; }
    else if (args[i] === '--max-findings' && args[i + 1]) { flags.maxFindings = args[++i]; }
    else if (!args[i].startsWith('-')) { target = args[i]; }
  }

  if (!command) return null;

  return {
    command,
    target: target || '.',
    format: (flags.format as any) || 'json',
    failOn: ['high', 'medium', 'low'].includes(flags.failOn ?? '') ? flags.failOn as any : undefined,
    useBaseline: flags.baseline === 'true',
    openInEditor: flags.open === 'true',
    maxFindings: flags.maxFindings ? parseInt(flags.maxFindings, 10) : undefined,
  };
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

  const scanner = new ProjectScanner(true);

  try {
    const report = await scanner.scan(rootPath);
    let findings: Finding[] = report.findings;

    // Apply baseline if requested
    if (args.useBaseline) {
      const baseline = loadBaseline(rootPath);
      if (baseline) {
        findings = applyBaseline(findings, baseline);
        console.error(`[SAST] Baseline applied: ${baseline.entries.length} known findings filtered`);
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
        outputJson(report, findings, rootPath, fullCounts);
        break;
      case 'pretty':
        outputPretty(report, findings, fullCounts);
        break;
      case 'summary':
        outputSummary(report, fullCounts);
        break;
    }

    // --open: open HIGH findings in editor
    if (args.openInEditor) {
      openHighFindings(findings, rootPath);
    }

    // Exit code for CI
    if (args.failOn) {
      const shouldFail = checkThreshold(findings, args.failOn);
      if (shouldFail) {
        console.error(`[SAST] Threshold exceeded: --fail-on ${args.failOn}`);
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

function outputJson(report: ProjectScanReport, findings: Finding[], rootPath: string, counts: FullCounts) {
  console.log(JSON.stringify({
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
      filePath: f.filePath,
      line: f.line,
      astUsed: f.astUsed ?? null,
    }))
  }, null, 2));
}

// ── Output: Pretty ──────────────────────────────

function outputPretty(report: ProjectScanReport, findings: Finding[], counts: FullCounts) {
  console.log(`\n  Flutter Supabase Helper — SAST Report`);
  console.log(`  ${'─'.repeat(40)}`);
  console.log(`  Files scanned:  ${report.totalFiles}`);
  console.log(`  Scan duration:  ${report.scanDurationMs}ms`);
  console.log(`  AST success:    ${report.astSuccessRate}%`);
  console.log(`  Total findings: ${counts.total}`);
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
  console.log(`  AST:      ${report.astSuccessRate}%`);
  console.log(`  HIGH:     ${counts.high}`);
  console.log(`  MEDIUM:   ${counts.medium}`);
  console.log(`  LOW:      ${counts.low}`);
  console.log(`  Total:    ${counts.total}\n`);
}

// ── CI threshold ────────────────────────────────

function checkThreshold(findings: Finding[], level: string): boolean {
  const thresholds: Record<string, string[]> = {
    high: ['high'],
    medium: ['high', 'medium'],
    low: ['high', 'medium', 'low'],
  };
  const levels = thresholds[level] || [];
  return findings.some(f => levels.includes(f.severity ?? ''));
}

// ── Telemetry (local-only) ──────────────────────

function saveTelemetry(rootPath: string, report: ProjectScanReport, counts: FullCounts) {
  try {
    const telemetryFile = path.join(rootPath, '.sast-telemetry.json');
    const entry = {
      timestamp: new Date().toISOString(),
      files: report.totalFiles,
      findings: counts.total,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      durationMs: report.scanDurationMs,
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

    fs.writeFileSync(telemetryFile, JSON.stringify(history, null, 2), 'utf8');
  } catch {
    // Non-critical — never crash for telemetry
  }
}

// ── Baseline ────────────────────────────────────

async function runBaseline(target: string) {
  const rootPath = path.resolve(target);
  console.error(`[SAST] Generating baseline for: ${rootPath}`);

  try {
    const scanner = new ProjectScanner(true);
    const report = await scanner.scan(rootPath);
    const baseline = generateBaseline(report.findings);

    saveBaseline(rootPath, baseline);
    console.error(`[SAST] Baseline saved: ${baseline.entries.length} findings in ${BASELINE_FILENAME}`);
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
Flutter Supabase Helper — Hybrid SAST Engine CLI

Usage:
  npx flutter-supabase-helper scan <dir> [options]
  npx flutter-supabase-helper baseline <dir>
  npx flutter-supabase-helper validate <dir>

Options:
  --json                  Output as JSON (default)
  --pretty                Human-readable grouped output
  --summary               Compact summary only
  --fail-on <level>       Exit 1 if findings >= level (high|medium|low)
  --baseline              Compare against baseline, show only new findings
  --open                  Open HIGH findings in editor (vscode:// URI)
  --max-findings <n>      Limit output to top N findings (by severity)

Examples:
  npx flutter-supabase-helper scan ./my-project --pretty
  npx flutter-supabase-helper scan . --fail-on high --json
  npx flutter-supabase-helper scan . --pretty --max-findings 10
  npx flutter-supabase-helper scan . --open
  npx flutter-supabase-helper baseline .
  npx flutter-supabase-helper scan . --baseline --summary
  npx flutter-supabase-helper validate ./test_repos
`);
}

main();
