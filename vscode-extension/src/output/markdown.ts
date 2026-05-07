/**
 * Markdown report emitter (§QW-14 / §IN-10).
 *
 * Produces a single Markdown document that pastes cleanly into PR
 * descriptions, GitHub issues, Slack, Notion, etc. Mirrors the SARIF emitter's
 * shape (no external deps, a single `to*` function over `ProjectScanReport`).
 */
import { Finding, FindingSeverity } from '../models/finding';
import { ProjectScanReport } from '../scanner/scanner';

export function toMarkdown(report: ProjectScanReport): string {
  const lines: string[] = [];
  lines.push('# SAST scan report');
  lines.push('');
  lines.push(`- **Files scanned:** ${report.totalFiles}`);
  lines.push(`- **Findings:** ${report.findings.length} (high: ${report.highCount}, medium: ${report.mediumCount}, low: ${report.lowCount})`);
  lines.push(`- **Scan duration:** ${report.scanDurationMs} ms`);
  lines.push(`- **AST success rate:** ${report.astSuccessRate}%`);
  if (report.skippedFiles.length > 0) {
    lines.push(`- **Skipped files:** ${report.skippedFiles.length} over the size budget`);
  }
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No findings.');
    lines.push('');
    return lines.join('\n');
  }

  lines.push('| Severity | Rule | File | Line | Message |');
  lines.push('|----------|------|------|------|---------|');
  for (const f of report.findings) {
    const sev = f.severity ?? 'low';
    const file = escapeMd(f.filePath ?? '');
    const line = f.line != null ? String(f.line) : '';
    lines.push(`| ${badge(sev)} | \`${escapeMd(f.code)}\` | ${file} | ${line} | ${escapeMd(f.message)} |`);
  }
  lines.push('');
  return lines.join('\n');
}

function badge(sev: FindingSeverity | 'high' | 'medium' | 'low'): string {
  switch (sev) {
    case 'high': return '🔴 HIGH';
    case 'medium': return '🟡 MEDIUM';
    case 'low':
    default: return '🔵 LOW';
  }
}

/** Escape characters that would break a Markdown table cell (`|`, newline). */
function escapeMd(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

// Re-export Finding for callers that want to render a custom subset.
export type { Finding };
