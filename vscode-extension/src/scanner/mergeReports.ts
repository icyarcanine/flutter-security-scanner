import * as path from 'path';
import { ProjectContext, SkippedFile } from './projectContext';
import { ProjectScanReport } from './scanner';
import { Finding } from '../models/finding';
import { ScannedFile } from './scannedFile';
import { AstDiagnostics } from '../ast/parser';

/**
 * Merge per-workspace-folder scan reports into a single combined report.
 *
 * Findings keep their original relative paths but are rewritten to be relative
 * to a synthetic merged root (or absolutized) so the diagnostics provider
 * resolves them correctly regardless of which folder produced them.
 *
 * The combined report uses the first report's rootPath so existing consumers
 * (PanelProvider, DiagnosticsProvider) keep working — we just guarantee every
 * finding's `filePath` is absolute, which both consumers already accept.
 */
export function mergeReports(reports: ProjectScanReport[]): ProjectScanReport {
  if (reports.length === 1) { return reports[0]; }

  const allFiles: ScannedFile[] = [];
  const allSkipped: SkippedFile[] = [];
  const allFindings: Finding[] = [];
  const failuresByLanguage: Record<string, number> = {};
  const failureReasons: string[] = [];
  const allSuppressions = new Map<string, number>();
  const stageDurationsMs: Record<string, number> = {};
  let attempted = 0;
  let succeeded = 0;
  let failed = 0;
  let totalDuration = 0;

  for (const r of reports) {
    totalDuration += r.scanDurationMs;
    for (const [stage, duration] of Object.entries(r.stageDurationsMs)) {
      stageDurationsMs[stage] = (stageDurationsMs[stage] ?? 0) + duration;
    }
    for (const file of r.context.files) { allFiles.push(file); }
    // Promote skipped paths to absolute so the merged report's "5 files
    // skipped" line points at unambiguous locations across folders.
    for (const sf of r.skippedFiles) {
      const abs = path.isAbsolute(sf.relativePath)
        ? sf.relativePath
        : path.join(r.context.rootPath, sf.relativePath);
      allSkipped.push({ relativePath: abs, sizeBytes: sf.sizeBytes, reason: sf.reason });
    }

    // Promote each finding's relative path to an absolute one so the merged
    // diagnostics provider can resolve it without knowing which folder it
    // came from.
    for (const f of r.findings) {
      if (f.filePath && !path.isAbsolute(f.filePath)) {
        const abs = path.join(r.context.rootPath, f.filePath);
        allFindings.push(new Finding({
          severity: f.severity,
          category: f.category,
          confidence: f.confidence,
          code: f.code,
          message: f.message,
          fix: f.fix,
          risk: f.risk,
          filePath: abs,
          line: f.line,
          astUsed: f.astUsed,
        }));
      } else {
        allFindings.push(f);
      }
    }

    attempted += r.astDiagnostics.attempted;
    succeeded += r.astDiagnostics.succeeded;
    failed += r.astDiagnostics.failed;
    for (const [lang, count] of Object.entries(r.astDiagnostics.failuresByLanguage)) {
      failuresByLanguage[lang] = (failuresByLanguage[lang] ?? 0) + count;
    }
    for (const reason of r.astDiagnostics.failureReasons) {
      failureReasons.push(reason);
    }
    // Sum per-rule suppression counts across folders so multi-root scans
    // surface noisy rules with the full project-wide tally.
    for (const [code, count] of r.suppressionsByRule) {
      allSuppressions.set(code, (allSuppressions.get(code) ?? 0) + count);
    }
  }

  // Use the first folder's rootPath as the merged report's anchor; consumers
  // that need a label show "Multi-root scan" via the title bar instead.
  const mergedContext = new ProjectContext(reports[0].context.rootPath, allFiles, allSkipped);
  const mergedDiagnostics: AstDiagnostics = {
    attempted, succeeded, failed, failuresByLanguage, failureReasons,
  };

  stageDurationsMs.total = totalDuration;
  return new ProjectScanReport(mergedContext, allFindings, mergedDiagnostics, totalDuration, allSuppressions, stageDurationsMs);
}
