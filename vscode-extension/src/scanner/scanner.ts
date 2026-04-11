import { Finding, FindingConfidence, FindingSeverity, severitySortOrder } from '../models/finding';
import { ProjectContext } from './projectContext';
import { buildDefaultRules } from '../rules/index';
import { ParserContext, AstDiagnostics } from '../ast/parser';
import { buildSuppressionContext, applySuppression } from '../suppression';
import { applyNonProductionNoiseReduction } from '../noise';

export class ProjectScanReport {
  readonly context: ProjectContext;
  readonly findings: Finding[];
  readonly astDiagnostics: AstDiagnostics;
  readonly scanDurationMs: number;

  constructor(context: ProjectContext, findings: Finding[], astDiagnostics: AstDiagnostics, scanDurationMs: number) {
    this.context = context;
    this.findings = findings;
    this.astDiagnostics = astDiagnostics;
    this.scanDurationMs = scanDurationMs;
  }

  get issueCount(): number {
    return this.findings.filter(f => !f.isSuggestion).length;
  }

  get suggestionCount(): number {
    return this.findings.filter(f => f.isSuggestion).length;
  }

  get highCount(): number {
    return this.findings.filter(f => f.severity === FindingSeverity.high).length;
  }

  get mediumCount(): number {
    return this.findings.filter(f => f.severity === FindingSeverity.medium).length;
  }

  get lowCount(): number {
    return this.findings.filter(f => f.severity === FindingSeverity.low).length;
  }

  get astSuccessRate(): number {
    return ParserContext.astSuccessRate;
  }

  get totalFiles(): number {
    return this.context.files.length;
  }
}

export class ProjectScanner {
  readonly includeSuggestions: boolean;

  constructor(includeSuggestions = true) {
    this.includeSuggestions = includeSuggestions;
  }

  async scan(rootPath: string): Promise<ProjectScanReport> {
    const startTime = Date.now();

    // Reset AST diagnostics for this scan session
    ParserContext.resetDiagnostics();

    const context = await ProjectContext.load(rootPath);

    // Build suppression context from .sastignore + inline comments
    const suppressionCtx = buildSuppressionContext(rootPath, context.files);

    const findings: Finding[] = [];
    const allRules = buildDefaultRules(this.includeSuggestions);
    const getStage = (r: any) => r.stage ?? 1;

    // Stage 1: Fast Scan (Regex / Heuristics)
    const fastRules = allRules.filter(r => getStage(r) === 1);
    for (const rule of fastRules) {
      try {
        findings.push(...(await Promise.resolve(rule.evaluate(context))));
      } catch (e) {
        console.error(`[SAST] Rule ${(rule as any).code} failed:`, (e as Error).message);
      }
    }

    // Stage 2 & 3: AST & Taint Scans (Selective)
    const astRules = allRules.filter(r => getStage(r) === 2);
    for (const rule of astRules) {
      try {
        findings.push(...(await Promise.resolve(rule.evaluate(context))));
      } catch (e) {
        console.error(`[SAST] Rule ${(rule as any).code} failed:`, (e as Error).message);
      }
    }

    const taintRules = allRules.filter(r => getStage(r) === 3);
    for (const rule of taintRules) {
      try {
        findings.push(...(await Promise.resolve(rule.evaluate(context))));
      } catch (e) {
        console.error(`[SAST] Rule ${(rule as any).code} failed:`, (e as Error).message);
      }
    }

    // Apply suppression (inline + .sastignore)
    const unsuppressed = applySuppression(findings, suppressionCtx);
    const noiseAdjusted = applyNonProductionNoiseReduction(unsuppressed);

    const deduped = ProjectScanner._dedupe(noiseAdjusted);
    deduped.sort(ProjectScanner._compareFindings);

    const elapsed = Date.now() - startTime;
    return new ProjectScanReport(context, deduped, { ...ParserContext.diagnostics }, elapsed);
  }

  private static _compareFindings(a: Finding, b: Finding): number {
    if (a.isSuggestion !== b.isSuggestion) {
      return a.isSuggestion ? 1 : -1;
    }
    const sevA = a.severity != null ? severitySortOrder(a.severity) : 3;
    const sevB = b.severity != null ? severitySortOrder(b.severity) : 3;
    if (sevA !== sevB) { return sevA - sevB; }

    const fileCompare = (a.filePath ?? '').localeCompare(b.filePath ?? '');
    if (fileCompare !== 0) { return fileCompare; }

    const lineCompare = (a.line ?? 0) - (b.line ?? 0);
    if (lineCompare !== 0) { return lineCompare; }

    return a.message.localeCompare(b.message);
  }

  private static _dedupe(findings: Finding[]): Finding[] {
    const seen = new Map<string, Finding>();
    for (const f of findings) {
      const key = [f.code, f.filePath ?? '', f.line?.toString() ?? ''].join('|');

      if (!seen.has(key)) {
        seen.set(key, f);
      } else {
        const existing = seen.get(key)!;
        const severityDelta = ProjectScanner._severityRank(f) - ProjectScanner._severityRank(existing);
        const confidenceDelta = ProjectScanner._confidenceRank(f) - ProjectScanner._confidenceRank(existing);
        if (severityDelta < 0 || (severityDelta === 0 && confidenceDelta < 0)) {
           seen.set(key, f);
        }
      }
    }
    return Array.from(seen.values());
  }

  private static _severityRank(finding: Finding): number {
    return finding.severity != null ? severitySortOrder(finding.severity) : 3;
  }

  private static _confidenceRank(finding: Finding): number {
    switch (finding.confidence) {
      case FindingConfidence.high: return 0;
      case FindingConfidence.medium: return 1;
      case FindingConfidence.low: return 2;
      default: return 3;
    }
  }
}
