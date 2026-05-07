import { Finding, FindingConfidence, FindingSeverity, severitySortOrder } from '../models/finding';
import { ProjectContext } from './projectContext';
import { buildDefaultRules } from '../rules/index';
import { RuleStage } from '../rules/rule';
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
    // Compute from this report's own astDiagnostics — never from the
    // global ParserContext singleton. The singleton reflects whichever
    // scan ran most recently, which is wrong for multi-root scans where
    // each folder mutates and resets it; the merged report needs the
    // *aggregated* diagnostics that mergeReports built up.
    const total = this.astDiagnostics.attempted;
    if (total === 0) { return 100; }
    return Math.round((this.astDiagnostics.succeeded / total) * 100);
  }

  get totalFiles(): number {
    return this.context.files.length;
  }
}

export interface ProjectScannerOptions {
  includeSuggestions?: boolean;
  /**
   * Rule codes (e.g. `"injection-flaw"`, `"high-entropy-secret"`) that should
   * not run during this scan. Disabled rules emit no findings, save no time
   * on the scheduler, and are not present in dedupe / suppression input.
   */
  disabledRules?: string[];
}

export class ProjectScanner {
  readonly includeSuggestions: boolean;
  readonly disabledRules: ReadonlySet<string>;

  constructor(includeSuggestionsOrOpts: boolean | ProjectScannerOptions = true) {
    if (typeof includeSuggestionsOrOpts === 'boolean') {
      this.includeSuggestions = includeSuggestionsOrOpts;
      this.disabledRules = new Set();
    } else {
      this.includeSuggestions = includeSuggestionsOrOpts.includeSuggestions ?? true;
      this.disabledRules = new Set(includeSuggestionsOrOpts.disabledRules ?? []);
    }
  }

  async scan(
    rootPath: string,
    onProgress?: (phase: 'loading' | 'rules', detail: string) => void,
  ): Promise<ProjectScanReport> {
    const startTime = Date.now();

    // Reset AST diagnostics for this scan session
    ParserContext.resetDiagnostics();

    const context = await ProjectContext.load(rootPath,
      onProgress ? n => onProgress('loading', `Loading files: ${n}`) : undefined,
    );
    if (onProgress) { onProgress('rules', `Running rules on ${context.files.length} files`); }

    // Build suppression context from .sastignore + inline comments
    const suppressionCtx = buildSuppressionContext(rootPath, context.files);

    const findings: Finding[] = [];
    const allRules = buildDefaultRules(this.includeSuggestions)
      .filter(r => !this.disabledRules.has(r.code));

    // Run rules concurrently within a stage. Rules are pure functions of
    // ProjectContext + Finding[]; they don't share writable state with one
    // another. The AST cache on `ScannedFile` is mutate-on-first-touch and
    // the underlying parse is idempotent, so concurrent first-touchers
    // converge on the same tree.
    //
    // Stages still run sequentially: stage 2 needs stage 1's heuristics
    // (none today, but the contract is documented). Stage 3 (taint) needs
    // stage 2's AST cache pre-warmed.
    const runStage = async (stage: RuleStage) => {
      const stageRules = allRules.filter(r => r.stage === stage);
      const results = await Promise.all(
        stageRules.map(async rule => {
          try {
            return await Promise.resolve(rule.evaluate(context));
          } catch (e) {
            console.error(`[SAST] Rule ${rule.code} failed:`, (e as Error).message);
            return [] as Finding[];
          }
        }),
      );
      for (const r of results) { findings.push(...r); }
    };

    await runStage(RuleStage.fast);  // regex / heuristics
    await runStage(RuleStage.ast);   // structural AST patterns
    await runStage(RuleStage.taint); // source-to-sink data flow

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
      // Key = code + path + line + column + message.
      //   * `message` distinguishes different sink kinds on the same line
      //     (e.g., `db.query(req.body.q); res.redirect(req.body.u)` — both
      //     emitted as `injection-flaw` with different sink names).
      //   * `column` distinguishes two calls of the SAME shape on the same
      //     line (`db.query(a + req.body.x); db.query(b + req.body.y);`).
      //     Same-stage duplicates from regex+AST still collide because they
      //     report the same column for a given AST node.
      const key = [
        f.code, f.filePath ?? '', f.line?.toString() ?? '',
        f.column?.toString() ?? '', f.message,
      ].join('|');

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
