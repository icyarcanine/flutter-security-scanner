import { Finding, FindingCategory, FindingConfidence, FindingSeverity, DetectionMethod, severitySortOrder } from '../models/finding';
import { ProjectContext, ProjectContextLoadOptions, SkippedFile } from './projectContext';
import { buildDefaultRules } from '../rules/index';
import { RuleStage } from '../rules/rule';
import { ParserContext, AstDiagnostics } from '../ast/parser';
import { buildSuppressionContext, applySuppressionWithStats, SUPPRESSION_REVIEW_THRESHOLD } from '../suppression';
import { applyNonProductionNoiseReduction } from '../noise';

/** Default per-rule timeout in ms. Overridable via ProjectScannerOptions. */
export const DEFAULT_RULE_TIMEOUT_MS = 30_000;

const RULE_TIMEOUT_SENTINEL: unique symbol = Symbol('rule-timeout');

export class ProjectScanReport {
  readonly context: ProjectContext;
  readonly findings: Finding[];
  readonly astDiagnostics: AstDiagnostics;
  readonly scanDurationMs: number;
  /**
   * Per-rule count of findings filtered out by a suppression directive.
   * Lets users notice rules with disproportionate FP rates (§QW-22 / §PR-15).
   * Empty when no suppression fired.
   */
  readonly suppressionsByRule: ReadonlyMap<string, number>;

  constructor(
    context: ProjectContext,
    findings: Finding[],
    astDiagnostics: AstDiagnostics,
    scanDurationMs: number,
    suppressionsByRule: ReadonlyMap<string, number> = new Map(),
  ) {
    this.context = context;
    this.findings = findings;
    this.astDiagnostics = astDiagnostics;
    this.scanDurationMs = scanDurationMs;
    this.suppressionsByRule = suppressionsByRule;
  }

  /**
   * Files the loader chose not to read (currently: oversize). Surfacing this
   * is the difference between a silently-incomplete scan and one the user
   * can act on. Stable shape so downstream tools can render it.
   */
  get skippedFiles(): readonly SkippedFile[] {
    return this.context.skippedFiles;
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
  /**
   * Per-rule wall-clock budget in ms. A rule that exceeds this is aborted
   * (results from that one rule discarded) and a `scanner-internal-error`
   * finding is emitted naming the rule. Defaults to {@link DEFAULT_RULE_TIMEOUT_MS}.
   * Pass `0` to disable the budget entirely (not recommended outside tests).
   */
  ruleTimeoutMs?: number;
  /**
   * Per-file size budget in bytes. Files larger than this are skipped, listed
   * in {@link ProjectScanReport.skippedFiles}, and surfaced via a console
   * warning. `0` disables the cap (every file is loaded — risky on monorepos
   * with vendored bundles). Defaults to 1 MB.
   */
  maxFileSizeBytes?: number;
}

export class ProjectScanner {
  readonly includeSuggestions: boolean;
  readonly disabledRules: ReadonlySet<string>;
  readonly ruleTimeoutMs: number;
  /** Per-file size budget passed to {@link ProjectContext.load}. `undefined` = use loader default. */
  readonly maxFileSizeBytes?: number;

  constructor(includeSuggestionsOrOpts: boolean | ProjectScannerOptions = true) {
    if (typeof includeSuggestionsOrOpts === 'boolean') {
      this.includeSuggestions = includeSuggestionsOrOpts;
      this.disabledRules = new Set();
      this.ruleTimeoutMs = DEFAULT_RULE_TIMEOUT_MS;
      this.maxFileSizeBytes = undefined;
    } else {
      this.includeSuggestions = includeSuggestionsOrOpts.includeSuggestions ?? true;
      this.disabledRules = new Set(includeSuggestionsOrOpts.disabledRules ?? []);
      const t = includeSuggestionsOrOpts.ruleTimeoutMs;
      this.ruleTimeoutMs = t == null ? DEFAULT_RULE_TIMEOUT_MS : Math.max(0, t);
      this.maxFileSizeBytes = includeSuggestionsOrOpts.maxFileSizeBytes;
    }
  }

  async scan(
    rootPath: string,
    onProgress?: (phase: 'loading' | 'rules', detail: string) => void,
  ): Promise<ProjectScanReport> {
    const startTime = Date.now();

    // Reset AST diagnostics for this scan session
    ParserContext.resetDiagnostics();

    const loadOpts: ProjectContextLoadOptions = {};
    if (this.maxFileSizeBytes != null) { loadOpts.maxFileSizeBytes = this.maxFileSizeBytes; }
    const context = await ProjectContext.load(
      rootPath,
      onProgress ? n => onProgress('loading', `Loading files: ${n}`) : undefined,
      loadOpts,
    );
    if (context.skippedFiles.length > 0) {
      const cap = this.maxFileSizeBytes ?? 1024 * 1024;
      const human = ProjectScanner._humanBytes(cap);
      console.error(
        `[SAST] Warning: ${context.skippedFiles.length} file(s) exceeded the ${human} per-file budget and were skipped.`,
      );
      // Log the largest 5 to give the user a useful starting point without
      // spamming the console on a vendored `node_modules`-shaped tree.
      const sorted = [...context.skippedFiles].sort((a, b) => b.sizeBytes - a.sizeBytes);
      for (const sf of sorted.slice(0, 5)) {
        console.error(`[SAST]   ${sf.relativePath} (${ProjectScanner._humanBytes(sf.sizeBytes)})`);
      }
      if (sorted.length > 5) {
        console.error(`[SAST]   …and ${sorted.length - 5} more.`);
      }
    }
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
    const ruleTimeoutMs = this.ruleTimeoutMs;
    const runStage = async (stage: RuleStage) => {
      const stageRules = allRules.filter(r => r.stage === stage);
      const results = await Promise.all(
        stageRules.map(async rule => {
          try {
            const ruleResult = Promise.resolve(rule.evaluate(context));
            if (ruleTimeoutMs > 0) {
              const raced = await ProjectScanner._raceWithTimeout(ruleResult, ruleTimeoutMs);
              if (raced === RULE_TIMEOUT_SENTINEL) {
                console.error(`[SAST] Rule ${rule.code} exceeded ${ruleTimeoutMs}ms budget; aborted.`);
                return [ProjectScanner._timeoutFinding(rule.code, ruleTimeoutMs)];
              }
              return raced;
            }
            return await ruleResult;
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
    const { kept: unsuppressed, suppressedByRule } = applySuppressionWithStats(findings, suppressionCtx);
    const noiseAdjusted = applyNonProductionNoiseReduction(unsuppressed);

    const deduped = ProjectScanner._dedupe(noiseAdjusted);
    deduped.sort(ProjectScanner._compareFindings);

    // Surface noisy rules — anything over the threshold gets a warning so
    // users notice rules they've been silencing en masse.
    for (const [code, count] of suppressedByRule) {
      if (count >= SUPPRESSION_REVIEW_THRESHOLD) {
        console.error(`[SAST] Rule "${code}" had ${count} findings suppressed — consider reviewing its FP rate.`);
      }
    }

    const elapsed = Date.now() - startTime;
    return new ProjectScanReport(
      context, deduped, { ...ParserContext.diagnostics }, elapsed, suppressedByRule,
    );
  }

  /** Pretty-print byte counts ("123 B", "2.5 KB", "1.2 MB"). */
  private static _humanBytes(n: number): string {
    if (n < 1024) { return `${n} B`; }
    if (n < 1024 * 1024) { return `${(n / 1024).toFixed(1)} KB`; }
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  /**
   * Race a rule's promise against a timeout. Resolves to either the rule's
   * Finding[] or {@link RULE_TIMEOUT_SENTINEL}. The timer is cleared on
   * resolution to avoid leaking handles.
   */
  private static _raceWithTimeout(
    p: Promise<Finding[]>,
    ms: number,
  ): Promise<Finding[] | typeof RULE_TIMEOUT_SENTINEL> {
    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<typeof RULE_TIMEOUT_SENTINEL>(resolve => {
      timer = setTimeout(() => resolve(RULE_TIMEOUT_SENTINEL), ms);
    });
    return Promise.race([p, timeoutPromise]).finally(() => {
      if (timer) { clearTimeout(timer); }
    });
  }

  /**
   * Synthetic finding emitted when a rule blows the timeout budget. We surface
   * it like any other so users see *why* a rule produced no results, instead
   * of the rule silently dropping out.
   */
  private static _timeoutFinding(ruleCode: string, ms: number): Finding {
    return new Finding({
      category: FindingCategory.bug,
      code: 'scanner-internal-error',
      severity: FindingSeverity.low,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.heuristic,
      message: `Rule "${ruleCode}" exceeded the ${ms}ms per-rule budget and was aborted.`,
      fix: `Investigate the rule for catastrophic regex / runaway recursion. Increase the budget via "ruleTimeoutMs" only after the root cause is understood.`,
      risk: 'Findings from this rule are missing for the affected scan.',
    });
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
