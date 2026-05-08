export enum FindingSeverity {
  high = 'high',
  medium = 'medium',
  low = 'low',
}

export enum FindingCategory {
  security = 'security',
  config = 'config',
  supabase = 'supabase',
  suggestion = 'suggestion',
  bug = 'bug',
  secrets = 'secrets',
}

export enum FindingConfidence {
  high = 'high',
  medium = 'medium',
  low = 'low',
}

/**
 * How a finding was detected. The tool used to conflate confidence with the
 * detection method and hardcoded "confirmed via taint analysis" for every
 * HIGH finding — including hardcoded secrets and committed `.env` files,
 * which have nothing to do with taint analysis. That was misleading.
 *
 * Detection method is now an explicit per-finding field. Every rule declares
 * how it arrived at its result, and the human-readable reason is derived from
 * both the confidence level AND the detection method so the explanation
 * always tells the truth about what the scanner actually did.
 */
export enum DetectionMethod {
  /** Intra-procedural taint tracking: a recognised source flows into a recognised sink. */
  taint = 'taint',
  /** AST structural match: a specific, unambiguous syntactic shape (e.g. `eval(...)`). */
  structural = 'structural',
  /** Regex match against a known-bad signature (e.g. `AKIA[0-9A-Z]{16}`). */
  regex = 'regex',
  /** Shannon-entropy secret scanning on string literals / assignments. */
  entropy = 'entropy',
  /** Inspected configuration files (AndroidManifest, Info.plist, pubspec, gradle, yaml). */
  config = 'config',
  /** Filesystem state (e.g. `.env` committed to the repo, `build/` present). */
  filesystem = 'filesystem',
  /** Ad-hoc heuristic — lowest-trust signal. */
  heuristic = 'heuristic',
}

export function severityLabel(s: FindingSeverity): string {
  return s.toUpperCase();
}

export function severitySortOrder(s: FindingSeverity): number {
  switch (s) {
    case FindingSeverity.high: return 0;
    case FindingSeverity.medium: return 1;
    case FindingSeverity.low: return 2;
  }
}

export function categoryLabel(c: FindingCategory): string {
  return c.toUpperCase();
}

export function confidenceLabel(c: FindingConfidence): string {
  return c.toUpperCase();
}

export function detectionMethodLabel(m: DetectionMethod): string {
  return m;
}

/**
 * Human-readable explanation of why a finding has its confidence level.
 *
 * The reason is a function of BOTH the confidence level and the detection
 * method — claiming "confirmed via taint analysis" on a regex-matched
 * hardcoded secret would be dishonest. Each (confidence, method) pair gets
 * its own accurate sentence so developers can calibrate their trust.
 */
export function confidenceReason(c?: FindingConfidence, m?: DetectionMethod): string {
  if (c == null) { return 'Confidence not assessed'; }

  const method = m ?? DetectionMethod.heuristic;

  switch (c) {
    case FindingConfidence.high:
      switch (method) {
        case DetectionMethod.taint:
          return 'User-controlled input flows into a dangerous sink (confirmed via intra-procedural taint analysis)';
        case DetectionMethod.structural:
          return 'Unambiguous AST match for a dangerous construct';
        case DetectionMethod.regex:
          return 'Regex match against a known-bad signature with high specificity';
        case DetectionMethod.entropy:
          return 'High-entropy string matching a known credential format';
        case DetectionMethod.config:
          return 'Confirmed from configuration file contents';
        case DetectionMethod.filesystem:
          return 'Confirmed from repository filesystem state';
        case DetectionMethod.heuristic:
          return 'High-confidence heuristic match';
      }
      break;
    case FindingConfidence.medium:
      switch (method) {
        case DetectionMethod.taint:
          return 'Indirect taint flow through an opaque wrapper (not fully confirmed)';
        case DetectionMethod.structural:
          return 'Suspicious AST pattern without data-flow confirmation';
        case DetectionMethod.regex:
          return 'Regex match that may have legitimate uses — review in context';
        case DetectionMethod.entropy:
          return 'Moderately entropic string in a sensitive position';
        case DetectionMethod.config:
          return 'Configuration pattern that is commonly but not always unsafe';
        case DetectionMethod.filesystem:
          return 'Filesystem state that often but not always indicates a problem';
        case DetectionMethod.heuristic:
          return 'Medium-confidence heuristic — verify in context';
      }
      break;
    case FindingConfidence.low:
      switch (method) {
        case DetectionMethod.taint:
          return 'Weak taint signal — may be a false positive';
        case DetectionMethod.structural:
          return 'Structural hint only — verify manually';
        case DetectionMethod.regex:
          return 'Heuristic regex match — may be a false positive, verify manually';
        case DetectionMethod.entropy:
          return 'Entropy-based match — may be a false positive, verify manually';
        case DetectionMethod.config:
          return 'Configuration hint — verify manually';
        case DetectionMethod.filesystem:
          return 'Filesystem hint — verify manually';
        case DetectionMethod.heuristic:
          return 'Low-confidence heuristic — verify manually';
      }
      break;
  }
  return 'Confidence not assessed';
}

export interface FindingOptions {
  category: FindingCategory;
  code: string;
  message: string;
  fix: string;
  risk?: string;
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  /**
   * How this finding was produced. Drives the human-readable confidence
   * explanation so we never claim "taint analysis" on a regex match again.
   */
  detectionMethod?: DetectionMethod;
  filePath?: string;
  line?: number;
  /**
   * Optional precise range info from AST analysis. When all four are present,
   * the diagnostics provider uses them to underline the exact node instead of
   * the entire line. 1-indexed, mirroring `line`.
   */
  endLine?: number;
  column?: number;
  endColumn?: number;
  /** Whether this finding was produced via AST analysis (true) or regex fallback (false) */
  astUsed?: boolean;
  /** CWE identifier(s) (e.g. "CWE-89") for taxonomy / SARIF integration. */
  cwe?: string | string[];
  /**
   * Optional ordered list of provenance steps explaining how data reached
   * the sink. Currently emitted by the taint engine as `[source, sink]`.
   * SARIF maps these to `codeFlows`; the webview renders them as a
   * "Source → Sink" chain under the finding.
   */
  pathSteps?: PathStep[];
  /** Internal source engine marker for telemetry/debugging. */
  engine?: 'ts' | 'rust';
}

/**
 * One node in a data-flow path. Minimal shape — line, optional column, and a
 * human-readable label like "tainted source: req.body.id" or
 * "sink: db.query".
 */
export interface PathStep {
  filePath?: string;
  line: number;
  column?: number;
  label: string;
}

export class Finding {
  readonly severity?: FindingSeverity;
  readonly category: FindingCategory;
  readonly confidence?: FindingConfidence;
  readonly detectionMethod?: DetectionMethod;
  readonly code: string;
  readonly message: string;
  readonly fix: string;
  readonly risk?: string;
  readonly filePath?: string;
  readonly line?: number;
  readonly endLine?: number;
  readonly column?: number;
  readonly endColumn?: number;
  readonly astUsed?: boolean;
  readonly cwe?: string | string[];
  readonly pathSteps?: PathStep[];
  readonly engine?: 'ts' | 'rust';

  constructor(opts: FindingOptions) {
    this.severity = opts.severity;
    this.category = opts.category;
    this.confidence = opts.confidence;
    this.detectionMethod = opts.detectionMethod;
    this.code = opts.code;
    this.message = opts.message;
    this.fix = opts.fix;
    this.risk = opts.risk;
    this.filePath = opts.filePath;
    this.line = opts.line;
    this.endLine = opts.endLine;
    this.column = opts.column;
    this.endColumn = opts.endColumn;
    this.astUsed = opts.astUsed;
    this.cwe = opts.cwe;
    this.pathSteps = opts.pathSteps;
    this.engine = opts.engine;
  }

  static fromRustEngine(o: {
    filePath: string;
    line: number;
    column: number;
    ruleCode: string;
    message: string;
    severity: FindingSeverity;
  }): Finding {
    return new Finding({
      category: FindingCategory.security,
      code: o.ruleCode,
      severity: o.severity,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.taint,
      filePath: o.filePath,
      line: o.line,
      column: o.column,
      message: o.message,
      fix: 'Use parameterized APIs or pass only validated, sanitized values to the sink.',
      risk: 'High-confidence taint flow detected by the Rust analysis kernel.',
      astUsed: true,
      engine: 'rust',
    });
  }

  get isSuggestion(): boolean {
    return this.category === FindingCategory.suggestion;
  }

  get confidenceReason(): string {
    return confidenceReason(this.confidence, this.detectionMethod);
  }

  get locationLabel(): string {
    if (!this.filePath) { return ''; }
    if (this.line == null) { return ` in ${this.filePath}`; }
    return ` in ${this.filePath}:${this.line}`;
  }

  toConsoleBlock(): string {
    const parts: string[] = [];
    if (this.isSuggestion) {
      parts.push(`[${categoryLabel(this.category)}]`);
    } else {
      parts.push(`[${severityLabel(this.severity!)}][${categoryLabel(this.category)}]`);
      if (this.confidence != null) {
        parts.push(`[CONFIDENCE: ${confidenceLabel(this.confidence)}]`);
      }
    }
    parts.push(` ${this.message}${this.locationLabel}`);
    let result = parts.join('');
    result += `\n→ Fix: ${this.fix}`;
    if (this.risk) {
      result += `\n→ Risk: ${this.risk}`;
    }
    return result;
  }
}
