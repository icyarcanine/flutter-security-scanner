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

/**
 * Human-readable explanation of why the confidence level was assigned.
 * Designed to build developer trust in findings.
 */
export function confidenceReason(c?: FindingConfidence): string {
  switch (c) {
    case FindingConfidence.high:
      return 'User-controlled input reaches a dangerous sink (confirmed via taint analysis)';
    case FindingConfidence.medium:
      return 'Suspicious pattern detected via AST structural analysis, but no data flow confirmation';
    case FindingConfidence.low:
      return 'Heuristic match (regex or entropy), may be a false positive — verify manually';
    default:
      return 'Confidence not assessed';
  }
}

export interface FindingOptions {
  category: FindingCategory;
  code: string;
  message: string;
  fix: string;
  risk?: string;
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  filePath?: string;
  line?: number;
  /** Whether this finding was produced via AST analysis (true) or regex fallback (false) */
  astUsed?: boolean;
}

export class Finding {
  readonly severity?: FindingSeverity;
  readonly category: FindingCategory;
  readonly confidence?: FindingConfidence;
  readonly code: string;
  readonly message: string;
  readonly fix: string;
  readonly risk?: string;
  readonly filePath?: string;
  readonly line?: number;
  readonly astUsed?: boolean;

  constructor(opts: FindingOptions) {
    this.severity = opts.severity;
    this.category = opts.category;
    this.confidence = opts.confidence;
    this.code = opts.code;
    this.message = opts.message;
    this.fix = opts.fix;
    this.risk = opts.risk;
    this.filePath = opts.filePath;
    this.line = opts.line;
    this.astUsed = opts.astUsed;
  }

  get isSuggestion(): boolean {
    return this.category === FindingCategory.suggestion;
  }

  get confidenceReason(): string {
    return confidenceReason(this.confidence);
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
