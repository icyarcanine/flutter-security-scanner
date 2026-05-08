import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;

/**
 * Detects nested quantifiers in regular expressions, e.g. `(a+)+`.
 *
 * This targets the high-confidence ReDoS class that causes catastrophic
 * backtracking in JavaScript's backtracking regex engine. The pattern is
 * deliberately conservative and only fires when a quantified group contains
 * another quantifier.
 */
export class RedosRule implements Rule {
  readonly code = 'redos';
  readonly stage = RuleStage.fast;

  private static readonly _REGEX_LITERAL = /\/((?:\\.|[^/\\\n])+?)\/[dgimsuvy]*/g;
  private static readonly _NEW_REGEXP = /\bnew\s+RegExp\s*\(\s*(['"`])((?:\\.|(?!\1)[\s\S])*?)\1/g;
  private static readonly _NESTED_QUANTIFIER = /\((?:\\.|[^()\\])*?[+*{](?:\\.|[^()\\])*?\)\s*(?:[+*]|\{\s*\d+\s*,)/;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }
      findings.push(...this._scanRegexLiterals(file));
      findings.push(...this._scanRegExpConstructors(file));
    }
    return findings;
  }

  private _scanRegexLiterals(file: { content: string; lines: string[]; relativePath: string; lineForOffset(offset: number): number }): Finding[] {
    const findings: Finding[] = [];
    RedosRule._REGEX_LITERAL.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = RedosRule._REGEX_LITERAL.exec(file.content)) !== null) {
      const line = file.lineForOffset(match.index);
      if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
      if (!RedosRule._NESTED_QUANTIFIER.test(match[1])) { continue; }
      findings.push(this._finding(file.relativePath, line));
    }
    return findings;
  }

  private _scanRegExpConstructors(file: { content: string; lines: string[]; relativePath: string; lineForOffset(offset: number): number }): Finding[] {
    const findings: Finding[] = [];
    RedosRule._NEW_REGEXP.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = RedosRule._NEW_REGEXP.exec(file.content)) !== null) {
      const line = file.lineForOffset(match.index);
      if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
      if (!RedosRule._NESTED_QUANTIFIER.test(match[2])) { continue; }
      findings.push(this._finding(file.relativePath, line));
    }
    return findings;
  }

  private _finding(filePath: string, line: number): Finding {
    return new Finding({
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.regex,
      category: FindingCategory.security,
      code: this.code,
      message: 'Regular expression contains nested quantifiers that can cause catastrophic backtracking',
      fix: 'Rewrite the expression to avoid nested repetition, cap input length before matching, or use a linear-time regex engine for untrusted input.',
      risk: 'A crafted string can force exponential regex backtracking and pin the event loop, causing denial of service.',
      filePath,
      line,
      cwe: 'CWE-1333',
    });
  }
}
