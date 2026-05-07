import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isProductionDartFile, collectLogStatements, isCommentLine } from '../ruleHelpers';

const PLAIN_PRINT_PATTERN = /\bprint\s*\(/;

export class DebugCodeRule implements Rule {
  readonly code = 'debug-print';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.dartFiles) {
      if (!isProductionDartFile(file)) { continue; }
      for (const stmt of collectLogStatements(file)) {
        const sourceLine = file.lines[stmt.startLine - 1];
        if (!PLAIN_PRINT_PATTERN.test(sourceLine)) { continue; }
        if (isCommentLine(sourceLine)) { continue; }
        if (this._looksSensitiveEnough(stmt.argument)) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.low,
          confidence: FindingConfidence.medium,
          category: FindingCategory.config,
          code: this.code,
          message: 'print() left in production code',
          fix: 'Remove the debug print or replace it with structured logging that can be disabled outside development.',
          risk: 'Debug output can leak internal state and increases binary verbosity in production.',
          filePath: file.relativePath,
          line: stmt.startLine,
        }));
      }
    }
    return findings;
  }

  private _looksSensitiveEnough(argument: string): boolean {
    if (/\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken|token)\b/i.test(argument)) {
      return true;
    }
    if (/\.(currentUser|currentSession|accessToken|refreshToken|idToken|jwt)\b/i.test(argument)) {
      return true;
    }
    return /(?<!\w)(?:session|currentUser|currentSession|accessToken|refreshToken)(?!\w)/i.test(argument);
  }
}
