import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { collectLogStatements } from '../ruleHelpers';

export class SensitiveLoggingRule implements Rule {
  readonly code = 'sensitive-logging';

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.appDartFiles) {
      for (const stmt of collectLogStatements(file)) {
        if (!this._looksSensitive(stmt.argument)) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: this.code,
          message: 'Sensitive auth or user data is being logged',
          fix: 'Remove the log statement or redact auth/session fields before writing anything to logs.',
          risk: 'Auth tokens and session objects in logs can be harvested from log files, crash reporters, or device storage.',
          filePath: file.relativePath,
          line: stmt.startLine,
        }));
      }
    }
    return findings;
  }

  private _looksSensitive(argument: string): boolean {
    const compact = argument.replace(/\s/g, '');
    if (['session', 'token', 'currentUser', 'currentSession'].includes(compact)) { return true; }

    if (/\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken)\b/i.test(argument)) {
      return true;
    }

    const stripped = argument
      .replace(/"(?:[^"\\]|\\.)*"/g, '')
      .replace(/'(?:[^'\\]|\\.)*'/g, '');

    return /(?<!\w)(session|accessToken|refreshToken|jwt|idToken|currentUser|currentSession|authState|authorization)(?!\w)|\.(currentUser|currentSession|accessToken|refreshToken|idToken)\b/i
      .test(stripped);
  }
}
