import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Python format-string injection detector (QW-44 / RC-27, CWE-134).
 *
 * Flags direct sink calls where `%` formatting or f-strings combine a format
 * string with request/input data. Parameterized DB calls stay clean because
 * they pass values as a separate argument instead of formatting the SQL.
 */
export class PythonFormatInjectionRule implements Rule {
  readonly code = 'python-format-injection';
  readonly stage = RuleStage.fast;

  private static readonly _SINK =
    /\b(?:cursor|conn|connection|db|session)\s*\.\s*(?:execute|executemany|executescript)\s*\(|\b(?:os\s*\.\s*system|subprocess\s*\.\s*(?:run|call|check_output|Popen))\s*\(|\b(?:logging|logger)\s*\.\s*(?:debug|info|warning|warn|error|critical|exception)\s*\(|\bprint\s*\(/i;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.py$/i.test(file.name)) { continue; }
      if (!/%|f['"]|f""\"|f'''/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i], '#');
        if (!PythonFormatInjectionRule._SINK.test(line)) { continue; }
        const kind = this._formatInjectionKind(line);
        if (!kind) { continue; }
        const commandOrSql = /\b(?:execute|executemany|executescript|os\s*\.\s*system|subprocess\s*\.)/i.test(line);
        findings.push(new Finding({
          category: FindingCategory.security,
          code: this.code,
          severity: commandOrSql ? FindingSeverity.high : FindingSeverity.medium,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.regex,
          message: `Python ${kind} formatting combines user-controlled data inside a sink call.`,
          fix: commandOrSql
            ? 'Use parameterized SQL / argument arrays instead of string formatting. For commands, pass an argv list with `shell=False` and validate each argument.'
            : 'Log structured fields separately or sanitize line breaks/control characters before logging user data.',
          risk: commandOrSql
            ? 'Formatting attacker data into SQL or shell strings can become injection when quoting, escaping, or command boundaries are wrong.'
            : 'Formatted user data in logs can forge records or leak unexpected request content.',
          filePath: file.relativePath,
          line: i + 1,
          cwe: 'CWE-134',
        }));
      }
    }
    return findings;
  }

  private _formatInjectionKind(line: string): 'percent' | 'f-string' | null {
    if (/%\s*(?:request\s*\.\s*(?:args|form|values|json|data|cookies|headers)|input\s*\(|sys\s*\.\s*argv|os\s*\.\s*environ)/.test(line)) {
      return 'percent';
    }
    if (/\bf(?:r)?['"`][^'"`]*\{[^}]*?(?:request\s*\.\s*(?:args|form|values|json|data|cookies|headers)|input\s*\(|sys\s*\.\s*argv|os\s*\.\s*environ)/.test(line)) {
      return 'f-string';
    }
    return null;
  }
}
