import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { collectLogStatements } from '../ruleHelpers';

/**
 * flutter_secure_storage logging detector (QW-35 / SF-12, CWE-532).
 *
 * `flutter_secure_storage` is normally used for tokens, refresh tokens, and
 * device secrets. Reading from it and then logging the value defeats the
 * point: logs are often exported, synced, or attached to support tickets.
 */
export class SecureStorageLoggingRule implements Rule {
  readonly code = 'secure-storage-logging';
  readonly stage = RuleStage.fast;

  private static readonly _READ_ASSIGN =
    /\b(?:final|var|String\??|dynamic)?\s*([A-Za-z_][\w]*)\s*=\s*(?:await\s*)?(?:[A-Za-z_][\w]*\s*\.\s*)?read\s*\(([^)]*)\)/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.appDartFiles) {
      if (!/flutter_secure_storage|FlutterSecureStorage|\.read\s*\(/.test(file.content)) { continue; }
      const sensitiveVars = this._secureStorageReadVariables(file.content);
      if (sensitiveVars.size === 0 && !/FlutterSecureStorage\s*\(\s*\)\s*\.\s*read\s*\(/.test(file.content)) {
        continue;
      }

      for (const stmt of collectLogStatements(file)) {
        const arg = stmt.argument;
        const loggedVar = Array.from(sensitiveVars).find(name =>
          new RegExp(String.raw`(?:^|[^\w])${name}(?:[^\w]|$)`).test(arg));
        const directRead = /FlutterSecureStorage\s*\(\s*\)\s*\.\s*read\s*\(/.test(arg);
        if (!loggedVar && !directRead) { continue; }
        findings.push(new Finding({
          category: FindingCategory.security,
          code: this.code,
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.regex,
          message: loggedVar
            ? `Value read from flutter_secure_storage is logged via \`${loggedVar}\`.`
            : 'Value read from flutter_secure_storage is logged directly.',
          fix: 'Remove the log or replace it with a constant redacted marker. Do not print secure-storage values, even in debug builds.',
          risk: 'Secure-storage values written to logs can leak through crash reports, adb logs, CI artifacts, and support bundles.',
          filePath: file.relativePath,
          line: stmt.startLine,
          cwe: 'CWE-532',
        }));
      }
    }
    return findings;
  }

  private _secureStorageReadVariables(content: string): Set<string> {
    const vars = new Set<string>();
    SecureStorageLoggingRule._READ_ASSIGN.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SecureStorageLoggingRule._READ_ASSIGN.exec(content)) !== null) {
      const name = m[1] ?? '';
      const args = m[2] ?? '';
      if (this._looksSensitiveName(name) || this._looksSensitiveName(args)) {
        vars.add(name);
      }
    }
    return vars;
  }

  private _looksSensitiveName(text: string): boolean {
    return /token|secret|password|credential|session|jwt|auth|refresh|api[_-]?key/i.test(text);
  }
}
