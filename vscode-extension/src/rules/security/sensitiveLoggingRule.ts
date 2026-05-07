import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { collectLogStatements } from '../ruleHelpers';

export class SensitiveLoggingRule implements Rule {
  readonly code = 'sensitive-logging';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.appDartFiles) {
      for (const stmt of collectLogStatements(file)) {
        if (!this._looksSensitive(stmt.argument)) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.structural,
          category: FindingCategory.security,
          code: this.code,
          message: 'Sensitive auth or user data is being logged',
          fix: 'Remove the log statement or redact auth/session fields before writing anything to logs.',
          risk: 'Auth tokens and session objects in logs can be harvested from log files, crash reporters, or device storage.',
          filePath: file.relativePath,
          line: stmt.startLine,
          cwe: 'CWE-532',
        }));
      }
    }
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\b(?:console|logger|log|winston|pino|bunyan)\b/.test(file.content) ||
          !/\bprocess\s*\.\s*env\b/.test(file.content)) {
        continue;
      }

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const envName = this._loggedSensitiveEnvName(line);
        if (!envName) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.regex,
          category: FindingCategory.security,
          code: this.code,
          message: `Sensitive environment variable \`process.env.${envName}\` is being logged`,
          fix: 'Remove the log statement or log a redacted marker instead. Secrets from process.env should never be written to application logs.',
          risk: 'Secrets in logs are routinely exported to observability systems, support bundles, crash reports, and long-lived archives.',
          filePath: file.relativePath,
          line: i + 1,
          cwe: 'CWE-532',
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

  private _loggedSensitiveEnvName(line: string): string | null {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
      return null;
    }
    if (!/\b(?:console|logger|log|winston|pino|bunyan)\s*(?:\.\s*)?(?:trace|debug|info|warn|warning|error|fatal|log)\s*\(/i.test(line)) {
      return null;
    }

    const envRe = /\bprocess\s*\.\s*env\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;
    let m: RegExpExecArray | null;
    while ((m = envRe.exec(line)) !== null) {
      const name = m[1];
      if (SensitiveLoggingRule._isSensitiveEnvName(name)) { return name; }
    }
    return null;
  }

  private static _isSensitiveEnvName(name: string): boolean {
    if (/^(?:NODE_ENV|PORT|HOST|HOSTNAME|TZ|DEBUG|LOG_LEVEL|CI)$/i.test(name)) {
      return false;
    }
    if (/^(?:NEXT_PUBLIC_|PUBLIC_|VITE_|REACT_APP_PUBLIC_)/i.test(name)) {
      return false;
    }
    return /(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API[_-]?KEY|AUTH|SESSION|JWT|CREDENTIAL|WEBHOOK|SLACK|STRIPE|TWILIO|SENDGRID|OPENAI|ANTHROPIC)/i
      .test(name);
  }
}
