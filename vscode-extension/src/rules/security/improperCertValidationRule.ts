import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Disabled TLS certificate validation (§QW-5 / §RC-43, CWE-295).
 *
 * Three escape hatches we catch:
 *   1. `rejectUnauthorized: false` — option to https.Agent / axios / got /
 *      request / node-fetch's https.Agent forwarding.
 *   2. `NODE_TLS_REJECT_UNAUTHORIZED = '0'` — process-wide opt-out, the
 *      most blunt of the three.
 *   3. `tls.checkServerIdentity = () => undefined` (or `() => null`) — the
 *      function-shaped no-op when the option above doesn't exist on the
 *      client being used.
 *
 * All three are HIGH severity: shipping any of these to prod converts HTTPS
 * into a cleartext-equivalent channel against an MITM attacker.
 */
export class ImproperCertValidationRule implements Rule {
  readonly code = 'improper-cert-validation';
  readonly stage = RuleStage.fast;

  // Match either object-property or assignment forms:
  //   rejectUnauthorized: false
  //   "rejectUnauthorized": false
  //   agent.rejectUnauthorized = false
  // Works on JS/TS/Dart/Python keyword-arg shapes alike (`reject_unauthorized=False`
  // in Python is rare so we don't try to localize).
  private static readonly _REJECT_UNAUTHORIZED =
    /\b['"]?rejectUnauthorized['"]?\s*[:=]\s*false\b/i;

  // Match the env-var assignment:
  //   process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  //   process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = "0"
  //   NODE_TLS_REJECT_UNAUTHORIZED=0   (in shell / .env)
  private static readonly _NODE_TLS_ENV =
    /\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[:=]?\s*['"]?\s*0\s*['"]?/;

  // Stub `checkServerIdentity` that always returns nothing — bypasses
  // hostname verification:
  //   checkServerIdentity: () => undefined
  //   checkServerIdentity: function() { return null; }
  //   checkServerIdentity: () => {}
  private static readonly _CHECK_SERVER_IDENTITY =
    /\b['"]?checkServerIdentity['"]?\s*[:=]\s*(?:\([^)]*\)\s*=>\s*(?:undefined|null|\{\s*\})|function\s*\([^)]*\)\s*\{\s*return\s+(?:undefined|null)\s*;?\s*\})/;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!ImproperCertValidationRule._isCodeFile(file.name)) { continue; }

      // Single-pass content prefilter to skip 99% of files.
      if (!/rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|checkServerIdentity/.test(file.content)) {
        continue;
      }

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const stripped = ImproperCertValidationRule._stripComment(line, file.name);
        if (!stripped) { continue; }

        if (ImproperCertValidationRule._REJECT_UNAUTHORIZED.test(stripped)) {
          findings.push(this._build(file.relativePath, i + 1,
            'TLS certificate validation disabled via `rejectUnauthorized: false`.',
            'Remove the option or set it to `true`. If the upstream uses a private CA, supply that CA explicitly via the `ca` option instead of disabling verification.'));
          continue; // one finding per line is plenty
        }
        if (ImproperCertValidationRule._NODE_TLS_ENV.test(stripped)) {
          findings.push(this._build(file.relativePath, i + 1,
            '`NODE_TLS_REJECT_UNAUTHORIZED=0` disables certificate validation process-wide.',
            'Never set NODE_TLS_REJECT_UNAUTHORIZED=0 outside local debugging. Use the per-request `ca` option for self-signed dev environments.'));
          continue;
        }
        if (ImproperCertValidationRule._CHECK_SERVER_IDENTITY.test(stripped)) {
          findings.push(this._build(file.relativePath, i + 1,
            'Custom `checkServerIdentity` returns nothing — hostname verification is bypassed.',
            'Remove the override, or implement a real hostname check. Returning undefined/null tells Node "this hostname is fine," which an MITM exploits trivially.'));
        }
      }
    }
    return findings;
  }

  private _build(filePath: string, line: number, message: string, fix: string): Finding {
    return new Finding({
      category: FindingCategory.security,
      code: this.code,
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.regex,
      message,
      fix,
      risk: 'Disabled TLS verification reduces HTTPS to cleartext-against-MITM. An attacker on the network path can intercept and modify all traffic to/from the affected client.',
      filePath,
      line,
      cwe: 'CWE-295',
    });
  }

  private static _isCodeFile(name: string): boolean {
    return /\.(?:js|jsx|ts|tsx|mjs|cjs|dart|env|sh|bash|zsh)$/i.test(name);
  }

  private static _stripComment(line: string, filename: string): string {
    const token = /\.(?:env|sh|bash|zsh)$/i.test(filename) ? '#' : '//';
    return stripLineComment(line, token);
  }
}
