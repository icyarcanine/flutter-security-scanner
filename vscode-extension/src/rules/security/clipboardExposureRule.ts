import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Clipboard exposure of sensitive payloads on the JS side
 * (§QW-46 / §RC-56, CWE-359).
 *
 * Pattern: `navigator.clipboard.writeText(<value>)` or the older
 * `document.execCommand('copy')` flow, where the copied value names a
 * secret. Any other browser tab — and on most OSes any other process —
 * can read the clipboard. Auto-copying tokens / passwords on click is a
 * routine UX anti-pattern that occasionally leaks credentials to other
 * apps users have running.
 *
 * We match on identifier *name*, not value, because at scan time we can
 * see what variable a copy uses but not what's inside. False positives
 * are managed by requiring the identifier to look credential-shaped
 * (`token`, `secret`, `password`, etc.) — a `clipboard.writeText(url)` or
 * `clipboard.writeText(name)` would not fire.
 */
export class ClipboardExposureRule implements Rule {
  readonly code = 'clipboard-exposure';
  readonly stage = RuleStage.fast;

  // Substring match (no leading \b) so compound names like `accessToken`,
  // `refreshToken`, `apiKey` are caught. Each pattern still has tail
  // anchors / word-boundaries where ambiguity matters.
  private static readonly _SENSITIVE_IDENT =
    /(?:token|secret|password|passcode|passphrase|jwt|apikey|api[._-]?key|authkey|privatekey|sessionid|otp|seed|mnemonic|credential|bearer|refresh[._-]?token)/i;

  private static readonly _CLIPBOARD_CALL =
    /\bnavigator\s*\.\s*clipboard\s*\.\s*writeText\s*\(\s*([^)]*?)\)/g;

  /**
   * Older copy-via-textarea flow: a hidden textarea + select() +
   * `document.execCommand('copy')`. We can't trace the copied value
   * statically, so flag the call site itself with a low-confidence
   * suggestion.
   */
  private static readonly _EXEC_COMMAND_COPY =
    /\bdocument\s*\.\s*execCommand\s*\(\s*['"]copy['"]/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|svelte|vue)$/i.test(file.name)) { continue; }
      if (!/clipboard|execCommand/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line) { continue; }

        ClipboardExposureRule._CLIPBOARD_CALL.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = ClipboardExposureRule._CLIPBOARD_CALL.exec(line)) !== null) {
          const arg = m[1];
          if (!ClipboardExposureRule._SENSITIVE_IDENT.test(arg)) { continue; }
          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            detectionMethod: DetectionMethod.regex,
            message: `Sensitive value (\`${ClipboardExposureRule._extractIdent(arg)}\`) copied to the clipboard.`,
            fix: 'Don\'t auto-copy tokens / passwords. If a copy button is required, document the risk in UI and clear the clipboard a few seconds after copy via a setTimeout that overwrites with empty text.',
            risk: 'Other tabs and (on most OSes) other apps can read the system clipboard for an unbounded time after copy.',
            filePath: file.relativePath,
            line: i + 1,
            cwe: 'CWE-359',
          }));
        }

        ClipboardExposureRule._EXEC_COMMAND_COPY.lastIndex = 0;
        if (ClipboardExposureRule._EXEC_COMMAND_COPY.test(line)) {
          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity: FindingSeverity.low,
            confidence: FindingConfidence.low,
            detectionMethod: DetectionMethod.regex,
            message: 'Legacy `document.execCommand("copy")` flow — confirm what\'s being copied is not a credential.',
            fix: 'Switch to the async clipboard API (navigator.clipboard.writeText) and confirm the copied payload contains no tokens.',
            risk: 'execCommand("copy") copies the current selection — easy to leak a secret if the selection happens to span one.',
            filePath: file.relativePath,
            line: i + 1,
            cwe: 'CWE-359',
          }));
        }
      }
    }
    return findings;
  }

  /** Extract the most token-like identifier from an arg expression. */
  private static _extractIdent(arg: string): string {
    const identifiers = arg.match(/[A-Za-z_$][\w$]*/g) ?? [];
    const sensitiveIdentifier = identifiers.find(ident =>
      ClipboardExposureRule._SENSITIVE_IDENT.test(ident));
    if (sensitiveIdentifier) { return sensitiveIdentifier; }

    const m = ClipboardExposureRule._SENSITIVE_IDENT.exec(arg);
    return m ? m[0] : arg.trim();
  }
}
