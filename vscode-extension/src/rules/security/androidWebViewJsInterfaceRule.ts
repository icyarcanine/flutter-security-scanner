import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Android WebView JavaScript interface detector (QW-36 / SF-13).
 *
 * `addJavascriptInterface` exposes native methods to page JavaScript. It is
 * only acceptable for tightly controlled first-party content with a minimal
 * bridge surface; with remote or user-influenced pages it becomes a native
 * privilege boundary violation.
 */
export class AndroidWebViewJsInterfaceRule implements Rule {
  readonly code = 'android-webview-js-interface';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:java|kt)$/i.test(file.name)) { continue; }
      if (!/addJava(?:s|S)criptInterface\s*\(/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!/addJava(?:s|S)criptInterface\s*\(/.test(line)) { continue; }
        findings.push(new Finding({
          category: FindingCategory.security,
          code: this.code,
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.regex,
          message: 'Android WebView exposes a native object to JavaScript.',
          fix: 'Avoid `addJavascriptInterface` for pages that can load remote or user-controlled content. If a bridge is required, keep it minimal, require HTTPS first-party origins, and expose only methods annotated for the exact supported API level.',
          risk: 'Injected page JavaScript can call exposed native methods and cross from web content into app privileges.',
          filePath: file.relativePath,
          line: i + 1,
          cwe: 'CWE-749',
        }));
      }
    }
    return findings;
  }
}
