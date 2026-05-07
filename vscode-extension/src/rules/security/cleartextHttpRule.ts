import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Cleartext HTTP transmission flag (§QW-7 / §RC-19, CWE-319).
 *
 * Pattern: a string literal `'http://hostname'` passed to a known network
 * client (`fetch`, `axios`, `https.get`, `request`, `got`, `ky`, `superagent`,
 * `Dio.get` etc.). We require the http URL be inside a call to a recognised
 * client so we don't flag every `'http://example.com'` in test files,
 * fixtures, or doc strings.
 *
 * Loopback (`http://localhost`, `http://127.0.0.1`) is excluded — local-dev
 * servers usually expose plaintext HTTP and that's not a deployable risk.
 *
 * The companion Dart-side `plaintext-http` rule handles `.dart` files. This
 * rule scopes to JS/TS so we don't double-flag.
 */
export class CleartextHttpRule implements Rule {
  readonly code = 'cleartext-http';
  readonly stage = RuleStage.fast;

  /**
   * Network-client call followed by an HTTP URL literal in its first
   * argument. The single capture group holds the URL for downstream
   * decisions ("loopback?" / "host that suggests prod?").
   *
   * The URL host pattern excludes whitespace and `'"` so we don't capture
   * past the closing quote; we then scrub `loopback?` in `_isLocalhost`.
   */
  private static readonly _CLIENT_HTTP =
    /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|delete|patch|head|options|request))?|got(?:\s*\.\s*(?:get|post|put|delete|patch|head|options))?|ky(?:\s*\.\s*(?:get|post|put|delete|patch|head))?|superagent\s*\.\s*\w+|request|https?\s*\.\s*(?:get|request)|XMLHttpRequest\s*\(\s*\)\s*\.\s*open\s*\(\s*['"][A-Z]+['"]\s*,)\s*\(\s*['"]?(http:\/\/[^\s'"`]+)['"]?/i;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      // JS/TS family only — Dart has its own plaintext-http rule.
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      // Cheap content gate before the heavier per-line scan.
      if (!file.content.includes('http://')) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line.includes('http://')) { continue; }

        const m = CleartextHttpRule._CLIENT_HTTP.exec(line);
        if (!m) { continue; }
        const url = m[1];
        if (CleartextHttpRule._isLocalhost(url)) { continue; }

        findings.push(new Finding({
          category: FindingCategory.security,
          code: this.code,
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          detectionMethod: DetectionMethod.regex,
          message: `Network client called with cleartext URL \`${url}\`.`,
          fix: 'Switch to https:// or, if the upstream genuinely speaks HTTP, document why and route through a TLS-terminating proxy. For local dev, prefer 127.0.0.1/localhost so this rule auto-suppresses.',
          risk: 'Cleartext HTTP exposes credentials, session tokens, and request bodies to any on-path attacker (open WiFi, malicious ISPs, broken corporate MITM).',
          filePath: file.relativePath,
          line: i + 1,
          cwe: 'CWE-319',
        }));
      }
    }
    return findings;
  }

  private static _isLocalhost(url: string): boolean {
    // Strip the http:// then take the host portion (before any `:port` or `/path`).
    const after = url.replace(/^http:\/\//i, '');
    const host = after.split(/[/:?#]/, 1)[0]?.toLowerCase() ?? '';
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') {
      return true;
    }
    // 10.x.x.x / 192.168.x.x / 172.16-31.x.x — RFC 1918 ranges, almost always
    // dev/lab and not prod.
    if (/^10(?:\.\d{1,3}){3}$/.test(host)) { return true; }
    if (/^192\.168(?:\.\d{1,3}){2}$/.test(host)) { return true; }
    const m = /^172\.(\d{1,3})(?:\.\d{1,3}){2}$/.exec(host);
    if (m) {
      const second = parseInt(m[1], 10);
      if (second >= 16 && second <= 31) { return true; }
    }
    return false;
  }
}
