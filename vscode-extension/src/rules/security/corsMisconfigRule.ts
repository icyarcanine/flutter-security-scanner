import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

/**
 * Detects CORS misconfiguration that effectively disables the protection:
 *   1. `Access-Control-Allow-Origin: *` paired with credentials.
 *   2. `cors({ origin: true, credentials: true })` — Express CORS package
 *      accepts ANY origin with credentials enabled, which is equivalent to
 *      `Allow-Origin: <reflected>` and bypasses CSRF protections.
 *   3. Reflecting `req.headers.origin` straight back into Allow-Origin while
 *      also enabling credentials.
 *
 * CWE-942 — Permissive Cross-domain Policy with Untrusted Domains.
 *
 * Conservative: only fires when both wildcard/origin-reflect AND credentials
 * are present. Plain `Allow-Origin: *` without credentials is intentional in
 * many public APIs and would be a noisy report.
 */
const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;

const CORS_WILDCARD_HEADER = /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/g;
const CORS_CREDENTIALS_HEADER = /Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"](?:true)['"]/g;
const CORS_PACKAGE_BAD = /\bcors\s*\(\s*\{[^}]*?origin\s*:\s*true[^}]*?credentials\s*:\s*true|\bcors\s*\(\s*\{[^}]*?credentials\s*:\s*true[^}]*?origin\s*:\s*true/g;
const CORS_REFLECT_BAD = /['"]Access-Control-Allow-Origin['"]\s*,\s*req(?:uest)?\s*\.\s*headers\s*\.\s*origin/g;

export class CorsMisconfigRule implements Rule {
  readonly code = 'cors-misconfig';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }

      // Pattern 1 — wildcard header AND credentials header in the same file.
      // Without the credentials half, wildcard alone is intentional for public APIs.
      const hasWildcard = CORS_WILDCARD_HEADER.exec(file.content);
      CORS_WILDCARD_HEADER.lastIndex = 0;
      const hasCredentials = CORS_CREDENTIALS_HEADER.exec(file.content);
      CORS_CREDENTIALS_HEADER.lastIndex = 0;
      if (hasWildcard && hasCredentials &&
          !isCommentLine(file.lines[file.lineForOffset(hasWildcard.index) - 1] ?? '')) {
        findings.push(this._make(file.relativePath, file.lineForOffset(hasWildcard.index),
          'CORS allows any origin with credentials enabled',
          'Pin Access-Control-Allow-Origin to a specific origin, or remove Access-Control-Allow-Credentials. The browser blocks `Allow-Origin: *` + credentials, but server-side enforcement should mirror that.',
          'Wildcard origin paired with credentials reflects ambient credentials (cookies, basic auth) to any site that requests them, defeating CSRF protections.'));
      }

      // Pattern 2 — Express `cors` package with origin: true + credentials: true.
      CORS_PACKAGE_BAD.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = CORS_PACKAGE_BAD.exec(file.content)) !== null) {
        const ln = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[ln - 1] ?? '')) { continue; }
        findings.push(this._make(file.relativePath, ln,
          'cors() configured with origin: true AND credentials: true',
          'Pin `origin` to a specific allowlist (string or function returning a verified origin). Never combine `origin: true` with `credentials: true`.',
          'origin:true reflects the request Origin header back. Combined with credentials, this turns CSRF defenses off — any third-party site can call your API with the user\'s cookies.'));
      }

      // Pattern 3 — manual reflection: setHeader('Allow-Origin', req.headers.origin)
      CORS_REFLECT_BAD.lastIndex = 0;
      while ((m = CORS_REFLECT_BAD.exec(file.content)) !== null) {
        const ln = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[ln - 1] ?? '')) { continue; }
        findings.push(this._make(file.relativePath, ln,
          'Allow-Origin reflects request Origin header',
          'Validate the request origin against an allowlist before echoing it back; do not blindly reflect req.headers.origin.',
          'Reflecting the Origin header allows any site to set itself as a trusted origin, defeating same-origin and CSRF protections.'));
      }
    }
    return findings;
  }

  private _make(filePath: string, line: number, message: string, fix: string, risk: string): Finding {
    return new Finding({
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      category: FindingCategory.security,
      code: this.code,
      message,
      fix,
      risk,
      filePath,
      line,
      cwe: 'CWE-942',
    });
  }
}
