import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Insecure web-storage of credentials (§QW-30 / §RC-55, CWE-922).
 *
 * `localStorage` / `sessionStorage` / `IndexedDB` are XSS-readable. Any
 * payload an attacker can pull through an XSS sink ends up in their hands —
 * if that payload is a session token, JWT, refresh token, password, or API
 * key, the XSS escalates from "execute JS as the user" to "log in as the
 * user from anywhere." The browser-cookie equivalents (httpOnly cookies)
 * are the right place for these.
 *
 * Flag the *key name* — most usages literally say what they're storing.
 * Match conservatively so storing UI preferences ("theme", "lastVisited")
 * doesn't fire.
 */
export class InsecureWebStorageRule implements Rule {
  readonly code = 'insecure-web-storage';
  readonly stage = RuleStage.fast;

  // localStorage.setItem('access_token', x) / window.sessionStorage.setItem('jwt', y)
  // Captures the key in group 1.
  private static readonly _SETITEM =
    /\b(?:window\s*\.\s*)?(?:local|session)Storage\s*\.\s*setItem\s*\(\s*['"]([^'"]+)['"]/g;

  // localStorage['token'] = x / sessionStorage["jwt"] = y
  private static readonly _BRACKET_ASSIGN =
    /\b(?:window\s*\.\s*)?(?:local|session)Storage\s*\[\s*['"]([^'"]+)['"]\s*\]\s*=/g;

  // localStorage.token = x — possible but rare; supports it for completeness.
  private static readonly _PROP_ASSIGN =
    /\b(?:window\s*\.\s*)?(?:local|session)Storage\s*\.\s*([A-Za-z_][\w]*)\s*=(?!=)/g;

  /**
   * Substrings that strongly imply the value is a credential / session token.
   * Match is case-insensitive and substring-based — `accessToken`, `idToken`,
   * `auth.token`, `JWT`, `refreshToken`, `apiKey` all hit. Generic words like
   * `id` or `user` are intentionally not in the list.
   */
  private static readonly _SENSITIVE_KEY_PATTERNS = [
    /token\b/i,
    /\bjwt\b/i,
    /\bsecret\b/i,
    /\bpassword\b/i,
    /\bpasscode\b/i,
    /\bcredential/i,
    /\bauth(?:orization)?\b/i,
    /\bsession(?:id|token)?\b/i,
    /\bapi[._-]?key\b/i,
    /\bbearer\b/i,
    /\brefresh[._-]?token\b/i,
    /\bsecret[._-]?key\b/i,
    /\bprivate[._-]?key\b/i,
  ];

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|html|svelte|vue)$/i.test(file.name)) { continue; }
      if (!/Storage/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line) { continue; }
        for (const re of [
          InsecureWebStorageRule._SETITEM,
          InsecureWebStorageRule._BRACKET_ASSIGN,
          InsecureWebStorageRule._PROP_ASSIGN,
        ]) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(line)) !== null) {
            const key = m[1];
            if (!InsecureWebStorageRule._isSensitiveKey(key)) { continue; }
            findings.push(new Finding({
              category: FindingCategory.security,
              code: this.code,
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.high,
              detectionMethod: DetectionMethod.regex,
              message: `Sensitive key \`${key}\` stored in localStorage / sessionStorage — readable by any XSS payload.`,
              fix: 'Move credentials/tokens out of web storage. Use httpOnly+secure+SameSite cookies for session, or a same-tab in-memory store paired with silent refresh. If client-side persistence is genuinely required, encrypt the value with a key the server controls.',
              risk: 'Web storage is fully accessible to any script that runs in the page — a single XSS exfiltrates the token wholesale.',
              filePath: file.relativePath,
              line: i + 1,
              cwe: 'CWE-922',
            }));
          }
        }
      }
    }
    return findings;
  }

  private static _isSensitiveKey(key: string): boolean {
    return InsecureWebStorageRule._SENSITIVE_KEY_PATTERNS.some(re => re.test(key));
  }
}
