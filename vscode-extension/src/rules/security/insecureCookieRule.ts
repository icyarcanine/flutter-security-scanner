import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

/**
 * Detects Express/Koa/Hapi-style `cookie(...)` calls that explicitly set
 * insecure flag values:
 *
 *   res.cookie('sid', value, { httpOnly: false, ... })  // CWE-1004
 *   res.cookie('sid', value, { secure: false, ... })    // CWE-614
 *   res.cookie('sid', value, { sameSite: 'none', secure: false })  // CSRF risk
 *
 * Conservative: only fires when the flag is *literally* `false` / `'none'`.
 * Missing flags ("forgot to set httpOnly") are not flagged because that
 * inflates noise on trivial test fixtures and one-off cookies.
 *
 * CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag.
 * CWE-614  — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute.
 */
const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;
// Locate the start of `res.cookie(`-style calls; the brace-balanced extractor
// walks forward to capture options regardless of nesting.
const COOKIE_CALL_START = /\b(?:res|reply|ctx)\s*\.\s*cookie\s*\(/g;

/**
 * Extract the *first* brace-balanced `{ … }` object literal that appears
 * after `start` and before the call's closing paren. Skips nested objects
 * and quoted strings so things like `domain: { a: 1 }` don't truncate the
 * options. Returns the inner-text (without the outer braces) or null if no
 * options object is found before the call closes.
 */
function extractCookieOptions(content: string, start: number): string | null {
  let i = start;
  let depth = 1; // we start AFTER the opening `(` of the call
  let inSingle = false, inDouble = false, inTemplate = false, escaped = false;

  while (i < content.length) {
    const ch = content[i];
    if (escaped) { escaped = false; i++; continue; }
    if (ch === '\\' && (inSingle || inDouble || inTemplate)) { escaped = true; i++; continue; }
    if (!inDouble && !inTemplate && ch === "'") { inSingle = !inSingle; i++; continue; }
    if (!inSingle && !inTemplate && ch === '"') { inDouble = !inDouble; i++; continue; }
    if (!inSingle && !inDouble && ch === '`') { inTemplate = !inTemplate; i++; continue; }
    if (inSingle || inDouble || inTemplate) { i++; continue; }

    if (ch === '(') { depth++; i++; continue; }
    if (ch === ')') {
      depth--;
      if (depth === 0) { return null; }   // closed call without seeing `{`
      i++; continue;
    }
    if (ch === '{') {
      // Found the start of an options object — extract balanced contents.
      const startBrace = i;
      let braceDepth = 1;
      i++;
      let bs = false, bd = false, bt = false, esc = false;
      while (i < content.length && braceDepth > 0) {
        const c = content[i];
        if (esc) { esc = false; i++; continue; }
        if (c === '\\' && (bs || bd || bt)) { esc = true; i++; continue; }
        if (!bd && !bt && c === "'") { bs = !bs; i++; continue; }
        if (!bs && !bt && c === '"') { bd = !bd; i++; continue; }
        if (!bs && !bd && c === '`') { bt = !bt; i++; continue; }
        if (bs || bd || bt) { i++; continue; }
        if (c === '{') { braceDepth++; }
        else if (c === '}') { braceDepth--; }
        i++;
      }
      // Inner text excludes the outermost braces.
      return content.slice(startBrace + 1, i - 1);
    }
    i++;
  }
  return null;
}

export class InsecureCookieRule implements Rule {
  readonly code = 'insecure-cookie';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }
      COOKIE_CALL_START.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = COOKIE_CALL_START.exec(file.content)) !== null) {
        const callStart = m.index + m[0].length; // position after the opening `(`
        const opts = extractCookieOptions(file.content, callStart);
        if (opts == null) { continue; }
        const line = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }

        if (/\bhttpOnly\s*:\s*false\b/.test(opts)) {
          findings.push(this._make(file.relativePath, line,
            'Cookie set with httpOnly: false',
            'Set `httpOnly: true` (the default in most frameworks) so client-side JS cannot read the cookie value. Removing the flag entirely is also acceptable when the framework defaults to true.',
            'Cookies readable by JavaScript can be stolen by XSS payloads, leading to session hijacking.',
            'CWE-1004'));
        }

        if (/\bsecure\s*:\s*false\b/.test(opts)) {
          findings.push(this._make(file.relativePath, line,
            'Cookie set with secure: false',
            'Set `secure: true` so the browser only sends this cookie over HTTPS.',
            'Cookies sent over HTTP can be sniffed on shared networks; an attacker with passive network access steals the session.',
            'CWE-614'));
        }

        if (/sameSite\s*:\s*['"]none['"]/.test(opts) && !/\bsecure\s*:\s*true\b/.test(opts)) {
          findings.push(this._make(file.relativePath, line,
            'Cookie sameSite: "none" without secure: true',
            'Browsers reject cross-site cookies with sameSite=none unless secure=true. Set secure: true alongside, or use sameSite: "lax".',
            'sameSite: none disables CSRF protections; pairing it with secure: false (or omitted) opens the cookie to passive sniffing AND CSRF.',
            'CWE-352'));
        }

        // §QW-31 / §RC-45 — leading-dot domain scopes the cookie to every
        // subdomain. That's almost always wider than needed; if a single
        // subdomain is XSS'd the auth cookie travels to it. Modern browsers
        // ignore the leading dot but the scope expansion remains.
        const domainMatch = /\bdomain\s*:\s*['"](\.[\w.-]+)['"]/i.exec(opts);
        if (domainMatch) {
          findings.push(this._make(file.relativePath, line,
            `Cookie scoped to "${domainMatch[1]}" — broader than the current host (leading-dot includes every subdomain).`,
            'Drop the `domain` option (cookie defaults to the host that set it) or scope to the exact subdomain that needs it. Wider scope means an XSS on any subdomain steals the cookie.',
            'A broad cookie domain expands the blast radius of XSS / subdomain takeover; one compromised subdomain reads the cookie everyone uses.',
            'CWE-732'));
        }
      }
    }
    return findings;
  }

  private _make(filePath: string, line: number, message: string, fix: string, risk: string, cwe: string): Finding {
    return new Finding({
      severity: FindingSeverity.medium,
      confidence: FindingConfidence.high,
      category: FindingCategory.security,
      code: this.code,
      message,
      fix,
      risk,
      filePath,
      line,
      cwe,
    });
  }
}
