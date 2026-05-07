import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

/**
 * Three flavors of JWT misuse:
 *
 * 1. `jwt.decode(...)` instead of `jwt.verify(...)` — `decode` does NOT
 *    validate the signature, so any client-supplied JWT is accepted.
 * 2. `algorithms: ['none']` — explicitly accepts unsigned tokens. Never
 *    intended in production code.
 * 3. `jwt.sign(payload, 'literal-secret', ...)` — hardcoded HMAC secret.
 *
 * Mostly textual / regex-level. AST is not necessary because each pattern
 * is unambiguous when present.
 *
 * CWE-347 — Improper Verification of Cryptographic Signature.
 */
const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;

const JWT_DECODE_PATTERN = /\b(?:jwt|jsonwebtoken|jwt_decode)\s*\.\s*decode\s*\(/g;
const JWT_NONE_ALG_PATTERN = /algorithms\s*:\s*\[\s*['"]none['"]/gi;
const JWT_HARDCODED_SECRET_PATTERN = /\bjwt\s*\.\s*sign\s*\(\s*[^,]+,\s*['"]([^'"]{4,})['"]/g;
// Variable form: `jwt.sign(payload, SECRET, …)` where `SECRET` is an
// identifier — we then look for `const|let|var SECRET = "literal"` in the
// same file (file-local, no cross-file scope).
const JWT_SIGN_VAR_PATTERN = /\bjwt\s*\.\s*sign\s*\(\s*[^,]+,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[,)]/g;
const LITERAL_ASSIGN_TEMPLATE = (name: string) =>
  new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*(?::[^=;]+)?=\\s*['\"]([^'\"]{4,})['\"]\\s*;?`);

export class JwtMisuseRule implements Rule {
  readonly code = 'jwt-misuse';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }

      // 1. jwt.decode without verify
      JWT_DECODE_PATTERN.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = JWT_DECODE_PATTERN.exec(file.content)) !== null) {
        const line = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: this.code,
          message: 'jwt.decode() does not verify the signature',
          fix: 'Use jwt.verify(token, secret, { algorithms: [...] }) so the token signature and algorithm are validated. decode() is only safe for inspecting attacker-controlled payloads after verification.',
          risk: 'Trusting a decoded-but-unverified JWT lets attackers forge claims (impersonate any user, escalate roles).',
          filePath: file.relativePath,
          line,
          cwe: 'CWE-347',
        }));
      }

      // 2. algorithms: ['none']
      JWT_NONE_ALG_PATTERN.lastIndex = 0;
      while ((m = JWT_NONE_ALG_PATTERN.exec(file.content)) !== null) {
        const line = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: this.code,
          message: "JWT verifier accepts algorithm 'none' (unsigned tokens)",
          fix: 'Remove "none" from the algorithms list; restrict to a specific algorithm (e.g. ["HS256"] or ["RS256"]).',
          risk: 'Accepting `alg: none` tokens means any attacker can forge a JWT with arbitrary claims and have it accepted as valid.',
          filePath: file.relativePath,
          line,
          cwe: 'CWE-347',
        }));
      }

      // 3a. jwt.sign with hardcoded literal secret
      JWT_HARDCODED_SECRET_PATTERN.lastIndex = 0;
      while ((m = JWT_HARDCODED_SECRET_PATTERN.exec(file.content)) !== null) {
        const secret = m[1];
        if (/your[-_]?|change[-_]?me|example|todo|xxx/i.test(secret)) { continue; }
        const line = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
        findings.push(this._signFinding(file.relativePath, line));
      }

      // 3b. jwt.sign(payload, SECRET, …) where SECRET is an identifier whose
      //     value is a string literal in the same file. File-local scope
      //     only — not full taint analysis, but catches the common
      //     `const SECRET = "literal"` pattern.
      JWT_SIGN_VAR_PATTERN.lastIndex = 0;
      while ((m = JWT_SIGN_VAR_PATTERN.exec(file.content)) !== null) {
        const varName = m[1];
        // Reserved words / generic placeholders we don't track.
        if (/^(?:secret|key|null|undefined)$/.test(varName)) {
          // Still check those — `SECRET` is a common name. Don't skip.
        }
        const literalAssign = file.content.match(LITERAL_ASSIGN_TEMPLATE(varName));
        if (!literalAssign) { continue; }
        const literal = literalAssign[1];
        if (/your[-_]?|change[-_]?me|example|todo|xxx/i.test(literal)) { continue; }
        const line = file.lineForOffset(m.index);
        if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
        findings.push(this._signFinding(file.relativePath, line,
          `jwt.sign() uses '${varName}' which holds a hardcoded literal in this file`));
      }
    }
    return findings;
  }

  /** Shared finding constructor for the two `jwt.sign` variants. */
  private _signFinding(filePath: string, line: number, message?: string): Finding {
    return new Finding({
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      category: FindingCategory.security,
      code: this.code,
      message: message ?? 'jwt.sign() called with a hardcoded secret string',
      fix: 'Read the JWT signing secret from a secret manager / environment variable, never embed it in source code.',
      risk: 'Hardcoded JWT secrets leak with the source code; anyone with the secret can forge valid tokens.',
      filePath,
      line,
      cwe: 'CWE-798',
    });
  }
}
