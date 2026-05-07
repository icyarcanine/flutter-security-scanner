import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

/**
 * Detects `Math.random()` used in *security-sensitive* contexts. The bare
 * function isn't dangerous on its own, so we only flag when the result feeds
 * into a security-flavored variable name (token, secret, key, password,
 * salt, otp, csrf, session, etc.) within a small window.
 *
 * Catches the classic vulnerability:
 *   const token = Math.random().toString(36).slice(2);
 *   const sessionId = Math.random();
 *
 * False-positive guard: requires a sensitive identifier on the same line OR
 * within 2 lines above (assignment patterns) to avoid flagging
 * `const x = Math.random();` in non-security code.
 *
 * CWE-338 — Use of Cryptographically Weak PRNG.
 */
const SENSITIVE_IDENTIFIER_PATTERN = /\b(token|secret|password|passwd|apikey|api_key|key|salt|nonce|otp|csrf|xsrf|session(?:id)?|sid|auth(?:code)?)\b/i;
const MATH_RANDOM_PATTERN = /\bMath\.random\s*\(\s*\)/g;
const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;

export class InsecureRandomRule implements Rule {
  readonly code = 'insecure-random';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }
      MATH_RANDOM_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = MATH_RANDOM_PATTERN.exec(file.content)) !== null) {
        const lineNum = file.lineForOffset(match.index);
        const lineText = file.lines[lineNum - 1] ?? '';
        // Skip commented-out code so `// const token = Math.random()` doesn't
        // produce a finding the developer was actively reviewing-out.
        if (isCommentLine(lineText)) { continue; }
        // Only inspect the current line. Looking back risks false positives
        // when an unrelated security identifier appears on a nearby line.
        // Multi-line wrapped assignments (where the LHS is on the previous
        // line) are deliberately not handled — false-negative is preferred
        // over false-positive for a high-severity rule.
        if (!SENSITIVE_IDENTIFIER_PATTERN.test(lineText)) { continue; }

        findings.push(new Finding({
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: this.code,
          message: 'Math.random() used to generate a security-sensitive value',
          fix: 'Use crypto.randomBytes(...).toString(\'hex\') (Node) or crypto.getRandomValues(new Uint8Array(...)) (browser) for tokens, salts, session IDs, and keys.',
          risk: 'Math.random() is a non-cryptographic PRNG; outputs are predictable from a small number of samples, allowing attackers to forge tokens/sessions.',
          filePath: file.relativePath,
          line: lineNum,
          cwe: 'CWE-338',
        }));
      }
    }
    return findings;
  }
}
