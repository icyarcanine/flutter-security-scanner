import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isCommentLine } from '../ruleHelpers';

const SUPPORTED_LANGS = /\.(?:js|jsx|ts|tsx)$/i;

/**
 * Catches high-confidence prototype-pollution assignments.
 *
 * This is intentionally narrow: direct writes through `__proto__`,
 * `constructor.prototype`, or request-controlled object keys in handler code.
 * It does not try to prove every recursive merge case; those belong in a
 * deeper object-flow pass.
 */
export class PrototypePollutionRule implements Rule {
  readonly code = 'prototype-pollution';
  readonly stage = RuleStage.fast;

  private static readonly _EXPLICIT_PROTO_WRITE =
    /(?:\.\s*__proto__|\[\s*['"]__proto__['"]\s*\]|\.\s*constructor\s*\.\s*prototype|\[\s*['"]constructor['"]\s*\]\s*\[\s*['"]prototype['"]\s*\])(?:\s*\[[^\]]+\]|\s*\.[A-Za-z_$][\w$]*)?\s*=/g;

  private static readonly _REQUEST_KEY_WRITE =
    /\b[A-Za-z_$][\w$]*(?:\s*\[[^\]]+\]|\s*\.[A-Za-z_$][\w$]*)*\s*\[\s*(?:req|request)\s*(?:\.|\[\s*['"])(?:body|query|params|headers|cookies|args|form|data|payload|json|files?)(?:['"]\s*\])?(?:[^\]]*)\]\s*=/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!SUPPORTED_LANGS.test(file.relativePath)) { continue; }
      findings.push(...this._scanPattern(file, PrototypePollutionRule._EXPLICIT_PROTO_WRITE, 'Prototype object is written directly'));
      findings.push(...this._scanPattern(file, PrototypePollutionRule._REQUEST_KEY_WRITE, 'Request-controlled property name is written into an object'));
    }
    return findings;
  }

  private _scanPattern(file: { content: string; lines: string[]; relativePath: string; lineForOffset(offset: number): number }, pattern: RegExp, message: string): Finding[] {
    const findings: Finding[] = [];
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(file.content)) !== null) {
      const line = file.lineForOffset(match.index);
      if (isCommentLine(file.lines[line - 1] ?? '')) { continue; }
      findings.push(new Finding({
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        detectionMethod: DetectionMethod.regex,
        category: FindingCategory.security,
        code: this.code,
        message,
        fix: 'Reject keys named `__proto__`, `prototype`, and `constructor` before assigning into objects. Prefer schema validation and safe merge utilities that create null-prototype objects.',
        risk: 'Prototype pollution lets attackers modify Object.prototype-derived state, which can bypass authorization checks, corrupt configuration, or trigger later code execution paths.',
        filePath: file.relativePath,
        line,
        cwe: 'CWE-1321',
      }));
    }
    return findings;
  }
}
