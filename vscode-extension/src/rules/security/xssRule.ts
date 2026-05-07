import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { childForFieldName, findNodesByType, getCallName, isAssignment, isFunctionCall, namedChild } from '../../ast/traversal';
import { findingRangeFromNode } from '../ruleHelpers';

export class XssRule implements Rule {
  readonly code = 'xss-flaw';
  readonly stage = RuleStage.ast;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    const unsafeProperties = new Set(['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML']);

    for (const file of context.files) {
      if (!file.name.endsWith('.js') && !file.name.endsWith('.ts') && !file.name.endsWith('.tsx') && !file.name.endsWith('.jsx')) {
        continue;
      }

      // Fast pre-filter
      if (!/innerHTML|outerHTML|dangerouslySetInnerHTML|document\s*\.\s*write/.test(file.content)) continue;

      const astNode = await context.getAst(file);

      // --- AST path ---
      if (astNode) {
        // Only walk JSX attributes here. Assignment_expression and
        // call_expression cases (`el.innerHTML = …`, `document.write(…)`) are
        // covered by the injection rule's taint engine with HIGH confidence
        // when tainted, and were producing duplicate MEDIUM findings before.
        const nodes = findNodesByType(astNode, ['jsx_attribute']);

        for (const node of nodes) {
          const sink = this._sinkName(node, unsafeProperties);
          if (sink) {
            // If the JSX attribute value textually contains a known untrusted
            // source (`req.body.x`, `req.query.x`, optional-chained variants),
            // escalate to HIGH. JSX attributes are outside the injection
            // rule's call/assignment surface, so we do a structural source
            // check here.
            const tainted = this._sinkValueLooksTainted(node);
            findings.push(new Finding({
              category: FindingCategory.security,
              code: this.code,
              severity: tainted ? FindingSeverity.high : FindingSeverity.medium,
              confidence: tainted ? FindingConfidence.high : FindingConfidence.medium,
              message: `Detected ${tainted ? 'tainted input flowing into ' : 'usage of '}unsafe HTML rendering sink -> ${sink}`,
              fix: 'Avoid direct HTML injection. Rely on safer framework mechanisms (e.g., textContent or standard React binding) or strictly sanitize the input using DOMPurify.',
              risk: 'Cross-Site Scripting (XSS) allows attackers to execute arbitrary scripts in other users\' browsers.',
              filePath: file.relativePath,
              ...findingRangeFromNode(node),
              astUsed: true,
              cwe: 'CWE-79',
            }));
          }
        }
        continue;
      }

      // --- Regex fallback when AST failed ---
      if (file.astStatus === 'failed') {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];
          if (/\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(/.test(line)) {
            // Quick sanitization check
            if (/DOMPurify|sanitize|escapeHtml|textContent/.test(line)) continue;

            findings.push(new Finding({
              category: FindingCategory.security,
              code: this.code,
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.low,
              message: `Potential XSS: unsafe HTML sink detected (AST unavailable, regex fallback)`,
              fix: 'Sanitize content with DOMPurify or use textContent instead of innerHTML.',
              risk: 'Without AST analysis, this is pattern-matched only.',
              filePath: file.relativePath,
              line: i + 1,
              astUsed: false,
              cwe: 'CWE-79',
            }));
          }
        }
      }
    }

    return findings;
  }

  private _sinkName(node: any, unsafeProperties: Set<string>): string | null {
    if (isFunctionCall(node) && getCallName(node).toLowerCase() === 'document.write') {
      return 'document.write';
    }

    if (isAssignment(node)) {
      const left = childForFieldName(node, 'left') ?? namedChild(node, 0);
      const property = left?.text.split('.').pop()?.replace(/\s+/g, '');
      return property && unsafeProperties.has(property) ? property : null;
    }

    if (node.type === 'jsx_attribute') {
      const name = childForFieldName(node, 'name')?.text ?? namedChild(node, 0)?.text ?? '';
      return unsafeProperties.has(name) ? name : null;
    }

    return null;
  }

  /**
   * Returns true if the sink value (RHS of assignment, JSX attribute value,
   * or document.write argument) textually contains a recognizable untrusted
   * source like `req.body.x`, `req.query.x`, optional-chained variants, etc.
   * Used to escalate confidence to HIGH for the JSX dangerouslySetInnerHTML
   * case, where the injection rule's call/assignment-based taint engine
   * cannot reach.
   */
  private _sinkValueLooksTainted(node: any): boolean {
    const valueNode = isAssignment(node)
      ? (childForFieldName(node, 'right') ?? namedChild(node, 1))
      : node.type === 'jsx_attribute'
        ? (childForFieldName(node, 'value') ?? namedChild(node, 1))
        : node; // call expression — check whole call
    if (!valueNode) { return false; }
    const text = valueNode.text ?? '';
    // Recognize common request sources, including optional chaining.
    if (/\b(?:req|request)\s*\??\s*\.\s*(?:body|query|params|args|form|values|json|cookies|headers|files|data|query_params|path_params)\b/.test(text)) {
      return true;
    }
    if (/\b(?:input|userInput|payload)\b/.test(text)) {
      return true;
    }
    return false;
  }
}
