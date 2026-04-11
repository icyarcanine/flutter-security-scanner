import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { childForFieldName, findNodesByType, getCallName, isAssignment, isFunctionCall, namedChild } from '../../ast/traversal';

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
        const nodes = findNodesByType(astNode, ['assignment_expression', 'call_expression', 'jsx_attribute']);

        for (const node of nodes) {
          const sink = this._sinkName(node, unsafeProperties);
          if (sink) {
            findings.push(new Finding({
              category: FindingCategory.security,
              code: this.code,
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.medium,
              message: `Detected usage of unsafe HTML rendering sink -> ${sink}`,
              fix: 'Avoid direct HTML injection. Rely on safer framework mechanisms (e.g., textContent or standard React binding) or strictly sanitize the input using DOMPurify.',
              risk: 'Cross-Site Scripting (XSS) allows attackers to execute arbitrary scripts in other users\' browsers.',
              filePath: file.relativePath,
              line: node.startPosition.row + 1,
              astUsed: true,
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
}
