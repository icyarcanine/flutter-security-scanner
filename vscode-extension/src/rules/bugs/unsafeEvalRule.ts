import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { findNodesByType, getCallName, isFunctionCall } from '../../ast/traversal';

export class UnsafeEvalRule implements Rule {
  readonly code = 'unsafe-eval';
  readonly stage = RuleStage.ast;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const file of context.files) {
      if (!/\b(?:eval|Function)\s*\(/.test(file.content)) continue;

      const astNode = await context.getAst(file);

      // --- AST path ---
      if (astNode) {
        const calls = findNodesByType(astNode, ['call_expression', 'new_expression', 'expression_statement', 'constructor_invocation']);

        for (const node of calls) {
          if (!isFunctionCall(node)) {
            continue;
          }
          const callName = getCallName(node);
          if (callName === 'eval' || callName === 'Function') {
            findings.push(new Finding({
              category: FindingCategory.bug,
              code: this.code,
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.medium,
              message: `Found direct usage of ${callName}() -> ${node.text.substring(0, 30)}...`,
              fix: `Remove ${callName}() and use safer alternatives like JSON.parse or safe expression parsers.`,
              risk: 'Using dynamic code execution paths is highly dangerous and can allow arbitrary code execution.',
              filePath: file.relativePath,
              line: node.startPosition.row + 1,
              astUsed: true,
            }));
          }
        }
        continue;
      }

      // --- Regex fallback ---
      if (file.astStatus === 'failed') {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];
          const evalMatch = line.match(/\b(eval|Function)\s*\(/);
          if (evalMatch) {
            // Skip if it's in a comment
            const trimmed = line.trimStart();
            if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

            findings.push(new Finding({
              category: FindingCategory.bug,
              code: this.code,
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.low,
              message: `Found usage of ${evalMatch[1]}() (AST unavailable, regex fallback)`,
              fix: `Remove ${evalMatch[1]}() and use safer alternatives.`,
              risk: 'Dynamic code execution is dangerous. Lower confidence due to regex-only detection.',
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
}
