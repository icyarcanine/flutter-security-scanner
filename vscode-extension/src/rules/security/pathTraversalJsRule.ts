import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * JS-side path traversal helper pattern (§QW-27 / §RC-24).
 *
 * Taint analysis already catches attacker-controlled values flowing into
 * fs.readFile/fs.writeFile. This dedicated fast rule catches the dangerous
 * construction site itself: `path.join(__dirname, req.query.file)`. Joining a
 * user-controlled suffix to a base directory does not stop `../` traversal;
 * callers must normalize and enforce that the final path remains under the
 * intended base directory.
 */
export class PathTraversalJsRule implements Rule {
  readonly code = 'path-traversal-js';
  readonly stage = RuleStage.fast;

  private static readonly _JOIN_WITH_DIRNAME =
    /\b(?:path\s*\.\s*)?(?:join|resolve)\s*\(\s*(?:__dirname|process\s*\.\s*cwd\s*\(\s*\))\s*,\s*([^)]*)\)/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\b(?:join|resolve)\s*\(/.test(file.content) || !/\b(?:__dirname|process\s*\.\s*cwd)\b/.test(file.content)) {
        continue;
      }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line) { continue; }
        PathTraversalJsRule._JOIN_WITH_DIRNAME.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = PathTraversalJsRule._JOIN_WITH_DIRNAME.exec(line)) !== null) {
          const suffix = m[1] ?? '';
          if (!PathTraversalJsRule._looksUserControlled(suffix)) { continue; }
          findings.push(new Finding({
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            detectionMethod: DetectionMethod.regex,
            category: FindingCategory.security,
            code: this.code,
            message: 'User-controlled path segment joined to a base directory',
            fix: 'Normalize the final path, then verify it remains under the intended base directory before reading or writing. Reject segments containing `..`, absolute paths, or path separators when only filenames are expected.',
            risk: '`path.join(__dirname, userInput)` still accepts `../` traversal and can escape the intended directory.',
            filePath: file.relativePath,
            line: i + 1,
            cwe: 'CWE-22',
          }));
        }
      }
    }
    return findings;
  }

  private static _looksUserControlled(expr: string): boolean {
    return /\b(?:req|request)\s*(?:\.\s*|\[\s*['"])(?:body|query|params|headers|cookies|files|file|path|url)\b/i.test(expr) ||
      /\b(?:input|userInput|payload|filename|fileName|pathParam|queryParam)\b/i.test(expr);
  }
}
