import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Symlink-following sink detector (QW-28 / RC-25, CWE-59).
 *
 * User-controlled paths passed directly into file reads/open/stat calls can be
 * redirected through symlinks unless the caller resolves and enforces the final
 * path or opens with a no-follow option. This rule intentionally flags only
 * obvious JS/TS fs calls with attacker-shaped path arguments.
 */
export class SymlinkFollowingRule implements Rule {
  readonly code = 'symlink-following';
  readonly stage = RuleStage.fast;

  private static readonly _FS_CALL =
    /\bfs(?:\s*\.\s*promises)?\s*\.\s*(?:readFile|readFileSync|createReadStream|open|openSync|stat|statSync|lstat|lstatSync)\s*\(\s*([^,\)]+)/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\bfs(?:\s*\.\s*promises)?\s*\./.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line) { continue; }
        SymlinkFollowingRule._FS_CALL.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = SymlinkFollowingRule._FS_CALL.exec(line)) !== null) {
          const pathExpr = m[1] ?? '';
          if (!SymlinkFollowingRule._looksUserControlled(pathExpr)) { continue; }
          if (SymlinkFollowingRule._hasNearbySymlinkGuard(file.lines, i)) { continue; }
          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            detectionMethod: DetectionMethod.regex,
            message: 'User-controlled filesystem path is opened without an obvious symlink guard.',
            fix: 'Resolve the final path with realpath/lstat and verify it remains under the intended root. For opens, prefer O_NOFOLLOW where available and reject symlinks explicitly before reading.',
            risk: 'A malicious symlink can redirect the read/open/stat operation outside the intended directory, exposing or modifying another file.',
            filePath: file.relativePath,
            line: i + 1,
            cwe: 'CWE-59',
          }));
        }
      }
    }
    return findings;
  }

  private static _looksUserControlled(expr: string): boolean {
    return /\b(?:req|request)\s*(?:\.\s*|\[\s*['"])(?:body|query|params|headers|cookies|files|file|path|url)\b/i.test(expr) ||
      /\b(?:userInput|input|payload|upload|filename|fileName|filePath|pathParam|queryParam)\b/i.test(expr);
  }

  private static _hasNearbySymlinkGuard(lines: string[], lineIndex: number): boolean {
    const start = Math.max(0, lineIndex - 4);
    const end = Math.min(lines.length, lineIndex + 3);
    const window = lines.slice(start, end).join('\n');
    return /\b(?:realpath|realpathSync|lstat|lstatSync)\s*\(/.test(window) ||
      /\bO_NOFOLLOW\b|\bnoFollow\b|\bfollowSymlinks\s*:\s*false\b/i.test(window);
  }
}
