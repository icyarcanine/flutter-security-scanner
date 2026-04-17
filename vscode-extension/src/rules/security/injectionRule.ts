import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { IntraProceduralTaintTracker } from '../../taint/dataFlow';

export class InjectionRule implements Rule {
  readonly code = 'injection-flaw';
  readonly stage = RuleStage.taint;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const tracker = new IntraProceduralTaintTracker();

    const sinkPrefilter =
      /\.(?:query|execute|executeQuery|executemany|executescript|raw|rawQuery)\s*\(|\b(?:exec|execSync|execFile|spawn|system|popen|eval|Function)\s*\(|\bProcess\s*\.\s*(?:run|start)\s*\(|document\s*\.\s*write\s*\(|\.(?:innerHTML|outerHTML)\s*=|\brender_template_string\s*\(|\bsubprocess\s*\.\s*(?:run|call|check_output|Popen)\s*\(|\bos\s*\.\s*(?:system|popen)\s*\(|\bfetch\s*\(|\baxios\s*(?:\.\s*(?:get|post|put|delete|patch|head|options|request))?\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\(|\brequests\s*\.\s*(?:get|post|put|delete|patch|head|options|request)\s*\(|\b(?:urllib\s*\.\s*request\s*\.\s*)?urlopen\s*\(|\bfs(?:\s*\.\s*promises)?\s*\.\s*(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|open|openSync|unlink|unlinkSync|stat|statSync|lstat|lstatSync|readdir|readdirSync)\s*\(|\bres\s*\.\s*(?:redirect|location)\s*\(|\bset(?:Timeout|Interval)\s*\(|\$(?:where|function|accumulator)\b|\b(?:c?pickle|_pickle|marshal|yaml)\s*\.\s*(?:loads?|load_all|unsafe_load|full_load)\s*\(|\bxpath\s*\.\s*(?:select1?|evaluate)\s*\(|\.(?:selectSingleNode|selectNodes|search_s|searchEntries?)\s*\(|\bldap(?:client)?\s*\.\s*search\s*\(/i;
    const sourcePrefilter =
      /\b(?:req|request)\s*\??\.\s*(?:body|query|params|args|form|values|json|cookies|headers|files|file|data|query_params|path_params|session|signedCookies|rawHeaders)\b|\b(?:req|request)\s*\[\s*['"](?:body|query|params|file|files|headers|cookies|args|form|session)['"]\s*\]|\bprocess\s*\.\s*(?:env|stdin)\b|\bstdin\b|\b(?:input|userInput|data|payload)\b|\(\s*\{[^}]*\b(?:query|body|params|headers|cookies|signedCookies|session|files|rawHeaders|queryParams|pathParams)\b/i;

    const tierFiles = context.files.filter(f =>
      f.isDart || f.name.endsWith('.js') || f.name.endsWith('.ts') ||
      f.name.endsWith('.tsx') || f.name.endsWith('.jsx') ||
      f.name.endsWith('.py') || f.name.endsWith('.go') || f.name.endsWith('.java')
    );

    for (const file of tierFiles) {
      if (!sinkPrefilter.test(file.content)) {
        continue;
      }

      const needsTaint = sourcePrefilter.test(file.content);
      const hasDynamicSink = /[`+]|document\s*\.\s*write\s*\(|\.(?:innerHTML|outerHTML)\s*=|\b(?:eval|Function)\s*\(/i.test(file.content);
      if (!needsTaint && !hasDynamicSink) {
        continue;
      }

      const astNode = await context.getAst(file);

      // --- AST available: full taint + dynamic sink analysis ---
      if (astNode) {
        const ext = file.name.substring(file.name.lastIndexOf('.'));

        const vulnerableSinks = needsTaint ? tracker.findTaintedSinks(astNode, ext) : [];

        for (const finding of vulnerableSinks) {
          if (finding.isSanitized) continue;

          // Indirect (weakTainted) findings are reported at medium confidence to
          // avoid inflating HIGH counts for long alias chains or Object.assign merges.
          const severity = finding.chainStrength === 'direct'
            ? FindingSeverity.high
            : FindingSeverity.medium;
          const confidence = finding.chainStrength === 'direct'
            ? FindingConfidence.high
            : FindingConfidence.medium;

          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity,
            confidence,
            detectionMethod: DetectionMethod.taint,
            message: `Detected tainted input flowing into ${finding.sinkKind} sink -> ${finding.sinkName}`,
            fix: 'Sanitize input thoroughly before passing it to this function or use parameterized abstractions.',
            risk: 'Unsanitized input reaching SQL, command, code execution, or HTML sinks can let attackers execute code, steal data, or run scripts in user sessions.',
            filePath: file.relativePath,
            line: finding.node.startPosition.row + 1,
            astUsed: true,
          }));
        }

        // All taint-confirmed lines (HIGH or MEDIUM-indirect) suppress duplicate
        // dynamic-AST findings on the same line.
        const highFindingLines = new Set(vulnerableSinks
          .filter(finding => !finding.isSanitized)
          .map(finding => finding.node.startPosition.row + 1));
        const astSinkFindings = tracker.findDynamicAstSinks(astNode, ext);

        for (const finding of astSinkFindings) {
          const line = finding.node.startPosition.row + 1;
          if (finding.isSanitized || highFindingLines.has(line)) continue;

          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            detectionMethod: DetectionMethod.structural,
            message: `Detected dynamic value passed into ${finding.sinkKind} sink -> ${finding.sinkName}`,
            fix: 'Use parameterized APIs, strict validation, or sanitizer/escaping helpers before this sink.',
            risk: 'Dynamic values in security-sensitive sinks are risky unless all inputs are validated or parameterized.',
            filePath: file.relativePath,
            line,
            astUsed: true,
          }));
        }
        continue;
      }

      // --- AST failed: regex fallback (lower confidence) ---
      if (file.astStatus === 'failed') {
        this._regexFallback(file, findings);
      }
    }

    return findings;
  }

  /**
   * Very basic regex-only injection detection. Produces LOW confidence findings.
   * Only runs when AST parsing failed for a file that matched the prefilter.
   */
  private _regexFallback(file: { relativePath: string; content: string; lines: string[] }, findings: Finding[]): void {
    const sinkPattern = /\b(?:exec|execSync|spawn|system|popen|eval|Function)\s*\(|\.(?:query|execute|executeQuery)\s*\(/gi;
    const sourcePattern = /\b(?:req|request)\s*\.\s*(?:body|query|params)\b|\bprocess\s*\.\s*env\b/i;

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (!sinkPattern.test(line)) continue;
      sinkPattern.lastIndex = 0;

      // Check if any source appears within a reasonable window around this sink
      const windowStart = Math.max(0, i - 10);
      const windowEnd = Math.min(file.lines.length - 1, i + 2);
      const window = file.lines.slice(windowStart, windowEnd + 1).join('\n');

      if (sourcePattern.test(window)) {
        // Check for parameterization markers that reduce risk
        const hasParams = /\[\s*\w/.test(line) || /\$\d/.test(line) || /\?\s*,/.test(line);
        if (hasParams) continue;

        findings.push(new Finding({
          category: FindingCategory.security,
          code: this.code,
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          detectionMethod: DetectionMethod.regex,
          message: `Potential injection: sink near user input source (AST unavailable, regex fallback)`,
          fix: 'Ensure user input is sanitized before reaching this sink. Use parameterized queries or safe APIs.',
          risk: 'Without AST confirmation, this finding has lower confidence but may still represent a real vulnerability.',
          filePath: file.relativePath,
          line: i + 1,
          astUsed: false,
        }));
      }
    }
  }
}
