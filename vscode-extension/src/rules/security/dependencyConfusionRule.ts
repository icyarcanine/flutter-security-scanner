import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

/**
 * Static npm typosquat detector (§QW-37 / §RC-35).
 *
 * This intentionally uses a tiny high-confidence denylist rather than fuzzy
 * edit-distance. Fuzzy matching creates too many false positives for private
 * packages; exact known-bad names catch the common copy/paste mistakes while
 * staying actionable.
 */
export class DependencyConfusionRule implements Rule {
  readonly code = 'dependency-confusion';
  readonly stage = RuleStage.fast;

  private static readonly _TYPOSQUATS: Record<string, string> = {
    expres: 'express',
    expresss: 'express',
    lodahs: 'lodash',
    loadsh: 'lodash',
    axois: 'axios',
    axiios: 'axios',
    momnet: 'moment',
    monent: 'moment',
    reatc: 'react',
    reactt: 'react',
    'react-domm': 'react-dom',
    vuee: 'vue',
    angualr: 'angular',
    'crossenv': 'cross-env',
    'cross-env.js': 'cross-env',
    'eslintt': 'eslint',
    'prettierx': 'prettier',
  };

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (file.name !== 'package.json') { continue; }
      let pkg: any;
      try {
        pkg = JSON.parse(file.content);
      } catch {
        continue;
      }

      for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        const deps = pkg?.[section];
        if (!deps || typeof deps !== 'object' || Array.isArray(deps)) { continue; }
        for (const name of Object.keys(deps)) {
          const canonical = DependencyConfusionRule._TYPOSQUATS[name];
          if (!canonical) { continue; }
          findings.push(new Finding({
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            detectionMethod: DetectionMethod.config,
            category: FindingCategory.security,
            code: this.code,
            message: `Suspicious npm package \`${name}\` looks like typosquat of \`${canonical}\``,
            fix: `Replace \`${name}\` with \`${canonical}\` if this was a typo. If the package is intentional, pin it exactly and document why it is trusted.`,
            risk: 'Typosquatted npm packages often execute install scripts or ship credential-stealing code under a familiar-looking name.',
            filePath: file.relativePath,
            line: this._lineForDependency(file.content, name),
            cwe: 'CWE-1357',
          }));
        }
      }
    }
    return findings;
  }

  private _lineForDependency(content: string, name: string): number {
    const quoted = `"${name}"`;
    const idx = content.indexOf(quoted);
    if (idx === -1) { return 1; }
    return content.slice(0, idx).split('\n').length;
  }
}
