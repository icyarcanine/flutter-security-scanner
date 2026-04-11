import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

export class CommittedEnvRule implements Rule {
  readonly code = 'committed-env';

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const envFile of context.envFiles) {
      if (envFile.isEnvTemplateFile || context.gitignoreCoversEnvFile(envFile.relativePath)) {
        continue;
      }
      findings.push(new Finding({
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: this.code,
        message: '.env file is present but not ignored by git',
        fix: `Add \`${envFile.name}\` or a \`.env*\` rule to \`.gitignore\` before committing environment files.`,
        risk: 'Checking in `.env` files exposes production secrets or keys to source control history.',
        filePath: envFile.relativePath,
        line: 1,
      }));
    }
    return findings;
  }
}
