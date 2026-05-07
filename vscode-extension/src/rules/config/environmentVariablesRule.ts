import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { ScannedFile } from '../../scanner/scannedFile';
import { firstReferenceFor } from '../ruleHelpers';

export class EnvironmentVariablesRule implements Rule {
  readonly code = 'missing-env-vars';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    if (!context.usesSupabase) { return []; }

    const configReferenceFiles = [
      ...context.appDartFiles,
      ...context.yamlFiles,
      ...context.envFiles,
    ];

    const findings: Finding[] = [];
    const keys = ['SUPABASE_URL', 'SUPABASE_ANON_KEY'];

    for (const key of keys) {
      const isUsed =
        this._filesContain(configReferenceFiles, new RegExp(`String\\.fromEnvironment\\s*\\(\\s*['"]${key}['"]\\s*\\)`, 'i')) ||
        this._filesContain(configReferenceFiles, new RegExp(`dotenv\\.env\\s*\\[\\s*['"]${key}['"]\\s*\\]`, 'i')) ||
        this._filesContain(configReferenceFiles, new RegExp(`\\b(?:env|Env|config|Config|environment)['"]?${key}['"]?\\b|Platform\\.environment\\s*\\[\\s*['"]${key}['"]\\s*\\]`, 'i')) ||
        context.envEntries.some(e => e.key === key);

      if (!isUsed) { continue; }

      const reference = firstReferenceFor(context, key, configReferenceFiles);
      const hasRealConfig = context.hasEnvFile || context.usesDartDefine || context.usesDotenv;
      const hasOnlyExample = context.hasExampleEnvFile && !hasRealConfig;

      if (hasRealConfig) { continue; }

      if (hasOnlyExample) {
        findings.push(new Finding({
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.config,
          code: this.code,
          message: 'Environment variable used but only example config found',
          fix: 'Create a real .env or provide runtime config via --dart-define.',
          risk: 'App may fail in production due to missing config.',
          filePath: reference?.file.relativePath,
          line: reference?.line,
        }));
      } else {
        findings.push(new Finding({
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.config,
          code: this.code,
          message: 'Environment variable used but no configuration detected',
          fix: 'Add .env or use --dart-define / dotenv.',
          risk: 'Runtime failures due to missing credentials.',
          filePath: reference?.file.relativePath,
          line: reference?.line,
        }));
      }
    }
    return findings;
  }

  private _filesContain(files: ScannedFile[], pattern: RegExp): boolean {
    for (const f of files) {
      if (pattern.test(f.content)) { return true; }
    }
    return false;
  }
}
