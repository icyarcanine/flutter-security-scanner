import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

const SENSITIVE_KEYS = new Set(['SUPABASE_URL', 'SUPABASE_ANON_KEY']);

export class PlaceholderEnvValuesRule implements Rule {
  readonly code = 'placeholder-env-value';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    if (!context.usesSupabase) { return []; }
    const findings: Finding[] = [];
    for (const entry of context.envEntries) {
      if (!SENSITIVE_KEYS.has(entry.key)) { continue; }
      if (entry.file.isEnvTemplateFile) { continue; }
      if (!this._looksLikePlaceholder(entry.value)) { continue; }
      findings.push(new Finding({
        severity: FindingSeverity.low,
        confidence: FindingConfidence.high,
        detectionMethod: DetectionMethod.config,
        category: FindingCategory.config,
        code: this.code,
        message: `${entry.key} appears to be a placeholder value in ${entry.file.name}`,
        fix: 'Replace the placeholder with the real value from your Supabase project settings before running the app.',
        risk: 'Using placeholder configuration values will cause network requests or authentication to fail.',
        filePath: entry.file.relativePath,
        line: entry.line,
      }));
    }
    return findings;
  }

  private _looksLikePlaceholder(value: string): boolean {
    if (!value) { return true; }
    const normalized = value.toLowerCase().trim();
    if (['changeme', 'change_me', 'replace_me', 'replace-me', 'todo',
      'your_key_here', 'your-key-here', 'your_url_here', 'your-url-here'].includes(normalized)) {
      return true;
    }
    if (/^<[^>]+>$/.test(value.trim())) { return true; }
    if (/^[A-Z][A-Z0-9_]+$/.test(value.trim())) { return true; }
    return normalized.includes('your-') || normalized.includes('your_') ||
      normalized.includes('placeholder') || normalized.includes('example') ||
      normalized.includes('xxx');
  }
}
