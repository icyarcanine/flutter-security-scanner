import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

export class MultipleSupabaseClientsRule implements Rule {
  readonly code = 'multiple-supabase-clients';

  evaluate(context: ProjectContext): Finding[] {
    const locations = context.supabaseClientLocations;
    if (locations.length <= 1) { return []; }
    const location = locations[1];
    const total = locations.length;
    return [new Finding({
      severity: FindingSeverity.low,
      confidence: FindingConfidence.high,
      category: FindingCategory.config,
      code: this.code,
      message: `${total} direct SupabaseClient(...) instances detected (first duplicate shown)`,
      fix: 'Create the client once and share it via a singleton, provider, or dependency injection so session state stays consistent.',
      risk: 'Multiple client instances can lead to desynchronized auth states and redundant network requests.',
      filePath: location.file.relativePath,
      line: location.line,
    })];
  }
}
