import { Rule } from '../rule';
import { Finding, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext, suggestedPolicyForTable } from '../../scanner/projectContext';

export class RlsPolicySuggestionRule implements Rule {
  readonly code = 'rls-policy-suggestion';

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    const seenTables = new Set<string>();

    for (const access of context.tableAccesses) {
      const normalized = access.table.toLowerCase();
      if (!seenTables.has(normalized)) { seenTables.add(normalized); } else { continue; }

      const confidence = this._confidenceForTable(normalized);
      if (!confidence) { continue; }

      const policy = suggestedPolicyForTable(access.table);
      if (!policy) { continue; }

      findings.push(new Finding({
        category: FindingCategory.suggestion,
        confidence,
        code: this.code,
        message: `Heuristic RLS suggestion for table '${access.table}' (${confidence.toUpperCase()} confidence — verify against your schema)`,
        fix: `Consider: \`${policy}\`  — this is a heuristic; confirm column names match your actual schema before applying.`,
        filePath: access.file.relativePath,
        line: access.line,
      }));
    }
    return findings;
  }

  private _confidenceForTable(normalized: string): FindingConfidence | null {
    switch (normalized) {
      case 'profiles':
      case 'users':
        return FindingConfidence.high;
      case 'posts':
      case 'todos':
      case 'notes':
      case 'orders':
      case 'comments':
      case 'messages':
        return FindingConfidence.medium;
      default:
        return null;
    }
  }
}
