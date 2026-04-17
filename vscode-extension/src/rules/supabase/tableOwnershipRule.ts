import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext, ownerColumnsForTable, suggestedPolicyForTable } from '../../scanner/projectContext';

export class TableOwnershipRule implements Rule {
  readonly code = 'table-ownership-filter';

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const access of context.tableAccesses) {
      if (access.operation === 'insert') { continue; }
      const expectedColumns = ownerColumnsForTable(access.table);
      if (expectedColumns.size === 0 || access.hasOwnershipFilter) { continue; }
      findings.push(new Finding({
        severity: (access.operation === 'update' || access.operation === 'delete')
          ? FindingSeverity.high
          : FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        detectionMethod: DetectionMethod.structural,
        category: FindingCategory.supabase,
        code: this.code,
        message: `Query on '${access.table}' has no obvious ownership filter`,
        fix: this._fixFor(access.table),
        risk: 'Without an ownership filter, this query may allow clients to read or modify data belonging to other users.',
        filePath: access.file.relativePath,
        line: access.line,
      }));
    }
    return findings;
  }

  private _fixFor(table: string): string {
    const policy = suggestedPolicyForTable(table);
    if (!policy) {
      return 'Add an ownership filter that matches the authenticated user, and enforce the same rule with RLS.';
    }
    const lower = table.toLowerCase();
    if (lower === 'profiles' || lower === 'users') {
      return "Prefer RLS and, when filtering client-side, scope the query to the signed-in user with `.eq('id', supabase.auth.currentUser!.id)`.";
    }
    return `Prefer RLS and, when filtering client-side, scope the query to the signed-in user. A common policy for \`${table}\` is \`${policy}\`.`;
  }
}
