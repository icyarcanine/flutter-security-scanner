import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext, RlsEvidenceLevel } from '../../scanner/projectContext';

export class MissingRlsAwarenessRule implements Rule {
  readonly code = 'missing-rls-awareness';

  evaluate(context: ProjectContext): Finding[] {
    if (context.tableAccesses.length === 0) { return []; }
    const level = context.rlsEvidenceLevel;
    if (level === RlsEvidenceLevel.strong) { return []; }

    const firstAccess = context.tableAccesses[0];

    if (level === RlsEvidenceLevel.weak) {
      return [new Finding({
        severity: FindingSeverity.low,
        confidence: FindingConfidence.low,
        category: FindingCategory.supabase,
        code: this.code,
        message: 'Only informal RLS mentions found — no CREATE POLICY or ENABLE ROW LEVEL SECURITY detected',
        fix: 'Commit your RLS migration SQL (or check that supabase/migrations/ is included in the scan) so the access model is reviewable locally.',
        risk: 'Without verifiable RLS policies, it is impossible to audit row-level access control from the source code alone.',
        filePath: firstAccess.file.relativePath,
        line: firstAccess.line,
      })];
    }

    return [new Finding({
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      category: FindingCategory.supabase,
      code: this.code,
      message: 'Supabase table queries found but no RLS setup detected anywhere in the project',
      fix: 'Enable Row Level Security for every table the app touches and commit the policies or migration SQL so the access model is reviewable.',
      risk: 'Without RLS, any authenticated (or unauthenticated) user can read or mutate data they do not own.',
      filePath: firstAccess.file.relativePath,
      line: firstAccess.line,
    })];
  }
}
