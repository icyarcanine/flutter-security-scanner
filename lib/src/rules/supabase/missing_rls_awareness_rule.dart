import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Flags projects that query Supabase tables but show no evidence of RLS setup.
///
/// Severity and confidence are tiered based on the quality of RLS evidence:
///
/// * **No evidence**  → HIGH severity, HIGH confidence (clear gap).
/// * **Weak evidence** (informal text mention, no SQL DDL) → LOW severity,
///   LOW confidence (might be in progress; human review needed).
/// * **Strong evidence** (CREATE POLICY / ENABLE ROW LEVEL SECURITY DDL, or
///   `auth.uid()` in Dart source) → no finding emitted.
class MissingRlsAwarenessRule extends Rule {
  const MissingRlsAwarenessRule();

  @override
  String get code => 'missing-rls-awareness';

  @override
  List<Finding> evaluate(ProjectContext context) {
    if (context.tableAccesses.isEmpty) {
      return const [];
    }

    final level = context.rlsEvidenceLevel;

    // Strong evidence → the project has DDL or auth.uid() usage; trust it.
    if (level == RlsEvidenceLevel.strong) {
      return const [];
    }

    final firstAccess = context.tableAccesses.first;

    if (level == RlsEvidenceLevel.weak) {
      // Weak evidence: downgrade to LOW severity.  The developer may have
      // RLS in place on the Supabase side but hasn't committed SQL migrations.
      return [
        Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.supabase,
          code: code,
          message:
              'Only informal RLS mentions found — no CREATE POLICY or ENABLE ROW LEVEL SECURITY detected',
          fix:
              'Commit your RLS migration SQL (or check that supabase/migrations/ is included in the scan) so the access model is reviewable locally.',
          risk:
              'Without verifiable RLS policies, it is impossible to audit row-level access control from the source code alone.',
          filePath: firstAccess.file.relativePath,
          line: firstAccess.line,
        ),
      ];
    }

    // No evidence at all → HIGH severity.
    return [
      Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.supabase,
        code: code,
        message:
            'Supabase table queries found but no RLS setup detected anywhere in the project',
        fix:
            'Enable Row Level Security for every table the app touches and commit the policies or migration SQL so the access model is reviewable.',
        risk:
            'Without RLS, any authenticated (or unauthenticated) user can read or mutate data they do not own.',
        filePath: firstAccess.file.relativePath,
        line: firstAccess.line,
      ),
    ];
  }
}
