import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Flags Supabase table operations that are not backed by committed RLS DDL.
///
/// This is intentionally table/operation-specific: one policy elsewhere in
/// the project, or a README comment saying "add RLS later", must not suppress
/// a finding for the table the app actually queries.
class MissingRlsAwarenessRule extends Rule {
  const MissingRlsAwarenessRule();

  @override
  String get code => 'missing-rls-awareness';

  @override
  List<Finding> evaluate(ProjectContext context) {
    if (context.tableAccesses.isEmpty) {
      return const [];
    }

    final findings = <Finding>[];
    final seen = <String>{};
    final level = context.rlsEvidenceLevel;

    for (final access in context.tableAccesses) {
      final table = access.table.toLowerCase();
      final operation = access.operation.toLowerCase();
      if (!seen.add('$table|$operation')) {
        continue;
      }

      if (!context.ddlMetadata.hasRlsEvidenceForTable(table)) {
        findings.add(_missingTableRlsFinding(access, level));
        continue;
      }

      if (!context.ddlMetadata.hasRlsEnabled(table)) {
        findings.add(_policyWithoutEnableFinding(access));
        continue;
      }

      if (!context.ddlMetadata.hasPolicyForOperation(table, operation)) {
        findings.add(_missingOperationPolicyFinding(access));
      }
    }

    return findings;
  }

  Finding _missingTableRlsFinding(
    TableAccess access,
    RlsEvidenceLevel projectEvidence,
  ) {
    final hasOnlyWeakProjectEvidence = projectEvidence == RlsEvidenceLevel.weak;
    return Finding(
      severity: FindingSeverity.high,
      confidence: hasOnlyWeakProjectEvidence
          ? FindingConfidence.medium
          : FindingConfidence.high,
      detectionMethod: FindingDetectionMethod.config,
      category: FindingCategory.supabase,
      code: code,
      message: hasOnlyWeakProjectEvidence
          ? "No verifiable table-level RLS DDL found for '${access.table}'"
          : "Supabase table '${access.table}' is queried but has no committed RLS DDL",
      fix:
          'Commit a migration that enables Row Level Security for `${access.table}` and adds policies for the app operations that touch it.',
      risk:
          'Without table-level RLS, any authenticated or anonymous client allowed by the project API key may read or mutate rows outside its authority.',
      filePath: access.file.relativePath,
      line: access.line,
    );
  }

  Finding _policyWithoutEnableFinding(TableAccess access) {
    return Finding(
      severity: FindingSeverity.high,
      confidence: FindingConfidence.medium,
      detectionMethod: FindingDetectionMethod.config,
      category: FindingCategory.supabase,
      code: code,
      message:
          "RLS policies exist for '${access.table}', but no committed `ENABLE ROW LEVEL SECURITY` was found",
      fix:
          'Add `alter table ${access.table} enable row level security;` to the committed migration that defines the table policies.',
      risk:
          'Postgres policies do not protect a table while RLS is disabled; the app may be relying on policies that are never enforced.',
      filePath: access.file.relativePath,
      line: access.line,
    );
  }

  Finding _missingOperationPolicyFinding(TableAccess access) {
    return Finding(
      severity: FindingSeverity.medium,
      confidence: FindingConfidence.medium,
      detectionMethod: FindingDetectionMethod.config,
      category: FindingCategory.supabase,
      code: code,
      message:
          "No committed RLS policy for `${access.operation}` on '${access.table}'",
      fix:
          'Add a `${access.operation}` policy for `${access.table}` or commit the migration that already defines it. Use `FOR ALL` only when the same rule is correct for every operation.',
      risk:
          'RLS is enabled, but this app operation is not backed by a reviewable policy; it may fail at runtime or rely on an out-of-repo dashboard policy.',
      filePath: access.file.relativePath,
      line: access.line,
    );
  }
}
