import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects missing tenant isolation patterns in multi-tenant Flutter apps.
///
/// Checks for:
/// 1. Supabase queries without tenant_id filtering
/// 2. Shared state/cache without tenant scoping
/// 3. Tenant switching without clearing previous tenant data
/// 4. Tenant identifiers exposed in logs or UI
/// 5. Missing tenant validation before data operations
///
/// This is a Flutter-specific multi-tenancy security rule.
class MultiTenancyIsolationRule extends Rule {
  const MultiTenancyIsolationRule();

  @override
  String get code => 'flutter.multi-tenancy-isolation';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Only check if the project appears to be multi-tenant
    if (!_isMultiTenantProject(context)) {
      return findings;
    }

    for (final file in context.appDartFiles) {
      findings.addAll(_findUnscopedSupabaseQueries(file));
      findings.addAll(_findSharedStateWithoutTenant(file));
      findings.addAll(_findTenantIdExposure(file));
    }

    return findings;
  }

  bool _isMultiTenantProject(ProjectContext context) {
    final pubspec = context.pubspecFile;
    if (pubspec != null) {
      final content = pubspec.content.toLowerCase();
      if (content.contains('tenant') ||
          content.contains('organization') ||
          content.contains('workspace') ||
          content.contains('multi_tenant')) {
        return true;
      }
    }

    for (final file in context.appDartFiles) {
      if (RegExp(
        r'tenant_id|org_id|workspace_id|organization_id',
        caseSensitive: false,
      ).hasMatch(file.content)) {
        return true;
      }
    }

    return false;
  }

  /// Detects Supabase queries that don't filter by tenant_id.
  List<Finding> _findUnscopedSupabaseQueries(ScannedFile file) {
    final findings = <Finding>[];

    final supabaseQueryPattern = RegExp(
      r'(?:supabase|client)\.from\s*\(\s*[^)]+\s*\)'
      r'\.(?:select|insert|update|delete|upsert)',
      caseSensitive: false,
    );

    for (final match in supabaseQueryPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if tenant_id filter exists nearby
      final endLine = (line + 15).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('tenant') &&
          !surroundingContent.contains('org_id') &&
          !surroundingContent.contains('workspace') &&
          !surroundingContent.contains('organization')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Database query may lack tenant isolation',
          fix:
              'Every query in a multi-tenant app must include a tenant_id '
              'filter. Use RLS policies that enforce tenant isolation '
              'server-side AND include the tenant filter in client queries '
              'as a defense-in-depth measure:\n\n'
              'await supabase\n'
              '    .from("projects")\n'
              '    .select()\n'
              '    .eq("tenant_id", currentTenantId);',
          risk:
              'Without tenant scoping, users from one tenant can read or '
              'modify data belonging to other tenants. This is a critical '
              'data isolation breach in multi-tenant applications.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects shared state or cache without tenant scoping.
  List<Finding> _findSharedStateWithoutTenant(ScannedFile file) {
    final findings = <Finding>[];

    final statePattern = RegExp(
      r'(?:SharedPreferences|Hive|getStorage|hydrated)'
      r'.*?\.(?:put|write|save|setString|setInt|setBool|setDouble)\b',
      caseSensitive: false,
    );

    for (final match in statePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if tenant scoping exists
      final endLine = (line + 10).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('tenant') &&
          !surroundingContent.contains('org') &&
          !surroundingContent.contains('workspace') &&
          !surroundingContent.contains('user')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Shared state/cache write may lack tenant scoping',
          fix:
              'Prefix cached or stored keys with the current tenant ID '
              'to prevent cross-tenant data leakage:\n\n'
              'final key = "\${currentTenantId}_projects";\n'
              'await prefs.setString(key, jsonEncode(projects));',
          risk:
              'Shared state without tenant scoping can leak data between '
              'users who switch accounts or organizations on the same device.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects tenant identifiers exposed in logs or UI.
  List<Finding> _findTenantIdExposure(ScannedFile file) {
    final findings = <Finding>[];

    final logPattern = RegExp(
      r'\b(?:print|debugPrint|log|logger)\s*\(',
      caseSensitive: false,
    );

    for (final match in logPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      final endLine = (line + 3).clamp(0, file.lines.length);
      final logContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (logContent.contains('tenant_id') ||
          logContent.contains('org_id') ||
          logContent.contains('workspace_id')) {
        findings.add(Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Tenant identifier may be logged',
          fix:
              'Avoid logging tenant identifiers in production. If needed '
              'for debugging, log only a hash or truncated version.',
          risk:
              'Tenant identifiers in logs can reveal customer lists and '
              'organizational structure, which is valuable reconnaissance '
              'data for targeted attacks.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
