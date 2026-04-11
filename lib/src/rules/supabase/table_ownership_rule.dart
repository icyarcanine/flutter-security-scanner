import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class TableOwnershipRule extends Rule {
  const TableOwnershipRule();

  @override
  String get code => 'table-ownership-filter';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final access in context.tableAccesses) {
      if (access.operation == 'insert') {
        continue;
      }

      final expectedColumns = ownerColumnsForTable(access.table);
      if (expectedColumns.isEmpty || access.hasOwnershipFilter) {
        continue;
      }

      findings.add(
        Finding(
          severity: access.operation == 'update' || access.operation == 'delete'
              ? FindingSeverity.high
              : FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.supabase,
          code: code,
          message: "Query on '${access.table}' has no obvious ownership filter",
          fix: _fixFor(access.table),
          risk:
              'Without an ownership filter, this query may allow clients to read or modify data belonging to other users.',
          filePath: access.file.relativePath,
          line: access.line,
        ),
      );
    }

    return findings;
  }

  String _fixFor(String table) {
    final policy = suggestedPolicyForTable(table);
    if (policy == null) {
      return 'Add an ownership filter that matches the authenticated user, and enforce the same rule with RLS.';
    }

    if (table.toLowerCase() == 'profiles' || table.toLowerCase() == 'users') {
      return 'Prefer RLS and, when filtering client-side, scope the query to the signed-in user with `.eq(\'id\', supabase.auth.currentUser!.id)`.';
    }

    return 'Prefer RLS and, when filtering client-side, scope the query to the signed-in user. A common policy for `$table` is `$policy`.';
  }
}
