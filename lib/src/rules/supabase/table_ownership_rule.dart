import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class TableOwnershipRule extends Rule {
  const TableOwnershipRule();

  /// Tables with explicit column mappings (high-confidence ownership detection).
  static const _knownTables = {
    'profiles',
    'users',
    'posts',
    'messages',
    'todos',
    'notes',
    'orders',
    'comments',
  };

  /// Any chained filter method in a Supabase query-builder call. We use this
  /// to tell apart "bare `.select()`" (real risk) from "query scoped by some
  /// filter" (unknown-table false-positive on library code).
  static final _anyFilterPattern = RegExp(
    r'''\.(eq|neq|gt|gte|lt|lte|like|ilike|match|is|in_|contains|containedBy|'''
    r'''rangeGt|rangeGte|rangeLt|rangeLte|rangeAdjacent|overlaps|textSearch|'''
    r'''filter|or|not)\s*\(''',
    caseSensitive: false,
  );

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

      final isKnownTable = _knownTables.contains(access.table.toLowerCase());

      // For unknown tables we fall back on generic column-name heuristics
      // (`user_id`, `owner_id`, etc.). Those heuristics produce noise on
      // library/SDK code that legitimately queries internal tables with
      // non-ownership filters. Gate the heuristic: only fire on *unknown*
      // tables when the query has no filter at all. Bare `.select()` on an
      // unknown table (the real high-risk pattern) is still flagged.
      if (!isKnownTable && _anyFilterPattern.hasMatch(access.snippet)) {
        continue;
      }

      findings.add(
        Finding(
          severity: access.operation == 'update' || access.operation == 'delete'
              ? FindingSeverity.high
              : FindingSeverity.medium,
          confidence: isKnownTable
              ? FindingConfidence.medium
              : FindingConfidence.low,
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
