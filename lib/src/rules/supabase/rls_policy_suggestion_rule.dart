import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Emits heuristic RLS policy suggestions for tables the app accesses.
///
/// Suggestions are only shown for tables with HIGH or MEDIUM confidence
/// mappings (i.e. well-known tables in [suggestedPolicyForTable]).
/// Unknown tables get no suggestion — a wrong suggestion is worse than silence.
class RlsPolicySuggestionRule extends Rule {
  const RlsPolicySuggestionRule();

  @override
  String get code => 'rls-policy-suggestion';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];
    final seenTables = <String>{};

    for (final access in context.tableAccesses) {
      final normalized = access.table.toLowerCase();
      if (!seenTables.add(normalized)) {
        continue;
      }

      final confidence = _confidenceForTable(context, normalized);

      // Only emit for HIGH or MEDIUM confidence tables — skip unknowns.
      if (confidence == null) {
        continue;
      }

      final policy = suggestedPolicyForTable(
        access.table,
        ddl: context.ddlMetadata,
      );
      if (policy == null) {
        continue;
      }

      findings.add(
        Finding(
          category: FindingCategory.suggestion,
          confidence: confidence,
          code: code,
          message:
              "Heuristic RLS suggestion for table '${access.table}' "
              '(${confidence.label} confidence — verify against your schema)',
          fix:
              'Consider: `$policy`  — this is a heuristic; confirm column names match your actual schema before applying.',
          filePath: access.file.relativePath,
          line: access.line,
        ),
      );
    }

    return findings;
  }

  /// Returns confidence level for a table we know about, or null for unknowns.
  ///
  /// Tier 1 — DDL-resolved (FK to `auth.users`): MEDIUM. Concrete schema
  /// evidence ties the table to user-owned data, but we still don't know
  /// the policy semantics match without runtime data.
  ///
  /// Tier 2 — hardcoded HIGH/MEDIUM ladder for the canonical Supabase tables.
  ///
  /// Returns null for tables that are neither DDL-declared nor in the
  /// hardcoded list — no suggestion is emitted (a wrong suggestion is worse
  /// than silence).
  FindingConfidence? _confidenceForTable(
    ProjectContext context,
    String normalized,
  ) {
    if (context.ddlMetadata.forTable(normalized) != null) {
      return FindingConfidence.medium;
    }
    switch (normalized) {
      // HIGH: canonical Supabase auth tables — column names are prescribed.
      case 'profiles':
      case 'users':
        return FindingConfidence.high;
      // MEDIUM: common user-owned content tables with conventional columns.
      case 'posts':
      case 'todos':
      case 'notes':
      case 'orders':
      case 'comments':
      case 'messages':
        return FindingConfidence.medium;
      default:
        return null; // unknown table → no suggestion
    }
  }
}
