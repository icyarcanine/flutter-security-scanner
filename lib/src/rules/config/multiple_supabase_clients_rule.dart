import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class MultipleSupabaseClientsRule extends Rule {
  const MultipleSupabaseClientsRule();

  @override
  String get code => 'multiple-supabase-clients';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final locations = context.supabaseClientLocations;
    if (locations.length <= 1) {
      return const [];
    }

    // Point to the second instantiation (the first duplicate) so the
    // developer knows which one to consolidate.
    final location = locations[1];
    final total = locations.length;
    return [
      Finding(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.high,
        category: FindingCategory.config,
        code: code,
        message:
            '$total direct SupabaseClient(...) instances detected (first duplicate shown)',
        fix:
            'Create the client once and share it via a singleton, provider, or dependency injection so session state stays consistent.',
        risk:
            'Multiple client instances can lead to desynchronized auth states and redundant network requests.',
        filePath: location.file.relativePath,
        line: location.line,
      ),
    ];
  }
}
