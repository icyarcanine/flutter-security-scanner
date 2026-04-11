import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class ClientSideTrustRule extends Rule {
  const ClientSideTrustRule();

  @override
  String get code => 'client-side-trust';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final access in context.tableAccesses) {
      if (!access.usesClientProvidedUserId) {
        continue;
      }

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Supabase query relies on a client-provided user identifier',
          fix:
              'Do not trust route params or caller-provided `userId` values for authorization. Enforce ownership with RLS and only use `currentUser.id` as a convenience filter.',
          risk:
              'Trusting client-provided user IDs for authorization allows malicious users to spoof actions or access data on behalf of others.',
          filePath: access.file.relativePath,
          line: access.line,
        ),
      );
    }

    return findings;
  }
}
