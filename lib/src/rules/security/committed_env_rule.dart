import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class CommittedEnvRule extends Rule {
  const CommittedEnvRule();

  @override
  String get code => 'committed-env';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final envFile in context.envFiles) {
      if (envFile.isEnvTemplateFile ||
          context.gitignoreCoversEnvFile(envFile.relativePath)) {
        continue;
      }

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: '.env file is present but not ignored by git',
          fix:
              'Add `${envFile.name}` or a `.env*` rule to `.gitignore` before committing environment files.',
          risk:
              'Checking in `.env` files exposes production secrets or keys to source control history.',
          filePath: envFile.relativePath,
          line: 1,
        ),
      );
    }

    return findings;
  }
}
