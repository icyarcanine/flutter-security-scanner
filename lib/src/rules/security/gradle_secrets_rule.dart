import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects hardcoded secrets and insecure configurations in Gradle build files.
///
/// Gradle files often contain signing configs, API keys, and build secrets
/// that should be externalized to local.properties or environment variables.
class GradleSecretsRule extends Rule {
  const GradleSecretsRule();

  @override
  String get code => 'gradle-secrets';

  /// Hardcoded signing passwords or key aliases in Gradle.
  static final _signingConfigPattern = RegExp(
    r'''(?:storePassword|keyPassword|keyAlias)\s*(?:=|:)\s*['"]([^'"]{2,})['"]''',
  );

  /// API keys or secrets assigned directly in Gradle.
  static final _apiKeyPattern = RegExp(
    r'''(?:apiKey|API_KEY|secret|SECRET|token|TOKEN|password|PASSWORD)\s*(?:=|:)\s*['"]([^'"]{8,})['"]''',
    caseSensitive: false,
  );

  /// Placeholder values that are not real secrets.
  static final _placeholderPattern = RegExp(
    r'''(?:your|replace|example|placeholder|changeme|todo|xxx|insert|fill)''',
    caseSensitive: false,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files) {
      if (!file.name.endsWith('.gradle') &&
          file.name != 'gradle.properties' &&
          file.name != 'local.properties') {
        continue;
      }

      // local.properties is typically gitignored — skip it.
      if (file.name == 'local.properties') continue;

      _checkSigningConfig(file, findings);
      _checkApiKeys(file, findings);
    }

    return findings;
  }

  void _checkSigningConfig(ScannedFile file, List<Finding> findings) {
    for (final match in _signingConfigPattern.allMatches(file.content)) {
      final value = match.group(1)!;
      if (_placeholderPattern.hasMatch(value)) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Hardcoded signing credential in Gradle file',
          fix:
              'Move signing credentials to local.properties or environment '
              'variables. Reference them via project.property() in build.gradle.',
          risk:
              'Hardcoded signing passwords in checked-in files expose your '
              'app signing keys to anyone with repo access.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }
  }

  void _checkApiKeys(ScannedFile file, List<Finding> findings) {
    for (final match in _apiKeyPattern.allMatches(file.content)) {
      final value = match.group(1)!;
      if (_placeholderPattern.hasMatch(value)) continue;

      // Skip common Gradle build values that aren't secrets.
      if (value.contains('.') && value.contains('/')) continue; // file paths
      if (RegExp(r'^\d+(\.\d+)+$').hasMatch(value)) continue; // version numbers

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Potential hardcoded secret in Gradle file',
          fix:
              'Move secrets to local.properties (gitignored) or use '
              'environment variables. Never commit secrets in build files.',
          risk:
              'Secrets in Gradle files are committed to source control and '
              'visible to all contributors.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }
  }
}
