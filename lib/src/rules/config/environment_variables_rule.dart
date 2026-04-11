import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class EnvironmentVariablesRule extends Rule {
  const EnvironmentVariablesRule();

  bool _filesContain(Iterable<ScannedFile> files, RegExp pattern) {
    for (final file in files) {
      if (pattern.hasMatch(file.content)) {
        return true;
      }
    }
    return false;
  }

  @override
  String get code => 'missing-env-vars';

  @override
  List<Finding> evaluate(ProjectContext context) {
    if (!context.usesSupabase) {
      return const [];
    }

    final configReferenceFiles = [
      ...context.appDartFiles,
      ...context.yamlFiles,
      ...context.envFiles,
    ];

    final findings = <Finding>[];

    for (final key in const ['SUPABASE_URL', 'SUPABASE_ANON_KEY']) {
      final isVariableUsedInCode = _filesContain(configReferenceFiles, RegExp("String\\.fromEnvironment\\s*\\(\\s*['\"]$key['\"]\\s*\\)", caseSensitive: false)) ||
                                   _filesContain(configReferenceFiles, RegExp("dotenv\\.env\\s*\\[\\s*['\"]$key['\"]\\s*\\]", caseSensitive: false)) ||
                                   _filesContain(configReferenceFiles, RegExp("\\b(?:env|Env|config|Config|environment)['\"]?$key['\"]?\\b|Platform\\.environment\\s*\\[\\s*['\"]$key['\"]\\s*\\]", caseSensitive: false)) ||
                                   context.envEntries.any((e) => e.key == key);

      // We still want a reference point for the file/line if we warn.
      final reference = firstReferenceFor(context, key, files: configReferenceFiles);

      // 1. Variable is used in code
      if (!isVariableUsedInCode) {
        continue;
      }

      final hasRealConfig =
          context.hasEnvFile ||
          context.usesDartDefine ||
          context.usesDotenv;

      final hasOnlyExample =
          context.hasExampleEnvFile && !hasRealConfig;

      // Case A — Real config exists
      if (hasRealConfig) {
        continue;
      }

      // Case B — Only example exists
      if (hasOnlyExample) {
        findings.add(
          Finding(
            severity: FindingSeverity.low,
            confidence: FindingConfidence.low,
            category: FindingCategory.config,
            code: code,
            message: 'Environment variable used but only example config found',
            fix: 'create a real .env or provide runtime config',
            risk: 'app may fail in production due to missing config',
            filePath: reference?.file.relativePath,
            line: reference?.line,
          ),
        );
      } else {
        // Case C — No config at all
        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            category: FindingCategory.config,
            code: code,
            message: 'Environment variable used but no configuration detected',
            fix: 'add .env or use --dart-define / dotenv',
            risk: 'runtime failures due to missing credentials',
            filePath: reference?.file.relativePath,
            line: reference?.line,
          ),
        );
      }
    }

    return findings;
  }
}
