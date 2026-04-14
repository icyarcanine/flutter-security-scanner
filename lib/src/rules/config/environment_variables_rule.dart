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

    // Check for service role key in client code — this bypasses RLS.
    findings.addAll(_checkServiceRoleKey(context));

    for (final key in const ['SUPABASE_URL', 'SUPABASE_ANON_KEY']) {
      final isVariableUsedInCode =
          _filesContain(
            configReferenceFiles,
            RegExp(
              "String\\.fromEnvironment\\s*\\(\\s*['\"]$key['\"]\\s*\\)",
              caseSensitive: false,
            ),
          ) ||
          _filesContain(
            configReferenceFiles,
            RegExp(
              "dotenv\\.env\\s*\\[\\s*['\"]$key['\"]\\s*\\]",
              caseSensitive: false,
            ),
          ) ||
          _filesContain(
            configReferenceFiles,
            RegExp(
              "\\b(?:env|Env|config|Config|environment)['\"]?$key['\"]?\\b|Platform\\.environment\\s*\\[\\s*['\"]$key['\"]\\s*\\]",
              caseSensitive: false,
            ),
          ) ||
          context.envEntries.any((e) => e.key == key);

      // We still want a reference point for the file/line if we warn.
      final reference = firstReferenceFor(
        context,
        key,
        files: configReferenceFiles,
      );

      // 1. Variable is used in code
      if (!isVariableUsedInCode) {
        continue;
      }

      final hasRealConfig =
          context.hasEnvFile || context.usesDartDefine || context.usesDotenv;

      final hasOnlyExample = context.hasExampleEnvFile && !hasRealConfig;

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

  /// Detects usage of SUPABASE_SERVICE_ROLE_KEY in client code.
  /// Service role keys bypass RLS and should NEVER be in client apps.
  List<Finding> _checkServiceRoleKey(ProjectContext context) {
    final findings = <Finding>[];
    final pattern = RegExp(
      r'''SUPABASE_SERVICE_ROLE_KEY|serviceRoleKey|service_role_key|serviceRole''',
      caseSensitive: false,
    );

    for (final file in context.appDartFiles) {
      for (final match in pattern.allMatches(file.content)) {
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;

        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Service role key referenced in client code',
            fix:
                'NEVER use the Supabase service role key in client/mobile apps. '
                'It bypasses Row Level Security completely. Use the anon key '
                'and enforce RLS on the server.',
            risk:
                'The service role key has unrestricted access to all data, '
                'bypassing RLS. If exposed in a client app, attackers can read, '
                'modify, or delete all data in your database.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    // Also check env files for service role keys.
    for (final entry in context.envEntries) {
      if (entry.key.toLowerCase().contains('service_role') ||
          entry.key.toLowerCase().contains('servicerole')) {
        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Service role key found in environment file',
            fix:
                'Remove the service role key from the client .env file. '
                'Service role keys should only be used in server-side code.',
            risk:
                'Service role keys in client env files will be bundled into '
                'the app binary and can be extracted by anyone.',
            filePath: entry.file.relativePath,
            line: entry.line,
          ),
        );
      }
    }

    return findings;
  }
}
