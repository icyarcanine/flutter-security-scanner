import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Detects `.env` entries whose values are clearly placeholder text rather
/// than real secrets — e.g. `SUPABASE_ANON_KEY=YOUR_KEY_HERE`.
///
/// This catches the common mistake of committing an `.env` with scaffolded
/// values that were never replaced, which the `missing-env-vars` rule would
/// miss (the key is *present*, just wrong).
class PlaceholderEnvValuesRule extends Rule {
  const PlaceholderEnvValuesRule();

  @override
  String get code => 'placeholder-env-value';

  // Keys worth checking — only those the scanner actually cares about.
  static const _sensitiveKeys = {'SUPABASE_URL', 'SUPABASE_ANON_KEY'};

  @override
  List<Finding> evaluate(ProjectContext context) {
    if (!context.usesSupabase) {
      return const [];
    }

    final findings = <Finding>[];

    for (final entry in context.envEntries) {
      if (!_sensitiveKeys.contains(entry.key)) {
        continue;
      }
      if (entry.file.isEnvTemplateFile) {
        // Template files (.env.example etc.) are expected to have placeholders.
        continue;
      }
      if (!_looksLikePlaceholder(entry.value)) {
        continue;
      }

      findings.add(
        Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.high,
          category: FindingCategory.config,
          code: code,
          message:
              '${entry.key} appears to be a placeholder value in ${entry.file.name}',
          fix:
              'Replace the placeholder with the real value from your Supabase project settings before running the app.',
          risk:
              'Using placeholder configuration values will cause network requests or authentication to fail.',
          filePath: entry.file.relativePath,
          line: entry.line,
        ),
      );
    }

    return findings;
  }

  bool _looksLikePlaceholder(String value) {
    if (value.isEmpty) {
      return true;
    }
    final normalized = value.toLowerCase().trim();
    // Explicit placeholder keywords.
    if (normalized == 'changeme' ||
        normalized == 'change_me' ||
        normalized == 'replace_me' ||
        normalized == 'replace-me' ||
        normalized == 'todo' ||
        normalized == 'your_key_here' ||
        normalized == 'your-key-here' ||
        normalized == 'your_url_here' ||
        normalized == 'your-url-here') {
      return true;
    }
    // Angle-bracket templates: <SUPABASE_ANON_KEY>, <your-project-ref>.
    if (RegExp(r'^<[^>]+>$').hasMatch(value.trim())) {
      return true;
    }
    // ALL_CAPS env-var-style like YOUR_KEY_HERE or SUPABASE_URL (the key name
    // itself being used as the value is a clear copy-paste artifact).
    if (RegExp(r'^[A-Z][A-Z0-9_]+$').hasMatch(value.trim())) {
      return true;
    }
    // Contains 'your-', 'placeholder', 'example', 'xxx'.
    return normalized.contains('your-') ||
        normalized.contains('your_') ||
        normalized.contains('placeholder') ||
        normalized.contains('example') ||
        normalized.contains('xxx');
  }
}
