import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class HardcodedSecretsRule extends Rule {
  const HardcodedSecretsRule();

  @override
  String get code => 'hardcoded-secrets';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Scan Dart app files for hardcoded keys and URLs.
    for (final file in context.appDartFiles) {
      findings.addAll(_findHardcodedAnonKeys(file));
      findings.addAll(_findHardcodedUrls(file));
    }

    // Also scan YAML config files — some projects keep a config.yaml with
    // the project URL baked in (e.g., supabase_url: https://xyz.supabase.co).
    for (final file in context.yamlFiles) {
      if (_isToolOrLockFile(file)) {
        continue;
      }
      findings.addAll(_findHardcodedUrlsInYaml(file));
    }

    return findings;
  }

  List<Finding> _findHardcodedAnonKeys(ScannedFile file) {
    final findings = <Finding>[];
    final patterns = <RegExp>[
      RegExp(r'''anonKey\s*:\s*['"]([^'"]{20,})['"]\s'''),
      RegExp(r'''SUPABASE_ANON_KEY\s*[:=]\s*['"]([^'"]{20,})['"]'''),
      RegExp(
        r'''\bSupabaseClient\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]{20,})['"]''',
      ),
      RegExp(r'''supabaseAnonKey\s*[:=]\s*['"]([^'"]{20,})['"]'''),
      RegExp(r'''supabaseKey\s*[:=]\s*['"]([^'"]{20,})['"]'''),
    ];

    final seenLines = <int>{};
    for (final pattern in patterns) {
      for (final match in pattern.allMatches(file.content)) {
        final literal = match.group(match.groupCount)!;
        if (_looksLikePlaceholder(literal)) {
          continue;
        }

        final line = file.lineForOffset(match.start);
        if (!seenLines.add(line)) {
          continue;
        }
        if (isCommentLine(file.lines[line - 1])) {
          continue;
        }

        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Hardcoded Supabase anon key detected',
            fix:
                'Move the anon key into environment-backed config and load it at startup instead of committing it to Dart code.',
            risk:
                'Hardcoded credentials cannot be rotated easily and expose your Supabase project to unintended access.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  List<Finding> _findHardcodedUrls(ScannedFile file) {
    final findings = <Finding>[];
    final pattern = RegExp(
      r'''['"]https://([a-zA-Z0-9-]+)\.supabase\.co[^'"]*['"]''',
    );

    for (final match in pattern.allMatches(file.content)) {
      // Skip docs domains (docs.supabase.co, supabase.com, etc.) — these are
      // reference links, not project endpoints.
      final subdomain = match.group(1)!.toLowerCase();
      if (subdomain == 'docs' || subdomain == 'supabase' || subdomain == 'api') {
        continue;
      }

      final url = match.group(0)!.replaceAll(RegExp(r'''^['"]|['"]$'''), '');
      if (_looksLikePlaceholder(url)) {
        continue;
      }

      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) {
        continue;
      }

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Hardcoded Supabase URL detected',
          fix:
              'Move the Supabase project URL into environment-backed config so it is not copied across source files and examples.',
          risk:
              'Hardcoded URLs make it difficult to switch between development and production environments without modifying code.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  List<Finding> _findHardcodedUrlsInYaml(ScannedFile file) {
    final findings = <Finding>[];
    // Look for YAML values that contain a real Supabase project URL.
    // Pattern: key: https://xyz.supabase.co (quoted or unquoted)
    final pattern = RegExp(
      r''':\s*['"]?(https://([a-zA-Z0-9-]+)\.supabase\.co[^'"\s]*)['"]?''',
    );

    for (final match in pattern.allMatches(file.content)) {
      final subdomain = match.group(2)!.toLowerCase();
      if (subdomain == 'docs' || subdomain == 'supabase' || subdomain == 'api') {
        continue;
      }
      final url = match.group(1)!;
      if (_looksLikePlaceholder(url)) {
        continue;
      }

      final line = file.lineForOffset(match.start);

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Hardcoded Supabase URL detected in YAML config',
          fix:
              'Move the Supabase project URL into environment-backed config rather than embedding it in a checked-in YAML file.',
          risk:
              'Hardcoded URLs make it difficult to switch between development and production environments without committing changes.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  /// Returns true for values that are obviously placeholder text rather than
  /// a real secret or URL.
  bool _looksLikePlaceholder(String value) {
    final normalized = value.toLowerCase();
    // Common explicit placeholder substrings.
    if (normalized.contains('your-') ||
        normalized.contains('your_') ||
        normalized.contains('replace-me') ||
        normalized.contains('replace_me') ||
        normalized.contains('example') ||
        normalized.contains('placeholder') ||
        normalized.contains('changeme') ||
        normalized.contains('change_me') ||
        normalized.contains('xxx') ||
        normalized.contains('todo')) {
      return true;
    }
    // Angle-bracket templates like <SUPABASE_ANON_KEY> or <your_project_ref>.
    if (RegExp(r'^<[^>]+>$').hasMatch(value.trim())) {
      return true;
    }
    // ALL_CAPS env-var-style placeholders like SUPABASE_URL or YOUR_KEY_HERE.
    if (RegExp(r'^[A-Z][A-Z0-9_]+$').hasMatch(value.trim())) {
      return true;
    }
    return false;
  }

  bool _isToolOrLockFile(ScannedFile file) {
    final name = file.name.toLowerCase();
    return name == 'pubspec.yaml' ||
        name == 'pubspec.lock' ||
        name == 'analysis_options.yaml' ||
        name.endsWith('.lock');
  }
}
