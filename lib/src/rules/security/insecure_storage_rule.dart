import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects sensitive data stored using insecure storage mechanisms like
/// SharedPreferences instead of flutter_secure_storage or platform keychains.
///
/// OWASP Mobile Top 10: M9 — Insecure Data Storage.
class InsecureStorageRule extends Rule {
  const InsecureStorageRule();

  @override
  String get code => 'insecure-storage';

  /// Sensitive key names that should NOT be stored in SharedPreferences.
  static final _sensitiveKeyPattern = RegExp(
    r'''['"](?:token|access_token|refresh_token|auth_token|session|jwt|password|passwd|secret|api_key|apiKey|private_key|credit_card|card_number|cvv|ssn|pin|credentials|auth|bearer|encryption_key|master_key|client_secret|session_id|user_token|auth_state|login_token|biometric_key)['"]\s*(?:,|\))''',
    caseSensitive: false,
  );

  /// SharedPreferences write methods — broad receiver matching.
  static final _sharedPrefsWritePattern = RegExp(
    r'''(?:prefs|preferences|sharedPrefs|sharedPreferences|sp|pref|storage)\s*\.\s*set(?:String|Int|Bool|Double|StringList)\s*\(''',
    caseSensitive: false,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_checkSharedPrefsUsage(file));
    }

    return findings;
  }

  List<Finding> _checkSharedPrefsUsage(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _sharedPrefsWritePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Look at the arguments after the setString( call.
      final argStart = match.end;
      final argEnd = (argStart + 200).clamp(0, file.content.length);
      final argSnippet = file.content.substring(argStart, argEnd);

      if (_sensitiveKeyPattern.hasMatch(argSnippet)) {
        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Sensitive data stored in SharedPreferences (unencrypted)',
            fix:
                'Use flutter_secure_storage or platform keychain/keystore '
                'instead of SharedPreferences for sensitive data like tokens, '
                'passwords, and API keys.',
            risk:
                'SharedPreferences stores data as plaintext on disk. On rooted/jailbroken '
                'devices, any app can read this data.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }
}
