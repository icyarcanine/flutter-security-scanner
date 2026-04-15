import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects sensitive data stored using insecure storage mechanisms.
///
/// Covers three common on-device storage choices that ship without
/// encryption by default:
///
/// * **SharedPreferences** — plaintext XML on disk. Sensitive key names
///   (token, password, apiKey, …) should live in `flutter_secure_storage`
///   or the platform keychain/keystore instead.
/// * **sqflite** — `openDatabase()` from `package:sqflite` produces an
///   unencrypted SQLite file. If the project needs on-device SQL it should
///   use `sqflite_sqlcipher` (or the Android Room + SQLCipher recipe).
/// * **Hive** — `Hive.openBox('…')` without passing `encryptionCipher:`
///   stores every object as plaintext. Hive supports `HiveAesCipher`
///   backed by a key held in `flutter_secure_storage`.
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

  // Sqflite -------------------------------------------------------------

  static final _sqfliteImport = RegExp(
    r'''import\s+['"]package:sqflite/[^'"]+['"]''',
  );
  static final _sqflitesCipherImport = RegExp(
    r'''import\s+['"]package:sqflite_sqlcipher/[^'"]+['"]|import\s+['"]package:sqflite_cipher/[^'"]+['"]|import\s+['"]package:sqflcipher/[^'"]+['"]''',
  );
  static final _openDatabasePattern = RegExp(
    r'''\bopenDatabase\s*\(''',
  );

  // Hive ----------------------------------------------------------------

  static final _hiveImport = RegExp(
    r'''import\s+['"]package:hive(?:_flutter)?/[^'"]+['"]''',
  );
  static final _openBoxPattern = RegExp(
    r'''\bHive\s*\.\s*openBox(?:<[^>]+>)?\s*\(''',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_checkSharedPrefsUsage(file));
      findings.addAll(_checkSqflite(file));
      findings.addAll(_checkHive(file));
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

  /// Flags `openDatabase(…)` calls in files that import `package:sqflite`
  /// but NOT a SQLCipher drop-in. We deliberately evaluate per-file rather
  /// than per-project so a single mixed codebase (some files encrypted,
  /// some not) is still diagnosed correctly.
  List<Finding> _checkSqflite(ScannedFile file) {
    final findings = <Finding>[];
    if (!_sqfliteImport.hasMatch(file.content)) return findings;
    if (_sqflitesCipherImport.hasMatch(file.content)) return findings;

    for (final match in _openDatabasePattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message:
              'sqflite openDatabase() without SQLCipher — database ships unencrypted',
          fix:
              'Swap package:sqflite for package:sqflite_sqlcipher (same API, '
              'accepts a `password:` argument) and load the database key '
              'from flutter_secure_storage on first launch.',
          risk:
              'Unencrypted SQLite files are trivially dumped from a rooted '
              'device or from a cloud backup and can be opened with any '
              'SQLite browser. Anything the app persists — auth tokens, '
              'user rows, offline caches — is readable plaintext.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    return findings;
  }

  /// Flags `Hive.openBox(…)` calls in files that import Hive and do NOT
  /// pass an `encryptionCipher:` argument.
  List<Finding> _checkHive(ScannedFile file) {
    final findings = <Finding>[];
    if (!_hiveImport.hasMatch(file.content)) return findings;

    for (final match in _openBoxPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Walk the argument list up to the matching close paren (200-char
      // bound is plenty) and check for the `encryptionCipher:` marker.
      final argStart = match.end;
      final argEnd = (argStart + 400).clamp(0, file.content.length);
      final args = file.content.substring(argStart, argEnd);
      if (args.contains('encryptionCipher:')) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message:
              'Hive.openBox() without encryptionCipher — box is stored in plaintext',
          fix:
              'Pass encryptionCipher: HiveAesCipher(key), where `key` is a '
              '256-bit value loaded from flutter_secure_storage. Without '
              'the cipher, Hive serializes every object to disk as plain '
              'MessagePack.',
          risk:
              'Hive files live in the app\'s documents directory and are '
              'readable by anyone with filesystem access to the device or '
              'an unencrypted cloud backup. Without a cipher, every object '
              'the app stores is recoverable as clear text.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    return findings;
  }
}
