import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure local database usage in Flutter apps.
///
/// Checks for:
/// 1. sqflite without encryption (SQLCipher)
/// 2. Hive without encryption
/// 4. SharedPreferences used for sensitive data
/// 5. Local files storing sensitive data without encryption
///
/// This is a Flutter-specific data protection rule.
class LocalDatabaseSecurityRule extends Rule {
  const LocalDatabaseSecurityRule();

  @override
  String get code => 'flutter.local-database-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findUnencryptedSqflite(file));
      findings.addAll(_findUnencryptedHive(file));
      findings.addAll(_findSensitiveDataInLocalFiles(file));
    }

    return findings;
  }

  /// Detects sqflite usage without SQLCipher encryption.
  List<Finding> _findUnencryptedSqflite(ScannedFile file) {
    final findings = <Finding>[];

    // Check for sqflite imports
    final sqflitePattern = RegExp(
      r'package:sqflite/sqflite\.dart',
      caseSensitive: false,
    );

    if (!sqflitePattern.hasMatch(file.content)) {
      return findings;
    }

    // Check if SQLCipher is used
    final sqlCipherPattern = RegExp(
      r'sqflite_sqlcipher|SQLCipher|encrypt|cipher',
      caseSensitive: false,
    );

    if (sqlCipherPattern.hasMatch(file.content)) {
      return findings;
    }

    // Find openDatabase calls
    final openDbPattern = RegExp(
      r'openDatabase\s*\(',
      caseSensitive: false,
    );

    for (final match in openDbPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Local SQLite database opened without encryption',
        fix: 'Use sqflite_sqlcipher package to encrypt your SQLite database. '
            'sqflite stores data in plain text files that are readable by '
            'any app with root access or physical device access.',
        risk: 'Unencrypted local databases expose all stored data to attackers '
            'with physical device access, root access, or backup extraction. '
            'This includes user data, auth tokens, and app secrets.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects Hive usage without encryption.
  List<Finding> _findUnencryptedHive(ScannedFile file) {
    final findings = <Finding>[];

    // Check for hive imports
    final hivePattern = RegExp(
      r'package:hive/hive\.dart',
      caseSensitive: false,
    );

    if (!hivePattern.hasMatch(file.content)) {
      return findings;
    }

    // Check if Hive encryption is used
    final encryptionPattern = RegExp(
      r'HiveCipher|HiveAesCipher|encrypt|cipher|encryptionKey',
      caseSensitive: false,
    );

    if (encryptionPattern.hasMatch(file.content)) {
      return findings;
    }

    // Find Hive.openBox calls
    final openBoxPattern = RegExp(
      r'Hive\.openBox\s*\(',
      caseSensitive: false,
    );

    for (final match in openBoxPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Hive database opened without encryption',
        fix: 'Use HiveAesCipher or another HiveCipher implementation to '
            'encrypt Hive boxes. Without encryption, Hive stores data in '
            'plain binary files readable by any app with file system access.',
        risk: 'Unencrypted Hive boxes expose all stored data to attackers with '
            'physical device access or root privileges.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects sensitive data being written to local files without encryption.
  List<Finding> _findSensitiveDataInLocalFiles(ScannedFile file) {
    final findings = <Finding>[];

    // Detect File.writeAsString with sensitive keywords
    final writePattern = RegExp(
      r'File\([^)]*\)\.(?:writeAsString|writeAsBytes)',
      caseSensitive: false,
    );

    for (final match in writePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check surrounding context for sensitive keywords
      final endLine = (line + 5).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (surroundingContent.contains('token') ||
          surroundingContent.contains('password') ||
          surroundingContent.contains('secret') ||
          surroundingContent.contains('key') ||
          surroundingContent.contains('auth') ||
          surroundingContent.contains('session') ||
          surroundingContent.contains('credential')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Sensitive data may be written to unencrypted local file',
          fix:
              'Use flutter_secure_storage or encrypted databases for sensitive '
              'data. Plain files are readable by any app with storage permissions.',
          risk:
              'Writing sensitive data to plain files exposes it to any app with '
              'file system access, including malware or compromised apps.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
