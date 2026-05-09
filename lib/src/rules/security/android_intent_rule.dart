import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects insecure Android intent handling and exported components.
///
/// Checks for:
/// 1. Exported activities without proper intent filters
/// 2. Content providers exposed to other apps
/// 3. Broadcast receivers with sensitive actions
/// 4. Intent data used without validation (path traversal, injection)
///
/// This is a Flutter-specific Android security rule.
class AndroidIntentSecurityRule extends Rule {
  const AndroidIntentSecurityRule();

  @override
  String get code => 'flutter.android-intent-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Scan AndroidManifest.xml
    for (final file in context.files
        .where((f) => f.name.toLowerCase() == 'androidmanifest.xml')) {
      findings.addAll(_findExportedActivities(file));
      findings.addAll(_findExportedProviders(file));
      findings.addAll(_findExportedReceivers(file));
      findings.addAll(_findDebuggableConfig(file));
      findings.addAll(_findBackupConfig(file));
    }

    // Scan Dart code for insecure intent handling
    for (final file in context.appDartFiles) {
      findings.addAll(_findInsecureIntentHandling(file));
    }

    return findings;
  }

  /// Detects exported activities without explicit permissions.
  List<Finding> _findExportedActivities(ScannedFile file) {
    final findings = <Finding>[];

    // Match activity elements with exported="true" and no permission
    final pattern = RegExp(
      r'<activity[^>]*android:exported="true"[^>]*>(?!.*?</activity>.*android:permission)',
      caseSensitive: false,
      dotAll: true,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Exported Android activity without permission',
        fix: 'Set android:exported="false" for activities that do not need '
            'to be accessible to other apps. If export is required, add '
            'android:permission with a custom signature-level permission.',
        risk: 'Exported activities can be launched by any app, potentially '
            'allowing unauthorized access to app functionality or data.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects exported content providers.
  List<Finding> _findExportedProviders(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<provider[^>]*android:exported="true"[^>]*>',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Exported Android content provider detected',
        fix: 'Set android:exported="false" for content providers. If sharing '
            'data with other apps is required, use FileProvider with '
            'grantUriPermissions instead of a fully exported provider.',
        risk: 'Exported content providers allow other apps to read and write '
            'your app\'s data, leading to data leakage or corruption.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects exported broadcast receivers with sensitive actions.
  List<Finding> _findExportedReceivers(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<receiver[^>]*android:exported="true"[^>]*>',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Exported Android broadcast receiver detected',
        fix: 'Set android:exported="false" for broadcast receivers. Use '
            'LocalBroadcastManager or explicit intents for internal communication.',
        risk: 'Exported broadcast receivers can receive intents from any app, '
            'potentially exposing sensitive actions to malicious apps.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects android:debuggable="true" in release builds.
  List<Finding> _findDebuggableConfig(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<application[^>]*android:debuggable="true"[^>]*>',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Android app marked as debuggable',
        fix: 'Remove android:debuggable="true" from the application tag. '
            'Debuggable apps can be attached to by debuggers, allowing '
            'inspection of memory, network traffic, and sensitive data.',
        risk: 'Debuggable apps are vulnerable to runtime analysis and can be '
            'inspected by attackers to extract secrets, tokens, or business logic.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects allowBackup="true" without encryption.
  List<Finding> _findBackupConfig(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<application[^>]*android:allowBackup="true"[^>]*>',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Android app allows full data backup',
        fix: 'Set android:allowBackup="false" or use '
            'android:fullBackupContent with explicit rules to exclude '
            'sensitive files. Encrypt any data that must be backed up.',
        risk: 'Backup data is stored in cleartext and can be extracted from '
            'Google Drive or iCloud backups by anyone with account access.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects insecure intent handling in Dart code.
  List<Finding> _findInsecureIntentHandling(ScannedFile file) {
    final findings = <Finding>[];

    // Detect getIntentData() or similar without validation
    final intentPattern = RegExp(
      r'(?:getIntentData|receive_sharing_intent|Intent\.get.*Extra)',
      caseSensitive: false,
    );

    for (final match in intentPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if there's validation in the next 20 lines
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (!surroundingContent.contains('validate') &&
          !surroundingContent.contains('sanitize') &&
          !surroundingContent.contains('check') &&
          !surroundingContent.contains('verify')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Intent data used without validation',
          fix: 'Always validate and sanitize intent data before using it. '
              'Check for path traversal in file paths, validate URLs, and '
              'sanitize any data passed to native code or WebViews.',
          risk: 'Unvalidated intent data can lead to path traversal, '
              'arbitrary code execution, or data exfiltration through '
              'maliciously crafted intents.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
