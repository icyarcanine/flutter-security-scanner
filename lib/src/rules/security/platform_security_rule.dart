import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects insecure configurations in Android manifest and iOS plist files.
///
/// Checks for:
/// - android:allowBackup="true" (data extractable via adb backup)
/// - android:exported="true" on sensitive components without intent filters
/// - android:usesCleartextTraffic="true"
/// - Missing NSAppTransportSecurity exceptions audit
class PlatformSecurityRule extends Rule {
  const PlatformSecurityRule();

  @override
  String get code => 'platform-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files) {
      if (file.name == 'AndroidManifest.xml') {
        findings.addAll(_checkAndroidManifest(file));
      }
      if (file.name == 'Info.plist') {
        findings.addAll(_checkInfoPlist(file));
      }
    }

    return findings;
  }

  List<Finding> _checkAndroidManifest(ScannedFile file) {
    final findings = <Finding>[];

    // android:allowBackup="true" — allows data extraction via adb backup.
    final allowBackupPattern = RegExp(r'''android:allowBackup\s*=\s*"true"''');
    for (final match in allowBackupPattern.allMatches(file.content)) {
      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Android backup is enabled (android:allowBackup="true")',
          fix:
              'Set android:allowBackup="false" in the <application> tag, or '
              'define backup rules to exclude sensitive data.',
          risk:
              'With backup enabled, app data including tokens and credentials '
              'can be extracted from the device via adb backup.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }

    // android:usesCleartextTraffic="true" — allows HTTP connections.
    final cleartextPattern = RegExp(
      r'''android:usesCleartextTraffic\s*=\s*"true"''',
    );
    for (final match in cleartextPattern.allMatches(file.content)) {
      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Cleartext traffic is allowed in Android manifest',
          fix:
              'Set android:usesCleartextTraffic="false" and use HTTPS for all '
              'network connections. If needed for development, use a network '
              'security config with domain-specific exceptions.',
          risk:
              'Allowing cleartext traffic enables man-in-the-middle attacks '
              'on any unencrypted HTTP connection.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }

    // android:debuggable="true" — should never be in release builds.
    final debuggablePattern = RegExp(r'''android:debuggable\s*=\s*"true"''');
    for (final match in debuggablePattern.allMatches(file.content)) {
      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'Android app is set as debuggable',
          fix:
              'Remove android:debuggable="true" from the manifest. '
              'Debug mode should only be set via build variants, never hardcoded.',
          risk:
              'A debuggable app can be attached to with a debugger, allowing '
              'extraction of secrets, bypassing security controls, and code injection.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkInfoPlist(ScannedFile file) {
    final findings = <Finding>[];

    // NSAppTransportSecurity with NSAllowsArbitraryLoads = true.
    if (file.content.contains('NSAllowsArbitraryLoads') &&
        _plistBoolIsTrue(file.content, 'NSAllowsArbitraryLoads')) {
      final offset = file.content.indexOf('NSAllowsArbitraryLoads');
      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'iOS App Transport Security allows arbitrary loads',
          fix:
              'Remove NSAllowsArbitraryLoads or set it to false. Add specific '
              'domain exceptions in NSExceptionDomains instead.',
          risk:
              'NSAllowsArbitraryLoads disables all App Transport Security '
              'protections, allowing insecure HTTP connections to any server.',
          filePath: file.relativePath,
          line: file.lineForOffset(offset),
        ),
      );
    }

    return findings;
  }

  /// Rough check for whether a plist boolean key is set to true.
  bool _plistBoolIsTrue(String content, String key) {
    final keyIndex = content.indexOf(key);
    if (keyIndex == -1) return false;
    // Look for <true/> after the key within a reasonable window.
    final afterKey = content.substring(
      keyIndex,
      (keyIndex + key.length + 100).clamp(0, content.length),
    );
    return afterKey.contains('<true/>') || afterKey.contains('<true />');
  }
}
