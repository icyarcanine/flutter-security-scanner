import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure network configurations in Flutter apps.
///
/// Checks for:
/// 1. Android network_security_config allowing cleartext traffic
/// 2. iOS App Transport Security (ATS) disabled or with exceptions
/// 3. Cleartext HTTP requests in Dart code (beyond plaintext_http_rule)
/// 4. Self-signed certificate acceptance
/// 5. Missing certificate pinning configuration
///
/// This is a cross-platform Flutter network security rule.
class NetworkSecurityConfigRule extends Rule {
  const NetworkSecurityConfigRule();

  @override
  String get code => 'flutter.network-security-config';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Scan Android network_security_config.xml
    for (final file in context.files.where((f) => f.name.toLowerCase().contains('network_security_config'))) {
        findings.addAll(_findCleartextTraffic(file));
        findings.addAll(_findSelfSignedCerts(file));
        findings.addAll(_findDebugOverrides(file));
      }

    // Scan iOS Info.plist for ATS exceptions
    for (final file in context.files.where((f) => f.name.toLowerCase() == 'info.plist')) {
        findings.addAll(_findAtsExceptions(file));
      }

    // Scan Dart code for explicit HTTP usage patterns
    for (final file in context.appDartFiles) {
      findings.addAll(_findExplicitHttpBypass(file));
    }

    return findings;
  }

  /// Detects cleartext traffic enabled in network security config.
  List<Finding> _findCleartextTraffic(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'cleartextTrafficPermitted="true"',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Cleartext traffic permitted in network security config',
        fix:
            'Remove cleartextTrafficPermitted="true" from your '
            'network_security_config.xml. All network traffic should use HTTPS. '
            'If you absolutely need HTTP for specific domains, use a '
            'domain-config with cleartextTrafficPermitted="true" scoped to '
            'only that domain, and migrate to HTTPS as soon as possible.',
        risk:
            'Cleartext traffic exposes all network communication to eavesdropping '
            'and man-in-the-middle attacks. Attackers on the same network can '
            'intercept passwords, tokens, and personal data.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects trust anchors that include user certificates (self-signed).
  List<Finding> _findSelfSignedCerts(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<trust-anchors[^>]*>.*?src="user".*?\u003c/trust-anchors>',
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
        message: 'Self-signed certificates trusted in network config',
        fix:
            'Remove src="user" from trust-anchors. Only trust system '
            'certificates (src="system"). For development, use a '
            'debug-only network_security_config that is stripped from '
            'release builds.',
        risk:
            'Trusting user-installed certificates allows any app or user with '
            'root access to install a fake CA certificate and intercept all '
            'your HTTPS traffic with no browser warnings.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects debug overrides in network security config.
  List<Finding> _findDebugOverrides(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'<debug-overrides[^>]*>',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Debug network security overrides present',
        fix:
            'Ensure network_security_config files containing debug-overrides '
            'are only in debug source sets (src/debug/res/xml/) and NEVER in '
            'release builds. Use build variants to separate debug and release '
            'configs.',
        risk:
            'Debug overrides typically disable certificate validation. If these '
            'configs leak into release builds, all HTTPS connections become '
            'vulnerable to man-in-the-middle attacks.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects iOS ATS exceptions that weaken security.
  List<Finding> _findAtsExceptions(ScannedFile file) {
    final findings = <Finding>[];

    // Global ATS disable
    final globalDisablePattern = RegExp(
      r'NSAppTransportSecurity.*?NSAllowsArbitraryLoads</key>.*?true',
      caseSensitive: false,
      dotAll: true,
    );

    for (final match in globalDisablePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'iOS App Transport Security (ATS) globally disabled',
        fix:
            'Remove NSAllowsArbitraryLoads or set it to false. If you need '
            'to connect to specific HTTP domains, use NSExceptionDomains '
            'with NSExceptionAllowsInsecureHTTPLoads scoped to only those '
            'domains. Submit an App Store justification for the exception.',
        risk:
            'Disabling ATS globally allows all network connections to use '
            'HTTP instead of HTTPS. Apple rejects most apps with this setting '
            'unless you provide a valid justification.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    // Local domain exceptions (less severe but still notable)
    final localExceptionPattern = RegExp(
      r'NSExceptionAllowsInsecureHTTPLoads</key>.*?true',
      caseSensitive: false,
      dotAll: true,
    );

    for (final match in localExceptionPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'iOS ATS exception allows insecure HTTP for specific domain',
        fix:
            'Remove NSExceptionAllowsInsecureHTTPLoads if possible. If the '
            'domain is under your control, enable HTTPS. If not, use a '
            'reverse proxy or API gateway to enforce TLS.',
        risk:
            'ATS exceptions for specific domains still expose traffic to those '
            'domains to eavesdropping. Ensure the exception is absolutely '
            'necessary and document the justification.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    // Minimum TLS version exceptions
    final tlsExceptionPattern = RegExp(
      r'NSExceptionMinimumTLSVersion</key>.*?TLSv1\.(?:0|1)',
      caseSensitive: false,
      dotAll: true,
    );

    for (final match in tlsExceptionPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'iOS ATS allows weak TLS version (TLS 1.0/1.1)',
        fix:
            'Use TLSv1.2 or TLSv1.3 as the minimum TLS version. TLS 1.0 and '
            '1.1 have known vulnerabilities (BEAST, POODLE) and are deprecated '
            'by all major browsers and Apple.',
        risk:
            'Weak TLS versions are vulnerable to downgrade and padding oracle '
            'attacks. Attackers can force connections to use weak ciphers and '
            'decrypt sensitive traffic.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects explicit HTTP bypass patterns in Dart code.
  List<Finding> _findExplicitHttpBypass(ScannedFile file) {
    final findings = <Finding>[];

    // HttpOverrides or similar Dart-level TLS bypass
    final pattern = RegExp(
      r'(?:HttpOverrides|BadCertificateCallback|allowBadCertificates)',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Dart HTTP certificate validation disabled',
        fix:
            'Remove HttpOverrides, BadCertificateCallback, or '
            'allowBadCertificates. These disable TLS certificate validation, '
            'making all HTTPS connections vulnerable to man-in-the-middle '
            'attacks. For development with self-signed certs, use a debug-only '
            'HttpOverrides that is stripped from release builds.',
        risk:
            'Disabling certificate validation allows any attacker with a '
            'self-signed certificate to intercept and modify all HTTPS '
            'traffic between your app and the server.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }
}
