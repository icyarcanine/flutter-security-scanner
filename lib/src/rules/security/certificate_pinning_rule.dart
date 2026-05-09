import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects missing or ineffective certificate pinning for network connections
/// in apps that handle sensitive data (auth, payments).
///
/// Checks for:
/// 1. No certificate pinning configured for sensitive apps
/// 2. badCertificateCallback that always returns true (disables validation)
/// 3. SecurityContext with no trusted certificates set
/// 4. Dio httpClientAdapter that bypasses certificate checks
///
/// This is a project-level and code-level check.
class CertificatePinningRule extends Rule {
  const CertificatePinningRule();

  @override
  String get code => 'missing-cert-pinning';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];
    final pubspec = context.pubspecFile;

    // Check for broken pinning configurations first.
    for (final file in context.appDartFiles) {
      findings.addAll(_findBypassedCertificateValidation(file));
      findings.addAll(_findEmptySecurityContext(file));
    }

    if (pubspec == null) return findings;

    // Only flag missing pinning if the app handles sensitive network traffic.
    final handlesSensitiveData = _handlesSensitiveData(pubspec.content);
    if (!handlesSensitiveData) return findings;

    // Check if any cert pinning mechanism is present.
    final hasPinning = _hasCertificatePinning(context);
    if (hasPinning) return findings;

    findings.add(
      Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message:
            'No certificate pinning detected in app that handles sensitive data',
        fix:
            'Implement certificate pinning using SecurityContext with trusted '
            'certificates, or use packages like http_certificate_pinning or '
            'dio_certificate_pinning. For Dio, configure TLS via '
            'httpClientAdapter.onHttpClientCreate.',
        risk:
            'Without certificate pinning, the app is vulnerable to man-in-the-middle '
            'attacks even over HTTPS, especially on compromised networks or devices '
            'with rogue CA certificates installed.',
        filePath: 'pubspec.yaml',
        line: 1,
      ),
    );

    return findings;
  }

  /// Detects certificate validation being bypassed.
  List<Finding> _findBypassedCertificateValidation(ScannedFile file) {
    final findings = <Finding>[];

    // badCertificateCallback that always returns true
    final bypassPattern = RegExp(
      r'badCertificateCallback\s*[:\=]\s*(?:\([^)]*\)\s*=>\s*true|'
      r'\{[^}]*return\s+true\s*;?\s*\})',
      caseSensitive: false,
    );

    for (final match in bypassPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Certificate validation is completely disabled',
        fix:
            'Never return true from badCertificateCallback in production. '
            'This disables ALL TLS certificate validation, making the app '
            'vulnerable to any man-in-the-middle attack. '
            'Validate certificates against a pinned set of public keys '
            'or trusted CAs.',
        risk:
            'With certificate validation disabled, attackers on any network '
            'can intercept and modify all HTTPS traffic, stealing credentials, '
            'tokens, and sensitive user data without detection.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    // onBadCertificate that returns true
    final onBadPattern = RegExp(
      r'onBadCertificate\s*[:\=]\s*(?:\([^)]*\)\s*=>\s*true|'
      r'\{[^}]*return\s+true\s*;?\s*\})',
      caseSensitive: false,
    );

    for (final match in onBadPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'onBadCertificate handler accepts all invalid certificates',
        fix:
            'Remove or properly implement onBadCertificate. Returning true '
            'accepts self-signed, expired, and forged certificates, '
            'completely defeating TLS protection.',
        risk:
            'Accepting all bad certificates allows any attacker with a '
            'network position to perform a man-in-the-middle attack, '
            'decrypting and modifying all app traffic.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects SecurityContext created but never configured with certificates.
  List<Finding> _findEmptySecurityContext(ScannedFile file) {
    final findings = <Finding>[];

    final securityContextPattern = RegExp(
      r'SecurityContext\s*\(\s*\)',
      caseSensitive: false,
    );

    for (final match in securityContextPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if setTrustedCertificates or useCertificateChain is called
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('settrustedcertificates') &&
          !surroundingContent.contains('usecertificatechain') &&
          !surroundingContent.contains('useprivatekey')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'SecurityContext created without trusted certificates',
          fix:
              'A SecurityContext with no trusted certificates provides no '
              'additional security. Either load pinned certificates:\n\n'
              'final context = SecurityContext();\n'
              'context.setTrustedCertificatesBytes(certBytes);\n'
              'final client = HttpClient(context: context);\n\n'
              'Or remove the SecurityContext if you are relying on the '
              'system certificate store.',
          risk:
              'Creating an empty SecurityContext and passing it to an '
              'HttpClient does not improve security. Without pinned '
              'certificates, the client still trusts any system CA, '
              'including rogue certificates installed on compromised devices.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  bool _handlesSensitiveData(String pubspecContent) {
    // Only flag when the project uses direct HTTP client packages alongside
    // authentication or payment packages. SDKs like supabase_flutter handle
    // their own transport security so we don't flag projects that only use an SDK.
    final usesDirectHttpClient = RegExp(
      r'(^|\s)(?:http|dio|chopper|retrofit)\s*:',
      multiLine: true,
    ).hasMatch(pubspecContent);

    final usesSensitivePackage = RegExp(
      r'(^|\s)(?:firebase_auth|google_sign_in|flutter_appauth|stripe_|in_app_purchase|pay)\s*:',
      multiLine: true,
    ).hasMatch(pubspecContent);

    return usesDirectHttpClient && usesSensitivePackage;
  }

  bool _hasCertificatePinning(ProjectContext context) {
    // Check pubspec for pinning packages.
    final pubspec = context.pubspecFile;
    if (pubspec != null) {
      if (RegExp(
        r'(^|\s)(?:http_certificate_pinning|ssl_pinning_plugin|dio_certificate_pinning|certificate_pinning_httpclient)\s*:',
        multiLine: true,
      ).hasMatch(pubspec.content)) {
        return true;
      }
    }

    // Check Dart code for actual pinning patterns.
    // Do NOT count bare SecurityContext() or badCertificateCallback as
    // evidence of pinning — those are often misconfigured or bypasses.
    for (final file in context.appDartFiles) {
      if (RegExp(
        r'''setTrustedCertificates|certificatePinning|pinnedCertificates|http_certificate_pinning|dio_certificate_pinning''',
        caseSensitive: false,
      ).hasMatch(file.content)) {
        return true;
      }
    }

    return false;
  }
}
