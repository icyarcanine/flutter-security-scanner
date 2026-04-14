import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Detects missing certificate pinning for network connections in apps that
/// handle sensitive data (auth, payments).
///
/// This is a project-level check: if the app uses authentication or payment
/// packages but has no certificate pinning configured, it flags the risk.
class CertificatePinningRule extends Rule {
  const CertificatePinningRule();

  @override
  String get code => 'missing-cert-pinning';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];
    final pubspec = context.pubspecFile;
    if (pubspec == null) return findings;

    // Only flag if the app handles sensitive network traffic.
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

    // Check Dart code for manual pinning patterns.
    for (final file in context.appDartFiles) {
      if (RegExp(
        r'''SecurityContext|badCertificateCallback|onBadCertificate|setTrustedCertificates|certificatePinning|pinnedCertificates''',
        caseSensitive: false,
      ).hasMatch(file.content)) {
        return true;
      }
    }

    return false;
  }
}
