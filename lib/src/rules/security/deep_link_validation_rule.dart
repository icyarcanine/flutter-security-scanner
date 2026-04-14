import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects deep link handlers that don't validate the incoming URI,
/// and Android manifest configurations that expose activities to arbitrary
/// deep links.
class DeepLinkValidationRule extends Rule {
  const DeepLinkValidationRule();

  @override
  String get code => 'deep-link-validation';

  /// Dart code handling deep links via uni_links, app_links, go_router, etc.
  static final _deepLinkHandlerPattern = RegExp(
    r'''(?:getInitialLink|linkStream|getInitialUri|uriLinkStream|onGenerateRoute|GoRouter|handleDeepLink|getLatestLink)''',
  );

  /// URI validation patterns that indicate the developer validates the link.
  static final _validationPatterns = [
    RegExp(r'''\.host\s*==|\.scheme\s*==|\.authority\s*=='''),
    RegExp(r'''Uri\.parse\([^)]+\)\.(?:host|scheme|authority)'''),
    RegExp(
      r'''allowedHosts|trustedDomains|whitelistedDomains|allowedSchemes''',
      caseSensitive: false,
    ),
    RegExp(
      r'''(?:validate|verify|check)(?:Uri|Url|Link|DeepLink)''',
      caseSensitive: false,
    ),
  ];

  /// Android manifest intent filter with custom scheme.
  static final _intentFilterPattern = RegExp(
    r'''<intent-filter[\s\S]*?<data\s[^>]*android:scheme\s*=\s*"(?!https?)([^"]+)"[\s\S]*?</intent-filter>''',
    caseSensitive: false,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Check Dart code for deep link handling without validation.
    for (final file in context.appDartFiles) {
      findings.addAll(_checkDartDeepLinks(file));
    }

    // Check Android manifest for exposed intent filters.
    for (final file in context.files) {
      if (file.name == 'AndroidManifest.xml') {
        findings.addAll(_checkAndroidManifest(file));
      }
    }

    return findings;
  }

  List<Finding> _checkDartDeepLinks(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _deepLinkHandlerPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check a window of code around the handler for validation.
      final context = file.contextAroundLine(line, before: 5, after: 20);
      final hasValidation = _validationPatterns.any(
        (pattern) => pattern.hasMatch(context),
      );

      if (!hasValidation) {
        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message: 'Deep link handler without visible URI validation',
            fix:
                'Validate the scheme, host, and path of incoming deep links '
                'before processing them. Use an allowlist of trusted domains.',
            risk:
                'Unvalidated deep links can be exploited for credential theft, '
                'unauthorized actions, or redirecting users to malicious content.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  List<Finding> _checkAndroidManifest(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _intentFilterPattern.allMatches(file.content)) {
      final scheme = match.group(1)!;
      final line = file.lineForOffset(match.start);

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Custom URI scheme "$scheme://" registered in intent filter',
          fix:
              'Validate incoming URI parameters in your Dart deep link handler. '
              'Consider using App Links (HTTPS) instead of custom schemes for '
              'better security via domain verification.',
          risk:
              'Custom URI schemes can be hijacked by malicious apps on the '
              'same device to intercept sensitive data.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }
}
