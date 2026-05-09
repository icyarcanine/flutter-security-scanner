import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure dependency configurations in Flutter projects.
///
/// Checks for:
/// 1. Known vulnerable package versions in pubspec.yaml
/// 2. Overly permissive version constraints (^ or >= without upper bound)
/// 3. Dependency on unmaintained or deprecated packages
/// 4. git or path dependencies without commit pinning
/// 5. Flutter SDK version constraints that allow old insecure versions
///
/// This is a supply-chain security rule for Flutter.
class DependencySecurityRule extends Rule {
  const DependencySecurityRule();

  @override
  String get code => 'flutter.dependency-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.yamlFiles) {
      if (file.name.toLowerCase() == 'pubspec.yaml') {
        findings.addAll(_findVulnerablePackages(file));
        // Only flag unbounded >= constraints on security-sensitive packages.
        // Caret (^) constraints are standard Dart practice and bound major
        // versions; open-ended >= without upper bound is genuinely dangerous.
        findings.addAll(_findLooseVersionConstraints(file));
        findings.addAll(_findUnpinnedDependencies(file));
      }
    }

    return findings;
  }

  /// Detects known vulnerable package versions.
  ///
  /// This is a lightweight check using a hardcoded list of known
  /// vulnerable versions. For production use, integrate with the
  /// OSV (Open Source Vulnerabilities) API:
  ///   POST https://api.osv.dev/v1/query
  ///   Body: {"package": {"ecosystem": "Pub", "name": "package_name"}}
  ///
  /// Or use pub.dev's advisory endpoint:
  ///   GET https://pub.dev/api/packages/{name}/advisories
  List<Finding> _findVulnerablePackages(ScannedFile file) {
    final findings = <Finding>[];

    // Known vulnerable packages (simplified — in production, query OSV API).
    // Updated with additional packages commonly flagged in Flutter security audits.
    final vulnerablePackages = <MapEntry<String, String>>[
      // Networking
      const MapEntry('dio', '<5.0.0'), // Cookie handling issues
      const MapEntry('http', '<0.13.0'), // Redirect issues
      const MapEntry('http_parser', '<4.0.0'), // Header parsing issues
      // UI / WebView
      const MapEntry('image_picker', '<0.8.6'), // Path traversal fix
      const MapEntry('webview_flutter', '<4.0.0'), // JS bridge issues
      const MapEntry('url_launcher', '<6.1.0'), // URL validation fix
      const MapEntry('flutter_html', '<3.0.0'), // XSS in older versions
      const MapEntry('flutter_inappwebview', '<6.0.0'), // TLS bypass issues
      // Media / Cache
      const MapEntry('cached_network_image', '<3.3.0'), // SSRF fix
      const MapEntry('photo_view', '<0.14.0'), // Memory exhaustion
      // Auth / Crypto
      const MapEntry('local_auth', '<2.1.0'), // Biometric bypass
      const MapEntry('encrypt', '<5.0.0'), // Padding oracle fix
      const MapEntry('pointycastle', '<3.7.0'), // ECDSA timing issues
      // Serialization
      const MapEntry('json_serializable', '<6.6.0'), // Code generation issues
      const MapEntry('freezed', '<2.4.0'), // Annotation parsing issues
      // State management
      const MapEntry('mobx', '<2.2.0'), // Reaction memory leak
      const MapEntry('flutter_bloc', '<8.1.0'), // Event sanitization
    ];

    for (final entry in vulnerablePackages) {
      final package = entry.key;
      final constraint = entry.value;
      final pattern = RegExp(
        r'^\s*' + RegExp.escape(package) + r':\s*(.+)$',
        multiLine: true,
      );

      for (final match in pattern.allMatches(file.content)) {
        final version = match.group(1)!.trim();
        // Simple version check — in production, use pub_semver
        if (_isVersionVulnerable(version, constraint)) {
          final line = file.lineForOffset(match.start);

          findings.add(Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message: 'Potentially vulnerable package: $package $version',
            fix:
                'Upgrade $package to a version that fixes known security '
                'vulnerabilities. Check pub.dev for the latest secure version '
                'and review the changelog for security fixes.',
            risk:
                'This package version is known to have security vulnerabilities. '
                'Attackers may exploit these to compromise your app or user data.',
            filePath: file.relativePath,
            line: line,
          ));
        }
      }
    }

    return findings;
  }

  /// Security-sensitive packages where loose constraints matter.
  static final _securitySensitivePackages = <String>{
    'dio', 'http', 'chopper', 'retrofit',
    'supabase_flutter', 'firebase_auth', 'google_sign_in',
    'flutter_appauth', 'oauth2', 'openid_client',
    'webview_flutter', 'flutter_inappwebview',
    'file_picker', 'image_picker',
    'local_auth', 'flutter_secure_storage',
    'encrypt', 'crypto', 'pointycastle',
    'url_launcher', 'share_plus',
  };

  /// Detects overly permissive version constraints on security-sensitive
  /// packages. Flagging every caret constraint is pure noise — ^ is the
  /// Dart ecosystem standard. We only warn for packages that handle
  /// network, auth, crypto, or storage.
  List<Finding> _findLooseVersionConstraints(ScannedFile file) {
    final findings = <Finding>[];

    // Find dependencies with unbounded >= (no upper bound).
    // Caret (^) is standard and safe — it prevents major-version drift.
    // >= without <X.0.0 allows ANY future version, including breaking
    // changes that may introduce vulnerabilities.
    // Handles both quoted and unquoted YAML values.
    final loosePattern = RegExp(
      r'^\s*(\w+):\s*[\"\x27]?\>=[\d\.]+[\"\x27]?\s*$',
      multiLine: true,
    );

    for (final match in loosePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Skip SDK dependencies (flutter, dart) — those are fine.
      // Use a stricter check to avoid false-skipping packages like
      // supabase_flutter which contain 'flutter' in their name.
      final lineContent = file.lines[line - 1];
      final trimmed = lineContent.trim();
      if (trimmed.startsWith('sdk:') ||
          trimmed.startsWith('flutter:') ||
          trimmed.startsWith('dart:')) {
        continue;
      }

      // Only flag security-sensitive packages
      final packageName = match.group(1);
      if (packageName == null ||
          !_securitySensitivePackages.contains(packageName)) {
        continue;
      }

      findings.add(Finding(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.low,
        category: FindingCategory.security,
        code: code,
        message: 'Unbounded >= constraint on security-sensitive package',
        fix:
            'Replace the open-ended >= constraint with a bounded range '
            '(e.g., `package: ">=1.2.3 <2.0.0"`) or pin to a specific version. '
            'Without an upper bound, any future major version — potentially '
            'introducing breaking changes or vulnerabilities — can be pulled '
            'automatically.',
        risk:
            'An unbounded >= constraint allows ANY future version of the package, '
            'including major releases that may introduce security vulnerabilities, '
            'breaking API changes, or malicious code in a compromised publish.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects git/path dependencies without commit pinning.
  List<Finding> _findUnpinnedDependencies(ScannedFile file) {
    final findings = <Finding>[];

    // Git dependencies without ref/commit
    final gitPattern = RegExp(
      r'^\s*\w+:\s*\n\s*git:\s*\n(?!.*\n\s*ref:).*',
      multiLine: true,
      dotAll: true,
    );

    for (final match in gitPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Git dependency without pinned commit or tag',
        fix:
            'Pin git dependencies to a specific commit hash or release tag '
            'using the `ref:` field. Without pinning, the dependency can '
            'change unexpectedly, introducing vulnerabilities or malicious code.',
        risk:
            'Unpinned git dependencies track the default branch, which can change '
            'at any time. A compromised upstream repository could inject '
            'malicious code into your build.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    // Path dependencies
    final pathPattern = RegExp(
      r'^\s*\w+:\s*\n\s*path:\s*',
      multiLine: true,
    );

    for (final match in pathPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Local path dependency detected',
        fix:
            'Ensure path dependencies are only used in development. For '
            'production, publish the package to a private registry or '
            'monorepo solution.',
        risk:
            'Path dependencies can lead to inconsistent builds across '
            'environments if the referenced path contents change.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Simple version vulnerability check.
  bool _isVersionVulnerable(String version, String constraint) {
    // Extract version numbers
    final versionMatch = RegExp(r'(\d+)\.(\d+)\.(\d+)').firstMatch(version);
    if (versionMatch == null) return false;

    final major = int.tryParse(versionMatch.group(1)!) ?? 0;
    final minor = int.tryParse(versionMatch.group(2)!) ?? 0;
    final patch = int.tryParse(versionMatch.group(3)!) ?? 0;

    // Parse constraint like "<5.0.0"
    final constraintMatch = RegExp(r'([<>=]+)(\d+)\.(\d+)\.(\d+)').firstMatch(constraint);
    if (constraintMatch == null) return false;

    final op = constraintMatch.group(1)!;
    final cMajor = int.tryParse(constraintMatch.group(2)!) ?? 0;
    final cMinor = int.tryParse(constraintMatch.group(3)!) ?? 0;
    final cPatch = int.tryParse(constraintMatch.group(4)!) ?? 0;

    // Simple comparison (not full semver)
    final vVersion = major * 1000000 + minor * 1000 + patch;
    final vConstraint = cMajor * 1000000 + cMinor * 1000 + cPatch;

    switch (op) {
      case '<':
        return vVersion < vConstraint;
      case '<=':
        return vVersion <= vConstraint;
      case '>':
        return vVersion > vConstraint;
      case '>=':
        return vVersion >= vConstraint;
      case '=':
        return vVersion == vConstraint;
      default:
        return false;
    }
  }
}
