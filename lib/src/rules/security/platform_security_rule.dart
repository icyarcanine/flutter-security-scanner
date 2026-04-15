import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects insecure configurations in Android manifest and iOS plist files.
///
/// This rule is the mobile-platform surface of the scanner. It is deliberately
/// broader than the usual "flag obvious misconfig" checker — the goal is to
/// close the gap between a Flutter developer who has never shipped a mobile
/// app before and the set of manifest / plist knobs the Google Play security
/// review and Apple App Review teams will actually ding them on.
///
/// Android (`AndroidManifest.xml`) checks:
///   * `android:allowBackup="true"` — attacker with adb can pull app data.
///   * `android:usesCleartextTraffic="true"` — opt-in HTTP MITM.
///   * `android:debuggable="true"` — never ship this.
///   * `android:testOnly="true"` — never ship this either.
///   * `android:exported="true"` on components that have no `<intent-filter>`
///     (nothing legit calls them but any app can).
///   * Dangerous permissions that trigger Play Console reviews:
///     `MANAGE_EXTERNAL_STORAGE`, `SYSTEM_ALERT_WINDOW`,
///     `REQUEST_INSTALL_PACKAGES`, `READ_LOGS`, `BIND_ACCESSIBILITY_SERVICE`,
///     `QUERY_ALL_PACKAGES`.
///   * `<uses-sdk android:minSdkVersion="X">` where `X < 24`. Pre-Android 7
///     devices can't enforce modern TLS, system CA pinning, or scoped
///     storage — flag so developers make a conscious choice.
///
/// iOS (`Info.plist`) checks:
///   * `NSAllowsArbitraryLoads = true` — global ATS bypass.
///   * `NSAllowsArbitraryLoadsInWebContent = true` — same thing for WKWebView.
///   * `NSExceptionAllowsInsecureHTTPLoads = true` — per-domain ATS bypass.
///   * `NSThirdPartyExceptionAllowsInsecureHTTPLoads = true` — same for 3rd
///     party domains.
///   * `UIFileSharingEnabled = true` — exposes the app's Documents folder via
///     Finder/Files.app unless that's genuinely intended.
///   * `ITSAppUsesNonExemptEncryption = false` when the project actually uses
///     crypto libraries. The Apple self-classification is wrong and will
///     eventually fail App Review.
///
/// All findings collapse under the single code `platform-security` so they
/// group cleanly in the report and deduplicate nicely for suppressions.
class PlatformSecurityRule extends Rule {
  const PlatformSecurityRule();

  @override
  String get code => 'platform-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    var usesNativeCrypto = false;
    for (final file in context.dartFiles) {
      final content = file.content;
      if (content.contains('pointycastle') ||
          content.contains('cryptography') ||
          content.contains('encrypt:') ||
          content.contains("import 'package:encrypt/")) {
        usesNativeCrypto = true;
        break;
      }
    }

    for (final file in context.files) {
      if (file.name == 'AndroidManifest.xml') {
        findings.addAll(_checkAndroidManifest(file));
      }
      if (file.name == 'Info.plist') {
        findings.addAll(_checkInfoPlist(file, usesNativeCrypto: usesNativeCrypto));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Android
  // ---------------------------------------------------------------------------

  List<Finding> _checkAndroidManifest(ScannedFile file) {
    final findings = <Finding>[];
    final content = file.content;

    void add({
      required FindingSeverity severity,
      required FindingConfidence confidence,
      required String message,
      required String fix,
      required String risk,
      required int offset,
    }) {
      findings.add(
        Finding(
          severity: severity,
          confidence: confidence,
          category: FindingCategory.security,
          code: code,
          message: message,
          fix: fix,
          risk: risk,
          filePath: file.relativePath,
          line: file.lineForOffset(offset),
        ),
      );
    }

    // android:allowBackup="true" — allows data extraction via adb backup.
    final allowBackupPattern = RegExp(r'''android:allowBackup\s*=\s*"true"''');
    for (final match in allowBackupPattern.allMatches(content)) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message: 'Android backup is enabled (android:allowBackup="true")',
        fix:
            'Set android:allowBackup="false" in the <application> tag, or '
            'define backup rules to exclude sensitive data.',
        risk:
            'With backup enabled, app data including tokens and credentials '
            'can be extracted from the device via adb backup.',
        offset: match.start,
      );
    }

    // android:usesCleartextTraffic="true" — allows HTTP connections.
    final cleartextPattern = RegExp(
      r'''android:usesCleartextTraffic\s*=\s*"true"''',
    );
    for (final match in cleartextPattern.allMatches(content)) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message: 'Cleartext traffic is allowed in Android manifest',
        fix:
            'Set android:usesCleartextTraffic="false" and use HTTPS for all '
            'network connections. If needed for development, use a network '
            'security config with domain-specific exceptions.',
        risk:
            'Allowing cleartext traffic enables man-in-the-middle attacks '
            'on any unencrypted HTTP connection.',
        offset: match.start,
      );
    }

    // android:debuggable="true" — should never be in release builds.
    final debuggablePattern = RegExp(r'''android:debuggable\s*=\s*"true"''');
    for (final match in debuggablePattern.allMatches(content)) {
      add(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        message: 'Android app is set as debuggable',
        fix:
            'Remove android:debuggable="true" from the manifest. '
            'Debug mode should only be set via build variants, never hardcoded.',
        risk:
            'A debuggable app can be attached to with a debugger, allowing '
            'extraction of secrets, bypassing security controls, and code '
            'injection.',
        offset: match.start,
      );
    }

    // android:testOnly="true" — never ship a test-only APK.
    final testOnlyPattern = RegExp(r'''android:testOnly\s*=\s*"true"''');
    for (final match in testOnlyPattern.allMatches(content)) {
      add(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        message: 'Android app is marked testOnly',
        fix:
            'Remove android:testOnly="true" from the manifest. A testOnly '
            'APK cannot be installed from the Play Store and typically has '
            'debugging flags enabled.',
        risk:
            'testOnly builds bypass several production checks and are often '
            'shipped accidentally alongside debuggable flags.',
        offset: match.start,
      );
    }

    // android:exported="true" on a component with no <intent-filter>.
    //
    // We scan each <activity|service|receiver|provider ...>...</tag> block,
    // look for `exported="true"` on the opening tag, then verify the block
    // between the opening tag and its matching `/>` or `</...>` contains an
    // `<intent-filter>`. If it doesn't, the component is reachable from any
    // other app on the device but nothing legit calls it — classic
    // misconfiguration.
    for (final component in const [
      'activity',
      'service',
      'receiver',
      'provider',
    ]) {
      final opener = RegExp(
        '<$component\\b[^>]*android:exported\\s*=\\s*"true"[^>]*>',
        caseSensitive: false,
      );
      for (final match in opener.allMatches(content)) {
        // Find the slice covering this component declaration (either a
        // self-closing `/>` or the matching `</component>`).
        final afterOpen = match.end;
        final selfClosing = content
            .substring(match.start, match.end)
            .trimRight()
            .endsWith('/>');
        String block;
        if (selfClosing) {
          block = content.substring(match.start, match.end);
        } else {
          final closeTag = '</$component>';
          final closeIdx = content.indexOf(closeTag, afterOpen);
          block = closeIdx == -1
              ? content.substring(match.start, afterOpen)
              : content.substring(match.start, closeIdx + closeTag.length);
        }
        if (block.contains('<intent-filter')) continue;
        // Also skip if there is a `permission=` attribute — the developer
        // is gating the component manually.
        if (RegExp(r'android:permission\s*=\s*"').hasMatch(
          content.substring(match.start, match.end),
        )) {
          continue;
        }
        add(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          message:
              'Android $component is exported without an <intent-filter> or permission',
          fix:
              'Set android:exported="false" unless this component is genuinely '
              'meant to be called from other apps. If it is, add an '
              '<intent-filter> (for IPC) or android:permission (for signature-'
              'protected access).',
          risk:
              'An exported $component with no intent filter and no permission '
              'can be invoked by any other app on the device, bypassing '
              'intended entry points.',
          offset: match.start,
        );
      }
    }

    // Dangerous permissions audit.
    const dangerousPermissions = {
      'MANAGE_EXTERNAL_STORAGE':
          'Broad file-system access triggers a special Play Console review '
              'and is rarely justifiable in a Flutter app.',
      'SYSTEM_ALERT_WINDOW':
          'Draw-over-other-apps is a common vehicle for overlay phishing '
              'attacks.',
      'REQUEST_INSTALL_PACKAGES':
          'Lets the app silently prompt to install other APKs — a malware '
              'vector.',
      'READ_LOGS':
          'Can read process logs on older/rooted devices, leaking tokens '
              'and PII from other apps.',
      'BIND_ACCESSIBILITY_SERVICE':
          'Accessibility services can read screen content and simulate '
              'taps; reserved for a narrow set of app categories.',
      'QUERY_ALL_PACKAGES':
          'Discloses the full list of installed apps. Play Console requires '
              'justification and it often leaks fingerprinting surface.',
    };
    for (final entry in dangerousPermissions.entries) {
      final perm = entry.key;
      final risk = entry.value;
      final permPattern = RegExp(
        '<uses-permission[^>]*android:name\\s*=\\s*"android\\.permission\\.$perm"',
      );
      for (final match in permPattern.allMatches(content)) {
        add(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          message: 'Sensitive Android permission requested: $perm',
          fix:
              'Remove android.permission.$perm unless the app genuinely needs '
              'it and you have a plan for Play Console review. Prefer '
              'scoped-storage, MediaStore, or Storage Access Framework '
              'alternatives where possible.',
          risk: risk,
          offset: match.start,
        );
      }
    }

    // Ancient minSdkVersion.
    final minSdkPattern = RegExp(
      r'android:minSdkVersion\s*=\s*"(\d+)"',
    );
    for (final match in minSdkPattern.allMatches(content)) {
      final level = int.tryParse(match.group(1) ?? '');
      if (level == null) continue;
      if (level < 24) {
        add(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.high,
          message:
              'Android minSdkVersion is $level (pre-Android 7) — weak TLS and '
              'legacy security model',
          fix:
              'Bump minSdkVersion to at least 24 (Android 7.0). Older levels '
              'cannot enforce modern TLS defaults, lack scoped storage, and '
              'share the full external storage partition.',
          risk:
              'Supporting pre-Android-7 devices means the app must operate '
              'under the legacy security model: weaker default TLS, world-'
              'readable shared storage, no per-app data isolation.',
          offset: match.start,
        );
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // iOS
  // ---------------------------------------------------------------------------

  List<Finding> _checkInfoPlist(
    ScannedFile file, {
    required bool usesNativeCrypto,
  }) {
    final findings = <Finding>[];
    final content = file.content;

    void add({
      required FindingSeverity severity,
      required FindingConfidence confidence,
      required String message,
      required String fix,
      required String risk,
      required int offset,
    }) {
      findings.add(
        Finding(
          severity: severity,
          confidence: confidence,
          category: FindingCategory.security,
          code: code,
          message: message,
          fix: fix,
          risk: risk,
          filePath: file.relativePath,
          line: file.lineForOffset(offset),
        ),
      );
    }

    // NSAppTransportSecurity.NSAllowsArbitraryLoads = true.
    final allowsArbitrary = _plistKeyBoolValue(
      content,
      'NSAllowsArbitraryLoads',
    );
    if (allowsArbitrary.isTrue) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message: 'iOS App Transport Security allows arbitrary loads',
        fix:
            'Remove NSAllowsArbitraryLoads or set it to false. Add specific '
            'domain exceptions in NSExceptionDomains instead.',
        risk:
            'NSAllowsArbitraryLoads disables all App Transport Security '
            'protections, allowing insecure HTTP connections to any server.',
        offset: allowsArbitrary.offset,
      );
    }

    // NSAllowsArbitraryLoadsInWebContent = true (WKWebView bypass).
    final allowsWebContent = _plistKeyBoolValue(
      content,
      'NSAllowsArbitraryLoadsInWebContent',
    );
    if (allowsWebContent.isTrue) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message:
            'iOS ATS bypass enabled for WebView content '
            '(NSAllowsArbitraryLoadsInWebContent="true")',
        fix:
            'Remove NSAllowsArbitraryLoadsInWebContent. If your WebView '
            'legitimately needs HTTP content, narrow it to specific domains '
            'via NSExceptionDomains.',
        risk:
            'Any HTTP URL loaded inside a WKWebView bypasses ATS, giving '
            'an attacker on the network an in-app surface to inject HTML '
            'and JavaScript.',
        offset: allowsWebContent.offset,
      );
    }

    // NSExceptionAllowsInsecureHTTPLoads (per-domain HTTP exception).
    final perDomainHttp = RegExp(
      r'<key>\s*NSExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true\s*/>',
    );
    for (final match in perDomainHttp.allMatches(content)) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message:
            'iOS plist has a per-domain ATS exception allowing insecure HTTP loads',
        fix:
            'Remove NSExceptionAllowsInsecureHTTPLoads or migrate the domain '
            'to HTTPS. Per-domain exceptions still require Apple review.',
        risk:
            'Per-domain HTTP exceptions allow plaintext traffic to a named '
            'host. If that host is ever proxied or DNS-spoofed, credentials '
            'and tokens sent to it are exposed.',
        offset: match.start,
      );
    }

    // NSThirdPartyExceptionAllowsInsecureHTTPLoads — same for 3rd-party.
    final thirdParty = RegExp(
      r'<key>\s*NSThirdPartyExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true\s*/>',
    );
    for (final match in thirdParty.allMatches(content)) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message:
            'iOS plist has a third-party ATS exception allowing insecure HTTP loads',
        fix:
            'Drop the NSThirdPartyExceptionAllowsInsecureHTTPLoads flag and '
            'require HTTPS from the third-party service, or isolate the '
            'insecure traffic to a server-side proxy.',
        risk:
            'Third-party HTTP exceptions let SDKs phone home in cleartext. '
            'Anything they send — device IDs, user events, session tokens — '
            'is visible to network-adjacent attackers.',
        offset: match.start,
      );
    }

    // UIFileSharingEnabled = true (Documents folder exposed via Files app).
    final fileSharing = _plistKeyBoolValue(content, 'UIFileSharingEnabled');
    if (fileSharing.isTrue) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message:
            'iOS Documents folder is exposed via file sharing '
            '(UIFileSharingEnabled="true")',
        fix:
            'Set UIFileSharingEnabled to false unless the app is genuinely a '
            'document editor. Otherwise everything in the Documents folder '
            'is visible and copyable via the Files app and iTunes.',
        risk:
            'Enabling file sharing publishes the contents of the Documents '
            'folder to the user and anyone with device access, which often '
            'includes cached attachments, exported data, or ad-hoc logs.',
        offset: fileSharing.offset,
      );
    }

    // ITSAppUsesNonExemptEncryption = false while the app ships crypto libs.
    final cryptoDeclaration =
        _plistKeyBoolValue(content, 'ITSAppUsesNonExemptEncryption');
    if (usesNativeCrypto && cryptoDeclaration.isFalse) {
      add(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.medium,
        message:
            'Info.plist claims the app uses no non-exempt encryption, but '
            'the project imports a crypto library',
        fix:
            'Either remove the ITSAppUsesNonExemptEncryption key (forcing '
            'Apple to ask at upload time) or set it to true and attach the '
            'encryption export self-classification. Lying here risks App '
            'Review rejection and export-compliance issues.',
        risk:
            'A mismatched encryption declaration can fail App Review and, '
            'in some jurisdictions, constitutes an incorrect export filing.',
        offset: cryptoDeclaration.offset,
      );
    }

    return findings;
  }

  /// Exact-match plist key lookup. Uses `<key>NAME</key>` as the anchor so
  /// `NSAllowsArbitraryLoads` does NOT match inside
  /// `NSAllowsArbitraryLoadsInWebContent`, and then walks forward to the
  /// nearest `<true/>` or `<false/>` within 200 characters.
  _PlistBool _plistKeyBoolValue(String content, String key) {
    final anchor = RegExp(
      '<key>\\s*' + RegExp.escape(key) + '\\s*</key>',
    );
    final match = anchor.firstMatch(content);
    if (match == null) return const _PlistBool(null, -1);

    final windowEnd = (match.end + 200).clamp(0, content.length);
    final window = content.substring(match.end, windowEnd);

    // Strip leading whitespace / comments so we genuinely read the next
    // element, not one several keys away.
    final trimmed = window.trimLeft();
    if (trimmed.startsWith('<true/>') || trimmed.startsWith('<true />')) {
      return _PlistBool(true, match.start);
    }
    if (trimmed.startsWith('<false/>') || trimmed.startsWith('<false />')) {
      return _PlistBool(false, match.start);
    }
    return _PlistBool(null, match.start);
  }
}

/// Simple value-object returned by [_plistKeyBoolValue].
class _PlistBool {
  const _PlistBool(this._value, this.offset);
  final bool? _value;
  final int offset;
  bool get isTrue => _value == true;
  bool get isFalse => _value == false;
}
