import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure WebView configurations in Flutter apps.
///
/// WebViews are a major attack surface: unrestricted JavaScript, debug mode
/// left on, and loading user-controlled URLs can all lead to compromise.
class WebViewSecurityRule extends Rule {
  const WebViewSecurityRule();

  @override
  String get code => 'webview-security';

  /// Unrestricted JavaScript mode.
  static final _unrestrictedJsPattern = RegExp(
    r'''JavascriptMode\s*\.\s*unrestricted''',
  );

  /// javaScriptMode: JavaScriptMode.unrestricted (webview_flutter v4+).
  static final _jsModeUnrestrictedPattern = RegExp(
    r'''JavaScriptMode\s*\.\s*unrestricted''',
  );

  /// WebView debugging enabled in production code.
  static final _debugEnabledPattern = RegExp(
    r'''debuggingEnabled\s*:\s*true''',
  );

  /// WebView with setJavaScriptEnabled(true) on Android side.
  static final _androidJsEnabledPattern = RegExp(
    r'''setJavaScriptEnabled\s*\(\s*true\s*\)''',
  );

  /// File access enabled in WebView.
  static final _fileAccessPattern = RegExp(
    r'''allowFileAccess\s*:\s*true|setAllowFileAccess\s*\(\s*true\s*\)''',
  );

  /// Loading user-controlled URL in WebView.
  static final _dynamicUrlLoadPattern = RegExp(
    r'''\.loadUrl\s*\(\s*(?:widget\.|args\.|params\[|queryParameters\[|\$)''',
  );

  /// `javascript:` URI fed to a WebView loader. This is a direct script-
  /// execution channel and is essentially never legitimate — even with a
  /// hardcoded literal it pollutes the page with attacker-controlled DOM.
  static final _javascriptUriPattern = RegExp(
    r'''(?:loadUrl|loadRequest|load)\s*\(\s*(?:Uri\.parse\s*\(\s*)?['"]\s*javascript:''',
    caseSensitive: false,
  );

  /// Dynamic script execution: `runJavaScript($foo)`,
  /// `runJavaScriptReturningResult("alert($x)")`,
  /// `evaluateJavascript('…$bar…')`. Any time the executed source is built
  /// from interpolation, the WebView is one tainted variable away from XSS.
  ///
  /// We detect interpolation by looking for a `$` character anywhere in the
  /// first 500 chars of the argument list. A more precise scan would have to
  /// understand Dart string-literal boundaries; the cost is not worth it for
  /// a rule that just needs to flag suspicious code for a human to review.
  static final _dynamicEvalPattern = RegExp(
    r'''(?:runJavaScript|runJavaScriptReturningResult|evaluateJavascript)\s*\([^)]{0,500}\$''',
  );

  /// String-concat variant: `runJavaScript('alert("' + userInput + '")')`.
  /// Catches the common builder pattern that escapes the simple `$` test.
  static final _concatEvalPattern = RegExp(
    r'''(?:runJavaScript|runJavaScriptReturningResult|evaluateJavascript)\s*\([^)]{0,500}['"][^)]{0,500}\+\s*[a-zA-Z_]''',
  );

  /// `loadHtmlString` with interpolated HTML — the `<script>` tag inside the
  /// page sees whatever the developer glued in, so user-supplied values become
  /// executable script.
  static final _dynamicHtmlPattern = RegExp(
    r'''loadHtmlString\s*\([^)]{0,500}\$''',
  );

  /// String-concat variant of `loadHtmlString` for the same reason as above.
  static final _concatHtmlPattern = RegExp(
    r'''loadHtmlString\s*\([^)]{0,500}['"][^)]{0,500}\+\s*[a-zA-Z_]''',
  );

  /// `content://` access enabled — lets the WebView pull data from any
  /// ContentProvider on the device.
  static final _contentAccessPattern = RegExp(
    r'''setAllowContentAccess\s*\(\s*true\s*\)|allowContentAccess\s*:\s*true''',
  );

  /// Universal-origin access from file URLs — classic same-origin bypass.
  static final _universalFileAccessPattern = RegExp(
    r'''(?:setAllowUniversalAccessFromFileURLs|allowUniversalAccessFromFileURLs)\s*(?::\s*|\(\s*)true''',
  );

  /// `setAllowFileAccessFromFileURLs(true)` — can read cross-origin file://
  /// URLs.
  static final _fileFromFilePattern = RegExp(
    r'''(?:setAllowFileAccessFromFileURLs|allowFileAccessFromFileURLs)\s*(?::\s*|\(\s*)true''',
  );

  /// Mixed content mode always allow — HTTP subresources on HTTPS pages.
  static final _mixedContentPattern = RegExp(
    r'''MIXED_CONTENT_ALWAYS_ALLOW|mixedContentMode\s*:\s*MixedContentMode\.alwaysAllow''',
  );

  /// JavaScript channel registration. Any `JavaScriptChannel(name: …)`
  /// instance exposes native method handlers to page scripts.
  static final _javaScriptChannelPattern = RegExp(
    r'''JavaScriptChannel\s*\(''',
  );

  /// Navigation guard indicator — if either a NavigationDelegate or an
  /// explicit onNavigationRequest handler exists in the same file, the
  /// developer at least has a chokepoint to validate origins.
  static final _navGuardPattern = RegExp(
    r'''NavigationDelegate\s*\(|onNavigationRequest\s*:|shouldOverrideUrlLoading\s*:''',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Only scan if the project uses webview packages.
    final usesWebView = _projectUsesWebView(context);
    if (!usesWebView) return findings;

    for (final file in context.appDartFiles) {
      findings.addAll(_checkJavaScriptMode(file));
      findings.addAll(_checkDebugMode(file));
      findings.addAll(_checkFileAccess(file));
      findings.addAll(_checkDynamicUrlLoad(file));
      findings.addAll(_checkJavascriptUri(file));
      findings.addAll(_checkDynamicScriptExecution(file));
      findings.addAll(_checkContentAccess(file));
      findings.addAll(_checkUniversalFileAccess(file));
      findings.addAll(_checkMixedContent(file));
      findings.addAll(_checkJavaScriptChannelOrigin(file));
    }

    return findings;
  }

  List<Finding> _checkContentAccess(ScannedFile file) {
    final findings = <Finding>[];
    for (final match in _contentAccessPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;
      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'WebView has content:// URI access enabled',
          fix:
              'Disable setAllowContentAccess. If you genuinely need to load '
              'data from a ContentProvider, load it yourself and pass the '
              'bytes into the WebView instead of granting the page '
              'unrestricted ContentResolver access.',
          risk:
              'Allowing content:// in a WebView lets scripts inside the '
              'loaded page pull data from any ContentProvider the host app '
              'can see — contacts, calendar, shared storage, other app '
              'databases.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    return findings;
  }

  List<Finding> _checkUniversalFileAccess(ScannedFile file) {
    final findings = <Finding>[];
    for (final match in _universalFileAccessPattern.allMatches(file.content)) {
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
              'WebView enables universal cross-origin access from file:// URLs',
          fix:
              'Set setAllowUniversalAccessFromFileURLs to false. Cross-origin '
              'reads from file:// URLs break the same-origin model and let a '
              'local HTML page read any other file:// URL on the device.',
          risk:
              'With universal file access, a page loaded from file:// can '
              'fetch() any other local file the app can see — arbitrary '
              'read of app-private storage from whatever HTML the WebView '
              'renders.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    for (final match in _fileFromFilePattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;
      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message:
              'WebView allows cross-origin file access between file:// pages',
          fix:
              'Disable setAllowFileAccessFromFileURLs. Even without the '
              'universal variant, cross-origin reads between local pages '
              'are rarely what you want.',
          risk:
              'A local page can fetch neighbouring file:// resources, '
              'leaking any data the app left in its private directories.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    return findings;
  }

  List<Finding> _checkMixedContent(ScannedFile file) {
    final findings = <Finding>[];
    for (final match in _mixedContentPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;
      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message:
              'WebView mixed-content mode is set to ALWAYS_ALLOW — HTTP '
              'resources load inside HTTPS pages',
          fix:
              'Switch to MIXED_CONTENT_NEVER_ALLOW (or '
              'MixedContentMode.neverAllow). If a specific HTTP endpoint is '
              'required, proxy it through HTTPS instead of lowering the '
              'WebView policy globally.',
          risk:
              'Allowing HTTP subresources on an HTTPS page gives a network '
              'attacker an injection point — any script, stylesheet, or '
              'image they can intercept runs inside the secure page.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
    return findings;
  }

  /// A JavaScriptChannel exposes Dart methods to the loaded page. If the
  /// file registers one but does NOT also contain a NavigationDelegate or
  /// onNavigationRequest handler, there is no place to pin the channel to
  /// a trusted origin — any redirect into attacker HTML inherits the
  /// bridge and can call the native handler.
  List<Finding> _checkJavaScriptChannelOrigin(ScannedFile file) {
    final findings = <Finding>[];
    final matches = _javaScriptChannelPattern.allMatches(file.content).toList();
    if (matches.isEmpty) return findings;
    if (_navGuardPattern.hasMatch(file.content)) return findings;

    // Only emit once per file — this is a structural observation, not a
    // per-call-site complaint.
    final first = matches.first;
    if (isOffsetCommented(file, first.start)) return findings;
    final line = file.lineForOffset(first.start);
    if (isCommentLine(file.lines[line - 1])) return findings;

    findings.add(
      Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message:
            'JavaScriptChannel is registered without a NavigationDelegate '
            'or onNavigationRequest guard',
        fix:
            'Wrap the WebViewController with a NavigationDelegate and '
            'reject navigations whose `request.url` is not on your '
            'allow-list. Without the guard, any redirect into attacker '
            'HTML inherits the channel and can call the native handler.',
        risk:
            'A JavaScript channel is a native-code bridge exposed to '
            'whatever page the WebView is currently rendering. If the '
            'WebView can be steered to third-party HTML (open redirect, '
            'cross-origin link, http→https downgrade) that page becomes '
            'able to invoke your native handlers.',
        filePath: file.relativePath,
        line: line,
      ),
    );
    return findings;
  }

  bool _projectUsesWebView(ProjectContext context) {
    final pubspec = context.pubspecFile;
    if (pubspec == null) return false;
    return RegExp(
      r'(^|\s)(?:webview_flutter|flutter_inappwebview|flutter_webview_plugin)\s*:',
      multiLine: true,
    ).hasMatch(pubspec.content);
  }

  List<Finding> _checkJavaScriptMode(ScannedFile file) {
    final findings = <Finding>[];

    for (final pattern in [
      _unrestrictedJsPattern,
      _jsModeUnrestrictedPattern,
      _androidJsEnabledPattern,
    ]) {
      for (final match in pattern.allMatches(file.content)) {
        if (isOffsetCommented(file, match.start)) continue;
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;

        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message: 'WebView has unrestricted JavaScript enabled',
            fix:
                'Only enable JavaScript when necessary and ensure the loaded '
                'URLs are from a trusted allowlist. Consider using '
                'NavigationDelegate to restrict navigation.',
            risk:
                'Unrestricted JavaScript in WebViews can be exploited for XSS '
                'attacks if the loaded content is untrusted.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  List<Finding> _checkDebugMode(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _debugEnabledPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'WebView debugging is enabled',
          fix:
              'Disable WebView debugging in release builds. Gate it behind '
              'kDebugMode: debuggingEnabled: kDebugMode.',
          risk:
              'WebView debugging allows attackers with physical device access '
              'to inspect and manipulate WebView content via Chrome DevTools.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkFileAccess(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _fileAccessPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'WebView file access is enabled',
          fix:
              'Disable file:// access in WebViews unless absolutely required. '
              'Use asset loading or HTTPS URLs instead.',
          risk:
              'File access in WebViews allows malicious scripts to read local '
              'files including app data and credentials.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkDynamicUrlLoad(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _dynamicUrlLoadPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'WebView loads a user-controlled URL',
          fix:
              'Validate and allowlist URLs before loading them in WebViews. '
              'Use a NavigationDelegate to restrict navigation to trusted domains.',
          risk:
              'Loading user-controlled URLs in WebViews can lead to phishing, '
              'credential theft, or JavaScript injection attacks.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkJavascriptUri(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _javascriptUriPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          category: FindingCategory.security,
          code: code,
          message: 'WebView loads a javascript: URI (XSS sink)',
          fix:
              'Never load javascript: URIs through loadUrl/loadRequest. '
              'Use runJavaScript() with a static, audited script and pass '
              'data via channel arguments instead of string-building.',
          risk:
              'javascript: URIs execute arbitrary script in the page context. '
              'Combined with any user-controlled fragment this is a direct XSS.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkDynamicScriptExecution(ScannedFile file) {
    final findings = <Finding>[];

    // Dedupe per (line, code) so the eval and concat patterns hitting the
    // same line don't double-report.
    final reported = <int>{};

    for (final pattern in [
      _dynamicEvalPattern,
      _concatEvalPattern,
      _dynamicHtmlPattern,
      _concatHtmlPattern,
    ]) {
      for (final match in pattern.allMatches(file.content)) {
        if (isOffsetCommented(file, match.start)) continue;
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;
        if (!reported.add(line)) continue;

        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message:
                'WebView executes dynamically built JavaScript or HTML',
            fix:
                'Do not interpolate values into runJavaScript / evaluateJavascript / '
                'loadHtmlString. Use postMessage channels (JavaScriptChannel) and '
                'jsonEncode() the payload, or build the script from a static template '
                'with parameterised channel calls.',
            risk:
                'Interpolated JavaScript/HTML executes attacker-controlled values as '
                'code, enabling XSS, cookie theft, and bridge escape.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }
}
