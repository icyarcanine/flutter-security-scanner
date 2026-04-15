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
    }

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
