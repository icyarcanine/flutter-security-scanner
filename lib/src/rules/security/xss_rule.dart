import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects unsafe HTML rendering patterns that can lead to cross-site scripting
/// (XSS) vulnerabilities in Flutter web or Dart server code.
class XssRule extends Rule {
  const XssRule();

  @override
  String get code => 'xss-flaw';

  static final _patterns = <_XssPattern>[
    _XssPattern(
      RegExp(r'''\.innerHTML\s*='''),
      'innerHTML assignment',
      'Use textContent for plain text or sanitize HTML with a library like DOMPurify.',
    ),
    _XssPattern(
      RegExp(r'''\.outerHTML\s*='''),
      'outerHTML assignment',
      'Avoid outerHTML with dynamic content. Use textContent or sanitize first.',
    ),
    _XssPattern(
      RegExp(r'''dangerouslySetInnerHTML'''),
      'dangerouslySetInnerHTML',
      'Sanitize HTML content before rendering. Use a sanitization library.',
    ),
    _XssPattern(
      RegExp(r'''document\.write\s*\('''),
      'document.write()',
      'Avoid document.write() with dynamic content. Use DOM manipulation instead.',
    ),
    _XssPattern(
      RegExp(r'''HtmlElementView\s*\('''),
      'HtmlElementView with potential unsanitized HTML',
      'Ensure any HTML passed to HtmlElementView is properly sanitized.',
    ),
    _XssPattern(
      RegExp(r'''Html\s*\(\s*data\s*:'''),
      'flutter_html widget with dynamic data',
      'Sanitize HTML data before passing to Html widget to prevent XSS.',
    ),
    _XssPattern(
      RegExp(r'''InAppWebViewController\s*\.\s*evaluateJavascript\s*\('''),
      'JavaScript evaluation in InAppWebView',
      'Sanitize all data before passing to evaluateJavascript(). Use parameterized message passing instead.',
    ),
    _XssPattern(
      RegExp(r'''Markdown\s*\(\s*data\s*:.*\$'''),
      'Markdown widget with interpolated data',
      'Sanitize user input before rendering as Markdown to prevent HTML injection.',
    ),
    _XssPattern(
      RegExp(r'''\.addJavaScriptHandler\s*\('''),
      'JavaScript handler registered in WebView',
      'Validate all data received from JavaScript handlers. Never trust data from the WebView context.',
    ),
  ];

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      for (final pattern in _patterns) {
        for (final match in pattern.regex.allMatches(file.content)) {
          final line = file.lineForOffset(match.start);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.medium,
              category: FindingCategory.security,
              code: code,
              message: 'Potential XSS: ${pattern.description}',
              fix: pattern.fix,
              risk:
                  'Cross-site scripting allows attackers to inject malicious scripts that steal user data or hijack sessions.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }
    }

    return findings;
  }
}

class _XssPattern {
  const _XssPattern(this.regex, this.description, this.fix);
  final RegExp regex;
  final String description;
  final String fix;
}
