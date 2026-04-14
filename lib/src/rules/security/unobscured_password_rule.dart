import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects password/PIN input fields that don't use obscureText: true.
///
/// OWASP Mobile Top 10: M6 — Inadequate Privacy Controls.
///
/// When a TextField is used for password input without obscuring, the password
/// is visible on screen and may appear in screenshots, screen recordings, or
/// over-the-shoulder observation.
class UnobscuredPasswordRule extends Rule {
  const UnobscuredPasswordRule();

  @override
  String get code => 'unobscured-password-field';

  /// TextField/TextFormField with password-related decoration or controller.
  static final _passwordFieldPattern = RegExp(
    r'''(?:TextField|TextFormField)\s*\([^;]{0,800}(?:password|passwd|pin|secret|credential)''',
    caseSensitive: false,
  );

  /// The obscureText property set to true.
  static final _obscureTextPattern = RegExp(r'''obscureText\s*:\s*true''');

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      for (final match in _passwordFieldPattern.allMatches(file.content)) {
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;

        // Check if the same TextField also has obscureText: true.
        final widgetText = match.group(0)!;
        if (_obscureTextPattern.hasMatch(widgetText)) continue;

        // Also check the broader context (in case obscureText is on a nearby line).
        final context = file.contextAroundLine(line, before: 2, after: 15);
        if (_obscureTextPattern.hasMatch(context)) continue;

        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message: 'Password input field without obscureText: true',
            fix:
                'Add obscureText: true to TextField/TextFormField widgets '
                'that accept passwords, PINs, or other sensitive input.',
            risk:
                'Without obscureText, passwords are visible on screen and may '
                'be captured in screenshots, screen recordings, or by observers.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }
}
