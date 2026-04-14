import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects sensitive data being copied to the system clipboard.
///
/// OWASP Mobile Top 10: M6 — Inadequate Privacy Controls.
///
/// On both Android and iOS, clipboard contents are accessible to other apps
/// (especially on Android < 12), and on iOS the clipboard is synced across
/// devices via Universal Clipboard.
class ClipboardExposureRule extends Rule {
  const ClipboardExposureRule();

  @override
  String get code => 'clipboard-exposure';

  /// Clipboard write calls.
  static final _clipboardSetPattern = RegExp(
    r'''Clipboard\s*\.\s*setData\s*\(''',
  );

  /// Sensitive identifiers that should never be on the clipboard.
  static final _sensitivePattern = RegExp(
    r'''(?:token|password|passwd|secret|apiKey|api_key|accessToken|refreshToken|jwt|session|creditCard|cardNumber|cvv|ssn|pin|privateKey|private_key)\b''',
    caseSensitive: false,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      for (final match in _clipboardSetPattern.allMatches(file.content)) {
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;

        // Check the argument region for sensitive data.
        final argStart = match.end;
        final argEnd = (argStart + 300).clamp(0, file.content.length);
        final argSnippet = file.content.substring(argStart, argEnd);

        if (_sensitivePattern.hasMatch(argSnippet)) {
          findings.add(
            Finding(
              severity: FindingSeverity.high,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message: 'Sensitive data copied to clipboard',
              fix:
                  'Do not copy sensitive data (tokens, passwords, keys) to the '
                  'system clipboard. If necessary, clear the clipboard after a '
                  'short timeout using Clipboard.setData(ClipboardData(text: "")).',
              risk:
                  'Clipboard contents are accessible to other apps and may be '
                  'synced across devices. Sensitive data on the clipboard can be '
                  'harvested by malicious apps.',
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
