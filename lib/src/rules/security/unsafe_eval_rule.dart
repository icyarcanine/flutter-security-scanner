import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects usage of `eval(...)` and `Function.apply(...)` — the only runtime
/// code-evaluation entry points reachable from Dart.
///
/// A bare `Function(...)` expression is NOT flagged: in Dart `Function` is a
/// type, so `void Function()`, `Function() callback`, and `typedef Foo =
/// Function()` are all declarations — not executable code. The older pattern
/// `\bFunction\s*\(` generated thousands of false positives on idiomatic Dart
/// and has been removed.
class UnsafeEvalRule extends Rule {
  const UnsafeEvalRule();

  @override
  String get code => 'unsafe-eval';

  // `eval(` covers `dart:js` / `dart:js_interop` bridges such as
  // `js.context.callMethod('eval', [...])` or a helper named `eval(...)`.
  static final _evalPattern = RegExp(r'''\beval\s*\(''');

  // `Function.apply(...)` is Dart's reflective invocation API. It is NOT a
  // string-eval, but it can still invoke arbitrary closures with arbitrary
  // arguments; flagging it is worthwhile as a medium-confidence signal.
  static final _functionApplyPattern = RegExp(r'''\bFunction\s*\.\s*apply\s*\(''');

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      _scanPattern(file, _evalPattern, 'eval()', findings);
      _scanPattern(
        file,
        _functionApplyPattern,
        'Function.apply()',
        findings,
      );
    }

    return findings;
  }

  void _scanPattern(
    ScannedFile file,
    RegExp pattern,
    String callName,
    List<Finding> findings,
  ) {
    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Unsafe $callName call detected',
          fix:
              'Avoid using $callName with dynamic content. Refactor to use '
              'safer alternatives like a lookup table or predefined operations.',
          risk:
              '$callName executes arbitrary code at runtime and can be exploited '
              'for code injection attacks.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
  }
}
