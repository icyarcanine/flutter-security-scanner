import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects usage of eval() and Function() constructors that execute arbitrary
/// code at runtime — a common code injection vector.
class UnsafeEvalRule extends Rule {
  const UnsafeEvalRule();

  @override
  String get code => 'unsafe-eval';

  static final _evalPattern = RegExp(r'''\beval\s*\(''');

  static final _functionConstructorPattern = RegExp(r'''\bFunction\s*\(''');

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      _scanPattern(file, _evalPattern, 'eval()', findings);
      _scanPattern(file, _functionConstructorPattern, 'Function()', findings);
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
