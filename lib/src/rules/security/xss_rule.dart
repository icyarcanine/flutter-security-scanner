import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../../taint/taint_engine.dart';
import '../rule_helpers.dart';

/// Detects unsafe HTML rendering patterns that can lead to cross-site scripting
/// (XSS) vulnerabilities in Flutter web or Dart server code.
class XssRule extends Rule {
  const XssRule();

  @override
  String get code => 'xss-flaw';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      final ast = file.ast;
      if (ast == null) continue;

      final tracker = TaintTracker();
      ast.accept(tracker);

      for (final tf in tracker.findings) {
        if (tf.sinkKind == SinkKind.xss) {
          final line = file.lineForOffset(tf.node.offset);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: tf.confidence == 'high' ? FindingConfidence.high : FindingConfidence.medium,
              category: FindingCategory.security,
              code: code,
              message: 'Potential XSS: ${tf.sinkName} assignment',
              fix: 'Sanitize HTML data before assigning or use safe alternatives like textContent.',
              risk: 'Cross-site scripting allows attackers to inject malicious scripts that steal user data or hijack sessions.',
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
