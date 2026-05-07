import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../../taint/taint_engine.dart';
import '../rule_helpers.dart';

/// Detects potential SQL injection and command injection patterns in Dart code.
class InjectionRule extends Rule {
  const InjectionRule();

  @override
  String get code => 'injection-flaw';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      final ast = file.ast;
      if (ast == null) continue;

      final tracker = TaintTracker();
      ast.accept(tracker);

      for (final tf in tracker.findings) {
        if (tf.sinkKind == SinkKind.sql) {
          final line = file.lineForOffset(tf.node.offset);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.high,
              confidence: tf.confidence == 'high' ? FindingConfidence.high : FindingConfidence.medium,
              category: FindingCategory.security,
              code: code,
              message: 'Potential SQL injection: dynamic string passed to .${tf.sinkName}()',
              fix: 'Use parameterized queries instead of string interpolation.',
              risk: 'SQL injection allows attackers to read, modify, or delete database contents.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        } else if (tf.sinkKind == SinkKind.command) {
          final line = file.lineForOffset(tf.node.offset);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.high,
              confidence: tf.confidence == 'high' ? FindingConfidence.high : FindingConfidence.medium,
              category: FindingCategory.security,
              code: code,
              message: 'Potential command injection: dynamic string in process execution',
              fix: 'Avoid passing user-controlled values to process execution.',
              risk: 'Command injection allows attackers to execute arbitrary system commands.',
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

