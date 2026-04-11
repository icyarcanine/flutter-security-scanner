import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class DebugCodeRule extends Rule {
  const DebugCodeRule();

  @override
  String get code => 'debug-print';

  // Only bare `print(` — not debugPrint or developer.log.
  // Those are used intentionally far more often; flagging them here causes noise.
  static final _plainPrintPattern = RegExp(r'''\bprint\s*\(''');

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.dartFiles) {
      if (!isProductionDartFile(file)) {
        continue;
      }

      for (final stmt in collectLogStatements(file)) {
        // Restrict to statements that start on a line containing `print(`.
        final sourceLine = file.lines[stmt.startLine - 1];
        if (!_plainPrintPattern.hasMatch(sourceLine)) {
          continue;
        }
        if (isCommentLine(sourceLine)) {
          continue;
        }

        // Skip if SensitiveLoggingRule will handle it at HIGH severity.
        if (_looksSensitiveEnough(stmt.argument)) {
          continue;
        }

        findings.add(
          Finding(
            severity: FindingSeverity.low,
            confidence: FindingConfidence.medium,
            category: FindingCategory.config,
            code: code,
            message: 'print() left in production code',
            fix:
                'Remove the debug print or replace it with structured logging that can be disabled outside development.',
            risk:
                'Debug output can leak internal state and increases binary verbosity in production.',
            filePath: file.relativePath,
            line: stmt.startLine,
          ),
        );
      }
    }

    return findings;
  }

  /// Returns true if the argument contains auth-sensitive interpolations or
  /// member accesses — in which case SensitiveLoggingRule owns this finding
  /// at HIGH severity and DebugCodeRule should stay silent.
  bool _looksSensitiveEnough(String argument) {
    // Interpolated auth variable: $session, ${accessToken}, etc.
    if (RegExp(
      r'''\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken|token)\b''',
      caseSensitive: false,
    ).hasMatch(argument)) {
      return true;
    }
    // Member access: .currentSession, .accessToken, etc.
    if (RegExp(
      r'''\.(?:currentUser|currentSession|accessToken|refreshToken|idToken|jwt)\b''',
      caseSensitive: false,
    ).hasMatch(argument)) {
      return true;
    }
    // Bare standalone auth-specific identifiers (word-bounded).
    return RegExp(
      r'''(?<!\w)(?:session|currentUser|currentSession|accessToken|refreshToken)(?!\w)''',
      caseSensitive: false,
    ).hasMatch(argument);
  }
}
