import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects potential SQL injection and command injection patterns in Dart code.
///
/// Looks for string interpolation or concatenation used in database queries
/// and process execution calls.
class InjectionRule extends Rule {
  const InjectionRule();

  @override
  String get code => 'injection-flaw';

  // SQL sink methods: .query(), .rawQuery(), .execute(), .rawExecute()
  static final _sqlSinkPattern = RegExp(
    r'''\.(query|rawQuery|execute|rawExecute|rawInsert|rawUpdate|rawDelete)\s*\(''',
  );

  // Command injection sinks: Process.run, Process.start, etc.
  static final _commandSinkPattern = RegExp(
    r'''\bProcess\.(run|start)\s*\(|io\.Process\.(run|start)\s*\(''',
  );

  // Dynamic SQL: string interpolation or concatenation with SQL keywords.
  static final _dynamicSqlPattern = RegExp(
    r'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|WHERE|FROM)\b[^;]*(?:\$[{a-zA-Z]|['"]?\s*\+\s*[a-zA-Z])''',
    caseSensitive: false,
  );

  // Dynamic string in command: interpolation in Process.run argument.
  static final _dynamicStringPattern = RegExp(
    r'''\$\{[^}]+\}|\$[a-zA-Z_][a-zA-Z0-9_]*''',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_checkSqlInjection(file));
      findings.addAll(_checkCommandInjection(file));
    }

    return findings;
  }

  List<Finding> _checkSqlInjection(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _sqlSinkPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Get the argument to the call (up to 500 chars forward).
      final argStart = match.end;
      final argEnd = (argStart + 500).clamp(0, file.content.length);
      final argSnippet = file.content.substring(argStart, argEnd);

      // Check if the first argument uses string interpolation/concatenation
      // with SQL keywords — a strong signal of SQL injection.
      if (_dynamicSqlPattern.hasMatch(argSnippet) ||
          _hasDynamicFirstArg(argSnippet)) {
        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message:
                'Potential SQL injection: dynamic string passed to ${match.group(0)!.trim()}',
            fix:
                'Use parameterized queries instead of string interpolation. '
                'Pass user input as query parameters: query("SELECT * FROM t WHERE id = ?", [userId]).',
            risk:
                'SQL injection allows attackers to read, modify, or delete database contents.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  List<Finding> _checkCommandInjection(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _commandSinkPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      final argStart = match.end;
      final argEnd = (argStart + 300).clamp(0, file.content.length);
      final argSnippet = file.content.substring(argStart, argEnd);

      if (_dynamicStringPattern.hasMatch(argSnippet)) {
        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message:
                'Potential command injection: dynamic string in process execution',
            fix:
                'Avoid passing user-controlled values to process execution. '
                'Use a fixed command with a list of arguments instead of string interpolation.',
            risk:
                'Command injection allows attackers to execute arbitrary system commands.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  /// Checks if the first argument to a SQL call contains interpolation.
  bool _hasDynamicFirstArg(String argSnippet) {
    // Look at just the first argument (up to first comma at depth 0 or closing paren).
    var depth = 0;
    var inSingleQuote = false;
    var inDoubleQuote = false;

    for (var i = 0; i < argSnippet.length && i < 300; i++) {
      final ch = argSnippet[i];

      if (ch == '\\') {
        i++; // skip escaped char
        continue;
      }

      if (!inDoubleQuote && ch == "'") {
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (!inSingleQuote && ch == '"') {
        inDoubleQuote = !inDoubleQuote;
        continue;
      }

      if (inSingleQuote || inDoubleQuote) continue;

      if (ch == '(') depth++;
      if (ch == ')') {
        if (depth == 0) break;
        depth--;
      }
      if (ch == ',' && depth == 0) break;
    }

    final firstArg = argSnippet.substring(0, argSnippet.length.clamp(0, 300));

    // Check for string interpolation inside the first argument.
    return _dynamicStringPattern.hasMatch(firstArg) &&
        RegExp(
          r'''\b(select|insert|update|delete|where|from)\b''',
          caseSensitive: false,
        ).hasMatch(firstArg);
  }
}
