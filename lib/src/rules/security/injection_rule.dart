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

  // Dynamic SQL: string interpolation or `"sql" + var` concatenation
  // following a SQL keyword. We only check ONE direction here — `var + "sql"`
  // is handled by [_reverseConcatSqlPattern] below so the regex engine does
  // not need to backtrack across the whole snippet.
  static final _dynamicSqlPattern = RegExp(
    r'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|WHERE|FROM)\b[^;]*(?:\$[{a-zA-Z]|['"]?\s*\+\s*[a-zA-Z])''',
    caseSensitive: false,
  );

  // Reverse concatenation: `userInput + " WHERE …"` — a tainted variable
  // glued onto a SQL fragment. Common in Dart string-builder patterns.
  static final _reverseConcatSqlPattern = RegExp(
    r'''[a-zA-Z_][a-zA-Z0-9_.]*\s*\+\s*['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|JOIN)\b''',
    caseSensitive: false,
  );

  // SQL string built into a local variable. Two-stage detection: first find a
  // local assignment that looks like a SQL string with interpolation/concat,
  // then look for the variable being passed to a SQL sink within the next
  // `_localVarLookahead` characters.
  static final _localSqlAssignmentPattern = RegExp(
    r'''(?:final|var|String)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^;]*?(?:\$[{a-zA-Z]|['"]?\s*\+\s*[a-zA-Z])''',
    caseSensitive: false,
  );

  static const int _localVarLookahead = 600;

  // Dynamic string in command: interpolation in Process.run argument.
  static final _dynamicStringPattern = RegExp(
    r'''\$\{[^}]+\}|\$[a-zA-Z_][a-zA-Z0-9_]*''',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      final taintedSqlVars = _findTaintedSqlLocals(file);
      findings.addAll(_checkSqlInjection(file, taintedSqlVars));
      findings.addAll(_checkCommandInjection(file));
    }

    return findings;
  }

  /// First pass: walk the file and record every local variable whose RHS
  /// looks like a dynamically-built SQL string. Returns a map of
  /// `variable name → byte offset of the assignment` so the sink check can
  /// confirm the call site sits within [_localVarLookahead] characters.
  Map<String, int> _findTaintedSqlLocals(ScannedFile file) {
    final tainted = <String, int>{};
    for (final match in _localSqlAssignmentPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final name = match.group(1);
      if (name == null) continue;
      // Keep the latest assignment (closest to a sink) for each name.
      tainted[name] = match.start;
    }
    return tainted;
  }

  List<Finding> _checkSqlInjection(
    ScannedFile file,
    Map<String, int> taintedSqlVars,
  ) {
    final findings = <Finding>[];

    for (final match in _sqlSinkPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Get the argument to the call (up to 500 chars forward).
      final argStart = match.end;
      final argEnd = (argStart + 500).clamp(0, file.content.length);
      final argSnippet = file.content.substring(argStart, argEnd);

      var dynamic = false;

      // 1. Inline SQL with `$var` interpolation or `"sql" + var` concat.
      if (_dynamicSqlPattern.hasMatch(argSnippet) ||
          _reverseConcatSqlPattern.hasMatch(argSnippet)) {
        dynamic = true;
      }

      // 2. The argument is a bare identifier that we previously saw being
      //    assigned a tainted SQL string nearby.
      if (!dynamic) {
        final firstArg = _firstArgIdentifier(argSnippet);
        if (firstArg != null) {
          final assignmentOffset = taintedSqlVars[firstArg];
          if (assignmentOffset != null &&
              match.start - assignmentOffset >= 0 &&
              match.start - assignmentOffset <= _localVarLookahead) {
            dynamic = true;
          }
        }
      }

      if (dynamic) {
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

  /// Returns the first argument's identifier if and only if the argument is a
  /// bare variable reference (no method call, no concatenation). For example,
  /// `db.query(myQuery)` returns `myQuery`; `db.query('SELECT …')` returns
  /// `null`; `db.query(myObj.build())` returns `null`.
  String? _firstArgIdentifier(String argSnippet) {
    var i = 0;
    while (i < argSnippet.length && argSnippet[i] == ' ') {
      i++;
    }
    final identStart = i;
    while (i < argSnippet.length) {
      final ch = argSnippet[i];
      final isLetterOrDigit = (ch.codeUnitAt(0) >= 0x30 &&
              ch.codeUnitAt(0) <= 0x39) ||
          (ch.codeUnitAt(0) >= 0x41 && ch.codeUnitAt(0) <= 0x5A) ||
          (ch.codeUnitAt(0) >= 0x61 && ch.codeUnitAt(0) <= 0x7A) ||
          ch == '_';
      if (!isLetterOrDigit) break;
      i++;
    }
    if (i == identStart) return null;
    final ident = argSnippet.substring(identStart, i);
    // Only return when the next non-space char is a `,` or `)` — i.e. the
    // identifier really IS the entire first argument.
    while (i < argSnippet.length && argSnippet[i] == ' ') {
      i++;
    }
    if (i >= argSnippet.length) return null;
    final terminator = argSnippet[i];
    if (terminator != ',' && terminator != ')') return null;
    return ident;
  }

  List<Finding> _checkCommandInjection(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _commandSinkPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
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

}
