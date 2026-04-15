import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Flags `.rpc(…)` calls whose first argument — the RPC function name —
/// is not a safe string literal.
///
/// Supabase's PostgREST exposes every SQL function declared in `public`
/// as an HTTP endpoint reachable via `supabase.rpc('fn_name', …)`. When
/// the function name comes from a variable, a string interpolation, or
/// any other non-literal source, an attacker who can influence that
/// variable may be able to invoke unintended functions — including
/// admin functions, functions owned by `postgres`, or functions that
/// bypass Row Level Security via `SECURITY DEFINER`.
///
/// The rule also flags PostgREST text filters (`.or()`, `.filter()`,
/// `.textSearch()`, `.match()`) whose argument is built with string
/// interpolation. PostgREST's filter grammar is parsed server-side and
/// is trivially injectable when user input is concatenated into the
/// filter string.
class SupabaseRpcInjectionRule extends Rule {
  const SupabaseRpcInjectionRule();

  @override
  String get code => 'supabase-rpc-injection';

  /// Every `.rpc(` call site. We accept an optional `<T>` type argument
  /// in between because Supabase's typed generics look like `.rpc<int>(`.
  static final _rpcCallPattern = RegExp(r'\.rpc\s*(?:<[^>]*>)?\s*\(\s*');

  /// PostgREST text-filter call sites where the first argument is a
  /// freeform expression that gets sent to the server as-is. Any
  /// interpolation inside that string is an injection vector.
  static final _filterCallPattern = RegExp(
    r'\.(or|filter|textSearch|match)\s*\(\s*',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.supabaseCandidateDartFiles) {
      findings.addAll(_scanRpc(file));
      findings.addAll(_scanFilters(file));
    }

    return findings;
  }

  Iterable<Finding> _scanRpc(ScannedFile file) sync* {
    for (final match in _rpcCallPattern.allMatches(file.content)) {
      final argStart = match.end;
      if (argStart >= file.content.length) continue;

      final line = file.lineForOffset(match.start);
      if (isOffsetCommented(file, match.start) ||
          isCommentLine(file.lines[line - 1])) continue;

      final classification = _classifyFirstArg(file.content, argStart);
      switch (classification) {
        case _RpcArgKind.cleanLiteral:
          continue;
        case _RpcArgKind.interpolatedLiteral:
          yield Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message:
                'Supabase RPC function name built with string interpolation',
            fix:
                'Pass the RPC function name as a hardcoded string literal. If you really need to dispatch by name, constrain the value to a fixed whitelist (e.g. a `switch` over an enum) and never concatenate user input into it.',
            risk:
                'An attacker who controls the interpolated value can call any SQL function reachable via PostgREST — including ones marked SECURITY DEFINER that bypass Row Level Security — which may lead to privilege escalation, data exfiltration, or destructive writes.',
            filePath: file.relativePath,
            line: line,
          );
        case _RpcArgKind.nonLiteral:
          yield Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.low,
            category: FindingCategory.security,
            code: code,
            message: 'Supabase RPC function name is not a string literal',
            fix:
                'Pass the RPC function name as a hardcoded string literal or resolve it through a fixed whitelist. Confirm the variable is never influenced by user input.',
            risk:
                'Non-literal RPC names become injection vectors the moment the underlying variable is touched by untrusted input.',
            filePath: file.relativePath,
            line: line,
          );
      }
    }
  }

  Iterable<Finding> _scanFilters(ScannedFile file) sync* {
    for (final match in _filterCallPattern.allMatches(file.content)) {
      final argStart = match.end;
      if (argStart >= file.content.length) continue;

      // Only care about string-literal first arguments — identifier args
      // to `.filter()` are typically ColumnNames/OperatorNames where the
      // third argument is the actual value, which is parameterised.
      final ch = file.content[argStart];
      if (ch != "'" && ch != '"') continue;

      final closeIndex = _findStringClose(file.content, argStart);
      if (closeIndex == -1) continue;
      final literal = file.content.substring(argStart + 1, closeIndex);
      final interpolations = _extractInterpolations(literal);
      if (interpolations.isEmpty) continue;

      // Any PostgREST filter whose only interpolations resolve to the
      // current auth principal (auth.uid(), currentUser.id, or a local
      // aliasing variable) is the officially-documented ownership pattern
      // and must not be flagged as injection.
      if (interpolations.every((expr) => _isAuthDerived(expr, file.content))) {
        continue;
      }

      final line = file.lineForOffset(match.start);
      if (isOffsetCommented(file, match.start) ||
          isCommentLine(file.lines[line - 1])) continue;

      final method = match.group(1)!;
      yield Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message:
            'PostgREST `.$method()` filter built with string interpolation',
        fix:
            'Use PostgREST\'s parameterised builders instead of concatenating values into the filter string. Prefer `.eq()`, `.in_()`, `.lt()` with the value passed as a separate argument, and build `.or()` clauses from pre-validated literals only.',
        risk:
            'PostgREST parses the filter expression server-side. Concatenating user input into `.or()`, `.filter()`, `.textSearch()`, or `.match()` allows attackers to inject additional clauses, disable RLS conditions, or exfiltrate data from columns the user should never see.',
        filePath: file.relativePath,
        line: line,
      );
    }
  }

  _RpcArgKind _classifyFirstArg(String content, int start) {
    final ch = content[start];
    if (ch == "'" || ch == '"') {
      final closeIndex = _findStringClose(content, start);
      if (closeIndex == -1) return _RpcArgKind.cleanLiteral;
      final literal = content.substring(start + 1, closeIndex);
      return _hasInterpolation(literal)
          ? _RpcArgKind.interpolatedLiteral
          : _RpcArgKind.cleanLiteral;
    }
    // Anything else starting at a non-quote character — an identifier, a
    // call, `const`, `this.`, etc. — is a non-literal first argument.
    return _RpcArgKind.nonLiteral;
  }

  /// Finds the matching close-quote for the string literal whose opening
  /// quote sits at [start]. Handles triple-quoted strings and backslash
  /// escapes. Returns the index of the closing quote, or -1 if the file
  /// is truncated mid-string.
  static int _findStringClose(String content, int start) {
    final quote = content[start];
    // Triple-quoted?
    if (start + 2 < content.length &&
        content[start + 1] == quote &&
        content[start + 2] == quote) {
      final triple = '$quote$quote$quote';
      final end = content.indexOf(triple, start + 3);
      return end == -1 ? -1 : end;
    }

    var i = start + 1;
    while (i < content.length) {
      final ch = content[i];
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == quote) return i;
      // Unterminated literal — bail out.
      if (ch == '\n') return -1;
      i++;
    }
    return -1;
  }

  /// Returns true if the string literal body contains a Dart interpolation
  /// (`$identifier` or `${expression}`). A bare `\$` escape is not an
  /// interpolation.
  static bool _hasInterpolation(String literal) {
    return _extractInterpolations(literal).isNotEmpty;
  }

  /// Parses every `$identifier` and `${expression}` interpolation out of
  /// [literal] and returns the raw expression text. `\$` escapes are
  /// skipped.
  static List<String> _extractInterpolations(String literal) {
    final result = <String>[];
    var i = 0;
    while (i < literal.length) {
      final ch = literal[i];
      if (ch == r'\') {
        i += 2;
        continue;
      }
      if (ch != r'$' || i + 1 >= literal.length) {
        i++;
        continue;
      }
      final next = literal[i + 1];
      if (next == '{') {
        // ${expr} — find the matching close brace, accounting for nested
        // braces. This is a rough parse; if the expression has strings of
        // its own we'll still capture the textual expression, which is
        // what we want.
        var depth = 1;
        var j = i + 2;
        while (j < literal.length && depth > 0) {
          final c = literal[j];
          if (c == '{') {
            depth++;
          } else if (c == '}') {
            depth--;
          }
          j++;
        }
        if (depth == 0) {
          result.add(literal.substring(i + 2, j - 1));
          i = j;
          continue;
        }
        break;
      }
      final nextCode = next.codeUnitAt(0);
      if (next == '_' ||
          (nextCode >= 0x41 && nextCode <= 0x5A) ||
          (nextCode >= 0x61 && nextCode <= 0x7A)) {
        // $identifier — read a dotted identifier chain.
        var j = i + 1;
        while (j < literal.length) {
          final c = literal[j];
          final cc = c.codeUnitAt(0);
          final isWord = c == '_' ||
              (cc >= 0x30 && cc <= 0x39) ||
              (cc >= 0x41 && cc <= 0x5A) ||
              (cc >= 0x61 && cc <= 0x7A);
          if (!isWord) break;
          j++;
        }
        result.add(literal.substring(i + 1, j));
        i = j;
        continue;
      }
      i++;
    }
    return result;
  }

  /// Returns true if [expr] is (or resolves to) an auth-derived identifier
  /// like `auth.uid()`, `currentUser.id`, or a local variable whose RHS
  /// references auth state. PostgREST filters that only interpolate
  /// auth-derived UUIDs are the officially-documented ownership pattern
  /// and not injection vectors.
  static bool _isAuthDerived(String expr, String fileContent) {
    final trimmed = expr.trim();
    if (trimmed.isEmpty) return false;

    // Direct auth references inside the expression text.
    final directPattern = RegExp(
      r'(?:supabase\.)?auth\.(?:uid\s*\(\s*\)|currentUser(?:!|\?)?\.id)'
      r'|currentUser(?:!|\?)?\.id'
      r'|user(?:!|\?)?\.id\b',
    );
    if (directPattern.hasMatch(trimmed)) return true;

    // Simple identifier — look upstream in the file for a local binding
    // whose right-hand side reads auth state.
    final identifier = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$');
    if (!identifier.hasMatch(trimmed)) return false;

    final bindingPattern = RegExp(
      '(?:final|var|const|String|String\\?|dynamic)\\s+' +
          RegExp.escape(trimmed) +
          r'\s*=\s*([^;]*);',
    );
    final match = bindingPattern.firstMatch(fileContent);
    if (match == null) return false;
    return directPattern.hasMatch(match.group(1) ?? '');
  }
}

enum _RpcArgKind { cleanLiteral, interpolatedLiteral, nonLiteral }
