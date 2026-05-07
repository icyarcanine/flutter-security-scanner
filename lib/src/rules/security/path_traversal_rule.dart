import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects potential path traversal vulnerabilities where user-controlled input
/// is used to construct file paths without sanitization.
///
/// OWASP Mobile Top 10: M4 — Insufficient Input/Output Validation.
class PathTraversalRule extends Rule {
  const PathTraversalRule();

  @override
  String get code => 'path-traversal';

  /// Flutter / Dart source patterns that signal "this value came from
  /// somewhere untrusted". Used as a fragment inside the path sink regexes
  /// below so every sink variant gets the same source list.
  ///
  /// The previous list only recognised Node/Express-ish idioms (`widget.`,
  /// `args.`, `params[`, `request.`, `req.`) plus generic `${}`. That was
  /// enough for simple widget-state injection but missed the real Flutter
  /// exposure points — text field input, platform channel arguments,
  /// clipboard reads, deep-link query parameters, platform environment
  /// variables. Adding those closes the biggest Flutter-source blindspot
  /// the scanner had.
  static const String _flutterSourcePatterns =
      // Widget / route / request-like sources (original list).
      r'widget\.|args\.|params\[|request\.|req\.|'
      // Deep-link / web query string sources.
      r'queryParameters|queryParametersAll|pathParameters|pathParams|'
      // Text field and form input.
      r'Controller\.text|_[a-zA-Z0-9_]*Controller\.text|'
      r'[a-zA-Z_][a-zA-Z0-9_]*Field\.text|TextEditingController|'
      // Platform channel / MethodCall arguments.
      r'MethodCall\.arguments|call\.arguments|'
      // Clipboard pastes.
      r'Clipboard\.getData|ClipboardData|'
      // File pickers and image pickers — user-picked file paths.
      r'FilePicker\.platform|ImagePicker\(\)?\.pick|'
      // ModalRoute / GoRouter / Navigator state.
      r'ModalRoute\.of|GoRouterState|settings\.arguments|'
      // Platform environment + compile-time defines.
      r'Platform\.environment|String\.fromEnvironment|'
      // Stdin.
      r'stdin\.readLineSync|io\.stdin|'
      // Generic string interpolation (weakest signal, kept for continuity).
      r'\$\{|\$[a-zA-Z_]';

  /// File system constructor with a dynamic path argument.
  static final _fileOpPattern = RegExp(
    r'''\b(?:File|Directory)\s*\(\s*(?:\$|['"][^'"]*\$)''',
  );

  /// path.join / join with an attacker-controlled segment.
  static final _pathJoinPattern = RegExp(
    '(?:path\\.join|join)\\s*\\([^)]*(?:$_flutterSourcePatterns)',
    caseSensitive: false,
  );

  /// File/Directory constructor with an attacker-controlled segment in a
  /// plain identifier — e.g. `File(_searchController.text)` or
  /// `File(call.arguments['path'])`.
  static final _pathConcatPattern = RegExp(
    '(?:File|Directory)\\s*\\([^)]*(?:$_flutterSourcePatterns)',
  );

  /// Sanitization patterns that indicate the developer validates the path.
  ///
  /// The previous version of this list included a bare `\.\.` regex "to
  /// detect `..` traversal awareness". That pattern also matches Dart's
  /// cascade operator (`file..createSync()`, `path..trim()`), so virtually
  /// every file that used cascades was silently treated as already-sanitized
  /// — a catastrophic false negative. We now look only for patterns that
  /// clearly target path components: a `..` inside a string literal, or a
  /// `..` followed by a path separator.
  static final _sanitizationPatterns = [
    // Traversal marker inside a string literal: `"\.\."`, `'..'`, etc.
    RegExp(r'''['"]\.\.['"]'''),
    // Traversal marker in a path fragment: `"../"`, `"..\\"`.
    RegExp(r'''\.\.[\\/]'''),
    RegExp(
      r'''canonicalize|normalize|sanitize|validate''',
      caseSensitive: false,
    ),
    RegExp(r'''\.contains\s*\(\s*['"]\.\.['"]'''),
    RegExp(r'''\.startsWith\s*\('''),
    RegExp(r'''path\.isWithin|path\.isAbsolute'''),
  ];

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      _checkPattern(file, _fileOpPattern, findings);
      _checkPattern(file, _pathJoinPattern, findings);
      _checkPattern(file, _pathConcatPattern, findings);
    }

    return findings;
  }

  void _checkPattern(ScannedFile file, RegExp pattern, List<Finding> findings) {
    for (final match in pattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check surrounding context for path sanitization.
      final context = file.contextAroundLine(line, before: 8, after: 8);
      final hasSanitization = _sanitizationPatterns.any(
        (p) => p.hasMatch(context),
      );
      if (hasSanitization) continue;

      findings.add(
        Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          detectionMethod: FindingDetectionMethod.structural,
          trace: TaintTrace([
            TaintStep(
              kind: 'sink',
              filePath: file.relativePath,
              line: line,
              message: 'User-controlled value reaches a filesystem path',
            ),
          ]),
          category: FindingCategory.security,
          code: code,
          message: 'Potential path traversal: user input in file path',
          fix:
              'Validate and sanitize file paths before use. Ensure the resolved '
              'path stays within the intended directory using canonicalize() '
              'and startsWith() checks. Reject paths containing "..".',
          risk:
              'Path traversal allows attackers to read or write arbitrary files '
              'on the device by injecting "../" sequences into file paths.',
          filePath: file.relativePath,
          line: line,
        ),
      );
    }
  }
}
