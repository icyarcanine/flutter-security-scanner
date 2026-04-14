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

  /// File system operations that accept paths.
  static final _fileOpPattern = RegExp(
    r'''\b(?:File|Directory)\s*\(\s*(?:\$|['"][^'"]*\$)''',
  );

  /// Path.join or path concatenation with user input.
  static final _pathJoinPattern = RegExp(
    r'''(?:path\.join|join)\s*\([^)]*(?:widget\.|args\.|params\[|request\.|req\.|queryParameters|pathParameters|\$\{)''',
    caseSensitive: false,
  );

  /// Direct string concatenation for file paths with user input.
  static final _pathConcatPattern = RegExp(
    r'''(?:File|Directory)\s*\([^)]*(?:widget\.|args\.|params\[|request\.|req\.)''',
  );

  /// Sanitization patterns that indicate the developer validates the path.
  static final _sanitizationPatterns = [
    RegExp(r'''\.\.'''), // Check for .. traversal
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
