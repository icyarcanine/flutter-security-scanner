import 'package:analyzer/dart/analysis/features.dart';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';

import '../utils/path_utils.dart';

class ScannedFile {
  ScannedFile({
    required this.absolutePath,
    required this.relativePath,
    required this.content,
  }) : lines = content.split('\n'),
       _lineOffsets = _buildLineOffsets(content),
       _commentSpans = _buildCommentSpans(content, isDart: _isDartName(relativePath));

  final String absolutePath;
  final String relativePath;
  final String content;
  final List<String> lines;
  final List<int> _lineOffsets;

  /// Sorted, non-overlapping `[start, end)` offsets where the file is inside
  /// a line or block comment. Only computed for source file types where
  /// comments are well-defined; for other files this list is empty.
  final List<(int start, int end)> _commentSpans;

  /// Lazily-parsed Dart AST. Built on first read via the `analyzer` package
  /// (parser-only, no resolution). Returns `null` for non-Dart files or when
  /// the parse throws (e.g. very broken syntax — we don't want a single
  /// malformed file to fail the whole scan).
  CompilationUnit? _astUnit;
  CompilationUnit? get ast {
    if (!isDart) return null;
    if (_astUnit != null) return _astUnit;
    try {
      final result = parseString(
        content: content,
        featureSet: FeatureSet.latestLanguageVersion(),
        throwIfDiagnostics: false,
      );
      _astUnit = result.unit;
    } catch (_) {
      // Ignore parse errors for broken files.
    }
    return _astUnit;
  }

  /// Returns `true` when [offset] falls inside a `/* … */` block comment or
  /// a `// …` line comment. Works even when the match sits well inside a
  /// multi-line comment whose opening line is far above.
  bool isOffsetInsideComment(int offset) {
    if (_commentSpans.isEmpty) return false;
    // Binary search for the last span with `start <= offset`.
    var low = 0;
    var high = _commentSpans.length - 1;
    while (low <= high) {
      final mid = (low + high) ~/ 2;
      final (start, end) = _commentSpans[mid];
      if (offset < start) {
        high = mid - 1;
      } else if (offset >= end) {
        low = mid + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  String get name => basename(relativePath);
  String get extension {
    final fileName = name;
    final dotIndex = fileName.lastIndexOf('.');
    return dotIndex == -1 ? '' : fileName.substring(dotIndex);
  }

  bool get isDart => extension == '.dart';
  bool get isSql => extension == '.sql';
  bool get isMarkdown => extension == '.md';
  bool get isYaml => extension == '.yaml' || extension == '.yml';
  bool get isGitIgnore => name == '.gitignore';
  bool get isEnvFile => name == '.env' || name.startsWith('.env.');
  bool get isEnvTemplateFile {
    if (!isEnvFile) {
      return false;
    }

    final lowered = name.toLowerCase();
    return lowered.endsWith('.example') ||
        lowered.endsWith('.sample') ||
        lowered.endsWith('.template') ||
        lowered.endsWith('.dist');
  }

  int lineForOffset(int offset) {
    var low = 0;
    var high = _lineOffsets.length - 1;

    while (low <= high) {
      final mid = (low + high) ~/ 2;
      final current = _lineOffsets[mid];
      final next = mid + 1 < _lineOffsets.length
          ? _lineOffsets[mid + 1]
          : content.length + 1;
      if (offset >= current && offset < next) {
        return mid + 1;
      }

      if (offset < current) {
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    }

    return 1;
  }

  String contextAroundLine(int line, {int before = 8, int after = 4}) {
    final start = (line - before).clamp(1, lines.length);
    final end = (line + after).clamp(1, lines.length);
    return lines.sublist(start - 1, end).join('\n');
  }

  static List<int> _buildLineOffsets(String content) {
    final offsets = <int>[0];
    for (var index = 0; index < content.length; index++) {
      if (content.codeUnitAt(index) == 10) {
        offsets.add(index + 1);
      }
    }
    return offsets;
  }

  static bool _isDartName(String path) {
    final lower = path.toLowerCase();
    // Comment tracking is only meaningful for C-style comment grammars.
    // JSON/YAML/plist have their own (or no) comment syntax and are scanned
    // structurally elsewhere.
    return lower.endsWith('.dart') ||
        lower.endsWith('.kt') ||
        lower.endsWith('.java') ||
        lower.endsWith('.swift') ||
        lower.endsWith('.ts') ||
        lower.endsWith('.js');
  }

  /// Scans [content] once and records every `// …` and `/* … */` span.
  /// String literals (single-, double-, and triple-quoted, plus raw strings)
  /// are honoured so that `"http://"` does not get treated as a comment.
  /// Non-source file types get an empty list.
  static List<(int, int)> _buildCommentSpans(
    String content, {
    required bool isDart,
  }) {
    if (!isDart) return const [];

    final spans = <(int, int)>[];
    final length = content.length;
    var i = 0;

    while (i < length) {
      final ch = content.codeUnitAt(i);

      // Raw string: `r'…'`, `r"…"`, `r'''…'''`, `r"""…"""`. Content is
      // treated verbatim — no escape handling, but quote counting still
      // applies.
      if (ch == 0x72 /* r */ && i + 1 < length) {
        final next = content.codeUnitAt(i + 1);
        if (next == 0x27 /* ' */ || next == 0x22 /* " */) {
          i = _skipStringLiteral(content, i + 1, raw: true);
          continue;
        }
      }

      // Regular string literals.
      if (ch == 0x27 /* ' */ || ch == 0x22 /* " */) {
        i = _skipStringLiteral(content, i, raw: false);
        continue;
      }

      // Single-line comment: `// …` up to the next newline.
      if (ch == 0x2F /* / */ && i + 1 < length) {
        final next = content.codeUnitAt(i + 1);
        if (next == 0x2F) {
          final start = i;
          i += 2;
          while (i < length && content.codeUnitAt(i) != 0x0A) {
            i++;
          }
          spans.add((start, i));
          continue;
        }
        // Block comment: `/* … */`, may nest in Dart.
        if (next == 0x2A /* * */) {
          final start = i;
          i += 2;
          var depth = 1;
          while (i + 1 < length && depth > 0) {
            final c0 = content.codeUnitAt(i);
            final c1 = content.codeUnitAt(i + 1);
            if (c0 == 0x2F && c1 == 0x2A) {
              depth++;
              i += 2;
            } else if (c0 == 0x2A && c1 == 0x2F) {
              depth--;
              i += 2;
            } else {
              i++;
            }
          }
          if (depth > 0) {
            // Unterminated block comment — treat the rest of the file as
            // commented so no finding escapes.
            i = length;
          }
          spans.add((start, i));
          continue;
        }
      }

      i++;
    }

    return spans;
  }

  /// Advances past a string literal starting at [start] (the opening quote).
  /// Handles triple quotes, escape sequences, and raw strings. Returns the
  /// index one past the closing quote. On unterminated literals returns the
  /// end of the file.
  static int _skipStringLiteral(String content, int start, {required bool raw}) {
    final length = content.length;
    final quote = content.codeUnitAt(start);
    // Detect triple-quoted form.
    final isTriple = start + 2 < length &&
        content.codeUnitAt(start + 1) == quote &&
        content.codeUnitAt(start + 2) == quote;
    var i = isTriple ? start + 3 : start + 1;

    while (i < length) {
      final ch = content.codeUnitAt(i);
      if (!raw && ch == 0x5C /* backslash */) {
        // Skip the escaped char; guard against trailing backslash.
        i += 2;
        continue;
      }
      if (ch == quote) {
        if (isTriple) {
          if (i + 2 < length &&
              content.codeUnitAt(i + 1) == quote &&
              content.codeUnitAt(i + 2) == quote) {
            return i + 3;
          }
          i++;
          continue;
        }
        return i + 1;
      }
      i++;
    }
    return length;
  }
}
