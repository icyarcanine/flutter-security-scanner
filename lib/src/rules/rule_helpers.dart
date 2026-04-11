import '../models/project_context.dart';
import '../models/scanned_file.dart';

bool isTestLikePath(String path) {
  return path.startsWith('test/') ||
      path.startsWith('integration_test/') ||
      path.startsWith('example/') ||
      path.contains('/test/') ||
      path.contains('/integration_test/') ||
      path.contains('/example/');
}

bool isProductionDartFile(ScannedFile file) {
  if (!file.isDart) {
    return false;
  }

  if (isTestLikePath(file.relativePath)) {
    return false;
  }

  return file.relativePath.startsWith('lib/') ||
      file.relativePath.startsWith('bin/');
}

bool isCommentLine(String line) {
  final trimmed = line.trimLeft();
  return trimmed.startsWith('//') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*');
}

Location? firstReferenceFor(
  ProjectContext context,
  String token, {
  Iterable<ScannedFile>? files,
}) {
  for (final file in files ?? context.files) {
    final offset = file.content.indexOf(token);
    if (offset == -1) {
      continue;
    }

    return Location(file: file, line: file.lineForOffset(offset));
  }

  return null;
}

/// A log statement with its starting line (1-indexed) and the joined argument
/// text for analysis.
class LogStatement {
  const LogStatement({required this.startLine, required this.argument});

  /// The 1-indexed line where the print / debugPrint / developer.log call starts.
  final int startLine;

  /// The joined, trimmed argument text of the call.  May span multiple physical
  /// source lines when the call itself is multi-line.
  final String argument;
}

/// Collects all `print(...)`, `debugPrint(...)`, and `developer.log(...)` calls
/// in [file], correctly handling multi-line calls.
///
/// The scanner buffers at most [maxContinuationLines] additional lines after the
/// opening `(` to cap memory use.  Calls that do not close within that window
/// are still emitted with whatever text was captured — false negatives here are
/// preferable to large allocations on adversarial input.
List<LogStatement> collectLogStatements(
  ScannedFile file, {
  int maxContinuationLines = 8,
}) {
  final result = <LogStatement>[];
  final callPattern = RegExp(
    r'''\b(?:print|debugPrint|developer\.log)\s*\(''',
  );

  final lines = file.lines;

  for (var i = 0; i < lines.length; i++) {
    final lineText = lines[i];
    if (isCommentLine(lineText)) {
      continue;
    }

    final match = callPattern.firstMatch(lineText);
    if (match == null) {
      continue;
    }

    // Everything after the opening '(' on the first line.
    final afterParen = lineText.substring(match.end);

    // Try to close the statement on a single line first (fast path).
    final closeIndex = _findMatchingClose(afterParen, 0);
    if (closeIndex != -1) {
      result.add(
        LogStatement(
          startLine: i + 1,
          argument: afterParen.substring(0, closeIndex).trim(),
        ),
      );
      continue;
    }

    // Multi-line path: buffer continuation lines.
    final buffer = StringBuffer(afterParen);
    // Depth counts the net open parens. We start at 1 to account for the '('
    // that opened the `print(` call.
    var depth = 1 + _countOpenParens(afterParen) - _countCloseParens(afterParen);
    var closed = false;

    for (var j = i + 1;
        j < lines.length && j <= i + maxContinuationLines;
        j++) {
      final continuation = lines[j].trim();
      // Stop at a blank line or a comment-only line that looks like a new
      // statement — avoids bleeding into unrelated code.
      if (continuation.isEmpty || isCommentLine(continuation)) {
        break;
      }
      buffer.write(' $continuation');
      depth += _countOpenParens(continuation) - _countCloseParens(continuation);
      if (depth <= 0) {
        closed = true;
        break;
      }
    }

    // Extract argument: everything between the outer parens.
    final joined = buffer.toString();
    final endMark = closed ? joined.lastIndexOf(')') : joined.length;
    final safeEndMark = endMark == -1 ? joined.length : endMark;
    result.add(
      LogStatement(
        startLine: i + 1,
        argument: joined.substring(0, safeEndMark).trim(),
      ),
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Finds the index of the closing `)` in [text] that matches the first `(`
/// (i.e. depth becomes 0), handling nested parens and ignoring characters
/// inside string literals (single and double quotes with escapes).
/// Returns -1 if not found.
int _findMatchingClose(String text, int startDepth) {
  var depth = startDepth;
  var inSingleQuote = false;
  var inDoubleQuote = false;
  var inTripleSingle = false;
  var inTripleDouble = false;
  var isEscaped = false;

  for (var i = 0; i < text.length; i++) {
    final ch = text[i];

    if (isEscaped) {
      isEscaped = false;
      continue;
    }

    if (ch == '\\') {
      isEscaped = true;
      continue;
    }

    // Rough check for triple quotes (look ahead 2 chars, very basic)
    if (ch == "'" && !inSingleQuote && !inDoubleQuote && !inTripleDouble) {
      if (i + 2 < text.length && text[i + 1] == "'" && text[i + 2] == "'") {
        inTripleSingle = !inTripleSingle;
        i += 2; // skip
        continue;
      }
    }
    if (ch == '"' && !inSingleQuote && !inDoubleQuote && !inTripleSingle) {
      if (i + 2 < text.length && text[i + 1] == '"' && text[i + 2] == '"') {
        inTripleDouble = !inTripleDouble;
        i += 2; // skip
        continue;
      }
    }

    // Normal quote checks
    if (ch == "'" && !inTripleSingle && !inTripleDouble && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }
    if (ch == '"' && !inTripleSingle && !inTripleDouble && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    if (inSingleQuote || inDoubleQuote || inTripleSingle || inTripleDouble) {
      continue;
    }

    if (ch == '(') {
      depth++;
    } else if (ch == ')') {
      if (depth == 0) {
        return i;
      }
      depth--;
    }
  }
  return -1;
}

/// Strip string literals before doing raw character counting
String _stripStrings(String text) {
  return text
      .replaceAll(RegExp(r'''"""[\s\S]*?"""'''), '')
      .replaceAll(RegExp(r"'''[\s\S]*?'''"), '')
      .replaceAll(RegExp(r'''"(?:[^"\\]|\\.)*"'''), '')
      .replaceAll(RegExp(r"""'(?:[^'\\]|\\.)*'"""), '');
}

int _countOpenParens(String text) {
  var count = 0;
  final sanitized = _stripStrings(text);
  for (var i = 0; i < sanitized.length; i++) {
    if (sanitized[i] == '(') count++;
  }
  return count;
}

int _countCloseParens(String text) {
  var count = 0;
  final sanitized = _stripStrings(text);
  for (var i = 0; i < sanitized.length; i++) {
    if (sanitized[i] == ')') count++;
  }
  return count;
}
