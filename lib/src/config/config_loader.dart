import 'dart:convert';
import 'dart:io';

import '../utils/path_utils.dart';
import 'scanner_config.dart';

/// Loads a [ScannerConfig] from disk. Looks for `.fshrc.yaml`, `.fshrc.yml`,
/// or `.fshrc.json` (in that order) at the given project root, unless an
/// explicit `configPath` is supplied via `--config=…`.
///
/// Returns [ScannerConfig.empty] when no config file is present — absence is
/// not an error. A malformed file raises [ConfigFormatException], which the
/// CLI turns into `exit 2`.
class ConfigLoader {
  const ConfigLoader();

  static const List<String> _candidateNames = <String>[
    '.fshrc.yaml',
    '.fshrc.yml',
    '.fshrc.json',
  ];

  ScannerConfig loadFromRoot(String rootPath) {
    for (final name in _candidateNames) {
      final file = File(joinPath(rootPath, name));
      if (file.existsSync()) {
        return loadFromFile(file.path);
      }
    }
    return ScannerConfig.empty;
  }

  ScannerConfig loadFromFile(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      throw ConfigFormatException(
        'Config file not found: $path',
        sourcePath: path,
      );
    }
    final content = file.readAsStringSync();
    final lowered = path.toLowerCase();
    Map<String, Object?> parsed;
    if (lowered.endsWith('.json')) {
      parsed = _parseJson(content, path);
    } else if (lowered.endsWith('.yaml') || lowered.endsWith('.yml')) {
      parsed = parseYamlSubset(content, sourcePath: path);
    } else {
      // Fallback: sniff the content. JSON files start with `{` after
      // whitespace. Anything else we try as YAML.
      final trimmed = content.trimLeft();
      if (trimmed.startsWith('{')) {
        parsed = _parseJson(content, path);
      } else {
        parsed = parseYamlSubset(content, sourcePath: path);
      }
    }
    return ScannerConfig.fromMap(parsed, sourcePath: path);
  }

  static Map<String, Object?> _parseJson(String source, String path) {
    try {
      final decoded = jsonDecode(source);
      if (decoded is! Map) {
        throw ConfigFormatException(
          'Config root must be a JSON object.',
          sourcePath: path,
        );
      }
      return Map<String, Object?>.from(decoded);
    } on FormatException catch (e) {
      throw ConfigFormatException(
        'JSON parse error: ${e.message}',
        sourcePath: path,
      );
    }
  }
}

/// Parses the YAML subset accepted by `.fshrc.yaml`.
///
/// The scanner intentionally ships with zero pub dependencies, so we do not
/// depend on the canonical `package:yaml`. In exchange, we support only the
/// block-style subset teams actually need for configuration:
///
/// * Nested maps via `key:` + indentation.
/// * Block lists via `- item`.
/// * Scalars: bare strings, double-quoted strings, single-quoted strings,
///   booleans (`true|false|yes|no|on|off`), integers, and `null`/`~`.
/// * Comments with `#` (either at start of a line or preceded by whitespace).
///
/// Unsupported (will throw): flow-style (`{a: 1}`, `[1, 2]`), anchors/aliases,
/// tags, multi-line block scalars (`|`, `>`), tab indentation, nested lists.
/// If a project needs any of these, users should write `.fshrc.json` instead
/// — we explicitly support both.
Map<String, Object?> parseYamlSubset(
  String source, {
  String? sourcePath,
}) {
  final lines = _prepareLines(source, sourcePath);
  final cursor = _Cursor(lines);
  final root = _parseMap(cursor, 0, sourcePath);
  if (!cursor.isAtEnd) {
    final line = cursor.peek()!;
    throw ConfigFormatException(
      'Unexpected content after top-level map: `${line.content}`.',
      sourcePath: sourcePath,
      line: line.lineNumber,
    );
  }
  return root;
}

List<_IndentedLine> _prepareLines(String source, String? sourcePath) {
  final result = <_IndentedLine>[];
  final raw = const LineSplitter().convert(source);
  for (var i = 0; i < raw.length; i++) {
    var line = raw[i];
    if (line.contains('\t')) {
      final tabIndex = line.indexOf('\t');
      final before = line.substring(0, tabIndex);
      if (before.trim().isEmpty) {
        throw ConfigFormatException(
          'Tab characters are not allowed in YAML indentation '
          '(use spaces).',
          sourcePath: sourcePath,
          line: i + 1,
        );
      }
    }
    final commentIdx = _commentStart(line);
    if (commentIdx != -1) {
      line = line.substring(0, commentIdx);
    }
    if (line.trim().isEmpty) continue;
    final trimmed = line.trimLeft();
    final indent = line.length - trimmed.length;
    result.add(
      _IndentedLine(
        lineNumber: i + 1,
        indent: indent,
        content: trimmed.trimRight(),
      ),
    );
  }
  return result;
}

int _commentStart(String line) {
  for (var i = 0; i < line.length; i++) {
    final ch = line[i];
    if (ch != '#') continue;
    if (i == 0) return 0;
    final prev = line[i - 1];
    if (prev == ' ' || prev == '\t') return i;
  }
  return -1;
}

Map<String, Object?> _parseMap(
  _Cursor cursor,
  int baseIndent,
  String? sourcePath,
) {
  final result = <String, Object?>{};
  while (!cursor.isAtEnd) {
    final line = cursor.peek()!;
    if (line.indent < baseIndent) break;
    if (line.indent > baseIndent) {
      throw ConfigFormatException(
        'Unexpected indent at line ${line.lineNumber} '
        '(expected $baseIndent spaces, got ${line.indent}).',
        sourcePath: sourcePath,
        line: line.lineNumber,
      );
    }
    if (line.content.startsWith('- ')) {
      throw ConfigFormatException(
        'List item at a map position (did you forget a key?).',
        sourcePath: sourcePath,
        line: line.lineNumber,
      );
    }
    cursor.advance();

    final colonIdx = _findColon(line.content);
    if (colonIdx == -1) {
      throw ConfigFormatException(
        'Expected `key: value` but got `${line.content}`.',
        sourcePath: sourcePath,
        line: line.lineNumber,
      );
    }

    final key = line.content.substring(0, colonIdx).trim();
    final remainder = line.content.substring(colonIdx + 1).trim();

    if (remainder.isNotEmpty) {
      result[key] = _parseScalar(remainder);
      continue;
    }

    // Empty RHS — either a nested map, a block list, or `null`.
    if (cursor.isAtEnd) {
      result[key] = null;
      continue;
    }
    final next = cursor.peek()!;
    if (next.indent <= baseIndent) {
      result[key] = null;
      continue;
    }
    final childIndent = next.indent;
    if (next.content.startsWith('- ')) {
      result[key] = _parseList(cursor, childIndent, sourcePath);
    } else {
      result[key] = _parseMap(cursor, childIndent, sourcePath);
    }
  }
  return result;
}

List<Object?> _parseList(
  _Cursor cursor,
  int baseIndent,
  String? sourcePath,
) {
  final result = <Object?>[];
  while (!cursor.isAtEnd) {
    final line = cursor.peek()!;
    if (line.indent < baseIndent) break;
    if (line.indent > baseIndent) {
      throw ConfigFormatException(
        'Unexpected indent inside a list at line ${line.lineNumber}.',
        sourcePath: sourcePath,
        line: line.lineNumber,
      );
    }
    if (!line.content.startsWith('- ') && line.content != '-') {
      break;
    }
    cursor.advance();

    final rhs = line.content == '-'
        ? ''
        : line.content.substring(2).trim();

    if (rhs.isEmpty) {
      throw ConfigFormatException(
        'Empty list item at line ${line.lineNumber}. Nested maps inside '
        'list items are not supported by the YAML subset parser — use '
        '.fshrc.json for complex configs.',
        sourcePath: sourcePath,
        line: line.lineNumber,
      );
    }
    result.add(_parseScalar(rhs));
  }
  return result;
}

/// Returns the index of the first `:` that is NOT inside a quoted section,
/// and is followed by either whitespace or end-of-line. This lets us keep
/// URLs and rule codes like `supabase:signed-url-ttl` intact while still
/// finding the `key: value` separator.
int _findColon(String content) {
  var inSingle = false;
  var inDouble = false;
  for (var i = 0; i < content.length; i++) {
    final ch = content[i];
    if (ch == '"' && !inSingle) inDouble = !inDouble;
    if (ch == "'" && !inDouble) inSingle = !inSingle;
    if (inSingle || inDouble) continue;
    if (ch == ':') {
      final next = i + 1 < content.length ? content[i + 1] : null;
      if (next == null || next == ' ' || next == '\t') {
        return i;
      }
    }
  }
  return -1;
}

Object? _parseScalar(String raw) {
  final s = raw.trim();
  if (s.isEmpty) return '';
  if (s == 'null' || s == '~' || s == 'Null' || s == 'NULL') return null;
  final lowered = s.toLowerCase();
  if (lowered == 'true' || lowered == 'yes' || lowered == 'on') return true;
  if (lowered == 'false' || lowered == 'no' || lowered == 'off') return false;
  final asInt = int.tryParse(s);
  if (asInt != null) return asInt;
  if (s.length >= 2 &&
      ((s[0] == '"' && s[s.length - 1] == '"') ||
          (s[0] == "'" && s[s.length - 1] == "'"))) {
    return s.substring(1, s.length - 1);
  }
  return s;
}

class _IndentedLine {
  const _IndentedLine({
    required this.lineNumber,
    required this.indent,
    required this.content,
  });

  final int lineNumber;
  final int indent;
  final String content;
}

class _Cursor {
  _Cursor(this._lines);

  final List<_IndentedLine> _lines;
  int _position = 0;

  bool get isAtEnd => _position >= _lines.length;

  _IndentedLine? peek() => isAtEnd ? null : _lines[_position];

  void advance() => _position++;
}
