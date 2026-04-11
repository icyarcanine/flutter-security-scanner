import '../utils/path_utils.dart';

class ScannedFile {
  ScannedFile({
    required this.absolutePath,
    required this.relativePath,
    required this.content,
  }) : lines = content.split('\n'),
       _lineOffsets = _buildLineOffsets(content);

  final String absolutePath;
  final String relativePath;
  final String content;
  final List<String> lines;
  final List<int> _lineOffsets;

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
}
