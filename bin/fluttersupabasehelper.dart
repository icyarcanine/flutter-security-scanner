import 'dart:io';

import 'package:fluttersupabasehelper/fluttersupabasehelper.dart';

void main(List<String> args) {
  final options = _CliOptions.parse(args);

  if (options.showHelp) {
    stdout.writeln(_CliOptions.usage);
    exit(0);
  }

  if (options.error != null) {
    stderr.writeln(options.error);
    stderr.writeln(_CliOptions.usage);
    exit(2);
  }

  final root = Directory(options.targetPath);
  if (!root.existsSync()) {
    stderr.writeln('Target path does not exist: ${options.targetPath}');
    exit(2);
  }

  final scanner = ProjectScanner(
    includeSuggestions: options.includeSuggestions,
  );
  final report = scanner.scan(root.path);

  if (report.findings.isEmpty) {
    stdout.writeln('No actionable issues found.');
    stdout.writeln(
      'No major security or config issues detected. Basic security posture looks good.',
    );
    exit(0);
  }

  for (final finding in report.findings) {
    stdout.writeln(finding.toConsoleBlock());
    stdout.writeln();
  }

  final issues = report.findings.where((f) => !f.isSuggestion).toList();
  final issueCount = issues.length;
  final suggestionCount = report.findings.where((f) => f.isSuggestion).length;

  if (issueCount > 0 || suggestionCount > 0) {
    stdout.writeln(
      'Found $issueCount issue${issueCount == 1 ? '' : 's'}'
      '${suggestionCount > 0 ? ' and $suggestionCount suggestion${suggestionCount == 1 ? '' : 's'}' : ''}.',
    );
  }

  final hasHighOrMedium = issues.any(
    (f) =>
        f.severity == FindingSeverity.high ||
        f.severity == FindingSeverity.medium,
  );

  if (!hasHighOrMedium) {
    stdout.writeln();
    stdout.writeln(
      'No major security or config issues detected. Basic security posture looks good.',
    );
  }

  exit(issueCount > 0 ? 1 : 0);
}

class _CliOptions {
  _CliOptions({
    required this.targetPath,
    required this.includeSuggestions,
    required this.showHelp,
    required this.error,
  });

  final String targetPath;
  final bool includeSuggestions;
  final bool showHelp;
  final String? error;

  static const usage = '''
Usage: dart run fluttersupabasehelper [path] [--no-suggestions] [--help]

Scans a Flutter + Supabase project for common security and configuration mistakes.

Arguments:
  path               Project directory to scan. Defaults to the current directory.

Options:
  --no-suggestions   Hide heuristic RLS policy suggestions.
  --help             Show this message.
''';

  static _CliOptions parse(List<String> args) {
    var targetPath = '.';
    var includeSuggestions = true;
    var showHelp = false;
    String? error;

    for (final arg in args) {
      if (arg == '--help' || arg == '-h') {
        showHelp = true;
      } else if (arg == '--no-suggestions') {
        includeSuggestions = false;
      } else if (arg.startsWith('--')) {
        error = 'Unknown option: $arg';
      } else if (targetPath == '.') {
        targetPath = arg;
      } else {
        error = 'Only one target path can be provided.';
      }
    }

    return _CliOptions(
      targetPath: targetPath,
      includeSuggestions: includeSuggestions,
      showHelp: showHelp,
      error: error,
    );
  }
}
