import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
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
    baselinePath: options.useBaseline ? '${root.path}/.sast-baseline.json' : null,
  );
  final report = scanner.scan(root.path);

  if (options.generateBaseline) {
    final file = File('${root.path}/.sast-baseline.json');
    final jsonList = report.findings.map((f) => {
      'code': f.code,
      'filePath': f.filePath,
      'message': f.message,
    }).toList();
    file.writeAsStringSync(jsonEncode(jsonList));
    stdout.writeln('Baseline generated at .sast-baseline.json');
    exit(0);
  }

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
    required this.useBaseline,
    required this.generateBaseline,
    required this.error,
  });

  final String targetPath;
  final bool includeSuggestions;
  final bool showHelp;
  final bool useBaseline;
  final bool generateBaseline;
  final String? error;

  static const usage = '''
Usage: dart run fluttersupabasehelper [path] [--no-suggestions] [--help] [--baseline] [baseline]

Scans a Flutter + Supabase project for common security and configuration mistakes.

Arguments:
  path               Project directory to scan. Defaults to the current directory.
  baseline           Generate a new .sast-baseline.json file in the target directory.

Options:
  --no-suggestions   Hide heuristic RLS policy suggestions.
  --baseline         Only show findings that are not in the .sast-baseline.json file.
  --help             Show this message.
''';

  static _CliOptions parse(List<String> args) {
    final parser = ArgParser()
      ..addFlag('help', abbr: 'h', negatable: false)
      ..addFlag('baseline', negatable: false)
      ..addFlag('suggestions', defaultsTo: true, negatable: true);

    try {
      final results = parser.parse(args);
      
      var targetPath = '.';
      var generateBaseline = false;

      if (results.rest.isNotEmpty) {
        if (results.rest.contains('baseline')) {
          generateBaseline = true;
          final restWithoutBaseline = results.rest.where((r) => r != 'baseline').toList();
          if (restWithoutBaseline.isNotEmpty) {
            targetPath = restWithoutBaseline.first;
          }
        } else {
          targetPath = results.rest.first;
        }

        if (results.rest.where((r) => r != 'baseline').length > 1) {
          return _CliOptions(
            targetPath: targetPath,
            includeSuggestions: true,
            showHelp: false,
            useBaseline: false,
            generateBaseline: false,
            error: 'Only one target path can be provided.',
          );
        }
      }

      return _CliOptions(
        targetPath: targetPath,
        includeSuggestions: results['suggestions'] as bool,
        showHelp: results['help'] as bool,
        useBaseline: results['baseline'] as bool,
        generateBaseline: generateBaseline,
        error: null,
      );
    } on ArgParserException catch (e) {
      return _CliOptions(
        targetPath: '.',
        includeSuggestions: true,
        showHelp: false,
        useBaseline: false,
        generateBaseline: false,
        error: e.message,
      );
    }
  }
}
