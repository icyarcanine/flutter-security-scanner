import 'dart:convert';
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

  // Partition findings once — both human and JSON paths need the counts.
  final issues = report.findings.where((f) => !f.isSuggestion).toList();
  final suggestions = report.findings.where((f) => f.isSuggestion).toList();
  final issueCount = issues.length;
  final suggestionCount = suggestions.length;

  switch (options.format) {
    case _OutputFormat.sarif:
      _emitSarif(
        findings: report.findings,
        targetPath: options.targetPath,
      );
    case _OutputFormat.json:
      _emitJson(
        findings: report.findings,
        issueCount: issueCount,
        suggestionCount: suggestionCount,
        targetPath: options.targetPath,
      );
    case _OutputFormat.human:
      _emitHuman(
        findings: report.findings,
        issues: issues,
        issueCount: issueCount,
        suggestionCount: suggestionCount,
      );
  }

  exit(_computeExitCode(issues: issues, threshold: options.failOn));
}

void _emitHuman({
  required List<Finding> findings,
  required List<Finding> issues,
  required int issueCount,
  required int suggestionCount,
}) {
  if (findings.isEmpty) {
    stdout.writeln('No actionable issues found.');
    stdout.writeln(
      'No major security or config issues detected. Basic security posture looks good.',
    );
    return;
  }

  for (final finding in findings) {
    stdout.writeln(finding.toConsoleBlock());
    stdout.writeln();
  }

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
}

void _emitSarif({
  required List<Finding> findings,
  required String targetPath,
}) {
  const writer = SarifWriter();
  stdout.writeln(writer.encode(findings, targetPath: targetPath));
}

void _emitJson({
  required List<Finding> findings,
  required int issueCount,
  required int suggestionCount,
  required String targetPath,
}) {
  final payload = <String, Object?>{
    'tool': 'fluttersupabasehelper',
    'schema_version': 1,
    'target': targetPath,
    'summary': <String, Object?>{
      'total': findings.length,
      'issues': issueCount,
      'suggestions': suggestionCount,
      'high': findings
          .where((f) => f.severity == FindingSeverity.high)
          .length,
      'medium': findings
          .where((f) => f.severity == FindingSeverity.medium)
          .length,
      'low': findings.where((f) => f.severity == FindingSeverity.low).length,
    },
    'findings': findings.map((f) => f.toJson()).toList(),
  };
  stdout.writeln(const JsonEncoder.withIndent('  ').convert(payload));
}

/// Resolves the process exit code from the [issues] list and the `--fail-on`
/// threshold. The default threshold is [FindingSeverity.low] which preserves
/// the original "exit 1 when any non-suggestion issue exists" behaviour.
int _computeExitCode({
  required List<Finding> issues,
  required FindingSeverity threshold,
}) {
  for (final issue in issues) {
    final severity = issue.severity;
    if (severity == null) continue;
    // Lower sortOrder means higher severity, so "at or above the threshold"
    // means severity.sortOrder <= threshold.sortOrder.
    if (severity.sortOrder <= threshold.sortOrder) {
      return 1;
    }
  }
  return 0;
}

enum _OutputFormat { human, json, sarif }

class _CliOptions {
  _CliOptions({
    required this.targetPath,
    required this.includeSuggestions,
    required this.format,
    required this.failOn,
    required this.showHelp,
    required this.error,
  });

  final String targetPath;
  final bool includeSuggestions;
  final _OutputFormat format;
  final FindingSeverity failOn;
  final bool showHelp;
  final String? error;

  static const usage = '''
Usage: dart run fluttersupabasehelper [path] [options]

Scans a Flutter + Supabase project for common security and configuration mistakes.

Arguments:
  path                  Project directory to scan. Defaults to the current directory.

Options:
  --no-suggestions      Hide heuristic RLS policy suggestions.
  --format=<fmt>        Output format: human (default), json, sarif.
  --json                Alias for --format=json.
  --sarif               Alias for --format=sarif (SARIF 2.1.0 for GitHub
                        Code Scanning and other SAST integrations).
  --fail-on=<level>     Exit non-zero only when an issue at or above <level> is
                        found. Levels: high, medium, low. Default: low.
  --help, -h            Show this message.

Exit codes:
  0   No issues at or above --fail-on threshold (or report was clean).
  1   At least one issue met the --fail-on threshold.
  2   Invalid invocation (bad path, unknown flag, …).
''';

  static _CliOptions parse(List<String> args) {
    var targetPath = '.';
    var includeSuggestions = true;
    var format = _OutputFormat.human;
    var failOn = FindingSeverity.low;
    var showHelp = false;
    String? error;

    for (final arg in args) {
      if (arg == '--help' || arg == '-h') {
        showHelp = true;
      } else if (arg == '--no-suggestions') {
        includeSuggestions = false;
      } else if (arg == '--json') {
        format = _OutputFormat.json;
      } else if (arg == '--sarif') {
        format = _OutputFormat.sarif;
      } else if (arg.startsWith('--format=')) {
        final value = arg.substring('--format='.length).toLowerCase();
        switch (value) {
          case 'human':
            format = _OutputFormat.human;
          case 'json':
            format = _OutputFormat.json;
          case 'sarif':
            format = _OutputFormat.sarif;
          default:
            error =
                'Unknown --format value: $value (expected human|json|sarif)';
        }
      } else if (arg == '--format') {
        error = '--format requires a value, e.g. --format=sarif';
      } else if (arg.startsWith('--fail-on=')) {
        final value = arg.substring('--fail-on='.length).toLowerCase();
        switch (value) {
          case 'high':
            failOn = FindingSeverity.high;
          case 'medium':
            failOn = FindingSeverity.medium;
          case 'low':
            failOn = FindingSeverity.low;
          default:
            error = 'Unknown --fail-on level: $value (expected high|medium|low)';
        }
      } else if (arg == '--fail-on') {
        error = '--fail-on requires a value, e.g. --fail-on=high';
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
      format: format,
      failOn: failOn,
      showHelp: showHelp,
      error: error,
    );
  }
}
