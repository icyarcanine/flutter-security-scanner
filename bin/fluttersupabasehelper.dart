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

  // Load .fshrc.{yaml,yml,json} if present (or the explicit --config=path).
  // A malformed config is treated as a CLI error so CI fails fast.
  ScannerConfig fileConfig;
  try {
    if (options.configPath != null) {
      fileConfig = const ConfigLoader().loadFromFile(options.configPath!);
    } else {
      fileConfig = const ConfigLoader().loadFromRoot(root.path);
    }
  } on ConfigFormatException catch (e) {
    stderr.writeln('Config error: $e');
    exit(2);
  }

  // CLI flags always win over config values.
  final effectiveIncludeSuggestions = options.explicitNoSuggestions
      ? false
      : (fileConfig.includeSuggestions ?? options.includeSuggestions);
  final effectiveFailOn = options.explicitFailOn
      ? options.failOn
      : (fileConfig.failOn ?? options.failOn);

  final scanner = ProjectScanner(
    includeSuggestions: effectiveIncludeSuggestions,
    config: fileConfig,
  );
  final report = scanner.scan(root.path);

  // --write-baseline: snapshot *everything* the scanner found (before
  // baseline filtering) so the new baseline reflects the current state of
  // the repo. A caller that both writes and applies a baseline in the same
  // invocation still sees unsuppressed output, which is what they want for
  // the "capture then verify" workflow.
  if (options.writeBaselinePath != null) {
    try {
      BaselineFile.fromFindings(
        report.findings,
        toolVersion: SarifWriter.kToolVersion,
      ).writeToFile(options.writeBaselinePath!);
      stderr.writeln(
        'Baseline written to ${options.writeBaselinePath} '
        '(${report.findings.length} finding${report.findings.length == 1 ? '' : 's'}).',
      );
    } catch (e) {
      stderr.writeln('Failed to write baseline: $e');
      exit(2);
    }
  }

  // --baseline: suppress findings that were already present when the
  // baseline was captured. This is the primary adoption lever for existing
  // codebases — teams lock in the current state and only pay attention to
  // what the scanner newly discovers.
  var filtered = report.findings;
  var suppressedCount = 0;
  if (options.baselinePath != null) {
    try {
      final baseline = BaselineFile.loadFromFile(options.baselinePath!);
      filtered = baseline.filter(report.findings);
      suppressedCount = report.findings.length - filtered.length;
    } on BaselineFormatException catch (e) {
      stderr.writeln('Baseline error: $e');
      exit(2);
    }
  }

  // Partition findings once — both human and JSON paths need the counts.
  final issues = filtered.where((f) => !f.isSuggestion).toList();
  final suggestions = filtered.where((f) => f.isSuggestion).toList();
  final issueCount = issues.length;
  final suggestionCount = suggestions.length;

  switch (options.format) {
    case _OutputFormat.sarif:
      _emitSarif(
        findings: filtered,
        targetPath: options.targetPath,
      );
    case _OutputFormat.json:
      _emitJson(
        findings: filtered,
        issueCount: issueCount,
        suggestionCount: suggestionCount,
        targetPath: options.targetPath,
      );
    case _OutputFormat.human:
      _emitHuman(
        findings: filtered,
        issues: issues,
        issueCount: issueCount,
        suggestionCount: suggestionCount,
      );
      if (suppressedCount > 0) {
        stdout.writeln();
        stdout.writeln(
          '$suppressedCount finding(s) suppressed by baseline '
          '${options.baselinePath}.',
        );
      }
  }

  exit(_computeExitCode(issues: issues, threshold: effectiveFailOn));
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
    required this.explicitNoSuggestions,
    required this.format,
    required this.failOn,
    required this.explicitFailOn,
    required this.configPath,
    required this.baselinePath,
    required this.writeBaselinePath,
    required this.showHelp,
    required this.error,
  });

  final String targetPath;
  final bool includeSuggestions;
  final bool explicitNoSuggestions;
  final _OutputFormat format;
  final FindingSeverity failOn;
  final bool explicitFailOn;
  final String? configPath;
  final String? baselinePath;
  final String? writeBaselinePath;
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
  --config=<path>       Explicit path to a config file. By default the scanner
                        looks for .fshrc.yaml / .fshrc.yml / .fshrc.json at the
                        target root. CLI flags override config values.
  --baseline=<path>     Suppress findings whose fingerprint is present in the
                        baseline file. Use this to adopt the scanner on an
                        existing codebase without fixing every finding up
                        front — only NEW findings break the build.
  --write-baseline=<p>  Write the current run's findings to <p> as a fresh
                        baseline file. Combine with --baseline to regenerate.
  --help, -h            Show this message.

Exit codes:
  0   No issues at or above --fail-on threshold (or report was clean).
  1   At least one issue met the --fail-on threshold.
  2   Invalid invocation (bad path, unknown flag, malformed config, …).
''';

  static _CliOptions parse(List<String> args) {
    var targetPath = '.';
    var includeSuggestions = true;
    var explicitNoSuggestions = false;
    var format = _OutputFormat.human;
    var failOn = FindingSeverity.low;
    var explicitFailOn = false;
    String? configPath;
    String? baselinePath;
    String? writeBaselinePath;
    var showHelp = false;
    String? error;

    for (final arg in args) {
      if (arg == '--help' || arg == '-h') {
        showHelp = true;
      } else if (arg == '--no-suggestions') {
        includeSuggestions = false;
        explicitNoSuggestions = true;
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
        explicitFailOn = true;
      } else if (arg == '--fail-on') {
        error = '--fail-on requires a value, e.g. --fail-on=high';
      } else if (arg.startsWith('--config=')) {
        configPath = arg.substring('--config='.length);
        if (configPath.isEmpty) {
          error = '--config requires a path, e.g. --config=.fshrc.yaml';
        }
      } else if (arg == '--config') {
        error = '--config requires a path, e.g. --config=.fshrc.yaml';
      } else if (arg.startsWith('--baseline=')) {
        baselinePath = arg.substring('--baseline='.length);
        if (baselinePath.isEmpty) {
          error = '--baseline requires a path';
        }
      } else if (arg == '--baseline') {
        error = '--baseline requires a path, e.g. --baseline=.fsbaseline.json';
      } else if (arg.startsWith('--write-baseline=')) {
        writeBaselinePath = arg.substring('--write-baseline='.length);
        if (writeBaselinePath.isEmpty) {
          error = '--write-baseline requires a path';
        }
      } else if (arg == '--write-baseline') {
        error =
            '--write-baseline requires a path, e.g. --write-baseline=.fsbaseline.json';
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
      explicitNoSuggestions: explicitNoSuggestions,
      format: format,
      failOn: failOn,
      explicitFailOn: explicitFailOn,
      configPath: configPath,
      baselinePath: baselinePath,
      writeBaselinePath: writeBaselinePath,
      showHelp: showHelp,
      error: error,
    );
  }
}
