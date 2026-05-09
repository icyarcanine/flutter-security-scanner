// Public entry point used by ProjectScanner.
//
// Runs `engine-cli` once per built-in YAML rule, parses each invocation's
// JSON output, and converts every entry into a `Finding`. Returns an
// empty list when the binary cannot be located — caller should also
// surface the install hint to the user (see ProjectScanner.scan
// integration).
//
// The YAML rules live in `vscode-extension/rules/` and are shipped alongside
// the extension. For the in-tree Dart scanner, the rules dir is resolved
// relative to the repo root. If the Dart scanner gets published as its own
// pub package later, the rules will need to live under `lib/rules/`.

import 'dart:convert';
import 'dart:io';

import '../models/finding.dart';
import '../models/project_context.dart';
import 'engine_resolver.dart';

/// Result of a single `engine-cli` invocation for one YAML rule.
class EngineRuleResult {
  const EngineRuleResult({
    required this.ruleId,
    required this.findings,
    this.warning,
    this.duration = Duration.zero,
  });

  final String ruleId;
  final List<Finding> findings;
  final String? warning;
  final Duration duration;
}

/// Aggregate result across all YAML rules.
class EngineRunResult {
  const EngineRunResult({
    required this.findings,
    this.warnings = const [],
    this.totalDuration = Duration.zero,
    this.installHint,
  });

  final List<Finding> findings;
  final List<String> warnings;
  final Duration totalDuration;

  /// Set when the binary couldn't be found. Caller may print this to stderr
  /// so the user knows IFDS taint analysis was skipped.
  final String? installHint;

  bool get engineAvailable => installHint == null;
}

/// YAML rule descriptors that the engine-cli can run.
///
/// These correspond to the `.yaml` files in `vscode-extension/rules/`.
const _engineRules = <_RuleDesc>[
  _RuleDesc(
    ruleFile: 'dart-sql-injection.yaml',
    ruleId: 'dart.security.sql-injection',
  ),
  _RuleDesc(
    ruleFile: 'dart-command-injection.yaml',
    ruleId: 'dart.security.command-injection',
  ),
  _RuleDesc(
    ruleFile: 'dart-xss.yaml',
    ruleId: 'dart.security.xss-html-widget',
  ),
];

class _RuleDesc {
  const _RuleDesc({required this.ruleFile, required this.ruleId});
  final String ruleFile;
  final String ruleId;
}

/// Find the repository root directory by looking for known markers.
///
/// Search order:
///   1. The `FLUTTER_SECURITY_SCANNER_ROOT` environment variable (explicit override).
///   2. Walk up from [Platform.script] looking for a `vscode-extension/rules/` dir.
///   3. Walk up from the working directory looking for the same marker.
///   4. Fall back to [fallbackRoot] (the scanned project directory) — in this
///      case rules won't be found and the engine pass will be skipped gracefully.
String _findRepoRoot({String? fallbackRoot}) {
  // Explicit env override.
  final envRoot = Platform.environment['FLUTTER_SECURITY_SCANNER_ROOT'];
  if (envRoot != null && envRoot.isNotEmpty) {
    return envRoot;
  }

  // Try the binary's discovered location: if the resolver found engine-cli
  // at `<repo>/engine/target/release/engine-cli`, the repo root is 4 up.
  // This is handled by checking for the rules dir marker below.

  for (final start in [
    // From Platform.script (the running Dart script).
    Directory(Platform.script.toFilePath()).parent.path,
    // From the current working directory.
    Directory.current.path,
    if (fallbackRoot != null) fallbackRoot,
  ]) {
    var dir = Directory(start);
    while (true) {
      final rulesDir = Directory('${dir.path}/vscode-extension/rules');
      if (rulesDir.existsSync()) {
        return dir.path;
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break; // Reached filesystem root.
      dir = parent;
    }
  }

  return fallbackRoot ?? Directory.current.path;
}

/// Resolve the path to a YAML rule file.
/// Uses the repository root detected from the filesystem or environment.
String _resolveRulePath(String repoRoot, String ruleFile) {
  return '$repoRoot/vscode-extension/rules/$ruleFile';
}

/// Run the Rust engine against [context], invoking engine-cli once per YAML
/// rule via [Process.run]. Returns an aggregate result. When the binary cannot
/// be located, returns an empty findings list with an [installHint] the caller
/// can show.
Future<EngineRunResult> runRustEngine(
  ProjectContext context, {
  Duration timeout = const Duration(seconds: 60),
}) async {
  return runRustEngineSync(context, timeout: timeout);
}

/// Synchronous variant of [runRustEngine] that uses [Process.runSync].
///
/// Suitable for the CLI scanner where blocking the process is acceptable. The
/// async variant delegates to this one and wraps it; both share the same
/// logic path.
EngineRunResult runRustEngineSync(
  ProjectContext context, {
  Duration timeout = const Duration(seconds: 60),
}) {
  final resolveResult = EngineResolver.resolve(repoRoot: context.rootPath);

  if (resolveResult.status == EngineStatus.missing) {
    return EngineRunResult(
      findings: const [],
      installHint: resolveResult.installHint,
    );
  }

  final binaryPath = resolveResult.path!;
  // The scanned project path (engine-cli first argument).
  final scanRoot = context.rootPath;
  // Use the actual repository root (where rules live), not the scanned
  // project root. The repo root is discovered by walking up from the
  // running script or working directory.
  final repoRoot = _findRepoRoot(fallbackRoot: scanRoot);
  final allFindings = <Finding>[];
  final warnings = <String>[];
  var totalDuration = Duration.zero;

  for (final rule in _engineRules) {
    final rulePath = _resolveRulePath(repoRoot, rule.ruleFile);

    // Skip if the YAML file doesn't exist (e.g. rules not checked out).
    if (!File(rulePath).existsSync()) {
      warnings.add('Rule file not found: $rulePath — skipping');
      continue;
    }

    final stopwatch = Stopwatch()..start();
    try {
      final result = Process.runSync(
        binaryPath,
        [
          scanRoot,
          '--rules',
          rulePath,
          '--format',
          'json',
        ],
      );

      stopwatch.stop();
      totalDuration += stopwatch.elapsed;

      if (result.exitCode != 0) {
        final stderrText = (result.stderr as String?)?.trim();
        warnings.add(
          'engine-cli exited with code ${result.exitCode} for rule '
          '${rule.ruleId}: $stderrText',
        );
        continue;
      }

      final stdoutText = result.stdout as String;
      if (stdoutText.trim().isEmpty) {
        continue; // No findings for this rule.
      }

      final parsed = jsonDecode(stdoutText);
      if (parsed is! List) {
        warnings.add(
          'Unexpected JSON output for rule ${rule.ruleId}: '
          'expected array, got ${parsed.runtimeType}',
        );
        continue;
      }

      for (final entry in parsed) {
        if (entry is! Map<String, dynamic>) continue;
        final finding = _parseEngineFinding(entry, rule.ruleId);
        if (finding != null) {
          allFindings.add(finding);
        }
      }
    } catch (e) {
      stopwatch.stop();
      totalDuration += stopwatch.elapsed;
      warnings.add(
        'engine-cli error for rule ${rule.ruleId}: $e',
      );
    }
  }

  return EngineRunResult(
    findings: allFindings,
    warnings: warnings,
    totalDuration: totalDuration,
  );
}

/// Parse a single engine finding JSON entry into a [Finding].
///
/// Expected JSON shape:
/// ```json
/// {
///   "file": "lib/main.dart",
///   "line": 42,
///   "col": 3,
///   "rule_id": "dart.security.sql-injection",
///   "severity": "ERROR",
///   "message": "User-controlled value flows into a SQL sink."
/// }
/// ```
Finding? _parseEngineFinding(Map<String, dynamic> entry, String ruleId) {
  final file = entry['file']?.toString();
  final line = entry['line'];
  final severity = entry['severity']?.toString();
  final message = entry['message']?.toString();

  if (file == null || message == null) return null;

  return Finding(
    category: FindingCategory.security,
    code: ruleId,
    severity: _mapSeverity(severity),
    confidence: FindingConfidence.high,
    detectionMethod: FindingDetectionMethod.taint,
    filePath: file,
    line: line is int ? line : (line is num ? line.toInt() : null),
    message: message,
    fix: '(see rule documentation)',
    risk: 'High-confidence taint flow detected by the Rust analysis kernel.',
  );
}

/// Map engine-cli severity strings to [FindingSeverity].
///
/// engine-cli uses Semgrep-style severity: "ERROR" → high, "WARNING" →
/// medium, anything else → low.
FindingSeverity _mapSeverity(String? severity) {
  if (severity == null) return FindingSeverity.low;
  switch (severity.toUpperCase()) {
    case 'ERROR':
    case 'CRITICAL':
    case 'HIGH':
      return FindingSeverity.high;
    case 'WARNING':
    case 'MEDIUM':
      return FindingSeverity.medium;
    default:
      return FindingSeverity.low;
  }
}
