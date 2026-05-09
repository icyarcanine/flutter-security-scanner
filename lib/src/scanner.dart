import 'dart:convert';
import 'dart:io';

import 'config/scanner_config.dart';
import 'engine/engine_runner.dart';
import 'models/finding.dart';
import 'models/project_context.dart';
import 'rule.dart';
import 'rules.dart';

class ProjectScanReport {
  const ProjectScanReport({required this.context, required this.findings});

  final ProjectContext context;
  final List<Finding> findings;
}

class ProjectScanner {
  const ProjectScanner({
    this.includeSuggestions = true,
    this.baselinePath,
    this.config = ScannerConfig.empty,
  });

  final bool includeSuggestions;
  final String? baselinePath;

  /// In-repo configuration (`.fshrc.yaml` / `.fshrc.json`). When
  /// [ScannerConfig.empty] is used the scanner behaves exactly as before
  /// config support landed — all discovered rules run, no severity remap,
  /// no path filtering.
  final ScannerConfig config;

  /// Tracks whether the engine install hint has been printed this process
  /// lifetime so we don't spam stderr on every scan invocation.
  static bool _engineHintPrinted = false;

  ProjectScanReport scan(String rootPath) {
    final context = ProjectContext.load(
      rootPath,
      excludePath: config.excludePatterns.isEmpty
          ? null
          : config.isPathExcluded,
    );
    final findings = <Finding>[];

    // ---- Rust engine pass (high-confidence taint analysis) ----
    // Run BEFORE the regex rules so an engine timeout doesn't block the
    // cheap pattern-matching tier. When the binary isn't found, emit the
    // install hint to stderr once per process lifetime.
    final engineResult = runRustEngineSync(context);
    findings.addAll(engineResult.findings);
    for (final w in engineResult.warnings) {
      stderr.writeln('[fluttersupabasehelper] engine: $w');
    }
    if (engineResult.installHint != null && !_engineHintPrinted) {
      _engineHintPrinted = true;
      stderr.writeln(engineResult.installHint);
    }

    // ---- Dart-side regex / structural rules ----
    final rules = buildDefaultRules(
      includeSuggestions: includeSuggestions,
    ).where((rule) => !config.isRuleDisabled(rule.code));

    for (final rule in rules) {
      try {
        findings.addAll(rule.evaluate(context));
      } catch (error, stackTrace) {
        // Isolate rule failures: one broken rule (catastrophic regex
        // backtracking, unexpected input shape, assertion error) must not
        // abort the entire scan. Emit an internal finding so the failure is
        // visible in the report without masking the remaining rules.
        findings.add(_internalRuleFailureFinding(rule, error));
        stderr.writeln(
          '[fluttersupabasehelper] rule ${rule.code} failed: $error',
        );
        stderr.writeln(stackTrace);
      }
    }

    final postConfig = _applyConfig(findings);
    final dedupedFindings = _dedupe(postConfig);
    dedupedFindings.sort(_compareFindings);

    var filteredFindings = _applySuppressions(context, dedupedFindings);
    
    if (baselinePath != null) {
      filteredFindings = _applyBaseline(filteredFindings, baselinePath!);
    }

    return ProjectScanReport(context: context, findings: filteredFindings);
  }

  List<Finding> _applyBaseline(List<Finding> findings, String baselinePath) {
    final file = File(baselinePath);
    if (!file.existsSync()) return findings;

    try {
      final content = file.readAsStringSync();
      final baselineRaw = jsonDecode(content) as List<dynamic>;
      
      final baselineSet = <String>{};
      for (final item in baselineRaw) {
        if (item is Map<String, dynamic>) {
          final code = item['code']?.toString() ?? '';
          final filePath = item['filePath']?.toString() ?? '';
          baselineSet.add('$code|$filePath');
        }
      }

      return findings.where((f) {
        final key = '${f.code}|${f.filePath ?? ''}';
        return !baselineSet.contains(key);
      }).toList();
    } catch (_) {
      return findings;
    }
  }

  List<Finding> _applySuppressions(ProjectContext context, List<Finding> findings) {
    final Map<String, List<String>> fileLinesCache = {};

    return findings.where((finding) {
      if (finding.filePath == null || finding.line == null) return true;

      final lines = fileLinesCache.putIfAbsent(finding.filePath!, () {
        for (final file in context.files) {
          if (file.relativePath == finding.filePath) {
            return file.lines;
          }
        }
        return [];
      });

      if (lines.isEmpty) return true;

      final lineIdx = finding.line! - 1;
      if (lineIdx < 0 || lineIdx >= lines.length) return true;

      final currentLine = lines[lineIdx];
      final prevLine = lineIdx > 0 ? lines[lineIdx - 1] : '';

      final ignoreAllPattern = RegExp(r'//\s*sast-ignore-next-line');
      final ignoreSpecificPattern = RegExp(r'//\s*sast-ignore\s+([a-zA-Z0-9-]+)');

      // Check previous line
      if (ignoreAllPattern.hasMatch(prevLine)) return false;
      final prevMatch = ignoreSpecificPattern.firstMatch(prevLine);
      if (prevMatch != null && prevMatch.group(1) == finding.code) return false;

      // Check current line (trailing comment)
      final currMatch = ignoreSpecificPattern.firstMatch(currentLine);
      if (currMatch != null && currMatch.group(1) == finding.code) return false;

      return true;
    }).toList();
  }

  /// Applies per-rule exclude globs and severity overrides from [config].
  /// Runs after rule evaluation so rule bodies stay agnostic of config.
  List<Finding> _applyConfig(List<Finding> findings) {
    if (config.severityOverrides.isEmpty &&
        config.ruleExcludePatterns.isEmpty) {
      return findings;
    }
    final result = <Finding>[];
    for (final finding in findings) {
      final path = finding.filePath;
      if (path != null && config.isRulePathExcluded(finding.code, path)) {
        continue;
      }
      final override = config.severityFor(finding.code);
      if (override != null && finding.severity != null) {
        result.add(
          Finding(
            category: finding.category,
            code: finding.code,
            message: finding.message,
            fix: finding.fix,
            risk: finding.risk,
            severity: override,
            confidence: finding.confidence,
            filePath: finding.filePath,
            line: finding.line,
          ),
        );
        continue;
      }
      result.add(finding);
    }
    return result;
  }

  static Finding _internalRuleFailureFinding(Rule rule, Object error) {
    return Finding(
      severity: FindingSeverity.low,
      confidence: FindingConfidence.low,
      category: FindingCategory.suggestion,
      code: 'scanner-internal-error',
      message: 'Rule `${rule.code}` crashed and was skipped',
      fix:
          'Re-run the scanner with verbose output or file an issue including the '
          'error text. Other rules still produced findings below.',
      risk:
          'A skipped rule means its class of vulnerability was NOT checked on '
          'this run. Do not rely on a clean report until the rule is fixed.',
    );
  }

  static int _compareFindings(Finding left, Finding right) {
    if (left.isSuggestion != right.isSuggestion) {
      return left.isSuggestion ? 1 : -1;
    }

    final severityCompare = (left.severity?.sortOrder ?? 3).compareTo(
      right.severity?.sortOrder ?? 3,
    );
    if (severityCompare != 0) {
      return severityCompare;
    }

    final fileCompare = (left.filePath ?? '').compareTo(right.filePath ?? '');
    if (fileCompare != 0) {
      return fileCompare;
    }

    final lineCompare = (left.line ?? 0).compareTo(right.line ?? 0);
    if (lineCompare != 0) {
      return lineCompare;
    }

    return left.message.compareTo(right.message);
  }

  static List<Finding> _dedupe(List<Finding> findings) {
    final seen = <String>{};
    final deduped = <Finding>[];

    for (final finding in findings) {
      // NUL is not legal in file paths or Dart string literals, so it cannot
      // appear in any component of the key. A `|` delimiter was previously
      // used and could collide when a finding message contained `|`.
      final key = [
        finding.code,
        finding.filePath ?? '',
        finding.line?.toString() ?? '',
        finding.message,
      ].join('\x00');
      if (seen.add(key)) {
        deduped.add(finding);
      }
    }

    return deduped;
  }
}
