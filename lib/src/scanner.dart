import 'dart:io';

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
  const ProjectScanner({this.includeSuggestions = true});

  final bool includeSuggestions;

  ProjectScanReport scan(String rootPath) {
    final context = ProjectContext.load(rootPath);
    final findings = <Finding>[];

    for (final rule in buildDefaultRules(
      includeSuggestions: includeSuggestions,
    )) {
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

    final dedupedFindings = _dedupe(findings);
    dedupedFindings.sort(_compareFindings);

    return ProjectScanReport(context: context, findings: dedupedFindings);
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
