import 'models/finding.dart';
import 'models/project_context.dart';
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
      findings.addAll(rule.evaluate(context));
    }

    final dedupedFindings = _dedupe(findings);
    dedupedFindings.sort(_compareFindings);

    return ProjectScanReport(context: context, findings: dedupedFindings);
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
      final key = [
        finding.code,
        finding.filePath ?? '',
        finding.line?.toString() ?? '',
        finding.message,
      ].join('|');
      if (seen.add(key)) {
        deduped.add(finding);
      }
    }

    return deduped;
  }
}
