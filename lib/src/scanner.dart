import 'dart:convert';
import 'dart:io';

import 'models/finding.dart';
import 'models/project_context.dart';
import 'rules.dart';

class ProjectScanReport {
  const ProjectScanReport({required this.context, required this.findings});

  final ProjectContext context;
  final List<Finding> findings;
}

class ProjectScanner {
  const ProjectScanner({this.includeSuggestions = true, this.baselinePath});

  final bool includeSuggestions;
  final String? baselinePath;

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
