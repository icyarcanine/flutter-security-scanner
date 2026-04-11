import 'dart:io';

import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class InvalidSupabaseUrlRule extends Rule {
  const InvalidSupabaseUrlRule();

  @override
  String get code => 'invalid-supabase-url';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final entry in context.envEntries.where(
      (entry) => entry.key == 'SUPABASE_URL',
    )) {
      if (entry.file.isEnvTemplateFile) {
        continue;
      }
      if (_looksValid(entry.value)) {
        continue;
      }

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.config,
          code: code,
          message: 'SUPABASE_URL does not look like a valid Supabase HTTPS URL',
          fix:
              'Use the full project URL from Supabase, for example `https://your-project.supabase.co`.',
          risk:
              'Malformed URLs will cause network requests to fail entirely, breaking app connectivity.',
          filePath: entry.file.relativePath,
          line: entry.line,
        ),
      );
    }

    final initializePattern = RegExp(
      r'''Supabase\.initialize\([^;]*?\burl\s*:\s*['"]([^'"]+)['"]''',
      dotAll: true,
    );
    final clientPattern = RegExp(
      r'''\bSupabaseClient\s*\(\s*['"]([^'"]+)['"]''',
      dotAll: true,
    );
    for (final file in context.appDartFiles) {
      for (final pattern in [initializePattern, clientPattern]) {
        for (final match in pattern.allMatches(file.content)) {
          final value = match.group(1)!;
          if (_looksValid(value)) {
            continue;
          }

          final line = file.lineForOffset(match.start);
          if (isCommentLine(file.lines[line - 1])) {
            continue;
          }

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.high,
              category: FindingCategory.config,
              code: code,
              message: 'Hardcoded Supabase URL is malformed',
              fix:
                  'Replace the URL with a valid Supabase project URL or load it from environment config.',
              risk:
                  'Malformed URLs will cause network requests to fail entirely, breaking app connectivity.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }
    }

    return findings;
  }

  bool _looksValid(String value) {
    final uri = Uri.tryParse(value);
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
      return _looksLikeLocalDevelopmentUrl(uri);
    }

    return uri.host.endsWith('.supabase.co') ||
        _looksLikeLocalDevelopmentUrl(uri);
  }

  bool _looksLikeLocalDevelopmentUrl(Uri? uri) {
    if (uri == null || uri.host.isEmpty) {
      return false;
    }

    const localHosts = {
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '10.0.2.2',
      'host.docker.internal',
      '::1',
    };
    if (localHosts.contains(uri.host)) {
      return true;
    }

    final address = InternetAddress.tryParse(uri.host);
    if (address == null || address.type != InternetAddressType.IPv4) {
      return false;
    }

    final octets = uri.host.split('.').map(int.tryParse).toList();
    if (octets.length != 4 || octets.any((value) => value == null)) {
      return false;
    }

    final first = octets[0]!;
    final second = octets[1]!;
    return first == 10 ||
        (first == 172 && second >= 16 && second <= 31) ||
        (first == 192 && second == 168);
  }
}
