import 'dart:io';
import 'package:fluttersupabasehelper/fluttersupabasehelper.dart';
import 'package:test/test.dart';

void main() {
  group('Scanner Tests (Enterprise AST & Regex Engine)', () {
    late ProjectScanner scanner;
    late ProjectScanReport report;

    setUpAll(() {
      scanner = ProjectScanner(includeSuggestions: false);
      final fixturesPath = Directory('test/fixtures').absolute.path;
      report = scanner.scan(fixturesPath);
    });

    test('Identifies SQL Injection with True Data Flow', () {
      final findings = report.findings
          .where((f) =>
              f.code == 'injection-flaw' && f.message.contains('SQL injection'))
          .toList();
      expect(findings.length,
          greaterThanOrEqualTo(5)); // Caught all direct and alias scenarios

      // Ensure parameterized queries are NOT flagged (FP fix)
      final fp = findings
          .where((f) =>
              f.line == 11 && f.filePath!.contains('sql_injection_test.dart'))
          .toList();
      expect(fp, isEmpty,
          reason: 'Parameterized SQL array should not be flagged');
    });

    test('Identifies Command Injection with True Data Flow', () {
      final findings = report.findings
          .where((f) =>
              f.code == 'injection-flaw' &&
              f.message.contains('command injection'))
          .toList();
      expect(findings.length, 3); // run, start, and the alias cmd

      // Ensure fixed strings are NOT flagged (FP fix)
      final fp = findings
          .where((f) =>
              f.line == 12 &&
              f.filePath!.contains('command_injection_test.dart'))
          .toList();
      expect(fp, isEmpty,
          reason: 'Fixed argument with \$ should not be flagged');
    });

    test('Identifies XSS and Html widget instantiation', () {
      final findings =
          report.findings.where((f) => f.code == 'xss-flaw').toList();
      expect(findings.length, 3); // innerHTML, outerHTML, Html

      // Ensure textContent is NOT flagged (FP fix)
      final fp = findings
          .where((f) => f.line == 14 && f.filePath!.contains('xss_test.dart'))
          .toList();
      expect(fp, isEmpty, reason: 'textContent is safe');

      // Ensure sanitized HTML is NOT flagged
      final fpSanitized = findings
          .where((f) => f.line == 21 && f.filePath!.contains('xss_test.dart'))
          .toList();
      expect(fpSanitized, isEmpty,
          reason: 'sanitized string assignment should be ignored');
    });

    test('Identifies Hardcoded AWS and Firebase Keys', () {
      final findings = report.findings
          .where((f) =>
              f.code == 'hardcoded-secrets' || f.code == 'generic-secret')
          .toList();

      final awsKey =
          findings.where((f) => f.message.contains('AWS Access Key')).toList();
      expect(awsKey.length, 1);

      final firebaseKey = findings
          .where((f) => f.message.contains('Firebase API key'))
          .toList();
      expect(firebaseKey.length, 1);
    });

    test('Uses DDL owner metadata for schema-only audit_log table', () {
      final findings = report.findings.where((f) {
        return f.code == 'table-ownership-filter' &&
            f.filePath == 'migration_schema_only_app/lib/main.dart' &&
            f.message.contains("'audit_log'");
      }).toList();

      expect(findings.length, 1);
      expect(findings.single.severity, FindingSeverity.high);
      expect(findings.single.fix, contains('auth.uid() = actor_id'));
    });

    test('Requires table-specific RLS instead of trusting global evidence', () {
      final fixtureReport = scanner.scan(
        Directory('test/fixtures/partial_rls_app').absolute.path,
      );

      final findings = fixtureReport.findings.where((f) {
        return f.code == 'missing-rls-awareness' &&
            f.filePath == 'lib/main.dart' &&
            f.message.contains("'audit_log'");
      }).toList();

      expect(findings.length, 1);
      expect(findings.single.severity, FindingSeverity.high);
      expect(findings.single.message, contains('no committed RLS DDL'));
    });

    test('Requires operation-specific RLS policies', () {
      final fixtureReport = scanner.scan(
        Directory('test/fixtures/rls_select_only_update_app').absolute.path,
      );

      final findings = fixtureReport.findings.where((f) {
        return f.code == 'missing-rls-awareness' &&
            f.filePath == 'lib/main.dart' &&
            f.message.contains('update') &&
            f.message.contains("'posts'");
      }).toList();

      expect(findings.length, 1);
      expect(findings.single.severity, FindingSeverity.medium);
      expect(findings.single.fix, contains('update'));
    });

    test('Flags unsafe SECURITY DEFINER RPC calls from client code', () {
      final fixtureReport = scanner.scan(
        Directory('test/fixtures/security_definer_rpc_app').absolute.path,
      );

      final findings = fixtureReport.findings.where((f) {
        return f.code == 'supabase-rpc-injection' &&
            f.filePath == 'lib/main.dart' &&
            f.message.contains('admin_delete_user');
      }).toList();

      expect(findings.length, 1);
      expect(findings.single.severity, FindingSeverity.high);
      expect(findings.single.confidence, FindingConfidence.high);
      expect(
        fixtureReport.findings.where(
          (f) => f.message.contains('safe_user_summary'),
        ),
        isEmpty,
      );
    });

    test('Does not downgrade missing RLS based on README or code comments', () {
      final readmeReport = scanner.scan(
        Directory('test/fixtures/readme_rls_only_app').absolute.path,
      );
      final weakCommentReport = scanner.scan(
        Directory('test/fixtures/weak_rls_app').absolute.path,
      );

      final readmeFinding = readmeReport.findings.singleWhere(
        (f) => f.code == 'missing-rls-awareness',
      );
      final commentFinding = weakCommentReport.findings.singleWhere(
        (f) => f.code == 'missing-rls-awareness',
      );

      expect(readmeFinding.severity, FindingSeverity.high);
      expect(commentFinding.severity, FindingSeverity.high);
      expect(readmeFinding.message, contains('No verifiable table-level RLS'));
      expect(commentFinding.message, contains('No verifiable table-level RLS'));
    });

    test('Bypasses odd formatting and comment blindspots', () {
      final edgeCaseFile = report.findings
          .where((f) => f.filePath!.contains('edge_cases_test.dart'))
          .toList();

      // Comments should be ignored
      final comment = edgeCaseFile.where((f) => f.line == 5).toList();
      expect(comment, isEmpty);
    });
  });
}
