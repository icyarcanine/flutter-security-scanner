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
      final findings = report.findings.where((f) => f.code == 'injection-flaw' && f.message.contains('SQL injection')).toList();
      expect(findings.length, greaterThanOrEqualTo(5)); // Caught all direct and alias scenarios
      
      // Ensure parameterized queries are NOT flagged (FP fix)
      final fp = findings.where((f) => f.line == 11 && f.filePath!.contains('sql_injection_test.dart')).toList();
      expect(fp, isEmpty, reason: 'Parameterized SQL array should not be flagged');
    });

    test('Identifies Command Injection with True Data Flow', () {
      final findings = report.findings.where((f) => f.code == 'injection-flaw' && f.message.contains('command injection')).toList();
      expect(findings.length, 3); // run, start, and the alias cmd
      
      // Ensure fixed strings are NOT flagged (FP fix)
      final fp = findings.where((f) => f.line == 12 && f.filePath!.contains('command_injection_test.dart')).toList();
      expect(fp, isEmpty, reason: 'Fixed argument with \$ should not be flagged');
    });

    test('Identifies XSS and Html widget instantiation', () {
      final findings = report.findings.where((f) => f.code == 'xss-flaw').toList();
      expect(findings.length, 3); // innerHTML, outerHTML, Html
      
      // Ensure textContent is NOT flagged (FP fix)
      final fp = findings.where((f) => f.line == 14 && f.filePath!.contains('xss_test.dart')).toList();
      expect(fp, isEmpty, reason: 'textContent is safe');

      // Ensure sanitized HTML is NOT flagged
      final fpSanitized = findings.where((f) => f.line == 21 && f.filePath!.contains('xss_test.dart')).toList();
      expect(fpSanitized, isEmpty, reason: 'sanitized string assignment should be ignored');
    });

    test('Identifies Hardcoded AWS and Firebase Keys', () {
      final findings = report.findings.where((f) => f.code == 'hardcoded-secrets' || f.code == 'generic-secret').toList();
      
      final awsKey = findings.where((f) => f.message.contains('AWS Access Key')).toList();
      expect(awsKey.length, 1);
      
      final firebaseKey = findings.where((f) => f.message.contains('Firebase API key')).toList();
      expect(firebaseKey.length, 1);
    });

    test('Bypasses odd formatting and comment blindspots', () {
      final edgeCaseFile = report.findings.where((f) => f.filePath!.contains('edge_cases_test.dart')).toList();
      
      // Comments should be ignored
      final comment = edgeCaseFile.where((f) => f.line == 5).toList();
      expect(comment, isEmpty);
    });
  });
}
