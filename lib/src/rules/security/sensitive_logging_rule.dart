import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class SensitiveLoggingRule extends Rule {
  const SensitiveLoggingRule();

  @override
  String get code => 'sensitive-logging';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Use appDartFiles: already excludes test/, integration_test/, example/.
    for (final file in context.appDartFiles) {
      // collectLogStatements handles both single-line and multi-line calls.
      for (final stmt in collectLogStatements(file)) {
        if (!_looksSensitive(stmt.argument)) {
          continue;
        }

        findings.add(
          Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Sensitive auth or user data is being logged',
            fix:
                'Remove the log statement or redact auth/session fields before writing anything to logs.',
            risk:
                'Auth tokens and session objects in logs can be harvested from log files, crash reporters, or device storage.',
            filePath: file.relativePath,
            line: stmt.startLine,
          ),
        );
      }
    }

    return findings;
  }

  bool _looksSensitive(String argument) {
    // Exact single-identifier matches (compact form strips spaces).
    final compact = argument.replaceAll(' ', '');
    if (compact == 'session' ||
        compact == 'token' ||
        compact == 'currentUser' ||
        compact == 'currentSession') {
      return true;
    }

    // Interpolated sensitive variables: $session, ${accessToken}, etc.
    // The word-boundary prevents matching $username, $userCount, $sessionIndex.
    if (RegExp(
      r'''\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken)\b''',
      caseSensitive: false,
    ).hasMatch(argument)) {
      return true;
    }

    // Interpolated PII variables: $email, ${phoneNumber}, $password, etc.
    if (RegExp(
      r'''\$\{?\s*(email|password|passwd|phoneNumber|phone|ssn|socialSecurity|creditCard|cardNumber|cvv|dateOfBirth|dob)\b''',
      caseSensitive: false,
    ).hasMatch(argument)) {
      return true;
    }

    // Strip string literals so text inside quoted strings doesn't create
    // false positives.  Non-greedy to handle: 'label: ' + accessToken
    final strippedArgument = argument
        .replaceAll(RegExp(r'"(?:[^"\\]|\\.)*"'), '')
        .replaceAll(RegExp(r"""'(?:[^'\\]|\\.)*'"""), '');

    // After stripping, look for identifiers that are exclusively auth-related.
    // Deliberately excludes bare `user` (too broad — matches userCount, etc.)
    if (RegExp(
      r'''(?<!\w)(session|accessToken|refreshToken|jwt|idToken|currentUser|currentSession|authState|authorization)(?!\w)'''
      r'''|\.(?:currentUser|currentSession|accessToken|refreshToken|idToken)\b''',
      caseSensitive: false,
    ).hasMatch(strippedArgument)) {
      return true;
    }

    // PII identifiers: email, password, phone, SSN, credit card, etc.
    if (RegExp(
      r'''(?<!\w)(password|passwd|creditCard|cardNumber|cvv|ssn|socialSecurity|dateOfBirth)(?!\w)'''
      r'''|\.(?:password|creditCard|cardNumber|ssn|socialSecurity)\b''',
      caseSensitive: false,
    ).hasMatch(strippedArgument)) {
      return true;
    }

    return false;
  }
}
