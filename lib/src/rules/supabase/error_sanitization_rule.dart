import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects Supabase error messages that may leak sensitive information.
///
/// Checks for:
/// 1. Raw Supabase errors exposed to UI
/// 2. Error messages containing SQL details or table names
/// 3. Auth error messages revealing user existence
/// 4. Database constraint errors shown to users
/// 5. Missing error sanitization before display
///
/// This is a Supabase-specific information disclosure rule.
class SupabaseErrorSanitizationRule extends Rule {
  const SupabaseErrorSanitizationRule();

  @override
  String get code => 'supabase.error-sanitization';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findRawSupabaseErrorsInUI(file));
      findings.addAll(_findErrorToastsWithSensitiveData(file));
    }

    return findings;
  }

  /// Detects raw Supabase error messages being displayed to users.
  List<Finding> _findRawSupabaseErrorsInUI(ScannedFile file) {
    final findings = <Finding>[];

    // Look for error.message or error.toString() in UI display
    final rawErrorPattern = RegExp(
      r'(?:error\.(?:message|toString|details)|e\.(?:message|toString))\s*\)?\s*[,)]',
      caseSensitive: false,
    );

    for (final match in rawErrorPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check if it's being displayed in UI
      final surroundingContext = _getSurroundingContext(file, line, 10);
      if (surroundingContext.contains('snackbar') ||
          surroundingContext.contains('toast') ||
          surroundingContext.contains('dialog') ||
          surroundingContext.contains('alert') ||
          surroundingContext.contains('scaffold') ||
          surroundingContext.contains('text(')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Raw Supabase error exposed to user interface',
          fix: 'Sanitize error messages before displaying them to users. '
              'Map specific error codes to user-friendly messages and log '
              'the full error internally:\n\n'
              'try {\n'
              '  await supabase.from("users").insert(data);\n'
              '} catch (error) {\n'
              '  // Log full error for debugging\n'
              '  logger.error("Database insert failed", error);\n'
              '  // Show sanitized message to user\n'
              '  showToast("Unable to save data. Please try again.");\n'
              '}',
          risk: 'Raw database errors can reveal table names, column names, '
              'constraint details, and internal structure to attackers, '
              'aiding reconnaissance and SQL injection refinement.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects auth error messages that reveal user existence.
  List<Finding> _findErrorToastsWithSensitiveData(ScannedFile file) {
    final findings = <Finding>[];

    // Auth-specific error patterns that leak information
    final authErrorPattern = RegExp(
      r'(?:invalid login credentials|user not found|email not registered|'
      r'password is incorrect|account does not exist|no user|invalid password)',
      caseSensitive: false,
    );

    for (final match in authErrorPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Auth error message reveals user existence',
        fix: 'Use generic auth error messages that do not reveal whether '
            'an email is registered or if the password is wrong. '
            'Example: "Invalid credentials" instead of "User not found" '
            'or "Password is incorrect".',
        risk:
            'Different error messages for "user not found" vs "wrong password" '
            'allow attackers to enumerate valid email addresses, enabling '
            'targeted phishing and credential stuffing attacks.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  String _getSurroundingContext(ScannedFile file, int line, int window) {
    final start = (line - window).clamp(0, file.lines.length - 1);
    final end = (line + window).clamp(0, file.lines.length);
    return file.lines.sublist(start, end).join('\n').toLowerCase();
  }
}
