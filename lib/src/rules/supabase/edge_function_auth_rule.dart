import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure Supabase Edge Function configurations.
///
/// Checks for:
/// 1. Edge functions with verify_jwt = false
/// 2. Edge functions without CORS origin restriction
/// 3. Edge functions logging sensitive data
/// 4. Edge functions using service_role key without authentication
/// 5. Edge functions without input validation
///
/// This is a Supabase backend security rule.
class SupabaseEdgeFunctionAuthRule extends Rule {
  const SupabaseEdgeFunctionAuthRule();

  @override
  String get code => 'supabase.edge-function-auth';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files.where((f) => f.name.endsWith('.ts') || f.name.endsWith('.js'))) {
      findings.addAll(_findUnauthenticatedEdgeFunctions(file));
      findings.addAll(_findCorsMisconfiguration(file));
      findings.addAll(_findSensitiveLogging(file));
      findings.addAll(_findMissingInputValidation(file));
    }

    for (final file in context.files.where((f) => f.name.endsWith('.toml'))) {
      findings.addAll(_findJwtVerificationDisabled(file));
    }

    return findings;
  }

  /// Detects edge functions that don't verify JWT tokens.
  List<Finding> _findJwtVerificationDisabled(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'verify_jwt\s*=\s*false',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Edge function has JWT verification disabled',
        fix:
            'Set verify_jwt = true in supabase/config.toml for all edge '
            'functions that handle sensitive data. If you need unauthenticated '
            'access, implement alternative authentication (API keys, webhook '
            'signatures) and document the security implications.',
        risk:
            'With verify_jwt = false, any request to the edge function is '
            'treated as authenticated. Attackers can invoke the function '
            'without any credentials, potentially accessing or modifying '
            'sensitive data.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects edge functions with permissive CORS settings.
  List<Finding> _findCorsMisconfiguration(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'Access-Control-Allow-Origin\s*:\s*\*',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Edge function allows CORS from any origin',
        fix:
            'Restrict Access-Control-Allow-Origin to your specific domains. '
            'Use a whitelist approach and validate the Origin header against '
            'known good domains. Never use "*" for functions handling '
            'sensitive data or authentication.',
        risk:
            'Permissive CORS allows any website to make requests to your '
            'edge function. If the function uses cookies or bearer tokens '
            'for auth, attackers can make cross-origin authenticated requests.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects sensitive data logging in edge functions.
  List<Finding> _findSensitiveLogging(ScannedFile file) {
    final findings = <Finding>[];

    final pattern = RegExp(
      r'console\.(?:log|warn|error)\s*\([^)]*(?:password|token|secret|key|auth|session)',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Edge function logs potentially sensitive data',
        fix:
            'Remove or redact sensitive fields (passwords, tokens, API keys) '
            'before logging. Use structured logging with allowlists of safe '
            'fields, or hash sensitive identifiers.',
        risk:
            'Log data is often stored in plaintext and accessible to platform '
            'operators, monitoring tools, or attackers who gain access to log '
            'infrastructure.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects edge functions without input validation.
  List<Finding> _findMissingInputValidation(ScannedFile file) {
    final findings = <Finding>[];

    // Look for request body access without validation
    final bodyPattern = RegExp(
      r'req\.json\(\)|req\.text\(\)|req\.formData\(\)',
      caseSensitive: false,
    );

    for (final match in bodyPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check next 30 lines for validation
      final endLine = (line + 30).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('validate') &&
          !surroundingContent.contains('zod') &&
          !surroundingContent.contains('schema') &&
          !surroundingContent.contains('sanitize') &&
          !surroundingContent.contains('check') &&
          !surroundingContent.contains('required')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Edge function may lack input validation',
          fix:
              'Always validate and sanitize incoming request data. Use a '
              'schema validator like Zod, Joi, or Yup. Check required fields, '
              'data types, and value ranges. Reject malformed requests early.',
          risk:
              'Unvalidated input can lead to injection attacks, data '
              'corruption, or unexpected behavior in edge functions.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects edge functions that bypass authentication.
  List<Finding> _findUnauthenticatedEdgeFunctions(ScannedFile file) {
    final findings = <Finding>[];

    // Check if the function uses supabase service role key but no auth check
    final serviceRolePattern = RegExp(
      r'service_role|SUPABASE_SERVICE_ROLE_KEY',
      caseSensitive: false,
    );

    if (!serviceRolePattern.hasMatch(file.content)) {
      return findings;
    }

    // Check if there's any auth validation
    final hasAuthCheck = RegExp(
      r'authorization|Authorization|auth|jwt|token',
      caseSensitive: false,
    ).hasMatch(file.content);

    if (!hasAuthCheck) {
      final match = serviceRolePattern.firstMatch(file.content);
      if (match != null) {
        final line = file.lineForOffset(match.start);

        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Edge function uses service_role key without authentication',
          fix:
              'Add authentication checks before using the service_role key. '
              'Use verify_jwt = true and check the user context. For '
              'webhook-style functions, validate webhook signatures instead '
              'of relying on service_role alone.',
          risk:
              'The service_role key bypasses all RLS policies. If an attacker '
              'accesses a function using this key without authentication, they '
              'can read, write, or delete any data in your database.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
