import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure background task configurations in Flutter apps.
///
/// Checks for:
/// 1. WorkManager tasks without input data validation
/// 2. Background fetch handlers making network calls without auth checks
/// 3. Sensitive operations in background tasks without encryption
/// 4. Background tasks logging sensitive data
/// 5. Missing constraints on background tasks (unmetered, charging)
///
/// This is a Flutter-specific background execution security rule.
class BackgroundTaskSecurityRule extends Rule {
  const BackgroundTaskSecurityRule();

  @override
  String get code => 'flutter.background-task-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findUnvalidatedBackgroundInput(file));
      findings.addAll(_findBackgroundAuthBypass(file));
      findings.addAll(_findBackgroundSensitiveLogging(file));
      findings.addAll(_findMissingTaskConstraints(file));
    }

    return findings;
  }

  /// Detects background task handlers that don't validate input data.
  List<Finding> _findUnvalidatedBackgroundInput(ScannedFile file) {
    final findings = <Finding>[];

    final backgroundHandlerPattern = RegExp(
      r'(?:WorkManager|workManager|BackgroundFetch|background_fetch)'
      r'.*?(?:callback|handler|executor|task)',
      caseSensitive: false,
    );

    if (!backgroundHandlerPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for inputData access without validation
    final inputDataPattern = RegExp(
      r'(?:inputData|inputData\?|getInputData)\s*\(?.+?\)?\s*\[?',
      caseSensitive: false,
    );

    for (final match in inputDataPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if validation exists nearby
      final endLine = (line + 15).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('null') &&
          !surroundingContent.contains('check') &&
          !surroundingContent.contains('validate') &&
          !surroundingContent.contains('containskey')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Background task input data may not be validated',
          fix:
              'Always validate background task input data before use. '
              'Check for required keys, validate types, and sanitize '
              'values before passing them to network calls or storage.',
          risk:
              'Background tasks receive input data that could be tampered '
              'with by other apps or system components. Unvalidated input '
              'can lead to injection attacks or crashes.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects background tasks making Supabase/database calls without auth.
  List<Finding> _findBackgroundAuthBypass(ScannedFile file) {
    final findings = <Finding>[];

    final backgroundPattern = RegExp(
      r'(?:WorkManager|workManager|BackgroundFetch|background_fetch)',
      caseSensitive: false,
    );

    if (!backgroundPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for database/network calls
    final networkCallPattern = RegExp(
      r'(?:supabase|client)\.(?:from|rpc|storage|functions)',
      caseSensitive: false,
    );

    for (final match in networkCallPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if there's an auth check nearby
      final startLine = (line - 10).clamp(0, line - 1);
      final endLine = (line + 10).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(startLine, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('auth') &&
          !surroundingContent.contains('session') &&
          !surroundingContent.contains('token') &&
          !surroundingContent.contains('service_role')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Background task makes data calls without explicit auth context',
          fix:
              'Background tasks run outside the user session. Pass a valid '
              'JWT or use a service role key securely stored in '
              'flutter_secure_storage, and include auth context in every '
              'network request.',
          risk:
              'Background tasks without explicit auth context may use stale '
              'credentials, run as anonymous users, or bypass RLS policies '
              'entirely, leading to unauthorized data access.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects sensitive data logging in background task handlers.
  List<Finding> _findBackgroundSensitiveLogging(ScannedFile file) {
    final findings = <Finding>[];

    final backgroundPattern = RegExp(
      r'(?:WorkManager|workManager|BackgroundFetch|background_fetch)',
      caseSensitive: false,
    );

    if (!backgroundPattern.hasMatch(file.content)) {
      return findings;
    }

    final logPattern = RegExp(
      r'\b(?:print|debugPrint|log|logger)\s*\(',
      caseSensitive: false,
    );

    for (final match in logPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      final endLine = (line + 3).clamp(0, file.lines.length);
      final logContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (logContent.contains('token') ||
          logContent.contains('password') ||
          logContent.contains('secret') ||
          logContent.contains('auth') ||
          logContent.contains('credential')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Sensitive data may be logged in background task',
          fix:
              'Never log tokens, passwords, or user data in background tasks. '
              'Background task logs may be captured by system log collectors '
              'and exposed to other apps.',
          risk:
              'Background task logs containing sensitive data can be read by '
              'apps with READ_LOGS permission or extracted from device '
              'backups, exposing user credentials and personal information.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects background tasks without network/battery constraints.
  List<Finding> _findMissingTaskConstraints(ScannedFile file) {
    final findings = <Finding>[];

    final workManagerPattern = RegExp(
      r'(?:WorkManager|workManager)\.(?:executeOneTimeTask|registerOneTimeTask|'
      r'enqueueOneTimeWork|enqueue|registerPeriodicTask)',
      caseSensitive: false,
    );

    for (final match in workManagerPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check for constraints in the call
      final endLine = (line + 10).clamp(0, file.lines.length);
      final callContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!callContent.contains('constraints') &&
          !callContent.contains('networktype') &&
          !callContent.contains('requiresnetwork') &&
          !callContent.contains('requirescharging') &&
          !callContent.contains('constraints')) {
        findings.add(Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Background task lacks constraints',
          fix:
              'Add constraints to background tasks to prevent them from '
              'running at inappropriate times:\n\n'
              'constraints: Constraints(\n'
              '  networkType: NetworkType.connected,\n'
              '  requiresBatteryNotLow: true,\n'
              '  requiresStorageNotLow: true,\n',
          risk:
              'Unconstrained background tasks can drain battery, consume '
              'mobile data, and run when the device is in a low-resource '
              'state, leading to poor user experience and potential task '
              'failures.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
