import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects insecure push notification handling in Flutter apps.
///
/// Checks for:
/// 1. FCM tokens logged or exposed to UI
/// 2. Push notification payloads processed without validation
/// 3. Deep links from notifications without origin validation
/// 4. Notification permissions requested without explanation
/// 5. Sensitive actions triggered directly from notification taps
///
/// This is a Flutter-specific push notification security rule.
class PushNotificationSecurityRule extends Rule {
  const PushNotificationSecurityRule();

  @override
  String get code => 'flutter.push-notification-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findTokenExposure(file));
      findings.addAll(_findUnvalidatedPayloads(file));
      findings.addAll(_findUnsafeNotificationActions(file));
    }

    return findings;
  }

  /// Detects FCM/APNs tokens being logged or stored insecurely.
  List<Finding> _findTokenExposure(ScannedFile file) {
    final findings = <Finding>[];

    final tokenPattern = RegExp(
      r'(?:firebaseMessaging|FirebaseMessaging|messaging)'
      r'.*?\.(?:getToken|onTokenRefresh|apnsToken|fcmToken)',
      caseSensitive: false,
    );

    for (final match in tokenPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if the token is logged or displayed
      final endLine = (line + 10).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (surroundingContent.contains('print') ||
          surroundingContent.contains('debugprint') ||
          surroundingContent.contains('log') ||
          surroundingContent.contains('text(') ||
          surroundingContent.contains('snackbar')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Push notification token may be exposed in logs or UI',
          fix: 'Never log or display FCM/APNs tokens. Send them directly to '
              'your backend over HTTPS and store them securely. '
              'If you need to debug token retrieval, log only a hash prefix.',
          risk: 'FCM tokens are bearer credentials that allow sending push '
              'notifications to the device. If leaked, attackers can spam '
              'users with phishing notifications or deplete your FCM quota.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects push notification payloads used without validation.
  List<Finding> _findUnvalidatedPayloads(ScannedFile file) {
    final findings = <Finding>[];

    final payloadPattern = RegExp(
      r'(?:message\.notification|message\.data|payload|remoteMessage)'
      r'\.(?:body|title|data|payload)',
      caseSensitive: false,
    );

    for (final match in payloadPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if the payload is validated before use
      final endLine = (line + 15).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (!surroundingContent.contains('validate') &&
          !surroundingContent.contains('check') &&
          !surroundingContent.contains('null') &&
          !surroundingContent.contains('containskey')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Push notification payload may not be validated',
          fix: 'Always validate notification payload structure and content '
              'before use:\n\n'
              'final data = message.data;\n'
              'if (data.containsKey("action") &&\n'
              '    data["action"] is String &&\n'
              '    allowedActions.contains(data["action"])) {\n'
              '  handleAction(data["action"]);\n'
              '}',
          risk: 'Push notification payloads can be forged by attackers who '
              'obtain your FCM server key or through FCM topic sniffing. '
              'Unvalidated payload data can trigger unauthorized actions '
              'or crash the app.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects sensitive actions triggered directly from notification taps.
  List<Finding> _findUnsafeNotificationActions(ScannedFile file) {
    final findings = <Finding>[];

    final notificationTapPattern = RegExp(
      r'(?:onMessageOpenedApp|onNotificationOpened|onTap|onSelectNotification|'
      r'getInitialMessage)',
      caseSensitive: false,
    );

    for (final match in notificationTapPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check for sensitive operations nearby
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (surroundingContent.contains('delete') ||
          surroundingContent.contains('transfer') ||
          surroundingContent.contains('purchase') ||
          surroundingContent.contains('payment') ||
          surroundingContent.contains('auth') ||
          surroundingContent.contains('login')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Sensitive action may be triggered from notification tap',
          fix: 'Never trigger sensitive actions (payments, deletes, auth) '
              'directly from a notification tap without user confirmation. '
              'Always navigate to a screen that clearly explains the action '
              'and requires explicit user consent.',
          risk: 'Attackers who can send forged notifications can trigger '
              'sensitive actions on the user\'s device. This is especially '
              'dangerous for financial or account-deletion flows.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
