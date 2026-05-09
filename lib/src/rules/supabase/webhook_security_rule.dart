import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure Supabase webhook configurations.
///
/// Checks for:
/// 1. Webhook handlers without signature verification (HMAC)
/// 2. Missing webhook secret/token validation
/// 3. Webhook endpoints without authentication
/// 4. Webhook payload used without validation
/// 5. Missing replay protection (timestamp/nonce validation)
///
/// This is a Supabase backend security rule.
class SupabaseWebhookSecurityRule extends Rule {
  const SupabaseWebhookSecurityRule();

  @override
  String get code => 'supabase.webhook-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Scan backend webhook/edge-function files (TS/JS/Dart).
    // Flutter client .dart files that import supabase_flutter are NOT
    // webhook handlers and should never be flagged by this rule.
    for (final file in context.files.where((f) {
      final path = f.relativePath.toLowerCase();
      final name = f.name.toLowerCase();
      final isBackendFile = f.name.endsWith('.ts') ||
          f.name.endsWith('.js') ||
          f.name.endsWith('.dart');
      final isEdgeFunction = path.contains('supabase/functions/') ||
          path.contains('edge-functions/') ||
          path.contains('edge_functions/');
      final isWebhookFile = name.contains('webhook') || name.contains('hook');
      final isBackendDir = path.contains('backend/') ||
          path.contains('server/') ||
          path.contains('api/') ||
          path.contains('webhooks/');
      // For Dart files, require stronger backend signals to avoid
      // flagging Flutter client code.
      if (f.name.endsWith('.dart')) {
        final hasServerFramework = RegExp(
          r'package:shelf|package:dart_frog|package:alfred|package:vania|'
          r'import\s+["\x27]dart:io["\x27]|'
          r'HttpServer|Router|Request\s+\w+|Response\.ok|Response\.json',
          caseSensitive: false,
        ).hasMatch(f.content);
        final hasWebhookContext = isWebhookFile || isEdgeFunction || isBackendDir;
        return hasServerFramework && hasWebhookContext;
      }
      return isBackendFile && (isEdgeFunction || isWebhookFile);
    })) {
      findings.addAll(_findMissingWebhookSignature(file));
      findings.addAll(_findMissingWebhookAuth(file));
      findings.addAll(_findUnvalidatedWebhookPayload(file));
      findings.addAll(_findMissingReplayProtection(file));
    }

    return findings;
  }

  /// Detects webhook handlers without HMAC signature verification.
  List<Finding> _findMissingWebhookSignature(ScannedFile file) {
    final findings = <Finding>[];

    // Look for webhook-related endpoints.
    // Do NOT match bare 'supabase' — that fires on every client file.
    final webhookPattern = RegExp(
      r'(?:webhook|hook|stripe|auth\.hook|db\.hook|storage\.hook)',
      caseSensitive: false,
    );

    if (!webhookPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for HMAC verification — ignore matches inside comments,
    // which often contain explanatory text like "No signature verification".
    final hmacPattern = RegExp(
      r'(?:hmac|signature|verify|crypto\.createHmac|timingSafeEqual)',
      caseSensitive: false,
    );

    var hasHmac = false;
    for (final line in file.lines) {
      if (isCommentLine(line)) continue;
      if (hmacPattern.hasMatch(line)) {
        hasHmac = true;
        break;
      }
    }

    if (!hasHmac) {
      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Webhook endpoint missing signature verification',
        fix:
            'Implement HMAC signature verification for all webhook endpoints. '
            'Use a shared secret to sign payloads and verify signatures using '
            'crypto.timingSafeEqual to prevent timing attacks:\n\n'
            'const signature = req.headers["x-webhook-signature"];\n'
            'const expected = crypto.createHmac("sha256", WEBHOOK_SECRET).update(body).digest("hex");\n'
            'if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {\n'
            '  throw new Error("Invalid signature");\n'
            '}',
        risk:
            'Without signature verification, anyone can send fake webhook '
            'events to your endpoint, triggering actions, modifying data, '
            'or causing denial of service.',
        filePath: file.relativePath,
        line: 1,
      ));
    }

    return findings;
  }

  /// Detects webhook endpoints without authentication.
  List<Finding> _findMissingWebhookAuth(ScannedFile file) {
    final findings = <Finding>[];

    // Look for webhook endpoints that don't check auth
    final endpointPattern = RegExp(
      r'(?:app\.(?:post|put|patch)|Deno\.serve|serve\(|handler\()',
      caseSensitive: false,
    );

    for (final match in endpointPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if the endpoint body has auth checks
      final endLine = (line + 30).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (surroundingContent.contains('webhook') &&
          !surroundingContent.contains('authorization') &&
          !surroundingContent.contains('api-key') &&
          !surroundingContent.contains('token')) {
        findings.add(Finding(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Webhook endpoint may lack authentication',
          fix:
              'Require authentication for webhook endpoints. Use API keys, '
              'bearer tokens, or IP allowlists. Combine with signature '
              'verification for defense in depth.',
          risk:
              'Unauthenticated webhook endpoints can be invoked by anyone, '
              'allowing attackers to trigger business logic, modify data, '
              'or probe your API.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects webhook payloads used without validation.
  List<Finding> _findUnvalidatedWebhookPayload(ScannedFile file) {
    final findings = <Finding>[];

    // Look for payload access from request body
    final payloadPattern = RegExp(
      r'req\.(?:json|body|text)\(\)|request\.json\(\)|await req\.json',
      caseSensitive: false,
    );

    for (final match in payloadPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if there's payload validation nearby
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('validate') &&
          !surroundingContent.contains('schema') &&
          !surroundingContent.contains('zod') &&
          !surroundingContent.contains('check')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Webhook payload may lack validation',
          fix:
              'Always validate webhook payloads against an expected schema. '
              'Check required fields, data types, and value ranges. Reject '
              'unexpected or malformed payloads.',
          risk:
              'Unvalidated webhook payloads can contain malicious data, '
              'leading to injection attacks, data corruption, or unexpected '
              'behavior in your webhook handler.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects missing replay protection in webhooks.
  List<Finding> _findMissingReplayProtection(ScannedFile file) {
    final findings = <Finding>[];

    // Check for webhook handling without timestamp or nonce
    final webhookHandlerPattern = RegExp(
      r'(?:webhook|hook|stripe)',
      caseSensitive: false,
    );

    if (!webhookHandlerPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for replay protection mechanisms
    final replayPattern = RegExp(
      r'(?:timestamp|nonce|iat|exp|Date\.now|replay|cache|dedup)',
      caseSensitive: false,
    );

    if (!replayPattern.hasMatch(file.content)) {
      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.low,
        category: FindingCategory.security,
        code: code,
        message: 'Webhook handler may lack replay protection',
        fix:
            'Implement replay protection for webhooks:\n'
            '1. Check timestamp is within a reasonable window (e.g., 5 minutes)\n'
            '2. Use a nonce cache to reject duplicate event IDs\n'
            '3. Store processed webhook IDs in a short-lived cache\n'
            '4. Reject events with timestamps in the future or distant past',
        risk:
            'Without replay protection, attackers can resend legitimate '
            'webhook events multiple times, causing duplicate actions, '
            'double charges, or data inconsistency.',
        filePath: file.relativePath,
        line: 1,
      ));
    }

    return findings;
  }
}
