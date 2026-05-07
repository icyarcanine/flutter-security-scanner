import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Flags configuration and code issues specific to Supabase Edge Functions
/// (the Deno runtimes at `supabase/functions/<name>/index.ts`).
///
/// Edge functions live on the server side and legitimately hold
/// service-role credentials, so the client-side leakage rules do not
/// apply here. The risks that DO apply are:
///
/// 1. `verify_jwt = false` declared in `supabase/config.toml`, which
///    turns the function into an unauthenticated endpoint reachable by
///    anyone with the URL.
/// 2. `Access-Control-Allow-Origin: *` inside the function handler,
///    which opens the endpoint to cross-origin browser attacks if the
///    function also accepts credentials.
/// 3. The service-role key being returned in a response body or an
///    `Authorization` header — any `new Response(...)` or
///    `Response.json(...)` whose payload references the service role
///    variable.
/// 4. Unauthenticated handlers that still touch `SUPABASE_SERVICE_ROLE_KEY`.
///    Without a JWT check, the function effectively exposes service-role
///    power to any caller.
class SupabaseEdgeFunctionSecretsRule extends Rule {
  const SupabaseEdgeFunctionSecretsRule();

  @override
  String get code => 'supabase-edge-function-secrets';

  static final _serviceRoleEnvPattern = RegExp(
    r'''\bSUPABASE_SERVICE_ROLE(?:_KEY)?\b''',
  );

  static final _corsWildcardPattern = RegExp(
    r'''['"]Access-Control-Allow-Origin['"]\s*(?::|,)\s*['"]\*['"]''',
    caseSensitive: false,
  );

  /// `verify_jwt = false` declared under any `[functions.*]` section in
  /// `supabase/config.toml`. Captures the function name so the finding
  /// message can name it.
  static final _verifyJwtFalsePattern = RegExp(
    r'\[functions\.([A-Za-z0-9_\-]+)\][^\[]*?verify_jwt\s*=\s*false',
    multiLine: true,
    dotAll: true,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files) {
      final normalized = file.relativePath.replaceAll(r'\\', '/');

      if (normalized == 'supabase/config.toml' ||
          normalized.endsWith('/supabase/config.toml')) {
        findings.addAll(_scanConfigToml(file));
        continue;
      }

      if (!_isEdgeFunctionFile(normalized)) continue;
      findings.addAll(_scanFunctionFile(file));
    }

    return findings;
  }

  Iterable<Finding> _scanConfigToml(ScannedFile file) sync* {
    for (final match in _verifyJwtFalsePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isOffsetCommented(file, match.start) ||
          isCommentLine(file.lines[line - 1])) continue;

      final functionName = match.group(1) ?? '(unknown)';
      yield Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.supabase,
        code: code,
        message:
            'Edge function `$functionName` has `verify_jwt = false` — requests are unauthenticated',
        fix:
            'Remove the `verify_jwt = false` line or wrap the function body in an explicit JWT/anonymous-key check. If you genuinely need a public endpoint, validate the payload, rate-limit it, and NEVER call `Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")` inside it.',
        risk:
            'With JWT verification disabled, any caller can invoke the function. If the function uses the service-role key internally, that caller effectively has unrestricted database access; if it does anything expensive or side-effecting, it becomes a DoS and billing attack surface.',
        filePath: file.relativePath,
        line: line,
      );
    }
  }

  Iterable<Finding> _scanFunctionFile(ScannedFile file) sync* {
    final content = file.content;
    final usesServiceRole = _serviceRoleEnvPattern.hasMatch(content);

    for (final match in _corsWildcardPattern.allMatches(content)) {
      final line = file.lineForOffset(match.start);
      if (isOffsetCommented(file, match.start) ||
          isCommentLine(file.lines[line - 1])) continue;

      yield Finding(
        severity: usesServiceRole
            ? FindingSeverity.high
            : FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.supabase,
        code: code,
        message: usesServiceRole
            ? 'Edge function opens `Access-Control-Allow-Origin: *` while using the service-role key'
            : 'Edge function opens `Access-Control-Allow-Origin: *`',
        fix:
            'Constrain CORS to the specific origins your web frontends ship from. A wildcard is only safe if the endpoint is genuinely anonymous, idempotent, and never touches service-role credentials.',
        risk: usesServiceRole
            ? 'A wildcard CORS policy combined with a service-role-powered handler lets any origin invoke the function from a victim\'s browser and exfiltrate whatever data the service-role can reach.'
            : 'Wildcard CORS allows any website to invoke this endpoint from a browser. If the function ever ships behind credentials or returns sensitive data, the attack surface is the entire web.',
        filePath: file.relativePath,
        line: line,
      );
    }

    // Look for `new Response(...)` / `Response.json(...)` call sites that
    // textually reference the service role variable — a strong signal
    // that the key is being leaked back to the caller.
    final responsePattern = RegExp(
      r'\bnew\s+Response\s*\(|Response\.json\s*\(',
    );
    for (final match in responsePattern.allMatches(content)) {
      final callOpen = content.indexOf('(', match.start);
      if (callOpen == -1) continue;
      final closeIndex = _findParenClose(content, callOpen + 1);
      if (closeIndex == -1) continue;
      final body = content.substring(callOpen + 1, closeIndex);
      // Catch `SUPABASE_SERVICE_ROLE_KEY`, `service_role`, `service-role`, and
      // camelCase variants like `serviceRoleKey`, `serviceRoleJwt`, etc. The
      // right-hand word boundary is intentionally omitted so suffixes such as
      // `Key` / `Jwt` / `Token` don't mask the match.
      if (!_serviceRoleEnvPattern.hasMatch(body) &&
          !RegExp(r'\bservice[_-]?role', caseSensitive: false)
              .hasMatch(body)) {
        continue;
      }

      final line = file.lineForOffset(match.start);
      if (isOffsetCommented(file, match.start) ||
          isCommentLine(file.lines[line - 1])) continue;

      yield Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.supabase,
        code: code,
        message:
            'Edge function response payload references the service-role key',
        fix:
            'Never return the service-role key (or anything derived from it) in a response body or header. The key must stay inside the function process; emit only the data the caller is authorised to see.',
        risk:
            'Leaking the service-role key to a caller is game-over for the project: the caller can read, mutate, or delete every row in every table bypassing Row Level Security.',
        filePath: file.relativePath,
        line: line,
      );
    }
  }

  bool _isEdgeFunctionFile(String normalizedPath) {
    return normalizedPath.startsWith('supabase/functions/') ||
        normalizedPath.contains('/supabase/functions/');
  }

  static int _findParenClose(String content, int start) {
    var depth = 1;
    var i = start;
    while (i < content.length) {
      final ch = content[i];
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == "'" || ch == '"' || ch == '`') {
        var j = i + 1;
        while (j < content.length) {
          final cj = content[j];
          if (cj == '\\') {
            j += 2;
            continue;
          }
          if (cj == ch) break;
          j++;
        }
        i = j + 1;
        continue;
      }
      if (ch == '(') {
        depth++;
      } else if (ch == ')') {
        depth--;
        if (depth == 0) return i;
      }
      i++;
    }
    return -1;
  }
}
