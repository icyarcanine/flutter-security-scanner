import 'dart:convert';

import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects Supabase **service role** JWTs checked into client code.
///
/// Supabase issues two keys for every project:
///
/// * **anon** — safe to ship in the client, scoped by RLS.
/// * **service_role** — bypasses RLS entirely. It is meant for server-side
///   automation only (Edge Functions, backoffice scripts). Shipping it in a
///   Flutter, Next.js, or React Native app hands every row of every table
///   to any attacker who disassembles the binary.
///
/// Both keys are JWTs with the same shape; the only way to tell them apart
/// without asking Supabase is to decode the payload and inspect the `role`
/// claim. That is exactly what this rule does.
///
/// Severity is pinned to HIGH and confidence to HIGH when a decoded JWT
/// carries `"role":"service_role"`. False positives are essentially
/// impossible — this is the signature of a real production service key.
class ServiceRoleKeyRule extends Rule {
  const ServiceRoleKeyRule();

  @override
  String get code => 'supabase-service-role-key-in-client';

  /// Any `eyJ…` JWT-ish literal. We intentionally accept a permissive prefix
  /// because we still verify the payload before reporting.
  static final _jwtPattern = RegExp(
    r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
  );

  /// Environment-variable names that should *never* appear in client-side
  /// code. Matching one of these is a separate, even stronger signal than
  /// the JWT payload check — the developer has typed out the key name.
  static final _envNamePattern = RegExp(
    r'\b(?:SUPABASE_SERVICE_ROLE(?:_KEY)?|SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY)\b',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Scan every Dart file in the client surface. Unlike the broader
    // `hardcoded_secrets` rule, we intentionally DO include test-like paths
    // here: checked-in test fixtures that ship with service-role keys are
    // themselves a leak vector the moment the repo is public.
    for (final file in context.dartFiles) {
      findings.addAll(_checkFile(file, context));
    }

    // Also walk env files (.env, .env.local, .env.production). Developers
    // sometimes commit them on accident, and if the committed file holds a
    // service role key that is an immediate compromise.
    for (final file in context.envFiles) {
      findings.addAll(_checkEnvFile(file, context));
    }

    // JS/TS/TSX files if the scanner was configured with web extensions
    // enabled. Same risk shape — shipping the key in a Next.js client
    // bundle is game over.
    for (final file in context.files) {
      if (!_isClientSourceFile(file)) continue;
      findings.addAll(_checkFile(file, context));
    }

    return findings;
  }

  bool _isClientSourceFile(ScannedFile file) {
    const webExtensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'};
    if (!webExtensions.contains(file.extension)) return false;
    // Supabase Edge Functions run server-side (Deno) and legitimately
    // need the service role. A service_role reference inside
    // `supabase/functions/...` is NOT a client leak; the dedicated
    // edge-function-secrets rule handles the narrower concerns there
    // (CORS wildcards, `verify_jwt = false`, response-body leaks).
    final normalized = file.relativePath.replaceAll(r'\\', '/');
    if (normalized.startsWith('supabase/functions/') ||
        normalized.contains('/supabase/functions/')) {
      return false;
    }
    return true;
  }

  List<Finding> _checkFile(ScannedFile file, ProjectContext context) {
    final findings = <Finding>[];
    final seenLines = <int>{};

    // Step 1 — JWT payload inspection.
    for (final match in _jwtPattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final token = match.group(0)!;
      if (!_jwtClaimsRoleServiceRole(token)) continue;

      final line = file.lineForOffset(match.start);
      if (!seenLines.add(line)) continue;
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(_serviceRoleFinding(file, line, reason: 'decoded JWT payload carries "role":"service_role"'));
    }

    // Step 2 — env-var name reference inside a client source file.
    for (final match in _envNamePattern.allMatches(file.content)) {
      if (isOffsetCommented(file, match.start)) continue;
      final line = file.lineForOffset(match.start);
      if (!seenLines.add(line)) continue;
      if (isCommentLine(file.lines[line - 1])) continue;

      // Skip the match if the surrounding snippet looks like documentation
      // ("DO NOT commit the SUPABASE_SERVICE_ROLE_KEY…") rather than a real
      // reference. A cheap heuristic: the same line mentions "do not",
      // "never", or "warning".
      final lineText = file.lines[line - 1].toLowerCase();
      if (lineText.contains('do not') ||
          lineText.contains('never ') ||
          lineText.contains('warning') ||
          lineText.contains('// ')) {
        continue;
      }

      findings.add(
        _serviceRoleFinding(
          file,
          line,
          reason: 'client source references SUPABASE_SERVICE_ROLE_KEY by name',
        ),
      );
    }

    return findings;
  }

  List<Finding> _checkEnvFile(ScannedFile file, ProjectContext context) {
    final findings = <Finding>[];
    // `.env.*.example` / `.env.sample` / `.env.template` are placeholder
    // templates, not real secrets — skip them.
    if (file.isEnvTemplateFile) return findings;

    final lines = file.lines;
    for (var i = 0; i < lines.length; i++) {
      final line = lines[i];
      if (line.trim().startsWith('#')) continue;

      // Key name on the LHS.
      final assignment = RegExp(
        r'^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$',
      ).firstMatch(line);
      if (assignment == null) continue;
      final key = assignment.group(1)!;
      var value = assignment.group(2)!.trim();
      // Strip surrounding quotes.
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.substring(1, value.length - 1);
      }

      final isServiceKeyName =
          _envNamePattern.hasMatch(key) ||
          key.toLowerCase().contains('service_role');
      final isServiceJwt = _jwtClaimsRoleServiceRole(value);

      if (!isServiceKeyName && !isServiceJwt) continue;

      // At this point we know either the key name or the JWT payload points
      // to a service role key. If the env file is gitignored *and* the
      // value is not a placeholder, downgrade severity a touch — the
      // developer at least knows not to commit it. But if the .env is
      // tracked by git (i.e. present in the scan), we still flag it HIGH
      // because checked-in service keys are always a leak.
      final tracked = !context.gitignoreCoversEnvFile(file.relativePath);
      findings.add(
        Finding(
          severity: tracked ? FindingSeverity.high : FindingSeverity.medium,
          confidence: FindingConfidence.high,
          category: FindingCategory.supabase,
          code: code,
          message: tracked
              ? 'Supabase service_role key present in an env file that is not .gitignored'
              : 'Supabase service_role key present in an env file (ensure .gitignored)',
          fix:
              'Move the service_role key out of any file that can reach a '
              'client machine or a public repo. Keep it in a server-side '
              'secret manager (Vercel/Netlify/GitHub Actions secret, '
              'Supabase Edge Function env, Doppler, AWS Secrets Manager). '
              'Never reference SUPABASE_SERVICE_ROLE_KEY from Flutter, '
              'React Native, Next.js client bundles, or mobile binaries.',
          risk:
              'The service_role key bypasses Row Level Security entirely. '
              'Anyone who obtains it can read or mutate every row of every '
              'table in the project.',
          filePath: file.relativePath,
          line: i + 1,
        ),
      );
    }

    return findings;
  }

  Finding _serviceRoleFinding(
    ScannedFile file,
    int line, {
    required String reason,
  }) {
    return Finding(
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      category: FindingCategory.supabase,
      code: code,
      message:
          'CRITICAL: Supabase service_role key detected in client source ($reason)',
      fix:
          'The service_role key bypasses Row Level Security. Rotate it in '
          'the Supabase dashboard immediately, then: (1) remove every '
          'occurrence from client code and committed files, (2) load it '
          'only from a server-side secret store, (3) confirm no published '
          'build has ever carried it. For client access use the anon key '
          'and rely on RLS to enforce authorization.',
      risk:
          'A service_role key embedded in a mobile or web client gives '
          'any attacker with the compiled binary or the downloaded bundle '
          'full read/write access to every table in the Supabase project. '
          'This is the single most common fatal Supabase mistake.',
      filePath: file.relativePath,
      line: line,
    );
  }

  /// Best-effort base64url JWT payload decoder. Returns `true` only when the
  /// second segment decodes to JSON containing `"role":"service_role"`.
  static bool _jwtClaimsRoleServiceRole(String token) {
    final parts = token.split('.');
    if (parts.length != 3) return false;
    final payload = parts[1];
    if (payload.isEmpty) return false;

    try {
      // Base64url → base64 → bytes → UTF-8 → JSON.
      final normalized = base64.normalize(payload);
      final decoded = utf8.decode(base64Url.decode(normalized));
      final dynamic parsed = jsonDecode(decoded);
      if (parsed is! Map) return false;
      final role = parsed['role'];
      return role is String && role == 'service_role';
    } catch (_) {
      return false;
    }
  }
}
