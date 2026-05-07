import 'dart:convert';
import 'dart:math';

import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects hardcoded secrets that are not Supabase-specific: AWS keys, private
/// keys, JWT tokens, generic API keys, and high-entropy string literals.
///
/// This is the Dart CLI port of the VS Code extension's `GenericSecretRule`.
class GenericSecretRule extends Rule {
  const GenericSecretRule();

  @override
  String get code => 'generic-secret';

  /// File names that should never be scanned for entropy secrets.
  static const _entropySkipNames = {
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'composer.lock',
    'Gemfile.lock',
    'Pipfile.lock',
    'poetry.lock',
    'go.sum',
    'Cargo.lock',
    'pubspec.lock',
    'packages.lock.json',
  };

  /// Binary / encoded file formats where neither targeted regexes nor the
  /// entropy heuristic make sense. These are skipped entirely.
  static const _binarySkipExtensions = {
    '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.jar',
    '.map',
  };

  /// Text formats where targeted vendor regexes (JWT, ghp_, AKIA, …) still
  /// run, but the entropy heuristic is too noisy to be useful. Covers
  /// documentation and markup/config files where quoted values are schema
  /// keys, resource identifiers, or package names — not programming-language
  /// string literals. Entropy here is almost always a false positive (e.g.
  /// `android.permission.REQUEST_INSTALL_PACKAGES` clears the 4.5 bar).
  static const _entropySkipExtensions = {
    '.md', '.txt', '.rst', // documentation
    '.xml', '.plist', '.properties',
  };

  static final _testPathPattern = RegExp(
    r'(?:^|/)(test|tests|__tests__|spec|specs|fixtures|fixture|mocks|mock|examples?|e2e|testdata|test-data)(?:/|$)',
    caseSensitive: false,
  );

  /// High-precision secret prefixes. Each entry is essentially "if the string
  /// contains this byte pattern, it almost certainly IS that vendor's secret".
  /// We deliberately list every common modern provider — the cost of one
  /// extra regex per file is negligible compared to a missed leaked key.
  static final _patterns = <_SecretPattern>[
    // AWS
    _SecretPattern(RegExp(r'\bAKIA[0-9A-Z]{16}\b'), 'AWS Access Key'),
    _SecretPattern(RegExp(r'\bASIA[0-9A-Z]{16}\b'), 'AWS Temporary Access Key'),

    // Cryptographic key material
    _SecretPattern(
      RegExp(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
      'Private Key',
    ),
    _SecretPattern(
      RegExp(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
      'PGP Private Key',
    ),

    // JWT (signed: 3 base64url segments separated by dots)
    _SecretPattern(
      RegExp(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
      'JWT Token',
    ),

    // GitHub — personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
    // server-to-server (ghs_), refresh (ghr_).
    _SecretPattern(
      RegExp(r'\bgh[pousr]_[A-Za-z0-9]{36,255}\b'),
      'GitHub Token',
    ),

    // Slack — xoxb (bot), xoxp (user), xoxa (workspace), xoxr (refresh),
    // xoxe (legacy)
    _SecretPattern(
      RegExp(r'\bxox[baprse]-[A-Za-z0-9-]{10,}'),
      'Slack Token',
    ),

    // Stripe — sk_live_ / rk_live_ / pk_live_ (and corresponding _test_ keys)
    _SecretPattern(
      RegExp(r'\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b'),
      'Stripe API Key',
    ),

    // OpenAI — `sk-` followed by ≥40 alphanumerics; project keys use `sk-proj-`.
    _SecretPattern(
      RegExp(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b'),
      'OpenAI API Key',
    ),

    // Anthropic — `sk-ant-` followed by alphanumerics/dashes.
    _SecretPattern(
      RegExp(r'\bsk-ant-[A-Za-z0-9_-]{40,}\b'),
      'Anthropic API Key',
    ),

    // SendGrid — `SG.` + base62 + `.` + base62
    _SecretPattern(
      RegExp(r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b'),
      'SendGrid API Key',
    ),

    // Twilio — Account SID (`AC` + 32 hex), API Key (`SK` + 32 hex)
    _SecretPattern(
      RegExp(r'\bAC[0-9a-fA-F]{32}\b'),
      'Twilio Account SID',
    ),
    _SecretPattern(
      RegExp(r'\bSK[0-9a-fA-F]{32}\b'),
      'Twilio API Key',
    ),

    // npm — token starts with `npm_` and is at least 36 chars.
    _SecretPattern(
      RegExp(r'\bnpm_[A-Za-z0-9]{36,}\b'),
      'npm Access Token',
    ),

    // Google API key prefix (`AIzaSy` + 33 chars). Already caught in the
    // Supabase rule for `_findFirebaseKeys` but worth covering here for
    // non-Firebase Google services scanned outside Dart files.
    _SecretPattern(
      RegExp(r'\bAIzaSy[A-Za-z0-9_-]{33}\b'),
      'Google API Key',
    ),

    // Discord bot token: 24 base64 chars, `.`, 6 chars, `.`, 27 chars.
    _SecretPattern(
      RegExp(r'\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b'),
      'Discord Bot Token',
    ),

    // Generic credential variable assignment — kept LAST so vendor-specific
    // patterns above always win. Loosened from the previous list to also
    // catch `db_pass`, `client_secret`, `auth_token`, etc.
    _SecretPattern(
      RegExp(
        r'''(?:bearer|token|api[_-]?key|secret|password|passwd|pass|client[_-]?secret|auth[_-]?token|access[_-]?token|db[_-]?pass(?:word)?)["'\s:=]+["'][A-Za-z0-9_.\-]{20,}["']''',
        caseSensitive: false,
      ),
      'API Key',
    ),
  ];

  static final _literalPattern = RegExp(r'''(["'])((?:(?!\1).)*?)\1''');

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files) {
      if (_isBinaryExtension(file)) continue;

      // Targeted patterns run on all text files — including docs, XML, and
      // config. A leaked vendor token is still a leaked token regardless of
      // which file it hides in.
      for (final pattern in _patterns) {
        for (final match in pattern.regex.allMatches(file.content)) {
          // Use the STRICT placeholder filter for targeted patterns. The
          // broad filter (which strips anything containing `test`, `mock`,
          // `sandbox`, …) is too aggressive for high-precision regexes —
          // a real `sandboxApiKey = "ghp_…"` is still a leaked GitHub
          // token regardless of what the variable is named.
          if (_looksLikeStrictPlaceholder(match.group(0)!)) continue;

          final line = file.lineForOffset(match.start);
          if (isOffsetCommented(file, match.start) ||
              isCommentLine(file.lines[line - 1])) continue;

          // JWT special case: decode the payload so a Supabase service_role
          // token gets the critical-severity treatment it deserves, while a
          // harmless anon token is downgraded. The dedicated
          // ServiceRoleKeyRule handles Dart/env/web client files — we
          // intentionally still run the generic path so docs, YAML, JSON,
          // and similar configuration files also get coverage.
          if (pattern.type == 'JWT Token') {
            final token = match.group(0)!;
            final classification = _classifyJwt(token);
            findings.add(
              Finding(
                severity: classification.severity,
                confidence: classification.confidence,
                category: FindingCategory.security,
                code: code,
                message: classification.message,
                fix: classification.fix,
                risk: classification.risk,
                filePath: file.relativePath,
                line: line,
              ),
            );
            continue;
          }

          findings.add(
            Finding(
              severity: FindingSeverity.high,
              confidence: FindingConfidence.low,
              category: FindingCategory.security,
              code: code,
              message: 'Potential hardcoded ${pattern.type} detected',
              fix:
                  'Move this ${pattern.type} to environment variables or a secure vault.',
              risk:
                  'Hardcoded secrets can be extracted from source code and binaries, leading to system compromise.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }

      // Entropy scan — skip noisy files, doc/markup extensions, and tests.
      if (_entropySkipExtensions.contains(file.extension)) continue;
      if (_isEntropySkipped(file)) continue;

      for (final match in _literalPattern.allMatches(file.content)) {
        final candidate = match.group(2)!;
        // Entropy heuristics see a much higher false-positive rate, so the
        // broad placeholder filter (test/mock/demo/…) is justified here.
        if (_looksLikeBroadPlaceholder(candidate)) continue;
        if (_isHighEntropy(candidate)) {
          final line = file.lineForOffset(match.start);
          if (isOffsetCommented(file, match.start) ||
              isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.low,
              category: FindingCategory.security,
              code: 'high-entropy-secret',
              message: 'High-entropy string literal detected (possible secret)',
              fix:
                  'Verify if this string is a secret. If so, move it to environment variables.',
              risk:
                  'High-entropy strings often indicate hardcoded cryptographic keys or secrets.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }
    }

    return findings;
  }

  bool _isBinaryExtension(ScannedFile file) {
    return _binarySkipExtensions.contains(file.extension);
  }

  bool _isEntropySkipped(ScannedFile file) {
    if (_entropySkipNames.contains(file.name)) return true;
    if (file.name.endsWith('.min.js') || file.name.endsWith('.min.css')) {
      return true;
    }
    if (_testPathPattern.hasMatch(file.relativePath)) return true;
    return false;
  }

  /// Strict filter for targeted secret regexes (vendor prefixes, JWT, etc.).
  /// Only obvious placeholder text is filtered — substrings like `test` or
  /// `sandbox` are NOT enough to skip a high-precision match. A real
  /// `sandboxApiKey = "ghp_real_token_here…"` should still fire.
  static bool _looksLikeStrictPlaceholder(String value) {
    final normalized = value.toLowerCase();
    return normalized.contains('your-') ||
        normalized.contains('your_') ||
        normalized.contains('replace-me') ||
        normalized.contains('replace_me') ||
        normalized.contains('placeholder') ||
        normalized.contains('changeme') ||
        normalized.contains('change_me') ||
        normalized.contains('xxxxxxxx') ||
        normalized.contains('todo') ||
        normalized.contains('insertkeyhere') ||
        normalized.contains('lorem');
  }

  /// Broad filter for the entropy heuristic. Entropy alone is a noisy signal
  /// (commit hashes, asset URLs, build IDs all look high-entropy) so we
  /// cast a wide net for "looks like example/test data".
  static bool _looksLikeBroadPlaceholder(String value) {
    if (_looksLikeStrictPlaceholder(value)) return true;
    final normalized = value.toLowerCase();
    return normalized.contains('replace') ||
        normalized.contains('example') ||
        normalized.contains('xxx') ||
        normalized.contains('test') ||
        normalized.contains('mock') ||
        normalized.contains('dummy') ||
        normalized.contains('fake') ||
        normalized.contains('sample') ||
        normalized.contains('demo') ||
        normalized.contains('sandbox') ||
        normalized.contains('staging') ||
        normalized.contains('fixture');
  }

  /// Shannon entropy >= 4.5 but exclude common false positive patterns.
  static bool _isHighEntropy(String value) {
    if (value.length < 8 || value.length > 200) return false;
    // Skip strings that look like paths, URLs, prose, or UUIDs.
    if (value.contains('/') ||
        value.contains(' ') ||
        value.startsWith('http')) {
      return false;
    }
    // UUID pattern (common high-entropy non-secret).
    if (RegExp(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
      caseSensitive: false,
    ).hasMatch(value)) {
      return false;
    }
    // SHA-256 hash output (64 hex chars — common in lock files and checksums).
    if (RegExp(r'^[0-9a-f]{64}$', caseSensitive: false).hasMatch(value)) {
      return false;
    }
    // Base64-encoded very short strings (low risk).
    if (value.endsWith('==') && value.length < 16) return false;
    // Repeated characters.
    if (RegExp(r'^(.)\1+$').hasMatch(value)) return false;

    final freq = <int, int>{};
    for (var i = 0; i < value.length; i++) {
      final c = value.codeUnitAt(i);
      freq[c] = (freq[c] ?? 0) + 1;
    }

    var entropy = 0.0;
    final len = value.length.toDouble();
    for (final count in freq.values) {
      final p = count / len;
      entropy -= p * (log(p) / ln2);
    }

    return entropy >= 4.5;
  }

  /// Decodes a JWT payload and differentiates Supabase service_role tokens
  /// from anon tokens so generic_secret reports the right severity in docs,
  /// YAML, JSON and any other non-Dart surface that ServiceRoleKeyRule does
  /// not cover. Any decode failure falls back to the generic JWT finding.
  static _JwtClassification _classifyJwt(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3) return _defaultJwtClassification;
      final payloadSegment = parts[1];
      if (payloadSegment.isEmpty) return _defaultJwtClassification;
      final decodedBytes = base64Url.decode(base64.normalize(payloadSegment));
      final claims = jsonDecode(utf8.decode(decodedBytes));
      if (claims is! Map<String, dynamic>) return _defaultJwtClassification;

      final role = claims['role'];
      if (role == 'service_role') {
        return const _JwtClassification(
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          message: 'Hardcoded Supabase service_role JWT detected',
          fix:
              'Rotate this key immediately and remove it from the repository. The service_role key bypasses Row Level Security and grants unrestricted database access — it must NEVER be shipped in clients, docs, fixtures, or configuration files. Use environment variables on a trusted backend only.',
          risk:
              'A leaked service_role JWT bypasses every Row Level Security policy and gives unrestricted read/write/delete access to the entire Supabase project. An attacker holding this token can exfiltrate user data, tamper with records, or destroy tables.',
        );
      }
      if (role == 'anon') {
        return const _JwtClassification(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.high,
          message: 'Supabase anon JWT detected',
          fix:
              'Anon keys are intended to be shipped to clients. Confirm this key matches the target project and that Row Level Security is enabled on every table it can reach.',
          risk:
              'Anon keys are only safe when RLS is fully configured. A project with missing or permissive RLS policies will leak data through the anon role.',
        );
      }
      return _defaultJwtClassification;
    } catch (_) {
      return _defaultJwtClassification;
    }
  }

  static const _defaultJwtClassification = _JwtClassification(
    severity: FindingSeverity.high,
    confidence: FindingConfidence.low,
    message: 'Potential hardcoded JWT Token detected',
    fix: 'Move this JWT Token to environment variables or a secure vault.',
    risk:
        'Hardcoded secrets can be extracted from source code and binaries, leading to system compromise.',
  );
}

class _SecretPattern {
  const _SecretPattern(this.regex, this.type);
  final RegExp regex;
  final String type;
}

class _JwtClassification {
  const _JwtClassification({
    required this.severity,
    required this.confidence,
    required this.message,
    required this.fix,
    required this.risk,
  });

  final FindingSeverity severity;
  final FindingConfidence confidence;
  final String message;
  final String fix;
  final String risk;
}
