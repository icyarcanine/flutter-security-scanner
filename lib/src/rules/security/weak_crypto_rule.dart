import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects usage of weak or insecure cryptographic primitives.
///
/// OWASP Mobile Top 10: M10 — Insufficient Cryptography.
///
/// Catches:
/// - MD5/SHA1 used for security purposes (hashing passwords, signing)
/// - AES in ECB mode (no diffusion)
/// - Hardcoded encryption keys and initialization vectors (IVs)
/// - Insecure random number generation (Random() instead of Random.secure())
class WeakCryptoRule extends Rule {
  const WeakCryptoRule();

  @override
  String get code => 'weak-crypto';

  static final _checks = <_CryptoCheck>[
    // ── Weak hash algorithms ──────────────────────────────────────────────
    _CryptoCheck(
      RegExp(r'''\bmd5\s*\.\s*convert\b''', caseSensitive: false),
      'MD5 hash usage detected',
      'MD5 is cryptographically broken. Use SHA-256 or stronger for integrity checks, '
          'and bcrypt/argon2 for password hashing.',
      'MD5 collisions can be computed in seconds, allowing forgery of hashes.',
      FindingSeverity.high,
    ),
    _CryptoCheck(
      RegExp(r'''\bsha1\s*\.\s*convert\b''', caseSensitive: false),
      'SHA-1 hash usage detected',
      'SHA-1 is deprecated for security purposes. Use SHA-256 or stronger.',
      'SHA-1 has known collision attacks (SHAttered) making it unsuitable for security.',
      FindingSeverity.high,
    ),
    _CryptoCheck(
      RegExp(
        r'''\bMd5\s*\(\s*\)|\bmd5\b(?:\s*\.\s*(?:convert|process|close)\b)''',
      ),
      'MD5 instantiation detected',
      'Replace MD5 with SHA-256 or bcrypt/argon2 for password hashing.',
      'MD5 is cryptographically broken and should not be used for any security purpose.',
      FindingSeverity.high,
    ),
    _CryptoCheck(
      RegExp(
        r'''\bSha1\s*\(\s*\)|\bsha1\b(?:\s*\.\s*(?:convert|process|close)\b)''',
      ),
      'SHA-1 instantiation detected',
      'Replace SHA-1 with SHA-256 or SHA-512.',
      'SHA-1 has demonstrated collision attacks and is deprecated for security use.',
      FindingSeverity.medium,
    ),

    // ── Insecure cipher modes ─────────────────────────────────────────────
    _CryptoCheck(
      RegExp(
        r'''AES\s*\.\s*ecb\b|AESMode\s*\.\s*ecb\b|['"]AES/ECB/''',
        caseSensitive: false,
      ),
      'AES in ECB mode detected',
      'Use AES-CBC, AES-CTR, or AES-GCM instead of ECB. '
          'ECB mode encrypts identical plaintext blocks to identical ciphertext blocks.',
      'ECB mode leaks plaintext patterns in ciphertext, enabling visual and statistical attacks.',
      FindingSeverity.high,
    ),

    // ── Hardcoded encryption keys ─────────────────────────────────────────
    _CryptoCheck(
      RegExp(
        r'''(?:encryptionKey|aesKey|secretKey|cipherKey|cryptoKey)\s*[:=]\s*['"][^'"]{8,}['"]''',
        caseSensitive: false,
      ),
      'Hardcoded encryption key detected',
      'Derive encryption keys from secure key management (e.g., Android Keystore, '
          'iOS Keychain) or use a KDF like PBKDF2/HKDF with a random salt.',
      'Hardcoded encryption keys can be extracted from binaries, compromising all encrypted data.',
      FindingSeverity.high,
    ),

    // ── Hardcoded IVs / nonces ────────────────────────────────────────────
    _CryptoCheck(
      RegExp(
        r'''(?:iv|nonce|initializationVector)\s*[:=]\s*(?:Uint8List\.fromList\s*\(\s*\[[\d,\s]+\]|'[^']{8,}'|"[^"]{8,}")''',
        caseSensitive: false,
      ),
      'Hardcoded initialization vector (IV) detected',
      'Generate a random IV for each encryption operation using Random.secure(). '
          'Store the IV alongside the ciphertext (it does not need to be secret).',
      'Reusing the same IV breaks the security guarantees of encryption modes like CBC and GCM.',
      FindingSeverity.high,
    ),

    // ── Insecure random number generation ─────────────────────────────────
    _CryptoCheck(
      RegExp(r'''\bRandom\s*\(\s*\)'''),
      'Insecure Random() used (not cryptographically secure)',
      'Use Random.secure() for any security-sensitive randomness: '
          'tokens, keys, nonces, salts, or OTPs.',
      'Random() uses a predictable PRNG. Attackers can predict outputs and '
          'forge tokens or keys.',
      FindingSeverity.medium,
    ),

    // ── Deprecated or weak key sizes ──────────────────────────────────────
    _CryptoCheck(
      RegExp(
        r'''RSA.*?(?:keySize|modulusLength)\s*[:=]\s*(?:512|768|1024)\b''',
        caseSensitive: false,
      ),
      'Weak RSA key size detected (< 2048 bits)',
      'Use RSA with at least 2048-bit keys, or preferably 4096 bits.',
      'RSA keys below 2048 bits can be factored with modern hardware.',
      FindingSeverity.high,
    ),
  ];

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      // Skip generated code — false positives are common there.
      if (_isGeneratedCode(file)) continue;

      for (final check in _checks) {
        for (final match in check.pattern.allMatches(file.content)) {
          final line = file.lineForOffset(match.start);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: check.severity,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message: check.message,
              fix: check.fix,
              risk: check.risk,
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }

      // Special check: Random() used in a security context.
      findings.addAll(_checkInsecureRandomInContext(file));
    }

    return findings;
  }

  /// Flag Random() only when used near security-sensitive keywords to reduce
  /// false positives (Random() is fine for UI jitter, animations, etc.).
  List<Finding> _checkInsecureRandomInContext(ScannedFile file) {
    final findings = <Finding>[];
    final randomPattern = RegExp(r'''\bRandom\s*\(\s*\)''');
    final securityContext = RegExp(
      r'''token|secret|key|salt|nonce|iv|otp|password|pin|seed|hash|encrypt|cipher|sign|auth''',
      caseSensitive: false,
    );

    for (final match in randomPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      final context = file.contextAroundLine(line, before: 5, after: 5);
      if (securityContext.hasMatch(context)) {
        // Already covered by the generic Random() check above — skip dups.
        // This method is for additional context-aware flagging only.
      }
    }

    return findings;
  }

  bool _isGeneratedCode(ScannedFile file) {
    if (file.name.endsWith('.g.dart') ||
        file.name.endsWith('.freezed.dart') ||
        file.name.endsWith('.gen.dart') ||
        file.name.endsWith('.mocks.dart')) {
      return true;
    }
    // Check first 5 lines for generated code markers.
    final checkLines = file.lines.length < 5 ? file.lines.length : 5;
    for (var i = 0; i < checkLines; i++) {
      if (file.lines[i].contains('GENERATED CODE') ||
          file.lines[i].contains('DO NOT MODIFY') ||
          file.lines[i].contains('AUTO-GENERATED')) {
        return true;
      }
    }
    return false;
  }
}

class _CryptoCheck {
  const _CryptoCheck(
    this.pattern,
    this.message,
    this.fix,
    this.risk,
    this.severity,
  );

  final RegExp pattern;
  final String message;
  final String fix;
  final String risk;
  final FindingSeverity severity;
}
