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

  static const _entropySkipExtensions = {
    '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.jar',
    '.map',
    '.md', '.txt', '.rst', // documentation
  };

  static final _testPathPattern = RegExp(
    r'(?:^|/)(test|tests|__tests__|spec|specs|fixtures|fixture|mocks|mock|examples?|e2e|testdata|test-data)(?:/|$)',
    caseSensitive: false,
  );

  static final _patterns = <_SecretPattern>[
    _SecretPattern(RegExp(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key'),
    _SecretPattern(
      RegExp(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
      'Private Key',
    ),
    _SecretPattern(
      RegExp(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
      'JWT Token',
    ),
    _SecretPattern(
      RegExp(
        r'''(?:bearer|token|apikey|api_key|secret|password)["'\s:=]+["'][A-Za-z0-9_.\-]{20,}["']''',
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
      if (_isSkippedExtension(file)) continue;

      // Targeted patterns run on all text files.
      for (final pattern in _patterns) {
        for (final match in pattern.regex.allMatches(file.content)) {
          if (_looksLikePlaceholder(match.group(0)!)) continue;

          final line = file.lineForOffset(match.start);
          if (isCommentLine(file.lines[line - 1])) continue;

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

      // Entropy scan — skip noisy files.
      if (_isEntropySkipped(file)) continue;

      for (final match in _literalPattern.allMatches(file.content)) {
        final candidate = match.group(2)!;
        if (_looksLikePlaceholder(candidate)) continue;
        if (_isHighEntropy(candidate)) {
          final line = file.lineForOffset(match.start);
          if (isCommentLine(file.lines[line - 1])) continue;

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

  bool _isSkippedExtension(ScannedFile file) {
    return _entropySkipExtensions.contains(file.extension);
  }

  bool _isEntropySkipped(ScannedFile file) {
    if (_entropySkipNames.contains(file.name)) return true;
    if (file.name.endsWith('.min.js') || file.name.endsWith('.min.css')) {
      return true;
    }
    if (_testPathPattern.hasMatch(file.relativePath)) return true;
    return false;
  }

  static bool _looksLikePlaceholder(String value) {
    final normalized = value.toLowerCase();
    return normalized.contains('your-') ||
        normalized.contains('your_') ||
        normalized.contains('replace') ||
        normalized.contains('example') ||
        normalized.contains('placeholder') ||
        normalized.contains('changeme') ||
        normalized.contains('xxx') ||
        normalized.contains('todo') ||
        normalized.contains('test') ||
        normalized.contains('mock') ||
        normalized.contains('dummy') ||
        normalized.contains('fake') ||
        normalized.contains('sample') ||
        normalized.contains('demo') ||
        normalized.contains('sandbox') ||
        normalized.contains('staging') ||
        normalized.contains('fixture') ||
        normalized.contains('lorem');
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
}

class _SecretPattern {
  const _SecretPattern(this.regex, this.type);
  final RegExp regex;
  final String type;
}
