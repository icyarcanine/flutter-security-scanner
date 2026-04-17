import 'dart:convert';

import '../models/finding.dart';

/// Stable 16-char hex fingerprint for a [Finding].
///
/// Used by SARIF output (`partialFingerprints.primaryLocationLineHash/v1`)
/// and by the baseline file to match findings across runs. We intentionally
/// exclude the line number so cosmetic reformats don't invalidate the
/// fingerprint — a baseline captured today should still match after somebody
/// adds a blank line above the finding tomorrow.
///
/// Algorithm: FNV-1a 64-bit over `code \x01 filePath \x01 message`. Pure Dart
/// BigInt arithmetic so the scanner stays dependency-free.
String fingerprintFinding(Finding finding) {
  final input = <Object?>[
    finding.code,
    finding.filePath ?? '',
    finding.message,
  ].join('\u0001');
  return _fnv1a64Hex(input);
}

String _fnv1a64Hex(String input) {
  final prime = BigInt.parse('0x100000001b3');
  final mask = BigInt.parse('0xffffffffffffffff');
  var hash = BigInt.parse('0xcbf29ce484222325');
  final bytes = utf8.encode(input);
  for (final byte in bytes) {
    hash = ((hash ^ BigInt.from(byte)) * prime) & mask;
  }
  return hash.toRadixString(16).padLeft(16, '0');
}
