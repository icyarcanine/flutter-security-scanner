import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects plaintext HTTP connections that should use HTTPS instead.
///
/// Flags http:// URLs in Dart code (excluding localhost and LAN addresses
/// which are common for development). Handles all Dart string literal forms
/// including raw strings (r'...') and triple-quoted strings.
class PlaintextHttpRule extends Rule {
  const PlaintextHttpRule();

  @override
  String get code => 'plaintext-http';

  static final _httpPattern = RegExp(r'^http://(.+)');
  static final _wsPattern = RegExp(r'^ws://(.+)');

  /// Localhost and LAN patterns that are acceptable for development.
  static final _devHostPattern = RegExp(
    r'^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      // Use string literal extraction to handle raw/triple-quoted strings.
      for (final (offset, content) in extractStringLiterals(file.content)) {
        final httpMatch = _httpPattern.firstMatch(content);
        if (httpMatch != null) {
          final host = httpMatch.group(1)!;
          if (_devHostPattern.hasMatch(host)) continue;

          final line = file.lineForOffset(offset);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message: 'Plaintext HTTP connection detected',
              fix:
                  'Use HTTPS instead of HTTP to encrypt data in transit. '
                  'Replace http:// with https:// in the URL.',
              risk:
                  'Plaintext HTTP traffic can be intercepted by attackers on the '
                  'same network (man-in-the-middle attack), exposing sensitive data.',
              filePath: file.relativePath,
              line: line,
            ),
          );
          continue;
        }

        final wsMatch = _wsPattern.firstMatch(content);
        if (wsMatch != null) {
          final host = wsMatch.group(1)!;
          if (_devHostPattern.hasMatch(host)) continue;

          final line = file.lineForOffset(offset);
          if (isCommentLine(file.lines[line - 1])) continue;

          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message: 'Plaintext WebSocket connection detected',
              fix:
                  'Use WSS (WebSocket Secure) instead of WS. '
                  'Replace ws:// with wss:// in the URL.',
              risk:
                  'Plaintext WebSocket traffic can be intercepted, exposing '
                  'real-time data streams to eavesdroppers.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }
    }

    return findings;
  }
}
