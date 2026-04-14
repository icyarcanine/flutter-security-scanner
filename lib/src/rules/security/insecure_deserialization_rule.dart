import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects unsafe deserialization of untrusted data.
///
/// OWASP Mobile Top 10: M4 — Insufficient Input/Output Validation.
///
/// Flags patterns where external/user-provided JSON is decoded without
/// validation, or where type casting is done unsafely on deserialized data.
class InsecureDeserializationRule extends Rule {
  const InsecureDeserializationRule();

  @override
  String get code => 'insecure-deserialization';

  /// jsonDecode/json.decode from request/external data.
  static final _jsonDecodePattern = RegExp(
    r'''(?:jsonDecode|json\.decode)\s*\(''',
  );

  /// Indicators that the decoded data comes from an untrusted source.
  static final _untrustedSourcePattern = RegExp(
    r'''(?:response\.body|request\.body|req\.body|utf8\.decode|body\.data|socket\.read|stdin|readAsString|readAsBytes|readLine|message\.data|event\.data|payload)''',
    caseSensitive: false,
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      for (final match in _jsonDecodePattern.allMatches(file.content)) {
        final line = file.lineForOffset(match.start);
        if (isCommentLine(file.lines[line - 1])) continue;

        // Check the argument and surrounding context for untrusted sources.
        final argStart = match.end;
        final argEnd = (argStart + 400).clamp(0, file.content.length);
        final argSnippet = file.content.substring(argStart, argEnd);

        // Also check the context around for the data source.
        final context = file.contextAroundLine(line, before: 5, after: 3);

        if (_untrustedSourcePattern.hasMatch(argSnippet) ||
            _untrustedSourcePattern.hasMatch(context)) {
          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.medium,
              category: FindingCategory.security,
              code: code,
              message:
                  'JSON deserialization of external data without validation',
              fix:
                  'Validate the structure and types of deserialized data before '
                  'using it. Use typed model classes with fromJson() factories '
                  'that validate fields, or use json_serializable / freezed.',
              risk:
                  'Deserializing untrusted data without validation can lead to '
                  'type confusion, null pointer exceptions, or injection of '
                  'unexpected values into application state.',
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
