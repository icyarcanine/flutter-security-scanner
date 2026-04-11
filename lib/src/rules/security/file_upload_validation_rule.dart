import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class FileUploadValidationRule extends Rule {
  const FileUploadValidationRule();

  @override
  String get code => 'file-upload-validation';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final upload in context.uploadCalls) {
      if (upload.hasValidationHelper ||
          (upload.hasTypeValidation && upload.hasSizeValidation)) {
        continue;
      }

      final missingChecks = <String>[];
      if (!upload.hasTypeValidation) {
        missingChecks.add('file type');
      }
      if (!upload.hasSizeValidation) {
        missingChecks.add('size');
      }

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message:
              'Upload call is missing nearby ${missingChecks.join(' and ')} validation',
          fix:
              'Validate MIME/extension and file size before calling `.upload(...)` so unsafe files are rejected on the client before they hit storage.',
          risk:
              'Unvalidated client uploads can lead to malicious file execution, oversized payloads, or storage quota exhaustion.',
          filePath: upload.file.relativePath,
          line: upload.line,
        ),
      );
    }

    return findings;
  }
}
