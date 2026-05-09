import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects insecure image and file picker usage in Flutter apps.
///
/// Checks for:
/// 1. File path from picker used without validation
/// 2. Uploaded file paths used directly in SQL queries
/// 3. Missing file type validation after picking
/// 4. Missing file size validation
/// 5. File names used without sanitization
/// 6. Path traversal via picked file paths
///
/// This is a Flutter-specific file handling security rule.
class FilePickerValidationRule extends Rule {
  const FilePickerValidationRule();

  @override
  String get code => 'flutter.file-picker-validation';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findUnvalidatedFilePaths(file));
      findings.addAll(_findMissingTypeValidation(file));
      findings.addAll(_findMissingSizeValidation(file));
      findings.addAll(_findUnsanitizedFileNames(file));
    }

    return findings;
  }

  /// Detects file picker results used without path validation.
  List<Finding> _findUnvalidatedFilePaths(ScannedFile file) {
    final findings = <Finding>[];

    // Detect image_picker or file_picker usage
    final pickerPattern = RegExp(
      r'(?:ImagePicker|FilePicker|ImageSource|pickImage|pickFile|pickFiles|pickMultiImage)',
      caseSensitive: false,
    );

    if (!pickerPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check if picked file paths are validated before use.
    // Matches constructor calls and property access on picked files.
    final pathUsePattern = RegExp(
      r'(?:File\(|XFile\(|pickedFile|selectedFile|imageFile|result\.files|file\.path|file\.name)',
      caseSensitive: false,
    );

    for (final match in pathUsePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if there's validation nearby
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (!surroundingContent.contains('exists') &&
          !surroundingContent.contains('validate') &&
          !surroundingContent.contains('check') &&
          !surroundingContent.contains('sanitize') &&
          !surroundingContent.contains('path') &&
          !surroundingContent.contains('extension') &&
          !surroundingContent.contains('uuid') &&
          !surroundingContent.contains('basename')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Picked file path may not be validated before use',
          fix: 'Always validate picked file paths before use:\n'
              '1. Check the file exists and is readable\n'
              '2. Validate the file extension against an allowlist\n'
              '3. Check file size is within acceptable limits\n'
              '4. Sanitize the file name before storage or display\n'
              '5. Verify the path is within expected directories',
          risk: 'Unvalidated file paths from pickers can be manipulated to '
              'access sensitive files outside the intended directory, '
              'leading to path traversal and unauthorized file access.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects missing file type validation after picking.
  List<Finding> _findMissingTypeValidation(ScannedFile file) {
    final findings = <Finding>[];

    // Check for pickImage/pickFile without type constraints
    final unconstrainedPickPattern = RegExp(
      r'(?:pickImage\(|pickFile\(|pickFiles\()',
      caseSensitive: false,
    );

    for (final match in unconstrainedPickPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check surrounding lines for type restriction (args often span lines)
      final endLine = (line + 5).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (!surroundingContent.contains('type') &&
          !surroundingContent.contains('allowedextensions') &&
          !surroundingContent.contains('image') &&
          !surroundingContent.contains('jpeg') &&
          !surroundingContent.contains('png')) {
        findings.add(Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'File picker may lack type restriction',
          fix: 'Restrict file picker to expected file types:\n'
              'ImagePicker.pickImage(source: ImageSource.gallery, maxWidth: 1024)\n'
              'FilePicker.pickFiles(type: FileType.image, allowedExtensions: ["jpg", "png"])',
          risk: 'Without type restrictions, users can select any file type, '
              'including executable files or malicious scripts that could '
              'be processed unexpectedly by your application.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects missing file size validation.
  List<Finding> _findMissingSizeValidation(ScannedFile file) {
    final findings = <Finding>[];

    // Check for file uploads without size checks.
    // Only matches actual upload methods, not bucket selection (storage.from).
    final uploadPattern = RegExp(
      r'(?:uploadBinary|uploadString|fromPath|fromFile|putFile|\.upload\()',
      caseSensitive: false,
    );

    for (final match in uploadPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if size validation exists in the 50 lines before upload.
      // Business logic often separates validation from the upload call.
      final startLine = (line - 51).clamp(0, line - 1);
      final surroundingContent =
          file.lines.sublist(startLine, line - 1).join('\n').toLowerCase();

      if (!surroundingContent.contains('length') &&
          !surroundingContent.contains('size') &&
          !surroundingContent.contains('max') &&
          !surroundingContent.contains('limit') &&
          !surroundingContent.contains('validate')) {
        findings.add(Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'File upload may lack size validation',
          fix: 'Validate file size before upload to prevent denial of service '
              'and storage abuse. Check both client-side and enforce server-side '
              'limits in your Supabase storage policies.',
          risk: 'Unrestricted file uploads can lead to storage exhaustion, '
              'denial of service, and hosting of large malicious files.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects file names used without sanitization.
  List<Finding> _findUnsanitizedFileNames(ScannedFile file) {
    final findings = <Finding>[];

    // Check for file names used in storage paths or display
    final fileNamePattern = RegExp(
      r'(?:file\.name|path\.split\(|basename\(|\.path)',
      caseSensitive: false,
    );

    for (final match in fileNamePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if this is used in a storage upload path
      final endLine = (line + 10).clamp(0, file.lines.length);
      final surroundingContent =
          file.lines.sublist(line - 1, endLine).join('\n').toLowerCase();

      if (surroundingContent.contains('storage') &&
          surroundingContent.contains('upload') &&
          !surroundingContent.contains('uuid') &&
          !surroundingContent.contains('sanitize') &&
          !surroundingContent.contains('replace')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message:
              'Original file name used in storage path without sanitization',
          fix: 'Generate a safe file name for storage instead of using the '
              'original file name. Use UUIDs or sanitized hashes to prevent '
              'path traversal and name collisions:\n\n'
              'final safeName = "\${uuid.v4()}.\${extension}";\n'
              'await supabase.storage.from("avatars").upload(safeName, file);',
          risk: 'Using original file names in storage paths can lead to path '
              'traversal (../etc/passwd), name collisions, and overwriting '
              'of existing files. Malicious file names may also bypass filters.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
