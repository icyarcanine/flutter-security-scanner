import { Rule } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

export class FileUploadValidationRule implements Rule {
  readonly code = 'file-upload-validation';

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const upload of context.uploadCalls) {
      if (upload.hasValidationHelper || (upload.hasTypeValidation && upload.hasSizeValidation)) {
        continue;
      }
      const missing: string[] = [];
      if (!upload.hasTypeValidation) { missing.push('file type'); }
      if (!upload.hasSizeValidation) { missing.push('size'); }
      findings.push(new Finding({
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        detectionMethod: DetectionMethod.structural,
        category: FindingCategory.security,
        code: this.code,
        message: `Upload call is missing nearby ${missing.join(' and ')} validation`,
        fix: 'Validate MIME/extension and file size before calling `.upload(...)` so unsafe files are rejected on the client before they hit storage.',
        risk: 'Unvalidated client uploads can lead to malicious file execution, oversized payloads, or storage quota exhaustion.',
        filePath: upload.file.relativePath,
        line: upload.line,
      }));
    }
    return findings;
  }
}
