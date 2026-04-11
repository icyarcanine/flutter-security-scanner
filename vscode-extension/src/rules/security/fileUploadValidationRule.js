"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileUploadValidationRule = void 0;
const finding_1 = require("../../models/finding");
class FileUploadValidationRule {
    constructor() {
        this.code = 'file-upload-validation';
    }
    evaluate(context) {
        const findings = [];
        for (const upload of context.uploadCalls) {
            if (upload.hasValidationHelper || (upload.hasTypeValidation && upload.hasSizeValidation)) {
                continue;
            }
            const missing = [];
            if (!upload.hasTypeValidation) {
                missing.push('file type');
            }
            if (!upload.hasSizeValidation) {
                missing.push('size');
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.medium,
                category: finding_1.FindingCategory.security,
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
exports.FileUploadValidationRule = FileUploadValidationRule;
