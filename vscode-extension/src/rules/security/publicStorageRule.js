"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PublicStorageRule = void 0;
const finding_1 = require("../../models/finding");
const HIGH_RISK_BUCKETS = new Set(['public']);
const REVIEW_BUCKETS = new Set(['avatar', 'avatars', 'public-files']);
class PublicStorageRule {
    constructor() {
        this.code = 'public-storage';
    }
    evaluate(context) {
        const findings = [];
        for (const bucket of context.storageBucketUses) {
            const normalized = bucket.bucketName.toLowerCase();
            const bucketTokens = normalized.split(/[-_.]+/);
            const looksPublicish = HIGH_RISK_BUCKETS.has(normalized) ||
                REVIEW_BUCKETS.has(normalized) ||
                bucketTokens.includes('public');
            if (!looksPublicish) {
                continue;
            }
            // Require BOTH user identifier AND sensitive context for HIGH severity
            const isHighRisk = bucket.pathHasUserIdPattern && bucket.pathHasSensitiveContext;
            if (!isHighRisk) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.high,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.security,
                code: this.code,
                message: `Potentially public storage bucket '${bucket.bucketName}' is used for app data`,
                fix: 'Verify that the bucket should be public. If the files are user-private, switch to a private bucket and enforce access with storage policies.',
                risk: 'Uploading user-specific files to a public bucket allows anyone to read those files if they can guess the URL.',
                filePath: bucket.file.relativePath,
                line: bucket.line,
            }));
        }
        return findings;
    }
}
exports.PublicStorageRule = PublicStorageRule;
