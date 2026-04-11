"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClientSideTrustRule = void 0;
const finding_1 = require("../../models/finding");
class ClientSideTrustRule {
    constructor() {
        this.code = 'client-side-trust';
    }
    evaluate(context) {
        const findings = [];
        for (const access of context.tableAccesses) {
            if (!access.usesClientProvidedUserId) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.medium,
                category: finding_1.FindingCategory.security,
                code: this.code,
                message: 'Supabase query relies on a client-provided user identifier',
                fix: 'Do not trust route params or caller-provided `userId` values for authorization. Enforce ownership with RLS and only use `currentUser.id` as a convenience filter.',
                risk: 'Trusting client-provided user IDs for authorization allows malicious users to spoof actions or access data on behalf of others.',
                filePath: access.file.relativePath,
                line: access.line,
            }));
        }
        return findings;
    }
}
exports.ClientSideTrustRule = ClientSideTrustRule;
