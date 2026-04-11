"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MissingRlsAwarenessRule = void 0;
const finding_1 = require("../../models/finding");
const projectContext_1 = require("../../scanner/projectContext");
class MissingRlsAwarenessRule {
    constructor() {
        this.code = 'missing-rls-awareness';
    }
    evaluate(context) {
        if (context.tableAccesses.length === 0) {
            return [];
        }
        const level = context.rlsEvidenceLevel;
        if (level === projectContext_1.RlsEvidenceLevel.strong) {
            return [];
        }
        const firstAccess = context.tableAccesses[0];
        if (level === projectContext_1.RlsEvidenceLevel.weak) {
            return [new finding_1.Finding({
                    severity: finding_1.FindingSeverity.low,
                    confidence: finding_1.FindingConfidence.low,
                    category: finding_1.FindingCategory.supabase,
                    code: this.code,
                    message: 'Only informal RLS mentions found — no CREATE POLICY or ENABLE ROW LEVEL SECURITY detected',
                    fix: 'Commit your RLS migration SQL (or check that supabase/migrations/ is included in the scan) so the access model is reviewable locally.',
                    risk: 'Without verifiable RLS policies, it is impossible to audit row-level access control from the source code alone.',
                    filePath: firstAccess.file.relativePath,
                    line: firstAccess.line,
                })];
        }
        return [new finding_1.Finding({
                severity: finding_1.FindingSeverity.high,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.supabase,
                code: this.code,
                message: 'Supabase table queries found but no RLS setup detected anywhere in the project',
                fix: 'Enable Row Level Security for every table the app touches and commit the policies or migration SQL so the access model is reviewable.',
                risk: 'Without RLS, any authenticated (or unauthenticated) user can read or mutate data they do not own.',
                filePath: firstAccess.file.relativePath,
                line: firstAccess.line,
            })];
    }
}
exports.MissingRlsAwarenessRule = MissingRlsAwarenessRule;
