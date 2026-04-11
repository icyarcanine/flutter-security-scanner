"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RlsPolicySuggestionRule = void 0;
const finding_1 = require("../../models/finding");
const projectContext_1 = require("../../scanner/projectContext");
class RlsPolicySuggestionRule {
    constructor() {
        this.code = 'rls-policy-suggestion';
    }
    evaluate(context) {
        const findings = [];
        const seenTables = new Set();
        for (const access of context.tableAccesses) {
            const normalized = access.table.toLowerCase();
            if (!seenTables.has(normalized)) {
                seenTables.add(normalized);
            }
            else {
                continue;
            }
            const confidence = this._confidenceForTable(normalized);
            if (!confidence) {
                continue;
            }
            const policy = (0, projectContext_1.suggestedPolicyForTable)(access.table);
            if (!policy) {
                continue;
            }
            findings.push(new finding_1.Finding({
                category: finding_1.FindingCategory.suggestion,
                confidence,
                code: this.code,
                message: `Heuristic RLS suggestion for table '${access.table}' (${confidence.toUpperCase()} confidence — verify against your schema)`,
                fix: `Consider: \`${policy}\`  — this is a heuristic; confirm column names match your actual schema before applying.`,
                filePath: access.file.relativePath,
                line: access.line,
            }));
        }
        return findings;
    }
    _confidenceForTable(normalized) {
        switch (normalized) {
            case 'profiles':
            case 'users':
                return finding_1.FindingConfidence.high;
            case 'posts':
            case 'todos':
            case 'notes':
            case 'orders':
            case 'comments':
            case 'messages':
                return finding_1.FindingConfidence.medium;
            default:
                return null;
        }
    }
}
exports.RlsPolicySuggestionRule = RlsPolicySuggestionRule;
