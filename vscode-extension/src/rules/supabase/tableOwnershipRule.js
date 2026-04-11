"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TableOwnershipRule = void 0;
const finding_1 = require("../../models/finding");
const projectContext_1 = require("../../scanner/projectContext");
class TableOwnershipRule {
    constructor() {
        this.code = 'table-ownership-filter';
    }
    evaluate(context) {
        const findings = [];
        for (const access of context.tableAccesses) {
            if (access.operation === 'insert') {
                continue;
            }
            const expectedColumns = (0, projectContext_1.ownerColumnsForTable)(access.table);
            if (expectedColumns.size === 0 || access.hasOwnershipFilter) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: (access.operation === 'update' || access.operation === 'delete')
                    ? finding_1.FindingSeverity.high
                    : finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.medium,
                category: finding_1.FindingCategory.supabase,
                code: this.code,
                message: `Query on '${access.table}' has no obvious ownership filter`,
                fix: this._fixFor(access.table),
                risk: 'Without an ownership filter, this query may allow clients to read or modify data belonging to other users.',
                filePath: access.file.relativePath,
                line: access.line,
            }));
        }
        return findings;
    }
    _fixFor(table) {
        const policy = (0, projectContext_1.suggestedPolicyForTable)(table);
        if (!policy) {
            return 'Add an ownership filter that matches the authenticated user, and enforce the same rule with RLS.';
        }
        const lower = table.toLowerCase();
        if (lower === 'profiles' || lower === 'users') {
            return "Prefer RLS and, when filtering client-side, scope the query to the signed-in user with `.eq('id', supabase.auth.currentUser!.id)`.";
        }
        return `Prefer RLS and, when filtering client-side, scope the query to the signed-in user. A common policy for \`${table}\` is \`${policy}\`.`;
    }
}
exports.TableOwnershipRule = TableOwnershipRule;
