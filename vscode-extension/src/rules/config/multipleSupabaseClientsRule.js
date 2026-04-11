"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultipleSupabaseClientsRule = void 0;
const finding_1 = require("../../models/finding");
class MultipleSupabaseClientsRule {
    constructor() {
        this.code = 'multiple-supabase-clients';
    }
    evaluate(context) {
        const locations = context.supabaseClientLocations;
        if (locations.length <= 1) {
            return [];
        }
        const location = locations[1];
        const total = locations.length;
        return [new finding_1.Finding({
                severity: finding_1.FindingSeverity.low,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.config,
                code: this.code,
                message: `${total} direct SupabaseClient(...) instances detected (first duplicate shown)`,
                fix: 'Create the client once and share it via a singleton, provider, or dependency injection so session state stays consistent.',
                risk: 'Multiple client instances can lead to desynchronized auth states and redundant network requests.',
                filePath: location.file.relativePath,
                line: location.line,
            })];
    }
}
exports.MultipleSupabaseClientsRule = MultipleSupabaseClientsRule;
