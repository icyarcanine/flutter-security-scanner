"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImproperInitializationRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
class ImproperInitializationRule {
    constructor() {
        this.code = 'improper-initialization';
    }
    evaluate(context) {
        if (!context.usesSupabaseFlutter || context.hasSupabaseInitialize) {
            return [];
        }
        const candidates = [
            ...context.appDartFiles,
            ...(context.pubspecFile ? [context.pubspecFile] : []),
        ];
        const reference = (0, ruleHelpers_1.firstReferenceFor)(context, 'supabase_flutter', candidates);
        return [new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.config,
                code: this.code,
                message: 'supabase_flutter is used but Supabase.initialize(...) was not found',
                fix: 'Call `Supabase.initialize(...)` before `runApp()` so auth persistence and the shared client are configured once.',
                risk: 'Without proper initialization, auth state cannot be restored and the client may throw exceptions.',
                filePath: reference?.file.relativePath ?? context.pubspecFile?.relativePath,
                line: reference?.line,
            })];
    }
}
exports.ImproperInitializationRule = ImproperInitializationRule;
