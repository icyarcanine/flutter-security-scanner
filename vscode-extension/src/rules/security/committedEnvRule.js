"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CommittedEnvRule = void 0;
const finding_1 = require("../../models/finding");
class CommittedEnvRule {
    constructor() {
        this.code = 'committed-env';
    }
    evaluate(context) {
        const findings = [];
        for (const envFile of context.envFiles) {
            if (envFile.isEnvTemplateFile || context.gitignoreCoversEnvFile(envFile.relativePath)) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.high,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.security,
                code: this.code,
                message: '.env file is present but not ignored by git',
                fix: `Add \`${envFile.name}\` or a \`.env*\` rule to \`.gitignore\` before committing environment files.`,
                risk: 'Checking in `.env` files exposes production secrets or keys to source control history.',
                filePath: envFile.relativePath,
                line: 1,
            }));
        }
        return findings;
    }
}
exports.CommittedEnvRule = CommittedEnvRule;
