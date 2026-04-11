"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnvironmentVariablesRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
class EnvironmentVariablesRule {
    constructor() {
        this.code = 'missing-env-vars';
    }
    evaluate(context) {
        if (!context.usesSupabase) {
            return [];
        }
        const configReferenceFiles = [
            ...context.appDartFiles,
            ...context.yamlFiles,
            ...context.envFiles,
        ];
        const findings = [];
        const keys = ['SUPABASE_URL', 'SUPABASE_ANON_KEY'];
        for (const key of keys) {
            const isUsed = this._filesContain(configReferenceFiles, new RegExp(`String\\.fromEnvironment\\s*\\(\\s*['"]${key}['"]\\s*\\)`, 'i')) ||
                this._filesContain(configReferenceFiles, new RegExp(`dotenv\\.env\\s*\\[\\s*['"]${key}['"]\\s*\\]`, 'i')) ||
                this._filesContain(configReferenceFiles, new RegExp(`\\b(?:env|Env|config|Config|environment)['"]?${key}['"]?\\b|Platform\\.environment\\s*\\[\\s*['"]${key}['"]\\s*\\]`, 'i')) ||
                context.envEntries.some(e => e.key === key);
            if (!isUsed) {
                continue;
            }
            const reference = (0, ruleHelpers_1.firstReferenceFor)(context, key, configReferenceFiles);
            const hasRealConfig = context.hasEnvFile || context.usesDartDefine || context.usesDotenv;
            const hasOnlyExample = context.hasExampleEnvFile && !hasRealConfig;
            if (hasRealConfig) {
                continue;
            }
            if (hasOnlyExample) {
                findings.push(new finding_1.Finding({
                    severity: finding_1.FindingSeverity.low,
                    confidence: finding_1.FindingConfidence.low,
                    category: finding_1.FindingCategory.config,
                    code: this.code,
                    message: 'Environment variable used but only example config found',
                    fix: 'Create a real .env or provide runtime config via --dart-define.',
                    risk: 'App may fail in production due to missing config.',
                    filePath: reference?.file.relativePath,
                    line: reference?.line,
                }));
            }
            else {
                findings.push(new finding_1.Finding({
                    severity: finding_1.FindingSeverity.medium,
                    confidence: finding_1.FindingConfidence.medium,
                    category: finding_1.FindingCategory.config,
                    code: this.code,
                    message: 'Environment variable used but no configuration detected',
                    fix: 'Add .env or use --dart-define / dotenv.',
                    risk: 'Runtime failures due to missing credentials.',
                    filePath: reference?.file.relativePath,
                    line: reference?.line,
                }));
            }
        }
        return findings;
    }
    _filesContain(files, pattern) {
        for (const f of files) {
            if (pattern.test(f.content)) {
                return true;
            }
        }
        return false;
    }
}
exports.EnvironmentVariablesRule = EnvironmentVariablesRule;
