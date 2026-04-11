"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SensitiveLoggingRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
class SensitiveLoggingRule {
    constructor() {
        this.code = 'sensitive-logging';
    }
    evaluate(context) {
        const findings = [];
        for (const file of context.appDartFiles) {
            for (const stmt of (0, ruleHelpers_1.collectLogStatements)(file)) {
                if (!this._looksSensitive(stmt.argument)) {
                    continue;
                }
                findings.push(new finding_1.Finding({
                    severity: finding_1.FindingSeverity.high,
                    confidence: finding_1.FindingConfidence.high,
                    category: finding_1.FindingCategory.security,
                    code: this.code,
                    message: 'Sensitive auth or user data is being logged',
                    fix: 'Remove the log statement or redact auth/session fields before writing anything to logs.',
                    risk: 'Auth tokens and session objects in logs can be harvested from log files, crash reporters, or device storage.',
                    filePath: file.relativePath,
                    line: stmt.startLine,
                }));
            }
        }
        return findings;
    }
    _looksSensitive(argument) {
        const compact = argument.replace(/\s/g, '');
        if (['session', 'token', 'currentUser', 'currentSession'].includes(compact)) {
            return true;
        }
        if (/\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken)\b/i.test(argument)) {
            return true;
        }
        const stripped = argument
            .replace(/"(?:[^"\\]|\\.)*"/g, '')
            .replace(/'(?:[^'\\]|\\.)*'/g, '');
        return /(?<!\w)(session|accessToken|refreshToken|jwt|idToken|currentUser|currentSession|authState|authorization)(?!\w)|\.(currentUser|currentSession|accessToken|refreshToken|idToken)\b/i
            .test(stripped);
    }
}
exports.SensitiveLoggingRule = SensitiveLoggingRule;
