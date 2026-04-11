"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DebugCodeRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
const PLAIN_PRINT_PATTERN = /\bprint\s*\(/;
class DebugCodeRule {
    constructor() {
        this.code = 'debug-print';
    }
    evaluate(context) {
        const findings = [];
        for (const file of context.dartFiles) {
            if (!(0, ruleHelpers_1.isProductionDartFile)(file)) {
                continue;
            }
            for (const stmt of (0, ruleHelpers_1.collectLogStatements)(file)) {
                const sourceLine = file.lines[stmt.startLine - 1];
                if (!PLAIN_PRINT_PATTERN.test(sourceLine)) {
                    continue;
                }
                if ((0, ruleHelpers_1.isCommentLine)(sourceLine)) {
                    continue;
                }
                if (this._looksSensitiveEnough(stmt.argument)) {
                    continue;
                }
                findings.push(new finding_1.Finding({
                    severity: finding_1.FindingSeverity.low,
                    confidence: finding_1.FindingConfidence.medium,
                    category: finding_1.FindingCategory.config,
                    code: this.code,
                    message: 'print() left in production code',
                    fix: 'Remove the debug print or replace it with structured logging that can be disabled outside development.',
                    risk: 'Debug output can leak internal state and increases binary verbosity in production.',
                    filePath: file.relativePath,
                    line: stmt.startLine,
                }));
            }
        }
        return findings;
    }
    _looksSensitiveEnough(argument) {
        if (/\$\{?\s*(session|accessToken|refreshToken|currentUser|currentSession|jwt|idToken|token)\b/i.test(argument)) {
            return true;
        }
        if (/\.(currentUser|currentSession|accessToken|refreshToken|idToken|jwt)\b/i.test(argument)) {
            return true;
        }
        return /(?<!\w)(?:session|currentUser|currentSession|accessToken|refreshToken)(?!\w)/i.test(argument);
    }
}
exports.DebugCodeRule = DebugCodeRule;
