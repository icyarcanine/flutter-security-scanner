"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidSupabaseUrlRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
class InvalidSupabaseUrlRule {
    constructor() {
        this.code = 'invalid-supabase-url';
    }
    evaluate(context) {
        const findings = [];
        for (const entry of context.envEntries.filter(e => e.key === 'SUPABASE_URL')) {
            if (entry.file.isEnvTemplateFile) {
                continue;
            }
            if (this._looksValid(entry.value)) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.config,
                code: this.code,
                message: 'SUPABASE_URL does not look like a valid Supabase HTTPS URL',
                fix: 'Use the full project URL from Supabase, for example `https://your-project.supabase.co`.',
                risk: 'Malformed URLs will cause network requests to fail entirely, breaking app connectivity.',
                filePath: entry.file.relativePath,
                line: entry.line,
            }));
        }
        const initializePattern = /Supabase\.initialize\([^;]*?\burl\s*:\s*['"]([^'"]+)['"]/gs;
        const clientPattern = /\bSupabaseClient\s*\(\s*['"]([^'"]+)['"]/gs;
        for (const file of context.appDartFiles) {
            for (const pattern of [initializePattern, clientPattern]) {
                pattern.lastIndex = 0;
                let match;
                while ((match = pattern.exec(file.content)) !== null) {
                    const value = match[1];
                    if (this._looksValid(value)) {
                        continue;
                    }
                    const line = file.lineForOffset(match.index);
                    if ((0, ruleHelpers_1.isCommentLine)(file.lines[line - 1])) {
                        continue;
                    }
                    findings.push(new finding_1.Finding({
                        severity: finding_1.FindingSeverity.medium,
                        confidence: finding_1.FindingConfidence.high,
                        category: finding_1.FindingCategory.config,
                        code: this.code,
                        message: 'Hardcoded Supabase URL is malformed',
                        fix: 'Replace the URL with a valid Supabase project URL or load it from environment config.',
                        risk: 'Malformed URLs will cause network requests to fail entirely, breaking app connectivity.',
                        filePath: file.relativePath,
                        line,
                    }));
                }
            }
        }
        return findings;
    }
    _looksValid(value) {
        try {
            const url = new URL(value);
            if (url.protocol !== 'https:') {
                return this._looksLikeLocalDevelopment(value);
            }
            return url.hostname.endsWith('.supabase.co') || this._looksLikeLocalDevelopment(value);
        }
        catch {
            return this._looksLikeLocalDevelopment(value);
        }
    }
    _looksLikeLocalDevelopment(value) {
        try {
            const url = new URL(value);
            const h = url.hostname;
            const localHosts = new Set(['localhost', '127.0.0.1', '0.0.0.0', '10.0.2.2', 'host.docker.internal', '::1']);
            if (localHosts.has(h)) {
                return true;
            }
            // Private IP ranges
            const octets = h.split('.').map(Number);
            if (octets.length !== 4 || octets.some(isNaN)) {
                return false;
            }
            const [a, b] = octets;
            return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
        }
        catch {
            return false;
        }
    }
}
exports.InvalidSupabaseUrlRule = InvalidSupabaseUrlRule;
