"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PlaceholderEnvValuesRule = void 0;
const finding_1 = require("../../models/finding");
const SENSITIVE_KEYS = new Set(['SUPABASE_URL', 'SUPABASE_ANON_KEY']);
class PlaceholderEnvValuesRule {
    constructor() {
        this.code = 'placeholder-env-value';
    }
    evaluate(context) {
        if (!context.usesSupabase) {
            return [];
        }
        const findings = [];
        for (const entry of context.envEntries) {
            if (!SENSITIVE_KEYS.has(entry.key)) {
                continue;
            }
            if (entry.file.isEnvTemplateFile) {
                continue;
            }
            if (!this._looksLikePlaceholder(entry.value)) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.low,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.config,
                code: this.code,
                message: `${entry.key} appears to be a placeholder value in ${entry.file.name}`,
                fix: 'Replace the placeholder with the real value from your Supabase project settings before running the app.',
                risk: 'Using placeholder configuration values will cause network requests or authentication to fail.',
                filePath: entry.file.relativePath,
                line: entry.line,
            }));
        }
        return findings;
    }
    _looksLikePlaceholder(value) {
        if (!value) {
            return true;
        }
        const normalized = value.toLowerCase().trim();
        if (['changeme', 'change_me', 'replace_me', 'replace-me', 'todo',
            'your_key_here', 'your-key-here', 'your_url_here', 'your-url-here'].includes(normalized)) {
            return true;
        }
        if (/^<[^>]+>$/.test(value.trim())) {
            return true;
        }
        if (/^[A-Z][A-Z0-9_]+$/.test(value.trim())) {
            return true;
        }
        return normalized.includes('your-') || normalized.includes('your_') ||
            normalized.includes('placeholder') || normalized.includes('example') ||
            normalized.includes('xxx');
    }
}
exports.PlaceholderEnvValuesRule = PlaceholderEnvValuesRule;
