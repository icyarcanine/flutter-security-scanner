"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HardcodedSecretsRule = void 0;
const finding_1 = require("../../models/finding");
const ruleHelpers_1 = require("../ruleHelpers");
class HardcodedSecretsRule {
    constructor() {
        this.code = 'hardcoded-secrets';
    }
    evaluate(context) {
        const findings = [];
        for (const file of context.appDartFiles) {
            findings.push(...this._findHardcodedAnonKeys(file));
            findings.push(...this._findHardcodedUrls(file));
        }
        for (const file of context.yamlFiles) {
            if (this._isToolOrLockFile(file)) {
                continue;
            }
            findings.push(...this._findHardcodedUrlsInYaml(file));
        }
        return findings;
    }
    _findHardcodedAnonKeys(file) {
        const findings = [];
        const patterns = [
            /anonKey\s*:\s*['"]([^'"]{20,})['"]\s/g,
            /SUPABASE_ANON_KEY\s*[:=]\s*['"]([^'"]{20,})['"]/g,
            /\bSupabaseClient\s*\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]{20,})['"]/g,
            /supabaseAnonKey\s*[:=]\s*['"]([^'"]{20,})['"]/g,
            /supabaseKey\s*[:=]\s*['"]([^'"]{20,})['"]/g,
        ];
        const seenLines = new Set();
        for (const pattern of patterns) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                const literal = match[match.length - 1];
                if (this._looksLikePlaceholder(literal)) {
                    continue;
                }
                const line = file.lineForOffset(match.index);
                if (seenLines.has(line)) {
                    continue;
                }
                seenLines.add(line);
                if ((0, ruleHelpers_1.isCommentLine)(file.lines[line - 1])) {
                    continue;
                }
                findings.push(new finding_1.Finding({
                    severity: finding_1.FindingSeverity.high,
                    confidence: finding_1.FindingConfidence.high,
                    category: finding_1.FindingCategory.security,
                    code: this.code,
                    message: 'Hardcoded Supabase anon key detected',
                    fix: 'Move the anon key into environment-backed config and load it at startup instead of committing it to Dart code.',
                    risk: 'Hardcoded credentials cannot be rotated easily and expose your Supabase project to unintended access.',
                    filePath: file.relativePath,
                    line,
                }));
            }
        }
        return findings;
    }
    _findHardcodedUrls(file) {
        const findings = [];
        const pattern = /['"]https:\/\/([a-zA-Z0-9-]+)\.supabase\.co[^'"]*['"]/g;
        let match;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(file.content)) !== null) {
            const subdomain = match[1].toLowerCase();
            if (subdomain === 'docs' || subdomain === 'supabase' || subdomain === 'api') {
                continue;
            }
            const url = match[0].replace(/^['"]|['"]$/g, '');
            if (this._looksLikePlaceholder(url)) {
                continue;
            }
            const line = file.lineForOffset(match.index);
            if ((0, ruleHelpers_1.isCommentLine)(file.lines[line - 1])) {
                continue;
            }
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.security,
                code: this.code,
                message: 'Hardcoded Supabase URL detected',
                fix: 'Move the Supabase project URL into environment-backed config so it is not copied across source files.',
                risk: 'Hardcoded URLs make it difficult to switch between development and production environments without modifying code.',
                filePath: file.relativePath,
                line,
            }));
        }
        return findings;
    }
    _findHardcodedUrlsInYaml(file) {
        const findings = [];
        const pattern = /:\s*['"]?(https:\/\/([a-zA-Z0-9-]+)\.supabase\.co[^'"\s]*)['"]?/g;
        let match;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(file.content)) !== null) {
            const subdomain = match[2].toLowerCase();
            if (subdomain === 'docs' || subdomain === 'supabase' || subdomain === 'api') {
                continue;
            }
            const url = match[1];
            if (this._looksLikePlaceholder(url)) {
                continue;
            }
            const line = file.lineForOffset(match.index);
            findings.push(new finding_1.Finding({
                severity: finding_1.FindingSeverity.medium,
                confidence: finding_1.FindingConfidence.high,
                category: finding_1.FindingCategory.security,
                code: this.code,
                message: 'Hardcoded Supabase URL detected in YAML config',
                fix: 'Move the Supabase project URL into environment-backed config rather than embedding it in a checked-in YAML file.',
                risk: 'Hardcoded URLs make it difficult to switch between development and production environments.',
                filePath: file.relativePath,
                line,
            }));
        }
        return findings;
    }
    _looksLikePlaceholder(value) {
        const normalized = value.toLowerCase();
        if (normalized.includes('your-') || normalized.includes('your_') ||
            normalized.includes('replace-me') || normalized.includes('replace_me') ||
            normalized.includes('example') || normalized.includes('placeholder') ||
            normalized.includes('changeme') || normalized.includes('change_me') ||
            normalized.includes('xxx') || normalized.includes('todo')) {
            return true;
        }
        if (/^<[^>]+>$/.test(value.trim())) {
            return true;
        }
        if (/^[A-Z][A-Z0-9_]+$/.test(value.trim())) {
            return true;
        }
        return false;
    }
    _isToolOrLockFile(file) {
        const name = file.name.toLowerCase();
        return name === 'pubspec.yaml' || name === 'pubspec.lock' ||
            name === 'analysis_options.yaml' || name.endsWith('.lock');
    }
}
exports.HardcodedSecretsRule = HardcodedSecretsRule;
