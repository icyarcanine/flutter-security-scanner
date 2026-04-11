"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProjectScanner = exports.ProjectScanReport = void 0;
const finding_1 = require("../models/finding");
const projectContext_1 = require("./projectContext");
const index_1 = require("../rules/index");
class ProjectScanReport {
    constructor(context, findings) {
        this.context = context;
        this.findings = findings;
    }
    get issueCount() {
        return this.findings.filter(f => !f.isSuggestion).length;
    }
    get suggestionCount() {
        return this.findings.filter(f => f.isSuggestion).length;
    }
    get highCount() {
        return this.findings.filter(f => f.severity === finding_1.FindingSeverity.high).length;
    }
    get mediumCount() {
        return this.findings.filter(f => f.severity === finding_1.FindingSeverity.medium).length;
    }
    get lowCount() {
        return this.findings.filter(f => f.severity === finding_1.FindingSeverity.low).length;
    }
}
exports.ProjectScanReport = ProjectScanReport;
class ProjectScanner {
    constructor(includeSuggestions = true) {
        this.includeSuggestions = includeSuggestions;
    }
    async scan(rootPath) {
        const context = await projectContext_1.ProjectContext.load(rootPath);
        const findings = [];
        for (const rule of (0, index_1.buildDefaultRules)(this.includeSuggestions)) {
            findings.push(...rule.evaluate(context));
        }
        const deduped = ProjectScanner._dedupe(findings);
        deduped.sort(ProjectScanner._compareFindings);
        return new ProjectScanReport(context, deduped);
    }
    static _compareFindings(a, b) {
        if (a.isSuggestion !== b.isSuggestion) {
            return a.isSuggestion ? 1 : -1;
        }
        const sevA = a.severity != null ? (0, finding_1.severitySortOrder)(a.severity) : 3;
        const sevB = b.severity != null ? (0, finding_1.severitySortOrder)(b.severity) : 3;
        if (sevA !== sevB) {
            return sevA - sevB;
        }
        const fileCompare = (a.filePath ?? '').localeCompare(b.filePath ?? '');
        if (fileCompare !== 0) {
            return fileCompare;
        }
        const lineCompare = (a.line ?? 0) - (b.line ?? 0);
        if (lineCompare !== 0) {
            return lineCompare;
        }
        return a.message.localeCompare(b.message);
    }
    static _dedupe(findings) {
        const seen = new Set();
        const result = [];
        for (const f of findings) {
            const key = [f.code, f.filePath ?? '', f.line?.toString() ?? '', f.message].join('|');
            if (!seen.has(key)) {
                seen.add(key);
                result.push(f);
            }
        }
        return result;
    }
}
exports.ProjectScanner = ProjectScanner;
