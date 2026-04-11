"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Finding = exports.FindingConfidence = exports.FindingCategory = exports.FindingSeverity = void 0;
exports.severityLabel = severityLabel;
exports.severitySortOrder = severitySortOrder;
exports.categoryLabel = categoryLabel;
exports.confidenceLabel = confidenceLabel;
var FindingSeverity;
(function (FindingSeverity) {
    FindingSeverity["high"] = "high";
    FindingSeverity["medium"] = "medium";
    FindingSeverity["low"] = "low";
})(FindingSeverity || (exports.FindingSeverity = FindingSeverity = {}));
var FindingCategory;
(function (FindingCategory) {
    FindingCategory["security"] = "security";
    FindingCategory["config"] = "config";
    FindingCategory["supabase"] = "supabase";
    FindingCategory["suggestion"] = "suggestion";
})(FindingCategory || (exports.FindingCategory = FindingCategory = {}));
var FindingConfidence;
(function (FindingConfidence) {
    FindingConfidence["high"] = "high";
    FindingConfidence["medium"] = "medium";
    FindingConfidence["low"] = "low";
})(FindingConfidence || (exports.FindingConfidence = FindingConfidence = {}));
function severityLabel(s) {
    return s.toUpperCase();
}
function severitySortOrder(s) {
    switch (s) {
        case FindingSeverity.high: return 0;
        case FindingSeverity.medium: return 1;
        case FindingSeverity.low: return 2;
    }
}
function categoryLabel(c) {
    return c.toUpperCase();
}
function confidenceLabel(c) {
    return c.toUpperCase();
}
class Finding {
    constructor(opts) {
        this.severity = opts.severity;
        this.category = opts.category;
        this.confidence = opts.confidence;
        this.code = opts.code;
        this.message = opts.message;
        this.fix = opts.fix;
        this.risk = opts.risk;
        this.filePath = opts.filePath;
        this.line = opts.line;
    }
    get isSuggestion() {
        return this.category === FindingCategory.suggestion;
    }
    get locationLabel() {
        if (!this.filePath) {
            return '';
        }
        if (this.line == null) {
            return ` in ${this.filePath}`;
        }
        return ` in ${this.filePath}:${this.line}`;
    }
    toConsoleBlock() {
        const parts = [];
        if (this.isSuggestion) {
            parts.push(`[${categoryLabel(this.category)}]`);
        }
        else {
            parts.push(`[${severityLabel(this.severity)}][${categoryLabel(this.category)}]`);
            if (this.confidence != null) {
                parts.push(`[CONFIDENCE: ${confidenceLabel(this.confidence)}]`);
            }
        }
        parts.push(` ${this.message}${this.locationLabel}`);
        let result = parts.join('');
        result += `\n→ Fix: ${this.fix}`;
        if (this.risk) {
            result += `\n→ Risk: ${this.risk}`;
        }
        return result;
    }
}
exports.Finding = Finding;
