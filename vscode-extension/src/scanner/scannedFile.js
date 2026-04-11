"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScannedFile = void 0;
exports.isTestLikePath = isTestLikePath;
const pathUtils_1 = require("../utils/pathUtils");
class ScannedFile {
    constructor(absolutePath, relativePath, content) {
        this.absolutePath = absolutePath;
        this.relativePath = relativePath;
        this.content = content;
        this.lines = content.split('\n');
        this._lineOffsets = ScannedFile._buildLineOffsets(content);
    }
    get name() {
        return (0, pathUtils_1.basename)(this.relativePath);
    }
    get extension() {
        const fileName = this.name;
        const dotIndex = fileName.lastIndexOf('.');
        return dotIndex === -1 ? '' : fileName.substring(dotIndex);
    }
    get isDart() { return this.extension === '.dart'; }
    get isSql() { return this.extension === '.sql'; }
    get isMarkdown() { return this.extension === '.md'; }
    get isYaml() { return this.extension === '.yaml' || this.extension === '.yml'; }
    get isJson() { return this.extension === '.json'; }
    get isTxt() { return this.extension === '.txt'; }
    get isGitIgnore() { return this.name === '.gitignore'; }
    get isEnvFile() {
        return this.name === '.env' || this.name.startsWith('.env.');
    }
    get isEnvTemplateFile() {
        if (!this.isEnvFile) {
            return false;
        }
        const lower = this.name.toLowerCase();
        return lower.endsWith('.example') || lower.endsWith('.sample') ||
            lower.endsWith('.template') || lower.endsWith('.dist');
    }
    lineForOffset(offset) {
        let low = 0;
        let high = this._lineOffsets.length - 1;
        while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            const current = this._lineOffsets[mid];
            const next = mid + 1 < this._lineOffsets.length
                ? this._lineOffsets[mid + 1]
                : this.content.length + 1;
            if (offset >= current && offset < next) {
                return mid + 1;
            }
            if (offset < current) {
                high = mid - 1;
            }
            else {
                low = mid + 1;
            }
        }
        return 1;
    }
    contextAroundLine(line, before = 8, after = 4) {
        const start = Math.max(1, line - before);
        const end = Math.min(this.lines.length, line + after);
        return this.lines.slice(start - 1, end).join('\n');
    }
    static _buildLineOffsets(content) {
        const offsets = [0];
        for (let i = 0; i < content.length; i++) {
            if (content.charCodeAt(i) === 10) { // '\n'
                offsets.push(i + 1);
            }
        }
        return offsets;
    }
}
exports.ScannedFile = ScannedFile;
function isTestLikePath(path) {
    const n = (0, pathUtils_1.normalizePath)(path);
    return n.startsWith('test/') ||
        n.startsWith('integration_test/') ||
        n.startsWith('example/') ||
        n.includes('/test/') ||
        n.includes('/integration_test/') ||
        n.includes('/example/');
}
