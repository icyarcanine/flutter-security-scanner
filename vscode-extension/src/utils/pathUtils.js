"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizePath = normalizePath;
exports.basename = basename;
exports.dirname = dirname;
exports.relativePath = relativePath;
function normalizePath(p) {
    return p.replace(/\\/g, '/');
}
function basename(p) {
    const normalized = normalizePath(p);
    const idx = normalized.lastIndexOf('/');
    return idx === -1 ? normalized : normalized.substring(idx + 1);
}
function dirname(p) {
    const normalized = normalizePath(p);
    const idx = normalized.lastIndexOf('/');
    if (idx === -1) {
        return '.';
    }
    if (idx === 0) {
        return '/';
    }
    return normalized.substring(0, idx);
}
function relativePath(rootPath, fullPath) {
    const normalizedRoot = normalizePath(rootPath).replace(/\/$/, '');
    const normalizedFull = normalizePath(fullPath);
    if (normalizedFull === normalizedRoot) {
        return '.';
    }
    const prefix = `${normalizedRoot}/`;
    if (normalizedFull.startsWith(prefix)) {
        return normalizedFull.substring(prefix.length);
    }
    return normalizedFull;
}
