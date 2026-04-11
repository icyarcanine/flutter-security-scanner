"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProjectContext = exports.RlsEvidenceLevel = void 0;
exports.ownerColumnsForTable = ownerColumnsForTable;
exports.suggestedPolicyForTable = suggestedPolicyForTable;
const fs = __importStar(require("fs/promises"));
const path = __importStar(require("path"));
const scannedFile_1 = require("./scannedFile");
const pathUtils_1 = require("../utils/pathUtils");
// ──────────────────────────────────────────────
// Supporting data classes
// ──────────────────────────────────────────────
var RlsEvidenceLevel;
(function (RlsEvidenceLevel) {
    RlsEvidenceLevel["strong"] = "strong";
    RlsEvidenceLevel["weak"] = "weak";
    RlsEvidenceLevel["none"] = "none";
})(RlsEvidenceLevel || (exports.RlsEvidenceLevel = RlsEvidenceLevel = {}));
// ──────────────────────────────────────────────
// Well-known table ownership columns
// ──────────────────────────────────────────────
function ownerColumnsForTable(tableName) {
    const normalized = tableName.toLowerCase();
    const mapping = {
        profiles: new Set(['id']),
        users: new Set(['id']),
        posts: new Set(['user_id']),
        messages: new Set(['sender_id', 'receiver_id']),
        todos: new Set(['user_id']),
        notes: new Set(['user_id']),
        orders: new Set(['user_id']),
        comments: new Set(['user_id']),
    };
    return mapping[normalized] ?? new Set();
}
function suggestedPolicyForTable(tableName) {
    const normalized = tableName.toLowerCase();
    switch (normalized) {
        case 'profiles':
        case 'users':
            return 'auth.uid() = id';
        case 'posts':
        case 'todos':
        case 'notes':
        case 'orders':
        case 'comments':
            return 'auth.uid() = user_id';
        case 'messages':
            return 'auth.uid() = sender_id OR auth.uid() = receiver_id';
        default:
            return null;
    }
}
// ──────────────────────────────────────────────
// ProjectContext
// ──────────────────────────────────────────────
const IGNORED_DIRECTORIES = new Set([
    '.dart_tool', '.git', '.idea', '.vscode',
    'build', 'coverage', 'dist', 'node_modules', 'Pods',
]);
const SUPPORTED_EXTENSIONS = new Set([
    '.dart', '.yaml', '.yml', '.sql', '.md', '.txt', '.json',
]);
class ProjectContext {
    constructor(rootPath, files) {
        this.rootPath = rootPath;
        this.files = files;
    }
    // ── Async Static loader ────────────────────────
    static async load(rootPath) {
        const rootDir = (0, pathUtils_1.normalizePath)(path.resolve(rootPath));
        const files = [];
        async function walk(dir) {
            let entries;
            try {
                entries = await fs.readdir(dir, { withFileTypes: true });
            }
            catch {
                return;
            }
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    if (!IGNORED_DIRECTORIES.has(entry.name)) {
                        await walk(fullPath);
                    }
                }
                else if (entry.isFile()) {
                    const rel = (0, pathUtils_1.relativePath)(rootDir, (0, pathUtils_1.normalizePath)(fullPath));
                    if (ProjectContext._shouldScan(rel)) {
                        const content = await ProjectContext._readTextFile(fullPath);
                        files.push(new scannedFile_1.ScannedFile((0, pathUtils_1.normalizePath)(fullPath), rel, content));
                    }
                }
            }
        }
        await walk(rootDir);
        files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
        return new ProjectContext(rootDir, files);
    }
    // ── File category getters ──────────────────────
    get dartFiles() {
        return this.files.filter(f => f.isDart);
    }
    get appDartFiles() {
        return this.dartFiles.filter(f => !(0, scannedFile_1.isTestLikePath)(f.relativePath));
    }
    get supabaseCandidateDartFiles() {
        return this.appDartFiles.filter(f => this._looksLikeSupabaseFile(f));
    }
    get envFiles() {
        return this.files.filter(f => f.isEnvFile);
    }
    get sqlFiles() {
        return this.files.filter(f => f.isSql);
    }
    get markdownFiles() {
        return this.files.filter(f => f.isMarkdown);
    }
    get yamlFiles() {
        return this.files.filter(f => f.isYaml);
    }
    get pubspecFile() {
        return this.files.find(f => f.relativePath === 'pubspec.yaml') ?? null;
    }
    // ── Supabase detection ─────────────────────────
    get usesSupabaseFlutter() {
        return this._fileContains(this.pubspecFile, /(?:^|\s)supabase_flutter\s*:/m) ||
            this._filesContain(this.appDartFiles, /package:supabase_flutter\/supabase_flutter\.dart/);
    }
    get usesSupabaseDart() {
        return this._fileContains(this.pubspecFile, /(?:^|\s)supabase\s*:/m) ||
            this._filesContain(this.appDartFiles, /package:supabase\/supabase\.dart/);
    }
    get usesSupabase() {
        return this.usesSupabaseFlutter || this.usesSupabaseDart ||
            this._filesContain(this.appDartFiles, SUPABASE_USAGE_PATTERN);
    }
    get usesDotenv() {
        return this._fileContains(this.pubspecFile, /(?:^|\s)flutter_dotenv\s*:/m) ||
            this._filesContain(this.appDartFiles, /dotenv\.env/);
    }
    get usesDartDefine() {
        return this._filesContain(this.appDartFiles, /String\.fromEnvironment\s*\(/);
    }
    get hasSupabaseInitialize() {
        return this._filesContain(this.appDartFiles, /Supabase\.initialize\s*\(/);
    }
    get hasEnvFile() {
        return this.envFiles.some(f => !f.isEnvTemplateFile);
    }
    get hasExampleEnvFile() {
        return this.envFiles.some(f => f.isEnvTemplateFile);
    }
    // ── Computed properties (lazy) ─────────────────
    get envEntries() {
        if (!this._envEntries) {
            this._envEntries = this._computeEnvEntries();
        }
        return this._envEntries;
    }
    get tableAccesses() {
        if (!this._tableAccesses) {
            this._tableAccesses = this._computeTableAccesses();
        }
        return this._tableAccesses;
    }
    get storageBucketUses() {
        if (!this._storageBucketUses) {
            this._storageBucketUses = this._computeStorageBucketUses();
        }
        return this._storageBucketUses;
    }
    get uploadCalls() {
        if (!this._uploadCalls) {
            this._uploadCalls = this._computeUploadCalls();
        }
        return this._uploadCalls;
    }
    get supabaseClientLocations() {
        if (!this._supabaseClientLocations) {
            this._supabaseClientLocations = this._computeSupabaseClientLocations();
        }
        return this._supabaseClientLocations;
    }
    get directSupabaseClientCount() {
        return this.supabaseClientLocations.length;
    }
    get hasRlsEvidence() {
        return this.rlsEvidenceLevel !== RlsEvidenceLevel.none;
    }
    get rlsEvidenceLevel() {
        if (!this._rlsEvidenceLevel) {
            this._rlsEvidenceLevel = this._computeRlsEvidenceLevel();
        }
        return this._rlsEvidenceLevel;
    }
    // ── Gitignore checking ─────────────────────────
    gitignoreCoversEnvFile(envFilePath) {
        const gitignoreFiles = this.files
            .filter(f => f.isGitIgnore)
            .sort((a, b) => {
            const da = ProjectContext._pathDepth(a.relativePath);
            const db = ProjectContext._pathDepth(b.relativePath);
            if (da !== db) {
                return da - db;
            }
            return a.relativePath.localeCompare(b.relativePath);
        });
        if (gitignoreFiles.length === 0) {
            return false;
        }
        let isIgnored = false;
        for (const file of gitignoreFiles) {
            const gitignoreDirectory = (0, pathUtils_1.dirname)(file.relativePath);
            for (const rawLine of file.lines) {
                const line = rawLine.trim();
                if (!line || line.startsWith('#')) {
                    continue;
                }
                const isNegated = line.startsWith('!');
                const pattern = isNegated ? line.substring(1) : line;
                if (this._gitignorePatternMatches(pattern, envFilePath, gitignoreDirectory)) {
                    isIgnored = !isNegated;
                }
            }
        }
        return isIgnored;
    }
    // ── Private computation methods ────────────────
    _computeEnvEntries() {
        const entries = [];
        const pattern = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/gm;
        for (const file of this.envFiles) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                const value = match[2];
                if (value.startsWith('#')) {
                    continue;
                }
                entries.push({
                    key: match[1],
                    value: ProjectContext._stripQuotes(value),
                    file,
                    line: file.lineForOffset(match.index),
                });
            }
        }
        return entries;
    }
    _computeTableAccesses() {
        const accesses = [];
        const pattern = /\.from\(\s*['"]([a-zA-Z0-9_:-]+)['"]\s*\)/g;
        const operationPattern = /\.(select|insert|update|delete|upsert)\s*\(/gi;
        for (const file of this.supabaseCandidateDartFiles) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                const prefixStart = Math.max(0, match.index - 30);
                const prefix = file.content.substring(prefixStart, match.index);
                if (prefix.includes('.storage')) {
                    continue;
                }
                const snippet = ProjectContext._statementSnippet(file.content, match.index, 360);
                operationPattern.lastIndex = 0;
                const opMatch = operationPattern.exec(snippet);
                if (!opMatch) {
                    continue;
                }
                const table = match[1];
                const line = file.lineForOffset(match.index);
                const expectedColumns = ownerColumnsForTable(table);
                const localContext = file.contextAroundLine(line, 40, 2);
                accesses.push({
                    table,
                    operation: opMatch[1].toLowerCase(),
                    file,
                    line,
                    snippet,
                    localContext,
                    hasOwnershipFilter: expectedColumns.size > 0 &&
                        ProjectContext._hasOwnershipFilter(snippet, expectedColumns),
                    usesClientProvidedUserId: expectedColumns.size > 0 &&
                        ProjectContext._usesClientProvidedUserId(snippet, localContext, expectedColumns),
                    referencesCurrentUser: /currentUser|auth\.user|auth\.currentUser/.test(snippet),
                });
            }
        }
        return accesses;
    }
    _computeStorageBucketUses() {
        const buckets = [];
        const pattern = /\.storage\s*\.from\(\s*['"]([a-zA-Z0-9_.-]+)['"]\s*\)/g;
        const opPattern = /\.(upload|uploadBinary|download|list|remove|getPublicUrl)\s*\(/gi;
        const userPathPattern = /\$(userId|uid)\b|\$\{[^}]*(\.id|uid)[^}]*\}|currentUser\.id|auth\.uid\(\)|user\.id\b|\buid\b/i;
        const sensitiveContextPattern = /avatar|profile|user|private/i;
        for (const file of this.appDartFiles) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                const snippet = ProjectContext._statementSnippet(file.content, match.index, 320);
                opPattern.lastIndex = 0;
                const opMatch = opPattern.exec(snippet);
                let uploadPath;
                if (opMatch) {
                    const afterOp = snippet.substring(opMatch.index + opMatch[0].length);
                    uploadPath = afterOp.length > 200 ? afterOp.substring(0, 200) : afterOp;
                }
                buckets.push({
                    bucketName: match[1],
                    operation: opMatch ? opMatch[1].toLowerCase() : 'access',
                    file,
                    line: file.lineForOffset(match.index),
                    pathHasUserIdPattern: uploadPath != null && userPathPattern.test(uploadPath),
                    pathHasSensitiveContext: uploadPath != null && sensitiveContextPattern.test(uploadPath),
                });
            }
        }
        return buckets;
    }
    _computeUploadCalls() {
        const uploads = [];
        const pattern = /\.upload(?:Binary)?\s*\(/g;
        const typeValidationPattern = /mime|contentType|lookupMimeType|allowedTypes|allowedExtensions|endsWith\(['"].+\.[a-z0-9]+['"]\)|fileType/i;
        const sizeValidationPattern1 = /(if|assert)\s*\([^)]*\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b[^)]*\)|\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size)\b[^;\n]{0,40}(<=|<|>=|>)|(?:<=|<|>=|>)[^;\n]{0,40}\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b/i;
        const sizeValidationPattern2a = /\b(?:file|image|video|media|byte|picked|asset|upload)[a-zA-Z0-9_]*\.(?:length\(\)|size\b)/i;
        const sizeValidationPattern2b = /\b(?:size|length)\b\s*(?:<=|<|>=|>)\s*\d+/i;
        const helperCallPattern = /\b(?:validate|verify|ensure|guard|check|sanitize|assert)(?:Valid)?[_A-Za-z0-9]*(?:upload|file|image|avatar|media|attachment)[_A-Za-z0-9]*\s*\(/i;
        for (const file of this.appDartFiles) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                const line = file.lineForOffset(match.index);
                const context = file.contextAroundLine(line, 12, 6);
                const hasSizeValidation = sizeValidationPattern1.test(context) ||
                    (sizeValidationPattern2a.test(context) && sizeValidationPattern2b.test(context));
                uploads.push({
                    file,
                    line,
                    hasTypeValidation: typeValidationPattern.test(context),
                    hasSizeValidation,
                    hasValidationHelper: ProjectContext._hasNearbyValidationHelperCall(file, line, helperCallPattern),
                });
            }
        }
        return uploads;
    }
    _computeSupabaseClientLocations() {
        const locations = [];
        const pattern = /\bSupabaseClient\s*\(/g;
        for (const file of this.appDartFiles) {
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(file.content)) !== null) {
                locations.push({ file, line: file.lineForOffset(match.index) });
            }
        }
        return locations;
    }
    _computeRlsEvidenceLevel() {
        // Strong: actual DDL in SQL files
        for (const file of this.sqlFiles) {
            const codeOnly = ProjectContext._stripSqlComments(file.content);
            if (STRONG_RLS_PATTERN.test(codeOnly)) {
                return RlsEvidenceLevel.strong;
            }
        }
        // Weak in SQL
        for (const file of this.sqlFiles) {
            const codeOnly = ProjectContext._stripSqlComments(file.content);
            if (WEAK_RLS_PATTERN.test(codeOnly)) {
                return RlsEvidenceLevel.weak;
            }
        }
        // auth.uid() in Dart source → strong
        if (this._filesContain(this.appDartFiles, AUTH_UID_PATTERN, true)) {
            return RlsEvidenceLevel.strong;
        }
        // Weak textual mention
        if (this._filesContain(this.appDartFiles, WEAK_RLS_PATTERN) ||
            this._filesContain(this.markdownFiles, WEAK_RLS_PATTERN)) {
            return RlsEvidenceLevel.weak;
        }
        return RlsEvidenceLevel.none;
    }
    // ── Static helpers ─────────────────────────────
    static _shouldScan(rel) {
        const name = (0, pathUtils_1.basename)(rel);
        if (name === '.gitignore' || name === '.env' || name.startsWith('.env.')) {
            return true;
        }
        const dotIndex = name.lastIndexOf('.');
        if (dotIndex === -1) {
            return false;
        }
        return SUPPORTED_EXTENSIONS.has(name.substring(dotIndex));
    }
    static async _readTextFile(filePath) {
        try {
            return await fs.readFile(filePath, { encoding: 'utf8' });
        }
        catch {
            return '';
        }
    }
    static _stripQuotes(value) {
        if (value.length < 2) {
            return value;
        }
        const q = value[0];
        if ((q === '"' || q === "'") && value.endsWith(q)) {
            return value.substring(1, value.length - 1);
        }
        return value;
    }
    static _snippetFrom(content, start, maxLength) {
        const end = Math.min(content.length, start + maxLength);
        return content.substring(start, end);
    }
    static _statementSnippet(content, start, maxLength) {
        const raw = ProjectContext._snippetFrom(content, start, maxLength);
        const semi = raw.indexOf(';');
        return semi === -1 ? raw : raw.substring(0, semi + 1);
    }
    static _hasOwnershipFilter(snippet, expectedColumns) {
        for (const column of expectedColumns) {
            const pattern = new RegExp(`\\.(eq|match|filter|or)\\([^\\n;]{0,140}['"]${column}['"]`, 'i');
            if (pattern.test(snippet)) {
                return true;
            }
            const orStringPattern = new RegExp(`\\.or\\(\\s*['"][^'"]*\\b${column}\\.eq\\b`, 'i');
            if (orStringPattern.test(snippet)) {
                return true;
            }
        }
        return false;
    }
    static _usesClientProvidedUserId(snippet, localContext, expectedColumns) {
        const suspiciousValuePattern = `widget\\.(userId|profileId|ownerId)|args\\.(userId|profileId|ownerId)|route(?:Args|Parameters|Params)?\\.(userId|profileId|ownerId)|params\\[['\"](userId|profileId|ownerId)['\"]\\]|queryParameters\\[['\"](userId|profileId|ownerId)['\"]\\]|pathParameters\\[['\"](userId|profileId|ownerId)['\"]\\]|state\\.(extra|pathParameters|uri\\.queryParameters)[^,\\n;)]*(userId|profileId|ownerId)|request\\.[a-zA-Z0-9_]*(id|Id)\\b|selectedUserId|targetUserId|routeUserId|suppliedUserId|providedUserId|incomingUserId|passedUserId`;
        const variableNames = ['userId', 'profileId', 'ownerId', 'suppliedUserId', 'providedUserId', 'incomingUserId', 'passedUserId'];
        for (const column of expectedColumns) {
            const filterPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,120}['"]${column}['"][^\\n;]{0,160}${suspiciousValuePattern}`, 'i');
            if (filterPattern.test(snippet)) {
                return true;
            }
            const fallbackPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,160}\\?\\?\\s*(?:${suspiciousValuePattern}|userId|profileId|ownerId)\\b`, 'i');
            if (fallbackPattern.test(snippet)) {
                return true;
            }
            const assignmentPattern = new RegExp(`['"]${column}['"]\\s*:\\s*${suspiciousValuePattern}`, 'i');
            if (assignmentPattern.test(snippet)) {
                return true;
            }
            for (const variableName of variableNames) {
                const snippetVarPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,120}['"]${column}['"][^\\n;]{0,80}\\b${variableName}\\b`, 'i');
                if (!snippetVarPattern.test(snippet)) {
                    continue;
                }
                const assignments = Array.from(localContext.matchAll(new RegExp(`\\b${variableName}\\b\\s*=\\s*([^\\n;]+)`, 'gi')));
                if (assignments.length === 0) {
                    continue;
                }
                const latestValue = assignments[assignments.length - 1][1].trim();
                if (/currentUser|auth\.user|auth\.currentUser/i.test(latestValue)) {
                    return false;
                }
                if (/widget\.|args\.|route|params\[|queryParameters\[|pathParameters\[|state\.|request\.|['"]/i.test(latestValue)) {
                    return true;
                }
            }
        }
        return false;
    }
    static _hasNearbyValidationHelperCall(file, line, helperCallPattern) {
        const functionDefinitionPattern = /^\s*(?:[\w<>,?]+\s+)+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*(?:async\s*)?(?:\{|=>)/;
        const startLine = Math.max(1, line - 12);
        for (let i = startLine - 1; i < line; i++) {
            const lineText = file.lines[i].trimEnd();
            if (!helperCallPattern.test(lineText)) {
                continue;
            }
            if (functionDefinitionPattern.test(lineText.trimStart())) {
                continue;
            }
            return true;
        }
        return false;
    }
    static _stripSqlComments(content) {
        return content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/--.*$/gm, '');
    }
    static _stripDartComments(content) {
        return content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
    }
    static _pathDepth(p) {
        return (0, pathUtils_1.normalizePath)(p).split('/').filter(s => s.length > 0).length;
    }
    _fileContains(file, pattern) {
        if (!file) {
            return false;
        }
        return pattern.test(file.content);
    }
    _filesContain(files, pattern, stripDartComments = false) {
        for (const file of files) {
            const content = stripDartComments ? ProjectContext._stripDartComments(file.content) : file.content;
            if (pattern.test(content)) {
                return true;
            }
        }
        return false;
    }
    _looksLikeSupabaseFile(file) {
        return SUPABASE_USAGE_PATTERN.test(file.content);
    }
    _gitignorePatternMatches(pattern, targetPath, gitignoreDirectory) {
        let normalizedTarget = (0, pathUtils_1.normalizePath)(targetPath);
        let normalizedPattern = (0, pathUtils_1.normalizePath)(pattern);
        if (normalizedPattern.endsWith('/')) {
            normalizedPattern = normalizedPattern.slice(0, -1);
        }
        if (!normalizedPattern) {
            return false;
        }
        const anchoredToRoot = normalizedPattern.startsWith('/');
        if (anchoredToRoot) {
            normalizedPattern = normalizedPattern.substring(1);
        }
        if (!normalizedPattern.includes('/')) {
            if (!anchoredToRoot && gitignoreDirectory !== '.') {
                const prefix = `${gitignoreDirectory}/`;
                if (!normalizedTarget.startsWith(prefix)) {
                    return false;
                }
            }
            const candidate = anchoredToRoot ? normalizedTarget : (0, pathUtils_1.basename)(normalizedTarget);
            return ProjectContext._globMatches(candidate, normalizedPattern);
        }
        let candidatePath;
        if (anchoredToRoot || gitignoreDirectory === '.') {
            candidatePath = normalizedTarget;
        }
        else {
            const prefix = `${gitignoreDirectory}/`;
            if (!normalizedTarget.startsWith(prefix)) {
                return false;
            }
            candidatePath = normalizedTarget.substring(prefix.length);
        }
        return ProjectContext._globMatches(candidatePath, normalizedPattern);
    }
    static _globMatches(value, pattern) {
        let regexStr = '^';
        for (let i = 0; i < pattern.length; i++) {
            const ch = pattern[i];
            if (ch === '*') {
                if (i + 1 < pattern.length && pattern[i + 1] === '*') {
                    regexStr += '.*';
                    i++;
                }
                else {
                    regexStr += '[^/]*';
                }
            }
            else if (ch === '?') {
                regexStr += '[^/]';
            }
            else {
                regexStr += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
            }
        }
        regexStr += '$';
        return new RegExp(regexStr).test(value);
    }
}
exports.ProjectContext = ProjectContext;
// ── Module-level regex constants ──────────────────
const SUPABASE_USAGE_PATTERN = /package:supabase(?:_flutter)?\/|\bSupabaseClient\b|\bSupabase\.(instance|initialize)\b|\bsupabase\.(from|storage|auth|rpc)\b|\.storage\.from\(|\.auth\.(currentUser|currentSession)\b/i;
const STRONG_RLS_PATTERN = /create\s+policy\b|enable\s+row\s+level\s+security\b/i;
const WEAK_RLS_PATTERN = /row\s+level\s+security|\brls\b|auth\.uid\(\)/i;
const AUTH_UID_PATTERN = /auth\.uid\(\)/i;
