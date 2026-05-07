import * as fs from 'fs/promises';
import * as path from 'path';
import { ScannedFile, isTestLikePath } from './scannedFile';
import { normalizePath, basename, dirname, relativePath as makeRelative } from '../utils/pathUtils';
import type { SyntaxNode } from 'web-tree-sitter';
import { ParserContext } from '../ast/parser';

// ──────────────────────────────────────────────
// Supporting data classes
// ──────────────────────────────────────────────

export enum RlsEvidenceLevel { strong = 'strong', weak = 'weak', none = 'none' }

export interface EnvEntry {
  key: string;
  value: string;
  file: ScannedFile;
  line: number;
}

export interface TableAccess {
  table: string;
  operation: string;
  file: ScannedFile;
  line: number;
  snippet: string;
  localContext: string;
  hasOwnershipFilter: boolean;
  usesClientProvidedUserId: boolean;
  referencesCurrentUser: boolean;
}

export interface StorageBucketUse {
  bucketName: string;
  operation: string;
  file: ScannedFile;
  line: number;
  pathHasUserIdPattern: boolean;
  pathHasSensitiveContext: boolean;
}

export interface UploadCall {
  file: ScannedFile;
  line: number;
  hasTypeValidation: boolean;
  hasSizeValidation: boolean;
  hasValidationHelper: boolean;
}

export interface Location {
  file: ScannedFile;
  line: number;
}

// ──────────────────────────────────────────────
// Well-known table ownership columns
// ──────────────────────────────────────────────

export function ownerColumnsForTable(tableName: string): Set<string> {
  const normalized = tableName.toLowerCase();
  const mapping: Record<string, Set<string>> = {
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

export function suggestedPolicyForTable(tableName: string): string | null {
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
  '.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java'
]);

/** Default per-file byte cap. Files larger than this are skipped with a warning. */
export const DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB

/**
 * One file the loader chose not to read. Surfaced via
 * {@link ProjectContext.skippedFiles} so the scanner can warn about silently
 * missing coverage instead of pretending everything was scanned.
 */
export interface SkippedFile {
  relativePath: string;
  sizeBytes: number;
  reason: 'oversize';
}

export interface ProjectContextLoadOptions {
  /** Per-file size cap in bytes. Defaults to {@link DEFAULT_MAX_FILE_SIZE_BYTES}. */
  maxFileSizeBytes?: number;
}

export class ProjectContext {
  readonly rootPath: string;
  readonly files: ScannedFile[];
  /**
   * Files that were rejected by the loader (e.g. exceeded the size budget).
   * Empty on a clean scan; non-empty when the scanner had to skip something.
   * Surfaces in `ProjectScanReport.skippedFiles` so users notice gaps
   * instead of getting a silently-incomplete scan.
   */
  readonly skippedFiles: SkippedFile[];

  private _envEntries?: EnvEntry[];
  private _tableAccesses?: TableAccess[];
  private _storageBucketUses?: StorageBucketUse[];
  private _uploadCalls?: UploadCall[];
  private _supabaseClientLocations?: Location[];
  private _rlsEvidenceLevel?: RlsEvidenceLevel;

  constructor(rootPath: string, files: ScannedFile[], skippedFiles: SkippedFile[] = []) {
    this.rootPath = rootPath;
    this.files = files;
    this.skippedFiles = skippedFiles;
  }

  // ── Async Static loader ────────────────────────

  static async load(
    rootPath: string,
    onProgress?: (filesLoaded: number) => void,
    options: ProjectContextLoadOptions = {},
  ): Promise<ProjectContext> {
    const rootDir = normalizePath(path.resolve(rootPath));
    const files: ScannedFile[] = [];
    const skippedFiles: SkippedFile[] = [];
    const maxFileSizeBytes = Math.max(
      0,
      options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES,
    );

    // Throttle progress reports — calling vscode's progress.report() on every
    // single file is expensive on big monorepos. Every 50 files is plenty.
    const reportEvery = 50;
    const tickProgress = () => {
      if (onProgress && files.length % reportEvery === 0) {
        onProgress(files.length);
      }
    };

    // Read the root-level `.gitignore` (if any) once and turn it into a
    // matcher used during the walk. This honors patterns like `vendor/`,
    // `generated/**`, or `third_party/` so the scanner doesn't accidentally
    // analyze artifacts the user has explicitly told git to skip.
    //
    // We deliberately read only the *root* .gitignore. Per-directory
    // .gitignore stacking is a more involved feature that we can layer on
    // later — handling the common case is more impactful in less code.
    const rootGitignorePatterns = await ProjectContext._readGitignorePatterns(rootDir);

    async function walk(dir: string): Promise<void> {
      let entries: any[];
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        const relForCheck = makeRelative(rootDir, normalizePath(fullPath));
        if (entry.isDirectory()) {
          if (IGNORED_DIRECTORIES.has(entry.name)) { continue; }
          // Skip directories that the root gitignore covers.
          if (ProjectContext._gitignoreMatchesAnyPattern(relForCheck + '/', rootGitignorePatterns) ||
              ProjectContext._gitignoreMatchesAnyPattern(relForCheck, rootGitignorePatterns)) {
            continue;
          }
          await walk(fullPath);
        } else if (entry.isFile()) {
          const rel = makeRelative(rootDir, normalizePath(fullPath));
          if (!ProjectContext._shouldScan(rel)) { continue; }
          // Always keep .gitignore files in the scan (other rules need them);
          // we filter only non-gitignore artifacts from gitignore patterns.
          if (basename(rel) !== '.gitignore' &&
              ProjectContext._gitignoreMatchesAnyPattern(rel, rootGitignorePatterns)) {
            continue;
          }
          try {
            const stat = await fs.stat(fullPath);
            if (maxFileSizeBytes === 0 || stat.size <= maxFileSizeBytes) {
              const content = await ProjectContext._readTextFile(fullPath);
              files.push(new ScannedFile(normalizePath(fullPath), rel, content));
              tickProgress();
            } else {
              // Surface oversize files instead of silently dropping them. The
              // scanner aggregates these into the report so users see a
              // warning + count rather than wondering why a 5 MB minified
              // bundle produced no findings.
              skippedFiles.push({
                relativePath: rel,
                sizeBytes: stat.size,
                reason: 'oversize',
              });
            }
          } catch (e) {
            // Ignore unreadable files
          }
        }
      }
    }

    await walk(rootDir);
    if (onProgress) { onProgress(files.length); }   // final tick
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
    skippedFiles.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
    return new ProjectContext(rootDir, files, skippedFiles);
  }

  /**
   * Read the root `.gitignore` and split it into pattern entries. Comments
   * and blank lines are stripped. Negations (`!pattern`) are preserved so
   * negation-resolution mirrors git's last-match-wins behavior in
   * `_gitignoreMatchesAnyPattern`.
   */
  private static async _readGitignorePatterns(rootDir: string): Promise<string[]> {
    try {
      const content = await fs.readFile(path.join(rootDir, '.gitignore'), 'utf8');
      return content.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('#'));
    } catch {
      return [];
    }
  }

  /**
   * Apply gitignore patterns with last-match-wins semantics. Returns true if
   * the path should be EXCLUDED. Re-uses the project context's existing glob
   * matcher (`_globMatches`) — no third-party gitignore lib required.
   */
  private static _gitignoreMatchesAnyPattern(relPath: string, patterns: string[]): boolean {
    if (patterns.length === 0) { return false; }
    const target = normalizePath(relPath);
    let ignored = false;
    for (const raw of patterns) {
      const isNegated = raw.startsWith('!');
      let pattern = isNegated ? raw.substring(1) : raw;
      // Trailing slash means "directory only" — strip for matching purposes.
      const dirOnly = pattern.endsWith('/');
      if (dirOnly) { pattern = pattern.slice(0, -1); }
      const anchored = pattern.startsWith('/');
      if (anchored) { pattern = pattern.substring(1); }

      let matched = false;
      if (!pattern.includes('/')) {
        // Bare pattern (e.g. `*.log`, `vendor`) matches anywhere by basename.
        const candidate = anchored ? target : basename(target);
        matched = ProjectContext._globMatches(candidate, pattern);
      } else {
        // Path pattern — match the full relative path (anchored at root).
        matched = ProjectContext._globMatches(target, pattern);
      }
      if (matched) { ignored = !isNegated; }
    }
    return ignored;
  }

  // ── AST Resolution ────────────────────────────

  async getAst(file: ScannedFile): Promise<SyntaxNode | undefined> {
    if (file.astNode) return file.astNode;
    if (file.astStatus === 'failed') return undefined; // already attempted and failed

    // De-dupe concurrent first-time parses of the same file. Without this,
    // N rules running under Promise.all hit the slow path N times — they
    // all see `astNode === undefined`, all call parser.parse(), and the
    // last writer wins (waste, not corruption, but real perf cost).
    if (file.astPromise) { return file.astPromise; }

    const ext = file.extension;
    if (!ParserContext.isAstSupported(ext)) {
      file.astStatus = 'skipped';
      return undefined;
    }

    const promise = (async () => {
      const parser = await ParserContext.getParserForFile(file.absolutePath);
      if (!parser) {
        file.astStatus = 'failed';
        file.astError = `No parser available for ${ext}`;
        ParserContext.recordAttempt(false, ext, file.astError);
        return undefined;
      }

      try {
        const tree = parser.parse(file.content);
        if (!tree || !tree.rootNode) {
          file.astStatus = 'failed';
          file.astError = 'Parser returned null tree';
          ParserContext.recordAttempt(false, ext, file.astError);
          return undefined;
        }
        file.astNode = tree.rootNode;
        file.astStatus = 'ok';
        ParserContext.recordAttempt(true, ext);
        return file.astNode;
      } catch (e) {
        file.astStatus = 'failed';
        file.astError = `Parse error: ${(e as Error).message}`;
        ParserContext.recordAttempt(false, ext, file.astError);
        return undefined;
      } finally {
        // Clear the in-flight slot once settled so callers after this
        // point fall through to the cached `astNode` / failed status.
        file.astPromise = undefined;
      }
    })();
    file.astPromise = promise;
    return promise;
  }

  // ── File category getters ──────────────────────

  get dartFiles(): ScannedFile[] {
    return this.files.filter(f => f.isDart);
  }

  get appDartFiles(): ScannedFile[] {
    return this.dartFiles.filter(f => !isTestLikePath(f.relativePath));
  }

  get supabaseCandidateDartFiles(): ScannedFile[] {
    return this.appDartFiles.filter(f => this._looksLikeSupabaseFile(f));
  }

  get envFiles(): ScannedFile[] {
    return this.files.filter(f => f.isEnvFile);
  }

  get sqlFiles(): ScannedFile[] {
    return this.files.filter(f => f.isSql);
  }

  get markdownFiles(): ScannedFile[] {
    return this.files.filter(f => f.isMarkdown);
  }

  get yamlFiles(): ScannedFile[] {
    return this.files.filter(f => f.isYaml);
  }

  get pubspecFile(): ScannedFile | null {
    return this.files.find(f => f.relativePath === 'pubspec.yaml') ?? null;
  }

  // ── Supabase detection ─────────────────────────

  get usesSupabaseFlutter(): boolean {
    return this._fileContains(this.pubspecFile, /(?:^|\s)supabase_flutter\s*:/m) ||
      this._filesContain(this.appDartFiles, /package:supabase_flutter\/supabase_flutter\.dart/);
  }

  get usesSupabaseDart(): boolean {
    return this._fileContains(this.pubspecFile, /(?:^|\s)supabase\s*:/m) ||
      this._filesContain(this.appDartFiles, /package:supabase\/supabase\.dart/);
  }

  get usesSupabase(): boolean {
    return this.usesSupabaseFlutter || this.usesSupabaseDart ||
      this._filesContain(this.appDartFiles, SUPABASE_USAGE_PATTERN);
  }

  get usesDotenv(): boolean {
    return this._fileContains(this.pubspecFile, /(?:^|\s)flutter_dotenv\s*:/m) ||
      this._filesContain(this.appDartFiles, /dotenv\.env/);
  }

  get usesDartDefine(): boolean {
    return this._filesContain(this.appDartFiles, /String\.fromEnvironment\s*\(/);
  }

  get hasSupabaseInitialize(): boolean {
    return this._filesContain(this.appDartFiles, /Supabase\.initialize\s*\(/);
  }

  get hasEnvFile(): boolean {
    return this.envFiles.some(f => !f.isEnvTemplateFile);
  }

  get hasExampleEnvFile(): boolean {
    return this.envFiles.some(f => f.isEnvTemplateFile);
  }

  // ── Computed properties (lazy) ─────────────────

  get envEntries(): EnvEntry[] {
    if (!this._envEntries) { this._envEntries = this._computeEnvEntries(); }
    return this._envEntries;
  }

  get tableAccesses(): TableAccess[] {
    if (!this._tableAccesses) { this._tableAccesses = this._computeTableAccesses(); }
    return this._tableAccesses;
  }

  get storageBucketUses(): StorageBucketUse[] {
    if (!this._storageBucketUses) { this._storageBucketUses = this._computeStorageBucketUses(); }
    return this._storageBucketUses;
  }

  get uploadCalls(): UploadCall[] {
    if (!this._uploadCalls) { this._uploadCalls = this._computeUploadCalls(); }
    return this._uploadCalls;
  }

  get supabaseClientLocations(): Location[] {
    if (!this._supabaseClientLocations) { this._supabaseClientLocations = this._computeSupabaseClientLocations(); }
    return this._supabaseClientLocations;
  }

  get directSupabaseClientCount(): number {
    return this.supabaseClientLocations.length;
  }

  get hasRlsEvidence(): boolean {
    return this.rlsEvidenceLevel !== RlsEvidenceLevel.none;
  }

  get rlsEvidenceLevel(): RlsEvidenceLevel {
    if (!this._rlsEvidenceLevel) { this._rlsEvidenceLevel = this._computeRlsEvidenceLevel(); }
    return this._rlsEvidenceLevel;
  }

  // ── Gitignore checking ─────────────────────────

  gitignoreCoversEnvFile(envFilePath: string): boolean {
    const gitignoreFiles = this.files
      .filter(f => f.isGitIgnore)
      .sort((a, b) => {
        const da = ProjectContext._pathDepth(a.relativePath);
        const db = ProjectContext._pathDepth(b.relativePath);
        if (da !== db) { return da - db; }
        return a.relativePath.localeCompare(b.relativePath);
      });

    if (gitignoreFiles.length === 0) { return false; }

    let isIgnored = false;
    for (const file of gitignoreFiles) {
      const gitignoreDirectory = dirname(file.relativePath);
      for (const rawLine of file.lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) { continue; }
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

  private _computeEnvEntries(): EnvEntry[] {
    const entries: EnvEntry[] = [];
    const pattern = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/gm;
    for (const file of this.envFiles) {
      let match: RegExpExecArray | null;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(file.content)) !== null) {
        const value = match[2];
        if (value.startsWith('#')) { continue; }
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

  private _computeTableAccesses(): TableAccess[] {
    const accesses: TableAccess[] = [];
    const pattern = /\.from\(\s*['"]([a-zA-Z0-9_:-]+)['"]\s*\)/g;
    const operationPattern = /\.(select|insert|update|delete|upsert)\s*\(/gi;

    for (const file of this.supabaseCandidateDartFiles) {
      let match: RegExpExecArray | null;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(file.content)) !== null) {
        const prefixStart = Math.max(0, match.index - 30);
        const prefix = file.content.substring(prefixStart, match.index);
        if (prefix.includes('.storage')) { continue; }

        const snippet = ProjectContext._statementSnippet(file.content, match.index, 360);
        operationPattern.lastIndex = 0;
        const opMatch = operationPattern.exec(snippet);
        if (!opMatch) { continue; }

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

  private _computeStorageBucketUses(): StorageBucketUse[] {
    const buckets: StorageBucketUse[] = [];
    const pattern = /\.storage\s*\.from\(\s*['"]([a-zA-Z0-9_.-]+)['"]\s*\)/g;
    const opPattern = /\.(upload|uploadBinary|download|list|remove|getPublicUrl)\s*\(/gi;
    const userPathPattern = /\$(userId|uid)\b|\$\{[^}]*(\.id|uid)[^}]*\}|currentUser\.id|auth\.uid\(\)|user\.id\b|\buid\b/i;
    const sensitiveContextPattern = /avatar|profile|user|private/i;

    for (const file of this.appDartFiles) {
      let match: RegExpExecArray | null;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(file.content)) !== null) {
        const snippet = ProjectContext._statementSnippet(file.content, match.index, 320);
        opPattern.lastIndex = 0;
        const opMatch = opPattern.exec(snippet);

        let uploadPath: string | undefined;
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

  private _computeUploadCalls(): UploadCall[] {
    const uploads: UploadCall[] = [];
    const pattern = /\.upload(?:Binary)?\s*\(/g;

    const typeValidationPattern = /mime|contentType|lookupMimeType|allowedTypes|allowedExtensions|endsWith\(['"].+\.[a-z0-9]+['"]\)|fileType/i;
    const sizeValidationPattern1 = /(if|assert)\s*\([^)]*\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b[^)]*\)|\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size)\b[^;\n]{0,40}(<=|<|>=|>)|(?:<=|<|>=|>)[^;\n]{0,40}\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b/i;
    const sizeValidationPattern2a = /\b(?:file|image|video|media|byte|picked|asset|upload)[a-zA-Z0-9_]*\.(?:length\(\)|size\b)/i;
    const sizeValidationPattern2b = /\b(?:size|length)\b\s*(?:<=|<|>=|>)\s*\d+/i;
    const helperCallPattern = /\b(?:validate|verify|ensure|guard|check|sanitize|assert)(?:Valid)?[_A-Za-z0-9]*(?:upload|file|image|avatar|media|attachment)[_A-Za-z0-9]*\s*\(/i;

    for (const file of this.appDartFiles) {
      let match: RegExpExecArray | null;
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

  private _computeSupabaseClientLocations(): Location[] {
    const locations: Location[] = [];
    const pattern = /\bSupabaseClient\s*\(/g;
    for (const file of this.appDartFiles) {
      let match: RegExpExecArray | null;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(file.content)) !== null) {
        locations.push({ file, line: file.lineForOffset(match.index) });
      }
    }
    return locations;
  }

  private _computeRlsEvidenceLevel(): RlsEvidenceLevel {
    // Strong: actual DDL in SQL files
    for (const file of this.sqlFiles) {
      const codeOnly = ProjectContext._stripSqlComments(file.content);
      if (STRONG_RLS_PATTERN.test(codeOnly)) { return RlsEvidenceLevel.strong; }
    }

    // Weak in SQL
    for (const file of this.sqlFiles) {
      const codeOnly = ProjectContext._stripSqlComments(file.content);
      if (WEAK_RLS_PATTERN.test(codeOnly)) { return RlsEvidenceLevel.weak; }
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

  private static _shouldScan(rel: string): boolean {
    const name = basename(rel);
    if (name === '.gitignore' || name === '.env' || name.startsWith('.env.')) { return true; }
    const dotIndex = name.lastIndexOf('.');
    if (dotIndex === -1) { return false; }
    return SUPPORTED_EXTENSIONS.has(name.substring(dotIndex));
  }

  private static async _readTextFile(filePath: string): Promise<string> {
    try {
      return await fs.readFile(filePath, { encoding: 'utf8' });
    } catch {
      return '';
    }
  }

  private static _stripQuotes(value: string): string {
    if (value.length < 2) { return value; }
    const q = value[0];
    if ((q === '"' || q === "'") && value.endsWith(q)) {
      return value.substring(1, value.length - 1);
    }
    return value;
  }

  private static _snippetFrom(content: string, start: number, maxLength: number): string {
    const end = Math.min(content.length, start + maxLength);
    return content.substring(start, end);
  }

  private static _statementSnippet(content: string, start: number, maxLength: number): string {
    const raw = ProjectContext._snippetFrom(content, start, maxLength);
    const semi = raw.indexOf(';');
    return semi === -1 ? raw : raw.substring(0, semi + 1);
  }

  private static _hasOwnershipFilter(snippet: string, expectedColumns: Set<string>): boolean {
    for (const column of expectedColumns) {
      const pattern = new RegExp(`\\.(eq|match|filter|or)\\([^\\n;]{0,140}['"]${column}['"]`, 'i');
      if (pattern.test(snippet)) { return true; }
      const orStringPattern = new RegExp(`\\.or\\(\\s*['"][^'"]*\\b${column}\\.eq\\b`, 'i');
      if (orStringPattern.test(snippet)) { return true; }
    }
    return false;
  }

  private static _usesClientProvidedUserId(
    snippet: string,
    localContext: string,
    expectedColumns: Set<string>,
  ): boolean {
    const suspiciousValuePattern = `widget\\.(userId|profileId|ownerId)|args\\.(userId|profileId|ownerId)|route(?:Args|Parameters|Params)?\\.(userId|profileId|ownerId)|params\\[['\"](userId|profileId|ownerId)['\"]\\]|queryParameters\\[['\"](userId|profileId|ownerId)['\"]\\]|pathParameters\\[['\"](userId|profileId|ownerId)['\"]\\]|state\\.(extra|pathParameters|uri\\.queryParameters)[^,\\n;)]*(userId|profileId|ownerId)|request\\.[a-zA-Z0-9_]*(id|Id)\\b|selectedUserId|targetUserId|routeUserId|suppliedUserId|providedUserId|incomingUserId|passedUserId`;
    const variableNames = ['userId', 'profileId', 'ownerId', 'suppliedUserId', 'providedUserId', 'incomingUserId', 'passedUserId'];

    for (const column of expectedColumns) {
      const filterPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,120}['"]${column}['"][^\\n;]{0,160}${suspiciousValuePattern}`, 'i');
      if (filterPattern.test(snippet)) { return true; }

      const fallbackPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,160}\\?\\?\\s*(?:${suspiciousValuePattern}|userId|profileId|ownerId)\\b`, 'i');
      if (fallbackPattern.test(snippet)) { return true; }

      const assignmentPattern = new RegExp(`['"]${column}['"]\\s*:\\s*${suspiciousValuePattern}`, 'i');
      if (assignmentPattern.test(snippet)) { return true; }

      for (const variableName of variableNames) {
        const snippetVarPattern = new RegExp(`\\.(eq|match|filter)\\([^\\n;]{0,120}['"]${column}['"][^\\n;]{0,80}\\b${variableName}\\b`, 'i');
        if (!snippetVarPattern.test(snippet)) { continue; }

        const assignments = Array.from(localContext.matchAll(new RegExp(`\\b${variableName}\\b\\s*=\\s*([^\\n;]+)`, 'gi')));
        if (assignments.length === 0) { continue; }

        const latestValue = assignments[assignments.length - 1][1].trim();
        if (/currentUser|auth\.user|auth\.currentUser/i.test(latestValue)) { return false; }
        if (/widget\.|args\.|route|params\[|queryParameters\[|pathParameters\[|state\.|request\.|['"]/i.test(latestValue)) { return true; }
      }
    }
    return false;
  }

  private static _hasNearbyValidationHelperCall(
    file: ScannedFile,
    line: number,
    helperCallPattern: RegExp,
  ): boolean {
    const functionDefinitionPattern = /^\s*(?:[\w<>,?]+\s+)+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*(?:async\s*)?(?:\{|=>)/;
    const startLine = Math.max(1, line - 12);
    for (let i = startLine - 1; i < line; i++) {
      const lineText = file.lines[i].trimEnd();
      if (!helperCallPattern.test(lineText)) { continue; }
      if (functionDefinitionPattern.test(lineText.trimStart())) { continue; }
      return true;
    }
    return false;
  }

  private static _stripSqlComments(content: string): string {
    return content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/--.*$/gm, '');
  }

  private static _stripDartComments(content: string): string {
    return content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
  }

  private static _pathDepth(p: string): number {
    return normalizePath(p).split('/').filter(s => s.length > 0).length;
  }

  private _fileContains(file: ScannedFile | null, pattern: RegExp): boolean {
    if (!file) { return false; }
    return pattern.test(file.content);
  }

  private _filesContain(files: ScannedFile[], pattern: RegExp, stripDartComments = false): boolean {
    for (const file of files) {
      const content = stripDartComments ? ProjectContext._stripDartComments(file.content) : file.content;
      if (pattern.test(content)) { return true; }
    }
    return false;
  }

  private _looksLikeSupabaseFile(file: ScannedFile): boolean {
    return SUPABASE_USAGE_PATTERN.test(file.content);
  }

  private _gitignorePatternMatches(
    pattern: string,
    targetPath: string,
    gitignoreDirectory: string,
  ): boolean {
    let normalizedTarget = normalizePath(targetPath);
    let normalizedPattern = normalizePath(pattern);
    if (normalizedPattern.endsWith('/')) {
      normalizedPattern = normalizedPattern.slice(0, -1);
    }
    if (!normalizedPattern) { return false; }

    const anchoredToRoot = normalizedPattern.startsWith('/');
    if (anchoredToRoot) { normalizedPattern = normalizedPattern.substring(1); }

    if (!normalizedPattern.includes('/')) {
      if (!anchoredToRoot && gitignoreDirectory !== '.') {
        const prefix = `${gitignoreDirectory}/`;
        if (!normalizedTarget.startsWith(prefix)) { return false; }
      }
      const candidate = anchoredToRoot ? normalizedTarget : basename(normalizedTarget);
      return ProjectContext._globMatches(candidate, normalizedPattern);
    }

    let candidatePath: string;
    if (anchoredToRoot || gitignoreDirectory === '.') {
      candidatePath = normalizedTarget;
    } else {
      const prefix = `${gitignoreDirectory}/`;
      if (!normalizedTarget.startsWith(prefix)) { return false; }
      candidatePath = normalizedTarget.substring(prefix.length);
    }

    return ProjectContext._globMatches(candidatePath, normalizedPattern);
  }

  private static _globMatches(value: string, pattern: string): boolean {
    let regexStr = '^';
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i];
      if (ch === '*') {
        if (i + 1 < pattern.length && pattern[i + 1] === '*') {
          regexStr += '.*';
          i++;
        } else {
          regexStr += '[^/]*';
        }
      } else if (ch === '?') {
        regexStr += '[^/]';
      } else {
        regexStr += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      }
    }
    regexStr += '$';
    return new RegExp(regexStr).test(value);
  }
}

// ── Module-level regex constants ──────────────────

const SUPABASE_USAGE_PATTERN = /package:supabase(?:_flutter)?\/|\bSupabaseClient\b|\bSupabase\.(instance|initialize)\b|\bsupabase\.(from|storage|auth|rpc)\b|\.storage\.from\(|\.auth\.(currentUser|currentSession)\b/i;
const STRONG_RLS_PATTERN = /create\s+policy\b|enable\s+row\s+level\s+security\b/i;
const WEAK_RLS_PATTERN = /row\s+level\s+security|\brls\b|auth\.uid\(\)/i;
const AUTH_UID_PATTERN = /auth\.uid\(\)/i;
