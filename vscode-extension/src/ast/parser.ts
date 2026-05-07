import * as path from 'path';

const WebTreeSitter = require('web-tree-sitter');

/** Global AST diagnostics that aggregate across an entire scan session. */
export interface AstDiagnostics {
  attempted: number;
  succeeded: number;
  failed: number;
  failuresByLanguage: Record<string, number>;
  failureReasons: string[];
}

export class ParserContext {
  private static readonly parserCache: Map<string, any> = new Map();
  /**
   * In-flight Language.load() promises keyed by grammar cacheKey. When two
   * concurrent rules ask for the same language at the same time (which
   * happens routinely under the F34 `Promise.all` rule scheduler) we
   * de-dupe to a single WASM load. Without this, identical work happens
   * N times where N = concurrent rules touching that file extension.
   */
  private static readonly inFlightLoads: Map<string, Promise<any | null>> = new Map();
  private static isInitialized = false;
  private static initPromise: Promise<void> | null = null;
  private static initFailed = false;
  private static readonly warnedLanguages = new Set<string>();

  /** Per-scan diagnostics — call resetDiagnostics() at scan start. */
  private static _diagnostics: AstDiagnostics = ParserContext._emptyDiagnostics();

  public static resetDiagnostics(): void {
    ParserContext._diagnostics = ParserContext._emptyDiagnostics();
  }

  public static get diagnostics(): Readonly<AstDiagnostics> {
    return ParserContext._diagnostics;
  }

  public static get astSuccessRate(): number {
    const total = ParserContext._diagnostics.attempted;
    if (total === 0) return 100;
    return Math.round((ParserContext._diagnostics.succeeded / total) * 100);
  }

  /**
   * Returns a cached parser for the given file extension, or null if:
   *   - extension has no WASM grammar
   *   - grammar previously failed to load (cached as null)
   *
   * Throws ONLY if Parser.init() itself fails (critical global failure).
   */
  public static async getParserForFile(filePath: string): Promise<any | null> {
    const ext = path.extname(filePath).toLowerCase();
    const grammar = ParserContext.getGrammarForExtension(ext);

    if (!grammar) {
      return null; // not an AST-supported extension, silently skip (not a failure)
    }

    // Critical global init — crash hard if this fails since nothing else can work.
    // Concurrent callers must share the SAME init promise (otherwise
    // WebTreeSitter.init() runs N times, which the underlying WASM module
    // handles inconsistently across versions).
    if (!ParserContext.isInitialized && !ParserContext.initFailed) {
      if (!ParserContext.initPromise) {
        ParserContext.initPromise = WebTreeSitter.init().then(
          () => { ParserContext.isInitialized = true; },
          (e: unknown) => {
            ParserContext.initFailed = true;
            throw new Error(`[SAST] CRITICAL: Parser.init() failed globally: ${(e as Error).message}`);
          },
        );
      }
      try {
        await ParserContext.initPromise;
      } catch (e) {
        // initPromise has already set initFailed; rethrow so the first
        // caller sees the failure.
        throw e;
      }
    }
    if (ParserContext.initFailed) {
      return null;
    }

    // Cached result (including cached null = previously failed language).
    if (ParserContext.parserCache.has(grammar.cacheKey)) {
      return ParserContext.parserCache.get(grammar.cacheKey) ?? null;
    }

    // De-dupe concurrent first-time loads of the same grammar.
    const existingLoad = ParserContext.inFlightLoads.get(grammar.cacheKey);
    if (existingLoad) {
      return existingLoad;
    }

    const loadPromise: Promise<any | null> = (async () => {
      try {
        const language = await WebTreeSitter.Language.load(grammar.wasmPath);
        const parser = new WebTreeSitter();
        parser.setLanguage(language);
        ParserContext.parserCache.set(grammar.cacheKey, parser);
        return parser;
      } catch (e) {
        const lang = grammar.language;
        const reason = `Failed to load WASM grammar ${grammar.cacheKey}: ${(e as Error).message}`;
        // Log once per language to avoid spam.
        if (!ParserContext.warnedLanguages.has(lang)) {
          console.error(`[SAST] AST unavailable for ${lang} – using regex fallback. (${reason})`);
          ParserContext.warnedLanguages.add(lang);
        }
        // Cache the failure so we don't retry on every file.
        ParserContext.parserCache.set(grammar.cacheKey, null);
        return null;
      } finally {
        ParserContext.inFlightLoads.delete(grammar.cacheKey);
      }
    })();
    ParserContext.inFlightLoads.set(grammar.cacheKey, loadPromise);
    return loadPromise;
  }

  /**
   * Record an AST parse attempt outcome for diagnostics.
   */
  public static recordAttempt(success: boolean, ext: string, error?: string): void {
    ParserContext._diagnostics.attempted++;
    if (success) {
      ParserContext._diagnostics.succeeded++;
    } else {
      ParserContext._diagnostics.failed++;
      const lang = ext.replace('.', '');
      ParserContext._diagnostics.failuresByLanguage[lang] =
        (ParserContext._diagnostics.failuresByLanguage[lang] || 0) + 1;
      if (error) {
        ParserContext._diagnostics.failureReasons.push(error);
      }
    }
  }

  private static getGrammarForExtension(ext: string): { cacheKey: string; language: string; wasmPath: string } | null {
    switch (ext) {
      case '.js': return ParserContext._treeSitterWasmsGrammar('javascript', 'tree-sitter-javascript.wasm');
      case '.jsx': return ParserContext._treeSitterWasmsGrammar('javascript', 'tree-sitter-javascript.wasm');
      case '.ts': return ParserContext._treeSitterWasmsGrammar('typescript', 'tree-sitter-typescript.wasm');
      case '.tsx': return ParserContext._treeSitterWasmsGrammar('tsx', 'tree-sitter-tsx.wasm');
      case '.py': return ParserContext._treeSitterWasmsGrammar('python', 'tree-sitter-python.wasm');
      case '.go': return ParserContext._treeSitterWasmsGrammar('go', 'tree-sitter-go.wasm');
      case '.java': return ParserContext._treeSitterWasmsGrammar('java', 'tree-sitter-java.wasm');
      case '.dart':
        return {
          cacheKey: 'tree-sitter-dart/tree-sitter-dart.wasm',
          language: 'dart',
          wasmPath: require.resolve('tree-sitter-dart/tree-sitter-dart.wasm'),
        };
      default: return null;
    }
  }

  /** Whether the given extension has a WASM grammar registered. */
  public static isAstSupported(ext: string): boolean {
    return ParserContext.getGrammarForExtension(ext.startsWith('.') ? ext : `.${ext}`) !== null;
  }

  private static _emptyDiagnostics(): AstDiagnostics {
    return { attempted: 0, succeeded: 0, failed: 0, failuresByLanguage: {}, failureReasons: [] };
  }

  private static _treeSitterWasmsGrammar(language: string, wasmName: string): { cacheKey: string; language: string; wasmPath: string } {
    return {
      cacheKey: wasmName,
      language,
      wasmPath: require.resolve(`tree-sitter-wasms/out/${wasmName}`),
    };
  }
}
