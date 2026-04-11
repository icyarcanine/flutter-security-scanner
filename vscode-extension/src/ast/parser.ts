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
  private static isInitialized = false;
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

    // Critical global init — crash hard if this fails since nothing else can work
    if (!ParserContext.isInitialized && !ParserContext.initFailed) {
      try {
        await WebTreeSitter.init();
        ParserContext.isInitialized = true;
      } catch (e) {
        ParserContext.initFailed = true;
        throw new Error(`[SAST] CRITICAL: Parser.init() failed globally: ${(e as Error).message}`);
      }
    }
    if (ParserContext.initFailed) {
      return null;
    }

    // Return from cache (including cached null = previously failed language)
    if (ParserContext.parserCache.has(grammar.cacheKey)) {
      return ParserContext.parserCache.get(grammar.cacheKey) ?? null;
    }

    try {
      const language = await WebTreeSitter.Language.load(grammar.wasmPath);
      const parser = new WebTreeSitter();
      parser.setLanguage(language);

      ParserContext.parserCache.set(grammar.cacheKey, parser);
      return parser;
    } catch (e) {
      const lang = grammar.language;
      const reason = `Failed to load WASM grammar ${grammar.cacheKey}: ${(e as Error).message}`;

      // Log once per language, avoid spam
      if (!ParserContext.warnedLanguages.has(lang)) {
        console.error(`[SAST] AST unavailable for ${lang} – using regex fallback. (${reason})`);
        ParserContext.warnedLanguages.add(lang);
      }

      // Cache the failure so we don't retry on every file
      ParserContext.parserCache.set(grammar.cacheKey, null);
      return null;
    }
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
