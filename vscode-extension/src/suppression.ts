import * as fs from 'fs';
import * as path from 'path';
import { Finding } from './models/finding';

/**
 * Suppression system for SAST findings.
 *
 * Supports:
 *   - Inline: `// sast-ignore-next-line` or `// sast-ignore <rule-code>`
 *   - File-level: `.sastignore` file with glob patterns
 *
 * Works identically in CLI and extension — zero editor dependency.
 */

const IGNORE_NEXT_LINE = /\/[/*]\s*sast-ignore-next-line\b/i;
const IGNORE_RULE = /\/[/*]\s*sast-ignore\s+([\w-]+)/gi;

export interface SuppressionContext {
  /** Set of file relative paths or glob-like prefixes to ignore entirely. */
  ignoredPaths: Set<string>;
  /** Map<filePath, Map<lineNumber, Set<ruleCode|'*'>>> for inline suppressions. */
  inlineSuppressions: Map<string, Map<number, Set<string>>>;
}

/**
 * Build suppression context from project root.
 * Reads `.sastignore` and scans file content for inline comments.
 */
export function buildSuppressionContext(rootPath: string, files: { relativePath: string; lines: string[] }[]): SuppressionContext {
  const ignoredPaths = loadSastIgnore(rootPath);
  const inlineSuppressions = new Map<string, Map<number, Set<string>>>();

  for (const file of files) {
    const fileMap = extractInlineSuppressions(file.lines);
    if (fileMap.size > 0) {
      inlineSuppressions.set(file.relativePath, fileMap);
    }
  }

  return { ignoredPaths, inlineSuppressions };
}

/**
 * Filter findings through the suppression context.
 * Returns only findings that are NOT suppressed.
 */
export function applySuppression(findings: Finding[], ctx: SuppressionContext): Finding[] {
  return findings.filter(f => {
    if (!f.filePath) return true;

    // File-level suppression via .sastignore
    if (isPathIgnored(f.filePath, ctx.ignoredPaths)) {
      return false;
    }

    // Inline suppression
    if (f.line != null) {
      const fileMap = ctx.inlineSuppressions.get(f.filePath);
      if (fileMap) {
        const suppressed = fileMap.get(f.line);
        if (suppressed && (suppressed.has('*') || suppressed.has(f.code))) {
          return false;
        }
      }
    }

    return true;
  });
}

// ── .sastignore ─────────────────────────────────

function loadSastIgnore(rootPath: string): Set<string> {
  const ignoredPaths = new Set<string>();
  const ignoreFile = path.join(rootPath, '.sastignore');

  try {
    const content = fs.readFileSync(ignoreFile, 'utf8');
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      ignoredPaths.add(line);
    }
  } catch {
    // No .sastignore — that's fine
  }

  return ignoredPaths;
}

function isPathIgnored(filePath: string, ignoredPaths: Set<string>): boolean {
  for (const pattern of ignoredPaths) {
    // Exact match
    if (filePath === pattern) return true;
    // Directory prefix (e.g., "vendor/" matches "vendor/lib/foo.js")
    if (pattern.endsWith('/') && filePath.startsWith(pattern)) return true;
    // Simple glob: "*.min.js" → endsWith
    if (pattern.startsWith('*') && filePath.endsWith(pattern.substring(1))) return true;
    // Substring match for dir segments (e.g., "test" matches "src/test/foo.js")
    if (!pattern.includes('/') && !pattern.includes('*')) {
      const segments = filePath.split('/');
      if (segments.includes(pattern)) return true;
    }
  }
  return false;
}

// ── Inline suppressions ─────────────────────────

/**
 * Maximum lines the suppression window may extend below the comment.
 * Acts as a hard cap; brace-balanced statement detection short-circuits
 * earlier in practice.
 */
const INLINE_SUPPRESSION_MAX_WINDOW = 8;

/**
 * Expand the suppression to cover one *logical statement* — the first
 * non-blank, non-comment line below the directive PLUS any continuation
 * lines until parentheses, braces, brackets, and template-string literals
 * are balanced AND a line ends with `;` or `}`. We refuse to go past a
 * blank line OR past a line that introduces a new top-level identifier
 * (heuristic: starts with a letter/underscore, ends without trailing
 * comma/operator).
 *
 * This stops the previous "next-N-lines" heuristic from leaking
 * suppressions across statement boundaries:
 *
 *     // sast-ignore injection-flaw
 *     db.query("a" + req.body.x); db.query("b" + req.body.y);  // only first call now suppressed
 *
 * vs the wrap-friendly case which still works:
 *
 *     // sast-ignore injection-flaw
 *     db.query(
 *       "SELECT * FROM users WHERE id = " + id,
 *     );
 */
function extractInlineSuppressions(lines: string[]): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();

  const addStatementWindow = (originIdx: number, ruleCode: string) => {
    // Find the first non-blank, non-comment statement-start line below.
    let start = originIdx + 1;
    while (start < lines.length) {
      const t = lines[start].trim();
      if (t === '' || t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) {
        start++; continue;
      }
      break;
    }
    if (start >= lines.length) { return; }

    // Accumulate lines until brackets balance and we hit a terminator on a line.
    let parenDepth = 0;
    let braceDepth = 0;
    let bracketDepth = 0;
    let inTemplate = false;
    let inSingle = false;
    let inDouble = false;

    let end = start;
    const hardLimit = Math.min(lines.length - 1, originIdx + INLINE_SUPPRESSION_MAX_WINDOW);
    for (; end <= hardLimit; end++) {
      const line = lines[end];
      let escaped = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (escaped) { escaped = false; continue; }
        if (ch === '\\') { escaped = true; continue; }
        if (!inDouble && !inTemplate && ch === "'") { inSingle = !inSingle; continue; }
        if (!inSingle && !inTemplate && ch === '"') { inDouble = !inDouble; continue; }
        if (!inSingle && !inDouble && ch === '`') { inTemplate = !inTemplate; continue; }
        if (inSingle || inDouble || inTemplate) { continue; }
        if (ch === '(') parenDepth++;
        else if (ch === ')') parenDepth = Math.max(0, parenDepth - 1);
        else if (ch === '[') bracketDepth++;
        else if (ch === ']') bracketDepth = Math.max(0, bracketDepth - 1);
        else if (ch === '{') braceDepth++;
        else if (ch === '}') braceDepth = Math.max(0, braceDepth - 1);
      }
      const trimmed = line.trim();
      const closed = parenDepth === 0 && bracketDepth === 0 && braceDepth === 0
        && !inSingle && !inDouble && !inTemplate;
      if (closed && (trimmed.endsWith(';') || trimmed.endsWith('}') || trimmed === '')) {
        break;
      }
    }

    // Emit suppression for every line in [start, end] (1-indexed).
    for (let lineIdx = start; lineIdx <= end && lineIdx < lines.length; lineIdx++) {
      const targetLine = lineIdx + 1;
      if (!map.has(targetLine)) map.set(targetLine, new Set());
      map.get(targetLine)!.add(ruleCode);
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (IGNORE_NEXT_LINE.test(line)) {
      addStatementWindow(i, '*');
    }

    let match: RegExpExecArray | null;
    IGNORE_RULE.lastIndex = 0;
    while ((match = IGNORE_RULE.exec(line)) !== null) {
      addStatementWindow(i, match[1]);
    }
  }

  return map;
}
