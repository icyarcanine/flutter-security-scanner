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

function extractInlineSuppressions(lines: string[]): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // `// sast-ignore-next-line` → suppresses ALL rules on line i+2 (1-indexed)
    if (IGNORE_NEXT_LINE.test(line)) {
      const targetLine = i + 2; // next line is i+1 (0-indexed) = i+2 (1-indexed)
      if (!map.has(targetLine)) map.set(targetLine, new Set());
      map.get(targetLine)!.add('*');
    }

    // `// sast-ignore injection-flaw` → suppresses specific rule on next line
    let match: RegExpExecArray | null;
    IGNORE_RULE.lastIndex = 0;
    while ((match = IGNORE_RULE.exec(line)) !== null) {
      const ruleCode = match[1];
      const targetLine = i + 2;
      if (!map.has(targetLine)) map.set(targetLine, new Set());
      map.get(targetLine)!.add(ruleCode);
    }
  }

  return map;
}
