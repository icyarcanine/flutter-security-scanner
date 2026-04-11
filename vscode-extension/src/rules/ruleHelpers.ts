import { ScannedFile } from '../scanner/scannedFile';
import { ProjectContext, Location } from '../scanner/projectContext';

export function isTestLikePath(p: string): boolean {
  return p.startsWith('test/') ||
    p.startsWith('integration_test/') ||
    p.startsWith('example/') ||
    p.includes('/test/') ||
    p.includes('/integration_test/') ||
    p.includes('/example/');
}

export function isProductionDartFile(file: ScannedFile): boolean {
  if (!file.isDart) { return false; }
  if (isTestLikePath(file.relativePath)) { return false; }
  return file.relativePath.startsWith('lib/') || file.relativePath.startsWith('bin/');
}

export function isCommentLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

export function firstReferenceFor(
  context: ProjectContext,
  token: string,
  files?: ScannedFile[],
): Location | null {
  for (const file of (files ?? context.files)) {
    const offset = file.content.indexOf(token);
    if (offset === -1) { continue; }
    return { file, line: file.lineForOffset(offset) };
  }
  return null;
}

// ─────────────────────────────────────────────
// Log statement collection (multi-line aware)
// ─────────────────────────────────────────────

export interface LogStatement {
  startLine: number;
  argument: string;
}

export function collectLogStatements(
  file: ScannedFile,
  maxContinuationLines = 8,
): LogStatement[] {
  const result: LogStatement[] = [];
  const callPattern = /\b(?:print|debugPrint|developer\.log)\s*\(/g;

  for (let i = 0; i < file.lines.length; i++) {
    const lineText = file.lines[i];
    if (isCommentLine(lineText)) { continue; }

    callPattern.lastIndex = 0;
    const match = callPattern.exec(lineText);
    if (!match) { continue; }

    const afterParen = lineText.substring(match.index + match[0].length);
    const closeIndex = findMatchingClose(afterParen, 0);

    if (closeIndex !== -1) {
      result.push({ startLine: i + 1, argument: afterParen.substring(0, closeIndex).trim() });
      continue;
    }

    // Multi-line: buffer continuation lines
    let buffer = afterParen;
    let depth = 1 + countOpenParens(afterParen) - countCloseParens(afterParen);
    let closed = false;

    for (let j = i + 1; j < file.lines.length && j <= i + maxContinuationLines; j++) {
      const continuation = file.lines[j].trim();
      if (!continuation || isCommentLine(continuation)) { break; }
      buffer += ` ${continuation}`;
      depth += countOpenParens(continuation) - countCloseParens(continuation);
      if (depth <= 0) { closed = true; break; }
    }

    const endMark = closed ? buffer.lastIndexOf(')') : buffer.length;
    const safeEnd = endMark === -1 ? buffer.length : endMark;
    result.push({ startLine: i + 1, argument: buffer.substring(0, safeEnd).trim() });
  }

  return result;
}

function findMatchingClose(text: string, startDepth: number): number {
  let depth = startDepth;
  let inSingle = false;
  let inDouble = false;
  let inTripleSingle = false;
  let inTripleDouble = false;
  let isEscaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (isEscaped) { isEscaped = false; continue; }
    if (ch === '\\') { isEscaped = true; continue; }

    if (ch === "'" && !inSingle && !inDouble && !inTripleDouble) {
      if (i + 2 < text.length && text[i + 1] === "'" && text[i + 2] === "'") {
        inTripleSingle = !inTripleSingle; i += 2; continue;
      }
    }
    if (ch === '"' && !inSingle && !inDouble && !inTripleSingle) {
      if (i + 2 < text.length && text[i + 1] === '"' && text[i + 2] === '"') {
        inTripleDouble = !inTripleDouble; i += 2; continue;
      }
    }
    if (ch === "'" && !inTripleSingle && !inTripleDouble && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inTripleSingle && !inTripleDouble && !inSingle) { inDouble = !inDouble; continue; }
    if (inSingle || inDouble || inTripleSingle || inTripleDouble) { continue; }

    if (ch === '(') { depth++; }
    else if (ch === ')') {
      if (depth === 0) { return i; }
      depth--;
    }
  }
  return -1;
}

function stripStrings(text: string): string {
  return text
    .replace(/"""[\s\S]*?"""/g, '')
    .replace(/'''[\s\S]*?'''/g, '')
    .replace(/"(?:[^"\\]|\\.)*"/g, '')
    .replace(/'(?:[^'\\]|\\.)*'/g, '');
}

function countOpenParens(text: string): number {
  const s = stripStrings(text);
  return (s.match(/\(/g) ?? []).length;
}

function countCloseParens(text: string): number {
  const s = stripStrings(text);
  return (s.match(/\)/g) ?? []).length;
}
