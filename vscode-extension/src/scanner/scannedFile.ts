import { basename, normalizePath } from '../utils/pathUtils';
import type { SyntaxNode } from 'web-tree-sitter';

export class ScannedFile {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly content: string;
  readonly lines: string[];
  private readonly _lineOffsets: number[];
  public astNode?: SyntaxNode;
  /** 'ok' = parsed successfully, 'failed' = parser error, 'skipped' = no grammar or not attempted */
  public astStatus: 'ok' | 'failed' | 'skipped' = 'skipped';
  /** If astStatus === 'failed', the reason string */
  public astError?: string;

  constructor(absolutePath: string, relativePath: string, content: string) {
    this.absolutePath = absolutePath;
    this.relativePath = relativePath;
    this.content = content;
    this.lines = content.split('\n');
    this._lineOffsets = ScannedFile._buildLineOffsets(content);
  }

  get name(): string {
    return basename(this.relativePath);
  }

  get extension(): string {
    const fileName = this.name;
    const dotIndex = fileName.lastIndexOf('.');
    return dotIndex === -1 ? '' : fileName.substring(dotIndex);
  }

  get isDart(): boolean { return this.extension === '.dart'; }
  get isSql(): boolean { return this.extension === '.sql'; }
  get isMarkdown(): boolean { return this.extension === '.md'; }
  get isYaml(): boolean { return this.extension === '.yaml' || this.extension === '.yml'; }
  get isJson(): boolean { return this.extension === '.json'; }
  get isTxt(): boolean { return this.extension === '.txt'; }

  get isGitIgnore(): boolean { return this.name === '.gitignore'; }

  get isEnvFile(): boolean {
    return this.name === '.env' || this.name.startsWith('.env.');
  }

  get isEnvTemplateFile(): boolean {
    if (!this.isEnvFile) { return false; }
    const lower = this.name.toLowerCase();
    return lower.endsWith('.example') || lower.endsWith('.sample') ||
      lower.endsWith('.template') || lower.endsWith('.dist');
  }

  lineForOffset(offset: number): number {
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
      } else {
        low = mid + 1;
      }
    }
    return 1;
  }

  contextAroundLine(line: number, before = 8, after = 4): string {
    const start = Math.max(1, line - before);
    const end = Math.min(this.lines.length, line + after);
    return this.lines.slice(start - 1, end).join('\n');
  }

  private static _buildLineOffsets(content: string): number[] {
    const offsets = [0];
    for (let i = 0; i < content.length; i++) {
      if (content.charCodeAt(i) === 10) { // '\n'
        offsets.push(i + 1);
      }
    }
    return offsets;
  }
}

export function isTestLikePath(path: string): boolean {
  const n = normalizePath(path);
  return n.startsWith('test/') ||
    n.startsWith('integration_test/') ||
    n.startsWith('example/') ||
    n.includes('/test/') ||
    n.includes('/integration_test/') ||
    n.includes('/example/');
}
