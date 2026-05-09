import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Finding } from './models/finding';

/**
 * Baseline system for SAST findings.
 *
 * `npx flutter-supabase-security-scanner baseline` saves current findings to
 * `.sast-baseline.json`. Future scans compare against the baseline and only
 * surface NEW findings.
 *
 * Works identically in CLI and extension — zero editor dependency.
 */

export const BASELINE_FILENAME = '.sast-baseline.json';
export const BASELINE_VERSION = 2 as const;

export interface BaselineEntry {
  code: string;
  filePath: string;
  line: number;
  fingerprint: string;
  /**
   * Optional v2 field: SHA-1 of the ±2 lines of source around the finding.
   * Survives line-shifts caused by unrelated edits while still detecting
   * meaningful local changes. Old v1 baselines without this field still load.
   */
  contextHash?: string;
}

export interface BaselineData {
  version: 1 | 2;
  createdAt: string;
  entries: BaselineEntry[];
}

/**
 * Per-finding fingerprint. v2 fingerprints are stable across formatting and
 * line-shift edits because they include a content hash of the surrounding
 * source — but consumers can still match against v1 strings (we keep the
 * `code|path|message[0:60]` shape as the primary key).
 */
export function fingerprintFinding(f: Finding): string {
  return `${f.code}|${f.filePath ?? ''}|${f.message.substring(0, 60)}`;
}

/**
 * Compute a stable hash of the lines surrounding a finding. Uses ±2 lines
 * so localized edits (e.g., adding a `console.log` two lines above the
 * vulnerability) don't invalidate the baseline. Lines are normalized
 * (whitespace collapsed) so reformatting doesn't change the hash.
 *
 * Returns `undefined` if file content / line aren't available — callers
 * fall back to the v1 fingerprint match.
 */
export function computeContextHash(
  finding: Finding,
  fileContents: Map<string, string>,
): string | undefined {
  if (!finding.filePath || finding.line == null) { return undefined; }
  const content = fileContents.get(finding.filePath);
  if (!content) { return undefined; }
  const lines = content.split('\n');
  const startIdx = Math.max(0, finding.line - 1 - 2);
  const endIdx = Math.min(lines.length - 1, finding.line - 1 + 2);
  const window = lines.slice(startIdx, endIdx + 1)
    .map(l => l.replace(/\s+/g, ' ').trim())
    .join('\n');
  return crypto.createHash('sha1').update(window).digest('hex').slice(0, 16);
}

/**
 * Generate baseline data from current findings. When `fileContents` is
 * provided, each entry also carries a context hash (v2). Without it we
 * still emit v2 but with `contextHash` undefined per-entry — callers fall
 * back to the v1 fingerprint match.
 */
export function generateBaseline(findings: Finding[], fileContents?: Map<string, string>): BaselineData {
  return {
    version: BASELINE_VERSION,
    createdAt: new Date().toISOString(),
    entries: findings
      .filter(f => f.filePath && f.line != null)
      .map(f => {
        const entry: BaselineEntry = {
          code: f.code,
          filePath: f.filePath!,
          line: f.line!,
          fingerprint: fingerprintFinding(f),
        };
        if (fileContents) {
          const ch = computeContextHash(f, fileContents);
          if (ch) { entry.contextHash = ch; }
        }
        return entry;
      }),
  };
}

/**
 * Save baseline to disk.
 */
export function saveBaseline(rootPath: string, data: BaselineData): void {
  const filePath = path.join(rootPath, BASELINE_FILENAME);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Load baseline from disk. Returns null if no baseline exists. Accepts both
 * v1 and v2 formats — v1 entries lack `contextHash` but still match by
 * fingerprint.
 */
export function loadBaseline(rootPath: string): BaselineData | null {
  const filePath = path.join(rootPath, BASELINE_FILENAME);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    if ((data.version === 1 || data.version === 2) && Array.isArray(data.entries)) {
      return data as BaselineData;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Filter out findings already in the baseline (return only NEW findings).
 *
 * Match strategy (most → least preferred):
 *   1. v2 contextHash match — survives line-shift edits.
 *   2. v1 fingerprint match — code + filePath + message prefix.
 *
 * The v2 path requires `fileContents` so we can recompute the current
 * finding's context hash; without it we fall back to v1 only.
 */
export function applyBaseline(
  findings: Finding[],
  baseline: BaselineData,
  fileContents?: Map<string, string>,
): Finding[] {
  const baselineFingerprints = new Set(baseline.entries.map(e => e.fingerprint));
  const baselineContextHashes = new Set(
    baseline.entries
      .map(e => e.contextHash)
      .filter((h): h is string => typeof h === 'string'),
  );

  return findings.filter(f => {
    if (fileContents && baselineContextHashes.size > 0) {
      const ch = computeContextHash(f, fileContents);
      if (ch && baselineContextHashes.has(ch)) { return false; }
    }
    const fp = fingerprintFinding(f);
    return !baselineFingerprints.has(fp);
  });
}
