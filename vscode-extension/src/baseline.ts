import * as fs from 'fs';
import * as path from 'path';
import { Finding } from './models/finding';

/**
 * Baseline system for SAST findings.
 *
 * `npx flutter-supabase-helper baseline` saves current findings to `.sast-baseline.json`.
 * Future scans compare against the baseline and only surface NEW findings.
 *
 * Works identically in CLI and extension — zero editor dependency.
 */

export const BASELINE_FILENAME = '.sast-baseline.json';

export interface BaselineEntry {
  code: string;
  filePath: string;
  line: number;
  /** Fingerprint for matching across minor line shifts */
  fingerprint: string;
}

export interface BaselineData {
  version: 1;
  createdAt: string;
  entries: BaselineEntry[];
}

/**
 * Create a fingerprint for a finding that survives minor edits.
 * Uses code + filePath + a hash-like substring of the message.
 */
export function fingerprintFinding(f: Finding): string {
  return `${f.code}|${f.filePath ?? ''}|${f.message.substring(0, 60)}`;
}

/**
 * Generate baseline data from current findings.
 */
export function generateBaseline(findings: Finding[]): BaselineData {
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    entries: findings
      .filter(f => f.filePath && f.line != null)
      .map(f => ({
        code: f.code,
        filePath: f.filePath!,
        line: f.line!,
        fingerprint: fingerprintFinding(f),
      })),
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
 * Load baseline from disk. Returns null if no baseline exists.
 */
export function loadBaseline(rootPath: string): BaselineData | null {
  const filePath = path.join(rootPath, BASELINE_FILENAME);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    if (data.version === 1 && Array.isArray(data.entries)) {
      return data as BaselineData;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Filter out findings that match the baseline (i.e. return only NEW findings).
 */
export function applyBaseline(findings: Finding[], baseline: BaselineData): Finding[] {
  const baselineFingerprints = new Set(baseline.entries.map(e => e.fingerprint));

  return findings.filter(f => {
    const fp = fingerprintFinding(f);
    return !baselineFingerprints.has(fp);
  });
}
