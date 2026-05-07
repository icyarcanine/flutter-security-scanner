/**
 * GitLab Code Quality emitter (§QW-17 / §IN-4).
 *
 * GitLab CI consumes a "Code Quality" JSON artifact in MR widgets. The format
 * is documented at:
 *   https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
 *
 * Each finding maps to one issue object. `fingerprint` is required for diff
 * stability — we reuse the SARIF-style `partialFingerprints` shape (sha-1 of
 * code+path+line+message).
 */
import { createHash } from 'crypto';
import { ProjectScanReport } from '../scanner/scanner';
import type { Finding } from '../models/finding';

interface GitLabIssue {
  description: string;
  check_name: string;
  fingerprint: string;
  severity: 'info' | 'minor' | 'major' | 'critical' | 'blocker';
  location: {
    path: string;
    lines: { begin: number };
  };
  categories?: string[];
  type?: 'issue';
}

export function toGitLabCodeQuality(report: ProjectScanReport): string {
  const issues: GitLabIssue[] = [];
  for (const f of report.findings) {
    if (!f.filePath) { continue; }
    issues.push({
      type: 'issue',
      description: `[${(f.severity ?? 'low').toUpperCase()}] ${f.message}`,
      check_name: f.code,
      fingerprint: fingerprint(f),
      severity: mapSeverity(f),
      location: {
        path: f.filePath,
        lines: { begin: f.line ?? 1 },
      },
      categories: ['Security'],
    });
  }
  return JSON.stringify(issues, null, 2);
}

/**
 * Map our internal severity onto GitLab's 5-level scale.
 *   high  → critical (blocker reserved for `injection` confirmed-taint).
 *   medium→ major
 *   low   → minor
 */
function mapSeverity(f: Finding): GitLabIssue['severity'] {
  if (f.severity === 'high' && f.confidence === 'high') { return 'blocker'; }
  if (f.severity === 'high') { return 'critical'; }
  if (f.severity === 'medium') { return 'major'; }
  if (f.severity === 'low') { return 'minor'; }
  return 'info';
}

function fingerprint(f: Finding): string {
  const key = [f.code, f.filePath ?? '', f.line ?? '', f.message].join('|');
  return createHash('sha1').update(key).digest('hex');
}
