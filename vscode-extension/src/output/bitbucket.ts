/**
 * Bitbucket Code Insights emitter (§QW-18 / §IN-6).
 *
 * Bitbucket Pipelines / Cloud / Server consume a Code Insights "report" +
 * "annotations" payload. We emit the annotations array — the typical CI
 * pattern is to upload it via `bitbucket-cli` or `curl` to the Pipeline
 * report endpoint.
 *
 * Spec:
 *   https://developer.atlassian.com/cloud/bitbucket/rest/api-group-reports/
 *   https://developer.atlassian.com/cloud/bitbucket/code-insights/
 */
import { ProjectScanReport } from '../scanner/scanner';
import type { Finding } from '../models/finding';

interface BitbucketAnnotation {
  external_id: string;
  type: 'CODE_SMELL' | 'BUG' | 'VULNERABILITY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  summary: string;
  details?: string;
  path: string;
  line: number;
  link?: string;
  annotation_type?: 'BUG' | 'CODE_SMELL' | 'VULNERABILITY';
}

export function toBitbucketCodeInsights(report: ProjectScanReport): string {
  const annotations: BitbucketAnnotation[] = [];
  for (let i = 0; i < report.findings.length; i++) {
    const f = report.findings[i];
    if (!f.filePath) { continue; }
    const sev = mapSeverity(f);
    annotations.push({
      external_id: `${f.code}-${i}`,
      type: 'VULNERABILITY',
      annotation_type: 'VULNERABILITY',
      severity: sev,
      summary: `[${f.code}] ${f.message}`,
      details: [
        f.fix ? `Fix: ${f.fix}` : '',
        f.risk ? `Risk: ${f.risk}` : '',
      ].filter(Boolean).join('\n\n'),
      path: f.filePath,
      line: f.line ?? 1,
    });
  }
  return JSON.stringify(annotations, null, 2);
}

function mapSeverity(f: Finding): BitbucketAnnotation['severity'] {
  if (f.severity === 'high' && f.confidence === 'high') { return 'CRITICAL'; }
  if (f.severity === 'high') { return 'HIGH'; }
  if (f.severity === 'medium') { return 'MEDIUM'; }
  return 'LOW';
}
