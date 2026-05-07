/**
 * GitLab SAST Security Report emitter (§IN-5).
 *
 * GitLab's Vulnerability Report widget consumes a different artifact than the
 * Code Quality one (§IN-4). Spec: GitLab security report schema 15+
 *   https://gitlab.com/gitlab-org/security-products/security-report-schemas
 *
 * The minimal valid v15 SAST report needs:
 *   - version (a security-report-schema version string)
 *   - scan: { analyzer, scanner, type: 'sast', status, start_time, end_time }
 *   - vulnerabilities: each with id, name, description, severity, location,
 *     identifiers (CVE/CWE/OWASP), scanner
 *
 * Severity mapping deliberately differs from GitLab Code Quality: the
 * Vulnerability Report uses Critical/High/Medium/Low/Info, while Code Quality
 * uses blocker/critical/major/minor/info.
 */
import { createHash } from 'crypto';
import { ProjectScanReport } from '../scanner/scanner';
import type { Finding } from '../models/finding';

const SCHEMA_VERSION = '15.0.6';
const ANALYZER_ID = 'flutter-supabase-helper';
const ANALYZER_NAME = 'Flutter Supabase Helper SAST';
const VENDOR_NAME = 'flutter-supabase-helper';

type GitLabSastSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | 'Unknown';

interface GitLabIdentifier {
  type: 'cwe' | 'owasp' | 'cve' | 'flutter-supabase-helper-rule';
  name: string;
  value: string;
  url?: string;
}

interface GitLabVulnerability {
  id: string;
  category: 'sast';
  name: string;
  description: string;
  severity: GitLabSastSeverity;
  scanner: { id: string; name: string };
  location: {
    file: string;
    start_line: number;
    end_line?: number;
  };
  identifiers: GitLabIdentifier[];
  links?: { url: string }[];
  raw_source_code_extract?: string;
  details?: Record<string, unknown>;
}

interface GitLabScanInfo {
  analyzer: { id: string; name: string; version: string; vendor: { name: string } };
  scanner: { id: string; name: string; version: string; vendor: { name: string } };
  type: 'sast';
  status: 'success' | 'failure';
  start_time: string;
  end_time: string;
}

interface GitLabSastReport {
  version: string;
  scan: GitLabScanInfo;
  vulnerabilities: GitLabVulnerability[];
}

export interface GitLabSecurityOptions {
  /** Override the embedded analyzer/scanner version. Defaults to the package's. */
  scannerVersion?: string;
  /** ISO-8601 start time. Defaults to scan completion timestamp. */
  startTime?: string;
  /** ISO-8601 end time. Defaults to "now". */
  endTime?: string;
}

export function toGitLabSecurity(
  report: ProjectScanReport,
  options: GitLabSecurityOptions = {},
): string {
  const version = options.scannerVersion ?? '1.0.0';
  const start = options.startTime
    ?? new Date(Date.now() - report.scanDurationMs).toISOString();
  const end = options.endTime ?? new Date().toISOString();

  // ISO-8601 with optional offset; GitLab's spec is permissive about Z vs.
  // numeric offset, but it requires the `T` separator. Strip the millisecond
  // component if present to match the documented `^\\d{4}-...$` pattern.
  const startCanonical = canonicalIso(start);
  const endCanonical = canonicalIso(end);

  const scanner = { id: ANALYZER_ID, name: ANALYZER_NAME };
  const vulnerabilities: GitLabVulnerability[] = [];

  for (const f of report.findings) {
    if (!f.filePath) { continue; }
    if (f.isSuggestion) { continue; }

    vulnerabilities.push({
      id: deterministicId(f),
      category: 'sast',
      name: `${f.code}: ${f.message.split('\n')[0].slice(0, 120)}`,
      description: buildDescription(f),
      severity: mapSeverity(f),
      scanner,
      location: {
        file: f.filePath,
        start_line: f.line ?? 1,
        ...(f.endLine && f.endLine !== f.line ? { end_line: f.endLine } : {}),
      },
      identifiers: buildIdentifiers(f),
    });
  }

  const out: GitLabSastReport = {
    version: SCHEMA_VERSION,
    scan: {
      analyzer: {
        id: ANALYZER_ID, name: ANALYZER_NAME, version,
        vendor: { name: VENDOR_NAME },
      },
      scanner: {
        id: ANALYZER_ID, name: ANALYZER_NAME, version,
        vendor: { name: VENDOR_NAME },
      },
      type: 'sast',
      status: 'success',
      start_time: startCanonical,
      end_time: endCanonical,
    },
    vulnerabilities,
  };
  return JSON.stringify(out, null, 2);
}

function canonicalIso(value: string): string {
  // GitLab's schema validates against `\\d{4}-\\d{2}-\\d{2}T...`. Date#toISOString
  // already produces that; we just strip milliseconds to match the spec's
  // example output and avoid bytes that some CI runners reject.
  const d = new Date(value);
  if (isNaN(d.getTime())) { return value; }
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function deterministicId(f: Finding): string {
  // GitLab requires a UUID-shaped id but uses string equality for dedupe
  // across runs. A SHA-1 over (code, path, line, message) reformatted as a
  // UUIDv4-shape string gives deterministic + collision-resistant IDs without
  // a `crypto.randomUUID` dependency.
  const key = [f.code, f.filePath ?? '', f.line ?? 0, f.message].join('|');
  const hex = createHash('sha1').update(key).digest('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    // Force version nibble to 4 (UUIDv4-shaped, but synthetic).
    '4' + hex.slice(13, 16),
    // Force variant nibble to 8/9/a/b.
    ((parseInt(hex.charAt(16), 16) & 0x3) | 0x8).toString(16) + hex.slice(17, 20),
    hex.slice(20, 32),
  ].join('-');
}

function buildDescription(f: Finding): string {
  const parts: string[] = [f.message];
  if (f.risk) { parts.push(`Risk: ${f.risk}`); }
  if (f.fix) { parts.push(`Fix: ${f.fix}`); }
  return parts.join('\n\n');
}

function buildIdentifiers(f: Finding): GitLabIdentifier[] {
  const identifiers: GitLabIdentifier[] = [
    {
      type: 'flutter-supabase-helper-rule',
      name: f.code,
      value: f.code,
    },
  ];
  const cweRaw = (f as Finding & { cwe?: string | string[] }).cwe;
  if (cweRaw) {
    const cwes = Array.isArray(cweRaw) ? cweRaw : [cweRaw];
    for (const cwe of cwes) {
      const numeric = cwe.replace(/^CWE-/i, '');
      identifiers.push({
        type: 'cwe',
        name: cwe,
        value: numeric,
        url: `https://cwe.mitre.org/data/definitions/${numeric}.html`,
      });
    }
  }
  return identifiers;
}

function mapSeverity(f: Finding): GitLabSastSeverity {
  // High + high-confidence is "Critical" so PRs gate on the same bar as our
  // built-in --fail-on=high + --fail-confidence=high pair. Low-confidence
  // findings drop one band so they don't clutter the Vulnerability Report.
  if (f.severity === 'high' && f.confidence === 'high') { return 'Critical'; }
  if (f.severity === 'high') { return 'High'; }
  if (f.severity === 'medium' && f.confidence === 'low') { return 'Low'; }
  if (f.severity === 'medium') { return 'Medium'; }
  if (f.severity === 'low') { return 'Low'; }
  return 'Info';
}
