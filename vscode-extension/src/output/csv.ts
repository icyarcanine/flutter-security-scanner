/**
 * CSV emitter (§QW-15 / §IN-11).
 *
 * RFC 4180 quoting. Each finding is one row; complex fields (cwe, pathSteps)
 * are flattened so the output round-trips through Excel / Sheets without
 * surprises. The first row is the header.
 */
import { ProjectScanReport } from '../scanner/scanner';
import type { Finding } from '../models/finding';

const COLUMNS: Array<{
  header: string;
  get: (f: Finding) => string;
}> = [
  { header: 'severity', get: f => f.severity ?? '' },
  { header: 'category', get: f => f.category },
  { header: 'confidence', get: f => f.confidence ?? '' },
  { header: 'code', get: f => f.code },
  { header: 'cwe', get: f => Array.isArray(f.cwe) ? f.cwe.join(';') : (f.cwe ?? '') },
  { header: 'file', get: f => f.filePath ?? '' },
  { header: 'line', get: f => f.line != null ? String(f.line) : '' },
  { header: 'column', get: f => f.column != null ? String(f.column) : '' },
  { header: 'message', get: f => f.message },
  { header: 'fix', get: f => f.fix },
];

export function toCsv(report: ProjectScanReport): string {
  const rows: string[] = [];
  rows.push(COLUMNS.map(c => csvField(c.header)).join(','));
  for (const f of report.findings) {
    rows.push(COLUMNS.map(c => csvField(c.get(f))).join(','));
  }
  // RFC 4180 recommends CRLF line endings — Excel honors LF too, but CRLF
  // works in everything.
  return rows.join('\r\n') + '\r\n';
}

/**
 * Quote a field per RFC 4180: if the value contains a comma, double-quote,
 * CR, or LF, wrap it in double-quotes and escape internal `"` as `""`.
 */
function csvField(value: string): string {
  if (value === '') { return ''; }
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
