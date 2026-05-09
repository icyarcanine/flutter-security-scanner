/**
 * JUnit XML emitter (§QW-16 / §IN-8).
 *
 * Jenkins, Bamboo, CircleCI, Buildkite, Azure DevOps, GitLab — virtually every
 * CI tool understands the JUnit / xUnit XML schema. We map each finding to a
 * `testcase` whose `failure` element carries the message and risk so a CI
 * job can render the full report inline.
 *
 * The output is XML 1.0 + UTF-8 with a single `<testsuite>` element containing
 * one `<testcase>` per finding. Skipped files become `<testcase><skipped/>`.
 */
import { ProjectScanReport } from '../scanner/scanner';
import type { Finding } from '../models/finding';

export function toJunit(report: ProjectScanReport): string {
  const testcases: string[] = [];
  for (const f of report.findings) {
    testcases.push(toTestcase(f));
  }
  for (const sf of report.skippedFiles) {
    testcases.push(
      `    <testcase classname="scanner.skipped" name="${xmlAttr(sf.relativePath)}">\n` +
      `      <skipped message="${xmlAttr(`oversize: ${sf.sizeBytes} bytes`)}"/>\n` +
      `    </testcase>`,
    );
  }

  const failures = report.findings.filter(f => f.severity === 'high').length;
  const errors = 0;
  const totalTests = testcases.length;
  const skipped = report.skippedFiles.length;

  const suiteAttrs = [
    `name="flutter-supabase-security-scanner"`,
    `tests="${totalTests}"`,
    `failures="${failures}"`,
    `errors="${errors}"`,
    `skipped="${skipped}"`,
    `time="${(report.scanDurationMs / 1000).toFixed(3)}"`,
  ].join(' ');

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<testsuites>',
    `  <testsuite ${suiteAttrs}>`,
    ...testcases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}

function toTestcase(f: Finding): string {
  // classname = file path, name = rule code + line — gives JUnit reporters
  // a stable per-finding identity that groups by file in tree views.
  const classname = (f.filePath ?? 'unknown').replace(/[\\/]/g, '.');
  const name = `${f.code}@${f.line ?? 0}`;
  const sev = (f.severity ?? 'low').toUpperCase();
  const msg = xmlAttr(`[${sev}] ${f.message}`);
  const body = xmlText([
    `Severity: ${sev}`,
    `Rule:     ${f.code}`,
    `File:     ${f.filePath ?? ''}:${f.line ?? ''}`,
    `Message:  ${f.message}`,
    `Fix:      ${f.fix}`,
    f.risk ? `Risk:     ${f.risk}` : '',
  ].filter(Boolean).join('\n'));
  return [
    `    <testcase classname="${xmlAttr(classname)}" name="${xmlAttr(name)}">`,
    `      <failure message="${msg}" type="${xmlAttr(f.code)}">${body}</failure>`,
    `    </testcase>`,
  ].join('\n');
}

function xmlAttr(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/[\r\n]+/g, ' ');
}

function xmlText(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
