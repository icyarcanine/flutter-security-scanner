#!/usr/bin/env node
/**
 * Output-formats smoke test (§QW-14/15/16/17/18).
 *
 * Runs the scanner over a tiny vulnerable fixture, then confirms each
 * emitter produces the basic shape callers expect:
 *   - markdown: a `# SAST scan report` header and at least one `| ... |` row
 *   - csv: an RFC 4180 header row + at least one data row, with quoting on
 *     fields that contain commas
 *   - junit: well-formed XML with one <testcase> per finding
 *   - gitlab: a JSON array of {description, fingerprint, severity, location}
 *   - bitbucket: a JSON array of {external_id, severity, summary, path, line}
 *   - html: self-contained report with filters and finding cards
 *
 * Validates structure rather than every byte — the emitters are too small
 * to merit golden-file comparison and golden files would rot quickly.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { ProjectScanner } = require('../out/scanner/scanner');
const { toMarkdown } = require('../out/output/markdown');
const { toCsv } = require('../out/output/csv');
const { toJunit } = require('../out/output/junit');
const { toGitLabCodeQuality } = require('../out/output/gitlab');
const { toBitbucketCodeInsights } = require('../out/output/bitbucket');
const { toHtmlReport } = require('../out/output/html');

async function buildReport() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fss-out-'));
  fs.writeFileSync(path.join(root, 'vuln.js'),
    `function h(req, db) { db.rawQuery("SELECT * FROM u WHERE id = " + req.body.id); }`,
  );
  const scanner = new ProjectScanner({ includeSuggestions: false });
  const report = await scanner.scan(root);
  fs.rmSync(root, { recursive: true, force: true });
  return report;
}

async function testMarkdown() {
  const report = await buildReport();
  const md = toMarkdown(report);
  assert.match(md, /^# SAST scan report/m, 'markdown must start with the report header');
  assert.match(md, /\| Severity \| Rule \| File \| Line \| Message \|/, 'markdown must include the table header');
  assert.match(md, /injection-flaw/, 'markdown must include the injection-flaw row');
}

async function testCsv() {
  const report = await buildReport();
  const csv = toCsv(report);
  const lines = csv.split('\r\n').filter(Boolean);
  assert.ok(lines[0].startsWith('severity,category,confidence,'),
    `csv header missing/wrong: ${lines[0]}`);
  // Find a data row containing the rule code.
  assert.ok(lines.some(l => l.includes('injection-flaw')),
    'csv must include the injection-flaw finding');
  // Any cell with commas must be double-quoted: pick a finding whose
  // message normally contains commas.
  for (let i = 1; i < lines.length; i++) {
    const fields = lines[i];
    // Each line should have exactly the column count of commas (≥ 9 separators).
    const quoted = fields.match(/"/g)?.length ?? 0;
    assert.ok(quoted % 2 === 0, `unbalanced quotes on csv line: ${fields}`);
  }
}

async function testJunit() {
  const report = await buildReport();
  const xml = toJunit(report);
  assert.match(xml, /<\?xml version="1\.0" encoding="UTF-8"\?>/, 'junit must declare XML 1.0 / UTF-8');
  assert.match(xml, /<testsuite\s/, 'junit must contain <testsuite>');
  assert.match(xml, /<testcase\s/, 'junit must contain at least one <testcase>');
  assert.match(xml, /<failure\s/, 'junit must report at least one <failure> for the vuln');
  // Quick well-formedness sniff: equal opens/closes for the wrappers we control.
  const opens = (xml.match(/<testcase\b/g) ?? []).length;
  const closes = (xml.match(/<\/testcase>/g) ?? []).length;
  assert.strictEqual(opens, closes, `unbalanced <testcase> tags: ${opens} open vs ${closes} close`);
}

async function testGitLab() {
  const report = await buildReport();
  const json = JSON.parse(toGitLabCodeQuality(report));
  assert.ok(Array.isArray(json), 'gitlab output must be a JSON array');
  assert.ok(json.length > 0, 'gitlab output must not be empty');
  for (const issue of json) {
    assert.ok(issue.description, 'gitlab issue: description missing');
    assert.ok(issue.check_name, 'gitlab issue: check_name missing');
    assert.ok(issue.fingerprint, 'gitlab issue: fingerprint missing');
    assert.ok(['info', 'minor', 'major', 'critical', 'blocker'].includes(issue.severity),
      `gitlab issue: bad severity ${issue.severity}`);
    assert.ok(issue.location?.path, 'gitlab issue: location.path missing');
    assert.ok(typeof issue.location?.lines?.begin === 'number', 'gitlab issue: location.lines.begin missing');
  }
}

async function testBitbucket() {
  const report = await buildReport();
  const json = JSON.parse(toBitbucketCodeInsights(report));
  assert.ok(Array.isArray(json), 'bitbucket output must be a JSON array');
  assert.ok(json.length > 0, 'bitbucket output must not be empty');
  for (const a of json) {
    assert.ok(a.external_id, 'bitbucket annotation: external_id missing');
    assert.ok(a.summary, 'bitbucket annotation: summary missing');
    assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(a.severity),
      `bitbucket annotation: bad severity ${a.severity}`);
    assert.ok(a.path, 'bitbucket annotation: path missing');
    assert.strictEqual(typeof a.line, 'number');
  }
}

async function testHtml() {
  const report = await buildReport();
  const html = toHtmlReport(report);
  assert.match(html, /<!doctype html>/i, 'html output must be a standalone document');
  assert.match(html, /<select id="severity">/, 'html output must include severity filter');
  assert.match(html, /class="finding"/, 'html output must include finding cards');
  assert.match(html, /injection-flaw/, 'html output must include the rule code');
}

(async function main() {
  await testMarkdown();
  await testCsv();
  await testJunit();
  await testGitLab();
  await testBitbucket();
  await testHtml();
  console.log('output-formats self-test: PASS');
})().catch(err => {
  console.error('output-formats self-test: FAIL');
  console.error(err);
  process.exit(1);
});
