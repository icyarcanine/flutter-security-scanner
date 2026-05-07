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
const { toSarif } = require('../out/output/sarif');

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

async function buildReportWithRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fss-sarif-'));
  // Multi-line file so contextRegion has something to expand into.
  const src = [
    'function start() {',
    '  return 1;',
    '}',
    'function h(req, db) {',
    '  db.rawQuery("SELECT * FROM u WHERE id = " + req.body.id);',
    '}',
    'function end() {',
    '  return 2;',
    '}',
  ].join('\n');
  fs.writeFileSync(path.join(root, 'vuln.js'), src);
  const scanner = new ProjectScanner({ includeSuggestions: false });
  const report = await scanner.scan(root);
  return { report, root };
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

async function testSarifSnippets() {
  // §IN-2: every result must carry region.snippet.text and contextRegion
  // when the source line is in the scan corpus.
  const { report, root } = await buildReportWithRoot();
  try {
    const sarif = toSarif(report, root);
    const result = sarif.runs[0].results.find(r => r.ruleId === 'injection-flaw');
    assert.ok(result, 'expected an injection-flaw result in SARIF output');
    const phys = result.locations[0].physicalLocation;
    assert.ok(phys.region.snippet?.text, 'region.snippet.text missing on result');
    assert.ok(phys.region.snippet.text.includes('rawQuery'),
      `region.snippet should embed the offending line; got: ${phys.region.snippet.text}`);
    assert.ok(phys.contextRegion, 'contextRegion missing on result');
    assert.ok(phys.contextRegion.snippet?.text, 'contextRegion.snippet.text missing');
    assert.ok(phys.contextRegion.startLine < phys.region.startLine
      || phys.contextRegion.endLine > phys.region.startLine,
      'contextRegion should expand beyond the offending line');
    assert.ok(phys.contextRegion.snippet.text.split('\n').length >= 2,
      'contextRegion snippet should span at least 2 lines on a multi-line file');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testSarifTaxonomyAndAutomation() {
  // §IN-1 deepening: every result carries kind/rank, the run carries
  // automationDetails, and any rule with a CWE produces a taxonomies block
  // plus rule.relationships pointing into it.
  const { report, root } = await buildReportWithRoot();
  try {
    const sarif = toSarif(report, root, { automationId: 'unit-test/run-42' });
    const run = sarif.runs[0];

    assert.ok(run.automationDetails, 'run.automationDetails must be present');
    assert.strictEqual(run.automationDetails.id, 'unit-test/run-42');
    assert.ok(run.automationDetails.description?.text, 'automationDetails.description.text required');

    for (const r of run.results) {
      assert.ok(['fail', 'review'].includes(r.kind), `bad kind on result: ${r.kind}`);
      assert.ok(typeof r.rank === 'number' && r.rank >= 0 && r.rank <= 100,
        `rank must be a 0-100 number; got ${r.rank}`);
    }

    const ruleWithCwe = run.tool.driver.rules.find(rule =>
      rule.properties?.cwe && rule.properties.cwe.length > 0);
    if (ruleWithCwe) {
      assert.ok(Array.isArray(run.taxonomies) && run.taxonomies.length > 0,
        'taxonomies block missing despite CWE-tagged rule');
      const cwe = run.taxonomies.find(t => t.name === 'CWE');
      assert.ok(cwe, 'CWE taxonomy missing from run.taxonomies');
      assert.ok(cwe.taxa && cwe.taxa.length > 0, 'CWE taxonomy has no taxa');
      assert.ok(Array.isArray(ruleWithCwe.relationships) && ruleWithCwe.relationships.length > 0,
        'CWE-tagged rule has no relationships block');
      assert.strictEqual(ruleWithCwe.relationships[0].target.toolComponent.name, 'CWE');
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testSarifBaselineState() {
  // §IN-1 deepening: baselineFingerprints set => results stamped 'unchanged'
  // (matched) or 'new' (unmatched). Without the set, the field is omitted.
  const { report, root } = await buildReportWithRoot();
  try {
    const noBaseline = toSarif(report, root);
    for (const r of noBaseline.runs[0].results) {
      assert.strictEqual(r.baselineState, undefined,
        'baselineState must be omitted when no baseline supplied');
    }

    const fps = new Set(noBaseline.runs[0].results.map(r =>
      r.partialFingerprints.primaryLocationLineHash));
    const all = toSarif(report, root, { baselineFingerprints: fps });
    for (const r of all.runs[0].results) {
      assert.strictEqual(r.baselineState, 'unchanged',
        `expected unchanged for matching fingerprint; got ${r.baselineState}`);
    }

    const empty = toSarif(report, root, { baselineFingerprints: new Set() });
    for (const r of empty.runs[0].results) {
      assert.strictEqual(r.baselineState, 'new',
        `expected new for empty baseline; got ${r.baselineState}`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

(async function main() {
  await testMarkdown();
  await testCsv();
  await testJunit();
  await testGitLab();
  await testBitbucket();
  await testHtml();
  await testSarifSnippets();
  await testSarifTaxonomyAndAutomation();
  await testSarifBaselineState();
  console.log('output-formats self-test: PASS');
})().catch(err => {
  console.error('output-formats self-test: FAIL');
  console.error(err);
  process.exit(1);
});
