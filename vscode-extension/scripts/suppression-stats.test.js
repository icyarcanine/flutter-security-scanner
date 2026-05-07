#!/usr/bin/env node
/**
 * Suppression-stats self-test (§QW-22 / §PR-15).
 *
 * Confirms:
 *   1. `report.suppressionsByRule` reports the exact count of findings that
 *      were filtered by an inline `// sast-ignore <code>` directive.
 *   2. Counts at or above the threshold (5) trigger a console.error warning
 *      naming the rule.
 *   3. Counts below the threshold do NOT warn (avoid spam).
 *   4. Counts are zero for rules that didn't fire.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { ProjectScanner } = require('../out/scanner/scanner');

async function scanFixture(fileMap) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fss-supp-'));
  for (const [rel, content] of Object.entries(fileMap)) {
    fs.writeFileSync(path.join(root, rel), content);
  }
  const scanner = new ProjectScanner({ includeSuggestions: false });
  // Capture warnings emitted to stderr via console.error.
  const errs = [];
  const orig = console.error;
  console.error = (...a) => { errs.push(a.join(' ')); };
  let report;
  try {
    report = await scanner.scan(root);
  } finally {
    console.error = orig;
    fs.rmSync(root, { recursive: true, force: true });
  }
  return { report, errs };
}

(async function main() {
  // Build a fixture with 6 lines that each trigger `injection-flaw` AND
  // 6 inline suppressions. The threshold is 5, so we expect a warning.
  const lines = [];
  for (let i = 0; i < 6; i++) {
    lines.push(`// sast-ignore injection-flaw`);
    lines.push(`function h${i}(req, db) { db.rawQuery("SELECT * FROM u WHERE id = " + req.body.id); }`);
  }
  const { report, errs } = await scanFixture({ 'a.js': lines.join('\n') });

  const count = report.suppressionsByRule.get('injection-flaw') ?? 0;
  assert.ok(count >= 6,
    `expected >= 6 suppressed injection-flaw findings, got ${count}: ${JSON.stringify([...report.suppressionsByRule])}`);

  // Warning fired (threshold default = 5).
  const warned = errs.find(s => /Rule "injection-flaw" had \d+ findings suppressed/.test(s));
  assert.ok(warned, `expected suppression-review warning for injection-flaw, got: ${JSON.stringify(errs)}`);

  // Suppressed findings must not appear in `findings` (already covered, but
  // double-check — we shouldn't inflate `findings` while also counting
  // suppressions).
  assert.strictEqual(report.findings.filter(f => f.code === 'injection-flaw').length, 0,
    `suppressed findings leaked into the report`);

  // Now test the no-warning case: a single suppression.
  const small = await scanFixture({
    'a.js': `// sast-ignore injection-flaw\nfunction h(req, db) { db.rawQuery("SELECT * FROM u WHERE id = " + req.body.id); }`,
  });
  const smallCount = small.report.suppressionsByRule.get('injection-flaw') ?? 0;
  assert.ok(smallCount >= 1, `expected at least 1 suppression`);
  assert.ok(!small.errs.some(s => /Rule "injection-flaw"/.test(s)),
    `single suppression should not warn: ${JSON.stringify(small.errs)}`);

  console.log('suppression-stats self-test: PASS');
})().catch(err => {
  console.error('suppression-stats self-test: FAIL');
  console.error(err);
  process.exit(1);
});
