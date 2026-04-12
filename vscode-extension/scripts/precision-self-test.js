#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProjectScanner } = require('../out/scanner/scanner');

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fsh-sast-'));

  // ── Test files ──────────────────────────────────

  fs.writeFileSync(path.join(root, 'vulnerable.js'), `
const { exec } = require('child_process');

function vulnerableSql(req, db) {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  return db.query(sql);
}

function vulnerableCommand(req) {
  const file = req.params.file;
  const command = \`cat \${file}\`;
  exec(command);
}

const accessKey = "AKIA1234567890ABCDEF";
`);

  fs.writeFileSync(path.join(root, 'safe.js'), `
function parameterized(req, db) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = $1", [id]);
}

const md5 = "d41d8cd98f00b204e9800998ecf8427e";
const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const normal = "This is a normal application string with words and spaces.";
const templateStr = "Hello \${world} this has interpolation markers and is long enough to test.";
const htmlLike = "<div class='container'><span>Hello</span></div>";
`);

  fs.writeFileSync(path.join(root, 'dynamic.js'), `
function dynamicSql(field, db) {
  const sql = "SELECT * FROM users ORDER BY " + field;
  return db.query(sql);
}
`);

  fs.writeFileSync(path.join(root, 'dart_vulnerable.dart'), `
void vulnerableDart(userInput, db) {
  final sql = "SELECT * FROM users WHERE id = $userInput";
  db.rawQuery(sql);
}
`);

  fs.mkdirSync(path.join(root, 'test'), { recursive: true });
  fs.writeFileSync(path.join(root, 'test', 'noise.dart'), `
void noisyTest(userInput, db) {
  final sql = "SELECT * FROM users WHERE id = $userInput";
  db.rawQuery(sql);
}

const token = "AKIAIOSFODNN7EXAMPLE";
`);

  // Empty file — should produce zero findings
  fs.writeFileSync(path.join(root, 'empty.js'), '');

  // Duplicate test — multiple identical patterns on same line
  fs.writeFileSync(path.join(root, 'dedup.js'), `
function dup(req, db) {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  db.query(sql);
}
`);

  // ── Fix 2: reassignment clears taint ────────────
  // After a clean `=` assignment the variable must NOT reach the sink as tainted.
  fs.writeFileSync(path.join(root, 'reassign_clean.js'), `
function testCleanReassign(req, db) {
  let x = req.body.id;
  x = 42;
  db.query(x);
}
`);

  // Augmented assignment (+=) must preserve existing taint on the LHS.
  fs.writeFileSync(path.join(root, 'augmented_assign.js'), `
const { exec } = require('child_process');
function testAugmented(req) {
  let cmd = req.body.cmd;
  cmd += " --flag";
  exec(cmd);
}
`);

  // ── Fix 3: function summary (return param) ───────
  // wrap() directly returns its parameter; result must still be detected as tainted.
  fs.writeFileSync(path.join(root, 'summary_test.js'), `
function wrap(p) {
  return p;
}
function testSummary(req, db) {
  const id = req.body.id;
  const v = wrap(id);
  db.query(v);
}
`);

  // ── Fix 4: Object.assign scalar noise ───────────
  // config.timeout is a safe scalar — must NOT generate a HIGH injection finding.
  fs.writeFileSync(path.join(root, 'object_assign.js'), `
function testObjectAssign(req, db) {
  const config = { timeout: 5000 };
  Object.assign(config, req.body);
  db.query(config.timeout);
}
`);

  // ── Fix 5: indirect taint depth limit ───────────
  // Chain of 4 aliases exceeds MAX_TAINT_DEPTH (3); the final variable must NOT
  // generate a HIGH finding (it may generate MEDIUM via weakTainted/indirect path).
  fs.writeFileSync(path.join(root, 'deep_alias.js'), `
const { exec } = require('child_process');
function testDeepAlias(req) {
  const a = req.body.cmd;
  const b = a;
  const c = b;
  const d = c;
  exec(d);
}
`);

  // ── Scan ────────────────────────────────────────

  const report = await new ProjectScanner(false).scan(root);
  const findings = report.findings;

  // ── MUST DETECT ─────────────────────────────────

  // 1. SQL injection via taint (high confidence)
  assert(
    findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.confidence === 'high' &&
      f.filePath === 'vulnerable.js' &&
      f.astUsed === true),
    `Expected high-confidence tainted SQL/command finding with astUsed=true. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 2. Real secret (AWS key)
  assert(
    findings.some(f =>
      f.code === 'generic-secret' &&
      f.confidence === 'low' &&
      f.filePath === 'vulnerable.js'),
    `Expected low-confidence regex secret finding. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 3. Dynamic SQL without taint proof (medium confidence)
  assert(
    findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'medium' &&
      f.confidence === 'medium' &&
      f.filePath === 'dynamic.js'),
    `Dynamic raw SQL should trigger medium-confidence AST finding. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 4. Dart taint should be AST-backed and high confidence
  assert(
    findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.confidence === 'high' &&
      f.filePath === 'dart_vulnerable.dart' &&
      f.astUsed === true),
    `Expected high-confidence Dart taint finding with astUsed=true. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 5. Test-path Dart findings should be downgraded, not reported as HIGH.
  assert(
    !findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.filePath === 'test/noise.dart'),
    `Test-path Dart finding should not remain HIGH. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 6. Known example credentials in test paths should be suppressed.
  assert(
    !findings.some(f => f.filePath === 'test/noise.dart' && f.code === 'generic-secret'),
    `Example test credentials should be suppressed. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── Fix 2: reassignment ─────────────────────────

  // Clean reassignment must clear taint — no HIGH injection finding expected.
  assert(
    !findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.filePath === 'reassign_clean.js'),
    `Clean reassignment should clear taint — no HIGH injection. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // Augmented assignment must keep taint flowing → HIGH finding expected.
  assert(
    findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.filePath === 'augmented_assign.js' &&
      f.astUsed === true),
    `Augmented assignment should preserve taint — expected HIGH injection. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── Fix 3: function summaries ────────────────────

  // wrap(id) where id is tainted → db.query(v) must be detected.
  assert(
    findings.some(f =>
      f.code === 'injection-flaw' &&
      f.filePath === 'summary_test.js' &&
      f.astUsed === true),
    `Function summary: wrap(tainted) should propagate taint to sink. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── Fix 4: Object.assign scalar noise ───────────

  // config.timeout is a safe scalar even if config is weakly tainted via Object.assign.
  assert(
    !findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.filePath === 'object_assign.js'),
    `Object.assign scalar property (config.timeout) must NOT produce a HIGH injection finding. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── Fix 5: depth limit degrades to non-HIGH ──────

  // A 4-alias chain exceeds MAX_TAINT_DEPTH; must NOT produce a HIGH finding.
  assert(
    !findings.some(f =>
      f.code === 'injection-flaw' &&
      f.severity === 'high' &&
      f.filePath === 'deep_alias.js'),
    `Deep alias chain (depth > MAX) must NOT produce a HIGH injection finding. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── MUST NOT DETECT ─────────────────────────────

  // 7. Hashes should not trigger entropy
  assert(
    !findings.some(f => f.code === 'high-entropy-secret' && f.filePath === 'safe.js'),
    `Hashes, normal strings, templates, or HTML should NOT trigger entropy. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 8. Parameterized queries should not trigger injection
  assert(
    !findings.some(f => f.code === 'injection-flaw' && f.filePath === 'safe.js'),
    `Parameterized query should NOT trigger injection. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // 9. Empty file should produce no findings
  assert(
    !findings.some(f => f.filePath === 'empty.js'),
    `Empty file should produce zero findings. Findings: ${JSON.stringify(findings, null, 2)}`
  );

  // ── DEDUPLICATION ───────────────────────────────

  // 7. No duplicate findings on same code+file+line
  const keys = findings.map(f => `${f.code}|${f.filePath}|${f.line}`);
  const uniqueKeys = new Set(keys);
  assert(
    keys.length === uniqueKeys.size,
    `Duplicate findings detected. Keys: ${JSON.stringify(keys)}`
  );

  // ── AST DIAGNOSTICS ─────────────────────────────

  // 11. AST success rate should be 100% for valid JS + Dart
  assert(
    report.astSuccessRate === 100,
    `AST success rate should be 100% for valid JS + Dart. Got: ${report.astSuccessRate}%`
  );

  // 12. Diagnostics structure
  assert(
    typeof report.astDiagnostics.attempted === 'number',
    `astDiagnostics.attempted should be a number`
  );

  // 13. totalFiles
  assert(
    report.totalFiles >= 12,
    `totalFiles should be >= 12. Got: ${report.totalFiles}`
  );

  fs.rmSync(root, { recursive: true, force: true });
  console.log('Precision self-test passed.');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
