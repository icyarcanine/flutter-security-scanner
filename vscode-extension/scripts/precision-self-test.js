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
    report.totalFiles >= 7,
    `totalFiles should be >= 7. Got: ${report.totalFiles}`
  );

  fs.rmSync(root, { recursive: true, force: true });
  console.log('Precision self-test passed.');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
