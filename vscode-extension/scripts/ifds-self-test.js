#!/usr/bin/env node
/**
 * IFDS taint engine self-test.
 *
 * Covers the following cases over real Dart fixture files, driven through
 * the same ProjectScanner pipeline the VS Code extension uses:
 *
 *   1. Intra-procedural: source and sink in one function.
 *   2. Inter-procedural: source in caller, sink in callee via direct call.
 *   3. Sanitizer negative: sanitized value must NOT reach the sink.
 *   4. Branching (if/else): taint in ONE branch must still reach the sink
 *      (soundness — a linear-flatten CFG would miss this).
 *   5. Reassignment negative: tainted var overwritten by a constant must
 *      NOT reach the sink (strong-kill).
 *   6. Class method: taint into a sink inside a class-body method.
 *   7. Sink with LHS: `final rows = db.rawQuery(userInput);` still fires.
 *   8. For-each: tainted collection loop-var into a sink inside the loop.
 *   9. Multi-file ICFG: source in file A, callee in file B.
 *  10. Parse-error robustness: a malformed .dart file next to valid files
 *      does not kill the scan; legitimate findings still come back.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProjectScanner } = require('../out/scanner/scanner');

function writeFixtures(root) {
  // 1. intra
  fs.writeFileSync(path.join(root, 'taint_intra.dart'), `
void vulnIntra(String userInput, db) {
  final sql = "SELECT * FROM users WHERE id = $userInput";
  db.rawQuery(sql);
}
`);
  // 2. inter
  fs.writeFileSync(path.join(root, 'taint_inter.dart'), `
String makeSql(String userInput) {
  return "SELECT * FROM users WHERE id = $userInput";
}
void callerInter(String userInput, db) {
  final sql = makeSql(userInput);
  db.rawQuery(sql);
}
`);
  // 3. sanitizer
  fs.writeFileSync(path.join(root, 'taint_sanitized.dart'), `
String sanitize(String x) {
  return x;
}
void vulnSanitized(String userInput, db) {
  final clean = sanitize(userInput);
  db.rawQuery(clean);
}
`);
  // 4. if/else — must STILL fire (taint in one branch must be observed)
  fs.writeFileSync(path.join(root, 'taint_branch.dart'), `
void vulnBranch(String userInput, db, bool flag) {
  String x = "safe";
  if (flag) {
    x = userInput;
  } else {
    x = "also_safe";
  }
  db.rawQuery(x);
}
`);
  // 5. reassignment — must NOT fire
  fs.writeFileSync(path.join(root, 'taint_reassign.dart'), `
void vulnReassign(String userInput, db) {
  String x = userInput;
  x = "constant_safe";
  db.rawQuery(x);
}
`);
  // 6. class method
  fs.writeFileSync(path.join(root, 'taint_class.dart'), `
class ApiHandler {
  final db;
  ApiHandler(this.db);
  void handle(String userInput) {
    db.rawQuery(userInput);
  }
}
`);
  // 7. sink with LHS
  fs.writeFileSync(path.join(root, 'taint_sink_lhs.dart'), `
void vulnSinkLhs(String userInput, db) {
  final rows = db.rawQuery(userInput);
  print(rows);
}
`);
  // 8. for-each — loop var inherits taint from the collection expression
  fs.writeFileSync(path.join(root, 'taint_for.dart'), `
void vulnFor(List<String> userInput, db) {
  for (var item in userInput) {
    db.rawQuery(item);
  }
}
`);
  // 9. multi-file ICFG (split across two files in the same scan)
  fs.writeFileSync(path.join(root, 'taint_mf_helper.dart'), `
String buildSql(String userInput) {
  return "SELECT * FROM t WHERE id = $userInput";
}
`);
  fs.writeFileSync(path.join(root, 'taint_mf_main.dart'), `
import 'taint_mf_helper.dart';
void vulnMulti(String userInput, db) {
  final sql = buildSql(userInput);
  db.rawQuery(sql);
}
`);
  // 10. deliberately-broken Dart — must not crash the scan
  fs.writeFileSync(path.join(root, 'broken.dart'), `
this is not ??? valid dart {{{{ syntax at all $$ <<<<< >>>>>>>
void  (
`);
  // 11. inline-suppression: `// sast-ignore ifds-taint` on the line above
  //     the sink must drop the finding. Regression-locks that consumers
  //     can silence IFDS findings the same way they silence every other
  //     rule in the scanner.
  fs.writeFileSync(path.join(root, 'taint_suppressed.dart'), `
void vulnSuppressed(String userInput, db) {
  final sql = "SELECT * FROM users WHERE id = $userInput";
  // sast-ignore ifds-taint
  db.rawQuery(sql);
}
`);
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fsh-ifds-'));
  writeFixtures(root);

  const report = await new ProjectScanner(false).scan(root);
  const ifds = report.findings.filter(f => f.code === 'ifds-taint');

  const dump = JSON.stringify(
    ifds.map(f => ({ file: f.filePath, line: f.line, msg: f.message, sev: f.severity, conf: f.confidence })),
    null, 2);

  const has = (file) => ifds.some(f =>
    f.filePath === file && f.severity === 'high' && f.confidence === 'high');
  const lacks = (file) => !ifds.some(f => f.filePath === file);

  // 1. intra
  assert(has('taint_intra.dart'),
    `1. intra-procedural taint must be detected. Findings: ${dump}`);
  // 2. inter
  assert(has('taint_inter.dart'),
    `2. inter-procedural taint must be detected. Findings: ${dump}`);
  // 3. sanitizer negative
  assert(lacks('taint_sanitized.dart'),
    `3. sanitized path must NOT be reported. Findings: ${dump}`);
  // 4. branching (if/else) — soundness
  assert(has('taint_branch.dart'),
    `4. if/else branching: taint in one branch must reach sink. Findings: ${dump}`);
  // 5. reassignment negative — strong-kill
  assert(lacks('taint_reassign.dart'),
    `5. reassignment to a constant must NOT be reported (strong kill). Findings: ${dump}`);
  // 6. class method
  assert(has('taint_class.dart'),
    `6. class method taint must be detected. Findings: ${dump}`);
  // 7. sink with lhs
  assert(has('taint_sink_lhs.dart'),
    `7. sink assigned to LHS must still fire. Findings: ${dump}`);
  // 8. for-each
  assert(has('taint_for.dart'),
    `8. for-each loop-var inheriting taint must fire. Findings: ${dump}`);
  // 9. multi-file ICFG
  assert(has('taint_mf_main.dart'),
    `9. multi-file inter-procedural taint must fire. Findings: ${dump}`);
  // 10. broken file tolerance — the scan must have completed, other findings
  //     must be present, and no finding attributed to broken.dart is expected.
  assert(ifds.length >= 7,
    `10. Broken file must not block other findings. Got ${ifds.length}. ${dump}`);
  // 11. inline-suppression: `// sast-ignore ifds-taint` above the sink
  //     must suppress the finding even though the engine would otherwise
  //     fire (same fixture shape as case 1, plus one comment line).
  assert(lacks('taint_suppressed.dart'),
    `11. inline sast-ignore must suppress ifds-taint findings. Findings: ${dump}`);

  fs.rmSync(root, { recursive: true, force: true });
  console.log(`IFDS self-test passed. ${ifds.length} taint finding(s).`);
  for (const f of ifds) {
    console.log(`  - ${f.filePath}:${f.line} [${f.severity}/${f.confidence}] ${f.message}`);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
