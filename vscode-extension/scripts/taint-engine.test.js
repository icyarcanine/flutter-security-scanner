#!/usr/bin/env node
/**
 * Unit tests for the IntraProceduralTaintTracker.
 *
 * These exercise the engine through the rule pipeline (since the engine's
 * surface is wired to AST + ProjectContext, going around it would require
 * mocking Tree-sitter). Each test sets up a minimal fixture, runs a scan,
 * and asserts on the produced findings.
 *
 * Run:  npm run compile && node scripts/taint-engine.test.js
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProjectScanner } = require('../out/scanner/scanner');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}\n      ${e.stack ?? e.message}`);
    failed++;
  }
}

async function scanWith(files, codeFilter) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'taint-eng-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  const scanner = new ProjectScanner({ includeSuggestions: false });
  const report = await scanner.scan(root);
  fs.rmSync(root, { recursive: true, force: true });
  const filter = codeFilter ?? 'injection-flaw';
  return report.findings.filter(f => f.code === filter);
}

async function main() {
  console.log('Taint engine unit tests:');

  // ── Source tracking ──────────────────────────────────────────────────────

  await test('strong source: req parameter → SQL sink', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { return db.query("SELECT WHERE id = " + req.body.id); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `expected HIGH finding, got: ${JSON.stringify(findings)}`);
  });

  await test('heuristic source `data` requires handler-shape sibling', async () => {
    const findings = await scanWith({
      'a.js': `function process(data, db) { return db.query("SELECT WHERE id = " + data); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `pure helper with 'data' param should NOT produce HIGH; got: ${JSON.stringify(findings)}`);
  });

  await test('heuristic `data` IS tainted with `res` sibling (handler shape)', async () => {
    const findings = await scanWith({
      'a.js': `function h(data, res, db) { return db.query("SELECT WHERE id = " + data); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `expected HIGH finding for handler with 'data' + 'res' sibling`);
  });

  // ── Sanitizer / numeric coercion ────────────────────────────────────────

  await test('parseInt() on tainted source clears taint', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { const id = parseInt(req.body.id); return db.query("WHERE id = " + id); }`,
    });
    assert(findings.length === 0 || !findings.some(f => f.severity === 'high'),
      `parseInt should sanitize: ${JSON.stringify(findings)}`);
  });

  await test('escape()-named function clears taint', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { const safe = sqlstring.escape(req.body.id); return db.query("WHERE id = " + safe); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `escape() should sanitize: ${JSON.stringify(findings)}`);
  });

  // ── SQL receiver heuristic (post-L4 tokenizer) ───────────────────────────

  await test('camelCase `myDb` receiver caught even without literal SQL', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, myDb, q) { const sql = q + " id = " + req.body.id; return myDb.query(sql); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `myDb receiver + tainted arg should flag: ${JSON.stringify(findings)}`);
  });

  await test('bare `analytics.query()` does NOT flag (no DB shape)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, analytics) { return analytics.query(req.body.event); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `analytics.query should NOT flag: ${JSON.stringify(findings)}`);
  });

  await test('`description.query()` not tricked by mid-token "db"', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, description) { return description.query(req.body.q); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `description.query should NOT flag: ${JSON.stringify(findings)}`);
  });

  // ── Sink kinds ───────────────────────────────────────────────────────────

  await test('command sink (exec) flags', async () => {
    const findings = await scanWith({
      'a.js': `const { exec } = require('child_process'); function h(req) { exec("ls " + req.body.f); }`,
    });
    assert(findings.some(f => f.severity === 'high' && f.cwe === 'CWE-78'),
      `exec sink should flag CWE-78: ${JSON.stringify(findings)}`);
  });

  await test('eval sink flags', async () => {
    const findings = await scanWith({
      'a.js': `function h(req) { return eval(req.body.code); }`,
    });
    assert(findings.some(f => f.severity === 'high' && f.cwe === 'CWE-95'),
      `eval sink should flag CWE-95: ${JSON.stringify(findings)}`);
  });

  await test('SSRF (fetch) flags only on confirmed taint, not dynamic-only', async () => {
    const tainted = await scanWith({
      'a.js': `function h(req) { return fetch(req.body.url); }`,
    });
    assert(tainted.some(f => f.cwe === 'CWE-918'),
      `tainted fetch should flag CWE-918: ${JSON.stringify(tainted)}`);

    const dynamic = await scanWith({
      'a.js': `function h(prefix, suffix) { return fetch(prefix + suffix); }`,
    });
    assert(!dynamic.some(f => f.cwe === 'CWE-918'),
      `dynamic fetch (no source) should NOT flag SSRF: ${JSON.stringify(dynamic)}`);
  });

  // ── Reassignment / augmented assignment ──────────────────────────────────

  await test('clean reassignment clears taint', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { let x = req.body.id; x = 42; return db.query("WHERE id = " + x); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `clean reassign should clear taint: ${JSON.stringify(findings)}`);
  });

  await test('augmented assignment preserves taint', async () => {
    const findings = await scanWith({
      'a.js': `const { exec } = require('child_process'); function h(req) { let cmd = req.body.cmd; cmd += " --flag"; exec(cmd); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `augmented assign should preserve taint: ${JSON.stringify(findings)}`);
  });

  // ── Parameterized queries ────────────────────────────────────────────────

  await test('parameterized query with positional placeholders is safe', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { return db.query("SELECT * FROM u WHERE id = $1", [req.body.id]); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `parameterized query should NOT flag: ${JSON.stringify(findings)}`);
  });

  // ── New-rule coverage ────────────────────────────────────────────────────
  // One assertion per rule, both happy-path and a known FP scenario.

  await test('insecure-random fires on Math.random() bound to a security identifier', async () => {
    const f = await scanWith({ 'a.js': `const token = Math.random().toString(36);` }, 'insecure-random');
    assert(f.length === 1 && f[0].cwe === 'CWE-338',
      `expected 1 insecure-random with CWE-338: ${JSON.stringify(f)}`);
  });

  await test('insecure-random does NOT fire on benign Math.random()', async () => {
    const f = await scanWith({ 'a.js': `const x = Math.random();` }, 'insecure-random');
    assert(f.length === 0, `expected 0 findings, got: ${JSON.stringify(f)}`);
  });

  await test('jwt-misuse: jwt.decode() flagged with CWE-347', async () => {
    const f = await scanWith({ 'a.js': `const d = jwt.decode(req.headers.authorization);` }, 'jwt-misuse');
    assert(f.some(x => x.cwe === 'CWE-347'),
      `expected jwt-misuse CWE-347: ${JSON.stringify(f)}`);
  });

  await test('jwt-misuse: algorithms: ["none"] flagged', async () => {
    const f = await scanWith({ 'a.js': `jwt.verify(t, s, { algorithms: ['none'] });` }, 'jwt-misuse');
    assert(f.length >= 1, `expected jwt-misuse: ${JSON.stringify(f)}`);
  });

  await test('jwt-misuse: variable holding literal secret flagged', async () => {
    const f = await scanWith({
      'a.js': `const SECRET = "hardcoded-jwt-secret-v1";\nconst t = jwt.sign({}, SECRET);`,
    }, 'jwt-misuse');
    assert(f.some(x => x.message.includes("'SECRET'")),
      `expected variable-secret detection: ${JSON.stringify(f)}`);
  });

  await test('insecure-cookie: nested options object still flagged', async () => {
    const f = await scanWith({
      'a.js': `res.cookie('sid', v, { domain: { a: 1 }, httpOnly: false, secure: false });`,
    }, 'insecure-cookie');
    assert(f.length === 2, `expected 2 cookie findings (httpOnly+secure), got: ${JSON.stringify(f)}`);
  });

  await test('insecure-cookie: safe cookie produces nothing', async () => {
    const f = await scanWith({
      'a.js': `res.cookie('sid', v, { httpOnly: true, secure: true, sameSite: 'lax' });`,
    }, 'insecure-cookie');
    assert(f.length === 0, `expected 0 findings: ${JSON.stringify(f)}`);
  });

  await test('cors-misconfig: cors() with origin:true + credentials:true flagged', async () => {
    const f = await scanWith({
      'a.js': `app.use(cors({ origin: true, credentials: true }));`,
    }, 'cors-misconfig');
    assert(f.length === 1 && f[0].cwe === 'CWE-942',
      `expected cors-misconfig CWE-942: ${JSON.stringify(f)}`);
  });

  await test('cors-misconfig: wildcard alone (no credentials) is NOT flagged', async () => {
    const f = await scanWith({
      'a.js': `res.setHeader("Access-Control-Allow-Origin", "*");`,
    }, 'cors-misconfig');
    assert(f.length === 0,
      `wildcard alone is intentional for public APIs: ${JSON.stringify(f)}`);
  });

  // ── Comment-line FP guard for new rules ─────────────────────────────────

  await test('new rules ignore commented-out vulnerabilities', async () => {
    const allCodes = ['insecure-random', 'jwt-misuse', 'insecure-cookie', 'cors-misconfig'];
    for (const code of allCodes) {
      const f = await scanWith({
        'a.js': `// const tok = Math.random();\n// jwt.decode(req.body);\n// res.cookie('s', v, { httpOnly: false });\n// res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Credentials", "true");`,
      }, code);
      assert(f.length === 0, `${code} should ignore comments: ${JSON.stringify(f)}`);
    }
  });

  // ── Concurrency safety ──────────────────────────────────────────────────
  // The F34 Promise.all rule scheduler exposes any race in the AST cache.
  // This invokes scan() against a fixture that triggers multiple AST-using
  // rules on the same file simultaneously and asserts the scanner produces
  // a stable, consistent finding set across many parallel runs.

  // ── git porcelain parsing (regression for changed-since bug) ───────────
  // Verifies that the porcelain line format `" M file.js"` (space at byte 2)
  // is parsed without trimming first — naive `.trim().substring(3)` would
  // turn "server.js" into "erver.js" and break filtering.

  await test('git status --porcelain shape parses without losing leading char', async () => {
    // Direct unit test on the parsing logic. We can't easily import the
    // helper from the bundled CLI, so we duplicate the parse one-liner
    // and lock in the contract.
    const dirty = ' M server.js\n?? new.js\nR  old.js -> new/path.js\n';
    const set = new Set();
    for (const line of dirty.split('\n')) {
      if (line.length < 4) continue;
      const arrow = line.indexOf(' -> ');
      const raw = arrow !== -1 ? line.substring(arrow + 4) : line.substring(3);
      const filePath = raw.replace(/^"|"$/g, '').trim();
      if (filePath) set.add(filePath);
    }
    assert(set.has('server.js'), `expected 'server.js'; got: ${[...set].join(',')}`);
    assert(set.has('new.js'),    `expected 'new.js'; got: ${[...set].join(',')}`);
    assert(set.has('new/path.js'), `expected rename target 'new/path.js'; got: ${[...set].join(',')}`);
  });

  await test('parallel scans of the same fixture produce identical findings', async () => {
    const fixture = {
      'a.js': `function h(req, db) { return db.query("SELECT * FROM u WHERE id = " + req.body.id); }`,
      'b.js': `function h(req) { return eval(req.body.code); }`,
    };
    const runs = await Promise.all([
      scanWith(fixture), scanWith(fixture), scanWith(fixture), scanWith(fixture),
    ]);
    const sigs = runs.map(rs => rs.map(f => `${f.code}:${f.line}:${f.column ?? 0}`).sort().join('|'));
    const allEqual = sigs.every(s => s === sigs[0]);
    assert(allEqual,
      `parallel scans diverged. Signatures:\n${sigs.map((s, i) => `  run ${i}: ${s}`).join('\n')}`);
    assert(runs[0].length >= 2,
      `expected at least 2 findings per run, got ${runs[0].length}`);
  });

  console.log(`\n  ${passed} passed, ${failed} failed`);
  if (failed > 0) { process.exit(1); }
}

main().catch(e => { console.error(e); process.exit(1); });
