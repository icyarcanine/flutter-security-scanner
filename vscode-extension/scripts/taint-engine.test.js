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

  await test('numeric coercion idioms clear taint for injection sinks (QW-11 / PR-18)', async () => {
    const findings = await scanWith({
      'a.js': `
        function h(req, db) {
          const a = Number(req.body.a);
          const b = +req.body.b;
          const c = ~~req.body.c;
          const d = req.body.d | 0;
          const e = req.body.e >>> 0;
          db.query("WHERE a=" + a);
          db.query("WHERE b=" + b);
          db.query("WHERE c=" + c);
          db.query("WHERE d=" + d);
          db.query("WHERE e=" + e);
        }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `numeric coercion should sanitize: ${JSON.stringify(findings)}`);
  });

  await test('String.replace sanitizer regex clears taint (QW-38 / EN-14)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { const slug = req.query.slug.replace(/[^A-Za-z0-9_-]/g, ''); return db.query("WHERE slug = '" + slug + "'"); }`,
    });
    assert(!findings.some(f => f.severity === 'high'),
      `sanitizing replace should clear taint: ${JSON.stringify(findings)}`);
  });

  await test('JSON.parse propagates taint (QW-39 / EN-14)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, db) { const parsed = JSON.parse(req.body.payload); return db.query("WHERE id = " + parsed.id); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `JSON.parse(taint) should propagate taint: ${JSON.stringify(findings)}`);
  });

  await test('URLSearchParams.get literal is treated as tainted (QW-40 / EN-14)', async () => {
    const findings = await scanWith({
      'a.js': `function h(db) { const params = new URLSearchParams(location.search); const id = params.get('id'); return db.query("WHERE id = " + id); }`,
    });
    assert(findings.some(f => f.severity === 'high'),
      `URLSearchParams.get should be treated as tainted: ${JSON.stringify(findings)}`);
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

  await test('setTimeout string-form code execution flags (QW-45)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req) { setTimeout(req.body.code, 10); }`,
    });
    assert(findings.some(f => f.severity === 'high' && f.cwe === 'CWE-95' &&
      /setTimeout/i.test(f.message)),
      `setTimeout(taint) should flag CWE-95: ${JSON.stringify(findings)}`);
  });

  await test('setTimeout callback form is fine (QW-45)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req) { setTimeout(() => console.log(req.body.code), 10); }`,
    });
    assert(!findings.some(f => /setTimeout/i.test(f.message)),
      `setTimeout(callback) should not flag code execution: ${JSON.stringify(findings)}`);
  });

  await test('dynamic import(taint) flags as code sink (QW-3 / RC-50)', async () => {
    // CodeQL classifies dynamic ESM import of an attacker-controlled module
    // path as code-injection (CWE-95) because the loaded module's top-level
    // code runs.
    const findings = await scanWith({
      'a.js': `async function h(req) { return await import('./mods/' + req.body.name); }`,
    });
    assert(findings.some(f => f.severity === 'high' && f.cwe === 'CWE-95' &&
      /import/i.test(f.message)),
      `dynamic import(taint) should flag CWE-95: ${JSON.stringify(findings)}`);
  });

  await test('static `import { x } from "..."` does NOT flag (QW-3 / RC-50)', async () => {
    // The static-import statement is parsed as `import_statement`, not as a
    // call_expression with `import` as callee. Verify the rule doesn't
    // accidentally fire on it.
    const findings = await scanWith({
      'a.js': `import { x } from './mod'; function h(req) { return req.body.code; }`,
    });
    assert(!findings.some(f => /import/i.test(f.message)),
      `static import should not flag: ${JSON.stringify(findings)}`);
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

  await test('jwt-misuse: HS algorithm with public key variable flagged (QW-23 / RC-60)', async () => {
    const f = await scanWith({
      'a.js': `const publicKey = fs.readFileSync('public.pem');\njwt.verify(token, publicKey, { algorithms: ['HS256'] });`,
    }, 'jwt-misuse');
    assert(f.some(x => /public-key-like/.test(x.message) && x.cwe === 'CWE-347'),
      `expected JWT algorithm-confusion detection: ${JSON.stringify(f)}`);
  });

  await test('jwt-misuse: RS256 with public key is fine', async () => {
    const f = await scanWith({
      'a.js': `const publicKey = fs.readFileSync('public.pem');\njwt.verify(token, publicKey, { algorithms: ['RS256'] });`,
    }, 'jwt-misuse');
    assert(!f.some(x => /public-key-like/.test(x.message)),
      `RS256 public-key verifier should not flag alg confusion: ${JSON.stringify(f)}`);
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

  await test('hardcoded-ip: public IPv4 flagged (QW-4 / RC-58)', async () => {
    const findings = await scanWith({
      'a.js': `const HOST = "8.8.8.8"; const url = "https://" + HOST;`,
    }, 'hardcoded-ip');
    assert(findings.some(f => f.message.includes('8.8.8.8') && f.cwe === 'CWE-547'),
      `public IPv4 8.8.8.8 should flag: ${JSON.stringify(findings)}`);
  });

  await test('hardcoded-ip: private + loopback NOT flagged (QW-4 / RC-58)', async () => {
    const findings = await scanWith({
      'a.js': `const local = "127.0.0.1"; const lan = "192.168.1.1"; const ten = "10.0.0.5"; const cgnat = "100.64.0.1"; const docTest = "203.0.113.4";`,
    }, 'hardcoded-ip');
    assert.strictEqual(findings.length, 0,
      `private/loopback/CGNAT/doc IPs should not flag: ${JSON.stringify(findings)}`);
  });

  await test('hardcoded-ip: example IP in // comment is ignored', async () => {
    const findings = await scanWith({
      'a.js': `// example: 8.8.8.8 is a public DNS\nconst x = 1;`,
    }, 'hardcoded-ip');
    assert.strictEqual(findings.length, 0,
      `IPs inside line comments must not flag: ${JSON.stringify(findings)}`);
  });

  await test('hardcoded-ip: public IPv6 flagged, link-local + doc NOT flagged', async () => {
    const flagged = await scanWith({
      'a.js': `const dns = "2606:4700:4700::1111";`,
    }, 'hardcoded-ip');
    assert(flagged.some(f => /2606:4700:4700::1111/.test(f.message)),
      `public IPv6 should flag: ${JSON.stringify(flagged)}`);

    const safe = await scanWith({
      'a.js': `const a = "::1"; const b = "fe80::1"; const c = "2001:db8::1"; const d = "fd12:3456::1";`,
    }, 'hardcoded-ip');
    assert.strictEqual(safe.length, 0,
      `loopback/link-local/doc/ULA IPv6 should not flag: ${JSON.stringify(safe)}`);
  });

  await test('hardcoded-ip: version strings like 1.2.3.4 require valid octets — 256.1.1.1 ignored', async () => {
    const findings = await scanWith({
      'a.js': `const v = "256.1.1.1"; const w = "1.2.3.4.5";`,
    }, 'hardcoded-ip');
    assert.strictEqual(findings.length, 0,
      `invalid octets / extra parts should not flag: ${JSON.stringify(findings)}`);
  });

  await test('improper-cert-validation: rejectUnauthorized:false flagged (QW-5 / RC-43)', async () => {
    const findings = await scanWith({
      'a.js': `const ax = require('axios'); ax.get('https://x', { rejectUnauthorized: false });`,
    }, 'improper-cert-validation');
    assert(findings.some(f => f.severity === 'high' && f.cwe === 'CWE-295' &&
      /rejectUnauthorized/.test(f.message)),
      `rejectUnauthorized:false should flag CWE-295: ${JSON.stringify(findings)}`);
  });

  await test('improper-cert-validation: NODE_TLS_REJECT_UNAUTHORIZED=0 flagged', async () => {
    const findings = await scanWith({
      'a.js': `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`,
    }, 'improper-cert-validation');
    assert(findings.some(f => /NODE_TLS_REJECT_UNAUTHORIZED/.test(f.message)),
      `env opt-out should flag: ${JSON.stringify(findings)}`);
  });

  await test('improper-cert-validation: checkServerIdentity stub flagged', async () => {
    const findings = await scanWith({
      'a.js': `const opts = { checkServerIdentity: () => undefined };`,
    }, 'improper-cert-validation');
    assert(findings.some(f => /checkServerIdentity/.test(f.message)),
      `checkServerIdentity stub should flag: ${JSON.stringify(findings)}`);
  });

  await test('improper-cert-validation: rejectUnauthorized:true is fine', async () => {
    const findings = await scanWith({
      'a.js': `const opts = { rejectUnauthorized: true };`,
    }, 'improper-cert-validation');
    assert.strictEqual(findings.length, 0,
      `rejectUnauthorized:true should not flag: ${JSON.stringify(findings)}`);
  });

  await test('tabnabbing: <a target="_blank"> without rel flags (QW-6 / RC-13)', async () => {
    const findings = await scanWith({
      'a.tsx': `export const L = () => <a href="https://x" target="_blank">go</a>;`,
    }, 'tabnabbing');
    assert(findings.some(f => f.cwe === 'CWE-1022' && /target="_blank"/.test(f.message)),
      `<a target=_blank without rel should flag: ${JSON.stringify(findings)}`);
  });

  await test('tabnabbing: rel="noopener" suppresses', async () => {
    const findings = await scanWith({
      'a.tsx': `export const L = () => <a href="https://x" target="_blank" rel="noopener noreferrer">go</a>;`,
    }, 'tabnabbing');
    assert.strictEqual(findings.length, 0,
      `safe rel="noopener noreferrer" should not flag: ${JSON.stringify(findings)}`);
  });

  await test('tabnabbing: window.open(_blank) without noopener flags', async () => {
    const findings = await scanWith({
      'a.js': `function go(url) { window.open(url, '_blank'); }`,
    }, 'tabnabbing');
    assert(findings.some(f => /window\.open/.test(f.message)),
      `window.open(_blank) should flag: ${JSON.stringify(findings)}`);
  });

  await test('tabnabbing: window.open with noopener feature is fine', async () => {
    const findings = await scanWith({
      'a.js': `function go(url) { window.open(url, '_blank', 'noopener,noreferrer'); }`,
    }, 'tabnabbing');
    assert.strictEqual(findings.length, 0,
      `safe window.open should not flag: ${JSON.stringify(findings)}`);
  });

  await test('cleartext-http: fetch("http://api.example.com") flagged (QW-7 / RC-19)', async () => {
    const findings = await scanWith({
      'a.js': `function load() { return fetch('http://api.example.com/data'); }`,
    }, 'cleartext-http');
    assert(findings.some(f => f.cwe === 'CWE-319' && /api\.example\.com/.test(f.message)),
      `cleartext fetch should flag CWE-319: ${JSON.stringify(findings)}`);
  });

  await test('cleartext-http: localhost / 127.0.0.1 / 192.168 NOT flagged', async () => {
    const findings = await scanWith({
      'a.js': `fetch('http://localhost:3000/x'); fetch('http://127.0.0.1:8080/y'); fetch('http://192.168.1.10/z'); fetch('http://10.0.0.5/q');`,
    }, 'cleartext-http');
    assert.strictEqual(findings.length, 0,
      `loopback / RFC1918 cleartext should not flag: ${JSON.stringify(findings)}`);
  });

  await test('cleartext-http: comment text is ignored', async () => {
    const findings = await scanWith({
      'a.js': `// fetch('http://example.com') from old code\nconst x = 1;`,
    }, 'cleartext-http');
    assert.strictEqual(findings.length, 0,
      `comment text should not flag: ${JSON.stringify(findings)}`);
  });

  await test('cleartext-http: https:// URLs are fine', async () => {
    const findings = await scanWith({
      'a.js': `fetch('https://api.example.com/x');`,
    }, 'cleartext-http');
    assert.strictEqual(findings.length, 0,
      `https should not flag: ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: createHash("md5") flagged (QW-8 / RC-20)', async () => {
    const findings = await scanWith({
      'a.js': `const h = crypto.createHash('md5').update(x).digest('hex');`,
    }, 'weak-crypto-js');
    assert(findings.some(f => f.cwe === 'CWE-327' && /md5/i.test(f.message)),
      `MD5 createHash should flag CWE-327: ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: aes-256-ecb flagged', async () => {
    const findings = await scanWith({
      'a.js': `const c = crypto.createCipheriv('aes-256-ecb', key, null);`,
    }, 'weak-crypto-js');
    assert(findings.some(f => /ECB/i.test(f.message)),
      `aes-256-ecb should flag: ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: CryptoJS.MD5 / mode.ECB on separate lines flag', async () => {
    const findings = await scanWith({
      'a.js': `const h = CryptoJS.MD5(x);\nconst o = { mode: CryptoJS.mode.ECB };`,
    }, 'weak-crypto-js');
    assert.strictEqual(findings.length, 2,
      `CryptoJS MD5 + mode.ECB should produce 2 findings (one per line): ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: createHash("sha256") is fine', async () => {
    const findings = await scanWith({
      'a.js': `const h = crypto.createHash('sha256');`,
    }, 'weak-crypto-js');
    assert.strictEqual(findings.length, 0,
      `SHA-256 should not flag: ${JSON.stringify(findings)}`);
  });

  await test('generic-secret: Stripe live key flagged (QW-9 / RC-21)', async () => {
    const stripeLiveKey = ['sk', 'live', 'AbCdEfGhIjKlMnOpQrStUvWxYz1234567890'].join('_');
    const findings = await scanWith({
      'a.js': `const stripe = "${stripeLiveKey}";`,
    }, 'generic-secret');
    assert(findings.some(f => /Stripe/.test(f.message) && f.confidence === 'high'),
      `Stripe sk_live should flag HIGH: ${JSON.stringify(findings)}`);
  });

  await test('generic-secret: Twilio SID flagged', async () => {
    const twilioSid = 'AC' + '1234567890abcdef1234567890abcdef';
    const findings = await scanWith({
      'a.js': `const sid = "${twilioSid}";`,
    }, 'generic-secret');
    assert(findings.some(f => /Twilio/.test(f.message)),
      `Twilio SID should flag: ${JSON.stringify(findings)}`);
  });

  await test('generic-secret: SendGrid API key flagged', async () => {
    const sendGridKey =
      'SG' + '.aBcDeFgHiJkLmNoPqRsTuV.' + 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHI';
    const findings = await scanWith({
      'a.js': `const sg = "${sendGridKey}";`,
    }, 'generic-secret');
    assert(findings.some(f => /SendGrid/.test(f.message)),
      `SendGrid key should flag: ${JSON.stringify(findings)}`);
  });

  await test('generic-secret: OpenAI / Anthropic / GitHub / Slack tokens flagged', async () => {
    const findings = await scanWith({
      'a.js': [
        'const oa = "sk-proj-' + 'a'.repeat(48) + '";',
        'const an = "sk-ant-api03-' + 'b'.repeat(80) + '";',
        'const gh = "ghp_' + 'c'.repeat(36) + '";',
        'const sl = "xoxb-' + 'd'.repeat(20) + '";',
      ].join('\n'),
    }, 'generic-secret');
    const messages = findings.map(f => f.message).join('\n');
    assert(/OpenAI/.test(messages), `OpenAI: ${messages}`);
    assert(/Anthropic/.test(messages), `Anthropic: ${messages}`);
    assert(/GitHub/.test(messages), `GitHub: ${messages}`);
    assert(/Slack/.test(messages), `Slack: ${messages}`);
  });

  await test('header-injection: res.setHeader(name, taint) flagged (QW-10 / RC-4)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { res.setHeader('X-Echo', req.body.echo); }`,
    });
    assert(findings.some(f => f.code === 'injection-flaw' && f.cwe === 'CWE-113' &&
      /header/.test(f.message)),
      `res.setHeader(taint) should flag CWE-113: ${JSON.stringify(findings)}`);
  });

  await test('header-injection: res.cookie(name, taint) flagged', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { res.cookie('session', req.query.s); }`,
    });
    assert(findings.some(f => f.cwe === 'CWE-113'),
      `res.cookie(taint) should flag: ${JSON.stringify(findings)}`);
  });

  await test('header-injection: res.location(taint) flagged with CWE-113 (header takes precedence over redirect)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { res.location(req.body.url); }`,
    });
    assert(findings.some(f => f.cwe === 'CWE-113'),
      `res.location(taint) should now flag CWE-113: ${JSON.stringify(findings)}`);
  });

  await test('header-injection: encodeURIComponent sanitizes', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { res.setHeader('X-Echo', encodeURIComponent(req.body.echo)); }`,
    });
    assert(!findings.some(f => f.cwe === 'CWE-113'),
      `encodeURIComponent should sanitize: ${JSON.stringify(findings)}`);
  });

  // ── §QW-32 / §RC-44 — crypto.createCipher (no IV / weak KDF) ────────────
  await test('weak-crypto-js: crypto.createCipher (no IV) flagged (QW-32 / RC-44)', async () => {
    const findings = await scanWith({
      'a.js': `const c = crypto.createCipher('aes-256-cbc', password);`,
    }, 'weak-crypto-js');
    assert(findings.some(f => /createCipher/.test(f.message) && f.severity === 'high'),
      `createCipher should flag HIGH: ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: createCipheriv (with IV) is fine', async () => {
    const findings = await scanWith({
      'a.js': `const c = crypto.createCipheriv('aes-256-gcm', key, iv);`,
    }, 'weak-crypto-js');
    assert.strictEqual(findings.length, 0,
      `createCipheriv with proper algo should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-29 / §RC-48 — TLSv1 / SSLv3 ─────────────────────────────────────
  await test('weak-crypto-js: secureProtocol: "TLSv1" flagged (QW-29 / RC-48)', async () => {
    const findings = await scanWith({
      'a.js': `https.createServer({ secureProtocol: 'TLSv1_method' }, h);`,
    }, 'weak-crypto-js');
    assert(findings.some(f => /TLS\/SSL pinned/i.test(f.message)),
      `TLSv1_method should flag: ${JSON.stringify(findings)}`);
  });

  await test('weak-crypto-js: minVersion: "TLSv1.2" is fine', async () => {
    const findings = await scanWith({
      'a.js': `tls.createServer({ minVersion: 'TLSv1.2' });`,
    }, 'weak-crypto-js');
    assert.strictEqual(findings.length, 0,
      `TLSv1.2 should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-31 / §RC-45 — leading-dot cookie domain ────────────────────────
  await test('insecure-cookie: leading-dot domain flagged (QW-31 / RC-45)', async () => {
    const findings = await scanWith({
      'a.js': `res.cookie('sid', s, { domain: '.example.com', secure: true });`,
    }, 'insecure-cookie');
    assert(findings.some(f => /\.example\.com/.test(f.message) && f.cwe === 'CWE-732'),
      `leading-dot domain should flag: ${JSON.stringify(findings)}`);
  });

  await test('insecure-cookie: scoped to current host (no domain) is fine', async () => {
    const findings = await scanWith({
      'a.js': `res.cookie('sid', s, { httpOnly: true, secure: true });`,
    }, 'insecure-cookie');
    assert(!findings.some(f => /domain/.test(f.message)),
      `no-domain should not flag domain rule: ${JSON.stringify(findings)}`);
  });

  // ── §QW-30 / §RC-55 — credentials in localStorage ──────────────────────
  await test('insecure-web-storage: setItem("token", x) flagged (QW-30 / RC-55)', async () => {
    const findings = await scanWith({
      'a.js': `localStorage.setItem('access_token', t);`,
    }, 'insecure-web-storage');
    assert(findings.some(f => f.cwe === 'CWE-922' && /access_token/.test(f.message)),
      `localStorage token write should flag CWE-922: ${JSON.stringify(findings)}`);
  });

  await test('insecure-web-storage: setItem("theme", "dark") is fine', async () => {
    const findings = await scanWith({
      'a.js': `localStorage.setItem('theme', 'dark');`,
    }, 'insecure-web-storage');
    assert.strictEqual(findings.length, 0,
      `non-sensitive key should not flag: ${JSON.stringify(findings)}`);
  });

  await test('insecure-web-storage: bracket assignment (sessionStorage["jwt"] =) flagged', async () => {
    const findings = await scanWith({
      'a.js': `sessionStorage['jwt'] = j;`,
    }, 'insecure-web-storage');
    assert(findings.some(f => /jwt/i.test(f.message)),
      `sessionStorage[key] = should flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-43 / §RC-18 — error info disclosure ────────────────────────────
  await test('error-info-disclosure: res.send(err.stack) flagged HIGH (QW-43 / RC-18)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { try { x(); } catch (err) { res.send(err.stack); } }`,
    }, 'error-info-disclosure');
    assert(findings.some(f => f.cwe === 'CWE-209' && f.severity === 'high' &&
      /stack/i.test(f.message)),
      `err.stack should flag HIGH/CWE-209: ${JSON.stringify(findings)}`);
  });

  await test('error-info-disclosure: res.json({ error: err }) flagged HIGH (raw)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { try { x(); } catch (err) { res.status(500).json({ error: err }); } }`,
    }, 'error-info-disclosure');
    assert(findings.some(f => /raw error/i.test(f.message) && f.severity === 'high'),
      `raw err should flag HIGH: ${JSON.stringify(findings)}`);
  });

  await test('error-info-disclosure: err.message flagged MEDIUM', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { try { x(); } catch (err) { res.send(err.message); } }`,
    }, 'error-info-disclosure');
    assert(findings.some(f => f.severity === 'medium'),
      `err.message should flag MEDIUM: ${JSON.stringify(findings)}`);
  });

  await test('error-info-disclosure: generic-message response is fine', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, res) { try { x(); } catch (err) { console.error(err); res.status(500).send('Internal server error'); } }`,
    }, 'error-info-disclosure');
    assert.strictEqual(findings.length, 0,
      `generic 500 message should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-46 / §RC-56 — clipboard exposure ───────────────────────────────
  await test('clipboard-exposure: writeText(token) flagged (QW-46 / RC-56)', async () => {
    const findings = await scanWith({
      'a.tsx': `function copy() { navigator.clipboard.writeText(accessToken); }`,
    }, 'clipboard-exposure');
    assert(findings.some(f => f.cwe === 'CWE-359' && /accessToken/.test(f.message)),
      `writeText(token) should flag: ${JSON.stringify(findings)}`);
  });

  await test('clipboard-exposure: writeText(url) is fine', async () => {
    const findings = await scanWith({
      'a.tsx': `function copy() { navigator.clipboard.writeText(currentUrl); }`,
    }, 'clipboard-exposure');
    assert.strictEqual(findings.length, 0,
      `non-sensitive copy should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-24 / §RC-3 — process.env secret logging ────────────────────────
  await test('sensitive-logging: console.log(process.env.JWT_SECRET) flagged (QW-24 / RC-3)', async () => {
    const findings = await scanWith({
      'a.js': `console.log('jwt', process.env.JWT_SECRET);`,
    }, 'sensitive-logging');
    assert(findings.some(f => f.cwe === 'CWE-532' && /JWT_SECRET/.test(f.message)),
      `process.env secret logging should flag: ${JSON.stringify(findings)}`);
  });

  await test('sensitive-logging: console.log(process.env.NODE_ENV) is fine', async () => {
    const findings = await scanWith({
      'a.js': `console.log('mode', process.env.NODE_ENV);`,
    }, 'sensitive-logging');
    assert.strictEqual(findings.length, 0,
      `public env logging should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-27 / §RC-24 — path.join(__dirname, taint) ──────────────────────
  await test('path-traversal-js: path.join(__dirname, req.query.file) flagged (QW-27 / RC-24)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req) { return path.join(__dirname, req.query.file); }`,
    }, 'path-traversal-js');
    assert(findings.some(f => f.cwe === 'CWE-22'),
      `path.join(__dirname, taint) should flag: ${JSON.stringify(findings)}`);
  });

  await test('path-traversal-js: static asset path is fine', async () => {
    const findings = await scanWith({
      'a.js': `const p = path.join(__dirname, 'public', 'index.html');`,
    }, 'path-traversal-js');
    assert.strictEqual(findings.length, 0,
      `static path.join should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-37 / §RC-35 — package typosquats ───────────────────────────────
  await test('dependency-confusion: package.json typosquat flagged (QW-37 / RC-35)', async () => {
    const findings = await scanWith({
      'package.json': JSON.stringify({ dependencies: { expres: '^4.0.0' } }, null, 2),
    }, 'dependency-confusion');
    assert(findings.some(f => /express/.test(f.message) && f.cwe === 'CWE-1357'),
      `expres should flag as express typosquat: ${JSON.stringify(findings)}`);
  });

  await test('dependency-confusion: normal package names are fine', async () => {
    const findings = await scanWith({
      'package.json': JSON.stringify({ dependencies: { express: '^4.0.0' } }, null, 2),
    }, 'dependency-confusion');
    assert.strictEqual(findings.length, 0,
      `normal dependency should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-28 / §RC-25 — symlink following ────────────────────────────────
  await test('symlink-following: fs.readFile(req.query.path) flagged (QW-28 / RC-25)', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, fs) { return fs.readFile(req.query.path, 'utf8'); }`,
    }, 'symlink-following');
    assert(findings.some(f => f.cwe === 'CWE-59'),
      `user-controlled fs path should flag symlink following: ${JSON.stringify(findings)}`);
  });

  await test('symlink-following: guarded realpath read is fine', async () => {
    const findings = await scanWith({
      'a.js': `function h(req, fs) { const safe = fs.realpathSync(req.query.path); return fs.readFile(safe, 'utf8'); }`,
    }, 'symlink-following');
    assert.strictEqual(findings.length, 0,
      `realpath-guarded read should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-33 / §SF-2 — Supabase realtime scoping ─────────────────────────
  await test('unscoped-realtime-channel: public table channel without filter flagged (QW-33 / SF-2)', async () => {
    const findings = await scanWith({
      'lib/main.dart': `void f(supabase) { supabase.channel('public:posts').onPostgresChanges(schema: 'public', table: 'posts', callback: (_) {}).subscribe(); }`,
    }, 'unscoped-realtime-channel');
    assert(findings.some(f => f.cwe === 'CWE-639'),
      `unscoped realtime channel should flag: ${JSON.stringify(findings)}`);
  });

  await test('unscoped-realtime-channel: user_id filter is fine', async () => {
    const findings = await scanWith({
      'lib/main.dart': `void f(supabase, userId) { supabase.channel('public:posts').eq('user_id', userId).subscribe(); }`,
    }, 'unscoped-realtime-channel');
    assert.strictEqual(findings.length, 0,
      `user-scoped realtime channel should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-34 / §SF-25 — Realtime subscription cleanup ────────────────────
  await test('realtime-subscription-leak: assigned subscription without cleanup flagged (QW-34 / SF-25)', async () => {
    const findings = await scanWith({
      'lib/main.dart': `void f(supabase) { final subscription = supabase.channel('public:posts').subscribe(); }`,
    }, 'realtime-subscription-leak');
    assert(findings.some(f => f.cwe === 'CWE-772'),
      `missing unsubscribe should flag: ${JSON.stringify(findings)}`);
  });

  await test('realtime-subscription-leak: unsubscribe cleanup is fine', async () => {
    const findings = await scanWith({
      'lib/main.dart': `void f(supabase) { final subscription = supabase.channel('public:posts').subscribe(); subscription.unsubscribe(); }`,
    }, 'realtime-subscription-leak');
    assert.strictEqual(findings.length, 0,
      `subscription cleanup should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-35 / §SF-12 — secure storage then logging ──────────────────────
  await test('secure-storage-logging: secure storage token logged (QW-35 / SF-12)', async () => {
    const findings = await scanWith({
      'lib/main.dart': `import 'package:flutter_secure_storage/flutter_secure_storage.dart'; Future<void> f(storage) async { final token = await storage.read(key: 'access_token'); print(token); }`,
    }, 'secure-storage-logging');
    assert(findings.some(f => f.cwe === 'CWE-532'),
      `secure storage log should flag: ${JSON.stringify(findings)}`);
  });

  await test('secure-storage-logging: non-sensitive secure read not logged is fine', async () => {
    const findings = await scanWith({
      'lib/main.dart': `import 'package:flutter_secure_storage/flutter_secure_storage.dart'; Future<void> f(storage) async { final theme = await storage.read(key: 'theme'); print('loaded'); }`,
    }, 'secure-storage-logging');
    assert.strictEqual(findings.length, 0,
      `non-sensitive read without logging value should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-36 / §SF-13 — Android WebView JS bridge ────────────────────────
  await test('android-webview-js-interface: native bridge exposure flagged (QW-36 / SF-13)', async () => {
    const findings = await scanWith({
      'android/app/src/main/java/App.java': `class App { void f(WebView w, Object bridge) { w.addJavascriptInterface(bridge, "Native"); } }`,
    }, 'android-webview-js-interface');
    assert(findings.some(f => f.cwe === 'CWE-749'),
      `addJavascriptInterface should flag: ${JSON.stringify(findings)}`);
  });

  await test('android-webview-js-interface: commented bridge is ignored', async () => {
    const findings = await scanWith({
      'android/app/src/main/java/App.java': `class App { void f(WebView w, Object bridge) { // w.addJavascriptInterface(bridge, "Native");\n } }`,
    }, 'android-webview-js-interface');
    assert.strictEqual(findings.length, 0,
      `commented addJavascriptInterface should not flag: ${JSON.stringify(findings)}`);
  });

  // ── §QW-44 / §RC-27 — Python format-string injection ───────────────────
  await test('python-format-injection: SQL percent-format with request arg flagged (QW-44 / RC-27)', async () => {
    const findings = await scanWith({
      'app.py': `def h(request, cursor):\n    cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.args.get('name'))`,
    }, 'python-format-injection');
    assert(findings.some(f => f.cwe === 'CWE-134' && f.severity === 'high'),
      `Python percent-format SQL should flag: ${JSON.stringify(findings)}`);
  });

  await test('python-format-injection: parameterized SQL is fine', async () => {
    const findings = await scanWith({
      'app.py': `def h(request, cursor):\n    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args.get('name'),))`,
    }, 'python-format-injection');
    assert.strictEqual(findings.length, 0,
      `parameterized SQL should not flag format injection: ${JSON.stringify(findings)}`);
  });

  await test('improper-cert-validation: comment lines are ignored', async () => {
    const findings = await scanWith({
      'a.js': `// rejectUnauthorized: false in older code\nconst x = 1;`,
    }, 'improper-cert-validation');
    assert.strictEqual(findings.length, 0,
      `comment text must not flag: ${JSON.stringify(findings)}`);
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
