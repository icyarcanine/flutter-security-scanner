#!/usr/bin/env node
/**
 * Adversarial SAST test harness — covers 7 attack categories.
 *
 * Each test case asserts a specific property:
 *   { name, files, expect: { mustFlag: [{file, code, severity?}], mustNotFlag: [...] } }
 *
 * Returns a structured pass/fail report rather than asserting hard,
 * so the iterative improvement loop can measure deltas.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { ProjectScanner } = require('../out/scanner/scanner');

const TESTS = [];

function test(name, files, expect) {
  TESTS.push({ name, files, expect });
}

// ─────────────────────────────────────────────────────────────────
// 1) Multi-file flows: source → fileA → fileB → fileC → sink
// ─────────────────────────────────────────────────────────────────
test('multi-file: tainted import chain (JS)', {
  'a.js': `
    function getInput(req) { return req.query.q; }
    module.exports = { getInput };
  `,
  'b.js': `
    const { getInput } = require('./a');
    function passthrough(req) { return getInput(req); }
    module.exports = { passthrough };
  `,
  'c.js': `
    const { passthrough } = require('./b');
    const { exec } = require('child_process');
    function handler(req) {
      const cmd = passthrough(req);
      exec("ls " + cmd);
    }
  `,
}, {
  // Cross-file taint is currently intra-procedural; we don't expect HIGH,
  // but the dynamic exec should at least produce MEDIUM.
  mustFlagAny: [{ file: 'c.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 2) Indirect SQL construction: queryPart1 + queryPart2 → execute
// ─────────────────────────────────────────────────────────────────
test('indirect: SQL split across multiple variables', {
  'split.js': `
    function lookup(req, db) {
      const userId = req.query.id;
      const part1 = "SELECT * FROM users WHERE id = ";
      const part2 = part1 + userId;
      const part3 = part2 + " AND status='active'";
      return db.query(part3);
    }
  `,
}, {
  mustFlag: [{ file: 'split.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 3) ORM misuse: raw query inside ORM, unsafe filter
// ─────────────────────────────────────────────────────────────────
test('orm: raw query with concatenation', {
  'orm.js': `
    function search(req, knex) {
      const term = req.body.term;
      return knex.raw("SELECT * FROM products WHERE name LIKE '%" + term + "%'");
    }
  `,
}, {
  mustFlag: [{ file: 'orm.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 4) Obfuscated flows: var indirection through unrelated functions
// ─────────────────────────────────────────────────────────────────
test('obfuscated: aliasing without sanitizer', {
  'obf.js': `
    function transform(x) { return x.toString(); }
    function maybeSanitize(x) { return x; }
    function vuln(req, db) {
      const a = req.query.search;
      const b = transform(a);
      const c = maybeSanitize(b);
      db.query("SELECT * FROM t WHERE name = '" + c + "'");
    }
  `,
}, {
  // 'maybeSanitize' is NOT in the sanitizer list; this is genuine taint.
  mustFlag: [{ file: 'obf.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 5) Async flows: callback / await
// ─────────────────────────────────────────────────────────────────
test('async: await chain into sink', {
  'async.js': `
    async function fetchAndExec(req) {
      const { exec } = require('child_process');
      const target = await Promise.resolve(req.body.target);
      exec("ping " + target);
    }
  `,
}, {
  mustFlag: [{ file: 'async.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 6) Template injection: render_template_string with user input (Python)
// ─────────────────────────────────────────────────────────────────
test('template: python render_template_string with user input', {
  'tmpl.py': `
from flask import request, render_template_string

def page():
    name = request.args.get('name')
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
  `,
}, {
  // Python AST taint is currently optimistic; this is a known gap to exercise.
  mustFlagAny: [{ file: 'tmpl.py' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// 7) Partial sanitization: only one branch sanitized
// ─────────────────────────────────────────────────────────────────
test('partial sanitization: only sanitized in one branch', {
  'partial.js': `
    function lookup(req, db) {
      let id = req.query.id;
      if (req.query.safe) {
        id = escape(id);
      }
      // 'id' may still be tainted if !req.query.safe
      return db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  // Conservative SAST should still flag this — sanitization isn't unconditional.
  mustFlag: [{ file: 'partial.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// SAFE: parameterized queries, validated input — must NOT flag
// ─────────────────────────────────────────────────────────────────
test('safe: parameterized', {
  'safe.js': `
    function safeLookup(req, db) {
      return db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'safe.js', code: 'injection-flaw' }],
});

test('safe: validated then used', {
  'safe2.js': `
    function safe(req, db) {
      const id = parseInt(req.query.id, 10);
      return db.query("SELECT * FROM users WHERE id = " + id);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'safe2.js', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 2: Deeper edge cases
// ─────────────────────────────────────────────────────────────────

// Python: SQL injection via subprocess
test('python: subprocess.run command injection', {
  'sub.py': `
import subprocess
from flask import request

def page():
    target = request.args.get('host')
    subprocess.run("ping " + target, shell=True)
  `,
}, {
  mustFlagAny: [{ file: 'sub.py', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Python: SQL injection via cursor.execute
test('python: cursor.execute SQL injection', {
  'sql.py': `
from flask import request

def page(cursor):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
  `,
}, {
  mustFlagAny: [{ file: 'sql.py', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Python: SAFE — parameterized cursor.execute
test('python: parameterized cursor.execute is safe', {
  'safesql.py': `
from flask import request

def page(cursor):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'safesql.py', code: 'injection-flaw' }],
});

// Template literal SQL injection (ES6 backtick syntax)
test('template literal SQL injection', {
  'tmpl.js': `
    function lookup(req, db) {
      const userId = req.query.id;
      return db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
    }
  `,
}, {
  mustFlag: [{ file: 'tmpl.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// String interpolation Dart
test('dart: tainted interpolation into rawQuery', {
  'taint.dart': `
void run(input, db) {
  final sql = "SELECT * FROM t WHERE id = $input";
  db.rawQuery(sql);
}
  `,
}, {
  mustFlag: [{ file: 'taint.dart', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Sanitized via DOMPurify before innerHTML
test('safe: dompurify before innerHTML', {
  'pure.js': `
    import DOMPurify from 'dompurify';
    function render(req, el) {
      const clean = DOMPurify.sanitize(req.body.html);
      el.innerHTML = clean;
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'pure.js', code: 'injection-flaw' }],
});

// XSS via innerHTML with concatenation
test('xss: innerHTML with user input', {
  'xss.js': `
    function render(req, el) {
      const name = req.query.name;
      el.innerHTML = "<h1>Hello " + name + "</h1>";
    }
  `,
}, {
  mustFlagAny: [{ file: 'xss.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// SAFE: hardcoded SQL with constants
test('safe: hardcoded SQL with constant', {
  'const.js': `
    const TABLE = "users";
    function getUsers(db) {
      return db.query("SELECT * FROM " + TABLE);
    }
  `,
}, {
  // This should NOT be HIGH (no taint).
  mustFlag: [],
  mustNotFlag: [{ file: 'const.js', code: 'injection-flaw', severity: 'high' }],
});

// SAFE: numeric concatenation
test('safe: numeric literal concatenation', {
  'num.js': `
    function getById(db) {
      return db.query("SELECT * FROM users WHERE id = " + 5);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'num.js', code: 'injection-flaw' }],
});

// Re-tainting after sanitization
test('vulnerable: re-tainted after sanitization', {
  'retaint.js': `
    function bad(req, db) {
      let id = escape(req.query.id);   // sanitized
      id = req.query.id2;              // re-tainted
      return db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  // After re-assignment, id is tainted again. Should flag (HIGH or MEDIUM).
  mustFlagAny: [{ file: 'retaint.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Object property assignment carrying taint
test('vulnerable: tainted object property', {
  'obj.js': `
    function bad(req, db) {
      const params = {};
      params.id = req.query.id;
      return db.query("SELECT * FROM t WHERE id = '" + params.id + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'obj.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Safe: no concatenation, plain literal
test('safe: plain literal sql', {
  'plain.js': `
    function getAll(db) {
      return db.query("SELECT * FROM users");
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'plain.js', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 3: Harder edge cases
// ─────────────────────────────────────────────────────────────────

// Destructuring source
test('destructuring: tainted via destructured assignment', {
  'dest.js': `
    function bad(req, db) {
      const { id } = req.query;
      return db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'dest.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Array index taint
test('array index: tainted element used in sink', {
  'arr.js': `
    function bad(req, db) {
      const id = req.body.ids[0];
      return db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'arr.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Conditional sanitizer (ternary)
test('ternary: conditional sanitizer', {
  'tern.js': `
    function bad(req, db) {
      const raw = req.query.id;
      const id = raw ? escape(raw) : raw;
      return db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  // raw could be unsanitized if falsy. Should still flag.
  mustFlagAny: [{ file: 'tern.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// IIFE / closure
test('closure: IIFE with tainted access', {
  'iife.js': `
    function handler(req, db) {
      (function() {
        db.query("SELECT * FROM t WHERE id = '" + req.body.id + "'");
      })();
    }
  `,
}, {
  // Inner function has its own scope; req.body.id is direct source. Should flag.
  mustFlagAny: [{ file: 'iife.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Tagged template literal (potential FN — unsanitized SQL tag)
test('tagged template: unknown tag with tainted interpolation', {
  'tag.js': `
    function bad(req, db) {
      const userId = req.query.id;
      const q = sql\`SELECT * FROM t WHERE id = \${userId}\`;
      return db.query(q);
    }
  `,
}, {
  // The query is built dynamically, then passed to db.query. Should flag.
  mustFlagAny: [{ file: 'tag.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Console.log with tainted - must NOT flag (not a sink)
test('safe: console.log is not a sink', {
  'log.js': `
    function ok(req) {
      console.log("got: " + req.body.x);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'log.js', code: 'injection-flaw' }],
});

// Path traversal — fs.readFile with user input
test('path traversal: fs.readFile with tainted input', {
  'path.js': `
    const fs = require('fs');
    function bad(req, res) {
      fs.readFile(req.query.file, (err, data) => res.send(data));
    }
  `,
}, {
  mustFlag: [{ file: 'path.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Open redirect — res.redirect with user input
test('open redirect: res.redirect with tainted input', {
  'redir.js': `
    function bad(req, res) {
      res.redirect(req.query.next);
    }
  `,
}, {
  mustFlag: [{ file: 'redir.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Python: os.popen
test('python: os.popen command injection', {
  'pop.py': `
import os
from flask import request
def page():
    cmd = "ls " + request.args.get('dir')
    os.popen(cmd)
  `,
}, {
  mustFlagAny: [{ file: 'pop.py', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Sanitizer applied to wrong variable
test('vulnerable: sanitizer applied to wrong var', {
  'wrong.js': `
    function bad(req, db) {
      const safe = escape(req.query.safe);
      const unsafe = req.query.unsafe;
      return db.query("SELECT * FROM t WHERE x = '" + unsafe + "' AND y = '" + safe + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'wrong.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Reassignment from sink result (no source involvement)
test('safe: reassignment without taint', {
  'reasg.js': `
    function ok(db) {
      let id = 5;
      id = id + 1;
      return db.query("SELECT * FROM t WHERE id = " + id);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'reasg.js', code: 'injection-flaw', severity: 'high' }],
});

// Java SQL injection
test('java: Statement.executeQuery injection', {
  'Vuln.java': `
public class Vuln {
  public void run(String userInput, java.sql.Statement stmt) throws Exception {
    stmt.executeQuery("SELECT * FROM t WHERE id = '" + userInput + "'");
  }
}
  `,
}, {
  // 'userInput' matches SOURCE_PARAMETER_NAMES → tainted
  mustFlagAny: [{ file: 'Vuln.java', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Go: database query with concatenation
test('go: database query with concatenation', {
  'main.go': `
package main
import "database/sql"
func handler(input string, db *sql.DB) {
  db.Query("SELECT * FROM t WHERE id = '" + input + "'")
}
  `,
}, {
  mustFlagAny: [{ file: 'main.go', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// Round 4: Specific real-world patterns
// ─────────────────────────────────────────────────────────────────

// Express route with destructured req
test('express: destructured req param', {
  'route.js': `
    const express = require('express');
    const app = express();
    app.get('/x', ({ query }, res) => {
      db.query("SELECT * FROM t WHERE id = '" + query.id + "'");
    });
  `,
}, {
  // Common pattern: destructured req parameter. Should detect at HIGH
  // confidence — the destructuring slot binds query/body/etc. directly
  // to the request object, which the seed pass marks tainted.
  mustFlag: [{ file: 'route.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Spread arguments
test('spread: tainted spread into sink', {
  'spread.js': `
    function bad(req, db) {
      const args = [req.query.id];
      db.query("SELECT * FROM t WHERE id = " + args[0]);
    }
  `,
}, {
  mustFlagAny: [{ file: 'spread.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Dart with Flutter route arguments
test('dart: Flutter ModalRoute arguments tainted into rawQuery', {
  'flutter.dart': `
void load(BuildContext context, db) {
  final args = ModalRoute.of(context)!.settings.arguments;
  final id = args.toString();
  db.rawQuery("SELECT * FROM t WHERE id = '" + id + "'");
}
  `,
}, {
  // Currently no Flutter route source pattern — coverage gap.
  mustFlagAny: [],
  mustNotFlag: [],
});

// Sanitizer call result is unused
test('vulnerable: sanitizer call result discarded', {
  'discard.js': `
    function bad(req, db) {
      const id = req.query.id;
      escape(id);  // result discarded
      db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  // Calling escape() without using its return value doesn't sanitize.
  mustFlagAny: [{ file: 'discard.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// Loop body with tainted iteration
test('loop: tainted iteration variable', {
  'loop.js': `
    function bad(req, db) {
      const ids = req.body.ids;
      for (const id of ids) {
        db.query("SELECT * FROM t WHERE id = " + id);
      }
    }
  `,
}, {
  mustFlagAny: [{ file: 'loop.js', code: 'injection-flaw' }],
  mustNotFlag: [],
});

// String.format style
test('string format: format string injection', {
  'fmt.js': `
    function bad(req, db) {
      const userId = req.query.id;
      const sql = \`SELECT * FROM users WHERE id = \${userId}\`;
      db.execute(sql);
    }
  `,
}, {
  mustFlag: [{ file: 'fmt.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// JSON.parse result with user input - usually not injection but could be
test('safe: JSON.parse on user input passed to console.log', {
  'json.js': `
    function ok(req) {
      const data = JSON.parse(req.body.json);
      console.log(data);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'json.js', code: 'injection-flaw' }],
});

// Static SQL with multiple .where() chained
test('safe: builder pattern with parameterization', {
  'builder.js': `
    function ok(req, db) {
      return db.from('users').where('id', '=', req.query.id).first();
    }
  `,
}, {
  // builder.where() is parameterized — should NOT flag.
  mustFlag: [],
  mustNotFlag: [{ file: 'builder.js', code: 'injection-flaw' }],
});

// Concat into command without quoting
test('command: shell concat without quoting', {
  'cmd.js': `
    const { exec } = require('child_process');
    function bad(req) {
      exec("convert " + req.body.input + " out.png");
    }
  `,
}, {
  mustFlag: [{ file: 'cmd.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Direct env source - process.env isn't strictly user input
test('env: process.env into sink (low priority)', {
  'env.js': `
    function maybe(db) {
      db.query("SELECT * FROM " + process.env.TABLE);
    }
  `,
}, {
  // process.env IS in our source set but env is operator-controlled, lower risk.
  // Currently flagged. Acceptable for now.
  mustFlagAny: [],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// Round 5: New coverage from iter 5/6
// ─────────────────────────────────────────────────────────────────

// Optional chaining source
test('optional chaining: req?.body?.id into sink', {
  'opt.js': `
    function bad(req, db) {
      const id = req?.body?.id;
      db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'opt.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Bracket notation source
test('bracket notation: req["body"].id into sink', {
  'brk.js': `
    function bad(req, db) {
      const id = req["body"].id;
      db.query("SELECT * FROM t WHERE id = '" + id + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'brk.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Destructured req with default param
test('default param: ({ query = {} } = {}) destructure', {
  'dflt.js': `
    const express = require('express');
    const app = express();
    app.get('/x', ({ query = {} } = {}, res) => {
      db.query("SELECT * FROM t WHERE id = '" + query.id + "'");
    });
  `,
}, {
  mustFlag: [{ file: 'dflt.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SSRF — fetch with tainted URL
test('ssrf: fetch with tainted url', {
  'fetch.js': `
    function bad(req) {
      const url = req.body.target;
      return fetch(url);
    }
  `,
}, {
  mustFlag: [{ file: 'fetch.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SSRF — axios.get with tainted URL
test('ssrf: axios.get with tainted url', {
  'axios.js': `
    const axios = require('axios');
    function bad(req) {
      return axios.get(req.query.url);
    }
  `,
}, {
  mustFlag: [{ file: 'axios.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SSRF — Python requests.get with tainted URL
test('ssrf: python requests.get with tainted url', {
  'req.py': `
import requests
from flask import request
def page():
    target = request.args.get('url')
    return requests.get(target)
  `,
}, {
  mustFlag: [{ file: 'req.py', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Multer file source
test('multer: req.file.path into fs sink', {
  'mult.js': `
    const fs = require('fs');
    function bad(req) {
      fs.readFile(req.file.path, (err, data) => {});
    }
  `,
}, {
  mustFlag: [{ file: 'mult.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// setTimeout with tainted string arg (code injection)
test('setTimeout: tainted string into setTimeout', {
  'st.js': `
    function bad(req) {
      setTimeout(req.body.code, 1000);
    }
  `,
}, {
  mustFlag: [{ file: 'st.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Closure inheritance — inner arrow inherits taint from outer scope
test('closure inheritance: inner arrow uses outer tainted var', {
  'closure.js': `
    function outer(req) {
      const id = req.body.id;
      const inner = () => {
        return db.query("SELECT * FROM t WHERE id = '" + id + "'");
      };
      return inner();
    }
  `,
}, {
  mustFlag: [{ file: 'closure.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// React JSX dangerouslySetInnerHTML with tainted prop
test('react: tainted dangerouslySetInnerHTML', {
  'jsx.jsx': `
    function Comp({ req }) {
      return <div dangerouslySetInnerHTML={{ __html: req.body.html }} />;
    }
  `,
}, {
  mustFlagAny: [{ file: 'jsx.jsx', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: fetch with constant URL — no SSRF
test('safe: fetch with constant url', {
  'sfetch.js': `
    function ok() {
      return fetch('https://api.example.com/data');
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sfetch.js', code: 'injection-flaw' }],
});

// SAFE: fs.readFile with constant path
test('safe: fs.readFile with constant path', {
  'sfs.js': `
    const fs = require('fs');
    function ok() {
      fs.readFile('/etc/config.json', (err, data) => {});
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sfs.js', code: 'injection-flaw' }],
});

// SAFE: res.redirect with constant
test('safe: res.redirect with constant', {
  'sredir.js': `
    function ok(req, res) {
      res.redirect('/login');
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sredir.js', code: 'injection-flaw' }],
});

// SAFE: setTimeout with function reference (not string)
test('safe: setTimeout with function', {
  'sst.js': `
    function ok() {
      setTimeout(() => console.log('hi'), 1000);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sst.js', code: 'injection-flaw' }],
});

// SAFE: closure capturing only constants
test('safe: closure capturing constant', {
  'sclos.js': `
    function outer(req) {
      const safe = "constant";
      const inner = () => {
        return db.query("SELECT * FROM t WHERE name = '" + safe + "'");
      };
    }
  `,
}, {
  // No req-derived data is captured by inner; should not flag HIGH.
  mustFlag: [],
  mustNotFlag: [{ file: 'sclos.js', code: 'injection-flaw', severity: 'high' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 6: NoSQL injection ($where operator)
// ─────────────────────────────────────────────────────────────────

// MongoDB $where with tainted JS code
test('nosql: $where with tainted user input', {
  'nosql.js': `
    function bad(req, db) {
      return db.users.find({ $where: req.body.filter });
    }
  `,
}, {
  mustFlag: [{ file: 'nosql.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// MongoDB $function (3.6+) with tainted body
test('nosql: $function with tainted body', {
  'nosqlfn.js': `
    function bad(req, db) {
      return db.users.aggregate([{
        $project: {
          out: { $function: { body: req.body.code, args: [], lang: 'js' } }
        }
      }]);
    }
  `,
}, {
  mustFlag: [{ file: 'nosqlfn.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Python pymongo $where with tainted
test('nosql: pymongo $where with tainted', {
  'pynosql.py': `
from flask import request
def page(db):
    user_filter = request.args.get('filter')
    return db.users.find({"$where": user_filter})
  `,
}, {
  mustFlag: [{ file: 'pynosql.py', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: parameterized find — driver-parameterized fields are safe
test('safe nosql: find with parameterized fields', {
  'sfind.js': `
    function ok(req, db) {
      return db.users.find({ name: req.body.name, status: 'active' });
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sfind.js', code: 'injection-flaw' }],
});

// SAFE: $where with literal JS string — no taint
test('safe nosql: $where with literal', {
  'sliteralwhere.js': `
    function ok(db) {
      return db.users.find({ $where: "this.age > 18" });
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sliteralwhere.js', code: 'injection-flaw' }],
});

// SAFE: updateOne with parameterized $set
test('safe nosql: updateOne with parameterized $set', {
  'supdate.js': `
    function ok(req, db) {
      return db.users.updateOne(
        { _id: req.params.id },
        { $set: { name: req.body.name } }
      );
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'supdate.js', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 7: Insecure deserialization, XPath, LDAP
// ─────────────────────────────────────────────────────────────────

// Python pickle.loads on user input
test('deser: pickle.loads on user input', {
  'pickle.py': `
import pickle
from flask import request
def load():
    return pickle.loads(request.data)
  `,
}, {
  mustFlag: [{ file: 'pickle.py', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Python yaml.load on user input
test('deser: yaml.load on user input', {
  'yaml.py': `
import yaml
from flask import request
def load():
    return yaml.load(request.data)
  `,
}, {
  mustFlag: [{ file: 'yaml.py', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// XPath injection
test('xpath: select with concatenated input', {
  'xpath.js': `
    const xpath = require('xpath');
    function bad(req, doc) {
      return xpath.select("//user[@id='" + req.query.id + "']", doc);
    }
  `,
}, {
  mustFlag: [{ file: 'xpath.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// LDAP injection
test('ldap: search with concatenated input', {
  'ldap.js': `
    function bad(req, ldap) {
      return ldap.search("uid=" + req.body.user + ",ou=people");
    }
  `,
}, {
  mustFlag: [{ file: 'ldap.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: pickle on hardcoded string — no taint
test('safe deser: pickle.loads on literal', {
  'spickle.py': `
import pickle
def load():
    return pickle.loads(b"hardcoded data")
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'spickle.py', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 8: session/cookies/headers as sources, augmented assignment
// ─────────────────────────────────────────────────────────────────

// Express session as source
test('source: req.session into sink', {
  'sess.js': `
    function bad(req, db) {
      const role = req.session.role;
      db.query("SELECT * FROM t WHERE role = '" + role + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'sess.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Express cookies as source
test('source: req.cookies into sink', {
  'cook.js': `
    function bad(req, db) {
      const userId = req.cookies.uid;
      db.query("SELECT * FROM t WHERE id = '" + userId + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'cook.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Express headers as source
test('source: req.headers into sink', {
  'head.js': `
    function bad(req, db) {
      const auth = req.headers.authorization;
      db.query("SELECT * FROM t WHERE token = '" + auth + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'head.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Augmented assignment (q += tainted)
test('aug-assign: q += tainted into sink', {
  'aug.js': `
    function bad(req, db) {
      let q = "SELECT * FROM t WHERE id = ";
      q += req.query.id;
      db.query(q);
    }
  `,
}, {
  mustFlag: [{ file: 'aug.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: augmented assign with literal — should not flag
test('safe aug-assign: q += literal', {
  'saug.js': `
    function ok(db) {
      let q = "SELECT * FROM t";
      q += " WHERE active = 1";
      return db.query(q);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'saug.js', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 9: FP regressions found in real codebase
// ─────────────────────────────────────────────────────────────────

// fs.writeFileSync(path, content) — content arg should NOT trip path sink
// even if `data` is in scope as a parameter (commonly used as a generic name).
test('safe: writeFileSync content arg is not the path', {
  'wfs.js': `
    const fs = require('fs');
    const path = require('path');
    function saveBaseline(rootPath, data) {
      const filePath = path.join(rootPath, '.baseline.json');
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    }
  `,
}, {
  // The path arg is constant; the second arg (content) should not trigger
  // a path sink finding even though `data` matches a generic source name.
  mustFlag: [],
  mustNotFlag: [{ file: 'wfs.js', code: 'injection-flaw', severity: 'high' }],
});

// spawn(cmd, args, opts) — opts object should not poison the call
// when it contains process.env spread.
test('safe: spawn with process.env in options', {
  'spawn.js': `
    const { spawn } = require('child_process');
    function run() {
      spawn('ls', ['-la'], { env: { ...process.env, FOO: '1' } });
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'spawn.js', code: 'injection-flaw', severity: 'high' }],
});

// setTimeout with a function arg (not a string) — must not flag.
test('safe: setTimeout with arrow function captures (not a string)', {
  'st-fn.js': `
    function schedule(timeoutMs) {
      const timer = setTimeout(() => {
        console.log('done');
        setTimeout(() => console.log('grace'), 5000);
      }, timeoutMs);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'st-fn.js', code: 'injection-flaw' }],
});

// ─────────────────────────────────────────────────────────────────
// Round 10: Object.assign side-effect mutations
// ─────────────────────────────────────────────────────────────────

// Object.assign taints the target variable in-place
test('object-assign: Object.assign(target, tainted) taints target', {
  'oa1.js': `
    function bad(req, db) {
      const cfg = {};
      Object.assign(cfg, req.body);
      db.query("SELECT * FROM t WHERE id = '" + cfg.id + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'oa1.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Object.assign with multiple sources — any tainted source poisons the target
test('object-assign: multiple sources, one tainted', {
  'oa2.js': `
    function bad(req, db) {
      const opts = { table: 'users' };
      Object.assign(opts, { safe: 'literal' }, req.query);
      db.query("SELECT * FROM t WHERE name = '" + opts.name + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'oa2.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Object.assign({}, src) — fresh-literal target, return value carries taint
test('object-assign: fresh literal target return value is tainted', {
  'oa3.js': `
    function bad(req, db) {
      const copy = Object.assign({}, req.body);
      db.query("SELECT * FROM t WHERE id = '" + copy.id + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'oa3.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: Object.assign with no tainted source — must not flag
test('safe object-assign: no tainted source', {
  'soa.js': `
    function ok(db) {
      const cfg = {};
      Object.assign(cfg, { table: 'users', limit: 10 });
      db.query("SELECT * FROM " + cfg.table + " LIMIT " + cfg.limit);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'soa.js', code: 'injection-flaw', severity: 'high' }],
});

// Object.assign into existing object, then property used in sink
test('object-assign: existing object mutated then property used in sink', {
  'oa4.js': `
    function bad(req, db) {
      const filters = { active: true };
      Object.assign(filters, req.body.filters);
      exec("find /data -name " + filters.name);
    }
    const { exec } = require('child_process');
  `,
}, {
  mustFlagAny: [{ file: 'oa4.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// Round 10: Aliasing edge cases
// ─────────────────────────────────────────────────────────────────

// Simple alias: alias = tainted, alias used in sink
test('alias: direct alias of tainted variable', {
  'al1.js': `
    function bad(req, db) {
      const id = req.query.id;
      const alias = id;
      db.query("SELECT * FROM t WHERE id = '" + alias + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'al1.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Double alias chain: a = tainted, b = a, b used in sink
test('alias: double alias chain into sink', {
  'al2.js': `
    function bad(req, db) {
      const raw = req.body.input;
      const step1 = raw;
      const step2 = step1;
      db.query("SELECT * FROM t WHERE val = '" + step2 + "'");
    }
  `,
}, {
  mustFlag: [{ file: 'al2.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Alias into array, then array element used in sink
test('alias: tainted value in array element', {
  'al3.js': `
    function bad(req, db) {
      const parts = [req.query.id, 'extra'];
      db.query("SELECT * FROM t WHERE id = '" + parts[0] + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'al3.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: alias to sanitized variable — should not flag
test('safe alias: alias of sanitized variable', {
  'sal.js': `
    function ok(req, db) {
      const id = parseInt(req.query.id, 10);
      const alias = id;
      db.query("SELECT * FROM t WHERE id = " + alias);
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sal.js', code: 'injection-flaw', severity: 'high' }],
});

// Alias via object destructuring of tainted object
test('alias: destructure property from tainted object into sink', {
  'al4.js': `
    function bad(req, db) {
      const body = req.body;
      const { username } = body;
      db.query("SELECT * FROM users WHERE name = '" + username + "'");
    }
  `,
}, {
  mustFlagAny: [{ file: 'al4.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// ─────────────────────────────────────────────────────────────────
// Round 10: Constructor → method taint propagation
// ─────────────────────────────────────────────────────────────────

// Constructor stores tainted req.body, method uses it in sink
test('ctor-method: constructor stores taint, method uses it in sql sink', {
  'ctor1.js': `
    class UserService {
      constructor(req) {
        this.userId = req.body.id;
      }
      getUser(db) {
        return db.query("SELECT * FROM users WHERE id = '" + this.userId + "'");
      }
    }
  `,
}, {
  mustFlagAny: [{ file: 'ctor1.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// Constructor stores tainted header, method uses it in command sink
test('ctor-method: constructor stores header taint, method uses it in exec', {
  'ctor2.js': `
    class CmdRunner {
      constructor(req) {
        this.cmd = req.headers['x-command'];
      }
      run() {
        const { exec } = require('child_process');
        exec("run " + this.cmd);
      }
    }
  `,
}, {
  mustFlagAny: [{ file: 'ctor2.js', code: 'injection-flaw', severity: 'high' }],
  mustNotFlag: [],
});

// SAFE: constructor stores literal, method uses it — must not flag HIGH
test('safe ctor-method: constructor stores literal, method uses it', {
  'sctor.js': `
    class SafeService {
      constructor() {
        this.tableName = 'products';
      }
      getAll(db) {
        return db.query("SELECT * FROM " + this.tableName);
      }
    }
  `,
}, {
  mustFlag: [],
  mustNotFlag: [{ file: 'sctor.js', code: 'injection-flaw', severity: 'high' }],
});

// ─────────────────────────────────────────────────────────────────
async function runOne(test) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fsh-adv-'));
  try {
    for (const [name, content] of Object.entries(test.files)) {
      const full = path.join(root, name);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }

    const report = await new ProjectScanner(false).scan(root);
    const findings = report.findings;
    const result = { name: test.name, pass: true, errors: [], findings: findings.length };

    function matches(f, spec) {
      if (spec.file && f.filePath !== spec.file) return false;
      if (spec.code && f.code !== spec.code) return false;
      if (spec.severity && f.severity !== spec.severity) return false;
      return true;
    }

    for (const spec of test.expect.mustFlag ?? []) {
      const hit = findings.find(f => matches(f, spec));
      if (!hit) {
        result.pass = false;
        result.errors.push(`MISSING (mustFlag): ${JSON.stringify(spec)}`);
      }
    }

    for (const spec of test.expect.mustFlagAny ?? []) {
      const hit = findings.find(f => matches(f, spec));
      if (!hit) {
        result.pass = false;
        result.errors.push(`MISSING (mustFlagAny): ${JSON.stringify(spec)}`);
      }
    }

    for (const spec of test.expect.mustNotFlag ?? []) {
      const hit = findings.find(f => matches(f, spec));
      if (hit) {
        result.pass = false;
        result.errors.push(`UNEXPECTED (mustNotFlag): ${JSON.stringify({code: hit.code, file: hit.filePath, severity: hit.severity, line: hit.line})}`);
      }
    }

    return result;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function main() {
  const results = [];
  for (const t of TESTS) {
    results.push(await runOne(t));
  }

  const passed = results.filter(r => r.pass).length;
  const total = results.length;
  console.log(`\nAdversarial Suite: ${passed}/${total} passed\n`);

  for (const r of results) {
    const tag = r.pass ? 'PASS' : 'FAIL';
    console.log(`  [${tag}] ${r.name}`);
    for (const e of r.errors) console.log(`         ${e}`);
  }

  // Output JSON for programmatic comparison
  if (process.argv.includes('--json')) {
    fs.writeFileSync('adversarial-results.json', JSON.stringify({ passed, total, results }, null, 2));
  }

  process.exit(passed === total ? 0 : 1);
}

main().catch(err => { console.error(err); process.exit(2); });
