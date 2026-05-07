#!/usr/bin/env node
/**
 * Hover provider smoke test (§IN-16).
 *
 * The hover provider can't be exercised end-to-end without spinning up the
 * VS Code extension host, but the rendering logic is pure — given a Finding,
 * does it produce a Markdown card containing the rule code, severity badge,
 * fix, risk, and CWE link? Verify that here, plus the diagnostic provider's
 * findingsAtLine index that backs it.
 *
 * Mocks the `vscode` module so the providers can load in plain Node.
 */
const assert = require('assert');
const Module = require('module');
const path = require('path');

// In-memory mock of the slice of `vscode` our diagnostic / hover code touches.
// Anything not used here is intentionally absent — failures highlight new
// surface area we forgot to mock.
const vscodeMock = {
  languages: {
    createDiagnosticCollection: () => ({
      set: () => {},
      clear: () => {},
      dispose: () => {},
    }),
  },
  Range: class { constructor(sl, sc, el, ec) { this.start = { line: sl, character: sc }; this.end = { line: el, character: ec }; } },
  Position: class { constructor(line, character) { this.line = line; this.character = character; } },
  Location: class { constructor(uri, position) { this.uri = uri; this.position = position; } },
  Uri: { file: (p) => ({ fsPath: p, scheme: 'file' }) },
  Diagnostic: class { constructor(range, message, severity) { this.range = range; this.message = message; this.severity = severity; } },
  DiagnosticRelatedInformation: class { constructor(loc, msg) { this.location = loc; this.message = msg; } },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Hover: class { constructor(contents) { this.contents = contents; } },
  MarkdownString: class {
    constructor() { this._buf = ''; this.isTrusted = false; this.supportHtml = false; }
    appendMarkdown(s) { this._buf += s; return this; }
    get value() { return this._buf; }
  },
};

// Inject the mock into Node's module cache before requiring anything that
// imports `vscode`.
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  if (request === 'vscode') return 'vscode';
  return origResolve.call(this, request, parent, ...rest);
};
require.cache['vscode'] = { id: 'vscode', filename: 'vscode', loaded: true, exports: vscodeMock };

const { DiagnosticsProvider } = require('../out/diagnostics/diagnosticsProvider');
const { FindingHoverProvider } = require('../out/diagnostics/hoverProvider');

function fakeFinding(overrides) {
  return {
    code: 'injection-flaw',
    message: 'Tainted input flows into rawQuery',
    severity: 'high',
    confidence: 'high',
    category: 'security',
    fix: 'Parameterize the query',
    risk: 'Attacker can read arbitrary rows',
    filePath: 'src/db.js',
    line: 12,
    cwe: 'CWE-89',
    isSuggestion: false,
    ...overrides,
  };
}

function makeReport(findings) {
  return {
    findings,
    context: { rootPath: '/repo' },
  };
}

function testFindingsAtLine() {
  const dx = new DiagnosticsProvider();
  const findings = [
    fakeFinding({ line: 10 }),
    fakeFinding({ code: 'xss-flaw', line: 10, endLine: 12 }),
    fakeFinding({ code: 'jwt-misuse', line: 25 }),
  ];
  dx.updateDiagnostics(makeReport(findings));
  const uri = vscodeMock.Uri.file(path.join('/repo', 'src/db.js'));

  const at9 = dx.findingsAtLine(uri, 9); // 0-based 9 == 1-based 10
  assert.strictEqual(at9.length, 2, 'expected 2 findings on line 10');

  const at10 = dx.findingsAtLine(uri, 10); // 0-based 10 == 1-based 11
  assert.strictEqual(at10.length, 1,
    'xss-flaw should still match line 11 (within startLine..endLine)');
  assert.strictEqual(at10[0].code, 'xss-flaw');

  const at24 = dx.findingsAtLine(uri, 24); // 0-based 24 == 1-based 25
  assert.deepStrictEqual(at24.map(f => f.code), ['jwt-misuse']);

  const empty = dx.findingsAtLine(uri, 0);
  assert.deepStrictEqual(empty, [], 'no finding on line 1');
}

function testHoverRendering() {
  const dx = new DiagnosticsProvider();
  dx.updateDiagnostics(makeReport([fakeFinding({ line: 12 })]));
  const provider = new FindingHoverProvider(dx);

  const uri = vscodeMock.Uri.file(path.join('/repo', 'src/db.js'));
  const doc = { uri };
  const pos = new vscodeMock.Position(11, 5); // 0-based line 11 == 1-based 12
  const hover = provider.provideHover(doc, pos);
  assert.ok(hover, 'hover should be returned for a flagged line');
  const md = hover.contents.value;

  assert.match(md, /injection-flaw/, 'hover should include rule code');
  assert.match(md, /HIGH/, 'hover should show severity');
  assert.match(md, /Tainted input flows into rawQuery/, 'hover should show message');
  assert.match(md, /Parameterize the query/, 'hover should show fix');
  assert.match(md, /attacker can read arbitrary rows/i, 'hover should show risk');
  assert.match(md, /https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html/,
    'hover should link to CWE-89 page');
}

function testHoverNothingOnCleanLine() {
  const dx = new DiagnosticsProvider();
  dx.updateDiagnostics(makeReport([fakeFinding({ line: 12 })]));
  const provider = new FindingHoverProvider(dx);
  const uri = vscodeMock.Uri.file(path.join('/repo', 'src/db.js'));
  const result = provider.provideHover({ uri }, new vscodeMock.Position(0, 0));
  assert.strictEqual(result, undefined, 'no hover should be returned on a clean line');
}

(function main() {
  try {
    testFindingsAtLine();
    testHoverRendering();
    testHoverNothingOnCleanLine();
    console.log('hover-provider self-test: PASS');
  } catch (err) {
    console.error('hover-provider self-test: FAIL');
    console.error(err);
    process.exit(1);
  }
})();
