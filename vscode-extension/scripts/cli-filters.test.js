#!/usr/bin/env node
/**
 * CLI filtering / threshold self-test (§QW-19 / §IN-27, §QW-20 / §IN-28).
 */

const assert = require('assert');
const cp = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const { ProjectScanner } = require('../out/scanner/scanner');
const { toSarif } = require('../out/output/sarif');

function tmpRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `fss-cli-${label}-`));
}

function runCli(args, opts = {}) {
  return cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'out', 'cli.js'), ...args], {
    encoding: 'utf8',
    ...opts,
  });
}

function runCliAsync(args) {
  return new Promise(resolve => {
    const child = cp.spawn(process.execPath, [path.join(__dirname, '..', 'out', 'cli.js'), ...args], {
      encoding: 'utf8',
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', status => resolve({ status, stdout, stderr }));
  });
}

async function testFailConfidence() {
  const highRoot = tmpRoot('high-conf');
  fs.writeFileSync(path.join(highRoot, 'a.js'), `const token = Math.random();`);
  const high = runCli(['scan', highRoot, '--summary', '--fail-confidence', 'high']);
  assert.strictEqual(high.status, 1,
    `high-confidence finding should fail --fail-confidence high; stdout=${high.stdout} stderr=${high.stderr}`);

  const mediumRoot = tmpRoot('med-conf');
  fs.writeFileSync(path.join(mediumRoot, 'a.tsx'), `navigator.clipboard.writeText(accessToken);`);
  const medium = runCli(['scan', mediumRoot, '--summary', '--fail-confidence', 'high']);
  assert.strictEqual(medium.status, 0,
    `medium-confidence finding should not fail --fail-confidence high; stdout=${medium.stdout} stderr=${medium.stderr}`);

  fs.rmSync(highRoot, { recursive: true, force: true });
  fs.rmSync(mediumRoot, { recursive: true, force: true });
}

async function testDiffAgainstSarif() {
  const root = tmpRoot('diff');
  fs.writeFileSync(path.join(root, 'a.js'),
    `function h(req, db) { db.rawQuery("SELECT * FROM u WHERE id = " + req.body.id); }`,
  );

  const scanner = new ProjectScanner({ includeSuggestions: false });
  const oldReport = await scanner.scan(root);
  const oldSarif = path.join(os.tmpdir(), `fss-old-${Date.now()}.sarif`);
  fs.writeFileSync(oldSarif, JSON.stringify(toSarif(oldReport, root), null, 2));

  fs.writeFileSync(path.join(root, 'b.js'), `const token = Math.random();`);
  const out = runCli(['scan', root, '--json', '--diff-against', oldSarif]);
  assert.strictEqual(out.status, 0,
    `--diff-against should exit 0; stdout=${out.stdout} stderr=${out.stderr}`);
  const json = JSON.parse(out.stdout);
  const codes = json.findings.map(f => f.code);
  assert.ok(codes.includes('insecure-random'),
    `new finding should remain after SARIF diff: ${JSON.stringify(codes)}`);
  assert.ok(!codes.includes('injection-flaw'),
    `old SARIF finding should be filtered: ${JSON.stringify(codes)}`);

  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(oldSarif, { force: true });
}

async function testSlackNotification() {
  const root = tmpRoot('notify');
  fs.writeFileSync(path.join(root, 'a.js'), `const token = Math.random();`);

  let received = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      received = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const out = await runCliAsync(['scan', root, '--summary', '--notify', `slack:http://127.0.0.1:${port}/hook`]);
    assert.strictEqual(out.status, 0,
      `--notify slack should not fail scan; stdout=${out.stdout} stderr=${out.stderr}`);
    assert.ok(received?.text?.includes('SAST scan'),
      `expected Slack-style text payload, got ${JSON.stringify(received)}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

async function testTelemetryDurations() {
  const root = tmpRoot('telemetry');
  const dataHome = path.join(root, '.data');
  fs.writeFileSync(path.join(root, 'a.js'), `const token = Math.random();`);

  const out = runCli(['scan', root, '--json'], {
    env: { ...process.env, HOME: root, XDG_DATA_HOME: dataHome },
  });
  assert.strictEqual(out.status, 0,
    `telemetry scan should exit 0; stdout=${out.stdout} stderr=${out.stderr}`);
  const report = JSON.parse(out.stdout);
  assert.ok(typeof report.stats.stageDurationsMs?.fast === 'number',
    `json report should expose stage durations: ${out.stdout}`);

  const telemetryFile = path.join(dataHome, 'flutter-supabase-security-scanner', 'telemetry.json');
  const telemetry = JSON.parse(fs.readFileSync(telemetryFile, 'utf8'));
  const last = telemetry.at(-1);
  assert.ok(typeof last.stageDurationsMs?.fast === 'number',
    `telemetry should store stage durations: ${JSON.stringify(last)}`);
  assert.ok(typeof last.durationDistributionMs?.p50 === 'number',
    `telemetry should store duration distribution: ${JSON.stringify(last)}`);

  fs.rmSync(root, { recursive: true, force: true });
}

(async function main() {
  await testFailConfidence();
  await testDiffAgainstSarif();
  await testSlackNotification();
  await testTelemetryDurations();
  console.log('cli-filters self-test: PASS');
})().catch(err => {
  console.error('cli-filters self-test: FAIL');
  console.error(err);
  process.exit(1);
});
