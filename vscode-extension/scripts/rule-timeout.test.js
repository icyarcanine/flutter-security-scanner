#!/usr/bin/env node
/**
 * Bounded-rule-runtime self-test (§QW-12 / §SC-8).
 *
 * Builds a `ProjectScanner` whose `runStage` races each rule against a wall
 * clock. Verifies:
 *   1. A pathological rule that hangs forever is aborted at the budget and
 *      surfaces a `scanner-internal-error` finding naming the offending rule.
 *   2. The budget is configurable via `ruleTimeoutMs`.
 *   3. `ruleTimeoutMs: 0` disables the budget (well-behaved rules still pass).
 *   4. A fast rule running alongside a slow one is unaffected — its findings
 *      survive intact.
 *
 * The test reaches into the same `runStage` code path the production scan
 * uses, by patching `buildDefaultRules` to return only synthetic rules. That
 * keeps the test fast (no AST, no fixtures) and isolated.
 */

const assert = require('assert');
const path = require('path');

// Patch the rule registry BEFORE requiring scanner.ts (which imports it).
const rulesIndexPath = require.resolve('../out/rules/index');
const fastFinding = {
  category: 'security',
  code: 'fast-rule-output',
  message: 'fast rule produced this',
  fix: 'n/a',
  severity: 'low',
};
const synthRules = [
  {
    code: 'fast-rule',
    stage: 1, // fast
    evaluate: () => [fastFinding],
  },
  {
    code: 'slow-rule',
    stage: 1,
    evaluate: () => new Promise(() => { /* never resolves */ }),
  },
];
require.cache[rulesIndexPath] = {
  id: rulesIndexPath,
  filename: rulesIndexPath,
  loaded: true,
  exports: {
    buildDefaultRules: () => synthRules.map(r => ({ ...r })),
  },
};

const { ProjectScanner } = require('../out/scanner/scanner');
const { ProjectContext } = require('../out/scanner/projectContext');
const { ScannedFile } = require('../out/scanner/scannedFile');

function fakeContext() {
  // ProjectContext expects a populated rootPath + at least one file so the
  // scanner doesn't short-circuit. The synthetic rules ignore the content.
  const file = new ScannedFile('/tmp/x.js', 'x.js', '');
  return new ProjectContext('/tmp', [file]);
}

async function withInjectedContext(scanner) {
  // Stub `ProjectContext.load` so we don't hit the real filesystem.
  const original = ProjectContext.load;
  ProjectContext.load = async () => fakeContext();
  try {
    return await scanner.scan('/tmp');
  } finally {
    ProjectContext.load = original;
  }
}

async function testBudgetAbortsSlowRule() {
  const scanner = new ProjectScanner({ ruleTimeoutMs: 200 });
  const t0 = Date.now();
  const report = await withInjectedContext(scanner);
  const elapsed = Date.now() - t0;

  assert.ok(elapsed < 2000, `scan took ${elapsed}ms, should have aborted near the 200ms budget`);

  const fast = report.findings.find(f => f.code === 'fast-rule-output');
  assert.ok(fast, 'fast rule output must survive when a sibling rule times out');

  const timeoutFinding = report.findings.find(f => f.code === 'scanner-internal-error');
  assert.ok(timeoutFinding, 'timeout must surface a scanner-internal-error finding');
  assert.match(timeoutFinding.message, /slow-rule/, 'timeout finding must name the offending rule');
  assert.match(timeoutFinding.message, /200/, 'timeout finding must mention the budget');
}

async function testZeroDisablesBudget() {
  // Replace slow-rule with one that's slow but finite so the test can still
  // complete when the budget is disabled.
  const replaced = require.cache[rulesIndexPath].exports.buildDefaultRules;
  require.cache[rulesIndexPath].exports.buildDefaultRules = () => ([
    {
      code: 'slow-but-finite',
      stage: 1,
      evaluate: () => new Promise(resolve => setTimeout(() => resolve([fastFinding]), 100)),
    },
  ]);
  try {
    const scanner = new ProjectScanner({ ruleTimeoutMs: 0 });
    const report = await withInjectedContext(scanner);
    const internal = report.findings.find(f => f.code === 'scanner-internal-error');
    assert.ok(!internal, 'budget=0 must not synthesize internal-error findings');
    const fast = report.findings.find(f => f.code === 'fast-rule-output');
    assert.ok(fast, 'finite slow rule output must come through when budget is disabled');
  } finally {
    require.cache[rulesIndexPath].exports.buildDefaultRules = replaced;
  }
}

(async function main() {
  await testBudgetAbortsSlowRule();
  await testZeroDisablesBudget();
  console.log('rule-timeout self-test: PASS');
})().catch(err => {
  console.error('rule-timeout self-test: FAIL');
  console.error(err);
  process.exit(1);
});
