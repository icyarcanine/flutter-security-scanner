#!/usr/bin/env node
/**
 * Bounded-file-size self-test (§QW-13 / §SC-4).
 *
 * Verifies that:
 *   1. Files larger than the configured per-file budget are dropped from the
 *      file list AND surfaced via `report.skippedFiles` (no silent loss).
 *   2. Files at-or-under the budget pass through unchanged.
 *   3. The `maxFileSizeBytes: 0` escape hatch loads even huge files.
 *   4. The default budget is 1 MB so existing behavior is preserved.
 *
 * Uses a real temp dir + filesystem walk so the integration with
 * `ProjectContext.load` is exercised end-to-end.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { ProjectContext, DEFAULT_MAX_FILE_SIZE_BYTES } = require('../out/scanner/projectContext');

function tmpRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `fss-qw13-${label}-`));
}

function writeBytes(file, bytes) {
  fs.writeFileSync(file, Buffer.alloc(bytes, 0x61)); // "a"
}

async function testBudgetSkipsOversize() {
  const root = tmpRoot('skips');
  writeBytes(path.join(root, 'small.js'), 1024);                 // 1 KB
  writeBytes(path.join(root, 'big.js'), 200 * 1024);             // 200 KB
  writeBytes(path.join(root, 'huge.js'), 5 * 1024 * 1024);       // 5 MB

  const ctx = await ProjectContext.load(root, undefined, { maxFileSizeBytes: 100 * 1024 });
  const loaded = ctx.files.map(f => path.basename(f.relativePath)).sort();
  assert.deepStrictEqual(loaded, ['small.js'], `expected only small.js, got ${loaded.join(',')}`);

  const skipped = ctx.skippedFiles.map(s => path.basename(s.relativePath)).sort();
  assert.deepStrictEqual(skipped, ['big.js', 'huge.js'], `unexpected skip list: ${skipped.join(',')}`);

  for (const sf of ctx.skippedFiles) {
    assert.strictEqual(sf.reason, 'oversize');
    assert.ok(sf.sizeBytes > 0);
  }
  fs.rmSync(root, { recursive: true, force: true });
}

async function testZeroDisablesCap() {
  const root = tmpRoot('zero');
  writeBytes(path.join(root, 'huge.js'), 3 * 1024 * 1024); // 3 MB
  const ctx = await ProjectContext.load(root, undefined, { maxFileSizeBytes: 0 });
  assert.strictEqual(ctx.skippedFiles.length, 0);
  assert.strictEqual(ctx.files.length, 1);
  assert.strictEqual(path.basename(ctx.files[0].relativePath), 'huge.js');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testDefaultBudgetIs1MB() {
  // The default must remain 1 MB so legacy callers see no behavior change.
  assert.strictEqual(DEFAULT_MAX_FILE_SIZE_BYTES, 1024 * 1024);

  const root = tmpRoot('default');
  // Just under and just over the default cap.
  writeBytes(path.join(root, 'under.js'), 1024 * 1024 - 1);  // ~1 MB - 1
  writeBytes(path.join(root, 'over.js'),  1024 * 1024 + 1);  // ~1 MB + 1
  const ctx = await ProjectContext.load(root); // no opts → default
  const loaded = ctx.files.map(f => path.basename(f.relativePath)).sort();
  assert.deepStrictEqual(loaded, ['under.js']);
  const skipped = ctx.skippedFiles.map(s => path.basename(s.relativePath));
  assert.deepStrictEqual(skipped, ['over.js']);
  fs.rmSync(root, { recursive: true, force: true });
}

(async function main() {
  await testBudgetSkipsOversize();
  await testZeroDisablesCap();
  await testDefaultBudgetIs1MB();
  console.log('file-size-budget self-test: PASS');
})().catch(err => {
  console.error('file-size-budget self-test: FAIL');
  console.error(err);
  process.exit(1);
});
