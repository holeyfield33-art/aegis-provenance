#!/usr/bin/env node
// Clean-pack package smoke test (finding #7: no clean-clone package smoke test
// existed). Packs the package exactly as it would be published, installs the
// tarball into a throwaway directory with no access to the source tree, imports
// the ESM entrypoint, runs a real runAegis call, and asserts the published
// surface actually works. Also asserts the published tarball does NOT ship the
// internal testing harness (dist/testing) so a packaging regression is caught
// here rather than by consumers.
//
// Exits non-zero on any failure. No external dependencies; Node >= 20.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = process.cwd();
const workDir = mkdtempSync(join(tmpdir(), 'aegis-smoke-'));

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
}

let failed = false;
function check(condition, message) {
  if (condition) {
    console.log(`  ok   ${message}`);
  } else {
    console.error(`  FAIL ${message}`);
    failed = true;
  }
}

try {
  console.log('Package smoke test');
  console.log('------------------');

  // 1. Pack the package as it would be published.
  const packOut = run('npm', ['pack', '--json', '--pack-destination', workDir], ROOT);
  const tarballName = JSON.parse(packOut)[0].filename;
  const tarballPath = join(workDir, tarballName);
  check(existsSync(tarballPath), `packed tarball ${tarballName}`);

  // 2. Inspect the tarball contents.
  const contents = run('npm', ['pack', '--dry-run', '--json'], ROOT);
  const files = JSON.parse(contents)[0].files.map((f) => f.path);
  check(
    files.some((p) => p === 'dist/index.js'),
    'ships dist/index.js'
  );
  check(
    files.some((p) => p === 'dist/index.d.ts'),
    'ships dist/index.d.ts type declarations'
  );
  check(
    !files.some((p) => p.startsWith('dist/testing/')),
    'does NOT ship dist/testing internal harness'
  );
  check(files.includes('README.md') && files.includes('LICENSE'), 'ships README and LICENSE');

  // 3. Install the tarball in an isolated consumer project.
  const consumerDir = join(workDir, 'consumer');
  execFileSync('mkdir', ['-p', consumerDir]);
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'consumer', version: '1.0.0', type: 'module', private: true }, null, 2)
  );
  run('npm', ['install', '--no-audit', '--no-fund', tarballPath], consumerDir);

  // 4. Import the ESM entrypoint and run a real call.
  const entry = pathToFileURL(join(consumerDir, 'node_modules', 'aegis-provenance', 'dist', 'index.js')).href;
  const aegis = await import(entry);
  check(typeof aegis.runAegis === 'function', 'runAegis is exported and callable');
  check(typeof aegis.wrapSpan === 'function', 'wrapSpan is exported');
  check(typeof aegis.ReceiptStore === 'function', 'ReceiptStore is exported');

  const result = await aegis.runAegis({
    system: 'You are a helpful assistant.',
    userMessage: 'Summarize the retrieved note.',
    retrievedSpans: [{ origin: 'untrusted-web', content: 'A benign note about the weather.' }],
    tools: [{ name: 'search', description: 'Search a corpus.' }],
    modelClient: { async call() { return { type: 'text', text: 'It is sunny.' }; } }
  });
  check(result?.receipt?.verdict === 'allow', 'runAegis produces an allow verdict on a benign flow');
  check(typeof result?.receipt?.receipt_hash === 'string' && result.receipt.receipt_hash.length === 64, 'receipt carries a sha256 hash');
} catch (error) {
  console.error('Smoke test threw:', error);
  failed = true;
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

if (failed) {
  console.error('\nPackage smoke test FAILED.');
  process.exit(1);
}
console.log('\nPackage smoke test PASSED.');
