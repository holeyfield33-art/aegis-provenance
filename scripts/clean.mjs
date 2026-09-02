#!/usr/bin/env node
// Remove the build output directory before a build so stale files from an
// earlier layout can never linger into the package (audit follow-up:
// `tsconfig.build.json` excludes `src/testing`, but TypeScript does not delete
// a `dist/testing` directory a previous build already emitted, so an old build
// dir could silently ship internal harness code in a manual publish).
//
// Deletes ONLY the `dist` directory directly under this repository root, after
// validating the resolved path, so the script cannot be coaxed into removing
// anything else.

import { rmSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = resolve(repoRoot, 'dist');

// Guard: the target must be exactly <repoRoot>/dist and nothing else.
const expected = join(repoRoot, 'dist');
if (distDir !== expected) {
  console.error(`Refusing to clean unexpected path: ${distDir} (expected ${expected})`);
  process.exit(1);
}

// Diagnostics go to stderr so this script never pollutes stdout when it runs
// inside an `npm pack --json` / `npm run build` lifecycle whose stdout a caller
// parses.
if (existsSync(distDir)) {
  rmSync(distDir, { recursive: true, force: true });
  console.error(`Cleaned ${distDir}`);
} else {
  console.error('Nothing to clean (dist/ does not exist).');
}
