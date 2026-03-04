/**
 * Preact Islands Build Pipeline
 *
 * Builds each island as an independent ES module with code splitting.
 * Preact core is shared across all islands via the splitting feature.
 *
 * Output: ../static/js/islands/*.js
 *
 * Usage:
 *   node build.mjs          # one-shot build
 *   node build.mjs --watch  # watch mode for development
 */

import * as esbuild from 'esbuild';
import { readdirSync } from 'fs';
import { join, basename } from 'path';

const ISLANDS_DIR = './src';
const OUT_DIR = '../static/js/islands';

// Discover all island entry points
const entries = readdirSync(ISLANDS_DIR)
  .filter((f) => f.endsWith('.tsx') || f.endsWith('.ts'))
  .filter((f) => !f.startsWith('_') && f !== 'hydrate.ts')
  .map((f) => join(ISLANDS_DIR, f));

/** @type {esbuild.BuildOptions} */
const buildOptions = {
  entryPoints: [...entries, join(ISLANDS_DIR, 'hydrate.ts')],
  outdir: OUT_DIR,
  bundle: true,
  splitting: true,
  format: 'esm',
  target: ['es2020'],
  minify: true,
  treeShaking: true,
  sourcemap: false,
  metafile: true,
  jsx: 'automatic',
  jsxImportSource: 'preact',
  alias: {
    'react': 'preact/compat',
    'react-dom': 'preact/compat',
  },
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  // Keep chunk names readable
  chunkNames: 'chunks/[name]-[hash]',
};

const isWatch = process.argv.includes('--watch');

if (isWatch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('[islands] watching for changes...');
} else {
  const result = await esbuild.build(buildOptions);

  // Print bundle size report
  if (result.metafile) {
    const text = await esbuild.analyzeMetafile(result.metafile, {
      verbose: false,
    });
    console.log('[islands] Build complete:\n');
    console.log(text);

    // Calculate total output size
    const outputs = result.metafile.outputs;
    let totalBytes = 0;
    for (const [file, info] of Object.entries(outputs)) {
      totalBytes += info.bytes;
    }
    console.log(`\nTotal output: ${(totalBytes / 1024).toFixed(1)} KB`);
  }
}
