#!/usr/bin/env node
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const BILLING_SRC = path.join(ROOT, 'apps', 'billing', 'src');
const BASELINE_FILE = path.join(ROOT, 'docs', 'migration', 'baselines', 'billing-ts-files.baseline.json');

function walkTsFiles(dir, output = []) {
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkTsFiles(fullPath, output);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith('.ts')) {
      continue;
    }
    output.push(path.relative(ROOT, fullPath).replace(/\\/g, '/'));
  }
  return output;
}

function isStripeOnlyPath(filePath) {
  const normalized = filePath.toLowerCase();
  return (
    normalized.includes('/webhooks') ||
    normalized.includes('stripe')
  );
}

function asSet(arr) {
  return new Set(arr);
}

function diff(current, baseline) {
  const currentSet = asSet(current);
  const baselineSet = asSet(baseline);
  const added = current.filter((file) => !baselineSet.has(file)).sort();
  const deleted = baseline.filter((file) => !currentSet.has(file)).sort();
  return { added, deleted };
}

function main() {
  const baseline = JSON.parse(readFileSync(BASELINE_FILE, 'utf8'));
  const trackedFiles = Array.isArray(baseline.trackedFiles) ? baseline.trackedFiles : [];
  const currentFiles = walkTsFiles(BILLING_SRC).sort();

  const { added, deleted } = diff(currentFiles, trackedFiles);
  const nonStripeAdded = added.filter((file) => !isStripeOnlyPath(file));
  const stripeScopedAdded = added.filter((file) => isStripeOnlyPath(file));

  console.log('[billing-ts-boundary] Baseline file:', path.relative(ROOT, BASELINE_FILE));
  console.log('[billing-ts-boundary] Current files:', currentFiles.length);
  console.log('[billing-ts-boundary] Added files:', added.length);
  console.log('[billing-ts-boundary] Deleted files:', deleted.length);

  if (stripeScopedAdded.length > 0) {
    console.log('[billing-ts-boundary] Added Stripe-scoped files (allowed):');
    for (const file of stripeScopedAdded) {
      console.log(`  - ${file}`);
    }
  }

  if (deleted.length > 0) {
    console.log('[billing-ts-boundary] Deleted files (allowed, usually migration progress):');
    for (const file of deleted) {
      console.log(`  - ${file}`);
    }
  }

  if (nonStripeAdded.length > 0) {
    console.error('[billing-ts-boundary] FAILED: New non-Stripe billing TS files detected:');
    for (const file of nonStripeAdded) {
      console.error(`  - ${file}`);
    }
    process.exit(1);
  }

  console.log('[billing-ts-boundary] OK: No new non-Stripe TS billing files were added.');
}

main();
