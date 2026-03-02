#!/usr/bin/env node
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const TARGET_ROOT = path.join(ROOT, 'services', 'mail-server', 'crates');

function walk(dir, files = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, files);
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.rs')) {
      files.push(fullPath);
    }
  }
  return files;
}

function checkFile(filePath) {
  const source = readFileSync(filePath, 'utf8');
  const lines = source.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    if (trimmed.startsWith('//')) continue;
    if (/\bunsafe\s*\{/.test(line) || /\bunsafe\s+fn\b/.test(line)) {
      findings.push({ line: i + 1, text: line.trim() });
    }
  }

  return findings;
}

const rustFiles = walk(TARGET_ROOT);
const violations = [];

for (const filePath of rustFiles) {
  const findings = checkFile(filePath);
  if (findings.length === 0) continue;
  for (const finding of findings) {
    violations.push({
      file: path.relative(ROOT, filePath).replace(/\\/g, '/'),
      line: finding.line,
      text: finding.text,
    });
  }
}

if (violations.length > 0) {
  console.error('[rust-no-unsafe] FAILED: unsafe usage detected in mail-server crates');
  for (const violation of violations) {
    console.error(`  - ${violation.file}:${violation.line}: ${violation.text}`);
  }
  process.exit(1);
}

console.log(`[rust-no-unsafe] OK: no unsafe blocks/functions in ${rustFiles.length} Rust source files.`);
