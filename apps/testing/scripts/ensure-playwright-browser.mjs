import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { chromium } from 'playwright';

const executable = chromium.executablePath();

if (fs.existsSync(executable)) {
  console.log(`[playwright] chromium already installed at ${executable}`);
  process.exit(0);
}

const cliPath = path.resolve(process.cwd(), 'node_modules/.bin/playwright');
console.log(`[playwright] installing chromium because ${executable} is missing`);

const result = spawnSync(cliPath, ['install', 'chromium'], {
  stdio: 'inherit',
  shell: false,
});

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}