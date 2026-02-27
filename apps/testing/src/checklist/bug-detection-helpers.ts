import * as fs from 'node:fs';
import * as path from 'node:path';

export const APPS_DIR = path.join(__dirname, '../../../..', 'apps');
export const PACKAGES_DIR = path.join(__dirname, '../../../..', 'packages');

export function report(message: string): void {
  process.stderr.write(`${message}\n`);
}

export function readFileSafe(filePath: string): string | null {
  try {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, 'utf-8');
    }
  } catch {
    // ignore
  }
  return null;
}

export function checkAllFiles(
  dir: string,
  check: (content: string, filePath: string) => string[]
): string[] {
  const issues: string[] = [];
  if (!fs.existsSync(dir)) {
    return issues;
  }

  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isFile() && file.endsWith('.ts')) {
      const content = readFileSafe(filePath);
      if (content) {
        issues.push(...check(content, filePath));
      }
    } else if (stat.isDirectory()) {
      issues.push(...checkAllFiles(filePath, check));
    }
  }

  return issues;
}
