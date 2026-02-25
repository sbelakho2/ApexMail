import fs from 'node:fs';
import path from 'node:path';

const root = '/Users/sabelakhoua/IdeaProjects/ApexMail';
const scanRoots = ['apps', 'packages', 'services', 'tools'].map((p) => path.join(root, p));

const excludeParts = new Set([
  '.git',
  'node_modules',
  '.next',
  'dist',
  'build',
  'out',
  'coverage',
  'test-results',
  'reports',
  'snapshots',
  '.venv',
  'venv',
  'target',
  'vendor',
  '__pycache__',
]);

const includeExt = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rs',
  '.go',
  '.java',
  '.kt',
  '.rb',
  '.php',
  '.sql',
  '.sh',
  '.yml',
  '.yaml',
  '.json',
]);

const patterns = [
  ['TODO left in code', /\bTODO\b/i],
  ['FIXME left in code', /\bFIXME\b/i],
  ['XXX/HACK marker', /\b(?:XXX|HACK)\b/i],
  ['Console logging in app code', /\bconsole\.(?:log|debug|trace)\s*\(/],
  ['Debugger statement present', /\bdebugger\b/],
  ['Any type usage', /\b:\s*any\b|\b<any>\b|\bas\s+any\b/],
  ['ts-ignore / ts-nocheck', /@ts-ignore|@ts-nocheck/],
  ['Disabled eslint rule', /eslint-disable(?:-next-line|-line)?/],
  ['Catch without action', /catch\s*\([^)]*\)\s*\{\s*\}/],
  ['Throw generic Error', /throw\s+new\s+Error\s*\(/],
  ['Potential hardcoded secret token key', /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"'\n]{6,}["']/i],
  ['Insecure http URL literal', /["']http:\/\/[^"']+["']/i],
  ['InnerHTML style injection', /dangerouslySetInnerHTML|innerHTML\s*=|insertAdjacentHTML\s*\(/],
  ['Random/Math.random in logic', /\bMath\.random\s*\(/],
  ['Date.now usage in ID-like contexts', /(id|key|nonce|seed)[^\n]{0,30}Date\.now\s*\(/i],
  ['setTimeout usage review', /setTimeout\s*\(/],
  ['setInterval usage', /setInterval\s*\(/],
  ['Unsafe SQL string interpolation', /(?:query|execute|raw|sql)\s*\(\s*`[^`]*(?:\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)[^`]*\$\{/i],
  ['eval/new Function usage', /(?<!\.)\beval\s*\(|new\s+Function\s*\(/],
  ['Process exit in runtime code', /\bprocess\.exit\s*\(/],
  ['Broad exception catch in Java', /catch\s*\(\s*Exception\s+\w+\s*\)/],
  ['Unbounded retry marker', /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/],
];

function shouldExcludeDir(dirPath) {
  const rel = path.relative(root, dirPath);
  if (!rel || rel.startsWith('..')) return false;
  const parts = rel.split(path.sep);
  return parts.some((part) => excludeParts.has(part));
}

function walk(dir, out) {
  if (!fs.existsSync(dir)) return;
  if (shouldExcludeDir(dir)) return;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, out);
      continue;
    }
    const ext = path.extname(entry.name).toLowerCase();
    if (includeExt.has(ext)) out.push(fullPath);
  }
}

const files = [];
for (const scanRoot of scanRoots) walk(scanRoot, files);

const findings = [];
for (const filePath of files) {
  let text = '';
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch {
    continue;
  }

  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const snippet = line.trim();
    if (!snippet) continue;

    for (const [title, pattern] of patterns) {
      if (!pattern.test(line)) continue;

      let severity = 'medium';
      const lower = title.toLowerCase();
      if (lower.includes('secret') || lower.includes('sql') || lower.includes('innerhtml') || lower.includes('eval')) severity = 'high';
      if (lower.includes('todo') || lower.includes('fixme') || lower.includes('console logging')) severity = 'low';

      findings.push({
        title,
        severity,
        file: path.relative(root, filePath).replaceAll(path.sep, '/'),
        line: index + 1,
        snippet: snippet.slice(0, 180),
      });
    }
  }
}

const dedup = [];
const seen = new Set();
for (const item of findings) {
  const key = `${item.title}::${item.file}::${item.line}`;
  if (seen.has(key)) continue;
  seen.add(key);
  dedup.push(item);
}

const severityOrder = { high: 0, medium: 1, low: 2 };
dedup.sort((a, b) => {
  const sev = (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
  if (sev !== 0) return sev;
  if (a.file !== b.file) return a.file.localeCompare(b.file);
  if (a.line !== b.line) return a.line - b.line;
  return a.title.localeCompare(b.title);
});

const outPath = '/tmp/apex_code_findings_firstparty.json';
fs.writeFileSync(outPath, `${JSON.stringify(dedup, null, 2)}\n`, 'utf8');

console.log(`files_scanned ${files.length}`);
console.log(`findings ${dedup.length}`);
console.log(`out ${outPath}`);