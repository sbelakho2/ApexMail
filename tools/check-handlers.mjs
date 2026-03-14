import fs from 'fs';

const unifiedSrc = fs.readFileSync('apps/ai/src/assistant/unified.ts', 'utf-8');
const actionsSrc = fs.readFileSync('apps/ai/src/assistant/actions.ts', 'utf-8');

// Extract all AssistantActionType values
const typeMatch = unifiedSrc.match(/export type AssistantActionType\s*=\s*([\s\S]*?);/);
if (!typeMatch) { console.log('NO TYPE FOUND'); process.exit(1); }
const types = typeMatch[1].match(/'([^']+)'/g).map(s => s.replace(/'/g, ''));

// Extract handler keys from all builder fns
const handlerKeys = new Set();
const re = /^\s+(\w+):\s*async/gm;
let m;
while ((m = re.exec(actionsSrc)) !== null) handlerKeys.add(m[1]);

const missing = types.filter(t => !handlerKeys.has(t));
const extra = [...handlerKeys].filter(k => !types.includes(k));

console.log('Total AssistantActionType values:', types.length);
console.log('Total handler keys:', handlerKeys.size);
console.log('Missing handlers:', missing.length);
if (missing.length > 0) console.log('  ->', missing.join(', '));
console.log('Extra handlers:', extra.length);
if (extra.length > 0) console.log('  ->', extra.join(', '));

if (missing.length > 0 || extra.length > 0) {
  process.exit(1);
}
