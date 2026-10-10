// Prototype-pollution regression for the page-influenced dictionary maps.
//
// A plain `{}` map keyed by a page-supplied string is a pollution sink:
// `map["__proto__"] = record` sets the map's [[Prototype]] to that record,
// so every other key inherits a forged entry. Every such store in the
// widget assets must be constructed with Object.create(null).
//
// Run with: node tests/prototype-pollution.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const here = path.dirname(fileURLToPath(import.meta.url));
const assets = path.resolve(here, '../assets');

function read(name) {
  return fs.readFileSync(path.join(assets, name), 'utf8');
}

const sources = {
  'widget-driver.js': read('widget-driver.js'),
  'widget-risk.js': read('widget-risk.js'),
  'widget-compat.js': read('widget-compat.js'),
  'widget-shims.js': read('widget-shims.js'),
  'execution-interpreter.js': read('execution-interpreter.js'),
};

const mapNames = [
  'kiwiWidgets',
  'compatControlById',
  'shimsControlById',
  'kiwiRuntimeGlueCache',
  'kiwiWorkerAssetCache',
  'kiwiModuleApis',
  'kiwiModuleLoads',
  'kiwiModuleFailedAt',
  'shimsScopeMapCache',
];

let failures = 0;
function check(label, fn) {
  try {
    fn();
    console.log(`ok - ${label}`);
  } catch (e) {
    failures += 1;
    console.error(`not ok - ${label}`);
    console.error(`  ${e && e.message}`);
  }
}

for (const [file, source] of Object.entries(sources)) {
  for (const mapName of mapNames) {
    check(`${file}: ${mapName} is never a plain {}`, () => {
      const plain = source.match(new RegExp(String.raw`\b${mapName}\s*=\s*\{\s*\}`, 'g')) ?? [];
      assert.deepEqual(plain, [], `${mapName} assigned a plain {}: ${plain.join(', ')}`);
    });
  }
  check(`${file}: docIds is never a plain {}`, () => {
    const plain = sources[file].match(/docIds:\s*\{\s*\}/g) ?? [];
    assert.deepEqual(plain, []);
  });
}

check('widget-driver.js: kiwiWidgets is Object.create(null)', () => {
  assert.match(sources['widget-driver.js'], /var\s+kiwiWidgets\s*=\s*Object\.create\(null\)/);
});
check('widget-compat.js: compatControlById is Object.create(null)', () => {
  assert.match(sources['widget-compat.js'], /var\s+compatControlById\s*=\s*Object\.create\(null\)/);
});
check('widget-shims.js: shimsControlById is Object.create(null)', () => {
  assert.match(sources['widget-shims.js'], /var\s+shimsControlById\s*=\s*Object\.create\(null\)/);
});

// Behavioral proof: a null-prototype map rejects the __proto__ pollution
// that a plain object accepts.
check('Object.create(null) rejects __proto__ pollution', () => {
  const safe = Object.create(null);
  const forged = { state: 'solving', token: '' };
  safe['__proto__'] = forged;
  assert.equal(Object.getPrototypeOf(safe), null, 'prototype must stay null');
  assert.equal(safe['other-id'], undefined, 'other keys must not inherit the forged record');
  assert.equal(safe['__proto__'], forged, 'the __proto__ key stays an ordinary own property');

  const unsafe = {};
  unsafe['__proto__'] = forged;
  assert.equal(unsafe['other-id'], undefined, 'control: plain {} own keys are empty');
  // The pollution shows up as an inherited property on other keys:
  assert.equal(Object.getPrototypeOf(unsafe), forged, 'plain {} [[Prototype]] is replaced');
});

if (failures > 0) {
  console.error(`FAIL: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('PASS: prototype-pollution dictionary maps');
