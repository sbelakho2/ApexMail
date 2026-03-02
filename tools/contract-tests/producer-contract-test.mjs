import fs from 'node:fs';
import path from 'node:path';

const cargoWorkspace = fs.readFileSync(path.resolve('services/mail-server/Cargo.toml'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.resolve('docs/api-contract-manifest.json'), 'utf8'));

function fail(message) {
  console.error(`[producer-contract-test] ${message}`);
  process.exit(1);
}

if (!cargoWorkspace.includes('crates/api-server')) {
  fail('Rust workspace does not include crates/api-server');
}

if (!Array.isArray(manifest.backendRoutePatterns) || manifest.backendRoutePatterns.length === 0) {
  fail('backendRoutePatterns must be present and non-empty');
}

if (!Array.isArray(manifest.frontendRequiredEndpoints) || manifest.frontendRequiredEndpoints.length === 0) {
  fail('frontendRequiredEndpoints must be present and non-empty');
}

console.log('[producer-contract-test] OK');
