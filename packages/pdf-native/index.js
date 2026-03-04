/* eslint-disable @typescript-eslint/no-var-requires */
/* eslint-disable no-console */
'use strict';

const { existsSync, readFileSync } = require('fs');
const { join } = require('path');

const { platform, arch } = process;

/** @type {string} */
let nativeBinding = null;
let loadError = null;

// Candidate paths for the compiled .node binary
const candidates = [
  // Platform-specific npm package (published builds)
  join(__dirname, `pdf-native.${platform}-${arch === 'x64' ? 'x86_64' : arch}.node`),
  // Local napi build output
  join(__dirname, 'pdf-native.node'),
  // Monorepo cargo target
  join(__dirname, '..', '..', 'target', 'release', 'libpdf_native.node'),
  join(__dirname, '..', '..', 'target', 'release', 'pdf_native.node'),
  // Debug build
  join(__dirname, '..', '..', 'target', 'debug', 'libpdf_native.node'),
  join(__dirname, '..', '..', 'target', 'debug', 'pdf_native.node'),
];

for (const candidate of candidates) {
  if (existsSync(candidate)) {
    try {
      nativeBinding = require(candidate);
      break;
    } catch (e) {
      loadError = e;
    }
  }
}

if (!nativeBinding) {
  const msg = [
    'Failed to load @apexmail/pdf-native native module.',
    '',
    'Tried the following paths:',
    ...candidates.map((c) => `  - ${c}`),
    '',
    loadError ? `Last error: ${loadError.message}` : 'No .node file found.',
    '',
    'Run `pnpm --filter @apexmail/pdf-native build` to compile.',
  ].join('\n');

  // Don't throw — allow graceful fallback to HTTP-based pdf-renderer
  console.warn(msg);
  module.exports = {
    renderPdf: () => Promise.reject(new Error('@apexmail/pdf-native not available')),
    renderPdfSync: () => { throw new Error('@apexmail/pdf-native not available'); },
    listTemplates: () => [],
  };
} else {
  module.exports = nativeBinding;
}
