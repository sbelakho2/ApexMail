'use strict'

/**
 * crypto-native – Native Node.js bindings for ApexMail cryptographic operations.
 *
 * Loads the platform-specific .node binary compiled by napi-rs.
 * Falls back to an informative error when the binary is missing so that
 * development machines that haven't compiled the addon get a clear message
 * rather than a cryptic MODULE_NOT_FOUND.
 */

const { existsSync, readdirSync } = require('fs')
const { join } = require('path')

/** Return the first .node file found in `dir`, or null. */
function findNativeAddon(dir) {
  if (!existsSync(dir)) return null
  const entry = readdirSync(dir).find((f) => f.endsWith('.node'))
  return entry ? join(dir, entry) : null
}

/** Candidate paths, in preference order. */
function candidatePaths() {
  const platform = process.platform               // 'darwin', 'linux', 'win32'
  const arch = process.arch                       // 'x64', 'arm64'
  const abi = process.versions.modules            // e.g. '115'

  const platformTag = (() => {
    if (platform === 'darwin') return `darwin-${arch}`
    if (platform === 'linux')  return `linux-${arch}-gnu`
    if (platform === 'win32')  return `win32-${arch}-msvc`
    return `${platform}-${arch}`
  })()

  return [
    // 1. Pre-built platform package installed via optionalDependencies
    join(__dirname, '..', `@apexmail/crypto-native-${platformTag}`),
    // 2. Locally compiled release build (napi build --release)
    join(__dirname, `crypto-native.${platform}-${arch}.node`),
    // 3. Locally compiled debug build
    join(
      __dirname,
      '..', '..', 'packages', 'crypto-native',
      'target', 'debug',
      `crypto_native.dylib`,
    ),
    // 4. Direct target/release path for the monorepo
    join(
      __dirname,
      '..', '..', 'packages', 'crypto-native',
      'target', 'release',
      `libcrypto_native.${platform === 'darwin' ? 'dylib' : platform === 'win32' ? 'dll' : 'so'}`,
    ),
  ]
}

let nativeBinding = null
let loadError = null

for (const candidate of candidatePaths()) {
  const addon = findNativeAddon(candidate) ?? (existsSync(candidate) ? candidate : null)
  if (!addon) continue
  try {
    nativeBinding = require(addon)
    break
  } catch (err) {
    loadError = err
  }
}

if (!nativeBinding) {
  // Provide a clear, actionable error message.
  throw new Error(
    `[crypto-native] Failed to load the native addon for ${process.platform}-${process.arch}.\n` +
    `To build it locally, run:\n` +
    `  cd packages/crypto-native && npm run build\n` +
    (loadError ? `\nUnderlying error: ${loadError.message}` : ''),
  )
}

module.exports = nativeBinding
