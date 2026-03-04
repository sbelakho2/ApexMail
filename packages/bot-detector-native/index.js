'use strict'

/**
 * bot-detector-native – Native Node.js bindings for bot/crawler detection.
 *
 * Loads the platform-specific .node binary compiled by napi-rs.
 */

const { existsSync, readdirSync } = require('fs')
const { join } = require('path')

function findNativeAddon(dir) {
  if (!existsSync(dir)) return null
  const entry = readdirSync(dir).find((f) => f.endsWith('.node'))
  return entry ? join(dir, entry) : null
}

function candidatePaths() {
  const platform = process.platform
  const arch = process.arch

  const platformTag = (() => {
    if (platform === 'darwin') return `darwin-${arch}`
    if (platform === 'linux')  return `linux-${arch}-gnu`
    if (platform === 'win32')  return `win32-${arch}-msvc`
    return `${platform}-${arch}`
  })()

  return [
    join(__dirname, '..', `@apexmail/bot-detector-native-${platformTag}`),
    join(__dirname, `bot-detector-native.${platform}-${arch}.node`),
    join(
      __dirname,
      '..', '..', 'packages', 'bot-detector-native',
      'target', 'release',
      `libbot_detector_native.${platform === 'darwin' ? 'dylib' : platform === 'win32' ? 'dll' : 'so'}`,
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
  throw new Error(
    `[bot-detector-native] Failed to load the native addon for ${process.platform}-${process.arch}.\n` +
    `To build it locally, run:\n` +
    `  cd packages/bot-detector-native && npm run build\n` +
    (loadError ? `\nUnderlying error: ${loadError.message}` : ''),
  )
}

module.exports = nativeBinding
