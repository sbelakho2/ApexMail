#!/usr/bin/env node
// Prints sha384-base64 SRI hashes for the built widget assets.
//
// Usage:
//   node tools/sri-hashes.mjs                      # all three assets
//   node tools/sri-hashes.mjs widget-driver.js     # a single asset
//
// The output lines are ready to paste into a script/link tag:
//   <script src="https://.../kiwicaptcha/2026-08-r1/widget-driver.js"
//           integrity="sha384-..." crossorigin="anonymous"></script>
// See `SECURITY.md` in this package for the full supply-chain guidance.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const assetsDir = join(here, "..", "assets");

const DEFAULT_ASSETS = ["kiwicaptcha-wasm.js", "kiwi-worker.js", "widget-driver.js", "widget.css"];
const names = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_ASSETS;

for (const name of names) {
  const data = readFileSync(join(assetsDir, name));
  const sri = `sha384-${createHash("sha384").update(data).digest("base64")}`;
  console.log(`${name}  ${sri}`);
}
