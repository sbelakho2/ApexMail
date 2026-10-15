#!/usr/bin/env node
/**
 * Dual-build pipeline for @apexmail/node.
 *
 * Emits:
 *   dist/esm/  — ES modules + .d.ts declarations (NodeNext)
 *   dist/cjs/  — CommonJS modules (the `require` arm of the exports map)
 *
 * Both trees are plain `tsc` output. The per-tree package.json files only
 * pin the module format, so Node interprets dist/cjs/*.js as CommonJS even
 * though the package root is `"type": "module"` (the standard dual-package
 * layout; see the TypeScript Handbook, "Publishing: dual packages").
 *
 * `dist/` is intentionally not committed: this script is what the CI lane
 * (ci/stages/test.sh `run_sdk_tests`) and `npm test` run.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TSC = join(ROOT, "node_modules", "typescript", "bin", "tsc");

if (!existsSync(TSC)) {
  console.error(`build: TypeScript compiler missing at ${TSC} — run 'npm ci' first`);
  process.exit(1);
}

const run = (args) => {
  const result = spawnSync(process.execPath, [TSC, ...args], {
    cwd: ROOT,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    console.error(`build: tsc ${args.join(" ")} failed`);
    process.exit(result.status ?? 1);
  }
};

rmSync(join(ROOT, "dist"), { recursive: true, force: true });
run(["-p", "tsconfig.esm.json"]);
run(["-p", "tsconfig.cjs.json"]);

for (const [dir, type] of [
  ["dist/esm", "module"],
  ["dist/cjs", "commonjs"],
]) {
  const target = join(ROOT, dir);
  if (!existsSync(target)) {
    mkdirSync(target, { recursive: true });
  }
  writeFileSync(join(target, "package.json"), `${JSON.stringify({ type }, null, 2)}\n`);
}

for (const entry of ["dist/esm/index.js", "dist/esm/index.d.ts", "dist/cjs/index.js"]) {
  if (!existsSync(join(ROOT, entry))) {
    console.error(`build: expected output missing: ${entry}`);
    process.exit(1);
  }
}

console.log("build: dist/esm + dist/cjs written (marker package.json files in place)");
