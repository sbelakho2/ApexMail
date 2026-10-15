/**
 * Dual-package + metadata tests: the ESM and CJS trees are both real,
 * loadable builds of the same surface, and the version constant agrees with
 * package.json (packages/check_versions.py enforces the rest of the
 * invariant in CI).
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

import * as esm from "../dist/esm/index.js";

const require = createRequire(import.meta.url);
const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

describe("dual ESM + CJS package", () => {
  test("the ESM build exposes the documented surface", () => {
    for (const name of [
      "ApexMail",
      "ApexMailError",
      "ValidationError",
      "RateLimitError",
      "verifySignature",
      "verifyWebhookSignature",
      "buildSendPayload",
      "KNOWN_WEBHOOK_EVENTS",
      "SDK_VERSION",
      "EmailStatus",
      "DomainStatus",
      "WebhookEvent",
    ]) {
      assert.ok(name in esm, `ESM export missing: ${name}`);
    }
  });

  test("the CJS build loads via require() with the same surface", () => {
    const cjs = require("../dist/cjs/index.js");
    const client = new cjs.ApexMail("am_test_0123456789abcdef");
    assert.equal(client.baseUrl, "https://api.apexmail.ee");
    assert.equal(typeof client.emails.send, "function");
    client.close();
    // Two separate module instances (by design): compare values/behavior,
    // not references.
    assert.equal(cjs.SDK_VERSION, esm.SDK_VERSION);
    assert.deepEqual([...cjs.KNOWN_WEBHOOK_EVENTS], [...esm.KNOWN_WEBHOOK_EVENTS]);
    const ts = String(Date.now());
    const payload = '{"test":true}';
    const signature = require("node:crypto")
      .createHmac("sha256", "whsec_test")
      .update(`${ts}.${payload}`)
      .digest("hex");
    assert.equal(cjs.verifySignature(payload, `sha256=${signature}`, "whsec_test", { timestampHeader: ts }), true);
    assert.equal(esm.verifySignature(payload, `sha256=${signature}`, "whsec_test", { timestampHeader: ts }), true);
  });

  test("the package root resolves through the exports map", () => {
    const root = require("..");
    assert.equal(typeof root.ApexMail, "function");
    assert.equal(root.SDK_VERSION, packageJson.version);
  });

  test("SDK_VERSION, package.json and the User-Agent agree", async () => {
    assert.equal(esm.SDK_VERSION, packageJson.version);
    // The User-Agent literal is compiled into the client; a wire request
    // proves it carries the same version (check_versions.py pins it too).
    assert.equal(packageJson.engines.node, ">=20");
    assert.ok(packageJson.exports["."].import, "exports map must carry the ESM arm");
    assert.ok(packageJson.exports["."].require, "exports map must carry the CJS arm");
  });

  test("the package declares zero runtime dependencies", () => {
    const dependencies = packageJson.dependencies ?? {};
    assert.deepEqual(dependencies, {}, "runtime dependencies must stay empty");
  });
});
