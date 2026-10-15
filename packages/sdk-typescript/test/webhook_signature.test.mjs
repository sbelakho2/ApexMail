/**
 * Webhook-signature verification tests.
 *
 * The platform (worker-processors/src/webhook/processor.rs sign_payload +
 * deliver_webhook) delivers:
 *
 *   X-ApexMail-Signature: sha256=<hex HMAC-SHA256>
 *   X-ApexMail-Timestamp: <milliseconds since epoch>
 *
 * and signs the exact string "{timestamp_millis}.{payload}". These tests
 * pin that format, including the known vector shared with sdk-python's
 * test_webhook_signature_platform.py:
 * HMAC-SHA256("1750000000000." + '{"test":true}', "whsec_test").
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { verifySignature, verifyWebhookSignature } from "../dist/esm/index.js";

const PAYLOAD = '{"test":true}';
const SECRET = "whsec_test";
const KNOWN_TS_MS = "1750000000000";
const KNOWN_VECTOR = "31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2";

function platformSign(tsText, payload, secret) {
  return "sha256=" + createHmac("sha256", secret).update(`${tsText}.${payload}`).digest("hex");
}

function freshMs() {
  return String(Date.now() - 1000);
}

describe("platform vector", () => {
  test("known vector pins the signed string", () => {
    assert.equal(
      KNOWN_VECTOR,
      createHmac("sha256", SECRET).update(`${KNOWN_TS_MS}.${PAYLOAD}`).digest("hex"),
    );
  });

  test("the SDK verifies the pinned vector with the timestamp header", () => {
    assert.equal(
      verifySignature(PAYLOAD, `sha256=${KNOWN_VECTOR}`, SECRET, {
        timestampHeader: KNOWN_TS_MS,
        toleranceSeconds: 0, // 2025-06 vector: staleness is asserted separately
      }),
      true,
    );
  });

  test("platform header pair verifies", () => {
    const ts = freshMs();
    assert.equal(
      verifySignature(PAYLOAD, platformSign(ts, PAYLOAD, SECRET), SECRET, { timestampHeader: ts }),
      true,
    );
  });

  test("millisecond timestamps are not treated as seconds", () => {
    const ts = freshMs();
    // A seconds-based staleness check would reject a ms timestamp as tens of
    // thousands of years stale — auto-detection must accept it.
    assert.equal(
      verifySignature(PAYLOAD, platformSign(ts, PAYLOAD, SECRET), SECRET, { timestampHeader: ts }),
      true,
    );
  });
});

describe("rejections", () => {
  test("sha256= header without a timestamp is rejected", () => {
    const ts = freshMs();
    assert.equal(verifySignature(PAYLOAD, platformSign(ts, PAYLOAD, SECRET), SECRET), false);
  });

  test("stale millisecond timestamps are rejected (tolerance 300s)", () => {
    assert.equal(
      verifySignature(PAYLOAD, `sha256=${KNOWN_VECTOR}`, SECRET, { timestampHeader: KNOWN_TS_MS }),
      false,
    );
  });

  test("tampered payloads are rejected", () => {
    const ts = freshMs();
    assert.equal(
      verifySignature('{"test":false}', platformSign(ts, PAYLOAD, SECRET), SECRET, { timestampHeader: ts }),
      false,
    );
  });

  test("wrong secrets are rejected", () => {
    const ts = freshMs();
    assert.equal(
      verifySignature(PAYLOAD, platformSign(ts, PAYLOAD, SECRET), "whsec_other", { timestampHeader: ts }),
      false,
    );
  });

  test("wrong signing order is rejected", () => {
    const ts = freshMs();
    const wrong =
      "sha256=" + createHmac("sha256", SECRET).update(`${PAYLOAD}.${ts}`).digest("hex");
    assert.equal(verifySignature(PAYLOAD, wrong, SECRET, { timestampHeader: ts }), false);
  });

  test("missing signature, empty secret and non-digit timestamps are rejected", () => {
    const ts = freshMs();
    const good = platformSign(ts, PAYLOAD, SECRET);
    assert.equal(verifySignature(PAYLOAD, null, SECRET, { timestampHeader: ts }), false);
    assert.equal(verifySignature(PAYLOAD, undefined, SECRET, { timestampHeader: ts }), false);
    assert.equal(verifySignature(PAYLOAD, "", SECRET, { timestampHeader: ts }), false);
    assert.equal(verifySignature(PAYLOAD, good, "", { timestampHeader: ts }), false);
    assert.equal(verifySignature(PAYLOAD, good, SECRET, { timestampHeader: "not-a-number" }), false);
    assert.equal(verifySignature(PAYLOAD, "sha256=", SECRET, { timestampHeader: ts }), false);
  });
});

describe("legacy and flexible forms", () => {
  test("legacy t=<seconds>,v1=<hex> header still verifies", () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const legacy = `t=${ts},v1=` + createHmac("sha256", SECRET).update(`${ts}.${PAYLOAD}`).digest("hex");
    assert.equal(verifySignature(PAYLOAD, legacy, SECRET), true);
  });

  test("the legacy header's own timestamp feeds the staleness check", () => {
    const staleSeconds = String(Math.floor(Date.now() / 1000) - 600);
    const stale = `t=${staleSeconds},v1=` + createHmac("sha256", SECRET).update(`${staleSeconds}.${PAYLOAD}`).digest("hex");
    assert.equal(verifySignature(PAYLOAD, stale, SECRET, { toleranceSeconds: 300 }), false);
    assert.equal(verifySignature(PAYLOAD, stale, SECRET, { toleranceSeconds: 0 }), true);
  });

  test("an explicit timestamp override is honored", () => {
    const ts = freshMs();
    const signature = platformSign(ts, PAYLOAD, SECRET);
    assert.equal(verifySignature(PAYLOAD, signature, SECRET, { timestamp: ts }), true);
  });

  test("repeated header values verify from the first entry", () => {
    const ts = freshMs();
    const signature = platformSign(ts, PAYLOAD, SECRET);
    assert.equal(verifySignature(PAYLOAD, [signature, "sha256=other"], SECRET, { timestampHeader: ts }), true);
    assert.equal(verifySignature(PAYLOAD, [], SECRET, { timestampHeader: ts }), false);
  });

  test("byte payloads verify identically to their string form", () => {
    const ts = freshMs();
    const signature = platformSign(ts, PAYLOAD, SECRET);
    assert.equal(
      verifySignature(Buffer.from(PAYLOAD, "utf8"), signature, SECRET, { timestampHeader: ts }),
      true,
    );
    assert.equal(
      verifySignature(new TextEncoder().encode(PAYLOAD), signature, SECRET, { timestampHeader: ts }),
      true,
    );
  });

  test("verifyWebhookSignature is the historical alias", () => {
    assert.equal(verifyWebhookSignature, verifySignature);
  });
});
