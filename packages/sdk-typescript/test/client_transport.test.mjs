/**
 * Transport contract tests: auth headers, base-URL policy, retry/backoff
 * (with honored Retry-After), idempotency keys, envelope handling, typed
 * error mapping, the response-size cap, cancellation and close() hygiene.
 *
 * All requests go to a local node:http stub — no external network.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import {
  ApexMail,
  ApexMailError,
  AuthenticationError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
  calculateBackoff,
  parseRetryAfter,
} from "../dist/esm/index.js";
import { TEST_API_KEY, recordingSleep, startStub } from "./helpers/stub.mjs";

async function withStub(handler, fn) {
  const stub = await startStub(handler);
  try {
    return await fn(stub);
  } finally {
    await stub.close();
  }
}

describe("authentication and base URL", () => {
  test("sends X-API-Key, JSON content type and the SDK User-Agent", async () => {
    await withStub(
      (record) => ({ body: { data: { ok: true } }, echo: record }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.domains.list();
          const record = stub.requests[0];
          assert.equal(record.headers["x-api-key"], TEST_API_KEY);
          assert.equal(record.headers["content-type"], "application/json");
          assert.match(record.headers["user-agent"], /^apexmail-node\/\d+\.\d+\.\d+$/);
        } finally {
          client.close();
        }
      },
    );
  });

  test("rejects malformed and empty API keys", () => {
    for (const bad of ["", "sk_test_0123456789abcdef", "am_live_short", "am_prod_0123456789abcdef"]) {
      assert.throws(() => new ApexMail(bad), ValidationError);
    }
    const client = new ApexMail(TEST_API_KEY);
    assert.equal(client.apiKey, TEST_API_KEY);
    client.close();
  });

  test("defaults to the production base URL and strips a /v1 suffix", () => {
    const client = new ApexMail(TEST_API_KEY);
    assert.equal(client.baseUrl, "https://api.apexmail.ee");
    client.close();
    const versioned = new ApexMail(TEST_API_KEY, { baseUrl: "https://api.apexmail.ee/v1" });
    assert.equal(versioned.baseUrl, "https://api.apexmail.ee");
    versioned.close();
    const trailing = new ApexMail(TEST_API_KEY, { baseUrl: "https://api.apexmail.ee/" });
    assert.equal(trailing.baseUrl, "https://api.apexmail.ee");
    trailing.close();
  });

  test("refuses to construct in a browser-like environment (secret protection)", () => {
    const savedProcess = globalThis.process;
    try {
      Object.defineProperty(globalThis, "process", { value: undefined, configurable: true, writable: true });
      globalThis.window = { document: {} };
      assert.throws(() => new ApexMail(TEST_API_KEY), (error) => {
        assert.equal(error.code, "BROWSER_ENVIRONMENT");
        return true;
      });
    } finally {
      delete globalThis.window;
      Object.defineProperty(globalThis, "process", { value: savedProcess, configurable: true, writable: true });
    }
    // ...and the guard is a no-op in Node-like runtimes.
    const ok = new ApexMail(TEST_API_KEY);
    ok.close();
  });

  test("enforces HTTPS outside localhost", () => {
    assert.throws(() => new ApexMail(TEST_API_KEY, { baseUrl: "http://api.apexmail.ee" }), ValidationError);
    // localhost forms are the documented development exception.
    const client = new ApexMail(TEST_API_KEY, { baseUrl: "http://localhost:8080" });
    assert.equal(client.baseUrl, "http://localhost:8080");
    client.close();
  });

  test("paths are prefixed once (no double /v1)", async () => {
    await withStub(
      () => ({ body: { data: { id: "msg_1", status: "queued" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: `${stub.url}/v1` });
        try {
          await client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "s", text: "t" });
          assert.equal(stub.requests[0].path, "/v1/messages");
        } finally {
          client.close();
        }
      },
    );
  });

  test("toString masks the API key", () => {
    const client = new ApexMail(TEST_API_KEY);
    const text = client.toString();
    assert.ok(!text.includes(TEST_API_KEY), "raw key must never appear");
    assert.match(text, /^ApexMail\(apiKey='am_t……cdef', baseUrl='https:\/\/api\.apexmail\.ee'\)$/);
    client.close();
  });

  test("close() clears key material and refuses further requests", async () => {
    const client = new ApexMail(TEST_API_KEY);
    client.close();
    assert.equal(client.apiKey, "");
    await assert.rejects(client.domains.list(), (error) => error.code === "CLIENT_CLOSED");
  });
});

describe("retry and backoff", () => {
  test("retries retryable 5xx then succeeds, honoring the backoff schedule", async () => {
    await withStub(
      (record, count) => (count < 3 ? { status: 503, body: { error: { code: "UNAVAILABLE" } } } : { body: { data: { ok: true } } }),
      async (stub) => {
        const { sleep, delaysMs } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, sleep });
        try {
          const data = await client.request("GET", "/v1/domains");
          assert.deepEqual(data, { ok: true });
          assert.equal(stub.requests.length, 3);
          assert.equal(delaysMs.length, 2);
          // Mirrors sdk-python's _calculate_backoff: the first TWO retries
          // both use the 0.5s floor (attempt 2 is the first quadratic step),
          // each with ±20% jitter.
          assert.ok(delaysMs[0] >= 400 && delaysMs[0] <= 600, `first backoff ${delaysMs[0]}ms`);
          assert.ok(delaysMs[1] >= 400 && delaysMs[1] <= 600, `second backoff ${delaysMs[1]}ms`);
        } finally {
          client.close();
        }
      },
    );
  });

  test("quadratic backoff is bounded by the 5s cap", () => {
    assert.equal(calculateBackoff(0), 0.5, "attempt 0 is treated as attempt 1");
    assert.equal(calculateBackoff(1), 0.5);
    assert.equal(calculateBackoff(2), 2);
    assert.equal(calculateBackoff(3), 4.5);
    assert.equal(calculateBackoff(4), 5, "capped at 5s");
  });

  test("honors Retry-After on 429 (and does not exceed the 120s cap)", async () => {
    await withStub(
      (record, count) => {
        if (count === 1) {
          return {
            status: 429,
            headers: { "retry-after": "60" },
            body: { error: { code: "RATE_LIMITED", message: "slow down" } },
          };
        }
        if (count === 2) {
          return {
            status: 429,
            headers: { "retry-after": "300" },
            body: { error: { code: "RATE_LIMITED", message: "slow down" } },
          };
        }
        return { body: { data: { ok: true } } };
      },
      async (stub) => {
        const { sleep, delaysMs } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, sleep });
        try {
          await client.request("GET", "/v1/domains");
          assert.equal(stub.requests.length, 3);
          assert.ok(delaysMs[0] >= 48000 && delaysMs[0] <= 72000, `60s honored (±20%): ${delaysMs[0]}`);
          // Retry-After 300s is capped at MAX_RETRY_AFTER_SECONDS = 120s.
          assert.ok(delaysMs[1] >= 96000 && delaysMs[1] <= 144000, `capped at 120s (±20%): ${delaysMs[1]}`);
        } finally {
          client.close();
        }
      },
    );
  });

  test("retries 408 and 429 without Retry-After, and 502/504", async () => {
    for (const status of [408, 429, 502, 504]) {
      await withStub(
        (record, count) => (count === 1 ? { status, body: { error: { code: "T" } } } : { body: { data: { ok: true } } }),
        async (stub) => {
          const { sleep } = recordingSleep();
          const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, sleep });
          try {
            await client.request("GET", "/v1/domains");
            assert.equal(stub.requests.length, 2, `status ${status} must retry`);
          } finally {
            client.close();
          }
        },
      );
    }
  });

  test("exhausts retries and raises the typed error for the final status", async () => {
    await withStub(
      () => ({ status: 503, body: { error: { code: "SERVICE_UNAVAILABLE", message: "Temporary outage" } } }),
      async (stub) => {
        const { sleep } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 2, sleep });
        try {
          await assert.rejects(client.request("GET", "/v1/domains"), (error) => {
            assert.ok(error instanceof ServerError);
            assert.equal(error.code, "SERVICE_UNAVAILABLE");
            assert.equal(error.statusCode, 500);
            return true;
          });
          assert.equal(stub.requests.length, 3, "initial + 2 retries");
        } finally {
          client.close();
        }
      },
    );
  });

  test("does not retry non-retryable statuses", async () => {
    await withStub(
      () => ({ status: 404, body: { error: { code: "NOT_FOUND", message: "no such domain" } } }),
      async (stub) => {
        const { sleep, delaysMs } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, sleep });
        try {
          await assert.rejects(client.request("GET", "/v1/domains/x"), NotFoundError);
          assert.equal(stub.requests.length, 1);
          assert.equal(delaysMs.length, 0);
        } finally {
          client.close();
        }
      },
    );
  });

  test("retries network failures, then maps them to NETWORK_ERROR", async () => {
    const { sleep, delaysMs } = recordingSleep();
    const failing = new ApexMail(TEST_API_KEY, {
      baseUrl: "http://127.0.0.1:9",
      maxRetries: 1,
      sleep,
    });
    try {
      await assert.rejects(failing.request("GET", "/v1/domains"), (error) => {
        assert.equal(error.code, "NETWORK_ERROR");
        return true;
      });
      assert.equal(delaysMs.length, 1, "one backoff between the two attempts");
    } finally {
      failing.close();
    }
  });

  test("maps a client timeout to TIMEOUT_ERROR after retrying", async () => {
    await withStub(
      () => ({ delayMs: 250, body: { data: { ok: true } } }),
      async (stub) => {
        const { sleep } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, {
          baseUrl: stub.url,
          timeout: 0.05,
          maxRetries: 1,
          sleep,
        });
        try {
          await assert.rejects(client.request("GET", "/v1/domains"), (error) => {
            assert.equal(error.code, "TIMEOUT_ERROR");
            assert.equal(error.statusCode, 408);
            return true;
          });
          assert.equal(stub.requests.length, 2, "the timeout attempt is retried");
        } finally {
          client.close();
        }
      },
    );
  });

  test("parseRetryAfter handles seconds, HTTP-dates and garbage", () => {
    assert.equal(parseRetryAfter("60"), 60);
    assert.equal(parseRetryAfter("2.5"), 2.5);
    assert.equal(parseRetryAfter(null), null);
    assert.equal(parseRetryAfter("not-a-date"), null);
    const now = Date.parse("2026-09-01T09:00:00Z");
    assert.equal(parseRetryAfter("Tue, 01 Sep 2026 09:00:30 GMT", now), 30);
  });
});

describe("idempotency keys", () => {
  test("send() generates a fresh key per logical send", async () => {
    await withStub(
      () => ({ body: { data: { id: "msg_1", status: "queued" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "s", text: "t" });
          await client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "s", text: "t" });
        } finally {
          client.close();
        }
        const [first, second] = stub.requests.map((record) => record.headers["idempotency-key"]);
        assert.match(first, /^[0-9a-f-]{36}$/);
        assert.match(second, /^[0-9a-f-]{36}$/);
        assert.notEqual(first, second);
      },
    );
  });

  test("send() honors a caller-supplied key", async () => {
    await withStub(
      () => ({ body: { data: { id: "msg_1", status: "queued" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.emails.send({
            from: "a@example.com",
            to: "b@example.com",
            subject: "s",
            text: "t",
            idempotencyKey: "caller-key-1",
          });
        } finally {
          client.close();
        }
        assert.equal(stub.requests[0].headers["idempotency-key"], "caller-key-1");
      },
    );
  });

  test("transport retries present the SAME key (no duplicate send, SDK-B)", async () => {
    await withStub(
      (record, count) =>
        count < 3
          ? { status: 500, body: { error: { code: "INTERNAL" } } }
          : { body: { data: { id: "msg_1", status: "queued" } } },
      async (stub) => {
        const { sleep } = recordingSleep();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, sleep });
        try {
          await client.emails.send({ from: "a@example.com", to: "b@example.com", subject: "s", text: "t" });
        } finally {
          client.close();
        }
        assert.equal(stub.requests.length, 3);
        const keys = stub.requests.map((record) => record.headers["idempotency-key"]);
        assert.equal(new Set(keys).size, 1, `all attempts share one key: ${keys}`);
      },
    );
  });

  test("other mutating POSTs get an automatic key too; GETs do not", async () => {
    await withStub(
      (record) => ({ body: { data: { id: "tpl_1", name: "t", subject: "s", html_body: "<p/>", version: 1, status: "active", created_at: "x", updated_at: "x" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.templates.create({ name: "t", subject: "s", htmlBody: "<p/>" });
          await client.domains.list();
        } finally {
          client.close();
        }
        assert.match(stub.requests[0].headers["idempotency-key"], /^[0-9a-f-]{36}$/);
        assert.equal(stub.requests[1].headers["idempotency-key"], undefined);
      },
    );
  });

  test("control characters are stripped and keys are bounded to 128 chars", async () => {
    await withStub(
      () => ({ body: { data: { id: "msg_1", status: "queued" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.emails.send({
            from: "a@example.com",
            to: "b@example.com",
            subject: "s",
            text: "t",
            idempotencyKey: "ab\r\ncd\u0000ef",
          });
          await client.emails.send({
            from: "a@example.com",
            to: "b@example.com",
            subject: "s",
            text: "t",
            idempotencyKey: "x".repeat(200),
          });
        } finally {
          client.close();
        }
        assert.equal(stub.requests[0].headers["idempotency-key"], "abcdef");
        assert.equal(stub.requests[1].headers["idempotency-key"].length, 128);
      },
    );
  });
});

describe("response handling", () => {
  test("treats every 2xx as success and unwraps the envelope", async () => {
    for (const status of [200, 201, 202, 206]) {
      await withStub(
        () => ({ status, body: { data: { id: "msg_1" }, meta: { hasMore: false } } }),
        async (stub) => {
          const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
          try {
            const data = await client.request("GET", "/v1/domains");
            assert.deepEqual(data, { id: "msg_1" }, `status ${status}`);
          } finally {
            client.close();
          }
        },
      );
    }
  });

  test("204 No Content returns an empty payload", async () => {
    await withStub(
      () => ({ status: 204 }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          assert.deepEqual(await client.request("DELETE", "/v1/domains/x"), {});
        } finally {
          client.close();
        }
      },
    );
  });

  test("non-enveloped payloads pass through unchanged", async () => {
    await withStub(
      () => ({ body: [{ id: "dom_1" }] }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          assert.deepEqual(await client.request("GET", "/v1/domains"), [{ id: "dom_1" }]);
        } finally {
          client.close();
        }
      },
    );
  });

  test("requestWithMeta surfaces the envelope meta (pagination)", async () => {
    await withStub(
      () => ({ body: { data: [{ id: "msg_1" }], meta: { hasMore: true, nextCursor: "cur_1" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          const { data, meta } = await client.requestWithMeta("GET", "/v1/messages");
          assert.deepEqual(data, [{ id: "msg_1" }]);
          assert.equal(meta.nextCursor, "cur_1");
          assert.equal(meta.hasMore, true);
        } finally {
          client.close();
        }
      },
    );
  });

  test("invalid JSON on a 2xx raises INVALID_RESPONSE", async () => {
    await withStub(
      () => ({ raw: "{not json" }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await assert.rejects(client.request("GET", "/v1/domains"), (error) => {
            assert.ok(error instanceof ApexMailError);
            assert.equal(error.code, "INVALID_RESPONSE");
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });

  test("response bodies over maxResponseBytes are refused while streaming", async () => {
    await withStub(
      () => ({ body: { data: { blob: "z".repeat(1024) } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxResponseBytes: 64 });
        try {
          await assert.rejects(client.request("GET", "/v1/domains"), (error) => {
            assert.equal(error.code, "RESPONSE_TOO_LARGE");
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });

  test("query parameters are forwarded", async () => {
    await withStub(
      () => ({ body: { data: [] } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          await client.request("GET", "/v1/messages", {
            params: { limit: 25, offset: 0, status: "sent", empty: null },
          });
        } finally {
          client.close();
        }
        const { query } = stub.requests[0];
        assert.equal(query.get("limit"), "25");
        assert.equal(query.get("offset"), "0");
        assert.equal(query.get("status"), "sent");
        assert.equal(query.get("empty"), null);
      },
    );
  });
});

describe("typed error mapping", () => {
  const cases = [
    [400, ValidationError, "VALIDATION_ERROR"],
    [401, AuthenticationError, "AUTHENTICATION_ERROR"],
    [403, ForbiddenError, "FORBIDDEN"],
    [404, NotFoundError, "NOT_FOUND"],
    [409, ConflictError, "CONFLICT"],
  ];

  for (const [status, ErrorClass, defaultCode] of cases) {
    test(`${status} maps to ${ErrorClass.name}`, async () => {
      await withStub(
        () => ({
          status,
          headers: { "x-request-id": "req_123" },
          body: { error: { code: "ENVELOPE_CODE", message: "boom", details: [{ field: "to" }] } },
        }),
        async (stub) => {
          const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 0 });
          try {
            await assert.rejects(client.request("GET", "/v1/messages/x"), (error) => {
              assert.ok(error instanceof ErrorClass, `expected ${ErrorClass.name}`);
              assert.equal(error.code, "ENVELOPE_CODE");
              assert.equal(error.message, "boom");
              assert.equal(error.statusCode, status);
              assert.equal(error.requestId, "req_123");
              if (error instanceof ValidationError) {
                assert.deepEqual(error.errors, [{ field: "to" }]);
              }
              return true;
            });
            assert.equal(client.lastRequestId, "req_123");
          } finally {
            client.close();
          }
        },
      );
    });
  }

  test("422 surfaces as ValidationError (server deserialization status)", async () => {
    await withStub(
      () => ({ status: 422, body: { error: { code: "VALIDATION_ERROR", message: "bad field" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 0 });
        try {
          await assert.rejects(client.request("POST", "/v1/messages"), (error) => {
            assert.ok(error instanceof ValidationError);
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });

  test("429 surfaces RateLimitError with retryAfter; 5xx surfaces ServerError", async () => {
    await withStub(
      (record, count) =>
        count === 1
          ? {
              status: 429,
              headers: { "retry-after": "120" },
              body: { error: { code: "RATE_LIMITED", message: "Slow down" } },
            }
          : { status: 503, body: { error: { code: "SERVICE_UNAVAILABLE", message: "Temporary outage" } } },
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 0 });
        try {
          await assert.rejects(client.request("GET", "/v1/messages"), (error) => {
            assert.ok(error instanceof RateLimitError);
            assert.equal(error.retryAfter, 120);
            assert.equal(error.code, "RATE_LIMITED");
            return true;
          });
          await assert.rejects(client.request("GET", "/v1/messages"), (error) => {
            assert.ok(error instanceof ServerError);
            assert.equal(error.code, "SERVICE_UNAVAILABLE");
            assert.equal(error.statusCode, 500);
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });

  test("legacy flat error envelopes and plain-text bodies are tolerated", async () => {
    await withStub(
      (record, count) =>
        count === 1
          ? { status: 429, body: { error: "Slow down", code: "RATE_LIMITED" } }
          : { status: 400, raw: "Failed to deserialize query string: unknown field `cursor`" },
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 0 });
        try {
          await assert.rejects(client.request("GET", "/v1/messages"), (error) => {
            assert.ok(error instanceof RateLimitError);
            assert.equal(error.code, "RATE_LIMITED");
            assert.equal(error.message, "Slow down");
            return true;
          });
          await assert.rejects(client.request("GET", "/v1/domains"), (error) => {
            assert.ok(error instanceof ValidationError);
            assert.equal(error.code, "UNKNOWN");
            assert.match(error.message, /Failed to deserialize query string/);
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });

  test("unknown 4xx statuses raise the base error with the status attached", async () => {
    await withStub(
      () => ({ status: 418, body: { error: { code: "TEAPOT", message: "short and stout" } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, maxRetries: 0 });
        try {
          await assert.rejects(client.request("GET", "/v1/messages"), (error) => {
            assert.ok(error instanceof ApexMailError);
            assert.equal(error.statusCode, 418);
            assert.equal(error.code, "TEAPOT");
            return true;
          });
        } finally {
          client.close();
        }
      },
    );
  });
});

describe("cancellation", () => {
  test("an aborted caller signal fails fast with REQUEST_ABORTED (no retries)", async () => {
    await withStub(
      () => ({ body: { data: { ok: true } } }),
      async (stub) => {
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url });
        try {
          const controller = new AbortController();
          controller.abort();
          await assert.rejects(
            client.request("GET", "/v1/domains", { signal: controller.signal }),
            (error) => {
              assert.equal(error.code, "REQUEST_ABORTED");
              return true;
            },
          );
          assert.equal(stub.requests.length, 0, "no attempt may be made after abort");
        } finally {
          client.close();
        }
      },
    );
  });

  test("a client-level signal aborts in-flight requests", async () => {
    await withStub(
      () => ({ delayMs: 200, body: { data: { ok: true } } }),
      async (stub) => {
        const controller = new AbortController();
        const client = new ApexMail(TEST_API_KEY, { baseUrl: stub.url, signal: controller.signal });
        try {
          const pending = client.request("GET", "/v1/domains");
          setTimeout(() => controller.abort(), 30);
          await assert.rejects(pending, (error) => error.code === "REQUEST_ABORTED");
        } finally {
          client.close();
        }
      },
    );
  });
});
