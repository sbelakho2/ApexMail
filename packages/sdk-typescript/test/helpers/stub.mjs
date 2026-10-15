/**
 * Local node:http stub-server helper for the contract suite.
 *
 * Every client-level test drives the REAL client (real validation, real
 * retry loop, real envelope parsing) against this server on 127.0.0.1 — the
 * SDK's HTTPS rule explicitly allows localhost — so the request shapes are
 * asserted where it counts: on the wire. No external network is touched.
 */
import http from "node:http";

/**
 * Start a stub server.
 *
 * `handler(record, count)` returns:
 *   undefined                      → 200 {}
 *   {status?, body?, headers?, raw?, delayMs?}
 *
 * `record` = {method, url, path, query (URLSearchParams), headers, body, json}
 * `count`  = 1-based index of this request.
 *
 * Returns {url, requests, close()}.
 */
export async function startStub(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const url = new URL(req.url, "http://127.0.0.1");
      const record = {
        method: req.method,
        url: req.url,
        path: url.pathname,
        query: url.searchParams,
        headers: req.headers,
        body,
        json: body ? JSON.parse(body) : null,
      };
      requests.push(record);
      let result;
      try {
        result = await handler(record, requests.length);
      } catch (error) {
        res.statusCode = 500;
        res.end(String(error && error.stack ? error.stack : error));
        return;
      }
      if (result === undefined) {
        result = {};
      }
      const finish = () => {
        res.statusCode = result.status ?? 200;
        for (const [key, value] of Object.entries(result.headers ?? {})) {
          res.setHeader(key, value);
        }
        if (result.raw !== undefined) {
          res.end(result.raw);
          return;
        }
        if (result.body === undefined || result.status === 204) {
          res.end();
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(typeof result.body === "string" ? result.body : JSON.stringify(result.body));
      };
      if (result.delayMs) {
        setTimeout(finish, result.delayMs);
      } else {
        finish();
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/** A sleep stub that records requested delays (seconds → ms) without waiting. */
export function recordingSleep() {
  const delaysMs = [];
  return {
    delaysMs,
    sleep: async (ms) => {
      delaysMs.push(ms);
    },
  };
}

/**
 * Capture console.warn for the duration of a callback (sync or async).
 * Returns {warnings, result}.
 */
export async function captureWarnings(callback) {
  const warnings = [];
  const original = console.warn;
  console.warn = (...args) => {
    warnings.push(args.map(String).join(" "));
  };
  try {
    const result = await callback();
    return { warnings, result };
  } finally {
    console.warn = original;
  }
}

/** The API-key literal the suite authenticates with (format-valid, synthetic). */
export const TEST_API_KEY = "am_test_0123456789abcdef";
