/**
 * ApexMail API client.
 *
 * One transport, zero runtime dependencies: the default fetch is Node's
 * built-in undici (Node >= 20), and all retry/backoff/envelope logic lives
 * here — the same contract as sdk-python's client.py:
 *
 *   * bounded quadratic backoff with ±20% jitter on {408, 429, 500, 502,
 *     503, 504}; Retry-After honored in full, capped at 120 s;
 *   * a 90 s total retry budget; a 20 MiB response-body cap enforced while
 *     streaming, not after buffering;
 *   * automatic per-logical-operation `Idempotency-Key` generation for
 *     POSTs with a body (SDK-B — a blind transport retry can then never
 *     duplicate a send);
 *   * `{"data": ..., "meta": ...}` envelope unwrapping and typed errors per
 *     the canonical envelope (docs/api/errors.md);
 *   * HTTPS enforcement (HTTP only for localhost), validated API-key format,
 *     masked key repr.
 */
import { randomUUID } from "node:crypto";

import {
  ApexMailError,
  AuthenticationError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
} from "./errors.js";
import type { ResponseMeta } from "./models.js";
import { AnalyticsResource } from "./resources/analytics.js";
import { ApiKeysResource } from "./resources/api-keys.js";
import { DomainsResource } from "./resources/domains.js";
import { EmailsResource } from "./resources/emails.js";
import { EventsResource } from "./resources/events.js";
import { SuppressionsResource } from "./resources/suppressions.js";
import { TemplatesResource } from "./resources/templates.js";
import { WebhooksResource } from "./resources/webhooks.js";

export const DEFAULT_BASE_URL = "https://api.apexmail.ee";
export const DEFAULT_TIMEOUT_SECONDS = 30;
export const DEFAULT_MAX_RETRIES = 3;
export const DEFAULT_TOTAL_RETRY_TIMEOUT_SECONDS = 90;
export const DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
export const DEFAULT_INITIAL_BACKOFF_SECONDS = 0.5;
export const DEFAULT_MAX_BACKOFF_SECONDS = 5;
/** Upper bound for honored Retry-After delays (SDK-F). */
export const MAX_RETRY_AFTER_SECONDS = 120;

/** Retry on these status codes. */
export const RETRYABLE_STATUS_CODES: ReadonlySet<number> = new Set([408, 429, 500, 502, 503, 504]);

/** `am_live_...` / `am_test_...` with at least 16 alphanumeric characters. */
export const API_KEY_PATTERN = /^am_(live|test)_[a-zA-Z0-9]{16,}$/;

/** User-Agent: `apexmail-<language>/<SDK_VERSION>` (check_versions.py pins it). */
const USER_AGENT = "apexmail-node/1.0.1";

export interface ApexMailOptions {
  /** API base URL override. Default: https://api.apexmail.ee */
  baseUrl?: string;
  /** Request timeout in seconds (default 30). */
  timeout?: number;
  /** Maximum retries for transient failures (default 3). */
  maxRetries?: number;
  /** Response-body size cap in bytes (default 20 MiB). */
  maxResponseBytes?: number;
  /** fetch implementation override (tests, proxies, instrumented transports). */
  fetch?: typeof fetch;
  /** Sleep implementation override, in milliseconds (tests). */
  sleep?: (ms: number) => Promise<void>;
  /** Cancellation signal combined into every request. */
  signal?: AbortSignal;
}

export interface RequestOptions {
  /** JSON request body. */
  json?: unknown;
  /** Query parameters (null/undefined entries are skipped). */
  params?: Record<string, string | number | boolean | null | undefined> | null;
  /** Idempotency key. When omitted, POSTs with a body get a generated one. */
  idempotencyKey?: string | null;
  /** Per-request cancellation signal. */
  signal?: AbortSignal | null;
}

/** One retry decision: delay in seconds, or null for "no retry". */
type RetryDelay = number;

/**
 * Browser-secret protection (sdk-support-levels.md checklist): an API key
 * embedded in client-side JavaScript is readable by every visitor. Node,
 * Bun and Deno runtimes all expose a Node-style `process`, so a
 * browser-like global (window + document and no process) is refused before
 * any request can be built.
 */
export function assertServerEnvironment(): void {
  const globals = globalThis as {
    window?: { document?: unknown };
    process?: unknown;
  };
  if (globals.window !== undefined && globals.window.document !== undefined && globals.process === undefined) {
    throw new ApexMailError(
      "The ApexMail SDK cannot run in a browser: an API key embedded in client-side " +
        "JavaScript is public to every visitor. Call the ApexMail API from a server " +
        "or a serverless function instead.",
      { code: "BROWSER_ENVIRONMENT", statusCode: 0 },
    );
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function combineSignals(signals: AbortSignal[]): AbortSignal {
  const usable = signals.filter((signal) => signal !== undefined && signal !== null);
  if (usable.length === 1) {
    return usable[0] as AbortSignal;
  }
  const anySignal = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof anySignal === "function") {
    return anySignal.call(AbortSignal, usable);
  }
  // Fallback for Node 20.0-20.2 (AbortSignal.any landed in 20.3).
  const controller = new AbortController();
  for (const signal of usable) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      return controller.signal;
    }
    signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
  }
  return controller.signal;
}

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "TimeoutError" || error.name === "AbortError")
  );
}

export interface ErrorEnvelope {
  message: string;
  code: string;
  errors: unknown[];
}

/**
 * Parse the API error envelope (docs/api/errors.md):
 *
 *   { "error": { "code": "...", "message": "...", "details": [...] } }
 *
 * Legacy flat shapes ({error: "msg", code}) are tolerated like sdk-python
 * does; a non-JSON body falls back to the raw text (or `HTTP <status>`).
 */
export function parseErrorEnvelope(status: number, bodyText: string): ErrorEnvelope {
  let parsed: unknown;
  try {
    parsed = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    return { message: bodyText || `HTTP ${status}`, code: "UNKNOWN", errors: [] };
  }
  if (parsed && typeof parsed === "object") {
    const data = parsed as Record<string, unknown>;
    const errorObj = data.error;
    if (errorObj && typeof errorObj === "object") {
      const error = errorObj as Record<string, unknown>;
      const message = (error.message as string) || bodyText || "Unknown error";
      const code = (error.code as string) || "UNKNOWN";
      const errors = (error.details as unknown[]) ?? (error.errors as unknown[]) ?? [];
      return { message, code, errors: Array.isArray(errors) ? errors : [] };
    }
    if (typeof errorObj === "string" && errorObj) {
      return {
        message: errorObj,
        code: (data.code as string) || "UNKNOWN",
        errors: Array.isArray(data.errors) ? (data.errors as unknown[]) : [],
      };
    }
    const message = (data.message as string) || bodyText || "Unknown error";
    const code = (data.code as string) || "UNKNOWN";
    const errors = data.errors ?? [];
    return { message, code, errors: Array.isArray(errors) ? errors : [] };
  }
  return { message: bodyText || `HTTP ${status}`, code: "UNKNOWN", errors: [] };
}

/** Parse a Retry-After header (seconds or HTTP-date) into seconds. */
export function parseRetryAfter(value: string | null | undefined, nowMs = Date.now()): number | null {
  if (!value) {
    return null;
  }
  const seconds = Number(value);
  if (Number.isFinite(seconds)) {
    return seconds;
  }
  const date = Date.parse(value);
  if (Number.isNaN(date)) {
    return null;
  }
  return Math.max(0, (date - nowMs) / 1000);
}

/** Bounded quadratic backoff: baseDelay * attempt² (attempt >= 1). */
export function calculateBackoff(attempt: number, initial = DEFAULT_INITIAL_BACKOFF_SECONDS, max = DEFAULT_MAX_BACKOFF_SECONDS): number {
  const effective = Math.max(1, attempt);
  return Math.min(initial * effective * effective, max);
}

/** Apply up to ±20% jitter; a delay is never shortened by more than 20%. */
export function addJitter(delay: number, random: () => number = Math.random): number {
  const jitter = delay * 0.2;
  return delay + (random() * 2 - 1) * jitter;
}

export class ApexMail {
  readonly emails: EmailsResource;
  readonly domains: DomainsResource;
  readonly templates: TemplatesResource;
  readonly suppressions: SuppressionsResource;
  readonly events: EventsResource;
  readonly webhooks: WebhooksResource;
  readonly analytics: AnalyticsResource;
  readonly apiKeys: ApiKeysResource;

  readonly baseUrl: string;
  readonly timeout: number;
  readonly maxRetries: number;
  readonly maxResponseBytes: number;
  readonly totalRetryTimeout: number;

  /** The `X-Request-Id` of the most recent response, when the server sent one. */
  lastRequestId: string | null = null;

  #apiKey: string;
  #closed = false;
  #fetch: typeof fetch;
  #sleep: (ms: number) => Promise<void>;
  #signal: AbortSignal | undefined;

  constructor(apiKey: string, options: ApexMailOptions = {}) {
    assertServerEnvironment();
    if (!apiKey) {
      throw new ValidationError("API key is required", { code: "INVALID_API_KEY", statusCode: 0 });
    }
    if (!API_KEY_PATTERN.test(apiKey)) {
      throw new ValidationError(
        "API key must match format 'am_live_<key>' or 'am_test_<key>' " +
          "where <key> is at least 16 alphanumeric characters",
        { code: "INVALID_API_KEY", statusCode: 0 },
      );
    }

    let normalizedBaseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    if (normalizedBaseUrl.endsWith("/v1")) {
      normalizedBaseUrl = normalizedBaseUrl.slice(0, -3);
    }

    // SECURITY: HTTPS is required outside localhost (mirrors sdk-python's
    // constructor check and every sibling SDK).
    let parsed: URL;
    try {
      parsed = new URL(normalizedBaseUrl);
    } catch (error) {
      throw new ValidationError(`Invalid base URL: "${options.baseUrl}"`, {
        code: "INVALID_BASE_URL",
        statusCode: 0,
        cause: error,
      });
    }
    if (parsed.protocol !== "https:") {
      const hostname = (parsed.hostname || "").toLowerCase();
      if (!["localhost", "127.0.0.1", "::1"].includes(hostname)) {
        throw new ValidationError(
          "HTTPS is required for production API URLs. HTTP is only allowed for localhost.",
          { code: "INSECURE_BASE_URL", statusCode: 0 },
        );
      }
    }

    const fetchImpl = options.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (typeof fetchImpl !== "function") {
      throw new ApexMailError(
        "No fetch implementation available — Node.js 20+ provides a global fetch, " +
          "or pass options.fetch",
        { code: "NO_FETCH", statusCode: 0 },
      );
    }

    this.#apiKey = apiKey;
    this.baseUrl = normalizedBaseUrl;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_SECONDS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.totalRetryTimeout = Math.max(this.timeout, DEFAULT_TOTAL_RETRY_TIMEOUT_SECONDS);
    this.#fetch = fetchImpl;
    this.#sleep = options.sleep ?? defaultSleep;
    this.#signal = options.signal;

    this.emails = new EmailsResource(this);
    this.domains = new DomainsResource(this);
    this.templates = new TemplatesResource(this);
    this.suppressions = new SuppressionsResource(this);
    this.events = new EventsResource(this);
    this.webhooks = new WebhooksResource(this);
    this.analytics = new AnalyticsResource(this);
    this.apiKeys = new ApiKeysResource(this);
  }

  /** Access the configured API key (use with caution). */
  get apiKey(): string {
    return this.#apiKey;
  }

  /** Masked representation — the key must never leak into logs. */
  toString(): string {
    const key = this.#apiKey;
    const masked = key.length >= 8 ? `${key.slice(0, 4)}\u2026\u2026${key.slice(-4)}` : "****";
    return `${this.constructor.name}(apiKey='${masked}', baseUrl='${this.baseUrl}')`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }

  /**
   * Clear sensitive key material. Kept for API parity with sdk-python's
   * close(); fetch holds no sockets of its own. After close() the client
   * refuses further requests.
   */
  close(): void {
    this.#apiKey = "";
    this.#closed = true;
  }

  /** Make a request and return the unwrapped `data` payload. */
  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    const { data } = await this.#send(method, path, options);
    return data as T;
  }

  /**
   * Make a request and return `{data, meta}`: list endpoints surface the
   * envelope's `meta.nextCursor` / `meta.hasMore` for pagination.
   */
  async requestWithMeta<T>(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<{ data: T; meta: ResponseMeta | null }> {
    return this.#send(method, path, options) as Promise<{ data: T; meta: ResponseMeta | null }>;
  }

  /** Build the request headers (also applies idempotency-key hygiene). */
  buildHeaders(idempotencyKey: string | null | undefined): Record<string, string> {
    const headers: Record<string, string> = {
      "X-API-Key": this.#apiKey,
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
    };
    if (idempotencyKey) {
      // Header injection: strip control characters (CR/LF/NUL) from
      // caller-supplied keys before they reach the transport, then bound
      // the length like the server's idempotency middleware does.
      const safeKey = Array.from(idempotencyKey)
        .filter((ch) => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) !== 0x7f)
        .join("");
      if (safeKey) {
        // The server reads `Idempotency-Key` (middleware/idempotency.rs);
        // the historical `X-Idempotency-Key` spelling was silently ignored
        // (SDK-IDEM).
        headers["Idempotency-Key"] = safeKey.slice(0, 128);
      }
    }
    return headers;
  }

  #autoIdempotencyKey(method: string, json: unknown): string | undefined {
    return method.toUpperCase() === "POST" && json !== undefined && json !== null
      ? randomUUID()
      : undefined;
  }

  #checkTotalTimeout(startedAt: number): void {
    if ((Date.now() - startedAt) / 1000 > this.totalRetryTimeout) {
      throw new ApexMailError("Total retry timeout exceeded", {
        code: "TOTAL_TIMEOUT",
        statusCode: 408,
      });
    }
  }

  /** Delay (seconds) when the response should be retried, else null. */
  #retryDelay(status: number, attempt: number, headers: Headers, nowMs: number): RetryDelay | null {
    if (RETRYABLE_STATUS_CODES.has(status) && attempt < this.maxRetries) {
      let delay = calculateBackoff(attempt);
      if (status === 429) {
        const retryAfter = parseRetryAfter(headers.get("retry-after"), nowMs);
        if (retryAfter !== null) {
          delay = Math.min(Math.max(delay, retryAfter), MAX_RETRY_AFTER_SECONDS);
        }
      }
      return delay;
    }
    return null;
  }

  /** Read the body with the size cap enforced while streaming (SDK-G). */
  async #readBodyCapped(response: Response): Promise<string> {
    const body = response.body;
    if (!body || typeof body.getReader !== "function") {
      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > this.maxResponseBytes) {
        throw new ApexMailError("Response body exceeds maxResponseBytes", {
          code: "RESPONSE_TOO_LARGE",
          statusCode: 0,
        });
      }
      return new TextDecoder().decode(buffer);
    }
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        total += value.byteLength;
        if (total > this.maxResponseBytes) {
          await reader.cancel().catch(() => undefined);
          throw new ApexMailError("Response body exceeds maxResponseBytes", {
            code: "RESPONSE_TOO_LARGE",
            statusCode: 0,
          });
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const buffer = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(buffer);
  }

  #handleResponse(status: number, bodyText: string, headers: Headers): { data: unknown; meta: ResponseMeta | null } {
    if (status === 204) {
      return { data: {}, meta: null };
    }
    if (status >= 200 && status < 300) {
      if (!bodyText) {
        return { data: {}, meta: null };
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(bodyText);
      } catch (error) {
        throw new ApexMailError("Invalid JSON in response body", {
          code: "INVALID_RESPONSE",
          statusCode: status,
          requestId: headers.get("x-request-id"),
          cause: error,
        });
      }
      // Unwrap the API envelope {"data": ..., "meta": ...} (SDK-111).
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && "data" in parsed) {
        const envelope = parsed as { data: unknown; meta?: unknown };
        const meta = envelope.meta && typeof envelope.meta === "object" ? (envelope.meta as ResponseMeta) : null;
        return { data: envelope.data, meta };
      }
      return { data: parsed, meta: null };
    }

    const { message, code, errors } = parseErrorEnvelope(status, bodyText);
    const requestId = headers.get("x-request-id");
    if (status === 400 || status === 422) {
      // 422 is the server's deserialization/validation status
      // (docs/api/errors.md VALIDATION_ERROR) and must surface as
      // ValidationError, not the generic base error (SDK-E).
      throw new ValidationError(message, { code, errors, requestId });
    }
    if (status === 401) {
      throw new AuthenticationError(message, { code, requestId });
    }
    if (status === 403) {
      throw new ForbiddenError(message, { code, requestId });
    }
    if (status === 404) {
      throw new NotFoundError(message, { code, requestId });
    }
    if (status === 409) {
      throw new ConflictError(message, { code, requestId });
    }
    if (status === 429) {
      const retryAfter = parseRetryAfter(headers.get("retry-after"));
      throw new RateLimitError(message, {
        code,
        requestId,
        retryAfter: retryAfter === null ? null : Math.trunc(retryAfter),
      });
    }
    if (status >= 500) {
      throw new ServerError(message, { code, requestId });
    }
    throw new ApexMailError(message, { code, statusCode: status, requestId });
  }

  async #send(
    method: string,
    path: string,
    options: RequestOptions,
  ): Promise<{ data: unknown; meta: ResponseMeta | null }> {
    if (this.#closed) {
      throw new ApexMailError("Client has been closed", { code: "CLIENT_CLOSED", statusCode: 0 });
    }

    const json = options.json ?? null;
    const idempotencyKey =
      options.idempotencyKey !== undefined && options.idempotencyKey !== null
        ? options.idempotencyKey
        : this.#autoIdempotencyKey(method, json);
    const headers = this.buildHeaders(idempotencyKey);

    let url = `${this.baseUrl}${path}`;
    if (options.params) {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined && value !== null) {
          search.append(key, String(value));
        }
      }
      const query = search.toString();
      if (query) {
        url += `?${query}`;
      }
    }

    const userSignal = options.signal ?? undefined;
    const body = json === null ? undefined : JSON.stringify(json);
    const startedAt = Date.now();
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      this.#checkTotalTimeout(startedAt);
      const timeoutSignal = AbortSignal.timeout(this.timeout * 1000);
      const signals = [timeoutSignal];
      if (this.#signal) {
        signals.push(this.#signal);
      }
      if (userSignal) {
        signals.push(userSignal);
      }
      const signal = combineSignals(signals);
      const nowMs = Date.now();

      let response: Response;
      try {
        response = await this.#fetch(url, { method, headers, body, signal });
      } catch (error) {
        if (userSignal?.aborted || this.#signal?.aborted) {
          throw new ApexMailError("Request aborted by caller", {
            code: "REQUEST_ABORTED",
            statusCode: 0,
            cause: error,
          });
        }
        lastError = error;
        if (attempt < this.maxRetries) {
          await this.#sleep(addJitter(calculateBackoff(attempt)) * 1000);
          continue;
        }
        if (isTimeoutError(error)) {
          throw new ApexMailError("Request timed out", {
            code: "TIMEOUT_ERROR",
            statusCode: 408,
            cause: error,
          });
        }
        throw new ApexMailError(`Network error: ${error instanceof Error ? error.message : String(error)}`, {
          code: "NETWORK_ERROR",
          statusCode: 0,
          cause: error,
        });
      }

      const requestId = response.headers.get("x-request-id");
      if (requestId) {
        this.lastRequestId = requestId;
      }

      const bodyText = await this.#readBodyCapped(response);
      const delay = this.#retryDelay(response.status, attempt, response.headers, nowMs);
      if (delay !== null) {
        await this.#sleep(addJitter(delay) * 1000);
        continue;
      }
      return this.#handleResponse(response.status, bodyText, response.headers);
    }

    // Unreachable in practice: the loop either returns, throws, or exhausts
    // retries inside the catch. Kept for completeness like sdk-python's
    // _build_timeout_error tail.
    if (lastError instanceof Error) {
      throw new ApexMailError(`Request failed: ${lastError.message}`, {
        code: "UNKNOWN",
        statusCode: 0,
        cause: lastError,
      });
    }
    throw new ApexMailError("Request failed", { code: "UNKNOWN", statusCode: 0 });
  }
}
