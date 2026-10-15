/**
 * Suppressions resource — suppression-list management.
 *
 * The suppressions check endpoint takes the addr-spec as a URL path
 * segment, so it is percent-encoded like sdk-python's `quote(email,
 * safe="")` — an unescaped `/`, `?` or `#` would rewrite the route (URL
 * injection) instead of checking the address.
 */
import type {
  BulkSuppressionResponse,
  Suppression,
  SuppressionCheckResponse,
} from "../models.js";
import { rejectCursor, validateId } from "../payload.js";
import type { ApexMail } from "../client.js";

export interface ListSuppressionsOptions {
  limit?: number;
  offset?: number;
  /** Not supported: the server rejects `cursor` with HTTP 400. */
  cursor?: string;
  reason?: string;
}

function extractList(data: unknown, key: string): Record<string, unknown>[] {
  if (Array.isArray(data)) {
    return data as Record<string, unknown>[];
  }
  if (data && typeof data === "object") {
    const record = data as Record<string, unknown>;
    for (const candidate of [key, "data", "items"]) {
      const value = record[candidate];
      if (Array.isArray(value)) {
        return value as Record<string, unknown>[];
      }
    }
  }
  return [];
}

/** RFC 3986 path-segment escaping (matches Python's urllib quote(safe="")). */
function escapePathSegment(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

export class SuppressionsResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /** Alias of add() (sdk-python keeps both spellings). */
  async create(
    input: { email: string; reason: string; source?: string | null; signal?: AbortSignal },
  ): Promise<Suppression> {
    return this.add(input);
  }

  async add(
    input: { email: string; reason: string; source?: string | null; signal?: AbortSignal },
  ): Promise<Suppression> {
    const payload: Record<string, unknown> = { email: input.email, reason: input.reason };
    if (input.source !== undefined && input.source !== null) {
      payload.source = input.source;
    }
    const data = await this.#client.request<unknown>("POST", "/v1/suppressions", {
      json: payload,
      signal: input.signal,
    });
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const record = data as Record<string, unknown>;
      if (record.suppression && typeof record.suppression === "object") {
        return record.suppression as Suppression;
      }
    }
    return data as Suppression;
  }

  async list(options: ListSuppressionsOptions = {}): Promise<Suppression[]> {
    rejectCursor("/v1/suppressions", options.cursor);
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) {
      params.limit = options.limit;
    }
    if (options.offset !== undefined) {
      params.offset = options.offset;
    }
    if (options.reason) {
      params.reason = options.reason;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/suppressions", { params });
    return extractList(data, "suppressions") as unknown as Suppression[];
  }

  async delete(suppressionId: string, options: { signal?: AbortSignal } = {}): Promise<void> {
    validateId(suppressionId, "suppression");
    await this.#client.request<unknown>("DELETE", `/v1/suppressions/${suppressionId}`, {
      signal: options.signal,
    });
  }

  /** Check whether an address is suppressed. */
  async check(email: string, options: { signal?: AbortSignal } = {}): Promise<SuppressionCheckResponse> {
    return this.#client.request<SuppressionCheckResponse>(
      "GET",
      `/v1/suppressions/check/${escapePathSegment(email)}`,
      { signal: options.signal },
    );
  }

  async bulk(
    entries: Array<Record<string, unknown>>,
    options: { signal?: AbortSignal } = {},
  ): Promise<BulkSuppressionResponse> {
    return this.#client.request<BulkSuppressionResponse>("POST", "/v1/suppressions/bulk", {
      json: { entries },
      signal: options.signal,
    });
  }
}
