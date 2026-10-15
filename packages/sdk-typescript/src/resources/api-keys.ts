/**
 * API keys resource.
 *
 * The server's CreateApiKeyRequest (auth.rs) accepts exactly
 * {name, scopes: string[], expires_in_days?} — `scopes` is required (use []
 * for a key with no scopes) and the legacy `expires_at` field is not part
 * of the API.
 */
import { rejectCursor } from "../payload.js";
import type { ApexMail } from "../client.js";

export interface CreateApiKeyOptions {
  name: string;
  /** Scopes for the key; defaults to [] (a key with no scopes). */
  scopes?: string[];
  /** Relative expiry 1..365 days. */
  expiresInDays?: number;
  /** Accepted for backwards compatibility but ignored (the API takes a relative expiry). */
  expiresAt?: string;
  signal?: AbortSignal;
}

export interface ListApiKeysOptions {
  limit?: number;
  offset?: number;
  /** Not supported: the server rejects `cursor` with HTTP 400. */
  cursor?: string;
}

/** RFC 3986 path-segment escaping (matches Python's urllib quote(safe="")). */
function escapePathSegment(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

export class ApiKeysResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /**
   * Create a new API key ({name, scopes, expires_in_days?} on the wire).
   * The full key value is returned only once, at creation time.
   */
  async create(options: CreateApiKeyOptions): Promise<Record<string, unknown>> {
    const payload: Record<string, unknown> = {
      name: options.name,
      scopes: options.scopes ? [...options.scopes] : [],
    };
    if (options.expiresInDays !== undefined && options.expiresInDays !== null) {
      payload.expires_in_days = options.expiresInDays;
    }
    return this.#client.request<Record<string, unknown>>("POST", "/v1/auth/api-keys", {
      json: payload,
      signal: options.signal,
    });
  }

  /** List API keys. The server returns a plain array (no envelope). */
  async list(options: ListApiKeysOptions = {}): Promise<Array<Record<string, unknown>>> {
    rejectCursor("/v1/auth/api-keys", options.cursor);
    return this.#client.request<Array<Record<string, unknown>>>("GET", "/v1/auth/api-keys", {
      params: { limit: options.limit ?? 50, offset: options.offset ?? 0 },
    });
  }

  /** Revoke an API key. Immediate and irreversible. */
  async revoke(keyId: string, options: { signal?: AbortSignal } = {}): Promise<void> {
    await this.#client.request<unknown>("DELETE", `/v1/auth/api-keys/${escapePathSegment(keyId)}`, {
      signal: options.signal,
    });
  }
}
