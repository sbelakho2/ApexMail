/**
 * Domains resource — domain management and verification.
 *
 * The server's CreateDomainRequest accepts exactly {name}
 * (deny_unknown_fields) and DomainResponse is the flat object
 * {id, name, status, ...verification booleans, created_at} — there is no
 * {"domain": ...} wrapper.
 */
import type { Domain, DomainListResponse } from "../models.js";
import { rejectCursor, validateId } from "../payload.js";
import type { ApexMail } from "../client.js";

export interface ListDomainsOptions {
  limit?: number;
  offset?: number;
  /** Not supported: the server rejects `cursor` with HTTP 400. */
  cursor?: string;
}

function parseDomain(data: unknown): Domain {
  let payload = data as Record<string, unknown> | null;
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    const wrapped = payload.domain;
    if (wrapped && typeof wrapped === "object") {
      payload = wrapped as Record<string, unknown>;
    } else if (typeof wrapped === "string" && payload.name === undefined) {
      // Older payloads used a `domain` string key for the name.
      payload = { ...payload, name: wrapped };
    }
  }
  return payload as unknown as Domain;
}

export class DomainsResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /**
   * Add a new domain. The body sent is exactly {name} per the API's
   * CreateDomainRequest; `verificationMethod` is accepted for backwards
   * compatibility but the API has no such field (verification is always
   * DNS-based).
   */
  async create(domain: string, options: { verificationMethod?: string; signal?: AbortSignal } = {}): Promise<Domain> {
    void options.verificationMethod; // ignored on the wire, like sdk-python
    const data = await this.#client.request<unknown>("POST", "/v1/domains", {
      json: { name: domain },
      signal: options.signal,
    });
    return parseDomain(data);
  }

  /** Get domain details by ID (flat DomainResponse). */
  async get(domainId: string, options: { signal?: AbortSignal } = {}): Promise<Domain> {
    validateId(domainId, "domain");
    const data = await this.#client.request<unknown>("GET", `/v1/domains/${domainId}`, {
      signal: options.signal,
    });
    return parseDomain(data);
  }

  /**
   * List all domains. The server's ListDomainsQuery accepts {limit, offset}
   * only — a `cursor` parameter is rejected with HTTP 400, so it is refused
   * client-side instead.
   */
  async list(options: ListDomainsOptions = {}): Promise<DomainListResponse> {
    rejectCursor("/v1/domains", options.cursor);
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) {
      params.limit = options.limit;
    }
    if (options.offset !== undefined) {
      params.offset = options.offset;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/domains", {
      params,
    });
    if (Array.isArray(data)) {
      return { domains: data as Domain[] };
    }
    const domains = (data as { domains?: Domain[] } | null)?.domains ?? [];
    return { domains };
  }

  /** Trigger domain verification ({domain, spf_verified, ..., status}). */
  async verify(domainId: string, options: { signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
    validateId(domainId, "domain");
    return this.#client.request<Record<string, unknown>>("POST", `/v1/domains/${domainId}/verify`, {
      signal: options.signal,
    });
  }

  /** Delete a domain. */
  async delete(domainId: string, options: { signal?: AbortSignal } = {}): Promise<void> {
    validateId(domainId, "domain");
    await this.#client.request<unknown>("DELETE", `/v1/domains/${domainId}`, {
      signal: options.signal,
    });
  }

  /**
   * Domain health/verification state. The API has no GET /:id/health
   * endpoint — GET /:id itself returns the health information, so this is a
   * thin alias of get().
   */
  async health(domainId: string, options: { signal?: AbortSignal } = {}): Promise<Domain> {
    validateId(domainId, "domain");
    return this.get(domainId, options);
  }
}
