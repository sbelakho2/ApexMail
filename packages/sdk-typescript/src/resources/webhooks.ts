/**
 * Webhooks resource — endpoint management.
 *
 * The server's CreateWebhookRequest accepts exactly {url, events}
 * (deny_unknown_fields) and returns the flat WebhookResponse
 * {id, url, events, secret?, status, created_at, updated_at} — there is no
 * {"webhook": ...} wrapper and no name/enabled fields. The signing secret is
 * generated server-side and returned only at creation and rotation; pass it
 * verbatim to verifySignature().
 */
import { ValidationError } from "../errors.js";
import type { Webhook, WebhookListResponse } from "../models.js";
import { validateId } from "../payload.js";
import type { ApexMail } from "../client.js";

/**
 * Event names the server accepts (api-server/src/routes/webhooks.rs
 * KNOWN_WEBHOOK_EVENTS, canonicalized 2026-09-08). Any other name is
 * rejected with 422 server-side.
 */
export const KNOWN_WEBHOOK_EVENTS: readonly string[] = [
  "message.accepted",
  "message.queued",
  "message.attempted",
  "message.deferred",
  "message.delivered",
  "message.bounced",
  "message.complained",
  "message.suppressed",
  "message.opened",
  "message.clicked",
  "message.cancelled",
  "recipient.unsubscribed",
  // Campaign lifecycle (produced by the campaign worker).
  "campaign.started",
  "campaign.ab_winner_selected",
  "campaign.completed",
  "placement_test.completed",
  "inbound",
  "*",
];

function validateWebhookUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ValidationError(`Webhook URL must use HTTPS: "${url}". HTTP is only allowed for localhost development.`);
  }
  if (parsed.protocol !== "https:") {
    const hostname = (parsed.hostname || "").toLowerCase();
    if (!["localhost", "127.0.0.1", "::1"].includes(hostname)) {
      throw new ValidationError(
        `Webhook URL must use HTTPS: "${url}". HTTP is only allowed for localhost development.`,
      );
    }
  }
}

/**
 * Warn on unknown event names — the server 422s them. Deliberately advisory
 * (audit SM15 F1): the server owns the vocabulary and a client-side gate
 * would brick the SDK every time the server adds an event type.
 */
export function warnUnknownEvents(events: string[]): void {
  const invalid = events.filter((event) => !KNOWN_WEBHOOK_EVENTS.includes(event.trim()));
  if (invalid.length > 0) {
    console.warn(
      `Unknown webhook event type(s): ${invalid.join(", ")}. ` +
        `Known events: ${KNOWN_WEBHOOK_EVENTS.join(", ")}`,
    );
  }
}

function parseWebhook(data: unknown): Webhook {
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const record = data as Record<string, unknown>;
    if (record.webhook && typeof record.webhook === "object") {
      return record.webhook as Webhook;
    }
  }
  return data as Webhook;
}

export interface WebhookCreateInput {
  // Legacy inputs accepted for backwards compatibility but ignored on the
  // wire (the server rejects unknown fields; the secret is generated
  // server-side).
  name?: string;
  url: string;
  events: string[];
  description?: string;
  secret?: string;
  headers?: Record<string, string>;
  enabled?: boolean;
  signal?: AbortSignal;
}

export interface WebhookUpdateInput {
  name?: string;
  url?: string;
  events?: string[];
  description?: string;
  headers?: Record<string, string>;
  /** Mapped to status active/paused for backwards compatibility. */
  enabled?: boolean;
  /** "active" | "paused" | "disabled". */
  status?: string;
  signal?: AbortSignal;
}

export class WebhooksResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /**
   * Create a webhook. Only {url, events} are transmitted; the signing
   * secret is generated server-side and present in this response only.
   */
  async create(input: WebhookCreateInput): Promise<Webhook> {
    validateWebhookUrl(input.url);
    warnUnknownEvents(input.events);
    const data = await this.#client.request<unknown>("POST", "/v1/webhooks", {
      json: { url: input.url, events: input.events },
      signal: input.signal,
    });
    return parseWebhook(data);
  }

  async get(webhookId: string, options: { signal?: AbortSignal } = {}): Promise<Webhook> {
    validateId(webhookId, "webhook");
    const data = await this.#client.request<unknown>("GET", `/v1/webhooks/${webhookId}`, {
      signal: options.signal,
    });
    return parseWebhook(data);
  }

  async list(options: { limit?: number; offset?: number } = {}): Promise<WebhookListResponse> {
    const params: Record<string, string | number | boolean> = {};
    if (options.limit !== undefined) {
      params.limit = options.limit;
    }
    if (options.offset !== undefined) {
      params.offset = options.offset;
    }
    const data = await this.#client.request<unknown>("GET", "/v1/webhooks", { params });
    if (Array.isArray(data)) {
      return { webhooks: data as Webhook[] };
    }
    const webhooks = (data as { webhooks?: Webhook[] } | null)?.webhooks ?? [];
    return { webhooks };
  }

  /**
   * Update a webhook. Transmits only {url, events, status} per the API's
   * UpdateWebhookRequest; a boolean `enabled` maps to active/paused.
   */
  async update(webhookId: string, input: WebhookUpdateInput): Promise<Webhook> {
    validateId(webhookId, "webhook");
    const payload: Record<string, unknown> = {};
    if (input.url !== undefined) {
      validateWebhookUrl(input.url);
      payload.url = input.url;
    }
    if (input.events !== undefined) {
      warnUnknownEvents(input.events);
      payload.events = input.events;
    }
    let resolvedStatus = input.status;
    if (resolvedStatus === undefined && input.enabled !== undefined) {
      resolvedStatus = input.enabled ? "active" : "paused";
    }
    if (resolvedStatus !== undefined) {
      if (!["active", "paused", "disabled"].includes(resolvedStatus)) {
        throw new ValidationError(
          `status must be one of "active", "paused", "disabled" (got ${JSON.stringify(resolvedStatus)})`,
        );
      }
      payload.status = resolvedStatus;
    }
    if (Object.keys(payload).length === 0) {
      throw new ValidationError("Update payload must include at least one field");
    }
    const data = await this.#client.request<unknown>("PUT", `/v1/webhooks/${webhookId}`, {
      json: payload,
      signal: input.signal,
    });
    return parseWebhook(data);
  }

  async delete(webhookId: string, options: { signal?: AbortSignal } = {}): Promise<void> {
    validateId(webhookId, "webhook");
    await this.#client.request<unknown>("DELETE", `/v1/webhooks/${webhookId}`, {
      signal: options.signal,
    });
  }

  /** Send a test event to the webhook (the server takes no body). */
  async test(webhookId: string, options: { signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
    validateId(webhookId, "webhook");
    return this.#client.request<Record<string, unknown>>("POST", `/v1/webhooks/${webhookId}/test`, {
      signal: options.signal,
    });
  }

  /**
   * Rotate the webhook's signing secret. The new secret is returned in this
   * response only; the previous secret stops verifying deliveries
   * immediately, so update the receiver before rotating. Pass the secret
   * verbatim (the full `whsec_…` string) to verifySignature().
   */
  async rotateSecret(webhookId: string, options: { signal?: AbortSignal } = {}): Promise<Webhook> {
    validateId(webhookId, "webhook");
    const data = await this.#client.request<unknown>("POST", `/v1/webhooks/${webhookId}/rotate-secret`, {
      signal: options.signal,
    });
    return parseWebhook(data);
  }
}
