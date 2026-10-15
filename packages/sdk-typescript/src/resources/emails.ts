/**
 * Emails resource — sending and managing messages.
 *
 * Mirrors sdk-python's EmailsResource: same validation, same wire
 * serialization (see payload.ts), same endpoints, same auto-idempotency
 * behavior (SDK-B: a random key is generated per logical send even when the
 * caller does not supply one, so transport retries can never duplicate).
 */
import { randomUUID } from "node:crypto";

import { ApexMailError, ValidationError } from "../errors.js";
import type {
  AddressInput,
  Attachment,
  Email,
  EmailListResponse,
  SendEmailResponse,
  TagInput,
} from "../models.js";
import {
  buildSendPayload,
  MAX_BATCH_SIZE,
  validateId,
  validateSendFields,
  type SendPayloadOptions,
} from "../payload.js";
import type { ApexMail } from "../client.js";

export interface SendOptions {
  /** Sender: bare address, "Name <addr>" display string, or {email, name}. */
  from: AddressInput;
  /** Recipient(s): a bare address, display string, or {email, name}. */
  to: AddressInput | AddressInput[];
  /** Optional when `templateId` is given (the stored template supplies it). */
  subject?: string;
  /** HTML body. Optional when `text` or `templateId` is given. */
  html?: string;
  /** Plain-text body. Optional when `html` or `templateId` is given. */
  text?: string;
  cc?: AddressInput[];
  bcc?: AddressInput[];
  replyTo?: AddressInput;
  /** Strings, or {name, value} objects flattened to "name=value". */
  tags?: TagInput[];
  /** {filename, content (base64), contentType} attachments. */
  attachments?: Attachment[];
  /** Custom email headers. */
  headers?: Record<string, string>;
  /** ISO 8601 string or Date for scheduled sending. */
  scheduledAt?: string | Date;
  metadata?: Record<string, unknown>;
  /** Queue priority: integer 1-10 or "high"/"normal"/"low". */
  priority?: number | string;
  /** Stored template id supplying subject/html/text, rendered with templateData. */
  templateId?: string;
  /** Variables for template rendering. */
  templateData?: Record<string, unknown>;
  /** Idempotency key; a random UUID is generated when omitted. */
  idempotencyKey?: string;
  /** Per-request cancellation signal. */
  signal?: AbortSignal;
}

/** One batch item: send()'s inputs with snake_case aliases accepted too. */
export type BatchEmail = Omit<SendOptions, "idempotencyKey" | "signal"> & {
  from_?: AddressInput;
  reply_to?: AddressInput;
  scheduled_at?: string | Date;
  template_id?: string;
  template_data?: Record<string, unknown>;
};

export interface ListEmailsOptions {
  limit?: number;
  offset?: number;
  /** Cursor pagination (only valid with the default created_at sort). */
  cursor?: string;
  status?: string;
  sortBy?: string;
  signal?: AbortSignal;
}

function normalizeBatchMessage(email: BatchEmail): SendPayloadOptions {
  return {
    from: (email.from ?? email.from_) as AddressInput,
    to: email.to,
    subject: email.subject,
    html: email.html,
    text: email.text,
    cc: email.cc,
    bcc: email.bcc,
    replyTo: email.replyTo ?? email.reply_to,
    tags: email.tags,
    attachments: email.attachments,
    headers: email.headers,
    scheduledAt: email.scheduledAt ?? email.scheduled_at,
    metadata: email.metadata,
    priority: email.priority,
    templateId: email.templateId ?? email.template_id,
    templateData: email.templateData ?? email.template_data,
  };
}

function parseBatchResults(data: unknown): SendEmailResponse[] {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new ApexMailError("Invalid batch response: expected object payload", {
      code: "INVALID_RESPONSE",
      statusCode: 0,
    });
  }
  const results = (data as { results?: unknown }).results;
  if (!Array.isArray(results)) {
    throw new ApexMailError("Invalid batch response: expected 'results' list", {
      code: "INVALID_RESPONSE",
      statusCode: 0,
    });
  }
  for (const item of results) {
    if (!item || typeof item !== "object") {
      throw new ApexMailError("Invalid batch response: each result must be an object", {
        code: "INVALID_RESPONSE",
        statusCode: 0,
      });
    }
  }
  // SDK-D: rejected items lack 'id' and carry {index, status: "rejected",
  // error} — modeled with an optional id, so a partial rejection does not
  // raise after the API already accepted siblings.
  return results as SendEmailResponse[];
}

export class EmailsResource {
  readonly #client: ApexMail;

  constructor(client: ApexMail) {
    this.#client = client;
  }

  /**
   * Send an email. Every accepted option is serialized — display names
   * survive as "Name <addr>" forms, tags go out as a string list,
   * attachments/headers/priority under their documented snake_case names.
   *
   * A template-only send (templateId + templateData, no subject/html/text)
   * is valid: the stored template supplies the content.
   */
  async send(options: SendOptions): Promise<SendEmailResponse> {
    const templateId = validateSendFields(options);
    const payload = buildSendPayload({ ...options, templateId });
    return this.#client.request<SendEmailResponse>("POST", "/v1/messages", {
      json: payload,
      // SDK-B: when the caller supplies no key, generate one per logical
      // send so transport-level retries present the same key.
      idempotencyKey: options.idempotencyKey ?? randomUUID(),
      signal: options.signal,
    });
  }

  /**
   * Send up to 100 emails in one batch. Each item accepts send()'s inputs
   * (plus the snake_case aliases) and is serialized with the exact same
   * coercion as send(). Rejected items come back with status "rejected",
   * an `error` message and no `id`.
   */
  async batch(emails: BatchEmail[], options: { idempotencyKey?: string; signal?: AbortSignal } = {}): Promise<SendEmailResponse[]> {
    if (!Array.isArray(emails) || emails.length === 0) {
      throw new ValidationError('"emails" list must not be empty');
    }
    if (emails.length > MAX_BATCH_SIZE) {
      throw new ValidationError(`Maximum ${MAX_BATCH_SIZE} emails per batch, got ${emails.length}`);
    }
    emails.forEach((email, index) => {
      validateSendFields(normalizeBatchMessage(email), { label: `Email at index ${index}` });
    });

    const data = await this.#client.request<unknown>("POST", "/v1/messages/batch", {
      json: { messages: emails.map((email) => buildSendPayload(normalizeBatchMessage(email))) },
      idempotencyKey: options.idempotencyKey ?? randomUUID(),
      signal: options.signal,
    });
    return parseBatchResults(data);
  }

  /**
   * Alias of batch() under the name documented in docs/api/sdk-reference.md
   * ("emails.send_batch()") — same endpoint, same serialization, same auto
   * idempotency key.
   */
  async sendBatch(emails: BatchEmail[], options: { idempotencyKey?: string; signal?: AbortSignal } = {}): Promise<SendEmailResponse[]> {
    return this.batch(emails, options);
  }

  /** Get message details by ID (flat MessageDetail payload). */
  async get(emailId: string, options: { signal?: AbortSignal } = {}): Promise<Email> {
    validateId(emailId, "email");
    let data = await this.#client.request<unknown>("GET", `/v1/messages/${emailId}`, {
      signal: options.signal,
    });
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const legacy = (data as { email?: unknown }).email;
      if (legacy && typeof legacy === "object") {
        data = legacy;
      }
    }
    return data as Email;
  }

  /**
   * List emails. The server's ListMessagesQuery accepts {limit, offset,
   * cursor, status, sort_by} only. Pagination: the envelope's
   * `meta.nextCursor` becomes `cursor` and `meta.hasMore` becomes
   * `has_more`; pass `cursor` back to fetch the next page.
   */
  async list(options: ListEmailsOptions = {}): Promise<EmailListResponse> {
    const params: Record<string, string | number | boolean> = {
      limit: options.limit ?? 25,
      offset: options.offset ?? 0,
    };
    if (options.cursor !== undefined) {
      params.cursor = options.cursor;
    }
    if (options.status) {
      params.status = options.status;
    }
    if (options.sortBy) {
      params.sort_by = options.sortBy;
    }

    const { data, meta } = await this.#client.requestWithMeta<unknown>("GET", "/v1/messages", {
      params,
      signal: options.signal,
    });
    const envelopes = meta as Record<string, unknown> | null;
    const emails = Array.isArray(data)
      ? data
      : ((data as { emails?: Email[] } | null)?.emails ?? []);
    const nextCursor =
      (envelopes?.nextCursor as string | undefined) ??
      (envelopes?.next_cursor as string | undefined) ??
      null;
    const hasMore = Boolean(envelopes?.hasMore ?? envelopes?.has_more ?? false);
    return { emails: emails as Email[], cursor: nextCursor, has_more: hasMore };
  }

  /** Cancel a scheduled email ({id, status, created_at} on the wire). */
  async cancel(emailId: string, options: { signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
    validateId(emailId, "email");
    let data = await this.#client.request<unknown>("POST", `/v1/messages/${emailId}/cancel`, {
      signal: options.signal,
    });
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const legacy = (data as { email?: unknown }).email;
      if (legacy && typeof legacy === "object") {
        data = legacy;
      }
    }
    return data as Record<string, unknown>;
  }
}
