/**
 * Typed request/response models.
 *
 * Response interfaces use the API's wire field names verbatim
 * (snake_case, e.g. `created_at`, `html_body`, `has_more`) — exactly like
 * sdk-python's pydantic models. Nothing is renamed or dropped between the
 * server payload and the returned object, so the types can be checked
 * against docs/api/endpoints/*.md directly.
 *
 * Request options (the `send()` keyword arguments, template create/update
 * inputs, ...) use idiomatic camelCase; every resource serializes them to
 * the documented snake_case wire keys.
 */

// ── Enumerations (const objects, mirroring the Python str enums) ───────────

/** Email delivery status (docs/api/endpoints/messages.md "Status Values"). */
export const EmailStatus = {
  QUEUED: "queued",
  SCHEDULED: "scheduled",
  PROCESSING: "processing",
  SENDING: "sending",
  SENT: "sent",
  PARTIAL: "partial",
  DELIVERED: "delivered",
  BOUNCED: "bounced",
  COMPLAINED: "complained",
  FAILED: "failed",
  REJECTED: "rejected",
  CANCELLED: "cancelled",
} as const;
export type EmailStatus = (typeof EmailStatus)[keyof typeof EmailStatus];

/** Domain verification status. */
export const DomainStatus = {
  PENDING: "pending",
  VERIFIED: "verified",
  FAILED: "failed",
  EXPIRED: "expired",
} as const;
export type DomainStatus = (typeof DomainStatus)[keyof typeof DomainStatus];

/**
 * Webhook event types — mirrors KNOWN_WEBHOOK_EVENTS in
 * api-server/src/routes/webhooks.rs (canonical `message.*` vocabulary,
 * canonicalized 2026-09-08). The server rejects any other name with 422.
 */
export const WebhookEvent = {
  MESSAGE_ACCEPTED: "message.accepted",
  MESSAGE_QUEUED: "message.queued",
  MESSAGE_ATTEMPTED: "message.attempted",
  MESSAGE_DEFERRED: "message.deferred",
  MESSAGE_DELIVERED: "message.delivered",
  MESSAGE_BOUNCED: "message.bounced",
  MESSAGE_COMPLAINED: "message.complained",
  MESSAGE_SUPPRESSED: "message.suppressed",
  MESSAGE_OPENED: "message.opened",
  MESSAGE_CLICKED: "message.clicked",
  MESSAGE_CANCELLED: "message.cancelled",
  RECIPIENT_UNSUBSCRIBED: "recipient.unsubscribed",
  PLACEMENT_TEST_COMPLETED: "placement_test.completed",
  INBOUND: "inbound",
  ALL: "*",
} as const;
export type WebhookEvent = (typeof WebhookEvent)[keyof typeof WebhookEvent];

// ── Addresses / attachments / tags ─────────────────────────────────────────

/** A mailbox: a bare address, a "Name <addr>" display string, or a pair. */
export interface EmailAddress {
  email: string;
  name?: string | null;
}

export type AddressInput = string | EmailAddress;

/** Email tag: a plain string, or {name, value} (flattened to "name=value"). */
export interface Tag {
  name: string;
  value?: string | null;
}

export type TagInput = string | Tag;

/** Email attachment (content is base64-encoded). */
export interface Attachment {
  filename: string;
  content: string;
  /** Wire key: `contentType`. */
  contentType?: string;
}

// ── Messages ───────────────────────────────────────────────────────────────

/**
 * A send response. Single sends return {id, status, created_at}; batch
 * items are {index, id? (accepted only), status: "queued"|"rejected",
 * error? (rejected only)}.
 */
export interface SendEmailResponse {
  id?: string | null;
  status: EmailStatus;
  index?: number | null;
  error?: string | null;
  created_at?: string | null;
}

/** Message details (the flat MessageDetail payload of GET /v1/messages/:id). */
export interface Email {
  id: string;
  from: string;
  to: string[];
  cc?: string[] | null;
  bcc?: string[] | null;
  subject: string;
  status: EmailStatus;
  scheduled_at?: string | null;
  created_at: string;
  sent_at?: string | null;
  delivered_at?: string | null;
  opened_at?: string | null;
  clicked_at?: string | null;
  tags?: string[] | null;
  metadata?: Record<string, unknown> | null;
}

/**
 * Response from listing emails. `cursor` carries the server's opaque
 * `meta.nextCursor` (null on the last page); `has_more` mirrors
 * `meta.hasMore`.
 */
export interface EmailListResponse {
  emails: Email[];
  cursor: string | null;
  has_more: boolean;
}

/** The wire body of POST /v1/messages (SendMessageRequest). */
export interface SendEmailRequest {
  from: string;
  to: string[];
  subject?: string;
  html?: string;
  text?: string;
  cc?: string[];
  bcc?: string[];
  reply_to?: string;
  tags?: string[];
  attachments?: Attachment[];
  headers?: Record<string, string>;
  scheduled_at?: string;
  metadata?: Record<string, unknown>;
  priority?: number | string;
  template_id?: string;
  template_data?: Record<string, unknown>;
}

// ── Domains ────────────────────────────────────────────────────────────────

export interface DNSRecord {
  type: string;
  name: string;
  value: string;
  verified: boolean;
}

/** Flat DomainResponse: {id, name, status, ...verification booleans}. */
export interface Domain {
  id: string;
  name?: string | null;
  status: DomainStatus;
  ses_verified?: boolean | null;
  spf_verified?: boolean | null;
  dkim_verified?: boolean | null;
  dmarc_verified?: boolean | null;
  return_path_verified?: boolean | null;
  verification_token?: string | null;
  dns_records?: Record<string, DNSRecord> | null;
  verified_at?: string | null;
  created_at: string;
}

export interface DomainListResponse {
  domains: Domain[];
}

// ── Webhooks ───────────────────────────────────────────────────────────────

/**
 * Webhook details. The signing `secret` is present only in create and
 * rotate-secret responses; `status` is "active" | "paused" | "disabled".
 */
export interface Webhook {
  id: string;
  url: string;
  events: string[];
  status: string;
  secret?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface WebhookListResponse {
  webhooks: Webhook[];
}

// ── Templates ──────────────────────────────────────────────────────────────

export interface Template {
  id: string;
  name: string;
  subject: string;
  html_body: string;
  text_body?: string | null;
  version: number;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface TemplateRenderResponse {
  subject: string;
  html: string;
  text?: string | null;
}

export interface TemplateListResponse {
  templates: Template[];
  cursor?: string | null;
  has_more?: boolean;
}

// ── Suppressions ───────────────────────────────────────────────────────────

export interface Suppression {
  id: string;
  email: string;
  reason: string;
  source?: string | null;
  created_at: string;
}

export interface SuppressionCheckResponse {
  email: string;
  suppressed: boolean;
  reason?: string | null;
}

export interface SuppressionListResponse {
  suppressions: Suppression[];
  cursor?: string | null;
  has_more?: boolean;
}

export interface BulkSuppressionResponse {
  created: number;
  duplicates: number;
  invalid: number;
}

// ── Events ─────────────────────────────────────────────────────────────────

export interface Event {
  id: string;
  message_id?: string | null;
  event_type: string;
  recipient?: string | null;
  metadata?: Record<string, unknown> | null;
  timestamp: string;
}

export interface EventStats {
  total: number;
  delivered: number;
  bounced: number;
  complained: number;
  opened: number;
  clicked: number;
}

export interface EventTimeseriesPoint {
  timestamp: string;
  count: number;
  event_type: string;
}

export interface EventListResponse {
  events: Event[];
  cursor?: string | null;
  has_more?: boolean;
}

// ── Envelope metadata ──────────────────────────────────────────────────────

/** The envelope's `meta` object on paginated list endpoints. */
export interface ResponseMeta {
  hasMore?: boolean;
  nextCursor?: string | null;
  [key: string]: unknown;
}
