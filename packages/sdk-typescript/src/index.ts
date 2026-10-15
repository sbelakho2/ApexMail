/**
 * ApexMail Node.js/TypeScript SDK (@apexmail/node).
 *
 * Official Node.js SDK for the ApexMail transactional email API — the same
 * resource surface as the other first-party SDKs, zero runtime
 * dependencies, ESM + CommonJS builds.
 *
 * Usage:
 *
 * ```ts
 * import { ApexMail } from "@apexmail/node";
 *
 * const client = new ApexMail("am_live_your_api_key");
 * const message = await client.emails.send({
 *   from: "hello@example.com",
 *   to: "user@example.com",
 *   subject: "Welcome!",
 *   html: "<h1>Hello!</h1>",
 * });
 * console.log(message.id);
 * ```
 */

// Client + transport configuration
export {
  ApexMail,
  API_KEY_PATTERN,
  DEFAULT_BASE_URL,
  DEFAULT_INITIAL_BACKOFF_SECONDS,
  DEFAULT_MAX_BACKOFF_SECONDS,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_MAX_RETRIES,
  DEFAULT_TIMEOUT_SECONDS,
  DEFAULT_TOTAL_RETRY_TIMEOUT_SECONDS,
  MAX_RETRY_AFTER_SECONDS,
  RETRYABLE_STATUS_CODES,
  addJitter,
  assertServerEnvironment,
  calculateBackoff,
  parseErrorEnvelope,
  parseRetryAfter,
  type ApexMailOptions,
  type ErrorEnvelope,
  type RequestOptions,
} from "./client.js";

// Errors
export {
  ApexMailError,
  AuthenticationError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
  type ApexMailErrorOptions,
  type RateLimitErrorOptions,
  type ValidationErrorOptions,
} from "./errors.js";

// Models
export {
  DomainStatus,
  EmailStatus,
  WebhookEvent,
  type AddressInput,
  type Attachment,
  type BulkSuppressionResponse,
  type DNSRecord,
  type Domain,
  type DomainListResponse,
  type Email,
  type EmailAddress,
  type EmailListResponse,
  type Event,
  type EventListResponse,
  type EventStats,
  type EventTimeseriesPoint,
  type ResponseMeta,
  type SendEmailRequest,
  type SendEmailResponse,
  type Suppression,
  type SuppressionCheckResponse,
  type SuppressionListResponse,
  type Tag,
  type TagInput,
  type Template,
  type TemplateListResponse,
  type TemplateRenderResponse,
  type Webhook,
  type WebhookListResponse,
} from "./models.js";

// Resources
export {
  AnalyticsResource,
  ApiKeysResource,
  DomainsResource,
  EmailsResource,
  EventsResource,
  KNOWN_WEBHOOK_EVENTS,
  SuppressionsResource,
  TemplatesResource,
  WebhooksResource,
  warnUnknownEvents,
  type AnalyticsExportOptions,
  type AnalyticsQuery,
  type BatchEmail,
  type CreateApiKeyOptions,
  type EventRangeOptions,
  type ListApiKeysOptions,
  type ListDomainsOptions,
  type ListEmailsOptions,
  type ListEventsOptions,
  type ListSuppressionsOptions,
  type ListTemplatesOptions,
  type SendOptions,
  type WebhookCreateInput,
  type WebhookUpdateInput,
} from "./resources/index.js";

// Shared send-payload contract (exported so the wire forms are testable
// and reusable — sdk-python exports the same helpers from its tests).
export {
  MAX_BATCH_SIZE,
  buildSendPayload,
  extractBareAddress,
  normalizeTags,
  rejectCursor,
  serializeAddress,
  serializeRecipientList,
  validateEmail,
  validateId,
  validatePriority,
  validateRecipients,
  validateSendFields,
  validateTemplateFields,
  type SendPayloadOptions,
} from "./payload.js";

// Webhook signature verification
export {
  verifySignature,
  verifyWebhookSignature,
  type SignatureHeader,
  type VerifySignatureOptions,
} from "./webhooks.js";

// Version
export { SDK_VERSION } from "./version.js";
