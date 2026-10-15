/**
 * Send-message wire contract + shared field validation.
 *
 * The serialized body must match the server DTO exactly: SendMessageRequest
 * (api-server/src/routes/messages.rs) is `deny_unknown_fields`, so one extra
 * key is a 422 — and every accepted option must reach the wire (audit F48's
 * "nothing is dropped silently" rule, pinned by
 * packages/contract/send-contract.json, the fixture set shared by all SDK
 * suites and the api-server contract tests).
 *
 * The helpers here mirror sdk-python's resources/emails.py one-to-one:
 * bare-addr-spec extraction, display-name-preserving serialization,
 * priority validation (integer 1-10 or "high"/"normal"/"low"), tag
 * flattening.
 */
import { ValidationError } from "./errors.js";
import type { AddressInput, Attachment, SendEmailRequest, TagInput } from "./models.js";

/** Basic email format validation (mirrors sdk-python's FIX-500-287 regex). */
const EMAIL_REGEX = /^[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/;

/** Resource-ID format validation (mirrors sdk-python's FIX-500-291 regex). */
const ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;

/** Server-side batch maximum (API_MESSAGES_MAX_BATCH_SIZE default). */
export const MAX_BATCH_SIZE = 100;

/**
 * F48 shared contract (packages/contract/send-contract.json): integers 1-10
 * and the documented named levels, mapped by the API to queue integers 7/5/3.
 */
const PRIORITY_NAMED_LEVELS: Record<string, number> = { high: 7, normal: 5, low: 3 };

export function validateEmail(email: string, field: string): void {
  if (!EMAIL_REGEX.test(email)) {
    throw new ValidationError(`Invalid "${field}" email format: ${email}`);
  }
}

export function validateId(resourceId: string, resourceName: string): void {
  if (!resourceId || !ID_REGEX.test(resourceId)) {
    throw new ValidationError(
      `Invalid ${resourceName} ID format: "${resourceId}". ` +
        "IDs must be 1-128 alphanumeric characters, hyphens, or underscores.",
    );
  }
}

/**
 * Fail fast on a `cursor` the server would reject with a plain-text 400:
 * these list endpoints' query structs are `deny_unknown_fields` without a
 * cursor field (see packages/README.md "Cursor Pagination"). Only
 * `emails.list()` supports cursor pagination.
 */
export function rejectCursor(path: string, cursor: unknown): void {
  if (cursor !== undefined && cursor !== null) {
    throw new ValidationError(
      `${path} does not support cursor pagination ` +
        "(the server rejects `cursor` with HTTP 400); use limit/offset",
      { code: "UNSUPPORTED_PAGINATION" },
    );
  }
}

/**
 * Extract the bare addr-spec from any accepted mailbox form (F48):
 * `"addr"` and `"Name <addr>"` display strings, and `{email, name}` objects
 * all yield the bare address. Malformed forms (unclosed/multiple mailboxes,
 * trailing text) return null — exactly the acceptance rule of the API's
 * structured mailbox parser.
 */
export function extractBareAddress(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const email = record.email ?? record.address;
    return email ? String(email) : null;
  }
  const raw = String(value).trim();
  const openAt = raw.lastIndexOf("<");
  if (openAt !== -1) {
    if (!raw.endsWith(">")) {
      return null;
    }
    const prefix = raw.slice(0, openAt);
    if (prefix.includes("<") || prefix.includes(">")) {
      return null;
    }
    return raw.slice(openAt + 1, -1).trim();
  }
  if (raw.includes(">")) {
    return null;
  }
  return raw;
}

/**
 * Validate priority per the F48 shared contract and return the exact wire
 * form the API deserializer accepts: an integer 1-10, or one of
 * "high"/"normal"/"low" (case-insensitive, canonicalized to lowercase).
 * Anything else raises before a request is sent.
 */
export function validatePriority(priority: unknown): number | string {
  const contract =
    'priority must be an integer between 1 and 10 or one of the named levels ' +
    '"high"/"normal"/"low" (mapped to 7/5/3)';
  if (typeof priority === "boolean" || (typeof priority !== "number" && typeof priority !== "string")) {
    throw new ValidationError(`${contract} — received ${JSON.stringify(priority)}`);
  }
  if (typeof priority === "number") {
    if (!Number.isInteger(priority) || priority < 1 || priority > 10) {
      throw new ValidationError(
        `${contract} — received the out-of-range integer ${priority}`,
      );
    }
    return priority;
  }
  const level = priority.trim().toLowerCase();
  if (level in PRIORITY_NAMED_LEVELS) {
    return level;
  }
  throw new ValidationError(`${contract} — received '${priority}'`);
}

/**
 * Serialize one address input to the wire form. `"addr"` stays bare;
 * `{email, name}` serializes as the RFC 5322 display form `"Name <addr>"`
 * so the display name survives instead of being silently dropped (F48).
 */
export function serializeAddress(recipient: AddressInput | null | undefined): string | null {
  if (recipient === null || recipient === undefined) {
    return null;
  }
  if (typeof recipient === "object") {
    const email = recipient.email;
    if (!email) {
      return null;
    }
    return recipient.name ? `${recipient.name} <${email}>` : String(email);
  }
  return String(recipient);
}

/** Serialize a recipient field, preserving display names (F48). */
export function serializeRecipientList(
  value: AddressInput | AddressInput[] | null | undefined,
): string[] | null {
  if (value === null || value === undefined) {
    return null;
  }
  const recipients = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (const recipient of recipients) {
    const formatted = serializeAddress(recipient);
    if (formatted) {
      out.push(formatted);
    }
  }
  return out.length > 0 ? out : null;
}

/**
 * The API requires tags to be a string list. Legacy {name, value} inputs are
 * still accepted and flattened to "name" or "name=value".
 */
export function normalizeTags(tags: TagInput[] | null | undefined): string[] | null {
  if (tags === null || tags === undefined) {
    return null;
  }
  const normalized: string[] = [];
  for (const tag of tags) {
    if (typeof tag === "string") {
      normalized.push(tag);
    } else if (tag && typeof tag === "object" && tag.name) {
      const value = tag.value;
      normalized.push(value !== undefined && value !== null ? `${tag.name}=${value}` : String(tag.name));
    }
  }
  return normalized.length > 0 ? normalized : null;
}

/**
 * A template supplies the subject/body when `templateId` is given, so a
 * template-only send is valid. Returns the normalized template id (or null)
 * and refuses shapes the server would: variables without a template, or a
 * non-object templateData.
 */
export function validateTemplateFields(
  templateId: unknown,
  templateData: unknown,
  label = "",
): string | null {
  const prefix = label ? `${label}: ` : "";
  const normalizedId = typeof templateId === "string" ? templateId.trim() : templateId;
  if (!normalizedId) {
    if (templateData !== undefined && templateData !== null) {
      throw new ValidationError(`${prefix}"templateData" requires "templateId"`);
    }
    return null;
  }
  if (
    templateData !== undefined &&
    templateData !== null &&
    (typeof templateData !== "object" || Array.isArray(templateData))
  ) {
    throw new ValidationError(`${prefix}"templateData" must be a JSON object of template variables`);
  }
  return String(normalizedId);
}

/** Validate a recipient group against the extracted bare addr-specs. */
export function validateRecipients(
  value: readonly unknown[] | null | undefined,
  field: string,
  { required = false }: { required?: boolean } = {},
): void {
  if (value === null || value === undefined) {
    if (required) {
      throw new ValidationError(`"${field}" is required`);
    }
    return;
  }
  if (value.length === 0) {
    throw new ValidationError(`"${field}" must contain at least one recipient`);
  }
  for (const recipient of value) {
    if (typeof recipient !== "string" && typeof recipient !== "object") {
      throw new ValidationError(`"${field}" must be a string or list of strings`);
    }
    const bare = extractBareAddress(recipient);
    if (!bare) {
      throw new ValidationError(`Invalid "${field}" email format: ${String(recipient)}`);
    }
    validateEmail(bare, field);
  }
}

export interface SendPayloadOptions {
  from: AddressInput;
  to: AddressInput | AddressInput[];
  subject?: string | null;
  html?: string | null;
  text?: string | null;
  cc?: AddressInput[] | null;
  bcc?: AddressInput[] | null;
  replyTo?: AddressInput | null;
  tags?: TagInput[] | null;
  attachments?: Attachment[] | null;
  headers?: Record<string, string> | null;
  scheduledAt?: string | Date | null;
  metadata?: Record<string, unknown> | null;
  priority?: number | string | null;
  templateId?: string | null;
  templateData?: Record<string, unknown> | null;
}

/**
 * Serialize a send body for POST /v1/messages.
 *
 * Every accepted option is serialized — nothing is dropped silently (F48):
 * from/to/cc/bcc/replyTo go out as address strings with display names
 * preserved as `"Name <addr>"` forms, tags as a string list,
 * attachments/headers/priority under their documented snake_case names, and
 * templateId/templateData for template sends. Priority follows the shared
 * contract — anything outside it raises before a request is sent.
 */
export function buildSendPayload(options: SendPayloadOptions): SendEmailRequest {
  const fromSerialized = serializeAddress(options.from);
  const payload: SendEmailRequest = {
    from: fromSerialized ?? String(options.from),
    to: serializeRecipientList(options.to) ?? [],
  };

  // A template-only send omits subject/html/text entirely — the stored
  // template supplies them (docs/api/endpoints/messages.md).
  if (options.subject) {
    payload.subject = options.subject;
  }
  if (options.html) {
    payload.html = options.html;
  }
  if (options.text) {
    payload.text = options.text;
  }
  const cc = serializeRecipientList(options.cc);
  if (cc) {
    payload.cc = cc;
  }
  const bcc = serializeRecipientList(options.bcc);
  if (bcc) {
    payload.bcc = bcc;
  }
  const replyTo = serializeAddress(options.replyTo);
  if (replyTo) {
    payload.reply_to = replyTo;
  }
  const tags = normalizeTags(options.tags);
  if (tags) {
    payload.tags = tags;
  }
  if (options.attachments && options.attachments.length > 0) {
    payload.attachments = options.attachments.map((attachment) => ({ ...attachment }));
  }
  if (options.headers && Object.keys(options.headers).length > 0) {
    payload.headers = { ...options.headers };
  }
  if (options.scheduledAt) {
    payload.scheduled_at =
      options.scheduledAt instanceof Date
        ? options.scheduledAt.toISOString()
        : options.scheduledAt;
  }
  if (options.metadata) {
    payload.metadata = options.metadata;
  }
  if (options.priority !== undefined && options.priority !== null) {
    payload.priority = validatePriority(options.priority);
  }
  if (options.templateId) {
    payload.template_id = options.templateId;
  }
  if (options.templateData) {
    payload.template_data = options.templateData;
  }
  return payload;
}

/**
 * Validate the fields a `send()` accepts (or one batch item's), so shapes
 * the API's deserializer refuses never reach the wire. `label` prefixes
 * batch errors with the item index like sdk-python does.
 */
export function validateSendFields(
  options: SendPayloadOptions,
  { label = "" }: { label?: string } = {},
): string | null {
  const prefix = label ? `${label}: ` : "";
  const fromBare = extractBareAddress(options.from);
  if (!fromBare) {
    throw new ValidationError(`${prefix}"from" must be an email address or {"email": ..., "name": ...}`);
  }
  validateEmail(fromBare, "from");

  const recipients = Array.isArray(options.to) ? options.to : [options.to];
  if (recipients.length === 0) {
    throw new ValidationError(`${prefix}"to" must contain at least one recipient`);
  }
  for (const recipient of recipients) {
    if (typeof recipient !== "string" && typeof recipient !== "object") {
      throw new ValidationError(`${prefix}"to" must be a string or list of strings`);
    }
    const recipientBare = extractBareAddress(recipient);
    if (!recipientBare) {
      throw new ValidationError(`${prefix}Invalid "to" email format: ${String(recipient)}`);
    }
    validateEmail(recipientBare, "to");
  }
  if (options.replyTo !== undefined && options.replyTo !== null) {
    const replyToBare = extractBareAddress(options.replyTo);
    if (!replyToBare) {
      throw new ValidationError(`${prefix}"replyTo" must be an email address or {"email": ...}`);
    }
    validateEmail(replyToBare, "replyTo");
  }
  if (options.cc !== undefined && options.cc !== null) {
    validateRecipients(options.cc, "cc");
  }
  if (options.bcc !== undefined && options.bcc !== null) {
    validateRecipients(options.bcc, "bcc");
  }
  if (options.priority !== undefined && options.priority !== null) {
    validatePriority(options.priority);
  }

  const templateId = validateTemplateFields(options.templateId, options.templateData, label);
  if (!options.subject && !templateId) {
    throw new ValidationError(`${prefix}"subject" is required (or provide templateId)`);
  }
  if (!options.html && !options.text && !templateId) {
    throw new ValidationError(
      `${prefix}Either "html" or "text" body is required (or provide templateId)`,
    );
  }
  if (options.html && !options.html.trim()) {
    throw new ValidationError(`${prefix}"html" body must not be empty or whitespace-only`);
  }
  if (options.text && !options.text.trim()) {
    throw new ValidationError(`${prefix}"text" body must not be empty or whitespace-only`);
  }
  return templateId;
}
