/** ApexMail API resources. */
export { EmailsResource, type BatchEmail, type ListEmailsOptions, type SendOptions } from "./emails.js";
export { DomainsResource, type ListDomainsOptions } from "./domains.js";
export { TemplatesResource, type ListTemplatesOptions } from "./templates.js";
export { SuppressionsResource, type ListSuppressionsOptions } from "./suppressions.js";
export { EventsResource, type EventRangeOptions, type ListEventsOptions } from "./events.js";
export {
  WebhooksResource,
  KNOWN_WEBHOOK_EVENTS,
  warnUnknownEvents,
  type WebhookCreateInput,
  type WebhookUpdateInput,
} from "./webhooks.js";
export { AnalyticsResource, type AnalyticsExportOptions, type AnalyticsQuery } from "./analytics.js";
export { ApiKeysResource, type CreateApiKeyOptions, type ListApiKeysOptions } from "./api-keys.js";
