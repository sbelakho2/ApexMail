# ApexMail Node.js/TypeScript SDK

Official Node.js SDK for the ApexMail transactional email API — `@apexmail/node`.

- Zero runtime dependencies (Node's built-in `fetch`), Node.js ≥ 20
- ESM + CommonJS builds with full TypeScript declarations
- Typed requests/responses, typed errors, automatic retries and idempotency keys
- Webhook signature verification matching the platform's exact signing scheme

## Installation

> **Not yet published to npm.** Until the first registry release, install from
> the monorepo source and pin to a specific commit:

```bash
npm install ./packages/sdk-typescript
```

## Quick Start

Use your real ApexMail API key in place of `am_live_xxxx`; the example value below is a placeholder.

```ts
import { ApexMail } from "@apexmail/node";

const client = new ApexMail("am_live_xxxx");

const message = await client.emails.send({
  from: "hello@example.com",
  to: "user@example.com",
  subject: "Welcome!",
  html: "<h1>Hello World!</h1>",
});

console.log(`Email sent! ID: ${message.id}`);
```

CommonJS works too:

```js
const { ApexMail } = require("@apexmail/node");
```

## Configuration

```ts
const client = new ApexMail("am_live_xxxx", {
  baseUrl: "https://api.apexmail.ee", // default; a trailing /v1 is stripped
  timeout: 30,                        // seconds, default 30
  maxRetries: 3,                      // default 3
  maxResponseBytes: 20 * 1024 * 1024, // default 20 MiB
  signal: controller.signal,          // optional: cancel every request
});
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | `https://api.apexmail.ee` | API base URL override (HTTPS required; HTTP only for localhost). |
| `timeout` | `number` | `30` | Per-attempt timeout in seconds. |
| `maxRetries` | `number` | `3` | Retries for `408/429/500/502/503/504` and transport failures. |
| `maxResponseBytes` | `number` | `20971520` | Response-body cap, enforced while streaming. |
| `signal` | `AbortSignal` | — | Cancellation for every request from this client. |
| `fetch` | `typeof fetch` | global `fetch` | Transport override (proxies, instrumentation, tests). |

Per-request cancellation is also available (`send(..., { signal })`).

**Secret protection:** the client refuses to construct in a browser-like
environment — an API key embedded in client-side JavaScript is public to
every visitor. Call the API from a server or a serverless function.

## API Reference

### Emails

```ts
// Single send — every accepted option is serialized onto the wire.
const message = await client.emails.send({
  from: { email: "hello@example.com", name: "Hello" }, // or "Hello <hello@example.com>"
  to: ["user@example.com"],
  subject: "Welcome!",
  html: "<h1>Hello!</h1>",
  text: "Hello!",                 // optional
  cc: ["cc@example.com"],         // optional
  bcc: ["bcc@example.com"],       // optional
  replyTo: "reply@example.com",   // optional
  tags: ["welcome"],              // optional (plain strings on the wire)
  scheduledAt: "2026-01-15T09:00:00Z", // optional (Date objects are ISO-encoded)
  priority: "high",               // integer 1-10 or "high" | "normal" | "low"
});

// Template send: templateId names a stored template supplying
// subject/html/text, rendered with templateData. A template-only send may
// omit subject/html/text.
await client.emails.send({
  from: "hello@example.com",
  to: "user@example.com",
  templateId: "tpl_welcome000000000001",
  templateData: { firstName: "Ada" },
});

// Batch send (up to 100)
const results = await client.emails.sendBatch([
  { from: "hello@example.com", to: "user1@example.com", subject: "Hi", html: "<h1>Hi</h1>" },
  { from: "hello@example.com", to: "user2@example.com", templateId: "tpl_welcome000000000001", templateData: { firstName: "Bob" } },
]);

// Read paths
const email = await client.emails.get("msg_x9y8z7w6");
const page = await client.emails.list({ limit: 25, status: "sent" });
// page.cursor / page.has_more mirror the envelope's meta.nextCursor / meta.hasMore
await client.emails.cancel("msg_x9y8z7w6");
```

### Domains

```ts
const domain = await client.domains.create("example.com");
await client.domains.verify(domain.id);
const { domains } = await client.domains.list({ limit: 25, offset: 0 });
await client.domains.delete(domain.id);
```

### Templates

```ts
const template = await client.templates.create({
  name: "welcome-email",
  subject: "Welcome, {{name}}!",
  htmlBody: "<h1>Hello, {{name}}</h1>",
});
const rendered = await client.templates.render(template.id, { name: "Jane" });
await client.templates.duplicate(template.id);
await client.templates.rollback(template.id, template.version - 1);
```

### Suppressions

```ts
await client.suppressions.add({ email: "bounced@example.com", reason: "bounce" });
const check = await client.suppressions.check("bounced@example.com");
const rows = await client.suppressions.list({ reason: "bounce" });
const summary = await client.suppressions.bulk([{ email: "a@example.com", reason: "manual" }]);
```

### Events

```ts
const events = await client.events.list({ eventType: "delivered", limit: 50 });
const forMessage = await client.events.getByMessage("msg_x9y8z7w6");
const stats = await client.events.stats({ from: "2026-08-01", to: "2026-08-31" });
const series = await client.events.timeseries({ from: "2026-08-01" });
```

### Webhooks

```ts
const webhook = await client.webhooks.create({
  url: "https://yourapp.com/webhooks/apexmail",
  events: ["message.delivered", "message.bounced", "message.complained"],
});
console.log(webhook.secret); // present only at creation (whsec_...)

const rotated = await client.webhooks.rotateSecret(webhook.id);
await client.webhooks.test(webhook.id);
await client.webhooks.update(webhook.id, { enabled: false }); // -> status "paused"
```

### Analytics

```ts
const dashboard = await client.analytics.dashboard({ from: "2026-02-01", to: "2026-02-09" });
const volume = await client.analytics.volume({ interval: "day" });
const engagement = await client.analytics.engagement();
const deliverability = await client.analytics.deliverability();
const analysis = await client.analytics.analyzeSubjectLine("Open me");
```

### API keys

```ts
const key = await client.apiKeys.create({ name: "Production Backend", scopes: ["messages:write"] });
const keys = await client.apiKeys.list();
await client.apiKeys.revoke("key_ghi789");
```

## Webhook signature verification

The platform signs every delivery with HMAC-SHA256 over the exact string
`"{timestamp}.{payload}"` (timestamp = milliseconds since epoch, used
verbatim) and sends:

```text
X-ApexMail-Signature: sha256=<hex hmac>
X-ApexMail-Timestamp: <milliseconds since epoch>
```

Verify against the **raw** request body before parsing it:

```ts
import { verifySignature } from "@apexmail/node";

const ok = verifySignature(rawBody, req.headers["x-apexmail-signature"], secret, {
  timestampHeader: req.headers["x-apexmail-timestamp"],
  toleranceSeconds: 300, // default; 0 disables the staleness check
});
```

The comparison is constant-time; stale, tampered, or unsigned payloads are
rejected. The legacy `t=<seconds>,v1=<hex>` header form is still accepted.

## Error handling

Every failure raises a typed error extending `ApexMailError`, carrying
`code`, `statusCode` and the server's `requestId`:

```ts
import { ApexMailError, RateLimitError, ValidationError } from "@apexmail/node";

try {
  await client.emails.send({ ... });
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter}s`);
  } else if (error instanceof ValidationError) {
    console.log(`Invalid request: ${error.code} — ${error.message}`, error.errors);
  } else if (error instanceof ApexMailError) {
    console.log(`API error: ${error.code} — ${error.message}`);
  }
}
```

| Error class | HTTP status | Description |
|-------------|-------------|-------------|
| `ApexMailError` | — | Base class for all SDK errors. |
| `ValidationError` | `400`, `422` | Request validation failed; `errors` carries field details. |
| `AuthenticationError` | `401` | Invalid, expired or missing API key. |
| `ForbiddenError` | `403` | The key lacks permission. |
| `NotFoundError` | `404` | The resource does not exist. |
| `ConflictError` | `409` | Conflicting resource state. |
| `RateLimitError` | `429` | Rate limited; `retryAfter` in seconds. |
| `ServerError` | `5xx` | Server-side failure. |

## Pagination

Only `emails.list()` supports cursor pagination: the response envelope's
`meta.nextCursor`/`meta.hasMore` are surfaced as `cursor`/`has_more`, and
the other list endpoints refuse a `cursor` client-side (their server query
structs reject it with a plain-text 400). Use `limit`/`offset` there.

## Development

```bash
npm ci
npm test        # builds dist/ (ESM + CJS) and runs the node:test suite
npm run typecheck
```

The suite drives the real client against a local `node:http` stub server —
no external network. CI runs the same `npm ci && npm test` in the
`sdk-typescript` lane (`ci/stages/test.sh`, gated by `CI_SDK_CHECK`).

## Requirements

Node.js ≥ 20. No runtime dependencies.
