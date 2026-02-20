# SDK Integration, Runtime Issues & Developer Experience Playbook

> **Audience:** ApexMail AI Assistant & Support Engineers
> **Scope:** Node.js SDK, Python SDK, Go SDK, Ruby SDK, PHP SDK, Java SDK, webhook signature verification, framework integration, TypeScript, ESM/CJS, edge runtime, scheduled sends, template rendering, error handling.
> **Last Updated:** 2026-02-16

---

## Reference: SDK Architecture

| SDK | Package | Source | Notes |
|-----|---------|--------|-------|
| Node.js | `@apexmail/node` | `packages/sdk-node/` | TypeScript, ESM + CJS; auto-retry |
| Python | `apexmail` | `packages/sdk-python/` | Sync (`ApexMail`) + Async (`AsyncApexMail`) |
| Go | `github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go` | `packages/sdk-go/` | Requires Go 1.21+; context-aware |
| Ruby | `apexmail` gem | `packages/sdk-ruby/` | Net::HTTP stdlib; no external deps |
| PHP | `apexmail/apexmail-php` (Composer) | `packages/sdk-php/` | cURL-based; requires PHP 8.0+ |
| Java | `ee.apexmail:apexmail-java` (Maven/Gradle) | `packages/sdk-java/` | JDK 17+; no Jackson/Gson dependency |

### Node.js SDK Features

| Feature | Method | Status |
|---------|--------|--------|
| Send email | `client.emails.send()` | ✅ |
| Send batch | `client.emails.sendBatch()` | ✅ |
| List domains | `client.domains.list()` | ✅ |
| Verify domain | `client.domains.verify()` | ✅ |
| Manage contacts | `client.contacts.*` | ✅ |
| Manage templates | `client.templates.*` | ✅ |
| Manage suppressions | `client.suppressions.*` | ✅ |
| Manage webhooks | `client.webhooks.*` | ✅ |
| Webhook verification | `client.webhooks.verify()` | ✅ |
| API keys | `client.apiKeys.*` | ✅ |

### Python SDK Features

| Feature | Sync Client | Async Client |
|---------|------------|-------------|
| Send email | `client.emails.send()` | `await client.emails.send()` |
| Full CRUD | ✅ All resources | ✅ All resources |
| Webhook verify | `apexmail.webhooks.verify()` | Same |

---

## Issue F166 — "'Headers is not defined' in Node.js SDK"

**Symptoms:** Error: `ReferenceError: Headers is not defined` when using the SDK.

**Root cause:** The SDK uses the `fetch` API which requires `Headers`, `Request`, `Response` globals. These are NOT available in Node.js < 18.

**Resolution:**
1. **Node.js 18+:** `fetch` and `Headers` are built-in globals. Ensure `node --version` returns 18.x or higher.
2. **Node.js 16-17:** Install a polyfill:
   ```bash
   npm install undici
   ```
   Then at the top of your entry file:
   ```javascript
   const { Headers, Request, Response, fetch } = require('undici');
   globalThis.Headers = Headers;
   globalThis.Request = Request;
   globalThis.Response = Response;
   globalThis.fetch = fetch;
   ```
3. **Node.js 14:** Upgrade to Node.js 18+ (LTS). Node.js 14 is EOL.
4. **Best practice:** Use Node.js 20 LTS or later.

---

## Issue F167 — "ESM vs CJS import issues"

**Symptoms:** Error: `require() of ES Module not supported` or `SyntaxError: Cannot use import statement outside a module`.

**Root cause:** Mismatch between the project's module system (CommonJS vs ESM) and how the SDK is imported.

**Resolution:**
1. **If using ESM (type: "module" in package.json):**
   ```javascript
   import { ApexMail } from '@apexmail/node';
   ```
2. **If using CJS (no type or type: "commonjs"):**
   ```javascript
   const { ApexMail } = require('@apexmail/node');
   ```
3. **If SDK is ESM-only and project is CJS:** Use dynamic import:
   ```javascript
   const { ApexMail } = await import('@apexmail/node');
   ```
4. **Check package.json of the SDK:**
   - Look for `"type": "module"` (ESM) or `"main"` (CJS) or `"exports"` (dual).
5. **TypeScript projects:** Ensure `tsconfig.json` has compatible `module` and `moduleResolution` settings:
   ```json
   {
     "compilerOptions": {
       "module": "nodenext",
       "moduleResolution": "nodenext"
     }
   }
   ```

---

## Issue F168 — "TypeScript type errors with SDK"

**Symptoms:** TypeScript reports type errors when using the SDK, even though the code works at runtime.

**Resolution:**
1. **Ensure the SDK version matches the TypeScript types:**
   ```bash
   npm list @apexmail/node
   ```
2. **Common type issues:**
   - `Property 'X' does not exist on type 'Y'`: SDK version is outdated. Update: `npm update @apexmail/node`.
   - `Type '...' is not assignable to type '...'`: TypeScript strictness. Check if the SDK provides `SendEmailRequest` or similar types.
3. **Import types explicitly:**
   ```typescript
   import { ApexMail, SendEmailRequest, SendEmailResponse } from '@apexmail/node';
   
   const request: SendEmailRequest = {
     from: 'sender@example.com',
     to: ['recipient@example.com'],
     subject: 'Hello',
     html: '<p>World</p>'
   };
   ```
4. **If types are missing:** Check if `@types/apexmail` exists, or if types are bundled with the SDK package.

---

## Issue F169 — "SDK timeout—request takes too long"

**Symptoms:** SDK call hangs or times out without a response.

**Resolution:**
1. **Default timeout:** The SDK has a default timeout of 30 seconds.
2. **Configure timeout:**
   ```javascript
   const client = new ApexMail({
     apiKey: 'key_...',
     timeout: 60000, // 60 seconds
   });
   ```
3. **Common causes of slow requests:**
   - Large batch sends (>1000 recipients in one call).
   - Network latency between customer's server and ApexMail API.
   - API server under load (check `https://status.apexmail.ee`).
4. **For slow batch sends:** Use async/queued sending instead of synchronous batch.
5. **Retry logic:** The SDK includes automatic retry with exponential backoff for 5xx errors and rate limits.

---

## Issue F170 — "SDK retry behavior—how does it handle failures?"

**Symptoms:** Customer wants to understand the SDK's built-in retry behavior.

**Resolution:**
1. **Automatic retry:**
   - **5xx errors:** Retried with exponential backoff (3 attempts by default).
   - **429 rate limit:** Retried after the `Retry-After` header duration.
   - **Network errors:** Retried (connection refused, timeout, DNS failure).
   - **4xx errors (except 429):** NOT retried (client errors).
2. **Configure retries:**
   ```javascript
   const client = new ApexMail({
     apiKey: 'key_...',
     maxRetries: 5,        // default: 3
     retryDelay: 1000,     // initial delay in ms (default: 500)
   });
   ```
3. **Disable retries:**
   ```javascript
   const client = new ApexMail({
     apiKey: 'key_...',
     maxRetries: 0,
   });
   ```

---

## Issue F171 — "Webhook signature verification fails"

**Symptoms:** Customer's webhook handler rejects all webhook payloads because signature verification fails.

**Root cause:** Incorrect signing secret, wrong payload parsing, or framework middleware modifying the request body.

**Resolution:**
1. **Node.js verification:**
   ```javascript
   import { ApexMail } from '@apexmail/node';
   
   const client = new ApexMail({ apiKey: 'key_...' });
   
   // Express.js — MUST use raw body
   app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
     const signature = req.headers['x-apexmail-signature'];
     const timestamp = req.headers['x-apexmail-timestamp'];
     const rawBody = req.body; // Must be raw Buffer, NOT parsed JSON
     
     const isValid = client.webhooks.verify({
       signature,
       timestamp,
       body: rawBody,
     });
     
     if (!isValid) {
       return res.status(401).send('Invalid signature');
     }
     
     const event = JSON.parse(rawBody);
     // Process event...
     res.status(200).send('OK');
   });
   ```
2. **CRITICAL: The body MUST be the raw, unparsed request body.** If Express's `json()` middleware parses it first, the signature won't match because `JSON.stringify(parsedBody)` may differ from the original raw body.
3. **Common mistakes:**
   - Using `express.json()` before the webhook route.
   - Using `JSON.stringify(req.body)` instead of the raw body.
   - Wrong signing secret (dashboard secret vs API key).
4. **Get the signing secret:** Dashboard → Webhooks → select webhook → Signing Secret. This is different from the API key.

---

## Issue F172 — "Webhook signature verification in Next.js App Router"

**Symptoms:** Signature verification fails in Next.js App Router because the body is consumed by the framework.

**Resolution:**
```typescript
// app/api/webhooks/apexmail/route.ts
import { ApexMail } from '@apexmail/node';

const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY! });

export async function POST(request: Request) {
  const rawBody = await request.text(); // Get raw body as string
  const signature = request.headers.get('x-apexmail-signature')!;
  const timestamp = request.headers.get('x-apexmail-timestamp')!;
  
  const isValid = client.webhooks.verify({
    signature,
    timestamp,
    body: rawBody,
  });
  
  if (!isValid) {
    return new Response('Invalid signature', { status: 401 });
  }
  
  const event = JSON.parse(rawBody);
  // Process event...
  
  return new Response('OK', { status: 200 });
}
```

**Key:** Use `request.text()` to get the raw body. Do NOT use `request.json()` before verification.

---

## Issue F173 — "Webhook signature verification in Next.js Pages Router"

**Symptoms:** Same as F172, but using Pages Router (API routes in `pages/api/`).

**Resolution:**
```typescript
// pages/api/webhooks/apexmail.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { ApexMail } from '@apexmail/node';

// Disable Next.js body parser to get raw body
export const config = {
  api: {
    bodyParser: false,
  },
};

const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY! });

async function getRawBody(req: NextApiRequest): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).end();
  
  const rawBody = await getRawBody(req);
  const signature = req.headers['x-apexmail-signature'] as string;
  const timestamp = req.headers['x-apexmail-timestamp'] as string;
  
  const isValid = client.webhooks.verify({ signature, timestamp, body: rawBody });
  
  if (!isValid) return res.status(401).send('Invalid signature');
  
  const event = JSON.parse(rawBody);
  // Process event...
  
  res.status(200).send('OK');
}
```

**Key:** Must disable Next.js body parser with `export const config = { api: { bodyParser: false } }`.

---

## Issue F174 — "Webhook signature verification in FastAPI (Python)"

**Symptoms:** Python webhook handler needs to verify ApexMail webhook signatures.

**Resolution:**
```python
from fastapi import FastAPI, Request, HTTPException
import apexmail

app = FastAPI()

WEBHOOK_SECRET = "whsec_..."

@app.post("/webhooks/apexmail")
async def handle_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("x-apexmail-signature")
    timestamp = request.headers.get("x-apexmail-timestamp")
    
    if not apexmail.webhooks.verify(
        signature=signature,
        timestamp=timestamp,
        body=raw_body,
        secret=WEBHOOK_SECRET,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    import json
    event = json.loads(raw_body)
    # Process event...
    
    return {"status": "ok"}
```

---

## Issue F175 — "Webhook signature verification in Flask (Python)"

**Symptoms:** Python Flask webhook handler needs signature verification.

**Resolution:**
```python
from flask import Flask, request, abort
import apexmail

app = Flask(__name__)

WEBHOOK_SECRET = "whsec_..."

@app.route("/webhooks/apexmail", methods=["POST"])
def handle_webhook():
    raw_body = request.get_data()
    signature = request.headers.get("X-ApexMail-Signature")
    timestamp = request.headers.get("X-ApexMail-Timestamp")
    
    if not apexmail.webhooks.verify(
        signature=signature,
        timestamp=timestamp,
        body=raw_body,
        secret=WEBHOOK_SECRET,
    ):
        abort(401)
    
    event = request.get_json(force=True)
    # Process event...
    
    return "OK", 200
```

**Key:** Use `request.get_data()` for raw body, NOT `request.json`.

---

## Issue F176 — "Webhook signature verification in Django"

**Symptoms:** Django webhook handler needs signature verification.

**Resolution:**
```python
# views.py
from django.http import HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
import apexmail
import json

WEBHOOK_SECRET = "whsec_..."

@csrf_exempt
def apexmail_webhook(request):
    if request.method != "POST":
        return HttpResponse(status=405)
    
    raw_body = request.body
    signature = request.META.get("HTTP_X_APEXMAIL_SIGNATURE")
    timestamp = request.META.get("HTTP_X_APEXMAIL_TIMESTAMP")
    
    if not apexmail.webhooks.verify(
        signature=signature,
        timestamp=timestamp,
        body=raw_body,
        secret=WEBHOOK_SECRET,
    ):
        return HttpResponseForbidden("Invalid signature")
    
    event = json.loads(raw_body)
    # Process event...
    
    return HttpResponse("OK")
```

**Key:** Must use `@csrf_exempt` decorator. Use `request.body` for raw body. Headers are prefixed with `HTTP_` and uppercased in Django.

---

## Issue F177 — "SDK in Cloudflare Workers / Vercel Edge"

**Symptoms:** SDK fails in edge runtime with errors about Node.js APIs (`Buffer`, `crypto`, `net`).

**Root cause:** Edge runtimes (Cloudflare Workers, Vercel Edge Functions) don't have full Node.js APIs.

**Resolution:**
1. **Check SDK edge compatibility:** The `@apexmail/node` SDK uses `fetch` (available in edge) but may use Node.js-specific APIs for signing.
2. **If SDK doesn't work in edge:**
   ```typescript
   // Use the raw API instead of the SDK
   export default {
     async fetch(request: Request): Promise<Response> {
       const response = await fetch('https://api.apexmail.ee/v1/emails', {
         method: 'POST',
         headers: {
           'Authorization': `Bearer ${API_KEY}`,
           'Content-Type': 'application/json',
         },
         body: JSON.stringify({
           from: 'sender@example.com',
           to: ['recipient@example.com'],
           subject: 'Hello from Edge',
           html: '<p>Sent from Cloudflare Workers</p>',
         }),
       });
       
       return new Response('OK', { status: 200 });
     },
   };
   ```
3. **For webhook verification in edge:** Use Web Crypto API instead of Node.js `crypto`:
   ```typescript
   async function verifySignature(body: string, signature: string, secret: string): Promise<boolean> {
     const encoder = new TextEncoder();
     const key = await crypto.subtle.importKey(
       'raw',
       encoder.encode(secret),
       { name: 'HMAC', hash: 'SHA-256' },
       false,
       ['sign']
     );
     const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
     const computed = btoa(String.fromCharCode(...new Uint8Array(sig)));
     return computed === signature;
   }
   ```

---

## Issue F178 — "SDK in AWS Lambda — cold start timeout"

**Symptoms:** First SDK call in Lambda times out. Subsequent calls work fine.

**Root cause:** Lambda cold start + SDK initialization + DNS resolution can exceed the default timeout.

**Resolution:**
1. **Increase Lambda timeout:** Set to at least 15 seconds (default is 3 seconds).
2. **Initialize client outside handler:**
   ```javascript
   const { ApexMail } = require('@apexmail/node');
   
   // Initialize outside handler — persists across invocations
   const client = new ApexMail({ apiKey: process.env.APEXMAIL_API_KEY });
   
   exports.handler = async (event) => {
     // Client is already initialized (warm)
     await client.emails.send({ ... });
   };
   ```
3. **Reduce cold start:** Use Node.js 20 runtime, minimize dependencies, use `aws-sdk` v3 (modular).
4. **Keep warm:** Use provisioned concurrency or a CloudWatch event to ping the Lambda every 5 minutes.

---

## Issue F179 — "Python async client — event loop issues"

**Symptoms:** `RuntimeError: This event loop is already running` when using the async Python client.

**Root cause:** Trying to use `asyncio.run()` inside an already-running event loop (e.g., Jupyter, FastAPI).

**Resolution:**
1. **In FastAPI/Starlette:** Don't use `asyncio.run()`. The framework manages the event loop:
   ```python
   import apexmail
   
   client = apexmail.AsyncApexMail(api_key="key_...")
   
   @app.post("/send")
   async def send_email():
       result = await client.emails.send(
           from_email="sender@example.com",
           to=["recipient@example.com"],
           subject="Hello",
           html="<p>World</p>",
       )
       return {"id": result.id}
   ```
2. **In Jupyter notebooks:** Use `await` directly (Jupyter has its own event loop):
   ```python
   result = await client.emails.send(...)
   ```
3. **In sync context that needs async:** Use the sync client instead:
   ```python
   client = apexmail.ApexMail(api_key="key_...")  # Sync client
   result = client.emails.send(...)
   ```

---

## Issue F180 — "Python SDK — SSL certificate verification error"

**Symptoms:** `ssl.SSLCertVerificationError` when calling the API from Python.

**Resolution:**
1. **Common causes:**
   - Corporate proxy intercepting HTTPS (MITM with custom CA).
   - Outdated `certifi` package.
   - System CA certificates not found.
2. **Fix outdated certifi:**
   ```bash
   pip install --upgrade certifi
   ```
3. **Corporate proxy:** Add the corporate CA cert:
   ```python
   import os
   os.environ['REQUESTS_CA_BUNDLE'] = '/path/to/corporate-ca-bundle.crt'
   ```
4. **Temporary workaround (NOT for production):**
   ```python
   client = apexmail.ApexMail(api_key="key_...", verify_ssl=False)
   ```
5. **macOS specific:** Run `Install Certificates.command` from the Python installation.

---

## Issue F181 — "Scheduled sends — how to send at a specific time"

**Symptoms:** Customer wants to schedule an email to be sent at a future time.

**Resolution:**
1. **Via API:**
   ```json
   {
     "from": "sender@example.com",
     "to": ["recipient@example.com"],
     "subject": "Scheduled Newsletter",
     "html": "<p>This was scheduled</p>",
     "scheduled_at": "2026-02-20T14:00:00Z"
   }
   ```
2. **Via Node.js SDK:**
   ```javascript
   await client.emails.send({
     from: 'sender@example.com',
     to: ['recipient@example.com'],
     subject: 'Scheduled',
     html: '<p>Hello</p>',
     scheduledAt: new Date('2026-02-20T14:00:00Z'),
   });
   ```
3. **Constraints:**
   - Maximum schedule ahead: 72 hours.
   - Minimum schedule ahead: 1 minute.
   - Timezone: always UTC. Customer must convert their timezone.
4. **Cancel scheduled:** Delete the message before the scheduled time:
   ```bash
   curl -X DELETE -H "Authorization: Bearer <KEY>" \
     "https://api.apexmail.ee/v1/messages/<MSG_ID>"
   ```

---

## Issue F182 — "Template rendering — variables not replaced in SDK"

**Symptoms:** Using a template via SDK, but merge variables aren't being applied.

**Resolution:**
1. **Correct SDK usage:**
   ```javascript
   await client.emails.send({
     from: 'sender@example.com',
     to: ['recipient@example.com'],
     templateId: 'tmpl_abc123',
     mergeVariables: {
       first_name: 'John',
       company: 'Acme Corp',
     },
   });
   ```
2. **Common mistakes:**
   - Using `html` AND `templateId` together — `html` takes precedence.
   - Variable name case mismatch: template uses `{{firstName}}` but SDK sends `first_name`.
   - Nested objects: `mergeVariables: { user: { name: 'John' } }` — template needs `{{user.name}}`.
3. **Test template rendering:**
   ```javascript
   const preview = await client.templates.render('tmpl_abc123', {
     first_name: 'Test',
   });
   console.log(preview.html);
   ```

---

## Issue F183 — "Bulk/batch sending — best practices"

**Symptoms:** Customer needs to send to thousands of recipients efficiently.

**Resolution:**
1. **Batch send API:**
   ```javascript
   await client.emails.sendBatch({
     from: 'sender@example.com',
     subject: 'Newsletter',
     templateId: 'tmpl_abc',
     recipients: [
       { to: 'a@example.com', mergeVariables: { name: 'Alice' } },
       { to: 'b@example.com', mergeVariables: { name: 'Bob' } },
       // ... up to 1,000 recipients per batch call
     ],
   });
   ```
2. **Limits:**
   - Max 1,000 recipients per batch API call.
   - For larger lists: paginate and make multiple batch calls.
   - Respect rate limits (see Playbook B).
3. **Best practices:**
   - Use templates with merge variables (not inline HTML per recipient).
   - Include idempotency key per batch: `idempotencyKey: 'batch-2026-02-16-newsletter'`.
   - Use webhook events to track delivery status.
   - Implement backoff for 429 responses.
4. **For very large sends (>100K):** Use the campaign/list API instead of batch sends:
   ```javascript
   const campaign = await client.campaigns.create({
     listId: 'list_abc',
     templateId: 'tmpl_abc',
     subject: 'Newsletter',
     from: 'sender@example.com',
   });
   await client.campaigns.send(campaign.id);
   ```

---

## Issue F184 — "How to handle API errors in the SDK"

**Symptoms:** Customer needs proper error handling patterns.

**Resolution:**
1. **Node.js error handling:**
   ```javascript
   try {
     const result = await client.emails.send({ ... });
     console.log('Sent:', result.id);
   } catch (error) {
     if (error instanceof ApexMailError) {
       console.error('API Error:', error.statusCode, error.message);
       console.error('Error Code:', error.code);
       console.error('Request ID:', error.requestId);
       
       if (error.statusCode === 429) {
         console.log('Rate limited. Retry after:', error.retryAfter);
       }
       if (error.statusCode === 422) {
         console.log('Validation errors:', error.errors);
       }
     } else {
       console.error('Network error:', error.message);
     }
   }
   ```
2. **Python error handling:**
   ```python
   try:
       result = client.emails.send(...)
   except apexmail.RateLimitError as e:
       print(f"Rate limited. Retry after {e.retry_after}s")
   except apexmail.ValidationError as e:
       print(f"Validation failed: {e.errors}")
   except apexmail.ApiError as e:
       print(f"API error {e.status_code}: {e.message}")
   except Exception as e:
       print(f"Network error: {e}")
   ```

---

## Issue F185 — "Idempotency key — what format and how long?"

**Symptoms:** Customer wants to use idempotency to prevent duplicate sends.

**Resolution:**
1. **Idempotency key is a string (max 255 chars):**
   ```javascript
   await client.emails.send({
     from: 'sender@example.com',
     to: ['recipient@example.com'],
     subject: 'Order Confirmation',
     html: '...',
     idempotencyKey: 'order-confirm-12345',
   });
   ```
2. **Behavior:**
   - First call: processed normally. Key is stored in Redis with 24-hour TTL.
   - Second call with same key: returns the same response as the first call. No duplicate send.
   - After 24 hours: key expires. After that, the same key would be treated as a new request.
3. **Best practice for key format:**
   - Include the action + unique identifier: `send-invoice-INV-2026-001`.
   - Use UUIDs for programmatic generation: `send-abc123-550e8400-e29b-41d4-a716-446655440000`.
   - Do NOT use timestamps alone (two calls in the same second would conflict).

**Backend:** `apps/api/src/middleware/idempotency.ts` — idempotency middleware using Redis SETNX.

---

## Issue F186 — "Attachment sending via SDK"

**Symptoms:** Customer needs to send emails with attachments.

**Resolution:**
1. **Node.js:**
   ```javascript
   import fs from 'fs';
   
   await client.emails.send({
     from: 'sender@example.com',
     to: ['recipient@example.com'],
     subject: 'Invoice',
     html: '<p>Please find attached.</p>',
     attachments: [
       {
         filename: 'invoice.pdf',
         content: fs.readFileSync('./invoice.pdf'),
         contentType: 'application/pdf',
       },
       {
         filename: 'logo.png',
         content: Buffer.from(base64String, 'base64'),
         contentType: 'image/png',
       },
     ],
   });
   ```
2. **Python:**
   ```python
   with open("invoice.pdf", "rb") as f:
       result = client.emails.send(
           from_email="sender@example.com",
           to=["recipient@example.com"],
           subject="Invoice",
           html="<p>Please find attached.</p>",
           attachments=[
               apexmail.Attachment(
                   filename="invoice.pdf",
                   content=f.read(),
                   content_type="application/pdf",
               ),
           ],
       )
   ```
3. **Limits:** See D113 for message size limits (10-50 MB plan-dependent). MIME base64 encoding adds ~33% overhead.

---

## Issue F187 — "Reply-To and custom headers"

**Symptoms:** Customer needs to set Reply-To or custom email headers.

**Resolution:**
```javascript
await client.emails.send({
  from: 'noreply@example.com',
  to: ['recipient@example.com'],
  replyTo: 'support@example.com',
  subject: 'Hello',
  html: '<p>Reply to support, not noreply</p>',
  headers: {
    'X-Custom-Header': 'custom-value',
    'X-Campaign-ID': 'campaign-123',
  },
});
```

**Restrictions:** Some headers cannot be overridden: `From`, `To`, `Date`, `Message-ID`, `DKIM-Signature`, `MIME-Version`.

---

## Issue F188 — "Tags and metadata for tracking"

**Symptoms:** Customer wants to tag emails for analytics grouping.

**Resolution:**
```javascript
await client.emails.send({
  from: 'sender@example.com',
  to: ['recipient@example.com'],
  subject: 'Welcome',
  html: '...',
  tags: ['onboarding', 'welcome-series'],
  metadata: {
    campaign_id: 'camp_123',
    user_segment: 'trial',
  },
});
```

- **Tags:** Used for grouping in analytics. Max 5 tags per message, alphanumeric + hyphens.
- **Metadata:** Key-value pairs included in webhook payloads. Max 10 pairs, 255 chars per value.

---

## Issue F189 — "CC and BCC support"

**Symptoms:** Customer needs to send with CC or BCC recipients.

**Resolution:**
```javascript
await client.emails.send({
  from: 'sender@example.com',
  to: ['recipient@example.com'],
  cc: ['cc@example.com'],
  bcc: ['bcc@example.com'],
  subject: 'Hello',
  html: '<p>World</p>',
});
```

- CC recipients see all other CC addresses.
- BCC recipients are hidden from To and CC recipients.
- Each recipient (To, CC, BCC) counts as a separate send for billing.

---

## Issue F190 — "Webhook event types — which events should I subscribe to?"

**Symptoms:** Customer setting up webhooks wants guidance on which event types to subscribe to.

**Resolution:**
| Event Type | When Fired | Use Case |
|-----------|-----------|----------|
| `message.accepted` | API accepted the message | Confirmation of receipt |
| `message.delivered` | Remote MTA accepted (250 OK) | Update CRM status |
| `message.bounced` | Hard bounce (5xx) | Remove from list |
| `message.deferred` | Soft bounce (4xx), will retry | Informational |
| `message.opened` | Tracking pixel loaded | Engagement analytics |
| `message.clicked` | Tracking link clicked | Engagement analytics |
| `message.unsubscribed` | One-click unsubscribe | Update preferences |
| `message.complained` | Spam complaint (FBL) | Immediate suppression |

**Recommendations:**
- **Transactional:** `delivered`, `bounced` (minimum viable).
- **Marketing:** All of the above.
- **Compliance-focused:** `bounced`, `unsubscribed`, `complained` (mandatory).

---

## Issue F191 — "SDK proxy configuration"

**Symptoms:** Customer behind a corporate proxy can't reach the ApexMail API.

**Resolution:**
1. **Node.js — via environment variable:**
   ```bash
   export HTTPS_PROXY=http://proxy.corp.com:8080
   ```
2. **Node.js — via SDK option:**
   ```javascript
   import { HttpsProxyAgent } from 'https-proxy-agent';
   
   const client = new ApexMail({
     apiKey: 'key_...',
     httpAgent: new HttpsProxyAgent('http://proxy.corp.com:8080'),
   });
   ```
3. **Python:**
   ```python
   client = apexmail.ApexMail(
       api_key="key_...",
       proxies={"https": "http://proxy.corp.com:8080"},
   )
   ```

---

## Issue F192 — "Custom API base URL (self-hosted or staging)"

**Symptoms:** Customer has a self-hosted instance or wants to test against staging.

**Resolution:**
```javascript
const client = new ApexMail({
  apiKey: 'key_...',
  baseUrl: 'https://api-staging.apexmail.ee',
});
```

```python
client = apexmail.ApexMail(
    api_key="key_...",
    base_url="https://api-staging.apexmail.ee",
)
```

---

## Issues F193-F200 — Additional SDK/Runtime Scenarios

### F193 — "How to test SDK integration without sending real emails"

Use the sandbox mode:
```javascript
const client = new ApexMail({
  apiKey: 'key_test_...', // Test API key
});
```
Test API keys accept all send requests but don't actually deliver email. Events are simulated for testing webhook handlers.

### F194 — "SDK versioning — which version should I use?"

Always use the latest stable version: `npm install @apexmail/node@latest` / `pip install --upgrade apexmail`. Check changelog at `https://docs.apexmail.ee/changelog`. Breaking changes are only in major versions (semver).

### F195 — "Rate limit headers — how to read them"

Response headers include:
- `X-RateLimit-Limit`: max requests per window.
- `X-RateLimit-Remaining`: remaining requests.
- `X-RateLimit-Reset`: Unix timestamp when the window resets.
- `Retry-After`: seconds to wait (on 429 responses).

### F196 — "Content-Type errors — 'Unsupported Media Type'"

Ensure requests include `Content-Type: application/json`. The SDK does this automatically. If using raw `fetch`: explicitly set the header.

### F197 — "Pagination — how to iterate all results"

```javascript
let cursor = undefined;
const allDomains = [];
do {
  const page = await client.domains.list({ cursor, limit: 50 });
  allDomains.push(...page.data);
  cursor = page.pagination.nextCursor;
} while (cursor);
```

### F198 — "Webhook timeout — how quickly must I respond?"

ApexMail expects webhook endpoints to respond within **30 seconds**. If your handler takes longer, return `200 OK` immediately and process the event asynchronously (e.g., push to your own queue).

### F199 — "Multiple webhook endpoints — fan-out"

You can create multiple webhook subscriptions, each with different URLs and event type filters. All matching endpoints receive the event independently.

### F200 — "SDK debug/verbose logging"

```javascript
const client = new ApexMail({
  apiKey: 'key_...',
  debug: true, // Logs all HTTP requests and responses
});
```

```python
import logging
logging.basicConfig(level=logging.DEBUG)
client = apexmail.ApexMail(api_key="key_...", debug=True)
```

---

## Troubleshooting Decision Tree

```
SDK / Runtime Issue
├── Node.js
│   ├── "Headers is not defined" → F166
│   ├── ESM/CJS import error → F167
│   ├── TypeScript types → F168
│   ├── Timeout → F169
│   └── Lambda cold start → F178
├── Python
│   ├── Async event loop error → F179
│   ├── SSL cert error → F180
│   └── Proxy → F191
├── Go
│   ├── Installation → see sdk-go-ruby-php-java.md
│   ├── Error handling (*apexmail.APIError) → see sdk-go-ruby-php-java.md
│   └── Context timeout → see sdk-go-ruby-php-java.md
├── Ruby
│   ├── Installation → see sdk-go-ruby-php-java.md
│   └── Error handling (ApexMail::Error) → see sdk-go-ruby-php-java.md
├── PHP
│   ├── Installation (Composer) → see sdk-go-ruby-php-java.md
│   └── Exception handling → see sdk-go-ruby-php-java.md
├── Java
│   ├── Installation (Maven/Gradle) → see sdk-go-ruby-php-java.md
│   └── Exception handling (ApexMailException) → see sdk-go-ruby-php-java.md
├── Webhook Verification
│   ├── General → F171
│   ├── Next.js App Router → F172
│   ├── Next.js Pages Router → F173
│   ├── FastAPI → F174
│   ├── Flask → F175
│   └── Django → F176
├── Edge / Serverless
│   ├── Cloudflare Workers → F177
│   ├── Vercel Edge → F177
│   └── AWS Lambda → F178
├── Sending
│   ├── Template variables → F182
│   ├── Batch/bulk → F183
│   ├── Scheduled sends → F181
│   ├── Attachments → F186
│   ├── Reply-To/headers → F187
│   ├── Tags/metadata → F188
│   └── CC/BCC → F189
├── API Usage
│   ├── Error handling → F184
│   ├── Idempotency → F185
│   ├── Retry behavior → F170
│   ├── Rate limit headers → F195
│   ├── Pagination → F197
│   └── Debug logging → F200
└── Configuration
    ├── Proxy → F191
    ├── Custom base URL → F192
    ├── Sandbox/testing → F193
    ├── Versioning → F194
    └── Webhook events → F190
```

---

## Related

- [D) API Auth Troubleshooting](d-api-auth-troubleshooting.md) — API authentication issues
- [E) Webhooks & Events](e-webhooks-events-troubleshooting.md) — webhook troubleshooting
- [API Errors](api-errors.md) — HTTP error code diagnosis
- [Webhook Failures](webhook-failures.md) — webhook delivery failures
- [Quota & Rate Limits](quota-rate-limits-billing.md) — rate limiting details
- Internal: `packages/sdk-node/` — Node.js SDK source
- Internal: `packages/sdk-python/` — Python SDK source
- Internal: `packages/sdk-go/` — Go SDK source
- Internal: `packages/sdk-ruby/` — Ruby SDK source
- Internal: `packages/sdk-php/` — PHP SDK source
- Internal: `packages/sdk-java/` — Java SDK source
- [Go / Ruby / PHP / Java SDK Playbook](sdk-go-ruby-php-java.md) — issues specific to these SDKs
