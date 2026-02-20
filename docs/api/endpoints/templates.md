# Templates API Endpoints

> **Base path:** `/v1/templates`
> **Required scopes:** `templates:read` (GET), `templates:write` (POST / PATCH / DELETE)
> **Rate limit:** 120 requests/minute per API key

Templates are versioned, immutable-on-send email documents that support multiple rendering engines. Every mutation creates a new version internally; the active version is served by default.

---

## Authentication

Include your API key in the `Authorization` header:

```
Authorization: Bearer ak_live_...
```

---

## Supported Template Engines

| Engine | Description |
|--------|-------------|
| `handlebars` | Handlebars-based syntax with helpers (`{{#if}}`, `{{#each}}`, `{{formatDate}}`) — **default** |
| `liquid` | Shopify Liquid-compatible engine |
| `mjml` | MJML markup compiled to responsive HTML |
| `ejs` | EJS (Embedded JavaScript) `<%= variable %>` style |
| `react` | **React Email** — compose emails as JSX using `@react-email/components`, transpiled server-side |
| `plain` | No processing; HTML and text are used verbatim |

---

## Common Error Codes

| HTTP Status | Code | Description |
|------------|------|-------------|
| 400 | `VALIDATION_ERROR` | Request body fails schema validation |
| 400 | `SLUG_EXISTS` | A template with the same `slug` already exists in this organization |
| 400 | `RENDER_FAILED` | Template rendering failed — usually a syntax error in the template body |
| 401 | `UNAUTHORIZED` | API key is missing or invalid |
| 403 | `INSUFFICIENT_SCOPE` | API key does not have the required `templates:*` scope |
| 404 | `NOT_FOUND` | Template ID does not exist or belongs to another organization |
| 409 | `VERSION_CONFLICT` | Concurrent update detected; retry with the latest version |
| 429 | `RATE_LIMITED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Server-side error |

---

## Endpoints

### POST `/v1/templates`

Create a new template.

**Scope:** `templates:write`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name (max 255 chars) |
| `slug` | string | Yes | URL-safe unique identifier (`[a-z0-9-]`, max 128 chars) |
| `description` | string | No | Internal description |
| `category` | string | No | Grouping category (e.g. `transactional`, `marketing`, `onboarding`) |
| `subject` | string | Yes | Email subject line; supports template variables |
| `html` | string | Yes | HTML body of the email |
| `text` | string | No | Plain-text fallback body |
| `preheader` | string | No | Preview text shown in inbox |
| `engine` | string | No | Rendering engine (default: `handlebars`) |
| `defaultData` | object | No | Default merge variables used when rendering |
| `metadata` | object | No | Arbitrary key-value metadata (max 50 keys, 500 chars per value) |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Order Confirmation",
    "slug": "order-confirmation",
    "description": "Sent after a successful purchase",
    "category": "transactional",
    "subject": "Your order #{{order_id}} is confirmed",
    "html": "<h1>Thanks, {{first_name}}!</h1><p>Order #{{order_id}} has been placed.</p>",
    "text": "Thanks, {{first_name}}! Order #{{order_id}} has been placed.",
    "preheader": "Your order is on its way",
    "engine": "handlebars",
    "defaultData": {
      "first_name": "Customer",
      "order_id": "000000"
    },
    "metadata": {
      "team": "ecommerce",
      "priority": "high"
    }
  }'
```

#### Example Response — `201 Created`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "name": "Order Confirmation",
    "slug": "order-confirmation",
    "description": "Sent after a successful purchase",
    "category": "transactional",
    "subject": "Your order #{{order_id}} is confirmed",
    "engine": "handlebars",
    "active": true,
    "version": 1,
    "defaultData": {
      "first_name": "Customer",
      "order_id": "000000"
    },
    "metadata": {
      "team": "ecommerce",
      "priority": "high"
    },
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-15T10:30:00Z"
  }
}
```

---

### GET `/v1/templates/:id`

Retrieve a single template by ID.

**Scope:** `templates:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID (`tpl_...`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "name": "Order Confirmation",
    "slug": "order-confirmation",
    "description": "Sent after a successful purchase",
    "category": "transactional",
    "subject": "Your order #{{order_id}} is confirmed",
    "html": "<h1>Thanks, {{first_name}}!</h1><p>Order #{{order_id}} has been placed.</p>",
    "text": "Thanks, {{first_name}}! Order #{{order_id}} has been placed.",
    "preheader": "Your order is on its way",
    "engine": "handlebars",
    "active": true,
    "version": 3,
    "defaultData": {
      "first_name": "Customer",
      "order_id": "000000"
    },
    "metadata": {
      "team": "ecommerce",
      "priority": "high"
    },
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-20T14:15:00Z"
  }
}
```

---

### GET `/v1/templates/:id/versions`

Retrieve the version history of a template, ordered newest-first.

**Scope:** `templates:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Example Request

```bash
curl -X GET "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/versions" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": [
    {
      "version": 3,
      "active": true,
      "subject": "Your order #{{order_id}} is confirmed",
      "engine": "handlebars",
      "created_at": "2026-01-20T14:15:00Z",
      "created_by": "usr_5e6f7a8b",
      "change_summary": "Updated CTA button color"
    },
    {
      "version": 2,
      "active": false,
      "subject": "Your order #{{order_id}} is confirmed",
      "engine": "handlebars",
      "created_at": "2026-01-18T09:00:00Z",
      "created_by": "usr_5e6f7a8b",
      "change_summary": "Added preheader text"
    },
    {
      "version": 1,
      "active": false,
      "subject": "Your order #{{order_id}} is confirmed",
      "engine": "handlebars",
      "created_at": "2026-01-15T10:30:00Z",
      "created_by": "usr_5e6f7a8b",
      "change_summary": "Initial version"
    }
  ],
  "pagination": {
    "total": 3,
    "page": 1,
    "per_page": 25
  }
}
```

---

### GET `/v1/templates`

List templates with filtering, searching, and sorting.

**Scope:** `templates:read`

#### Query Parameters

| Parameter  | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `category` | string | No | Filter by category |
| `active`   | boolean | No | Filter by active status (default: all) |
| `engine`   | string | No | Filter by rendering engine |
| `search`   | string | No | Full-text search across `name`, `slug`, `description` |
| `sort`     | string | No | Sort field: `name`, `created_at`, `updated_at` (default: `updated_at`); prefix with `-` for descending |
| `page`     | number | No | Page number (default: `1`) |
| `per_page`  | number | No | Results per page, max 100 (default: `25`) |

#### Example Request

```bash
curl -X GET "https://api.apexmail.dev/v1/templates?category=transactional&active=true&sort=-updated_at" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": [
    {
      "id": "tpl_a1b2c3d4",
      "name": "Order Confirmation",
      "slug": "order-confirmation",
      "category": "transactional",
      "engine": "handlebars",
      "active": true,
      "version": 3,
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-01-20T14:15:00Z"
    },
    {
      "id": "tpl_e5f6g7h8",
      "name": "Password Reset",
      "slug": "password-reset",
      "category": "transactional",
      "engine": "handlebars",
      "active": true,
      "version": 2,
      "created_at": "2026-01-10T08:00:00Z",
      "updated_at": "2026-01-12T11:45:00Z"
    }
  ],
  "pagination": {
    "total": 2,
    "page": 1,
    "per_page": 25
  }
}
```

---

### PATCH `/v1/templates/:id`

Partially update a template. Only the supplied fields are changed; a new version is created automatically.

**Scope:** `templates:write`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Request Body

All fields from `POST /v1/templates` are accepted, plus:

| Field | Type | Description |
|-------|------|-------------|
| `active` | boolean | Set `false` to deactivate the template |

#### Example Request

```bash
curl -X PATCH "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Order #{{order_id}} — Confirmed ✓",
    "preheader": "We have received your order"
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "name": "Order Confirmation",
    "slug": "order-confirmation",
    "subject": "Order #{{order_id}} — Confirmed ✓",
    "preheader": "We have received your order",
    "engine": "handlebars",
    "active": true,
    "version": 4,
    "updated_at": "2026-01-22T16:00:00Z"
  }
}
```

---

### POST `/v1/templates/:id/duplicate`

Create a copy of a template with a new slug.

**Scope:** `templates:write`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Source template ID |

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Name for the duplicate (default: `"Copy of {original}"`) |
| `slug` | string | Yes | Unique slug for the duplicate |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/duplicate" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Order Confirmation (V2 Test)",
    "slug": "order-confirmation-v2-test"
  }'
```

#### Example Response — `201 Created`

```json
{
  "data": {
    "id": "tpl_z9y8x7w6",
    "name": "Order Confirmation (V2 Test)",
    "slug": "order-confirmation-v2-test",
    "category": "transactional",
    "engine": "handlebars",
    "active": true,
    "version": 1,
    "source_template_id": "tpl_a1b2c3d4",
    "created_at": "2026-01-23T09:00:00Z",
    "updated_at": "2026-01-23T09:00:00Z"
  }
}
```

---

### GET `/v1/templates/:id/preview`

Returns the rendered HTML preview of a template using its `defaultData`.

**Scope:** `templates:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Example Request

```bash
curl -X GET "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/preview" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "subject": "Your order #000000 is confirmed",
    "html": "<h1>Thanks, Customer!</h1><p>Order #000000 has been placed.</p>",
    "text": "Thanks, Customer! Order #000000 has been placed.",
    "preheader": "Your order is on its way",
    "engine": "handlebars",
    "rendered_with": "defaultData"
  }
}
```

---

### GET `/v1/templates/:id/stats`

Returns usage statistics for a template: send counts, performance metrics, and last-sent timestamp.

**Scope:** `templates:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Example Request

```bash
curl -X GET "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/stats" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "template_id": "tpl_a1b2c3d4",
    "total_sends": 128450,
    "total_delivered": 126300,
    "rates": {
      "delivery_rate": 0.9833,
      "open_rate": 0.4120,
      "click_rate": 0.1385,
      "bounce_rate": 0.0167,
      "complaint_rate": 0.0002
    },
    "last_sent_at": "2026-01-22T18:45:00Z",
    "campaigns_using": 12,
    "active_version": 3
  }
}
```

---

### POST `/v1/templates/:id/activate`

Set the active version of a template. Only one version can be active at a time.

**Scope:** `templates:write`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | number | Yes | Version number to activate |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/activate" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{ "version": 2 }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "active_version": 2,
    "previous_version": 3,
    "activated_at": "2026-01-23T10:00:00Z"
  }
}
```

---

### POST `/v1/templates/:id/render`

Render a template with custom data and return the output without sending an email.

**Scope:** `templates:read`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data` | object | Yes | Merge variables to use for rendering |
| `version` | number | No | Specific version to render (default: active) |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/render" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "first_name": "Alice",
      "order_id": "ORD-98765"
    }
  }'
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "subject": "Your order #ORD-98765 is confirmed",
    "html": "<h1>Thanks, Alice!</h1><p>Order #ORD-98765 has been placed.</p>",
    "text": "Thanks, Alice! Order #ORD-98765 has been placed.",
    "preheader": "Your order is on its way",
    "engine": "handlebars",
    "version": 3
  }
}
```

#### Error Response — `400 RENDER_FAILED`

```json
{
  "error": {
    "code": "RENDER_FAILED",
    "message": "Template rendering failed: missing helper \"formatCurrency\" at line 42",
    "details": {
      "engine": "handlebars",
      "line": 42,
      "column": 15,
      "source": "{{formatCurrency total}}"
    }
  }
}
```

---

### POST `/v1/templates/:id/versions`

Explicitly create a new version of a template without changing the active version.

**Scope:** `templates:write`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Request Body

Same fields as `POST /v1/templates` (except `slug` — inherited from parent). Additionally:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `change_summary` | string | No | Description of what changed |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4/versions" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "html": "<h1>Thanks, {{first_name}}!</h1><p>Order #{{order_id}} confirmed. <a href=\"{{tracking_url}}\">Track it</a>.</p>",
    "change_summary": "Added order tracking link"
  }'
```

#### Example Response — `201 Created`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "version": 4,
    "active": false,
    "change_summary": "Added order tracking link",
    "created_at": "2026-01-24T11:30:00Z",
    "created_by": "usr_5e6f7a8b"
  }
}
```

---

### DELETE `/v1/templates/:id`

Soft-delete a template. The template is deactivated and hidden from list queries, but its data is retained for audit purposes. Templates actively in use by a scheduled campaign cannot be deleted.

**Scope:** `templates:write`

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template ID |

#### Example Request

```bash
curl -X DELETE "https://api.apexmail.dev/v1/templates/tpl_a1b2c3d4" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "data": {
    "id": "tpl_a1b2c3d4",
    "deleted": true,
    "deleted_at": "2026-01-25T08:00:00Z"
  }
}
```

#### Error Response — `409 Conflict`

```json
{
  "error": {
    "code": "TEMPLATE_IN_USE",
    "message": "Template is used by 2 scheduled campaigns and cannot be deleted",
    "details": {
      "campaign_ids": ["cmp_1a2b3c4d", "cmp_5e6f7g8h"]
    }
  }
}
```

---

### GET `/v1/templates/react-email/starter`

Returns a ready-to-use React Email JSX starter template string that can be used as the `html` field when creating a template with `engine: "react"`.

**Scope:** `templates:read`

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | No | Name for the root React component (default: `EmailTemplate`) |

#### Example Request

```bash
curl "https://api.apexmail.dev/v1/templates/react-email/starter?name=WelcomeEmail" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx"
```

#### Example Response — `200 OK`

```json
{
  "source": "import { Html, Head, Body, Container, Section, Text, Button, Link, Hr, Img, Preview } from '@react-email/components';\nimport * as React from 'react';\n\nexport default function WelcomeEmail(props) {\n  return (\n    <Html>\n      <Head />\n      <Preview>Your preview text here</Preview>\n      <Body style={{ fontFamily: 'sans-serif', backgroundColor: '#f6f6f6' }}>\n        <Container style={{ margin: '0 auto', padding: '20px' }}>\n          <Text>Hello!</Text>\n        </Container>\n      </Body>\n    </Html>\n  );\n}"
}
```

---

### POST `/v1/templates/react-email/validate`

Validates a React Email JSX source string for syntax correctness without saving it. Use this to lint a template before submission.

**Scope:** `templates:read`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | string | Yes | Raw JSX source string to validate |

#### Example Request

```bash
curl -X POST "https://api.apexmail.dev/v1/templates/react-email/validate" \
  -H "Authorization: Bearer ak_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{ "source": "import * as React from '\''react'\'';\nexport default function Email() { return <p>Hello</p>; }" }'
```

#### Example Response — `200 OK` (valid)

```json
{ "valid": true }
```

#### Example Response — `200 OK` (invalid)

```json
{
  "valid": false,
  "error": "SyntaxError: Unexpected token (3:12)"
}
```

**Error codes specific to React Email templates:**

| Code | Description |
|------|-------------|
| `INVALID_REACT_EMAIL_SOURCE` | JSX source failed syntax validation on template create/update |
| `REACT_EMAIL_TRANSPILE_ERROR` | esbuild could not transpile the JSX |
| `REACT_EMAIL_NO_DEFAULT_EXPORT` | Template JSX must have a default export returning a React element |
| `REACT_EMAIL_EXECUTION_ERROR` | Template threw an error during server-side render |
| `REACT_EMAIL_RENDER_ERROR` | `@react-email/render` failed to produce HTML output |

