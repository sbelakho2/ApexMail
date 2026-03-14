# Control Plane API Data Contracts

> Phase 6.1 — Documents all data contracts used by Control Plane API routes.
>
> **Status:** All 54 routes proxy to Rust unchanged. Data contracts are preserved by the transparent proxy.

---

## Contract Preservation Strategy

The `proxyToRust()` function in `src/lib/rust-api.ts` is a **transparent proxy** — it does not transform, filter, or enrich any data flowing between the Next.js frontend and the Rust backend. This means:

- **Request contracts** (query params, JSON bodies, headers) are forwarded verbatim.
- **Response contracts** (status codes, JSON bodies, Content-Type, Set-Cookie) are returned verbatim.
- **Error contracts** (HTTP status codes, JSON error bodies) are preserved.
- **Pagination contracts** (query params for page/limit/offset, response shape) are unchanged.

The only additions are:
- `x-api-key` header added by `proxyToRust()` for Rust-side authentication.
- `Content-Type: application/json` default header if not already set.

---

## Route-by-Route Data Contracts

### Authentication & Security

#### `POST /api/auth/login`
- **Request:** `{ email: string, password: string, captcha?: string }`
- **Response 200:** `{ token: string, user: { id, email, role }, expires: number }`
- **Response 401:** `{ error: "Invalid credentials" }`
- **Response 429:** `{ error: "Too many attempts", retryAfter: number }`
- **Cookies set:** `cp_session` (httpOnly, secure, sameSite: strict)

#### `POST /api/auth/logout`
- **Request:** Empty body
- **Response 200:** `{ success: true }`
- **Cookies cleared:** `cp_session`, `am_session`

#### `GET /api/auth/session`
- **Response 200:** `{ user: { id, email, role, name }, impersonating?: { tenantId, tenantName } }`
- **Response 401:** `{ error: "Not authenticated" }`

#### `GET /api/csrf`
- **Response 200:** `{ token: string }`
- **Cookies set:** `csrf_token`, `csrf_token_sig`

#### `POST /api/impersonate`
- **Request:** `{ tenantId: string }`
- **Response 200:** `{ success: true, tenant: { id, name } }`
- **Response 403:** `{ error: "Insufficient role" }` (requires admin+)

#### `DELETE /api/impersonate`
- **Response 200:** `{ success: true }`

### Tenant Management

#### `GET /api/tenants`
- **Query:** `?page=N&limit=N&search=STRING&status=active|suspended|deleted`
- **Response 200:** `{ tenants: Tenant[], total: number, page: number, limit: number }`

#### `PATCH /api/tenants`
- **Request:** `{ tenantId: string, ...updates }`
- **Response 200:** `{ tenant: Tenant }`

#### `DELETE /api/tenants`
- **Request:** `{ tenantId: string }`
- **Response 200:** `{ success: true }`

### Secrets Management

#### `GET /api/secrets`
- **Response 200:** `{ secrets: Secret[] }` (values redacted)

#### `POST /api/secrets`
- **Request:** `{ name: string, value: string, scope?: string }`
- **Response 201:** `{ secret: Secret }` (value redacted in response)

#### `PATCH /api/secrets`
- **Request:** `{ name: string, value?: string, scope?: string }`
- **Response 200:** `{ secret: Secret }`

#### `DELETE /api/secrets`
- **Request:** `{ name: string }`
- **Response 200:** `{ success: true }`

### Analytics & Dashboard

#### `GET /api/dashboard/stats`
- **Query:** `?period=7d|30d|90d`
- **Response 200:** `{ totalTenants, activeTenants, emailsSent, emailsDelivered, bounceRate, ... }`

#### `GET /api/analytics`
- **Query:** `?from=ISO&to=ISO&granularity=hour|day|week`
- **Response 200:** `{ data: TimeSeriesPoint[], summary: { ... } }`

#### `GET /api/analytics/platform`
- **Query:** `?from=ISO&to=ISO`
- **Response 200:** `{ platform: PlatformStats }`

#### `GET|POST /api/analytics/export`
- **GET Query:** `?format=csv|json&from=ISO&to=ISO`
- **POST Request:** `{ format, dateRange, metrics[] }`
- **Response 200:** Binary/JSON depending on format

### Audit & Compliance

#### `GET /api/audit`
- **Query:** `?page=N&limit=N&action=STRING&actor=STRING&from=ISO&to=ISO`
- **Response 200:** `{ entries: AuditEntry[], total, page, limit }`

#### `GET|POST /api/audit/alerts`
- **GET Response 200:** `{ alerts: AuditAlert[] }`
- **POST Request:** `{ type, threshold, recipients[] }`
- **Response 201:** `{ alert: AuditAlert }`

#### `GET|POST /api/audit/export`
- **GET Query:** `?status=pending|ready|expired`
- **Response 200:** `{ exports: AuditExport[] }`
- **POST Request:** `{ dateRange, filters }`
- **Response 201:** `{ export: { id, status: "pending" } }`

#### `GET /api/audit/export/[id]`
- **ID validation:** `SAFE_ID = /^[a-zA-Z0-9._:-]+$/`
- **Response 200:** Binary (export file download)
- **Response 404:** `{ error: "Export not found" }`

#### `GET /api/compliance/overview`
- **Response 200:** `{ frameworks: ComplianceFramework[], overallScore, gaps[] }`

#### `GET|POST /api/gdpr`
- **GET Response 200:** `{ requests: GDPRRequest[], stats }`
- **POST Request:** `{ type: "access"|"erasure"|"portability", subjectEmail }`
- **Response 201:** `{ request: GDPRRequest }`

### Campaign Management

#### `GET|POST /api/campaigns`
- **GET Query:** `?page=N&limit=N&status=draft|active|paused|completed`
- **Response 200:** `{ campaigns: Campaign[], total, page, limit }`
- **POST Request:** `{ name, subject, body, recipients, schedule? }`
- **Response 201:** `{ campaign: Campaign }`

#### `GET|PUT|DELETE /api/campaigns/[id]`
- **ID validation:** `SAFE_ID`
- **GET Response 200:** `{ campaign: Campaign }`
- **PUT Request:** `{ ...campaignUpdates }`
- **DELETE Response 200:** `{ success: true }`

### Content & Features

#### `GET|POST|PUT /api/content`
- **GET Query:** `?type=template|snippet|block`
- **Response 200:** `{ items: ContentItem[] }`
- **POST/PUT Request:** `{ type, name, body, metadata }`

#### `GET|POST|PUT /api/features`
- **GET Response 200:** `{ flags: FeatureFlag[] }`
- **POST Request:** `{ key, description, enabled, rules? }`
- **PUT Request:** `{ key, enabled?, rules? }`

### Sales & CRM

#### `GET|POST /api/crm/leads`
- **GET Query:** `?page=N&limit=N&status=STRING&source=STRING`
- **Response 200:** `{ leads: Lead[], total, page, limit }`
- **POST Request:** `{ email, company?, name?, source? }`

#### `GET /api/sales/leads`
- **Response 200:** `{ leads: SalesLead[] }`

#### `POST /api/sales/leads/enrich`
- **Request:** `{ leadIds: string[] }`
- **Response 200:** `{ enriched: EnrichedLead[] }`

#### `PATCH /api/sales/leads/update`
- **Request:** `{ updates: { id, ...changes }[] }`
- **Response 200:** `{ updated: number }`

#### `GET|PATCH /api/sales/campaigns`
- **GET Response 200:** `{ campaigns: SalesCampaign[] }`
- **PATCH Request:** `{ id, ...changes }`

#### `POST /api/sales/discovery/run`
- **Request:** `{ criteria: DiscoveryCriteria }`
- **Response 202:** `{ jobId: string, status: "queued" }`

#### `POST /api/sales/outreach/start`
- **Request:** `{ campaignId, leadIds[], template? }`
- **Response 202:** `{ jobId: string, status: "started" }`

#### `GET|PUT /api/sales/settings`
- **GET Response 200:** `{ settings: SalesSettings }`
- **PUT Request:** `{ ...settingsUpdates }`

#### `POST /api/leads/discovery`
- **Request:** `{ query: string, filters? }`
- **Response 200:** `{ results: DiscoveryResult[] }`

### Inbox & Integrations

#### `GET /api/inbox`
- **Query:** `?page=N&limit=N&folder=inbox|spam|quarantine`
- **Response 200:** `{ messages: Message[], total, page, limit }`

#### `GET|POST /api/inbox/config`
- **GET Response 200:** `{ config: InboxConfig }`
- **POST Request:** `{ ...configUpdates }`

#### `GET|POST /api/integrations`
- **GET Response 200:** `{ integrations: Integration[] }`
- **POST Request:** `{ type, name, config }`

#### `GET|PATCH|DELETE /api/integrations/[id]`
- **ID validation:** `SAFE_ID`
- **GET Response 200:** `{ integration: Integration }`
- **PATCH Request:** `{ ...changes }`
- **DELETE Response 200:** `{ success: true }`

### Calendar & Scheduling

#### `GET|POST /api/calendar`
- **GET Query:** `?from=ISO&to=ISO`
- **Response 200:** `{ events: CalendarEvent[] }`
- **POST Request:** `{ title, start, end, type }`

#### `GET|POST /api/calendar/availability`
- **GET Response 200:** `{ slots: AvailabilitySlot[] }`
- **POST Request:** `{ dayOfWeek, start, end }`

#### `DELETE /api/calendar/availability/[slotId]`
- **ID validation:** `SAFE_ID`
- **Response 200:** `{ success: true }`

#### `PATCH /api/calendar/events/[eventId]/status`
- **ID validation:** `SAFE_ID`
- **Request:** `{ status: "confirmed"|"cancelled"|"tentative" }`
- **Response 200:** `{ event: CalendarEvent }`

### Support

#### `GET|POST|PUT /api/support`
- **GET Query:** `?page=N&limit=N&status=open|closed|escalated`
- **Response 200:** `{ tickets: SupportTicket[], total, page, limit }`
- **POST Request:** `{ subject, body, priority }`
- **PUT Request:** `{ ticketId, status?, assignee?, response? }`

#### `GET /api/support/analytics`
- **Response 200:** `{ avgResponseTime, openTickets, resolvedToday, satisfaction }`

### System & Infrastructure

#### `GET /api/system/health`
- **Response 200:** `{ status: "healthy"|"degraded"|"unhealthy", components: { db, redis, queue, ... } }`

#### `POST /api/system/alerts/[alertId]/acknowledge`
- **ID validation:** `SAFE_ID`
- **Request:** `{ acknowledgedBy?: string, note?: string }`
- **Response 200:** `{ alert: SystemAlert }`

#### `POST /api/system/workers/[workerId]/restart`
- **ID validation:** `SAFE_ID`
- **Response 200:** `{ workerId, status: "restarting" }`

### Settings & Backup

#### `GET|POST /api/settings/backup`
- **GET Response 200:** `{ config: BackupConfig, lastRun?: BackupRun }`
- **POST Request:** `{ schedule, retention, targets[] }`

#### `POST /api/settings/backup/run`
- **Response 202:** `{ backupId, status: "started" }`

#### `POST /api/settings/backup/dr-test`
- **Response 202:** `{ testId, status: "started" }`

#### `GET|PUT /api/v1/operator/settings`
- **GET Response 200:** `{ settings: OperatorSettings }`
- **PUT Request:** `{ ...settingsUpdates }`

### IP Warmup

#### `GET /api/warmup`
- **Response 200:** `{ ips: WarmupIP[], schedule: WarmupSchedule }`

#### `POST /api/warmup/advance`
- **Response 200:** `{ advanced: number, ips: WarmupIP[] }`

#### `POST /api/warmup/ip/[ipAddress]/[action]`
- **IP validation:** `SAFE_IP = /^[0-9a-fA-F.:]+$/`
- **Action validation:** `SAFE_ACTION = /^(start|pause|resume|reset|day)$/`
- **Response 200:** `{ ip: WarmupIP }`

### Miscellaneous

#### `GET /api/revenue`
- **Query:** `?from=ISO&to=ISO`
- **Response 200:** `{ mrr, arr, growth, churn, byPlan: RevenueByPlan[] }`

#### `GET|PATCH /api/risk`
- **GET Response 200:** `{ tenants: RiskAssessment[], flags: RiskFlag[] }`
- **PATCH Request:** `{ tenantId, riskLevel?, notes? }`

#### `GET|POST /api/autopilot`
- **GET Response 200:** `{ rules: AutopilotRule[], status }`
- **POST Request:** `{ action, rule?, config? }`

#### `ALL /api/proxy`
- **Request:** Varies (generic proxy endpoint)
- **Response:** Varies

---

## Common Response Patterns

### Error Responses

All API routes return errors in a consistent format:

```json
{ "error": "Human-readable error message" }
```

With HTTP status codes:
- `400` — Bad Request (validation failure, invalid ID)
- `401` — Unauthorized (no session / invalid session)
- `403` — Forbidden (CSRF failure, insufficient role, IP blocked)
- `404` — Not Found
- `409` — Conflict
- `413` — Payload Too Large (body > 5 MB, enforced by proxy)
- `429` — Too Many Requests
- `500` — Internal Server Error
- `502/503/504` — Upstream Rust backend unavailable (retried automatically)

### Pagination

Paginated endpoints follow a consistent pattern:
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "limit": 20
}
```

Query parameters: `?page=N&limit=N`

### ID Validation

Routes with dynamic parameters validate IDs before proxying:
- **Standard IDs:** `SAFE_ID = /^[a-zA-Z0-9._:-]+$/`
- **IP addresses:** `SAFE_IP = /^[0-9a-fA-F.:]+$/`
- **Actions:** `SAFE_ACTION = /^(start|pause|resume|reset|day)$/`

Invalid IDs return `400 { error: "Invalid <paramName>" }` without proxying to Rust.
