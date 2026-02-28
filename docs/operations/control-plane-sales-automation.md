# Control Plane Sales Automation

Last updated: 2026-02-27

This runbook documents the Control Plane sales automation stack under `apps/control-plane/src/app/sales` and related API routes.

## Scope

UI surfaces:

- `/sales` (unified sales system)
- `/leads` (lead discovery and review)
- `/crm` (pipeline workflow)
- `/campaigns` (campaign monitor)

Control Plane API routes:

- `GET /api/sales/leads`
- `PATCH /api/sales/leads/update`
- `POST /api/sales/leads/enrich`
- `POST /api/sales/discovery/run`
- `POST /api/sales/outreach/start`
- `GET /api/sales/campaigns`
- `PATCH /api/sales/campaigns`
- `GET /api/sales/settings`
- `PUT /api/sales/settings`

## Key Behaviors

### Discovery

- Select sources and categories
- Trigger discovery job via sales-autopilot backend
- Refresh and ingest enriched lead records

### Lead Operations

- Search/filter/sort/paginate leads
- Bulk status updates persisted via `PATCH /api/sales/leads/update`
- Notes edits persisted via same route
- Optional enrichment run via `POST /api/sales/leads/enrich`

### Outreach

- Offer-based campaign creation from selected leads
- Rate-limited campaign starts in control-plane route
- Confirmation dialog before outbound campaign start

### Campaign Management

- List campaign status and delivery metrics
- Pause/resume/archive/cancel actions via `PATCH /api/sales/campaigns`

### Settings Persistence

Saved via `PUT /api/sales/settings`:

- Scoring weights
- Discovery schedule
- Notification preferences
- Enabled discovery sources
- Default discovery page depth

## Data Contract Notes

Lead response now includes extended fields used by the unified sales UI:

- Contact details (`contactEmail`, `contactName`, `contactTitle`)
- Revenue and ownership fields (`estimatedDealValue`, `assignedTo`)
- Lifecycle and fit fields (`status`, `icpFit`)
- Follow-up and enrichment fields (`lastContactedAt`, `nextFollowUpAt`, `linkedinUrl`, `websiteTraffic`)

## Operator Validation Checklist

- [ ] Discovery run returns stats and new leads
- [ ] Bulk status change survives page refresh
- [ ] Lead notes survive page refresh
- [ ] Enrichment endpoint accepts selected lead IDs
- [ ] Campaign list populates and status actions update row state
- [ ] Sales settings persist and reload correctly
- [ ] CSV export works for current filtered result set

## Failure Modes and Triage

### Discovery or enrichment timeouts

- Verify `AUTOPILOT_API_URL`
- Inspect autopilot service health and latency

### Empty campaign list

- Verify `sales_campaigns` table presence
- Verify control-plane DB connectivity and permissions

### Settings not saved

- Ensure `sales_settings` table is writable
- Confirm no DB constraint or serialization errors in API logs

## Security and Guardrails

- Outreach start route is rate-limited by source IP
- Owner tenant ID is env-configurable (`CONTROL_PLANE_OWNER_TENANT_ID`)
- Mutation endpoints should be called with authenticated control-plane session
