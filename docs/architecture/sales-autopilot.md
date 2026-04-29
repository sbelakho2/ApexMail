# Sales Autopilot

> **Implementation Note (2026-04):** `sales-autopilot` runs as a separate Axum service for ApexMail's internal sales workflow. It is not part of the customer-facing `/v1` API surface.

## Overview

The `sales-autopilot` crate powers ApexMail's internal sales automation flow: lead intake, company enrichment, campaign orchestration, calendar booking support, inbox triage, and scraper utilities for prospect discovery.

The current server binary lives at `services/mail-server/crates/sales-autopilot/src/bin/server.rs` and starts a dedicated HTTP service on port `3010` by default.

## Runtime Model

- Separate process from the main API server.
- Intended for trusted control-plane or operator workflows, not public tenant traffic.
- Protects all routes except `/health` with `INTERNAL_SERVICE_TOKEN` via `x-api-key` or `Authorization: Bearer ...`.
- Requires `DATABASE_URL` at startup.
- Initializes the `enriched_companies` cache table on boot.

## Core Components

### CRM

Two CRM implementations exist:

- `CrmService` provides an in-memory lead store for tests and self-contained development flows.
- `SqlxCrmService` provides a PostgreSQL-backed lead store with `sales_leads` table initialization and async CRUD operations.

The shipped server binary currently wires the in-memory `CrmService`, so lead state is not persisted across process restarts unless the binary is extended to use `SqlxCrmService`.

Lead scoring is currently deterministic and local: `40%` email engagement, `30%` company-size tier, `30%` recency, rounded to a `0..=100` score.

### Company Enrichment

`EnrichmentService` resolves firmographic data from a lead email or company domain.

- Extracts the domain from the lead email address.
- Uses deterministic mock data for known domains such as `acme.com`, `beta.io`, and `gamma.dev`.
- Falls back to a derived company name with `Unknown` metadata for unrecognized domains.
- Persists enrichment cache rows in `enriched_companies`.

The cache schema includes domain, company attributes, confidence score, and enrichment timestamps keyed by `(tenant_id, domain)`.

### Campaign Management

`CampaignManager` manages outreach campaigns with an in-memory state machine:

- `Draft` -> `Active` -> `Paused`
- Per-campaign recipient lists stored in memory
- Active-campaign cap enforced by `MAX_CAMPAIGNS`
- Lightweight delivery statistics tracked on the campaign record (`sent`, `opened`, `clicked`)

The current implementation is orchestration-focused. It does not yet persist campaigns or recipients to PostgreSQL.

### Calendar Scheduling

`CalendarService` models demo scheduling with fixed business rules:

- Working hours: `09:00-17:00` UTC
- Weekdays only
- 30-minute slots
- Overlap rejection for conflicting bookings

This service currently keeps events in memory and supports create/list/cancel plus available-slot calculation.

### Inbox Triage

`InboxManager` classifies inbound messages into:

- `Lead`
- `Customer`
- `Support`
- `Spam`
- `Other`

Classification is keyword-based today. The service stores message metadata in memory and tracks reply status plus aggregate reply rate.

### Scraper Utilities

`WebScraper` provides deterministic prospecting helpers:

- Email extraction from arbitrary text
- Basic company info derivation from domains
- HTTP(S) URL validation
- Conservative `robots.txt` allow/disallow evaluation

These utilities are text-processing helpers only; the crate does not embed a browser or autonomous crawler.

## HTTP Surface

The router defined in `src/routes.rs` exposes:

| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | `GET` | Liveness probe |
| `/leads` | `GET`, `POST` | List or create leads |
| `/leads/{id}` | `GET` | Fetch a single lead |
| `/companies` | `GET` | List enriched companies |
| `/enrich` | `POST` | Enrich a lead or company |
| `/campaigns` | `GET`, `POST` | List or create campaigns |
| `/campaigns/:id/recipients` | `POST` | Add campaign recipients |
| `/campaigns/:id/start` | `POST` | Start a campaign |
| `/campaigns/:id/pause` | `POST` | Pause a campaign |
| `/calendar` | `GET` | List calendar events / availability |
| `/inbox` | `GET` | List triaged inbox messages |

The service applies a `256 KB` body limit and a `30-second` request timeout.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `SALES_PORT` | `3010` | HTTP listen port |
| `ENRICHMENT_API_URL` | `https://enrich.apexmail.ee/v1` | Upstream enrichment endpoint configuration |
| `CALENDAR_SYNC_INTERVAL` | `300` | Calendar sync interval in seconds |
| `MAX_CAMPAIGNS` | `50` | Maximum active campaigns |
| `SCRAPER_RPM` | `30` | Ethical rate limit for scraper workflows |
| `INTERNAL_SERVICE_TOKEN` | empty | Internal route authentication secret |
| `DATABASE_URL` | none | Required Postgres connection string |

If config validation fails, the service falls back to `SalesConfig::default()` and logs the error.

## Persistence Boundaries

Current persisted state:

- `enriched_companies` cache table created by `routes::initialize_schema()`
- Optional `sales_leads` table supported by `SqlxCrmService::initialize()`

Current in-memory-only state in the shipped binary:

- leads
- campaigns and recipients
- calendar events
- inbox messages

## Current Implementation Notes

- The service is documented as storing ApexMail's own sales leads rather than tenant customer data.
- Resource-level tenant scoping is not yet enforced on every campaign path, so the current deployment model should remain internal-only.
- Scoring weights are compile-time constants today.
- Enrichment currently behaves like a deterministic mock for known domains and a fallback generator for unknown ones.
- Campaign execution is orchestration state only; it is not yet tied to an event-driven outbound delivery pipeline.

## Relevant Source Files

- `services/mail-server/crates/sales-autopilot/src/bin/server.rs`
- `services/mail-server/crates/sales-autopilot/src/routes.rs`
- `services/mail-server/crates/sales-autopilot/src/config.rs`
- `services/mail-server/crates/sales-autopilot/src/crm.rs`
- `services/mail-server/crates/sales-autopilot/src/crm_pg.rs`
- `services/mail-server/crates/sales-autopilot/src/campaigns.rs`
- `services/mail-server/crates/sales-autopilot/src/enrichment.rs`
- `services/mail-server/crates/sales-autopilot/src/calendar.rs`
- `services/mail-server/crates/sales-autopilot/src/inbox.rs`
- `services/mail-server/crates/sales-autopilot/src/scrapers.rs`