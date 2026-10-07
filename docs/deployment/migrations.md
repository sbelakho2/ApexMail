# Migration lineage decision (moved from services/mail-server/migrations/README.md — sqlx::migrate! scans that directory at compile time and rejects non-migration files)

**Canonical: this directory.** Applied in every deploy path by the
**`migrator`** one-shot job (`services/mail-server/crates/migrator`, which
embeds this directory via `sqlx::migrate!` at build time):

```sh
# What ci/stages/migrate.sh (pipeline migration gate) and deploy.sh (Step 5) run:
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env --profile migrate run --rm migrator
```

The pipeline images stage (`ci/stages/images.sh`) builds the
`ghcr.io/<ns>/migrator` image in lockstep with the service images, so the
embedded chain always matches the deployed binaries. The manual
`sqlx migrate run --source services/mail-server/migrations` invocation with a
`DATABASE_URL` remains the fallback for operators with direct database
access. `tools/migrations/` is a legacy archive (see its README) — never
mounted, never extended; schema changes land here only.

## The lineage convergence

The two historical lineages differ in id shapes (tools used VARCHAR(26)
ULIDs from the start; early services migrations used UUIDs), but they
converged inside this chain:

- **064** standardized every public `tenant_id`/`*_tenant_id` column to
  `VARCHAR(26)` as the canonical type and ships
  `apexmail_normalize_tenant_id`/`apexmail_lookup_tenant_id`, which accept
  both UUID strings and ULIDs during the transition.
- **088** unified `email_queue`/`inbound_messages` shapes across the
  lineages (its header documents the tools shapes it absorbed).
- **090** widened `email_queue.campaign_id` (and events id/message_id) to
  TEXT so both shapes fit.

Consequence for application code: bind tenant ids and ULID-shaped ids as
TEXT/VARCHAR(26); treat UUID-typed columns as legacy that 064/088/090 have
already absorbed where it matters. New tables use `tenant_id VARCHAR(26)`
and TEXT ids unless a FK to a still-UUID table forces otherwise — in that
case normalize through the 064 helpers.

## Conventions for new migrations

- Sequential three-digit numbering (next free at the time of writing: 109).
- Idempotent guards (`to_regclass`/`IF NOT EXISTS`) — follow 101-108.
- Never edit an applied migration; add a new one.
- Long-running type changes: see 064's batching pattern and 066's notes.

## Long-lived hosts: reclaim the test-database clones

Every DB-backed suite provisions an `apexmail_*` clone of the canonical
template and leaves it behind (CI is one-shot, so nothing cleans up). On a
developer or long-lived CI host the clones grow without bound — the
2026-10-07 whole-repo dogfood found 1,096 of them (~55 GB) and the resulting
disk pressure crashed Postgres mid-suite. Reclaim them with:

```bash
DATABASE_URL=postgresql://… cargo run -p migrator -- --gc-test-databases
```

The mode drops `apexmail_%` databases other than the protected base
(`apexmail`; extend protection with `MIGRATOR_GC_KEEP=name1,name2`), skips
databases with live connections, and reports every failure. Run it after a
test wave, before the next one.
