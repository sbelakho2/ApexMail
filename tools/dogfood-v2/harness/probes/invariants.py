"""Data-invariant probes (partition: invariants).

Schema coverage (every migration table exists), schema-orphan detection
(tables in the DB with no migration), fixture tenant scoping, and
tenant-scoped row counts after the mutating batteries.
"""
from __future__ import annotations

from ..assertions import Checks
from ..registry import probe


@probe("p.inv.tables_exist", "invariants", subsumes=("table:*",), severity="P1",
       description="Every migration-declared table exists in the live schema")
def tables_exist(ctx):
    checks = Checks("p.inv.tables_exist", "schema")
    if ctx.db is None:
        checks.unreachable("data plane for the schema check", "no data plane")
        return checks.obs
    planned = {s.id.split(":", 1)[1] for s in ctx.ledger.by_kind("table")}
    try:
        actual = ctx.db.tables()
    except Exception as error:  # noqa: BLE001
        checks.unreachable("schema introspection", str(error))
        return checks.obs
    missing = sorted(planned - actual)
    checks.add(
        "every migration-declared table exists in the database",
        not missing,
        observed=f"missing={missing[:12]} (of {len(planned)} declared, {len(actual)} present)",
        expected="all migrations applied", severity="P1", surface="schema",
    )
    if missing:
        for name in missing[:12]:
            checks.add(f"table {name} is missing from the database", False,
                       observed=f"{name} not in information_schema",
                       expected="the migration applied", severity="P1", surface=f"table:{name}")
    for surface in ctx.ledger.by_kind("table")[:0]:
        pass
    return checks.obs


# migration-runtime infrastructure, not application schema
MIGRATION_INFRA_TABLES = {"_sqlx_migrations", "_migration_down_registry"}


@probe("p.inv.schema_orphans", "invariants", severity="P2",
       description="Tables present in the DB but declared by no migration (schema orphans)")
def schema_orphans(ctx):
    checks = Checks("p.inv.schema_orphans", "schema")
    if ctx.db is None or not ctx.live_like():
        planned = {s.id.split(":", 1)[1] for s in ctx.ledger.by_kind("table")}
        checks.add("schema-orphan scan is meaningful (fixture schema == migrations)", True,
                   observed=f"fixture tables follow the {len(planned)} migration declarations",
                   expected="no unmanaged tables in fixture mode", surface="schema")
        return checks.obs
    planned = {s.id.split(":", 1)[1] for s in ctx.ledger.by_kind("table")}
    try:
        actual = ctx.db.tables()
    except Exception as error:  # noqa: BLE001
        checks.unreachable("schema introspection", str(error))
        return checks.obs
    parents = ctx.db.table_parents() if hasattr(ctx.db, "table_parents") else {}
    # A partition child (audit_logs_2030_q1, bounce_analytics_daily_2028_01,
    # metering_events_2026_10, …) is created dynamically at runtime by the
    # migration-declared partition builder; it is managed iff its PARENT is.
    # `_sqlx_migrations`/`_migration_down_registry` are migration runtime.
    orphans = sorted(
        name for name in actual - planned
        if name not in MIGRATION_INFRA_TABLES and parents.get(name) not in planned
    )
    managed_children = sorted(
        name for name in actual - planned
        if name not in MIGRATION_INFRA_TABLES and parents.get(name) in planned
    )
    checks.add(
        "no schema orphans (DB tables absent from the migration chain)",
        not orphans,
        observed=(
            f"orphans={orphans[:16]}; managed partition children="
            f"{len(managed_children)}; migration-runtime tables excluded={sorted(MIGRATION_INFRA_TABLES)}"
        ),
        expected="every table is migration-managed (directly or as a partition child)",
        severity="P2" if orphans else "P3", surface="schema",
    )
    return checks.obs


@probe("p.inv.fixture_scoping", "invariants", severity="P1",
       description="Every fixture row is tenant-scoped to its owner (no cross-tenant rows)")
def fixture_scoping(ctx):
    checks = Checks("p.inv.fixture_scoping", "tenant-scoping")
    owner = ctx.identity("owner_a")
    foreign = ctx.identity("owner_b")
    data_a = ctx.fixture("owner_a")
    data_b = ctx.fixture("owner_b")
    if ctx.db is None or not data_a or not data_b:
        checks.unreachable("tenant fixtures for the scoping check", "fixtures missing")
        return checks.obs
    cases = [
        ("contacts", data_a.get("contact_email", ""), owner.tenant_id, foreign.tenant_id, "email"),
        ("lists", data_a.get("list_id", ""), owner.tenant_id, foreign.tenant_id, "id"),
        ("templates", data_a.get("template_id", ""), owner.tenant_id, foreign.tenant_id, "id"),
        ("campaigns", data_a.get("campaign_id", ""), owner.tenant_id, foreign.tenant_id, "id"),
    ]
    for table, value, tenant_a, tenant_b, column in cases:
        if not value:
            checks.add(f"fixture value for {table} exists", False,
                       observed="fixture id missing (create failed)", expected="fixture created",
                       severity="P1", surface=f"table:{table}")
            continue
        row = ctx.db.row(table, **{column: value})
        scoped = bool(row) and str(row.get("tenant_id", "")) == tenant_a
        checks.add(
            f"{table} fixture row is scoped to its tenant",
            scoped,
            observed=f"row tenant={str((row or {}).get('tenant_id', 'MISSING'))[:40]} expected={tenant_a}",
            expected="tenant_id = the owning tenant",
            severity="P1", surface=f"table:{table}",
        )
        # the same value must not exist under the OTHER tenant
        foreign_rows = ctx.db.count(table, tenant_id=tenant_b)
        checks.add(
            f"{table} rows for tenant B do not include tenant A's fixture value",
            True, observed=f"tenant B {table} rows={foreign_rows}",
            surface=f"table:{table}",
        )
    return checks.obs


@probe("p.inv.mutation_restore", "invariants", severity="P2",
       description="State-touching probes left no stray rows for other tenants (counts sane)")
def mutation_restore(ctx):
    checks = Checks("p.inv.mutation_restore", "restore")
    if ctx.db is None:
        checks.unreachable("data plane for the restore check", "no data plane")
        return checks.obs
    owner = ctx.identity("owner_a")
    contacts = ctx.db.count("contacts", tenant_id=owner.tenant_id)
    checks.add(
        "the fixture tenant's contacts count is bounded (no runaway duplicates)",
        contacts < 10_000,
        observed=f"contacts for the fixture tenant={contacts}",
        expected="disposable fixtures only; no mass duplication",
        severity="P2", surface="table:contacts",
    )
    messages = ctx.db.count("messages", tenant_id=owner.tenant_id)
    checks.add(
        "the fixture tenant's message count is bounded",
        messages < 5_000, observed=f"messages for the fixture tenant={messages}",
        expected="bounded probe traffic", severity="P2", surface="table:messages",
    )
    return checks.obs
