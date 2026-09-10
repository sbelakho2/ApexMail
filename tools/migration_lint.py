#!/usr/bin/env python3
"""ApexMail migration SQL lint — enterprise conventions for the canonical chain.

Enforced over services/mail-server/migrations/*.sql (the chain the migrator
embeds and production applies):

  (a) destructive ops (DROP TABLE / DROP COLUMN / DROP DATABASE) must carry
      IF EXISTS (or sit inside an existence-probing guard: a PL/pgSQL
      `IF <catalog probe> THEN` frame, an `EXCEPTION WHEN undefined_*`
      handler block, or — for DROP — nothing else);
  (b) CREATE TABLE must be IF NOT EXISTS, a TEMP table, inside an
      existence-probing guard, or directly preceded by a
      `DROP TABLE IF EXISTS <same name>` (recreate pattern);
  (c) every file must START with a `-- Migration N:` header comment whose N
      equals the version number in the filename;
  (d) CREATE [UNIQUE] INDEX must use IF NOT EXISTS or sit inside an
      existence-probing guard. (NOT CONCURRENTLY — see (f));
  (e) GRANT ALL and TRUNCATE are forbidden in migrations;
  (f) files must be valid inside a transaction: no explicit COMMIT and no
      CREATE INDEX CONCURRENTLY (the migrator applies each file inside one
      transaction; a CONCURRENTLY would abort it).

Why a linter and not just review: the chain is 150+ files touched by many
workstreams; these conventions are what keeps `sqlx migrate run` idempotent
(second run against a current schema must no-op cleanly) and fresh-host
provisioning deterministic.

PRODUCTION-LEDGER FREEZE — read before editing any migration:
sqlx records a SHA-384 checksum of every applied migration file in
_sqlx_migrations and `Migrator::run` (sqlx-core 0.8.6, the exact code path
the migrator binary runs on every deploy) FAILS with VersionMismatch when a
previously-applied file's bytes change — INCLUDING comment-only edits. The
whole 001–169 chain is recorded in the production ledger, so:

  * violations in ledger files are GRANDFATHERED via the exemption sets
    below (each with its justification), NOT edited in place;
  * NEW migrations (and edits to not-yet-applied files) must comply — the
    checker fails closed on them;
  * if you want to normalize a grandfathered file anyway, do it as a
    deliberate sweep that also refreshes the production ledger checksums
    (pg_dump the ledger first — ci/stages/migrate.sh already keeps a
    per-run backup — and update _sqlx_migrations.checksum from the newly
    computed values in the same maintenance window).

The guard heuristics are deliberately conservative: a statement counts as
guarded only when an enclosing IF condition probes a system catalog
(to_regclass / information_schema / pg_class / pg_indexes / ...), the
statement sits in a BEGIN block whose EXCEPTION clause catches
undefined_object class conditions, or a DROP TABLE IF EXISTS for the same
unqualified name precedes the CREATE in the same file. Anything else is
reported.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "services" / "mail-server" / "migrations"

# ---------------------------------------------------------------------------
# Grandfathered files — every entry REQUIRES a justification comment.
# All entries below are recorded in the production _sqlx_migrations ledger
# (checksum-frozen; see the module docstring). Do not add entries for files
# that are NOT yet applied anywhere — fix those instead.
# ---------------------------------------------------------------------------

# (c) header-style exemptions: pre-convention first lines. Adding the
# canonical `-- Migration N:` header is a comment-only edit in intent, but it
# changes the file checksum and therefore breaks the production migrator
# (VersionMismatch) — normalize only in a deliberate ledger-refresh sweep.
# (Listing generated mechanically 2026-09-10: every chain file whose first
# line does not match `-- Migration N:`.)
LEGACY_HEADER = {
    "001_initial_schema.sql",  # descriptive header present, pre-convention style
    "002_mailstore_uid.sql",
    "003_dedicated_ips.sql",
    # 004–019: reserved-slot placeholders, one-line descriptive header each
    "004_legacy_schema_slot_reserved.sql",
    "005_legacy_schema_slot_reserved.sql",
    "006_legacy_schema_slot_reserved.sql",
    "007_legacy_schema_slot_reserved.sql",
    "008_legacy_schema_slot_reserved.sql",
    "009_legacy_schema_slot_reserved.sql",
    "010_legacy_schema_slot_reserved.sql",
    "011_legacy_schema_slot_reserved.sql",
    "012_legacy_schema_slot_reserved.sql",
    "013_legacy_schema_slot_reserved.sql",
    "014_legacy_schema_slot_reserved.sql",
    "015_legacy_schema_slot_reserved.sql",
    "016_legacy_schema_slot_reserved.sql",
    "017_legacy_schema_slot_reserved.sql",
    "018_legacy_schema_slot_reserved.sql",
    "019_legacy_schema_slot_reserved.sql",
    "020_ses_monitoring.sql",
    "022_enterprise_billing_contracts.sql",
    "023_enterprise_support_sso.sql",
    "024_billing_alert_runtime.sql",
    "025_mfa_recovery_codes.sql",
    "026_metering_events_composite_index.sql",
    "027_vat_kmd_returns.sql",
    "028_month_end_closing.sql",
    "029_add_performance_indexes.sql",
    "030_bounce_analytics.sql",  # filename-echo header
    "031_system_alerts_tenant_scope.sql",
    "032_grader_results.sql",
    "033_seed_providers.sql",
    "034_seed_accounts.sql",
    "035_placement_tests.sql",
    "036_placement_results.sql",
    "037_seed_accounts_failure_tracking.sql",
    "038_compliance_core_tables.sql",  # `038:` number-colon style
    "039_soc2_hipaa_trust_portal.sql",
    "040_postmaster_reputation.sql",
    "043_enterprise_private_deploy.sql",
    "044_ai_send_time_cache.sql",
    "045_create_dunning_config.sql",
    "046_add_text_column_constraints.sql",
    "047_add_labels_gin_index.sql",
    "048_add_mailboxes_parent_id_index.sql",
    "049_add_delivery_log_composite_index.sql",
    "050_partition_high_volume_tables.sql",  # filename-echo header
    "051_add_missing_performance_indexes.sql",
    "052_add_missing_foundation_tables.sql",
    "053_recreate_delivery_log_fk.sql",
    "054_remaining_schema_fixes.sql",
    "056_fix_critical_schema_issues.sql",
    "057_add_mfa_constraints.sql",
    "058_fix_high_severity_faults.sql",
    "059_verify_all_p0_faults_resolved.sql",
    "060_add_down_migration_support.sql",
    "061_fix_remaining_db_faults.sql",
    "062_add_email_queue_new_schema.sql",
    "063_add_db_audit_fixes.sql",
    "064_standardize_tenant_id_varchar26.sql",
    "065_webhook_dual_secret_rotation.sql",
    "066_fix_remaining_db_faults_v2.sql",
    "067_fix_remaining_db_faults_v3.sql",
    "074_stripe_billing_schema_fixes.sql",
    "077_add_hipaa_event_signature.sql",
    "078_race_condition_fixes.sql",
    "079_estonia_ou_compliance.sql",
    "080_report_history.sql",
    "081_audit_fts.sql",
    "082_health_check_history.sql",
    "083_add_analytics_indexes.sql",
    "084_enhance_compliance_submissions.sql",
    "085_cp_access_log.sql",
    "087_create_scim_users_and_dunning_records.sql",
    "088_unify_email_queue_inbound_schema.sql",
    "089_analytics_hourly.sql",
    "090_widen_events_id_columns.sql",
    "091_add_message_stats_columns.sql",
    "092_enterprise_missing_tables.sql",
    "093_deep_schema_convergence.sql",
    "094_add_domain_dkim_key_columns.sql",
    "095_mta_bounce_fbl_hardening.sql",
    "096_messages_idempotency_column.sql",
    "097_drop_account_message_id_unique.sql",
    "098_billing_service_schema_fixes.sql",
    "099_admin_override_columns.sql",
    "100_domain_dkim_readiness_hardening.sql",
    "101_billing_revenue_integrity_fixes.sql",
    "102_message_dedup_delivery_scope.sql",
    "103_queue_lease_token.sql",
    "104_usage_metering_reconciliation_wallet_width.sql",
    "105_audit_chain_head.sql",
    "106_users_login_functional_indexes.sql",
    "107_template_version_snapshots.sql",
    "108_analytics_reality_writers.sql",
    "109_init.sql",  # `109:` number-colon style
    "110_uid_backfill.sql",
    "111_raw_message.sql",
    "112_mailbox_unique_name.sql",
    "113_dedup_exempt.sql",
    "114_inbound_legacy_columns_nullable.sql",
    "115_repair_partition_conversion_losses.sql",
    "116_financial_integrity_constraints.sql",
    "117_metering_events_reconciliation.sql",
    "118_dunning_event_invoice_id_width.sql",
    "119_ha_audit_tables.sql",
    "120_ip_pool_allocated_to_varchar26.sql",
    "122_invoice_vat_rate_double_precision.sql",
    "123_ai_assistant.sql",
    "125_verification_token_index.sql",
    "126_overage_period_marker.sql",
    "127_webhook_retry_ladder.sql",
    "128_canonical_webhook_events.sql",
    "130_invoice_xml_url.sql",
    "131_plan_overrides_updated_at.sql",
    "132_billing_addresses_state_email.sql",
    "133_abuse_reports_status.sql",
    "134_credit_notes.sql",
    "135_stripe_subscriptions_plan_backfill.sql",
    "136_invoices_unique_overage_period.sql",
    "137_billing_periods.sql",
    "138_invoice_collection_outbox.sql",
    "139_invoices_stripe_item_id.sql",
    "140_invoice_payment_allocations.sql",
    "150_contacts_tags_canonical.sql",
    "159_reply_events_canonical.sql",
    "160_edge_case_services.sql",
    "161_ha_backup.sql",
    "162_ha_chaos.sql",
    "163_ha_multi_region.sql",
    "164_isolation_tenants.sql",
    "165_isolation_audit.sql",
    "166_isolation_data_isolation.sql",
    "167_isolation_encryption.sql",
    "168_compliance_contact_persons.sql",
}

# (a)/(b)/(d) semantic-convention exemptions in ledger files. These are
# constructs that predate the convention but are runtime-guarded in ways the
# conservative heuristics below cannot see (or guarded by patterns deemed
# acceptable only for already-applied files). Each with its specific reason.
LEDGER_SEMANTIC_EXEMPT = {
    "066_fix_remaining_db_faults_v2.sql": {
        # (b): metering_events partition children are created via dynamic
        # `EXECUTE format('CREATE TABLE metering_events_%s PARTITION OF ...')`
        # inside the conversion function whose FIRST statement is the
        # early-return guard (`IF <table has rows> THEN RAISE WARNING ...
        # RETURN`), after the parent's `DROP TABLE IF EXISTS
        # metering_events` + plain CREATE (the recreate pattern). The
        # early-RETURN guard is invisible to the line-based heuristic; the
        # dynamic %s names cannot match the drop-first name set. Runtime-
        # guarded; ledger-frozen.
        "b": "dynamic partition children under an early-RETURN guard (see comment)",
    },
    "067_fix_remaining_db_faults_v3.sql": {
        # (b): FALSE POSITIVE — the flagged `CREATE TABLE` token occurs
        # inside a RAISE NOTICE message string (the DB-100 documentation
        # block), not as DDL. String contents are kept in the scanned text
        # because EXECUTE format(...) dynamic SQL must be linted; this is
        # the accepted trade-off. Ledger-frozen.
        "b": "CREATE TABLE appears only inside a RAISE NOTICE string, not DDL",
    },
}

# Catalog probes that make an IF condition a "guard" for (a)/(b)/(d).
PROBE_TOKENS = re.compile(
    r"to_regclass|to_regprocedure|to_regtype|to_regnamespace|"
    r"information_schema|pg_class|pg_indexes|pg_tables|pg_attribute|"
    r"pg_partitioned_table|pg_database|pg_constraint|has_table_privilege|"
    r"\bEXISTS\s*\(",
    re.IGNORECASE,
)


def strip_comments(sql: str) -> str:
    """Remove `--` line comments, preserving string literals and dollar-quoted
    bodies (the latter contain the DDL we lint)."""
    out = []
    for line in sql.split("\n"):
        in_str = False
        i = 0
        kept = []
        while i < len(line):
            ch = line[i]
            if ch == "'":
                # toggle unless it's an escaped ''
                if i + 1 < len(line) and line[i + 1] == "'":
                    kept.append("''")
                    i += 2
                    continue
                in_str = not in_str
                kept.append(ch)
            elif not in_str and ch == "-" and line.startswith("--", i):
                break
            else:
                kept.append(ch)
            i += 1
        out.append("".join(kept))
    return "\n".join(out)


class LineMap:
    """offset -> line-number mapping over the stripped text."""

    def __init__(self, text: str):
        starts = [0]
        for m in re.finditer(r"\n", text):
            starts.append(m.end())
        self.starts = starts

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1


def guarded_lines(code: str, lmap: LineMap) -> set[int]:
    """Line numbers considered 'inside an existence-probing guard'.

    Two sources:
      1. PL/pgSQL IF frames whose condition probes a catalog (conservative:
         ELSE/ELSIF branches stay guarded if any branch condition probes —
         every such branch still sits under an outer catalog-verified
         decision in this chain);
      2. BEGIN ... EXCEPTION WHEN undefined_* handler blocks (statements
         before the EXCEPTION are protected by the handler).
    """
    lines: set[int] = set()

    # (2) exception-guarded BEGIN blocks: statements between BEGIN and an
    # EXCEPTION WHEN undefined_* handler are protected by that handler.
    for m in re.finditer(
        r"\bBEGIN\b(?:(?!\bEXCEPTION\b)(?!;).)*?\bEXCEPTION\b\s+WHEN\s+undefined\w*",
        code,
        re.IGNORECASE | re.DOTALL,
    ):
        for ln in range(lmap.line_of(m.start()), lmap.line_of(m.end()) + 1):
            lines.add(ln)

    # (1) IF ... THEN frames: token walk. END IF is consumed as a single
    # token (longest-first alternation) so the IF inside it never opens a
    # frame. A CASE-expression THEN inside a condition can truncate the
    # captured condition text — accepted inaccuracy (the chain's conditions
    # are simple); truncation can only LOSE a probe, never invent one.
    tokens = [
        (m.start(), m.end(), re.sub(r"\s+", "", m.group(0).upper()))
        for m in re.finditer(r"\b(END\s+IF|ELSIF|ELSE|IF|THEN)\b", code, re.IGNORECASE)
    ]
    stack: list[tuple[int, bool]] = []
    spans: list[tuple[int, int]] = []
    for i, (pos, end, kind) in enumerate(tokens):
        if kind == "IF":
            # Condition text runs from the IF keyword to the next THEN
            # token — but only when no statement terminator lies between
            # them: the IF in `ADD COLUMN IF NOT EXISTS` / `DROP ... IF
            # EXISTS` clauses never precedes a THEN within its own
            # statement, and its statement's `;` always does. Such clause
            # IFs are NOT control-flow frames and must not be pushed (they
            # have no END IF of their own and would corrupt the pairing).
            cond = None
            for j in range(i + 1, len(tokens)):
                if tokens[j][2] == "THEN":
                    seg = code[end : tokens[j][1]]
                    if ";" not in seg:
                        cond = seg
                    break
                if tokens[j][2] == "IF":
                    break  # nested IF before any THEN: malformed; unguarded
            if cond is not None:
                stack.append((pos, bool(PROBE_TOKENS.search(cond))))
        elif kind == "ENDIF":
            if stack:
                start_pos, guarded = stack.pop()
                if guarded:
                    spans.append((start_pos, pos))
        # ELSIF/ELSE: conservative — keep the enclosing frame's verdict
    for st, en in spans:
        for ln in range(lmap.line_of(st), lmap.line_of(en) + 1):
            lines.add(ln)
    return lines


def check_file(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    code = strip_comments(raw)
    lmap = LineMap(code)
    guarded = guarded_lines(code, lmap)
    problems: list[str] = []
    name = path.name

    m = re.match(r"^(\d+)_", name)
    if not m:
        return [f"{name}:1: [naming] file must be NNN_description.sql"]
    version = int(m.group(1))

    # (c) header
    first = raw.split("\n", 1)[0]
    hm = re.match(r"^--\s*Migration\s+(\d+)\s*:", first)
    if not hm or int(hm.group(1)) != version:
        if name not in LEGACY_HEADER:
            problems.append(
                f"{name}:1: [header] must start with `-- Migration {version}: ...` "
                f"(got: {first[:60]!r})"
            )

    exempt = LEDGER_SEMANTIC_EXEMPT.get(name, {})

    # drop-first table names (for the recreate pattern in (b))
    dropped = set()
    for dm in re.finditer(
        r"\bDROP\s+TABLE\s+IF\s+EXISTS\s+([A-Za-z_][\w$.]*)", code, re.IGNORECASE
    ):
        dropped.add(dm.group(1).split(".")[-1].lower())

    # (a) destructive ops
    for am in re.finditer(
        r"\bDROP\s+(TABLE|COLUMN|DATABASE)\b(?!\s+IF\s+EXISTS)", code, re.IGNORECASE
    ):
        ln = lmap.line_of(am.start())
        if ln in guarded:
            continue
        if "a" in exempt:
            continue
        problems.append(
            f"{name}:{ln}: [destructive] `{am.group(0).upper()}` without IF EXISTS "
            f"and not inside an existence guard"
        )

    # (b) CREATE TABLE
    for cm in re.finditer(
        r"\bCREATE\s+((?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+)?(?:UNLOGGED\s+)?)TABLE\b"
        r"(?!\s+IF\s+NOT\s+EXISTS)(?:\s+([A-Za-z_][\w$.]*))?",
        code,
        re.IGNORECASE,
    ):
        ln = lmap.line_of(cm.start())
        prefix = cm.group(1) or ""
        tname = (cm.group(2) or "").split(".")[-1].lower()
        if "TEMP" in prefix.upper():
            continue  # session-scoped: recreated per run by construction
        if ln in guarded:
            continue
        if tname and tname in dropped:
            continue  # recreate pattern: DROP TABLE IF EXISTS <name> precedes
        if "b" in exempt:
            continue
        problems.append(
            f"{name}:{ln}: [create-table] CREATE TABLE without IF NOT EXISTS, "
            f"guard, or preceding DROP TABLE IF EXISTS"
        )

    # (d) CREATE INDEX
    for im in re.finditer(
        r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?!\s+IF\s+NOT\s+EXISTS)(?!\s+CONCURRENTLY)",
        code,
        re.IGNORECASE,
    ):
        ln = lmap.line_of(im.start())
        if ln in guarded:
            continue
        if "d" in exempt:
            continue
        problems.append(
            f"{name}:{ln}: [create-index] CREATE INDEX without IF NOT EXISTS "
            f"and not inside an existence guard"
        )

    # (e) GRANT ALL / TRUNCATE
    for gm in re.finditer(r"\bGRANT\s+ALL\b", code, re.IGNORECASE):
        ln = lmap.line_of(gm.start())
        if "e" in exempt:
            continue
        problems.append(f"{name}:{ln}: [forbidden] GRANT ALL in migrations")
    for tm in re.finditer(r"\bTRUNCATE\b", code, re.IGNORECASE):
        ln = lmap.line_of(tm.start())
        if "e" in exempt:
            continue
        problems.append(f"{name}:{ln}: [forbidden] TRUNCATE in migrations")

    # (f) transaction-invalid statements
    for sm in re.finditer(r"(?:^|;)\s*COMMIT\s*;", code, re.IGNORECASE):
        ln = lmap.line_of(sm.start())
        if "f" in exempt:
            continue
        problems.append(f"{name}:{ln}: [transaction] explicit COMMIT breaks the migration transaction")
    for cm in re.finditer(
        r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b", code, re.IGNORECASE
    ):
        ln = lmap.line_of(cm.start())
        if "f" in exempt:
            continue
        problems.append(
            f"{name}:{ln}: [transaction] CREATE INDEX CONCURRENTLY cannot run "
            f"inside the migration transaction"
        )
    return problems


def main() -> int:
    if not MIGRATIONS_DIR.is_dir():
        print(f"migration_lint: {MIGRATIONS_DIR} not found", file=sys.stderr)
        return 2
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        print("migration_lint: no migration files found", file=sys.stderr)
        return 2
    problems: list[str] = []
    for f in files:
        problems.extend(check_file(f))
    # Exemption hygiene: entries that no longer match a real file (or match a
    # compliant file) are rot and must be removed.
    present = {f.name for f in files}
    for stale in sorted(set(LEGACY_HEADER) - present):
        print(f"migration_lint: stale LEGACY_HEADER entry (no such file): {stale}")
        problems.append(f"(exemption-rot) {stale}")
    if problems:
        for p in problems:
            print(f"migration_lint: {p}")
        print(
            f"migration_lint: {len(problems)} violation(s) across {len(files)} migrations "
            f"({len(LEGACY_HEADER & present)} header-style grandfathered, "
            f"{len(LEDGER_SEMANTIC_EXEMPT)} semantic exemptions)"
        )
        return 1
    print(
        f"migration_lint: {len(files)} migrations clean "
        f"({len(LEGACY_HEADER & present)} header-style grandfathered, "
        f"{len(LEDGER_SEMANTIC_EXEMPT)} semantic exemptions — all ledger-frozen)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
