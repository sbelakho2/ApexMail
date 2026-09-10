//! F63 regression test: the canonical migrations 161-163 (and 194, added in
//! the F63 completion pass) must define every table the ha crate's SQL
//! touches, with the exact column names/types the code binds and reads. If
//! this file fails after those migrations were renamed or reshaped, the
//! crate's persistence contract has drifted from the canonical schema —
//! update the migration (or this test) deliberately, never silently.

const MIGRATION_161: &str = include_str!("../../../migrations/161_ha_backup.sql");
const MIGRATION_162: &str = include_str!("../../../migrations/162_ha_chaos.sql");
const MIGRATION_163: &str = include_str!("../../../migrations/163_ha_multi_region.sql");
const MIGRATION_194: &str = include_str!("../../../migrations/194_ha_health_checks.sql");

#[test]
fn migrations_define_ha_tables() {
    assert!(
        MIGRATION_161.contains("CREATE TABLE IF NOT EXISTS ha_backups"),
        "migration 161 must create ha_backups"
    );
    assert!(
        MIGRATION_162.contains("CREATE TABLE IF NOT EXISTS ha_chaos_experiments"),
        "migration 162 must create ha_chaos_experiments"
    );
    for table in ["ha_regions", "ha_geo_routing_rules"] {
        assert!(
            MIGRATION_163.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "migration 163 must create {table}"
        );
    }
    assert!(
        MIGRATION_194.contains("CREATE TABLE IF NOT EXISTS ha_health_checks"),
        "migration 194 must create ha_health_checks"
    );
}

#[test]
fn migrations_match_column_types_bound_by_code() {
    // backup.rs BackupRow: nullable size-independent columns, i64 size and
    // duration, self-referencing parent backup id.
    assert!(MIGRATION_161.contains("size_bytes        BIGINT"));
    assert!(MIGRATION_161.contains("compression_ratio DOUBLE PRECISION"));
    assert!(MIGRATION_161.contains("parent_backup_id  UUID            REFERENCES ha_backups(id)"));

    // chaos.rs ExperimentRow: config/target/parameters/safety_checks are
    // non-Option JSON; created_by and results are optional.
    assert!(MIGRATION_162.contains("safety_checks   JSONB       NOT NULL"));
    assert!(MIGRATION_162.contains("created_by      VARCHAR(255)"));

    // multi_region.rs upserts regions ON CONFLICT (name); health_score is a
    // f64 defaulting to 100.0; rules carry priority + enabled.
    assert!(MIGRATION_163.contains("name                VARCHAR(255)    NOT NULL UNIQUE"));
    assert!(MIGRATION_163.contains("health_score        DOUBLE PRECISION NOT NULL DEFAULT 100.0"));
    assert!(MIGRATION_163.contains("priority       INTEGER      NOT NULL"));
    assert!(MIGRATION_163.contains("enabled        BOOLEAN      NOT NULL DEFAULT TRUE"));

    // health_check.rs record_health_check INSERTs (node_id, region, status,
    // components, checked_at) with ON CONFLICT DO NOTHING — which needs the
    // unique observation key; get_cluster_status scans checked_at DESC.
    assert!(MIGRATION_194.contains("node_id     VARCHAR(255) NOT NULL"));
    assert!(MIGRATION_194.contains("components  JSONB        NOT NULL"));
    assert!(MIGRATION_194.contains("checked_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()"));
    assert!(
        MIGRATION_194
            .contains("CONSTRAINT uq_ha_health_checks_node_checked UNIQUE (node_id, checked_at)"),
        "one observation per (node, instant)"
    );
    assert!(MIGRATION_194.contains("idx_ha_health_checks_checked_at"));
}
