//! F63 regression test: the canonical migrations 164-167 must define every
//! table the isolation crate's SQL touches, with the exact column names and
//! types the code binds and reads — and iso_workspaces must have exactly ONE
//! definition (tenant.rs and data_isolation.rs share it). If this file fails
//! after those migrations were renamed or reshaped, the crate's persistence
//! contract has drifted from the canonical schema — update the migration (or
//! this test) deliberately, never silently.

const MIGRATION_164: &str = include_str!("../../../migrations/164_isolation_tenants.sql");
const MIGRATION_165: &str = include_str!("../../../migrations/165_isolation_audit.sql");
const MIGRATION_166: &str = include_str!("../../../migrations/166_isolation_data_isolation.sql");
const MIGRATION_167: &str = include_str!("../../../migrations/167_isolation_encryption.sql");
const MIGRATION_195: &str = include_str!("../../../migrations/195_iso_access_attempts.sql");
const MIGRATION_196: &str = include_str!("../../../migrations/196_iso_encryption_policies.sql");

#[test]
fn migrations_define_isolation_tables() {
    for table in [
        "iso_organizations",
        "iso_workspaces",
        "iso_workspace_members",
        "iso_cleanup_queue",
    ] {
        assert!(
            MIGRATION_164.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "migration 164 must create {table}"
        );
    }
    assert!(
        MIGRATION_165.contains("CREATE TABLE IF NOT EXISTS iso_audit_logs"),
        "migration 165 must create iso_audit_logs"
    );
    for table in ["iso_access_policies", "iso_isolation_configs"] {
        assert!(
            MIGRATION_166.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "migration 166 must create {table}"
        );
    }
    assert!(
        MIGRATION_167.contains("CREATE TABLE IF NOT EXISTS iso_encryption_keys"),
        "migration 167 must create iso_encryption_keys"
    );
    // F63 remainder: the access-attempt audit trail and the encryption
    // policy catalog.
    assert!(
        MIGRATION_195.contains("CREATE TABLE IF NOT EXISTS iso_access_attempts"),
        "migration 195 must create iso_access_attempts"
    );
    assert!(
        MIGRATION_196.contains("CREATE TABLE IF NOT EXISTS iso_encryption_policies"),
        "migration 196 must create iso_encryption_policies"
    );
}

#[test]
fn iso_workspaces_has_exactly_one_definition() {
    // tenant.rs and data_isolation.rs share iso_workspaces; the canonical
    // chain must define it once (164) and never re-create it.
    let all = format!(
        "{}{}{}{}",
        MIGRATION_164, MIGRATION_165, MIGRATION_166, MIGRATION_167
    );
    let count = all
        .match_indices("CREATE TABLE IF NOT EXISTS iso_workspaces")
        .count()
        + all.match_indices("CREATE TABLE iso_workspaces").count();
    assert_eq!(count, 1, "iso_workspaces must be defined exactly once");
}

#[test]
fn migrations_match_column_types_bound_by_code() {
    // tenant.rs: ids are Uuid strings (TEXT), quota/usage/settings JSON,
    // members upsert ON CONFLICT (workspace_id, user_id), invited_by absent
    // from the creator-membership INSERT (NULLable).
    assert!(MIGRATION_164.contains("id               TEXT        PRIMARY KEY"));
    assert!(MIGRATION_164.contains("quota            JSONB       NOT NULL"));
    assert!(MIGRATION_164.contains("usage            JSONB       NOT NULL"));
    assert!(MIGRATION_164.contains("invited_by    TEXT"));

    // audit.rs AuditRow: details/metadata JSON NOT NULL, hash chain lives in
    // metadata; organization-scoped queries order by created_at DESC.
    assert!(MIGRATION_165.contains("details           JSONB       NOT NULL"));
    assert!(MIGRATION_165.contains("metadata          JSONB       NOT NULL"));
    assert!(MIGRATION_165.contains("REFERENCES iso_organizations(id)"));

    // data_isolation.rs load_policies decodes (id, name, resource,
    // conditions, actions, effect); isolation configs are keyed by
    // workspace_id and updated with current_level/migration_status.
    assert!(MIGRATION_166.contains("conditions  JSONB  NOT NULL"));
    assert!(MIGRATION_166
        .contains("workspace_id       TEXT        PRIMARY KEY REFERENCES iso_workspaces(id)"));

    // encryption.rs binds key_material as bytes and expires_at on every
    // insert; rotation keeps one active key per organization.
    assert!(MIGRATION_167.contains("key_material     BYTEA       NOT NULL"));
    assert!(MIGRATION_167.contains("expires_at       TIMESTAMPTZ NOT NULL"));
    assert!(MIGRATION_167.contains("WHERE status = 'active'"));

    // data_isolation.rs audit_access_attempt INSERTs the ten-column
    // decision row; organization/workspace FKs stay in the iso_* TEXT id
    // domain and retention cleanup scans created_at.
    assert!(MIGRATION_195
        .contains("organization_id     TEXT        NOT NULL REFERENCES iso_organizations(id)"));
    assert!(MIGRATION_195.contains("context             JSONB       NOT NULL"));
    assert!(MIGRATION_195.contains("idx_iso_access_attempts_created_at"));

    // encryption.rs create_policy/load_policies use the seven-column policy
    // contract; resource is the policy ownership identity (UNIQUE), the
    // rotation window must be positive.
    assert!(MIGRATION_196.contains("resource          TEXT        NOT NULL UNIQUE"));
    assert!(MIGRATION_196
        .contains("key_rotation_days BIGINT      NOT NULL CHECK (key_rotation_days > 0)"));
    assert!(MIGRATION_196.contains("enabled           BOOLEAN     NOT NULL DEFAULT true"));
}
