//! F63 regression test: the canonical migration 160 must define every table
//! the edge-cases crate's SQL touches, with the exact column names/types the
//! code binds and reads. If this file fails after 160 was renamed or
//! reshaped, the crate's persistence contract has drifted from the canonical
//! schema — update the migration (or this test) deliberately, never silently.

const MIGRATION_160: &str = include_str!("../../../migrations/160_edge_case_services.sql");

#[test]
fn migration_160_defines_edge_case_tables() {
    for table in [
        "edge_attachment_scans",
        "edge_calendar_events",
        "edge_delivery_attempts",
        "edge_domain_capabilities",
    ] {
        assert!(
            MIGRATION_160.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "migration 160 must create {table}"
        );
    }
}

#[test]
fn migration_160_matches_column_types_bound_by_code() {
    // attachment.rs record_scan_result binds errors/warnings as JSON values
    // and virus_name as Option<String>.
    assert!(MIGRATION_160.contains("virus_name    TEXT"));
    assert!(MIGRATION_160.contains("errors        JSONB       NOT NULL"));

    // calendar.rs store_event: location is Option, attendee_count is i32.
    assert!(MIGRATION_160.contains("location        TEXT"));
    assert!(MIGRATION_160.contains("attendee_count  INTEGER     NOT NULL"));

    // delivery.rs get_delivery_history decodes mx_priority/response_code as
    // i16 (SMALLINT), attempt_number as i32, duration_ms as i64.
    assert!(MIGRATION_160.contains("attempt_number   INTEGER     NOT NULL"));
    assert!(MIGRATION_160.contains("mx_priority      SMALLINT    NOT NULL"));
    assert!(MIGRATION_160.contains("response_code    SMALLINT    NOT NULL"));
    assert!(MIGRATION_160.contains("duration_ms      BIGINT      NOT NULL"));

    // eai.rs update_domain_capability upserts ON CONFLICT (domain).
    assert!(MIGRATION_160.contains("domain              TEXT        PRIMARY KEY"));
    assert!(MIGRATION_160.contains("supports_smtputf8   BOOLEAN     NOT NULL"));
}
