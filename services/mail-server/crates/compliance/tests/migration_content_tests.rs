//! F63 regression test: the canonical migration 168 must define the
//! contact_persons table that estonia_ou.rs register_contact_person writes
//! (INSERT ... ON CONFLICT (email) ... RETURNING). If this file fails after
//! 168 was renamed or reshaped, the crate's persistence contract has drifted
//! from the canonical schema — update the migration (or this test)
//! deliberately, never silently.

const MIGRATION_168: &str = include_str!("../../../migrations/168_compliance_contact_persons.sql");

#[test]
fn migration_168_defines_contact_persons() {
    assert!(
        MIGRATION_168.contains("CREATE TABLE IF NOT EXISTS contact_persons"),
        "migration 168 must create contact_persons"
    );

    // register_contact_person upserts ON CONFLICT (email) and binds
    // personal_code / phone as Option<&str>; registry_code is written as the
    // literal company registry code.
    assert!(MIGRATION_168.contains("email             TEXT        NOT NULL UNIQUE"));
    assert!(MIGRATION_168.contains("personal_code     TEXT"));
    assert!(MIGRATION_168.contains("phone             TEXT"));
    assert!(MIGRATION_168.contains("registry_code     VARCHAR(20) NOT NULL"));

    // record_contact_person_verification stores a contact-person id in
    // compliance_deadlines.submission_id; the migration must reconcile the
    // 079 cross-table FK so that UPDATE is not rejected.
    assert!(
        MIGRATION_168.contains("DROP CONSTRAINT %I"),
        "migration 168 must drop the compliance_deadlines.submission_id FK"
    );
}
