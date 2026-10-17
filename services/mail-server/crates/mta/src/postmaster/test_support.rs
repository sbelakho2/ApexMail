//! Test-only per-STATEMENT DML counters for the postmaster bulk-upsert tests.
//!
//! A `FOR EACH STATEMENT` trigger bumps the counter once per INSERT/UPDATE/
//! DELETE statement (not once per row), which is what distinguishes a batched
//! upsert from the old per-row loop: both write the same rows, only the
//! statement count differs.

use sqlx::PgPool;

/// Install (or replace) the statement-count trigger on `tables`.
pub(crate) async fn install_statement_counters(pool: &PgPool, tables: &[&str]) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _apexmail_test_stmt_counts (
             probed_table TEXT NOT NULL,
             op TEXT NOT NULL,
             statements BIGINT NOT NULL DEFAULT 0,
             PRIMARY KEY (probed_table, op)
         )",
    )
    .execute(pool)
    .await
    .expect("create statement-count table");

    sqlx::query(
        "CREATE OR REPLACE FUNCTION _apexmail_test_count_stmt() RETURNS trigger \
         LANGUAGE plpgsql AS $$ \
         BEGIN \
           INSERT INTO _apexmail_test_stmt_counts (probed_table, op, statements) \
           VALUES (TG_TABLE_NAME, TG_OP, 1) \
           ON CONFLICT (probed_table, op) \
           DO UPDATE SET statements = _apexmail_test_stmt_counts.statements + 1; \
           RETURN NULL; \
         END $$",
    )
    .execute(pool)
    .await
    .expect("create statement-count function");

    for table in tables {
        assert!(
            table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "statement counter table name must be identifier-shaped: {table}"
        );
        sqlx::query(&format!(
            "CREATE OR REPLACE TRIGGER _apexmail_test_count_stmt \
             AFTER INSERT OR UPDATE OR DELETE ON {table} \
             FOR EACH STATEMENT EXECUTE FUNCTION _apexmail_test_count_stmt()"
        ))
        .execute(pool)
        .await
        .expect("install statement-count trigger");
    }
}

/// Zero every counter (the triggers stay installed).
pub(crate) async fn reset_statement_counts(pool: &PgPool) {
    sqlx::query("UPDATE _apexmail_test_stmt_counts SET statements = 0")
        .execute(pool)
        .await
        .expect("reset statement counts");
}

/// Statements recorded for `(table, op)` (`INSERT`/`UPDATE`/`DELETE`).
pub(crate) async fn statement_count(pool: &PgPool, table: &str, op: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT statements FROM _apexmail_test_stmt_counts \
         WHERE probed_table = $1 AND op = $2",
    )
    .bind(table)
    .bind(op)
    .fetch_optional(pool)
    .await
    .expect("read statement count")
    .unwrap_or(0)
}
