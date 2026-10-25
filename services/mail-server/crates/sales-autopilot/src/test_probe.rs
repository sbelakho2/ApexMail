//! Statement-level INSERT probes for batch-write regression tests.
//!
//! A statement-level trigger cannot observe SELECTs, but batch INSERT fixes
//! need exactly that: "N logical rows are now written by ONE statement, not N
//! statements". Each installed trigger appends one row per distinct probe key
//! (tenant id, campaign id, …) it sees in the statement's transition table, so
//! tests sharing the canonical database never count each other's writes, they
//! filter by their own unique key.
//!
//! Installation is serialized with a PostgreSQL advisory lock so concurrent
//! test processes cannot race the DDL. Triggers are idempotent and only write
//! to `test_stmt_probe`; they do not change the probed table's behaviour.

use sqlx::PgPool;

/// Ensure the probe table, function and one INSERT statement trigger exist.
pub(crate) async fn install_insert_probe(pool: &PgPool, table: &str, key_column: &str) {
    assert_identifier(table);
    assert_identifier(key_column);
    let mut tx = pool
        .begin()
        .await
        .expect("begin probe installation transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('sales_autopilot_test_stmt_probe'))")
        .execute(&mut *tx)
        .await
        .expect("serialize probe installation");
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_stmt_probe (
             table_name TEXT NOT NULL,
             op TEXT NOT NULL,
             probe_key TEXT NOT NULL
         )",
    )
    .execute(&mut *tx)
    .await
    .expect("create test_stmt_probe");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION test_stmt_probe_insert_fn() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             EXECUTE format(
                 'INSERT INTO test_stmt_probe (table_name, op, probe_key)
                  SELECT %L, %L, NULLIF(%I::text, '''')
                  FROM new_rows WHERE %I IS NOT NULL GROUP BY 3',
                 TG_TABLE_NAME, TG_OP, TG_ARGV[0], TG_ARGV[0]);
             RETURN NULL;
         END
         $$",
    )
    .execute(&mut *tx)
    .await
    .expect("create test_stmt_probe_insert_fn");
    sqlx::query(&format!(
        "DROP TRIGGER IF EXISTS test_stmt_probe_insert ON {table}"
    ))
    .execute(&mut *tx)
    .await
    .expect("drop existing probe trigger");
    sqlx::query(&format!(
        "CREATE TRIGGER test_stmt_probe_insert
         AFTER INSERT ON {table}
         REFERENCING NEW TABLE AS new_rows
         FOR EACH STATEMENT EXECUTE FUNCTION test_stmt_probe_insert_fn('{key_column}')"
    ))
    .execute(&mut *tx)
    .await
    .expect("create statement-level probe trigger");
    tx.commit().await.expect("commit probe installation");
}

/// Forget the statements recorded for one `(table, key)`.
pub(crate) async fn reset_probe(pool: &PgPool, table: &str, key: &str) {
    sqlx::query("DELETE FROM test_stmt_probe WHERE table_name = $1 AND probe_key = $2")
        .bind(table)
        .bind(key)
        .execute(pool)
        .await
        .expect("reset statement probe");
}

/// How many INSERT statements touched `key` in `table` since the last reset.
pub(crate) async fn probe_count(pool: &PgPool, table: &str, key: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_stmt_probe WHERE table_name = $1 AND probe_key = $2",
    )
    .bind(table)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("read statement probe")
}

fn assert_identifier(value: &str) {
    assert!(
        !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "probe identifier must be a plain SQL identifier: {value:?}"
    );
}
