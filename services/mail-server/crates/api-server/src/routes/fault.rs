//! Test-only fault injection for adversarial route tests.
//!
//! Every helper here arms a database-level fault inside the CALLER's
//! per-test canonical database (`crate::test_db::canonical_pool` — each test
//! provisions its own throwaway database, so armed triggers and renamed
//! tables never leak between tests and need no cleanup).
//!
//! Two modes, both driven by a statement-level trigger:
//!
//! * **raise mode** ([`arm_write_fault`]): the Nth statement executed against
//!   `table` (INSERT/UPDATE/DELETE) fails with a database error. This is how
//!   a handler's `?` arm on its 2nd, 3rd, … write is reached — the earlier
//!   writes succeed, then the armed statement raises, flipping the flag
//!   "mid-handler".
//!
//! * **rename mode** ([`arm_rename_after_write`], [`hide_table`]): the victim
//!   table disappears (42P01). [`hide_table`] covers a handler whose FIRST
//!   statement reads the table; [`arm_rename_after_write`] covers a LATER
//!   read: an earlier write to a different table commits the rename, so the
//!   handler's subsequent SELECT of the victim fails.

#![cfg(test)]

use sqlx::PgPool;

const STATE_TABLE: &str = "_fault_injection_state";
const FUNCTION: &str = "_fault_injection_trigger_fn";

/// Install (idempotently) the shared state table and trigger function.
async fn ensure_machinery(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {STATE_TABLE} (\
             tag TEXT PRIMARY KEY, \
             fires INT NOT NULL DEFAULT 0, \
             skip INT NOT NULL, \
             victim TEXT, \
             done BOOLEAN NOT NULL DEFAULT FALSE)"
    ))
    .execute(pool)
    .await?;

    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION {FUNCTION}() RETURNS trigger AS $body$ \
         DECLARE \
           st {STATE_TABLE}%ROWTYPE; \
         BEGIN \
           SELECT * INTO st FROM {STATE_TABLE} WHERE tag = TG_ARGV[0]; \
           IF NOT FOUND THEN \
             RETURN NULL; \
           END IF; \
           IF st.victim IS NOT NULL THEN \
             IF st.fires >= st.skip AND NOT st.done THEN \
               EXECUTE format('ALTER TABLE %I RENAME TO %I', st.victim, st.victim || '_fi_hidden'); \
               UPDATE {STATE_TABLE} SET done = TRUE WHERE tag = TG_ARGV[0]; \
             END IF; \
             RETURN NULL; \
           END IF; \
           UPDATE {STATE_TABLE} SET fires = fires + 1 WHERE tag = TG_ARGV[0]; \
           IF st.fires >= st.skip THEN \
             RAISE EXCEPTION 'fault-injected database failure (tag=%, table=%)', \
               TG_ARGV[0], TG_TABLE_NAME; \
           END IF; \
           RETURN NULL; \
         END; \
         $body$ LANGUAGE plpgsql"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

/// Arm a statement-level trigger on `table`: the first `skip` writes succeed,
/// every write from the (`skip` + 1)-th on fails with a database error.
///
/// Statement-level counting means a multi-row INSERT is ONE fire — to make
/// the second INSERT of a handler fail, pass `skip: 1`.
///
/// `tag` must be unique per armed trigger within the test's database.
pub(crate) async fn arm_write_fault(
    pool: &PgPool,
    table: &str,
    tag: &str,
    skip: usize,
) -> Result<(), sqlx::Error> {
    ensure_machinery(pool).await?;
    let trigger = format!("_fi_{tag}");
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
        .execute(pool)
        .await?;
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT OR UPDATE OR DELETE ON {table} \
         FOR EACH STATEMENT EXECUTE FUNCTION {FUNCTION}('{tag}')"
    ))
    .execute(pool)
    .await?;
    sqlx::query(&format!(
        "INSERT INTO {STATE_TABLE} (tag, skip, victim) VALUES ($1, $2, NULL) \
         ON CONFLICT (tag) DO UPDATE SET skip = EXCLUDED.skip, victim = NULL, done = FALSE"
    ))
    .bind(tag)
    .bind(skip as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// Arm a DELETE-only statement-level trigger on `table`: the first `skip`
/// DELETE statements succeed, every DELETE from the (`skip` + 1)-th fails.
/// Use when other code (middleware, auto-provisioning) legitimately writes
/// the same table during the request and only the handler's DELETE should
/// fail.
pub(crate) async fn arm_delete_fault(
    pool: &PgPool,
    table: &str,
    tag: &str,
    skip: usize,
) -> Result<(), sqlx::Error> {
    ensure_machinery(pool).await?;
    let trigger = format!("_fi_{tag}");
    sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
        .execute(pool)
        .await?;
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON {table} \
         FOR EACH STATEMENT EXECUTE FUNCTION {FUNCTION}('{tag}')"
    ))
    .execute(pool)
    .await?;
    sqlx::query(&format!(
        "INSERT INTO {STATE_TABLE} (tag, skip, victim) VALUES ($1, $2, NULL) \
         ON CONFLICT (tag) DO UPDATE SET skip = EXCLUDED.skip, victim = NULL, done = FALSE"
    ))
    .bind(tag)
    .bind(skip as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// Rename `table` to `{table}_fi_hidden` immediately: the next statement that
/// references it fails with 42P01. For reaching the `?` arm of a handler's
/// FIRST statement.
pub(crate) async fn hide_table(pool: &PgPool, table: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "ALTER TABLE IF EXISTS {table} RENAME TO {table}_fi_hidden"
    ))
    .execute(pool)
    .await?;
    Ok(())
}
