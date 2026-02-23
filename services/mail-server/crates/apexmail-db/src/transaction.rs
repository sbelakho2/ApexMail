//! Transaction helper wrapping `sqlx::Transaction`.
//!
//! Provides a convenient RAII wrapper that automatically rolls back on drop
//! unless explicitly committed.

use sqlx::{PgPool, Postgres, Transaction};

/// A convenience wrapper around a PostgreSQL transaction.
pub struct Tx {
    inner: Option<Transaction<'static, Postgres>>,
}

impl Tx {
    /// Begin a new transaction from the pool.
    pub async fn begin(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let tx = pool.begin().await?;
        Ok(Self { inner: Some(tx) })
    }

    /// Get a mutable reference to the inner transaction (for passing to queries).
    pub fn as_mut(&mut self) -> &mut Transaction<'static, Postgres> {
        self.inner.as_mut().expect("transaction already consumed")
    }

    /// Commit the transaction.
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        if let Some(tx) = self.inner.take() {
            tx.commit().await?;
        }
        Ok(())
    }

    /// Explicitly roll back.
    pub async fn rollback(mut self) -> Result<(), sqlx::Error> {
        if let Some(tx) = self.inner.take() {
            tx.rollback().await?;
        }
        Ok(())
    }
}

/// Drop rolls back automatically if the transaction was neither committed nor rolled back.
impl Drop for Tx {
    fn drop(&mut self) {
        // sqlx::Transaction's own Drop already triggers an async rollback,
        // so we just let it happen. This impl exists for documentation clarity.
    }
}

/// Execute a closure inside a transaction.  
/// If the closure returns `Ok`, the tx is committed; on `Err` it is rolled back.
pub async fn with_transaction<F, Fut, T>(pool: &PgPool, f: F) -> Result<T, sqlx::Error>
where
    F: FnOnce(Tx) -> Fut,
    Fut: std::future::Future<Output = Result<(Tx, T), sqlx::Error>>,
{
    let tx = Tx::begin(pool).await?;
    match f(tx).await {
        Ok((tx, value)) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_struct_creation() {
        // Tx without a real connection — just verifying the type compiles.
        let tx = Tx { inner: None };
        assert!(tx.inner.is_none());
    }

    #[test]
    fn test_tx_drop_without_panic() {
        let tx = Tx { inner: None };
        drop(tx); // Should not panic.
    }
}
