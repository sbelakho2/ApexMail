//! Compaction worker – hot→cold migration, batch deletes, checksums.

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{debug, info};

use crate::config::CompactionConfig;
use crate::types::*;

pub struct CompactionWorker {
    pool: PgPool,
    redis: deadpool_redis::Pool,
    config: CompactionConfig,
    storage_path: String,
    /// #201: Stores the unique owner value for the distributed lock.
    lock_owner: tokio::sync::Mutex<Option<String>>,
}

impl CompactionWorker {
    pub fn new(
        pool: PgPool,
        redis: deadpool_redis::Pool,
        config: CompactionConfig,
        storage_path: String,
    ) -> Self {
        Self {
            pool,
            redis,
            config,
            storage_path,
            lock_owner: tokio::sync::Mutex::new(None),
        }
    }

    /// Run full compaction cycle: hot→cold migration + cold retention cleanup.
    pub async fn run(&self) -> anyhow::Result<CompactionStatus> {
        let lock_key = format!("compaction:lock:{}", Utc::now().format("%Y-%m-%d"));
        if !self.acquire_lock(&lock_key).await? {
            info!("Compaction already running, skipping");
            return Ok(CompactionStatus {
                rows_migrated: 0,
                rows_deleted: 0,
                bytes_written: 0,
                checksum: String::new(),
                completed: false,
            });
        }

        let result = self.compact_hot_to_cold().await;

        self.release_lock(&lock_key).await.ok();

        result
    }

    /// Migrate events older than hot_retention_days from Postgres to cold storage (JSONL).
    async fn compact_hot_to_cold(&self) -> anyhow::Result<CompactionStatus> {
        let cutoff = Utc::now() - Duration::days(self.config.hot_retention_days as i64);
        let batch_size = self.config.batch_size as i64;

        let mut total_migrated: i64 = 0;
        let mut total_deleted: i64 = 0;
        let mut total_bytes: u64 = 0;
        let mut hasher = Sha256::new();

        loop {
            let rows = sqlx::query_as::<_, EventRow>(
                "SELECT id, tenant_id, message_id, event_type, recipient, timestamp, \
                 metadata, ip_address, user_agent, link_id, bounce_type, bounce_subtype, \
                 provider, region, campaign_id \
                 FROM events WHERE timestamp < $1 ORDER BY timestamp LIMIT $2",
            )
            .bind(cutoff)
            .bind(batch_size)
            .fetch_all(&self.pool)
            .await?;

            if rows.is_empty() {
                break;
            }

            let count = rows.len() as i64;
            let (bytes, batch_data) = self.write_jsonl_batch(&rows).await?;
            hasher.update(&batch_data);
            total_bytes += bytes;

            // Delete migrated rows
            let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
            sqlx::query("DELETE FROM events WHERE id = ANY($1)")
                .bind(&ids)
                .execute(&self.pool)
                .await?;

            total_migrated += count;
            total_deleted += count;
            debug!("Compacted batch of {count} rows");

            if count < batch_size {
                break;
            }
        }

        let checksum = format!("{:x}", hasher.finalize());
        info!("Compaction complete: migrated={total_migrated}, bytes={total_bytes}");

        // Cold retention cleanup
        if self.config.cold_retention_days > 0 {
            self.cleanup_cold_storage().await?;
        }

        Ok(CompactionStatus {
            rows_migrated: total_migrated,
            rows_deleted: total_deleted,
            bytes_written: total_bytes,
            checksum,
            completed: true,
        })
    }

    /// Serialize batch of events to JSONL and write to storage path.
    /// #182: Use tokio::task::spawn_blocking to avoid blocking the Tokio runtime.
    async fn write_jsonl_batch(&self, rows: &[EventRow]) -> anyhow::Result<(u64, Vec<u8>)> {
        let mut buf = Vec::new();
        for row in rows {
            let line = serde_json::to_vec(row)?;
            buf.extend_from_slice(&line);
            buf.push(b'\n');
        }

        if let Some(first) = rows.first() {
            let date = first.timestamp.format("%Y/%m");
            let dir = format!("{}/{}/{}", self.storage_path, first.tenant_id, date);
            let filename = format!(
                "{}/events_{}.jsonl",
                dir,
                Utc::now().timestamp_millis()
            );
            let buf_clone = buf.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&filename, &buf_clone)?;
                Ok(())
            })
            .await??;
            debug!("Wrote cold storage batch ({} bytes)", buf.len());
        }

        let len = buf.len() as u64;
        Ok((len, buf))
    }

    /// Remove cold storage files older than cold_retention_days.
    /// #182: Use spawn_blocking to avoid blocking async context.
    async fn cleanup_cold_storage(&self) -> anyhow::Result<()> {
        let cutoff = Utc::now() - Duration::days(self.config.cold_retention_days as i64);
        let cutoff_year_month = cutoff.format("%Y/%m").to_string();
        let storage_path = self.storage_path.clone();

        info!("Cold storage cleanup: removing files before {cutoff_year_month}");

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            if let Ok(entries) = std::fs::read_dir(&storage_path) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                        cleanup_tenant_dir_sync(&entry.path(), &cutoff_year_month)?;
                    }
                }
            }
            Ok(())
        })
        .await?
    }

    /// Acquire distributed lock via Redis SET NX EX.
    /// #201: Store a unique owner value so release_lock only deletes our own lock.
    async fn acquire_lock(&self, key: &str) -> anyhow::Result<bool> {
        let owner = format!("{}:{}", std::process::id(), Utc::now().timestamp_millis());
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let result: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(&owner)
            .arg("NX")
            .arg("EX")
            .arg(3600_u64)
            .query_async(&mut *conn)
            .await?;
        if result.is_some() {
            // Store owner so release_lock can verify
            self.lock_owner.lock().await.replace(owner);
        }
        Ok(result.is_some())
    }

    /// Release lock only if we still own it (compare-and-delete via Lua script).
    async fn release_lock(&self, key: &str) -> anyhow::Result<()> {
        let owner = self.lock_owner.lock().await.take();
        let owner = match owner {
            Some(o) => o,
            None => return Ok(()), // We never acquired the lock
        };
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        // Atomic compare-and-delete
        let script = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            else
                return 0
            end
        "#;
        let _: i64 = redis::cmd("EVAL")
            .arg(script)
            .arg(1i32)
            .arg(key)
            .arg(&owner)
            .query_async(&mut *conn)
            .await?;
        Ok(())
    }
}

/// Free-standing directory cleanup (used inside spawn_blocking).
fn cleanup_tenant_dir_sync(
    tenant_dir: &std::path::Path,
    cutoff_ym: &str,
) -> anyhow::Result<()> {
    if let Ok(years) = std::fs::read_dir(tenant_dir) {
        for year_entry in years.flatten() {
            if let Ok(months) = std::fs::read_dir(year_entry.path()) {
                for month_entry in months.flatten() {
                    let year_name = year_entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    let month_name = month_entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    let ym = format!("{year_name}/{month_name}");
                    if ym.as_str() < cutoff_ym {
                        info!("Removing old cold storage: {}", month_entry.path().display());
                        std::fs::remove_dir_all(month_entry.path())?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Compute SHA-256 checksum for data.
pub fn compute_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_checksum() {
        let data = b"hello world";
        let checksum = compute_checksum(data);
        assert_eq!(checksum.len(), 64);
        // known SHA-256 of "hello world"
        assert_eq!(
            checksum,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_checksum_deterministic() {
        let data = b"test data for compaction";
        let c1 = compute_checksum(data);
        let c2 = compute_checksum(data);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_compaction_status_defaults() {
        let status = CompactionStatus {
            rows_migrated: 0,
            rows_deleted: 0,
            bytes_written: 0,
            checksum: String::new(),
            completed: false,
        };
        assert!(!status.completed);
    }

    #[test]
    fn test_checksum_empty() {
        let checksum = compute_checksum(b"");
        // SHA-256 of empty string
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
