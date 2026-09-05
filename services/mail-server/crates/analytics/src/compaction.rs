//! Compaction worker – hot→cold migration, batch deletes, checksums.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
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
    /// #201:Stores the unique owner value for the distributed lock.
    lock_owner: tokio::sync::RwLock<Option<String>>,
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
            lock_owner: tokio::sync::RwLock::new(None),
        }
    }

    /// Run full compaction cycle:hot→cold migration + cold retention cleanup.
    pub async fn run(&self) -> anyhow::Result<CompactionStatus> {
        let lock_key = format!("compaction:lock:{}", Utc::now().format("%Y-%m-%d"));
        if !self.acquire_lock(&lock_key).await? {
            info!("Compaction already running, skipping");
            return Ok(CompactionStatus {
                rows_migrated: 0,
                rows_deleted: 0,
                bytes_written: 0,
                checksum: "skipped-lock-held".to_string(),
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

        // Process compaction per-tenant to prevent a single noisy tenant from
        // blocking compaction for all others (M-36).
        let tenants: Vec<String> = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT tenant_id FROM events WHERE timestamp < $1",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        if tenants.is_empty() {
            return Ok(CompactionStatus {
                rows_migrated: 0,
                rows_deleted: 0,
                bytes_written: 0,
                checksum: format!("{:x}", hasher.finalize()),
                completed: true,
            });
        }

        for tenant_id in &tenants {
            debug!(tenant_id = %tenant_id, "compacting tenant events");

            // F13:ids already manifested in a previous (possibly crashed) run.
            // A crash between the JSONL write and the DELETE used to duplicate
            // cold rows on rerun — manifested ids are never re-written.
            let mut manifested = load_manifested_ids(&self.storage_path, tenant_id).await;

            loop {
                let rows = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    sqlx::query_as::<_, EventRow>(
                        "SELECT id, tenant_id, message_id, event_type, recipient, timestamp, \
                         metadata, ip_address, user_agent, link_id, bounce_type, bounce_subtype, \
                         provider, region, campaign_id \
                         FROM events WHERE tenant_id = $1 AND timestamp < $2 \
                         ORDER BY timestamp LIMIT $3",
                    )
                    .bind(tenant_id)
                    .bind(cutoff)
                    .bind(batch_size)
                    .fetch_all(&self.pool),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Timed out fetching compaction batch for tenant {}",
                        tenant_id
                    )
                })??;

                if rows.is_empty() {
                    break;
                }

                // F13:split the batch — ids already manifested (a previous run
                // wrote the cold copy but died before the DELETE) skip the
                // JSONL write; they still get deleted below to finish the
                // interrupted migration.
                let pending: Vec<&EventRow> = rows
                    .iter()
                    .filter(|r| !manifested.contains(&r.id))
                    .collect();
                let count = pending.len() as i64;

                if !pending.is_empty() {
                    // Manifest BEFORE the DELETE:once the (ids + file) pair is
                    // on disk, a crash at any later point is recoverable — the
                    // rerun sees the ids manifested and only deletes them.
                    // Residual window: a crash between the JSONL write and the
                    // manifest write can duplicate one batch in cold storage;
                    // the ids then manifest on the rerun, so it happens at
                    // most once per crash.
                    let (bytes, batch_data, file) = self.write_jsonl_batch(&pending).await?;
                    hasher.update(&batch_data);
                    total_bytes += bytes;

                    let dir = jsonl_dir(&self.storage_path, pending[0]);
                    write_batch_manifest(&dir, &file, pending.iter().map(|r| r.id)).await?;
                    manifested.extend(pending.iter().map(|r| r.id));
                }

                // Delete migrated rows (both fresh writes and ids whose cold
                // copy already existed from an interrupted run).
                let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
                sqlx::query("DELETE FROM events WHERE id = ANY($1)")
                    .bind(&ids)
                    .execute(&self.pool)
                    .await?;

                total_migrated += count;
                total_deleted += rows.len() as i64;
                debug!(tenant_id = %tenant_id, "Compacted batch of {} rows", rows.len());

                if (rows.len() as i64) < batch_size {
                    break;
                }
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
    /// #182:Use tokio::task::spawn_blocking to avoid blocking the Tokio runtime.
    ///
    /// GDPR:the cold copy stores the MASKED client IP (IPv4 → /24, IPv6 →
    /// /48 — see [`crate::ip_mask`]); the 730-day cold tier must not retain
    /// a full address.
    ///
    /// Returns `(bytes_written, batch_bytes_for_checksum, filename)`.
    async fn write_jsonl_batch(
        &self,
        rows: &[&EventRow],
    ) -> anyhow::Result<(u64, Vec<u8>, String)> {
        let mut buf = Vec::with_capacity(rows.len().saturating_mul(256));
        for row in rows {
            let mut masked = (*row).clone();
            masked.ip_address = crate::ip_mask::mask_ip_opt(row.ip_address.as_deref());
            let line = serde_json::to_vec(&masked)?;
            buf.extend_from_slice(&line);
            buf.push(b'\n');
        }

        let mut filename = String::new();
        if let Some(first) = rows.first() {
            let dir = jsonl_dir(&self.storage_path, first);
            filename = format!("events_{}.jsonl", Utc::now().timestamp_millis());
            let path = format!("{dir}/{filename}");
            let buf_clone = buf.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&path, &buf_clone)?;
                Ok(())
            })
            .await??;
            debug!("Wrote cold storage batch ({} bytes)", buf.len());
        }

        let len = buf.len() as u64;
        Ok((len, buf, filename))
    }

    /// Remove cold storage files older than cold_retention_days.
    /// #182:Use spawn_blocking to avoid blocking async context.
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
    /// #201:Store a unique owner value so release_lock only deletes our own lock.
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
            self.lock_owner.write().await.replace(owner);
        }
        Ok(result.is_some())
    }

    /// Release lock only if we still own it (compare-and-delete via Lua script).
    async fn release_lock(&self, key: &str) -> anyhow::Result<()> {
        let owner = self.lock_owner.write().await.take();
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
fn cleanup_tenant_dir_sync(tenant_dir: &std::path::Path, cutoff_ym: &str) -> anyhow::Result<()> {
    if let Ok(years) = std::fs::read_dir(tenant_dir) {
        for year_entry in years.flatten() {
            if let Ok(months) = std::fs::read_dir(year_entry.path()) {
                for month_entry in months.flatten() {
                    let year_name = year_entry.file_name().to_string_lossy().to_string();
                    let month_name = month_entry.file_name().to_string_lossy().to_string();
                    let ym = format!("{year_name}/{month_name}");
                    if ym.as_str() < cutoff_ym {
                        info!(
                            "Removing old cold storage: {}",
                            month_entry.path().display()
                        );
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

// ── Batch manifests (F13:idempotent compaction) ──────────────────────────────

/// Per-batch manifest recording WHICH event ids were written to WHICH cold
/// file. Written after the JSONL write but BEFORE the Postgres DELETE, so a
/// crash between file-write and delete never duplicates cold rows on rerun:
/// the rerun loads the manifested ids, skips re-writing them, and only
/// completes the DELETE.
#[derive(Debug, Serialize, Deserialize)]
struct BatchManifest {
    /// Cold JSONL file name (inside the manifest's own directory).
    file: String,
    /// Event ids contained in that file.
    ids: Vec<uuid::Uuid>,
}

/// Directory a batch's JSONL (+ manifest) lives in:
/// `{storage}/{tenant}/{YYYY/MM}` (by the first row's timestamp).
fn jsonl_dir(storage_path: &str, first_row: &EventRow) -> String {
    let date = first_row.timestamp.format("%Y/%m");
    format!("{}/{}/{}", storage_path, first_row.tenant_id, date)
}

/// Write the manifest for a just-written batch (spawn_blocking; same dir as
/// the JSONL so retention cleanup removes them together).
async fn write_batch_manifest(
    dir: &str,
    file: &str,
    ids: impl Iterator<Item = uuid::Uuid>,
) -> anyhow::Result<()> {
    let manifest = BatchManifest {
        file: file.to_string(),
        ids: ids.collect(),
    };
    let path = format!("{}/{}.manifest.json", dir, file.trim_end_matches(".jsonl"));
    let data = serde_json::to_vec(&manifest)?;
    let dir = dir.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, &data)?;
        Ok(())
    })
    .await??;
    Ok(())
}

/// Parse a manifest file's bytes (testable / used by [`load_manifested_ids`]).
fn parse_manifest(data: &[u8]) -> Option<BatchManifest> {
    serde_json::from_slice(data).ok()
}

/// Load all event ids already manifested for a tenant (scans every
/// `*.manifest.json` under the tenant's storage tree). Missing directories
/// or unreadable/corrupt manifests are skipped — a corrupt manifest costs a
/// possible cold duplicate for those ids, never data loss.
///
/// The scan is a blocking `std::fs` tree walk, so it runs on the blocking
/// pool (audit: it used to run directly on the async runtime thread); a
/// panic inside the blocking task degrades to an empty set (same
/// fail-open semantics as an unreadable manifest).
async fn load_manifested_ids(
    storage_path: &str,
    tenant_id: &str,
) -> std::collections::HashSet<uuid::Uuid> {
    let storage_path = storage_path.to_string();
    let tenant_id = tenant_id.to_string();
    tokio::task::spawn_blocking(move || scan_manifested_ids(&storage_path, &tenant_id))
        .await
        .unwrap_or_default()
}

/// Synchronous core of [`load_manifested_ids`] (runs on the blocking pool).
fn scan_manifested_ids(
    storage_path: &str,
    tenant_id: &str,
) -> std::collections::HashSet<uuid::Uuid> {
    let mut ids = std::collections::HashSet::new();
    let tenant_dir = std::path::Path::new(storage_path).join(tenant_id);
    let year_entries = match std::fs::read_dir(&tenant_dir) {
        Ok(entries) => entries,
        Err(_) => return ids,
    };
    for year in year_entries.flatten() {
        let months = match std::fs::read_dir(year.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        for month in months.flatten() {
            let files = match std::fs::read_dir(month.path()) {
                Ok(f) => f,
                Err(_) => continue,
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().to_string();
                if !name.ends_with(".manifest.json") {
                    continue;
                }
                if let Ok(data) = std::fs::read(file.path()) {
                    if let Some(manifest) = parse_manifest(&data) {
                        ids.extend(manifest.ids);
                    }
                }
            }
        }
    }
    ids
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

    // ── F13:idempotent compaction manifests ───────────────────────────

    fn example_row(id: uuid::Uuid, ip: Option<&str>) -> EventRow {
        EventRow {
            id,
            tenant_id: "tenant_a".into(),
            message_id: "msg_1".into(),
            event_type: "opened".into(),
            recipient: "user@example.com".into(),
            timestamp: Utc::now(),
            metadata: None,
            ip_address: ip.map(String::from),
            user_agent: None,
            link_id: None,
            bounce_type: None,
            bounce_subtype: None,
            provider: None,
            region: None,
            campaign_id: None,
        }
    }

    #[test]
    fn manifest_roundtrips_through_json() {
        let ids: Vec<uuid::Uuid> = vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let manifest = BatchManifest {
            file: "events_123.jsonl".into(),
            ids: ids.clone(),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let parsed = parse_manifest(&bytes).expect("manifest must parse");
        assert_eq!(parsed.file, "events_123.jsonl");
        assert_eq!(parsed.ids, ids);
    }

    #[test]
    fn corrupt_manifest_is_skipped_not_fatal() {
        assert!(parse_manifest(b"not json").is_none());
        assert!(parse_manifest(b"{\"file\":123}").is_none());
    }

    /// A crash between JSONL write and DELETE must not duplicate cold rows on
    /// rerun:the rerun loads the manifested ids and skips re-writing them.
    /// Drives the async wrapper so the blocking-pool path is exercised.
    #[tokio::test]
    async fn load_manifested_ids_finds_written_manifests() {
        let root = std::env::temp_dir().join(format!(
            "apexmail_compact_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let dir = root.join("tenant_a/2026/08");
        std::fs::create_dir_all(&dir).unwrap();

        let ids: Vec<uuid::Uuid> = vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let manifest = BatchManifest {
            file: "events_1.jsonl".into(),
            ids: ids.clone(),
        };
        std::fs::write(
            dir.join("events_1.manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        // Non-manifest files must be ignored.
        std::fs::write(dir.join("events_1.jsonl"), b"{}\n").unwrap();

        let loaded = load_manifested_ids(root.to_str().unwrap(), "tenant_a").await;
        assert_eq!(loaded.len(), 2);
        for id in &ids {
            assert!(loaded.contains(id));
        }

        // A different tenant / missing tree yields an empty set.
        assert!(load_manifested_ids(root.to_str().unwrap(), "tenant_b")
            .await
            .is_empty());
        assert!(
            load_manifested_ids(root.join("nope").to_str().unwrap(), "tenant_a")
                .await
                .is_empty()
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// GDPR:the cold JSONL line carries the MASKED IP, never the full one.
    #[test]
    fn cold_jsonl_line_masks_client_ip() {
        let row = example_row(uuid::Uuid::new_v4(), Some("203.0.113.178"));
        let mut masked = row.clone();
        masked.ip_address = crate::ip_mask::mask_ip_opt(row.ip_address.as_deref());
        let line = serde_json::to_string(&masked).unwrap();
        assert!(line.contains("203.0.113.0"), "{line}");
        assert!(!line.contains("203.0.113.178"), "{line}");

        let none_row = example_row(uuid::Uuid::new_v4(), None);
        assert!(serde_json::to_string(&none_row)
            .unwrap()
            .contains("\"ip_address\":null"));
    }
}
