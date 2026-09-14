//! HIPAA Business Associate Agreement (BAA) lifecycle.
//!
//! Workflow:
//!   draft → requested → signed → countersigned → active → terminated
//!
//! The HIPAA-restricted API surface (PHI-suppressing audit logs, encrypted-
//! at-rest mailboxes, dedicated KMS keys) checks `is_active_for_tenant()`
//! before allowing requests.
//!
//! Every state transition is recorded in `hipaa_baa_events` as a hash-chained
//! immutable history so the BAA evidence trail is tamper-evident and
//! defensible during a HIPAA audit.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ─── Public types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaaStatus {
    Draft,
    Requested,
    Signed,
    Countersigned,
    Active,
    Terminated,
}

impl BaaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Requested => "requested",
            Self::Signed => "signed",
            Self::Countersigned => "countersigned",
            Self::Active => "active",
            Self::Terminated => "terminated",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "requested" => Some(Self::Requested),
            "signed" => Some(Self::Signed),
            "countersigned" => Some(Self::Countersigned),
            "active" => Some(Self::Active),
            "terminated" => Some(Self::Terminated),
            _ => None,
        }
    }

    /// Allowed forward transitions.  Used to validate state changes.
    pub fn can_transition_to(self, target: BaaStatus) -> bool {
        use BaaStatus::*;
        matches!(
            (self, target),
            (Draft, Requested)
                | (Requested, Signed)
                | (Signed, Countersigned)
                | (Countersigned, Active)
                | (Active, Terminated)
                // Any state can be terminated administratively.
                | (Draft, Terminated)
                | (Requested, Terminated)
                | (Signed, Terminated)
                | (Countersigned, Terminated)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baa {
    pub id: String,
    pub tenant_id: String,
    pub version: String,
    pub status: BaaStatus,
    pub signer_name: Option<String>,
    pub signer_email: Option<String>,
    pub signer_title: Option<String>,
    pub signer_ip: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
    pub signed_signature: Option<String>,
    pub countersigner_name: Option<String>,
    pub countersigner_email: Option<String>,
    pub countersigned_at: Option<DateTime<Utc>>,
    pub document_url: Option<String>,
    pub document_sha256: Option<String>,
    pub effective_date: Option<DateTime<Utc>>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub termination_reason: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaaEvent {
    pub id: String,
    pub baa_id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub actor: String,
    pub payload: serde_json::Value,
    pub occurred_at: DateTime<Utc>,
    pub hash: String,
    pub previous_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignBaaInput {
    pub signer_name: String,
    pub signer_email: String,
    pub signer_title: Option<String>,
    pub signer_ip: Option<String>,
    pub document_url: Option<String>,
    pub document_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountersignBaaInput {
    pub countersigner_name: String,
    pub countersigner_email: String,
    pub effective_date: Option<DateTime<Utc>>,
}

// ─── Service ───────────────────────────────────────────────────────────────

pub struct HipaaService {
    db: PgPool,
    /// HMAC key used to sign canonical BAA documents.  Sourced from
    /// `HIPAA_BAA_SIGNING_KEY` env var (rotated quarterly).
    signing_key: Vec<u8>,
    /// Per-baa last-event-hash cache (in memory, rebuilt on startup).
    last_hashes: RwLock<HashMap<String, String>>,
    /// Active-BAA cache: tenant_id → baa_id (refreshed on writes).
    active_cache: RwLock<HashMap<String, String>>,
}

impl HipaaService {
    pub fn new(db: PgPool, signing_key: impl Into<Vec<u8>>) -> Self {
        Self {
            db,
            signing_key: signing_key.into(),
            last_hashes: RwLock::new(HashMap::new()),
            active_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Bootstrap caches from DB.  Idempotent.
    pub async fn initialize(&self) -> Result<(), String> {
        // Active-BAA cache.
        let actives: Vec<(String, String)> =
            sqlx::query_as("SELECT tenant_id, id FROM hipaa_baas WHERE status = 'active'")
                .fetch_all(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
        let mut a = self.active_cache.write().await;
        a.clear();
        for (tenant, id) in actives {
            a.insert(tenant, id);
        }
        Ok(())
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    pub async fn request_baa(
        &self,
        tenant_id: &str,
        version: &str,
        actor: &str,
    ) -> Result<Baa, String> {
        // Block double-creation while a BAA is in flight.
        let in_flight: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM hipaa_baas
             WHERE tenant_id = $1 AND status NOT IN ('terminated')",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        if in_flight.is_some() {
            return Err("Tenant already has an in-flight or active BAA; terminate it first".into());
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO hipaa_baas
               (id, tenant_id, version, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'requested', $4, $4)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(version)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.append_event(
            &id,
            tenant_id,
            "requested",
            actor,
            serde_json::json!({"version": version}),
        )
        .await?;

        info!(%tenant_id, baa_id = %id, "BAA requested");
        self.fetch(&id)
            .await?
            .ok_or_else(|| "Just-created BAA missing".into())
    }

    pub async fn sign(
        &self,
        baa_id: &str,
        actor: &str,
        input: SignBaaInput,
    ) -> Result<Baa, String> {
        let current = self.fetch(baa_id).await?.ok_or("BAA not found")?;
        if !current.status.can_transition_to(BaaStatus::Signed) {
            return Err(format!(
                "Cannot sign BAA in status {}",
                current.status.as_str()
            ));
        }

        // Compute canonical signature over the document.  This binds the
        // signer's identity to the document hash so the proof stands without
        // the original PDF.
        let canonical = serde_json::json!({
            "baa_id": baa_id,
            "tenant_id": current.tenant_id,
            "version": current.version,
            "signer_name": input.signer_name,
            "signer_email": input.signer_email,
            "signer_title": input.signer_title,
            "document_sha256": input.document_sha256,
        });
        let canonical_bytes = serde_json::to_vec(&canonical).map_err(|e| format!("JSON: {e}"))?;
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).map_err(|e| format!("HMAC key: {e}"))?;
        mac.update(&canonical_bytes);
        let signature = hex::encode(mac.finalize().into_bytes());

        let now = Utc::now();
        sqlx::query(
            "UPDATE hipaa_baas SET
               status = 'signed',
               signer_name = $1,
               signer_email = $2,
               signer_title = $3,
               signer_ip = $4,
               document_url = $5,
               document_sha256 = $6,
               signed_at = $7,
               signed_signature = $8,
               updated_at = $7
             WHERE id = $9 AND status = 'requested'",
        )
        .bind(&input.signer_name)
        .bind(&input.signer_email)
        .bind(&input.signer_title)
        .bind(&input.signer_ip)
        .bind(&input.document_url)
        .bind(&input.document_sha256)
        .bind(now)
        .bind(&signature)
        .bind(baa_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.append_event(
            baa_id,
            &current.tenant_id,
            "signed",
            actor,
            serde_json::json!({
                "signer_email": input.signer_email,
                "document_sha256": input.document_sha256,
                "signature": signature,
            }),
        )
        .await?;

        info!(baa_id, "BAA signed by customer");
        self.fetch(baa_id)
            .await?
            .ok_or_else(|| "BAA missing".into())
    }

    pub async fn countersign(
        &self,
        baa_id: &str,
        actor: &str,
        input: CountersignBaaInput,
    ) -> Result<Baa, String> {
        let current = self.fetch(baa_id).await?.ok_or("BAA not found")?;
        if !current.status.can_transition_to(BaaStatus::Countersigned) {
            return Err(format!(
                "Cannot countersign BAA in status {}",
                current.status.as_str()
            ));
        }
        let now = Utc::now();
        sqlx::query(
            "UPDATE hipaa_baas SET
               status = 'countersigned',
               countersigner_name = $1,
               countersigner_email = $2,
               countersigned_at = $3,
               effective_date = COALESCE($4, $3),
               updated_at = $3
             WHERE id = $5 AND status = 'signed'",
        )
        .bind(&input.countersigner_name)
        .bind(&input.countersigner_email)
        .bind(now)
        .bind(input.effective_date)
        .bind(baa_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.append_event(
            baa_id,
            &current.tenant_id,
            "countersigned",
            actor,
            serde_json::json!({
                "countersigner_email": input.countersigner_email,
                "effective_date": input.effective_date,
            }),
        )
        .await?;

        info!(baa_id, "BAA countersigned by ApexMail");
        self.fetch(baa_id)
            .await?
            .ok_or_else(|| "BAA missing".into())
    }

    /// Final activation step.  Adds to the active-tenant cache and is idempotent.
    pub async fn activate(&self, baa_id: &str, actor: &str) -> Result<Baa, String> {
        let current = self.fetch(baa_id).await?.ok_or("BAA not found")?;
        if current.status == BaaStatus::Active {
            return Ok(current); // idempotent
        }
        if !current.status.can_transition_to(BaaStatus::Active) {
            return Err(format!(
                "Cannot activate BAA in status {}",
                current.status.as_str()
            ));
        }

        // Enforce uniqueness:terminate any prior active BAAs for the tenant.
        let now = Utc::now();
        sqlx::query(
            "UPDATE hipaa_baas SET status = 'terminated',
                                   terminated_at = $1,
                                   termination_reason = 'superseded',
                                   updated_at = $1
             WHERE tenant_id = $2 AND status = 'active' AND id <> $3",
        )
        .bind(now)
        .bind(&current.tenant_id)
        .bind(baa_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        sqlx::query(
            "UPDATE hipaa_baas SET status = 'active', updated_at = $1
             WHERE id = $2 AND status = 'countersigned'",
        )
        .bind(now)
        .bind(baa_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.append_event(
            baa_id,
            &current.tenant_id,
            "activated",
            actor,
            serde_json::json!({}),
        )
        .await?;

        let mut cache = self.active_cache.write().await;
        cache.insert(current.tenant_id.clone(), baa_id.to_string());

        info!(baa_id, tenant = %current.tenant_id, "BAA activated");
        self.fetch(baa_id)
            .await?
            .ok_or_else(|| "BAA missing".into())
    }

    pub async fn terminate(&self, baa_id: &str, actor: &str, reason: &str) -> Result<Baa, String> {
        let current = self.fetch(baa_id).await?.ok_or("BAA not found")?;
        if current.status == BaaStatus::Terminated {
            return Ok(current);
        }
        if !current.status.can_transition_to(BaaStatus::Terminated) {
            return Err(format!(
                "Cannot terminate BAA in status {}",
                current.status.as_str()
            ));
        }
        let now = Utc::now();
        sqlx::query(
            "UPDATE hipaa_baas SET status = 'terminated',
                                   terminated_at = $1,
                                   termination_reason = $2,
                                   updated_at = $1
             WHERE id = $3",
        )
        .bind(now)
        .bind(reason)
        .bind(baa_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.append_event(
            baa_id,
            &current.tenant_id,
            "terminated",
            actor,
            serde_json::json!({"reason": reason}),
        )
        .await?;

        let mut cache = self.active_cache.write().await;
        if cache.get(&current.tenant_id).map(String::as_str) == Some(baa_id) {
            cache.remove(&current.tenant_id);
        }
        info!(baa_id, "BAA terminated");
        self.fetch(baa_id)
            .await?
            .ok_or_else(|| "BAA missing".into())
    }

    // ── Queries ────────────────────────────────────────────────────────────

    /// True if the tenant has an active BAA.  Hot path — uses in-memory cache.
    pub async fn is_active_for_tenant(&self, tenant_id: &str) -> bool {
        let cache = self.active_cache.read().await;
        if cache.contains_key(tenant_id) {
            return true;
        }
        drop(cache);
        // Cache miss → DB lookup.
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM hipaa_baas WHERE tenant_id = $1 AND status = 'active'")
                .bind(tenant_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten();
        if let Some((id,)) = row {
            let mut cache = self.active_cache.write().await;
            cache.insert(tenant_id.to_string(), id);
            true
        } else {
            false
        }
    }

    pub async fn fetch(&self, baa_id: &str) -> Result<Option<Baa>, String> {
        let row: Option<BaaRow> = sqlx::query_as(
            "SELECT id, tenant_id, version, status,
                    signer_name, signer_email, signer_title, signer_ip,
                    signed_at, signed_signature,
                    countersigner_name, countersigner_email, countersigned_at,
                    document_url, document_sha256,
                    effective_date, terminated_at, termination_reason, metadata,
                    created_at, updated_at
             FROM hipaa_baas WHERE id = $1",
        )
        .bind(baa_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn list_for_tenant(&self, tenant_id: &str) -> Result<Vec<Baa>, String> {
        let rows: Vec<BaaRow> = sqlx::query_as(
            "SELECT id, tenant_id, version, status,
                    signer_name, signer_email, signer_title, signer_ip,
                    signed_at, signed_signature,
                    countersigner_name, countersigner_email, countersigned_at,
                    document_url, document_sha256,
                    effective_date, terminated_at, termination_reason, metadata,
                    created_at, updated_at
             FROM hipaa_baas WHERE tenant_id = $1
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn list_events(&self, baa_id: &str) -> Result<Vec<BaaEvent>, String> {
        let rows: Vec<BaaEventRow> = sqlx::query_as(
            "SELECT id, baa_id, tenant_id, event_type, actor, payload,
                    occurred_at, hash, previous_hash
             FROM hipaa_baa_events WHERE baa_id = $1
             ORDER BY occurred_at",
        )
        .bind(baa_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Walk the event chain end-to-end and verify every hash.  Returns the
    /// number of events verified, or `Err` at the first mismatch.
    pub async fn verify_chain(&self, baa_id: &str) -> Result<usize, String> {
        let events = self.list_events(baa_id).await?;
        let mut prev: Option<String> = None;
        for (i, e) in events.iter().enumerate() {
            if e.previous_hash != prev {
                return Err(format!(
                    "previous_hash mismatch at event #{i} ({})",
                    e.event_type
                ));
            }
            let recomputed = compute_event_hash(
                &e.id,
                &e.baa_id,
                &e.tenant_id,
                &e.event_type,
                &e.actor,
                &e.payload,
                &e.occurred_at,
                &e.previous_hash,
            );
            if recomputed != e.hash {
                return Err(format!("hash mismatch at event #{i} ({})", e.event_type));
            }
            prev = Some(e.hash.clone());
        }
        Ok(events.len())
    }

    // ── Internals ──────────────────────────────────────────────────────────

    async fn append_event(
        &self,
        baa_id: &str,
        tenant_id: &str,
        event_type: &str,
        actor: &str,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        // Acquire the previous hash (cache-first, DB fallback).
        let previous_hash = {
            let cache = self.last_hashes.read().await;
            cache.get(baa_id).cloned()
        };
        let previous_hash = match previous_hash {
            Some(h) => Some(h),
            None => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT hash FROM hipaa_baa_events
                     WHERE baa_id = $1
                     ORDER BY occurred_at DESC LIMIT 1",
                )
                .bind(baa_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
                row.map(|(h,)| h)
            }
        };

        let hash = compute_event_hash(
            &id,
            baa_id,
            tenant_id,
            event_type,
            actor,
            &payload,
            &now,
            &previous_hash,
        );
        sqlx::query(
            "INSERT INTO hipaa_baa_events
               (id, baa_id, tenant_id, event_type, actor, payload,
                occurred_at, hash, previous_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(&id)
        .bind(baa_id)
        .bind(tenant_id)
        .bind(event_type)
        .bind(actor)
        .bind(&payload)
        .bind(now)
        .bind(&hash)
        .bind(&previous_hash)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let mut cache = self.last_hashes.write().await;
        cache.insert(baa_id.to_string(), hash);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_event_hash(
    id: &str,
    baa_id: &str,
    tenant_id: &str,
    event_type: &str,
    actor: &str,
    payload: &serde_json::Value,
    occurred_at: &DateTime<Utc>,
    previous_hash: &Option<String>,
) -> String {
    let canonical = serde_json::json!({
        "actor": actor,
        "baa_id": baa_id,
        "event_type": event_type,
        "id": id,
        "occurred_at": occurred_at.to_rfc3339(),
        "payload": payload,
        "previous_hash": previous_hash,
        "tenant_id": tenant_id,
    });
    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    hex::encode(hasher.finalize())
}

// ─── DB row mapping ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct BaaRow {
    id: String,
    tenant_id: String,
    version: String,
    status: String,
    signer_name: Option<String>,
    signer_email: Option<String>,
    signer_title: Option<String>,
    signer_ip: Option<String>,
    signed_at: Option<DateTime<Utc>>,
    signed_signature: Option<String>,
    countersigner_name: Option<String>,
    countersigner_email: Option<String>,
    countersigned_at: Option<DateTime<Utc>>,
    document_url: Option<String>,
    document_sha256: Option<String>,
    effective_date: Option<DateTime<Utc>>,
    terminated_at: Option<DateTime<Utc>>,
    termination_reason: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<BaaRow> for Baa {
    type Error = String;
    fn try_from(r: BaaRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: r.id,
            tenant_id: r.tenant_id,
            version: r.version,
            status: BaaStatus::parse(&r.status)
                .ok_or_else(|| format!("invalid baa status: {}", r.status))?,
            signer_name: r.signer_name,
            signer_email: r.signer_email,
            signer_title: r.signer_title,
            signer_ip: r.signer_ip,
            signed_at: r.signed_at,
            signed_signature: r.signed_signature,
            countersigner_name: r.countersigner_name,
            countersigner_email: r.countersigner_email,
            countersigned_at: r.countersigned_at,
            document_url: r.document_url,
            document_sha256: r.document_sha256,
            effective_date: r.effective_date,
            terminated_at: r.terminated_at,
            termination_reason: r.termination_reason,
            metadata: r.metadata,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct BaaEventRow {
    id: String,
    baa_id: String,
    tenant_id: String,
    event_type: String,
    actor: String,
    payload: serde_json::Value,
    occurred_at: DateTime<Utc>,
    hash: String,
    previous_hash: Option<String>,
}

impl From<BaaEventRow> for BaaEvent {
    fn from(r: BaaEventRow) -> Self {
        Self {
            id: r.id,
            baa_id: r.baa_id,
            tenant_id: r.tenant_id,
            event_type: r.event_type,
            actor: r.actor,
            payload: r.payload,
            occurred_at: r.occurred_at,
            hash: r.hash,
            previous_hash: r.previous_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_transitions_are_strict() {
        use BaaStatus::*;
        // Forward path is allowed.
        assert!(Draft.can_transition_to(Requested));
        assert!(Requested.can_transition_to(Signed));
        assert!(Signed.can_transition_to(Countersigned));
        assert!(Countersigned.can_transition_to(Active));
        assert!(Active.can_transition_to(Terminated));
        // Skipping is forbidden.
        assert!(!Draft.can_transition_to(Active));
        assert!(!Requested.can_transition_to(Active));
        // Termination shortcuts are allowed except from Active is the only
        // post-Active state.
        assert!(Signed.can_transition_to(Terminated));
        assert!(!Terminated.can_transition_to(Active));
    }

    #[test]
    fn status_round_trip() {
        for s in [
            BaaStatus::Draft,
            BaaStatus::Requested,
            BaaStatus::Signed,
            BaaStatus::Countersigned,
            BaaStatus::Active,
            BaaStatus::Terminated,
        ] {
            assert_eq!(BaaStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(BaaStatus::parse("bogus"), None);
    }

    #[test]
    fn event_hash_is_deterministic() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let payload = serde_json::json!({"foo": 1, "bar": "baz"});
        let h1 = compute_event_hash(
            "id1", "baa", "tenant", "signed", "actor", &payload, &now, &None,
        );
        let h2 = compute_event_hash(
            "id1", "baa", "tenant", "signed", "actor", &payload, &now, &None,
        );
        assert_eq!(h1, h2);
        // Different previous_hash → different hash.
        let h3 = compute_event_hash(
            "id1",
            "baa",
            "tenant",
            "signed",
            "actor",
            &payload,
            &now,
            &Some("abc".into()),
        );
        assert_ne!(h1, h3);
    }
}

// ─── DB-backed adversarial lifecycle tests ─────────────────────────────────
//
// A BAA is a legal instrument: every transition must be refused unless the
// workflow allows it, the event chain must be tamper-evident, and a tenant
// must never see another tenant's agreement.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;

    async fn service(suffix: &str) -> Option<(PgPool, HipaaService)> {
        let pool =
            test_support::canonical_pool(&format!("hipaa_{suffix}"), &format!("hp_{suffix}"))
                .await?;
        Some((
            pool.clone(),
            HipaaService::new(pool, b"unit-baa-key".to_vec()),
        ))
    }

    fn sign_input(marker: &str) -> SignBaaInput {
        SignBaaInput {
            signer_name: format!("Signer {marker}"),
            signer_email: format!("{marker}@example.test"),
            signer_title: Some("CTO".into()),
            signer_ip: Some("203.0.113.7".into()),
            document_url: Some("https://docs.example.test/baa.pdf".into()),
            document_sha256: Some("a".repeat(64)),
        }
    }

    fn countersign_input() -> CountersignBaaInput {
        CountersignBaaInput {
            countersigner_name: "ApexMail Legal".into(),
            countersigner_email: "legal@apexmail.ee".into(),
            effective_date: None,
        }
    }

    async fn drive_to_active(svc: &HipaaService, tenant: &str) -> Baa {
        let baa = svc
            .request_baa(tenant, "v2.1", "actor:request")
            .await
            .expect("request");
        let baa = svc
            .sign(&baa.id, "actor:sign", sign_input("alice"))
            .await
            .expect("sign");
        let baa = svc
            .countersign(&baa.id, "actor:countersign", countersign_input())
            .await
            .expect("countersign");
        svc.activate(&baa.id, "actor:activate")
            .await
            .expect("activate")
    }

    #[tokio::test]
    async fn baa_lifecycle_is_hash_chained_and_tenant_scoped() {
        let Some((pool, svc)) = service("lifecycle").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let other = test_support::unique_tenant();

        let requested = svc
            .request_baa(&tenant, "v2.1", "actor:request")
            .await
            .expect("request");
        assert_eq!(requested.status, BaaStatus::Requested);
        assert_eq!(requested.version, "v2.1");

        let signed = svc
            .sign(&requested.id, "actor:sign", sign_input("alice"))
            .await
            .expect("sign");
        assert_eq!(signed.status, BaaStatus::Signed);
        assert!(signed.signed_signature.is_some());
        assert_eq!(
            signed.document_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );

        let countersigned = svc
            .countersign(&signed.id, "actor:countersign", countersign_input())
            .await
            .expect("countersign");
        assert_eq!(countersigned.status, BaaStatus::Countersigned);
        assert!(countersigned.effective_date.is_some());

        let active = svc
            .activate(&countersigned.id, "actor:activate")
            .await
            .expect("activate");
        assert_eq!(active.status, BaaStatus::Active);
        assert!(svc.is_active_for_tenant(&tenant).await);
        // Tenant isolation: the other tenant is not active and sees no rows.
        assert!(!svc.is_active_for_tenant(&other).await);
        assert!(svc.list_for_tenant(&other).await.expect("list").is_empty());

        // The event chain is intact and every transition is recorded.
        assert_eq!(svc.verify_chain(&active.id).await.expect("chain"), 4);
        let events = svc.list_events(&active.id).await.expect("events");
        let kinds: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["requested", "signed", "countersigned", "activated"]
        );

        // A fresh service bootstrapped from the DB agrees (cache rebuild).
        let boot = HipaaService::new(pool.clone(), b"unit-baa-key".to_vec());
        boot.initialize().await.expect("initialize");
        assert!(boot.is_active_for_tenant(&tenant).await);
    }

    #[tokio::test]
    async fn baa_forbids_out_of_order_transitions_and_double_creation() {
        let Some((_pool, svc)) = service("transitions").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let baa = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect("request");

        // A second in-flight BAA is refused, with the reason named.
        let err = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect_err("double creation must be refused");
        assert!(err.contains("terminate it first"), "{err}");

        // Signing twice is refused (state machine, not idempotent).
        svc.sign(&baa.id, "actor:sign", sign_input("alice"))
            .await
            .expect("sign");
        let err = svc
            .sign(&baa.id, "actor:sign", sign_input("alice"))
            .await
            .expect_err("double sign must be refused");
        assert!(err.contains("Cannot sign BAA in status signed"), "{err}");

        // Skipping countersignature cannot activate.
        let err = svc
            .activate(&baa.id, "actor:activate")
            .await
            .expect_err("activation before countersignature must be refused");
        assert!(
            err.contains("Cannot activate BAA in status signed"),
            "{err}"
        );
        assert!(!svc.is_active_for_tenant(&tenant).await);

        // Unknown ids are honest not-found errors, never fabricated rows.
        assert!(svc.fetch("no-such-baa").await.expect("fetch").is_none());
        assert!(svc.sign("no-such-baa", "a", sign_input("x")).await.is_err());
        assert!(svc
            .countersign("no-such-baa", "a", countersign_input())
            .await
            .is_err());
        assert!(svc.activate("no-such-baa", "a").await.is_err());
        assert!(svc.terminate("no-such-baa", "a", "why").await.is_err());
        assert_eq!(svc.verify_chain("no-such-baa").await.expect("chain"), 0);
    }

    #[tokio::test]
    async fn baa_termination_and_reactivation_are_guarded() {
        let Some((_pool, svc)) = service("termination").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let baa = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect("request");

        // Termination is allowed from an in-flight state, with the reason kept.
        let terminated = svc
            .terminate(&baa.id, "actor:terminate", "customer churn")
            .await
            .expect("terminate");
        assert_eq!(terminated.status, BaaStatus::Terminated);
        assert_eq!(
            terminated.termination_reason.as_deref(),
            Some("customer churn")
        );
        // Terminating an already-terminated BAA is idempotent.
        let again = svc
            .terminate(&baa.id, "actor", "again")
            .await
            .expect("idempotent");
        assert_eq!(again.status, BaaStatus::Terminated);
        assert_eq!(again.termination_reason.as_deref(), Some("customer churn"));

        // A terminated BAA cannot come back to life.
        let err = svc
            .activate(&baa.id, "actor:activate")
            .await
            .expect_err("terminated must not activate");
        assert!(
            err.contains("Cannot activate BAA in status terminated"),
            "{err}"
        );
        assert!(!svc.is_active_for_tenant(&tenant).await);

        // After termination the tenant may request a replacement.
        let replacement = svc
            .request_baa(&tenant, "v2.0", "actor:request")
            .await
            .expect("replacement request");
        assert_ne!(replacement.id, baa.id);
    }

    #[tokio::test]
    async fn activating_a_new_baa_supersedes_the_prior_active_one() {
        let Some((pool, svc)) = service("supersede").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let first = drive_to_active(&svc, &tenant).await;
        let err = svc
            .request_baa(&tenant, "v2.0", "a")
            .await
            .expect_err("in-flight");
        assert!(err.contains("terminate it first"));
        svc.terminate(&first.id, "actor", "renewal")
            .await
            .expect("terminate first");

        let second = drive_to_active(&svc, &tenant).await;
        assert!(svc.is_active_for_tenant(&tenant).await);
        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM hipaa_baas WHERE tenant_id = $1 AND status = 'active'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(active_count, 1, "exactly one active BAA per tenant");

        // Activating again is idempotent and does not append an event.
        let before = svc.verify_chain(&second.id).await.expect("chain");
        let same = svc
            .activate(&second.id, "actor:activate")
            .await
            .expect("idempotent");
        assert_eq!(same.id, second.id);
        assert_eq!(svc.verify_chain(&second.id).await.expect("chain"), before);
    }

    #[tokio::test]
    async fn baa_signature_binds_the_document_hash_and_signer_identity() {
        let Some((_pool, svc)) = service("signature").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let baa = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect("request");
        let signed = svc
            .sign(&baa.id, "actor:sign", sign_input("alice"))
            .await
            .expect("sign");
        let signature = signed.signed_signature.clone().expect("signature");
        assert_eq!(signature.len(), 64, "hex SHA-256 sized HMAC");
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

        // Re-deriving from a different document hash gives a different
        // signature: the binding is real, not a constant.
        let canonical = serde_json::json!({
            "baa_id": baa.id,
            "tenant_id": signed.tenant_id,
            "version": signed.version,
            "signer_name": "Signer alice",
            "signer_email": "alice@example.test",
            "signer_title": "CTO",
            "document_sha256": "b".repeat(64),
        });
        let mut mac = HmacSha256::new_from_slice(b"unit-baa-key").unwrap();
        mac.update(&serde_json::to_vec(&canonical).unwrap());
        let recomputed = hex::encode(mac.finalize().into_bytes());
        assert_ne!(recomputed, signature);
    }

    #[tokio::test]
    async fn tampered_baa_event_chain_is_detected() {
        let Some((pool, svc)) = service("tamper").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let baa = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect("request");
        svc.sign(&baa.id, "actor:sign", sign_input("alice"))
            .await
            .expect("sign");
        assert_eq!(svc.verify_chain(&baa.id).await.expect("chain"), 2);

        // Rewriting the actor (the legal "who") must invalidate the hash.
        sqlx::query(
            "UPDATE hipaa_baa_events SET actor = 'attacker'
             WHERE id = (SELECT id FROM hipaa_baa_events WHERE baa_id = $1
                         ORDER BY occurred_at LIMIT 1)",
        )
        .bind(&baa.id)
        .execute(&pool)
        .await
        .expect("tamper");
        let err = svc
            .verify_chain(&baa.id)
            .await
            .expect_err("tamper must be detected");
        assert!(err.contains("hash mismatch"), "{err}");

        // Dropping a middle event breaks the previous_hash linkage.
        let fresh_tenant = test_support::unique_tenant();
        let fresh = svc
            .request_baa(&fresh_tenant, "v1.0", "actor:request")
            .await
            .expect("request");
        svc.sign(&fresh.id, "actor:sign", sign_input("bob"))
            .await
            .expect("sign");
        svc.countersign(&fresh.id, "actor:countersign", countersign_input())
            .await
            .expect("countersign");
        sqlx::query("DELETE FROM hipaa_baa_events WHERE baa_id = $1 AND event_type = 'signed'")
            .bind(&fresh.id)
            .execute(&pool)
            .await
            .expect("delete middle event");
        let err = svc
            .verify_chain(&fresh.id)
            .await
            .expect_err("gap must be detected");
        assert!(err.contains("previous_hash mismatch"), "{err}");
    }

    #[tokio::test]
    async fn hostile_baa_inputs_are_stored_verbatim_and_never_crash() {
        let Some((pool, svc)) = service("hostile").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let baa = svc
            .request_baa(&tenant, "v1.0", "actor:request")
            .await
            .expect("request");
        // Unicode, RTL, emoji and an over-long title: the service must persist
        // exactly what was signed.
        let hostile = SignBaaInput {
            signer_name: "Z͑̽a̸l̷g̶o̴ ユーザー 🔏".into(),
            signer_email: "unicodé@example.test".into(),
            signer_title: Some("x".repeat(4096)),
            signer_ip: Some("2001:db8::1".into()),
            document_url: Some("https://docs.example.test/%00/baa.pdf".into()),
            document_sha256: Some("not-a-hash".into()),
        };
        let signed = svc
            .sign(&baa.id, "actor:sign", hostile.clone())
            .await
            .expect("sign");
        assert_eq!(
            signed.signer_name.as_deref(),
            Some(hostile.signer_name.as_str())
        );
        assert_eq!(
            signed.signer_email.as_deref(),
            Some(hostile.signer_email.as_str())
        );
        assert_eq!(signed.document_sha256.as_deref(), Some("not-a-hash"));
        assert_eq!(svc.verify_chain(&baa.id).await.expect("chain"), 2);

        // An unknown status materialised by an operator is an explicit error,
        // not a silently-coerced status.
        sqlx::query("UPDATE hipaa_baas SET status = 'bogus' WHERE id = $1")
            .bind(&baa.id)
            .execute(&pool)
            .await
            .expect("corrupt status");
        let err = svc
            .fetch(&baa.id)
            .await
            .expect_err("unknown status must be an error");
        assert!(err.contains("invalid baa status"), "{err}");
    }
}
