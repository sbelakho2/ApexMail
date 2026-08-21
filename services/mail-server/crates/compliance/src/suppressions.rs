use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionScope {
    Global,
    Organization,
    Workspace,
    Subaccount,
    Stream,
    Domain,
}

impl std::fmt::Display for SuppressionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Global => "global",
            Self::Organization => "organization",
            Self::Workspace => "workspace",
            Self::Subaccount => "subaccount",
            Self::Stream => "stream",
            Self::Domain => "domain",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    HardBounce,
    Complaint,
    MarketingUnsubscribe,
    AdminBlock,
    CustomerBlock,
    Temporary,
    Policy,
}

impl std::fmt::Display for SuppressionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::HardBounce => "hard_bounce",
            Self::Complaint => "complaint",
            Self::MarketingUnsubscribe => "marketing_unsubscribe",
            Self::AdminBlock => "admin_block",
            Self::CustomerBlock => "customer_block",
            Self::Temporary => "temporary",
            Self::Policy => "policy",
        };
        f.write_str(s)
    }
}

impl SuppressionReason {
    pub fn is_removable(&self) -> bool {
        matches!(self, Self::Temporary | Self::CustomerBlock | Self::AdminBlock)
    }

    pub fn is_compliance_protected(&self) -> bool {
        matches!(self, Self::HardBounce | Self::Complaint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionSource {
    Api,
    Webhook,
    System,
    Import,
    AdminConsole,
    FeedbackLoop,
}

impl std::fmt::Display for SuppressionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Api => "api",
            Self::Webhook => "webhook",
            Self::System => "system",
            Self::Import => "import",
            Self::AdminConsole => "admin_console",
            Self::FeedbackLoop => "feedback_loop",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalRecord {
    pub id: String,
    pub removed_by: String,
    pub removed_at: DateTime<Utc>,
    pub reason: String,
    pub permission_level: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRecord {
    pub id: String,
    pub recipient: String,
    pub recipient_hash: String,
    pub scope: SuppressionScope,
    pub scope_id: String,
    pub reason: SuppressionReason,
    pub source_event: Option<SuppressionSource>,
    pub source_event_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub created_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub removal_history: Vec<RemovalRecord>,
    pub metadata: serde_json::Value,
}

impl SuppressionRecord {
    pub fn is_active(&self) -> bool {
        if let Some(expiry) = self.expires_at {
            Utc::now() < expiry && self.removal_history.is_empty()
        } else {
            self.removal_history.is_empty()
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|expiry| Utc::now() >= expiry)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionSearchQuery {
    pub recipient: Option<String>,
    pub scope: Option<SuppressionScope>,
    pub scope_id: Option<String>,
    pub reason: Option<SuppressionReason>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub active_only: Option<bool>,
    pub created_by: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAddRequest {
    pub entries: Vec<BulkSuppressionEntry>,
    pub created_by: String,
    pub source: SuppressionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSuppressionEntry {
    pub recipient: String,
    pub scope: SuppressionScope,
    pub scope_id: String,
    pub reason: SuppressionReason,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAddResult {
    pub total: u32,
    pub added: u32,
    pub skipped: u32,
    pub errors: Vec<BulkAddError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAddError {
    pub recipient: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionExportParams {
    pub scope: Option<SuppressionScope>,
    pub scope_id: Option<String>,
    pub reason: Option<SuppressionReason>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub active_only: Option<bool>,
    pub format: ExportFormat,
    pub max_records: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Ndjson,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv => f.write_str("csv"),
            Self::Json => f.write_str("json"),
            Self::Ndjson => f.write_str("ndjson"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub export_id: String,
    pub total_records: u32,
    pub download_url: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: ExportStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl std::fmt::Display for ExportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportJob {
    pub import_id: String,
    pub source: SuppressionSource,
    pub format: ImportFormat,
    pub total_records: u32,
    pub imported: u32,
    pub skipped: u32,
    pub errors: u32,
    pub status: ExportStatus,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportFormat {
    Csv,
    Json,
    Ndjson,
}

impl std::fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv => f.write_str("csv"),
            Self::Json => f.write_str("json"),
            Self::Ndjson => f.write_str("ndjson"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalRequest {
    pub suppression_id: String,
    pub removed_by: String,
    pub reason: String,
    pub permission_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalResult {
    pub success: bool,
    pub error: Option<String>,
    pub removed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionViolation {
    ComplaintRemovalAttempted,
    BroadcastUnsubscribeBypass,
    InsufficientPermission,
    RecipientNotSuppressed,
}

impl std::fmt::Display for SuppressionViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ComplaintRemovalAttempted => "complaint_removal_attempted",
            Self::BroadcastUnsubscribeBypass => "broadcast_unsubscribe_bypass",
            Self::InsufficientPermission => "insufficient_permission",
            Self::RecipientNotSuppressed => "recipient_not_suppressed",
        };
        f.write_str(s)
    }
}

/// Check if a recipient is suppressed for a given scope.
/// Returns the matching suppression or None if the recipient is clear.
///
/// Scope precedence: a broader-scoped suppression applies to sends in finer
/// scopes without requiring exact `scope_id` equality — a Global record blocks
/// everything, and a Domain record blocks every recipient in that domain.
/// Exact (scope, scope_id) matching still applies to the intermediate scopes
/// (Stream, Subaccount, Workspace, Organization).
pub fn check_suppression(
    recipient: &str,
    scope: SuppressionScope,
    scope_id: &str,
    records: &[SuppressionRecord],
) -> Option<SuppressionRecord> {
    let scope_order = [
        SuppressionScope::Domain,
        SuppressionScope::Stream,
        SuppressionScope::Subaccount,
        SuppressionScope::Workspace,
        SuppressionScope::Organization,
        SuppressionScope::Global,
    ];

    for check_scope in &scope_order {
        if let Some(rec) = records
            .iter()
            .find(|r| r.recipient == recipient && r.scope == *check_scope && r.is_active() && {
                match r.scope {
                    // Global blocks everything — no scope_id linkage required.
                    SuppressionScope::Global => true,
                    // Domain blocks domain sends: the record's scope_id is the
                    // domain, matched against the recipient's domain.
                    SuppressionScope::Domain => recipient_domain(recipient)
                        .map(|d| d.eq_ignore_ascii_case(&r.scope_id))
                        .unwrap_or(false),
                    // Intermediate scopes: exact scope + scope_id match.
                    _ => r.scope == scope && r.scope_id == scope_id,
                }
            })
        {
            return Some(rec.clone());
        }
    }

    None
}

/// Extract the lowercase domain part of an email-like recipient address.
fn recipient_domain(recipient: &str) -> Option<&str> {
    recipient.rsplit_once('@').map(|(_, domain)| domain)
}

/// Bulk add suppressions, skipping duplicates.
pub fn bulk_add_suppressions(
    entries: Vec<BulkSuppressionEntry>,
    created_by: &str,
    source: SuppressionSource,
    existing: &[SuppressionRecord],
) -> BulkAddResult {
    let _ = (created_by, source);
    let total = entries.len() as u32;
    let mut added = 0u32;
    let mut skipped = 0u32;
    let mut errors = Vec::new();

    for entry in &entries {
        let already_exists = existing
            .iter()
            .any(|r| r.recipient == entry.recipient && r.scope == entry.scope && r.scope_id == entry.scope_id && r.reason == entry.reason && r.is_active());

        if already_exists {
            skipped += 1;
            continue;
        }

        if entry.reason == SuppressionReason::HardBounce
            && !entry.recipient.contains('@')
        {
            errors.push(BulkAddError {
                recipient: entry.recipient.clone(),
                error: "Invalid recipient format for bounce suppression".into(),
            });
            continue;
        }

        added += 1;
    }

    BulkAddResult {
        total,
        added,
        skipped,
        errors,
    }
}

/// Permission-controlled removal of a suppression.
/// Complaint-based suppressions cannot be removed programmatically.
pub fn permission_controlled_removal(
    record: &SuppressionRecord,
    request: &RemovalRequest,
) -> Result<RemovalResult, SuppressionViolation> {
    if record.reason == SuppressionReason::Complaint {
        return Err(SuppressionViolation::ComplaintRemovalAttempted);
    }

    if record.reason == SuppressionReason::MarketingUnsubscribe {
        return Err(SuppressionViolation::BroadcastUnsubscribeBypass);
    }

    if record.reason == SuppressionReason::HardBounce && request.permission_level != "admin" {
        return Err(SuppressionViolation::InsufficientPermission);
    }

    Ok(RemovalResult {
        success: true,
        error: None,
        removed_at: Utc::now(),
    })
}

/// Export records to the specified format.
pub fn export_records(
    records: &[SuppressionRecord],
    params: &SuppressionExportParams,
) -> ExportResult {
    let filtered: Vec<&SuppressionRecord> = records
        .iter()
        .filter(|r| {
            params.scope.map_or(true, |s| r.scope == s)
                && params.scope_id.as_ref().map_or(true, |id| r.scope_id == *id)
                && params.reason.map_or(true, |rea| r.reason == rea)
                && params.start_date.map_or(true, |d| r.timestamp >= d)
                && params.end_date.map_or(true, |d| r.timestamp <= d)
                && params.active_only.map_or(true, |a| !a || r.is_active())
        })
        .collect();

    let max = params.max_records.unwrap_or(500_000).min(500_000);
    let total = (filtered.len() as u32).min(max);

    ExportResult {
        export_id: uuid::Uuid::new_v4().to_string(),
        total_records: total,
        download_url: None,
        expires_at: Utc::now() + chrono::Duration::days(7),
        status: ExportStatus::Pending,
    }
}

/// Search suppressions with the given query.
pub fn search_suppressions(
    records: &[SuppressionRecord],
    query: &SuppressionSearchQuery,
) -> Vec<SuppressionRecord> {
    let mut results: Vec<SuppressionRecord> = records
        .iter()
        .filter(|r| {
            query.recipient.as_ref().map_or(true, |rec| r.recipient.contains(rec))
                && query.scope.map_or(true, |s| r.scope == s)
                && query.scope_id.as_ref().map_or(true, |id| r.scope_id == *id)
                && query.reason.map_or(true, |rea| r.reason == rea)
                && query.start_date.map_or(true, |d| r.timestamp >= d)
                && query.end_date.map_or(true, |d| r.timestamp <= d)
                && query.active_only.map_or(true, |a| !a || r.is_active())
                && query.created_by.as_ref().map_or(true, |cb| r.created_by == *cb)
        })
        .cloned()
        .collect();

    results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    results
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_record(recipient: &str, reason: SuppressionReason, scope: SuppressionScope) -> SuppressionRecord {
        SuppressionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: recipient.into(),
            recipient_hash: format!("hash_{}", recipient),
            scope,
            scope_id: "test_scope".into(),
            reason,
            source_event: Some(SuppressionSource::Api),
            source_event_id: None,
            timestamp: Utc::now(),
            created_by: "admin".into(),
            expires_at: None,
            removal_history: vec![],
            metadata: json!({}),
        }
    }

    #[test]
    fn test_check_suppression_finds_match() {
        let rec = make_record("bounce@test.com", SuppressionReason::HardBounce, SuppressionScope::Global);
        let records = vec![rec.clone()];
        let result = check_suppression("bounce@test.com", SuppressionScope::Global, "test_scope", &records);
        assert!(result.is_some());
        assert_eq!(result.unwrap().reason, SuppressionReason::HardBounce);
    }

    #[test]
    fn test_check_suppression_no_match() {
        let rec = make_record("good@test.com", SuppressionReason::Temporary, SuppressionScope::Stream);
        let records = vec![rec];
        let result = check_suppression("other@test.com", SuppressionScope::Stream, "test_scope", &records);
        assert!(result.is_none());
    }

    #[test]
    fn test_complaint_removal_denied() {
        let rec = make_record("complaint@test.com", SuppressionReason::Complaint, SuppressionScope::Global);
        let req = RemovalRequest {
            suppression_id: rec.id.clone(),
            removed_by: "admin".into(),
            reason: "test".into(),
            permission_level: "admin".into(),
        };
        let result = permission_controlled_removal(&rec, &req);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SuppressionViolation::ComplaintRemovalAttempted);
    }

    #[test]
    fn test_bulk_add_skips_duplicates() {
        let existing = vec![make_record("dup@test.com", SuppressionReason::Policy, SuppressionScope::Global)];
        let entries = vec![
            BulkSuppressionEntry {
                recipient: "dup@test.com".into(),
                scope: SuppressionScope::Global,
                scope_id: "test_scope".into(),
                reason: SuppressionReason::Policy,
                expires_at: None,
                metadata: None,
            },
            BulkSuppressionEntry {
                recipient: "new@test.com".into(),
                scope: SuppressionScope::Global,
                scope_id: "test_scope".into(),
                reason: SuppressionReason::CustomerBlock,
                expires_at: None,
                metadata: None,
            },
        ];

        let result = bulk_add_suppressions(entries, "admin", SuppressionSource::Api, &existing);
        assert_eq!(result.total, 2);
        assert_eq!(result.added, 1);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_suppression_reason_removability() {
        assert!(SuppressionReason::Complaint.is_compliance_protected());
        assert!(SuppressionReason::HardBounce.is_compliance_protected());
        assert!(!SuppressionReason::Policy.is_removable());
        assert!(!SuppressionReason::HardBounce.is_removable());
        assert!(SuppressionReason::Temporary.is_removable());
        assert!(SuppressionReason::CustomerBlock.is_removable());
    }

    // ── Scope-precedence matrix ────────────────────────────────

    fn make_scoped_record(
        recipient: &str,
        reason: SuppressionReason,
        scope: SuppressionScope,
        scope_id: &str,
    ) -> SuppressionRecord {
        let mut rec = make_record(recipient, reason, scope);
        rec.scope_id = scope_id.into();
        rec
    }

    /// Global suppressions must block sends in any finer scope — the old code
    /// required scope_id equality on every branch, so a Global record never
    /// matched a Stream/Workspace/... send.
    #[test]
    fn test_global_suppression_matches_finer_scope() {
        let rec = make_scoped_record(
            "victim@test.com",
            SuppressionReason::Complaint,
            SuppressionScope::Global,
            "global-root",
        );
        for (scope, scope_id) in [
            (SuppressionScope::Stream, "stream-1"),
            (SuppressionScope::Subaccount, "sub-1"),
            (SuppressionScope::Workspace, "ws-1"),
            (SuppressionScope::Organization, "org-1"),
            (SuppressionScope::Global, "anything-else"),
        ] {
            let result = check_suppression("victim@test.com", scope, scope_id, &[rec.clone()]);
            assert!(
                result.is_some(),
                "Global suppression must match {scope:?} send"
            );
        }
    }

    /// Domain suppressions block sends to any recipient in that domain,
    /// regardless of the send scope.
    #[test]
    fn test_domain_suppression_matches_recipient_domain() {
        let rec = make_scoped_record(
            "anyone@evil.com",
            SuppressionReason::Policy,
            SuppressionScope::Domain,
            "evil.com",
        );
        // Different local part, finer send scope — still blocked.
        assert!(check_suppression(
            "other-user@evil.com",
            SuppressionScope::Stream,
            "stream-1",
            &[rec.clone()]
        )
        .is_some());
        // Domain match must be case-insensitive.
        assert!(check_suppression(
            "user@EVIL.com",
            SuppressionScope::Workspace,
            "ws-1",
            &[rec.clone()]
        )
        .is_some());
        // Different domain — not blocked.
        assert!(check_suppression(
            "user@good.com",
            SuppressionScope::Stream,
            "stream-1",
            &[rec.clone()]
        )
        .is_none());
    }

    /// Exact (scope, scope_id) matching still applies to intermediate scopes.
    #[test]
    fn test_intermediate_scopes_require_exact_match() {
        let rec = make_scoped_record(
            "user@test.com",
            SuppressionReason::Temporary,
            SuppressionScope::Stream,
            "stream-1",
        );
        assert!(check_suppression(
            "user@test.com",
            SuppressionScope::Stream,
            "stream-1",
            &[rec.clone()]
        )
        .is_some());
        // Wrong scope_id at the same scope.
        assert!(check_suppression(
            "user@test.com",
            SuppressionScope::Stream,
            "stream-2",
            &[rec.clone()]
        )
        .is_none());
        // A Stream record must NOT match a Workspace-context send (a stream
        // block does not lift/apply to the whole workspace).
        assert!(check_suppression(
            "user@test.com",
            SuppressionScope::Workspace,
            "stream-1",
            &[rec.clone()]
        )
        .is_none());
    }

    /// When multiple scopes match, the most specific record wins
    /// (Domain over Global).
    #[test]
    fn test_most_specific_scope_wins() {
        let domain_rec = make_scoped_record(
            "user@test.com",
            SuppressionReason::Policy,
            SuppressionScope::Domain,
            "test.com",
        );
        let global_rec = make_scoped_record(
            "user@test.com",
            SuppressionReason::HardBounce,
            SuppressionScope::Global,
            "root",
        );
        let result = check_suppression(
            "user@test.com",
            SuppressionScope::Stream,
            "stream-1",
            &[global_rec, domain_rec],
        );
        let matched = result.expect("expected a match");
        assert_eq!(matched.scope, SuppressionScope::Domain);
        assert_eq!(matched.reason, SuppressionReason::Policy);
    }

    /// Inactive (removed/expired) records never match, whatever the scope.
    #[test]
    fn test_inactive_records_never_match() {
        let mut rec = make_scoped_record(
            "gone@test.com",
            SuppressionReason::Temporary,
            SuppressionScope::Global,
            "root",
        );
        rec.removal_history.push(RemovalRecord {
            id: "r1".into(),
            removed_by: "admin".into(),
            removed_at: Utc::now(),
            reason: "manual".into(),
            permission_level: "admin".into(),
            ip_address: None,
        });
        assert!(check_suppression(
            "gone@test.com",
            SuppressionScope::Stream,
            "stream-1",
            &[rec]
        )
        .is_none());
    }

    #[test]
    fn test_recipient_domain_extraction() {
        assert_eq!(recipient_domain("a@b.c"), Some("b.c"));
        assert_eq!(recipient_domain("no-domain"), None);
        assert_eq!(recipient_domain(""), None);
    }
}
