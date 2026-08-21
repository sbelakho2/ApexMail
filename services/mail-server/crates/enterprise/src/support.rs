use std::sync::Once;

use chrono::{DateTime, Duration, TimeDelta, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

static SUPPORT_TICKETS_MISSING_WARNING: Once = Once::new();
static EMAIL_QUEUE_MISSING_WARNING: Once = Once::new();

fn is_missing_relation_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("42P01"))
}

fn log_missing_support_tickets_once(job: &'static str) {
    SUPPORT_TICKETS_MISSING_WARNING.call_once(|| {
        tracing::warn!(
            table = "ent_support_tickets",
            job,
            "Enterprise support tickets table missing; skipping support background job until migrations are applied"
        );
    });
}

fn log_missing_email_queue_once(context: &'static str) {
    EMAIL_QUEUE_MISSING_WARNING.call_once(|| {
        tracing::warn!(
            table = "email_queue",
            context,
            "email_queue table missing; support notifications cannot be queued until migrations are applied"
        );
    });
}

// ── Ticket lifecycle domain rules ────────────────────────────────────────
//
// The statuses mirror the CHECK constraint on ent_support_tickets.status
// (migration 023): 'new', 'open', 'pending', 'on_hold', 'waiting_customer',
// 'escalated', 'resolved', 'closed'. The transitions below are additionally
// enforced at the application layer so an invalid write (e.g. closed →
// escalated) can never reach the database.

pub const TICKET_STATUSES: &[&str] = &[
    "new",
    "open",
    "pending",
    "on_hold",
    "waiting_customer",
    "escalated",
    "resolved",
    "closed",
];

pub const TICKET_PRIORITIES: &[&str] = &["critical", "high", "medium", "low"];

/// Allowed comment author types (schema is free-form VARCHAR(50); the
/// application layer pins the enum the rest of the service assumes —
/// `first_response_at` stamping keys off `author_type == "agent"`).
pub const TICKET_AUTHOR_TYPES: &[&str] = &["agent", "customer", "system"];

pub fn is_valid_status(status: &str) -> bool {
    TICKET_STATUSES.contains(&status)
}

pub fn is_valid_priority(priority: &str) -> bool {
    TICKET_PRIORITIES.contains(&priority)
}

pub fn is_valid_author_type(author_type: &str) -> bool {
    TICKET_AUTHOR_TYPES.contains(&author_type)
}

/// Valid status transitions. A no-op (same status) is allowed so a caller
/// can update priority/assignment without a status change.
///
/// Principles: `resolved` may only be reopened (`open`) or closed; `closed`
/// may only be reopened (`open`); `escalated` returns to a working status
/// but is never reachable from a terminal state.
pub fn is_valid_ticket_transition(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    match from {
        "new" => matches!(to, "open" | "pending" | "on_hold" | "waiting_customer" | "escalated" | "resolved" | "closed"),
        "open" | "pending" => matches!(to, "on_hold" | "waiting_customer" | "escalated" | "resolved" | "closed" | "open" | "pending"),
        "on_hold" => matches!(to, "open" | "pending" | "escalated" | "closed" | "resolved"),
        "waiting_customer" => matches!(to, "open" | "pending" | "on_hold" | "escalated" | "resolved" | "closed"),
        "escalated" => matches!(to, "open" | "pending" | "on_hold" | "resolved" | "closed"),
        "resolved" => matches!(to, "closed" | "open"),
        "closed" => matches!(to, "open"),
        _ => false,
    }
}

/// Terminal tickets (resolved/closed) can never be escalated: escalation is
/// only meaningful while work is outstanding. A closed ticket must first be
/// reopened.
pub fn can_escalate(status: &str) -> bool {
    !matches!(status, "resolved" | "closed")
}

/// Public comments are only accepted on non-closed tickets; internal notes
/// remain possible on closed tickets for audit purposes.
pub fn can_comment(status: &str, is_internal: bool) -> bool {
    if is_internal {
        true
    } else {
        status != "closed"
    }
}

// ── Input bounds (mirror the schema column limits from migration 023) ────

pub const TICKET_SUBJECT_MAX_CHARS: usize = 500;
pub const TICKET_DESCRIPTION_MAX_CHARS: usize = 32_000;
pub const TICKET_CATEGORY_MAX_CHARS: usize = 100;
pub const TICKET_COMMENT_MAX_CHARS: usize = 16_000;
pub const TICKET_AUTHOR_MAX_CHARS: usize = 255;
pub const TICKET_REASON_MAX_CHARS: usize = 2_000;
pub const TICKET_FEEDBACK_MAX_CHARS: usize = 4_000;
pub const SATISFACTION_RATING_MIN: i32 = 1;
pub const SATISFACTION_RATING_MAX: i32 = 5;

/// List pagination bounds (defense-in-depth; the route layer clamps first).
pub const TICKET_LIST_MAX_LIMIT: i64 = 200;
pub const TICKET_LIST_MAX_OFFSET: i64 = 100_000;

/// Maximum length of a ticket subject search term (`q`).
pub const TICKET_SEARCH_MAX_CHARS: usize = 200;

/// Escape ILIKE/LIKE wildcard characters so a search term matches literally:
/// `%` → `\%`, `_` → `\_`, and a literal backslash is escaped first. Without
/// this, a term like `%` would match every subject.
pub(crate) fn escape_like_wildcards(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    for c in term.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn validation_err(message: impl Into<String>) -> Result<ApiResult<SupportTicket>, String> {
    Ok(ApiResult::err(message, "VALIDATION"))
}

fn validation_comment_err(
    message: impl Into<String>,
) -> Result<ApiResult<TicketComment>, String> {
    Ok(ApiResult::err(message, "VALIDATION"))
}

/// RFC-5321-ish sanity check for a contact/recipient address: exactly one @,
/// non-empty local part and domain, no whitespace, no control characters,
/// bounded length. Deliberately permissive on dot-atom details.
pub fn is_plausible_email(address: &str) -> bool {
    let address = address.trim();
    if address.len() > 320 || address.is_empty() {
        return false;
    }
    if address.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    !parts[0].is_empty() && parts[1].contains('.') && !parts[1].starts_with('.') && !parts[1].ends_with('.')
}

/// Keyset pagination cursor: `(created_at, id)` of the last row the caller
/// saw. Encoded as `<rfc3339-timestamp>,<uuid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketCursor {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

impl TicketCursor {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (ts, id) = raw
            .rsplit_once(',')
            .ok_or_else(|| "cursor must be '<rfc3339-timestamp>,<uuid>'".to_string())?;
        let created_at = DateTime::parse_from_rfc3339(ts.trim())
            .map_err(|e| format!("cursor timestamp is not RFC 3339: {e}"))?
            .with_timezone(&Utc);
        let id = Uuid::parse_str(id.trim()).map_err(|e| format!("cursor id is not a UUID: {e}"))?;
        Ok(Self { created_at, id })
    }
}

/// Strip control characters (except tab/newline in bodies) so notification
/// content can never smuggle SMTP header breaks into the queued email.
pub(crate) fn sanitize_notification_text(value: &str) -> String {
    value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Support notification queue ────────────────────────────────────────────
//
// The enterprise crate previously had no notification path at all: tickets
// were created, escalated and breached silently. This notifier mirrors the
// sales-autopilot/email_queue pattern (see api-server/src/routes/messages.rs):
// a row in the shared `email_queue` table with status 'pending' that the
// outbound worker drains. Notification failures are logged and NEVER fail
// the parent ticket operation.

/// `email_queue.tenant_id` is a UUID column (migrations 001/050) while
/// enterprise tenant ids are VARCHAR(26) ULID-style strings that are never
/// valid UUIDs. Binding the string directly would make every notification
/// INSERT fail at runtime (silently — failures are swallowed). Instead the
/// column is only populated when the id happens to be UUID-shaped, and the
/// authoritative tenant string always travels in `metadata` so notifications
/// stay attributable either way.
pub(crate) fn notification_tenant_uuid(tenant_id: Option<&str>) -> Option<Uuid> {
    tenant_id
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .and_then(|t| t.parse::<Uuid>().ok())
}

/// Satisfaction write path. The `AND satisfaction_rating IS NULL` guard is
/// the immutability invariant: once a rating exists the UPDATE matches no
/// row, and the caller surfaces ALREADY_SUBMITTED (409) — a rating can be
/// set exactly once and never overwritten.
pub(crate) const SUBMIT_SATISFACTION_SQL: &str = "UPDATE ent_support_tickets SET
             satisfaction_rating = $2,
             satisfaction_feedback = $3
             WHERE id = $1 AND satisfaction_rating IS NULL RETURNING *";

/// Queues transactional support notification emails into `email_queue`.
#[derive(Clone)]
pub struct SupportNotifier {
    db: PgPool,
    from_address: String,
}

impl SupportNotifier {
    pub fn new(db: PgPool) -> Self {
        let default_from = "support@apexmail.ee";
        let configured = std::env::var("SUPPORT_NOTIFICATION_FROM");
        // A malformed from-address would fail the email_queue CHECK on
        // every single insert (silently — failures are swallowed), so fall
        // back to the default instead of shipping a dead notifier.
        let from_address = match configured {
            Ok(value) if is_plausible_email(value.trim()) => value.trim().to_string(),
            Ok(value) => {
                tracing::warn!(
                    from = %sanitize_notification_text(&value),
                    "SUPPORT_NOTIFICATION_FROM is not a valid address — using {default_from}"
                );
                default_from.to_string()
            }
            Err(_) => default_from.to_string(),
        };
        Self { db, from_address }
    }

    /// Queue a plain-text notification. Best-effort: any error (missing
    /// table, FK violation, transient outage) is logged at warn level and
    /// swallowed — ticket operations must succeed regardless.
    pub async fn queue_email(
        &self,
        tenant_id: Option<&str>,
        to_address: &str,
        subject: &str,
        body: &str,
        kind: &str,
    ) {
        let to_address = to_address.trim();
        if !is_plausible_email(to_address) {
            tracing::warn!(to = %sanitize_notification_text(to_address), kind, "Skipping support notification with invalid recipient address");
            return;
        }
        let subject = sanitize_notification_text(&subject.chars().take(200).collect::<String>());
        let body: String = body.chars().take(10_000).collect();
        if subject.is_empty() {
            tracing::warn!(kind, "Skipping support notification with empty subject");
            return;
        }

        let tenant_uuid = notification_tenant_uuid(tenant_id);
        let metadata = serde_json::json!({
            "source": "enterprise-support",
            "kind": kind,
            // Authoritative tenant attribution: the email_queue.tenant_id
            // column is UUID-typed and stays NULL for ULID-style tenants.
            "tenant": tenant_id,
        });

        let result = sqlx::query(
            r#"INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body,
                status, priority, tags, metadata, tenant_id, created_at, updated_at
            ) VALUES (
                $1, $2, ARRAY[$3], $4, $5,
                'pending', 5, ARRAY['support-notification'], $6::jsonb, $7, NOW(), NOW()
            )"#,
        )
        .bind(Uuid::new_v4())
        .bind(&self.from_address)
        .bind(to_address)
        .bind(&subject)
        .bind(&body)
        .bind(metadata)
        .bind(tenant_uuid)
        .execute(&self.db)
        .await;

        match result {
            Ok(_) => info!(kind, "Support notification queued"),
            Err(error) if is_missing_relation_error(&error) => {
                log_missing_email_queue_once("queue_email");
            }
            Err(error) => {
                tracing::warn!(kind, error = %error, "Failed to queue support notification — ticket operation unaffected");
            }
        }
    }
}

/// Support Service:enterprise tickets, SLA tracking, agent assignment, escalation
pub struct SupportService {
    db: PgPool,
    notifier: SupportNotifier,
}

impl SupportService {
    pub fn new(db: PgPool) -> Self {
        let notifier = SupportNotifier::new(db.clone());
        Self { db, notifier }
    }

    /// Create a support ticket with SLA deadline calculation
    pub async fn create_ticket(
        &self,
        tenant_id: &str,
        subject: &str,
        description: &str,
        priority: &str,
        category: &str,
        contact_email: Option<&str>,
    ) -> Result<ApiResult<SupportTicket>, String> {
        // Input validation — invalid values must surface as 400s at the
        // route layer (code VALIDATION), never as a database CHECK failure.
        if tenant_id.trim().is_empty() || tenant_id.len() > 26 {
            return validation_err("tenant_id must be 1..=26 characters");
        }
        let subject_trimmed = subject.trim();
        if subject_trimmed.is_empty() {
            return validation_err("subject must not be empty");
        }
        if subject.chars().count() > TICKET_SUBJECT_MAX_CHARS {
            return validation_err(format!(
                "subject must not exceed {TICKET_SUBJECT_MAX_CHARS} characters"
            ));
        }
        if description.trim().is_empty() {
            return validation_err("description must not be empty");
        }
        if description.chars().count() > TICKET_DESCRIPTION_MAX_CHARS {
            return validation_err(format!(
                "description must not exceed {TICKET_DESCRIPTION_MAX_CHARS} characters"
            ));
        }
        if !is_valid_priority(priority) {
            return validation_err(format!(
                "priority must be one of: {}",
                TICKET_PRIORITIES.join(", ")
            ));
        }
        let category = category.trim();
        if category.is_empty() || category.chars().count() > TICKET_CATEGORY_MAX_CHARS {
            return validation_err(format!(
                "category must be 1..={TICKET_CATEGORY_MAX_CHARS} characters"
            ));
        }
        if let Some(email) = contact_email {
            if !email.trim().is_empty() && !is_plausible_email(email) {
                return validation_err("contact_email is not a valid email address");
            }
        }

        let id = Uuid::new_v4();

        // Calculate SLA deadlines based on priority
        let (fr_minutes, res_minutes) = sla_deadlines(priority);
        let sla_first_response_due = Utc::now() + Duration::minutes(fr_minutes);
        let sla_resolution_due = Utc::now() + Duration::minutes(res_minutes);

        // Auto-assign to least loaded agent with specialty matching
        let assigned_to = self.auto_assign_agent(category).await?;

        let contact_email_clean = contact_email.map(str::trim).filter(|e| !e.is_empty());

        let row = sqlx::query_as::<_, SupportTicket>(
            "INSERT INTO ent_support_tickets (id, tenant_id, subject, description, status, priority, category, contact_email, assigned_to, sla_first_response_due, sla_resolution_due, sla_breached, escalation_level, created_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,'open',$5,$6,$7,$8,$9,$10,false,0,'system',NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(subject_trimmed).bind(description)
        .bind(priority).bind(category).bind(contact_email_clean)
        .bind(assigned_to.as_ref())
        .bind(sla_first_response_due).bind(sla_resolution_due)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create ticket: {e}"))?;

        info!(ticket_id = %id, priority = priority, "Support ticket created");

        // Notification hooks: requester (if we have an address) and assignee.
        if let Some(email) = contact_email_clean {
            self.notifier
                .queue_email(
                    Some(tenant_id),
                    email,
                    &format!("[ApexMail Support] Ticket #{:?} received", row.number),
                    &format!(
                        "Your ticket \"{}\" has been received and assigned priority {}.\nWe will respond according to its SLA.",
                        sanitize_notification_text(subject_trimmed),
                        priority
                    ),
                    "ticket_created_requester",
                )
                .await;
        }
        if let Some(agent_id) = row.assigned_to {
            if let Ok(Some(agent_email)) = self.agent_email(agent_id).await {
                self.notifier
                    .queue_email(
                        Some(tenant_id),
                        &agent_email,
                        &format!("[ApexMail Support] New {} ticket: {}", priority, sanitize_notification_text(subject_trimmed)),
                        &format!(
                            "A new {}-priority ticket \"{}\" has been assigned to you.\nDescription: {}",
                            priority,
                            sanitize_notification_text(subject_trimmed),
                            description
                        ),
                        "ticket_created_assignee",
                    )
                    .await;
            }
        }

        Ok(ApiResult::ok(row))
    }

    /// Get a ticket by ID
    pub async fn get_ticket(&self, id: Uuid) -> Result<ApiResult<SupportTicket>, String> {
        let row =
            sqlx::query_as::<_, SupportTicket>("SELECT * FROM ent_support_tickets WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Get ticket: {e}"))?;

        match row {
            Some(t) => Ok(ApiResult::ok(t)),
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

    /// List tickets with optional filters and keyset (cursor) pagination.
    ///
    /// `cursor` (recommended) pages by `(created_at DESC, id DESC)` — a
    /// stable ordering backed by idx_ent_support_tickets_tenant_created.
    /// `offset` is kept for compatibility and clamped defensively.
    pub async fn list_tickets(
        &self,
        tenant_id: &str,
        status: Option<&str>,
        priority: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ApiResult<Vec<SupportTicket>>, String> {
        self.list_tickets_cursor(tenant_id, status, priority, limit, offset, None)
            .await
    }

    pub async fn list_tickets_cursor(
        &self,
        tenant_id: &str,
        status: Option<&str>,
        priority: Option<&str>,
        limit: i64,
        offset: i64,
        cursor: Option<TicketCursor>,
    ) -> Result<ApiResult<Vec<SupportTicket>>, String> {
        self.list_tickets_search(tenant_id, status, priority, limit, offset, cursor, None)
            .await
    }

    /// List tickets with filters, keyset pagination, and an optional bounded
    /// subject search (`q`). The search term is wildcard-escaped so caller
    /// `%`/`_` characters match literally and cannot force broad scans.
    pub async fn list_tickets_search(
        &self,
        tenant_id: &str,
        status: Option<&str>,
        priority: Option<&str>,
        limit: i64,
        offset: i64,
        cursor: Option<TicketCursor>,
        search: Option<&str>,
    ) -> Result<ApiResult<Vec<SupportTicket>>, String> {
        if let Some(s) = status {
            if !is_valid_status(s) {
                return Ok(ApiResult::err(
                    format!("status must be one of: {}", TICKET_STATUSES.join(", ")),
                    "VALIDATION",
                ));
            }
        }
        if let Some(p) = priority {
            if !is_valid_priority(p) {
                return Ok(ApiResult::err(
                    format!("priority must be one of: {}", TICKET_PRIORITIES.join(", ")),
                    "VALIDATION",
                ));
            }
        }
        let search = match search.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) if s.chars().count() <= TICKET_SEARCH_MAX_CHARS => Some(s),
            Some(_) => {
                return Ok(ApiResult::err(
                    format!("q must not exceed {TICKET_SEARCH_MAX_CHARS} characters"),
                    "VALIDATION",
                ))
            }
            None => None,
        };
        let limit = limit.clamp(1, TICKET_LIST_MAX_LIMIT);
        let offset = offset.clamp(0, TICKET_LIST_MAX_OFFSET);

        let mut query = String::from("SELECT * FROM ent_support_tickets WHERE tenant_id = $1");
        let mut param_idx = 2u32;
        let mut status_param: Option<String> = None;
        let mut priority_param: Option<String> = None;
        let mut search_param: Option<String> = None;

        if let Some(s) = status {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
            status_param = Some(s.to_string());
        }
        if let Some(p) = priority {
            query.push_str(&format!(" AND priority = ${param_idx}"));
            param_idx += 1;
            priority_param = Some(p.to_string());
        }
        if let Some(term) = search {
            query.push_str(&format!(
                " AND subject ILIKE '%' || ${param_idx} || '%'"
            ));
            param_idx += 1;
            search_param = Some(escape_like_wildcards(term));
        }
        if cursor.is_some() {
            // Keyset pagination: strictly older than the cursor row under
            // (created_at DESC, id DESC).
            query.push_str(&format!(
                " AND (created_at, id) < (${param_idx}, ${})",
                param_idx + 1
            ));
            param_idx += 2;
        }
        query.push_str(&format!(
            " ORDER BY created_at DESC, id DESC LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, SupportTicket>(&query).bind(tenant_id);
        if let Some(s) = status_param {
            q = q.bind(s);
        }
        if let Some(p) = priority_param {
            q = q.bind(p);
        }
        if let Some(s) = search_param {
            q = q.bind(s);
        }
        if let Some(c) = cursor {
            q = q.bind(c.created_at).bind(c.id);
        }
        q = q.bind(limit).bind(offset);

        let rows = q
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("List tickets: {e}"))?;
        Ok(ApiResult::ok(rows))
    }

    /// Update a ticket's status/priority/assignment with lifecycle enforcement.
    pub async fn update_ticket(
        &self,
        id: Uuid,
        status: Option<&str>,
        priority: Option<&str>,
        assigned_to: Option<Uuid>,
    ) -> Result<ApiResult<SupportTicket>, String> {
        if let Some(s) = status {
            if !is_valid_status(s) {
                return Ok(ApiResult::err(
                    format!("status must be one of: {}", TICKET_STATUSES.join(", ")),
                    "VALIDATION",
                ));
            }
        }
        if let Some(p) = priority {
            if !is_valid_priority(p) {
                return Ok(ApiResult::err(
                    format!(
                        "priority must be one of: {}",
                        TICKET_PRIORITIES.join(", ")
                    ),
                    "VALIDATION",
                ));
            }
        }

        // Enforce valid transitions against the CURRENT status: an
        // invalid-state write (e.g. resolved → pending) must be rejected
        // before any column is touched.
        let current = match self.get_ticket(id).await? {
            ApiResult { data: Some(t), .. } => t,
            ApiResult { error, .. } => {
                return Ok(ApiResult::err(
                    error.unwrap_or_else(|| "Ticket not found".into()),
                    "NOT_FOUND",
                ))
            }
        };
        if let Some(new_status) = status {
            if !is_valid_ticket_transition(&current.status, new_status) {
                return Ok(ApiResult::err(
                    format!(
                        "invalid status transition '{}' → '{}' (ticket {})",
                        current.status, new_status, id
                    ),
                    "INVALID_TRANSITION",
                ));
            }
        }

        let now = Utc::now();
        // Fix J-6: first_response_at is only stamped when the update moves the
        // ticket to a staff-facing status — a status set from the customer
        // side (e.g. 'waiting_customer') or any non-transition no longer
        // fabricates a "first response".
        //
        // The `AND status = $6` guard makes the transition check above
        // race-free: if another request changed the status between the read
        // and this write, the UPDATE matches no row and the caller gets a
        // 409 instead of an out-of-order transition being persisted.
        let row = sqlx::query_as::<_, SupportTicket>(
            "UPDATE ent_support_tickets SET
             status = COALESCE($2, status),
             priority = COALESCE($3, priority),
             assigned_to = COALESCE($4, assigned_to),
             first_response_at = CASE WHEN first_response_at IS NULL
                 AND $2 IN ('open', 'pending', 'on_hold', 'escalated', 'resolved', 'closed')
                 THEN $5 ELSE first_response_at END,
             updated_at = $5
             WHERE id = $1 AND status = $6 RETURNING *"
        )
        .bind(id).bind(status).bind(priority)
        .bind(assigned_to).bind(now).bind(&current.status)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Update ticket: {e}"))?;

        match row {
            Some(t) => Ok(ApiResult::ok(t)),
            None => {
                // No row: either the ticket never existed or its status
                // changed concurrently since the transition check above.
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM ent_support_tickets WHERE id = $1)",
                )
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Update ticket existence check: {e}"))?
                .unwrap_or(false);
                if exists {
                    Ok(ApiResult::err(
                        format!(
                            "ticket {} was modified concurrently — retry with the current status",
                            id
                        ),
                        "INVALID_TRANSITION",
                    ))
                } else {
                    Ok(ApiResult::err("Ticket not found", "NOT_FOUND"))
                }
            }
        }
    }

    /// Add a comment to a ticket
    pub async fn add_comment(
        &self,
        ticket_id: Uuid,
        author_id: &str,
        author_name: &str,
        author_type: &str,
        content: &str,
        is_internal: bool,
    ) -> Result<ApiResult<TicketComment>, String> {
        if !is_valid_author_type(author_type) {
            return Ok(ApiResult::err(
                format!(
                    "author_type must be one of: {}",
                    TICKET_AUTHOR_TYPES.join(", ")
                ),
                "VALIDATION",
            ));
        }
        if author_id.trim().is_empty() || author_id.chars().count() > TICKET_AUTHOR_MAX_CHARS {
            return validation_comment_err("author_id must be 1..=255 characters");
        }
        if author_name.trim().is_empty() || author_name.chars().count() > TICKET_AUTHOR_MAX_CHARS {
            return validation_comment_err("author_name must be 1..=255 characters");
        }
        let content_trimmed = content.trim();
        if content_trimmed.is_empty() {
            return validation_comment_err("content must not be empty");
        }
        if content.chars().count() > TICKET_COMMENT_MAX_CHARS {
            return validation_comment_err(format!(
                "content must not exceed {TICKET_COMMENT_MAX_CHARS} characters"
            ));
        }

        // Lifecycle rule: closed tickets accept internal (audit) notes only.
        let ticket = match self.get_ticket(ticket_id).await? {
            ApiResult { data: Some(t), .. } => t,
            ApiResult { error, .. } => {
                return Ok(ApiResult::err(
                    error.unwrap_or_else(|| "Ticket not found".into()),
                    "NOT_FOUND",
                ))
            }
        };
        if !can_comment(&ticket.status, is_internal) {
            return Ok(ApiResult::err(
                format!(
                    "ticket {} is closed — only internal notes are accepted; reopen the ticket first",
                    ticket_id
                ),
                "INVALID_TRANSITION",
            ));
        }

        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, TicketComment>(
            "INSERT INTO ent_ticket_comments (id, ticket_id, author_id, author_name, author_type, content, is_internal, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
             RETURNING *"
        )
        .bind(id).bind(ticket_id).bind(author_id.trim()).bind(author_name.trim())
        .bind(author_type).bind(content_trimmed).bind(is_internal)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Add comment: {e}"))?;

        // Mark first response time only for a PUBLIC agent reply — an
        // internal note is not a response the customer received, so it must
        // not start the first-response clock.
        if author_type == "agent" && !is_internal {
            if let Err(e) = sqlx::query(
                "UPDATE ent_support_tickets SET first_response_at = COALESCE(first_response_at, NOW()), updated_at = NOW() WHERE id = $1"
            )
            .bind(ticket_id)
            .execute(&self.db)
            .await
            {
                tracing::warn!(ticket_id = %ticket_id, error = %e, "Failed to update first_response_at");
            }

            // Notify the requester about the public agent reply.
            if let Some(email) = ticket.contact_email.as_deref() {
                if is_plausible_email(email) {
                    self.notifier
                        .queue_email(
                            Some(&ticket.tenant_id),
                            email,
                            &format!(
                                "[ApexMail Support] Update on ticket #{:?}",
                                ticket.number
                            ),
                            &format!(
                                "There is a new reply on your ticket \"{}\":\n\n{}",
                                sanitize_notification_text(&ticket.subject),
                                content_trimmed
                            ),
                            "ticket_reply_requester",
                        )
                        .await;
                }
            }
        }

        Ok(ApiResult::ok(row))
    }

    /// Get comments for a ticket
    pub async fn get_comments(
        &self,
        ticket_id: Uuid,
        include_internal: bool,
    ) -> Result<ApiResult<Vec<TicketComment>>, String> {
        let rows = if include_internal {
            sqlx::query_as::<_, TicketComment>(
                "SELECT * FROM ent_ticket_comments WHERE ticket_id = $1 ORDER BY created_at ASC"
            )
            .bind(ticket_id)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as::<_, TicketComment>(
                "SELECT * FROM ent_ticket_comments WHERE ticket_id = $1 AND is_internal = false ORDER BY created_at ASC"
            )
            .bind(ticket_id)
            .fetch_all(&self.db)
            .await
        }.map_err(|e| format!("Get comments: {e}"))?;

        Ok(ApiResult::ok(rows))
    }

    /// Escalate a ticket
    pub async fn escalate(
        &self,
        id: Uuid,
        reason: &str,
        escalated_by: Uuid,
    ) -> Result<ApiResult<SupportTicket>, String> {
        let reason_trimmed = reason.trim();
        if reason_trimmed.is_empty() {
            return Ok(ApiResult::err("escalation reason must not be empty", "VALIDATION"));
        }
        if reason.chars().count() > TICKET_REASON_MAX_CHARS {
            return Ok(ApiResult::err(
                format!("escalation reason must not exceed {TICKET_REASON_MAX_CHARS} characters"),
                "VALIDATION",
            ));
        }

        // Escalating a resolved/closed ticket is an invalid-state write.
        let ticket = match self.get_ticket(id).await? {
            ApiResult { data: Some(t), .. } => t,
            ApiResult { error, .. } => {
                return Ok(ApiResult::err(
                    error.unwrap_or_else(|| "Ticket not found".into()),
                    "NOT_FOUND",
                ))
            }
        };
        if !can_escalate(&ticket.status) {
            return Ok(ApiResult::err(
                format!(
                    "ticket {} is '{}' and cannot be escalated; reopen it first",
                    id, ticket.status
                ),
                "INVALID_TRANSITION",
            ));
        }

        // #263:Store reason and escalated_by in the update
        let row = sqlx::query_as::<_, SupportTicket>(
            "UPDATE ent_support_tickets SET
             status = 'escalated',
             escalation_level = escalation_level + 1,
             escalated_at = NOW(),
             escalation_reason = $2,
             escalated_by = $3,
             updated_at = NOW()
             WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(reason_trimmed)
        .bind(escalated_by)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Escalate ticket: {e}"))?;

        match row {
            Some(t) => {
                info!(ticket_id = %id, "Ticket escalated");

                // Notification hook: the assignee must learn about the escalation.
                if let Some(agent_id) = t.assigned_to {
                    if let Ok(Some(agent_email)) = self.agent_email(agent_id).await {
                        self.notifier
                            .queue_email(
                                Some(&t.tenant_id),
                                &agent_email,
                                &format!(
                                    "[ApexMail Support] Ticket #{:?} escalated (level {})",
                                    t.number, t.escalation_level
                                ),
                                &format!(
                                    "Ticket \"{}\" has been escalated to level {}.\nReason: {}",
                                    sanitize_notification_text(&t.subject),
                                    t.escalation_level,
                                    reason_trimmed
                                ),
                                "ticket_escalated_assignee",
                            )
                            .await;
                    }
                }

                Ok(ApiResult::ok(t))
            }
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

    /// Submit customer satisfaction rating.
    ///
    /// One submission per ticket, immutable once set: the UPDATE only fires
    /// while `satisfaction_rating IS NULL`, and a second submission returns
    /// ALREADY_SUBMITTED (409 at the route layer).
    pub async fn submit_satisfaction(
        &self,
        id: Uuid,
        rating: i32,
        feedback: Option<&str>,
    ) -> Result<ApiResult<SupportTicket>, String> {
        if !(SATISFACTION_RATING_MIN..=SATISFACTION_RATING_MAX).contains(&rating) {
            return Ok(ApiResult::err(
                format!(
                    "rating must be between {SATISFACTION_RATING_MIN} and {SATISFACTION_RATING_MAX}"
                ),
                "VALIDATION",
            ));
        }
        if let Some(fb) = feedback {
            if fb.chars().count() > TICKET_FEEDBACK_MAX_CHARS {
                return Ok(ApiResult::err(
                    format!("feedback must not exceed {TICKET_FEEDBACK_MAX_CHARS} characters"),
                    "VALIDATION",
                ));
            }
        }

        // #262:Store feedback in the satisfaction_feedback column.
        // Fix J-6: satisfaction is typically submitted after resolution; the
        // update deliberately does not bump `updated_at` so post-resolution
        // feedback does not skew avg_resolution_minutes.
        let row = sqlx::query_as::<_, SupportTicket>(SUBMIT_SATISFACTION_SQL)
            .bind(id)
            .bind(rating)
            .bind(feedback)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| format!("Submit satisfaction: {e}"))?;

        match row {
            // No row back: either the ticket does not exist or it already
            // carries a rating. Distinguish so the client gets the right code.
            None => {
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM ent_support_tickets WHERE id = $1)",
                )
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Submit satisfaction existence check: {e}"))?
                .unwrap_or(false);
                if exists {
                    Ok(ApiResult::err(
                        "satisfaction already submitted for this ticket and is immutable",
                        "ALREADY_SUBMITTED",
                    ))
                } else {
                    Ok(ApiResult::err("Ticket not found", "NOT_FOUND"))
                }
            }
            Some(t) => Ok(ApiResult::ok(t)),
        }
    }

    /// Get aggregate support metrics for a tenant
    pub async fn get_metrics(&self, tenant_id: &str) -> Result<ApiResult<SupportMetrics>, String> {
        let row: (i64, i64, Option<f64>, Option<f64>, Option<f64>) = sqlx::query_as(
            "SELECT
             COUNT(*),
             COUNT(*) FILTER (WHERE status IN ('open','new','pending')),
             AVG(EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60.0)::float8,
             AVG(CASE WHEN status IN ('resolved','closed') THEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 60.0 END)::float8,
             AVG(satisfaction_rating)::float8
             FROM ent_support_tickets WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Get metrics: {e}"))?;

        // Fix J-6: the SLA compliance denominator is ALL tickets in the
        // tenant, not just the subset that already has a first response —
        // the old formula measured "of the tickets we responded to, how many
        // were on time", which ignored every unanswered ticket.
        let sla_row: (i64, i64) = sqlx::query_as(
            "SELECT
             COUNT(*) FILTER (WHERE first_response_at IS NOT NULL AND first_response_at <= sla_first_response_due),
             COUNT(*)
             FROM ent_support_tickets WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("SLA metrics: {e}"))?;

        let sla_compliance_rate = if sla_row.1 > 0 {
            (sla_row.0 as f64 / sla_row.1 as f64) * 100.0
        } else {
            100.0
        };

        Ok(ApiResult::ok(SupportMetrics {
            total_tickets: row.0,
            open_tickets: row.1,
            avg_first_response_minutes: row.2.unwrap_or(0.0),
            avg_resolution_minutes: row.3.unwrap_or(0.0),
            satisfaction_avg: row.4.unwrap_or(0.0),
            sla_compliance_rate,
            tickets_by_priority: serde_json::json!({}),
            tickets_by_category: serde_json::json!({}),
        }))
    }

    /// Get agent workload for ticket assignment
    pub async fn get_agent_workload(&self) -> Result<Vec<(SupportAgent, i64)>, String> {
        let rows: Vec<SupportAgent> = sqlx::query_as::<_, SupportAgent>(
            "SELECT * FROM ent_support_agents WHERE available = true ORDER BY current_ticket_count ASC"
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Agent workload: {e}"))?;

        Ok(rows
            .into_iter()
            .map(|a| {
                let count = a.current_ticket_count as i64;
                (a, count)
            })
            .collect())
    }

    /// Resolve an agent's notification email address (None on unknown agent).
    async fn agent_email(&self, agent_id: Uuid) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, String>(
            "SELECT email FROM ent_support_agents WHERE id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&self.db)
        .await
    }

    /// Auto-assign to least loaded agent with optional specialty match
    /// #264:Now increments the assigned agent's current_ticket_count
    async fn auto_assign_agent(&self, category: &str) -> Result<Option<Uuid>, String> {
        // Try to find an agent with matching specialty first
        let row: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE ent_support_agents 
             SET current_ticket_count = current_ticket_count + 1
             WHERE id = (
                 SELECT id FROM ent_support_agents
                 WHERE available = true AND $1 = ANY(specialties)
                 ORDER BY current_ticket_count ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id",
        )
        .bind(category)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Auto-assign (specialty): {e}"))?;

        if let Some((id,)) = row {
            return Ok(Some(id));
        }

        // Fallback:assign to any available agent
        let row: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE ent_support_agents 
             SET current_ticket_count = current_ticket_count + 1
             WHERE id = (
                 SELECT id FROM ent_support_agents
                 WHERE available = true
                 ORDER BY current_ticket_count ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id",
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Auto-assign (fallback): {e}"))?;

        Ok(row.map(|(id,)| id))
    }

    /// Check SLA breaches (background job)
    pub async fn check_sla_breaches(&self) -> Result<Vec<SupportTicket>, String> {
        let now = Utc::now();
        let tickets = match sqlx::query_as::<_, SupportTicket>(
            "SELECT * FROM ent_support_tickets
             WHERE status NOT IN ('resolved','closed')
             AND sla_breached = false
             AND (
               (first_response_at IS NULL AND sla_first_response_due < $1)
               OR (sla_resolution_due < $1)
             )",
        )
        .bind(now)
        .fetch_all(&self.db)
        .await
        {
            Ok(tickets) => tickets,
            Err(error) if is_missing_relation_error(&error) => {
                log_missing_support_tickets_once("check_sla_breaches");
                return Ok(vec![]);
            }
            Err(error) => return Err(format!("SLA breach check: {error}")),
        };

        for ticket in &tickets {
            if let Err(e) =
                sqlx::query("UPDATE ent_support_tickets SET sla_breached = true WHERE id = $1")
                    .bind(ticket.id)
                    .execute(&self.db)
                    .await
            {
                tracing::error!(error = %e, ticket_id = %ticket.id, "Failed to mark SLA breach — ticket will be retried next cycle");
            }
            info!(ticket_id = %ticket.id, priority = %ticket.priority, "SLA breach detected");

            // Notification hook: assignee learns about the breach.
            if let Some(agent_id) = ticket.assigned_to {
                if let Ok(Some(agent_email)) = self.agent_email(agent_id).await {
                    self.notifier
                        .queue_email(
                            Some(&ticket.tenant_id),
                            &agent_email,
                            &format!(
                                "[ApexMail Support] SLA breached on ticket #{:?}",
                                ticket.number
                            ),
                            &format!(
                                "SLA breached on ticket \"{}\" (priority {}). First response due {} / resolution due {}.",
                                sanitize_notification_text(&ticket.subject),
                                ticket.priority,
                                ticket
                                    .sla_first_response_due
                                    .map(|t| t.to_rfc3339())
                                    .unwrap_or_else(|| "n/a".into()),
                                ticket
                                    .sla_resolution_due
                                    .map(|t| t.to_rfc3339())
                                    .unwrap_or_else(|| "n/a".into()),
                            ),
                            "ticket_sla_breach_assignee",
                        )
                        .await;
                }
            }
        }
        Ok(tickets)
    }

    /// Auto-escalation (background job).
    ///
    /// Thresholds come from [`auto_escalation_thresholds`] so the rules and
    /// their tests can never drift apart. Every ticket the thresholds promote
    /// also triggers the assignee notification hook — an escalation nobody
    /// hears about is not an escalation.
    pub async fn auto_escalate(&self) -> Result<i64, String> {
        let now = Utc::now();
        let rules = auto_escalation_thresholds()
            .into_iter()
            .map(|(priority, minutes)| {
                (priority, TimeDelta::try_minutes(minutes).unwrap_or(TimeDelta::zero()))
            })
            .collect::<Vec<_>>();

        let mut escalated = 0i64;
        for (priority, threshold) in rules {
            let cutoff = now - threshold;
            let rows = match sqlx::query_as::<_, SupportTicket>(
                "UPDATE ent_support_tickets SET status = 'escalated', escalation_level = escalation_level + 1, escalated_at = NOW(), updated_at = NOW()
                 WHERE status = 'open' AND priority = $1 AND escalation_level = 0 AND created_at < $2
                 RETURNING *",
            )
            .bind(priority)
            .bind(cutoff)
            .fetch_all(&self.db)
            .await
            {
                Ok(rows) => rows,
                Err(error) if is_missing_relation_error(&error) => {
                    log_missing_support_tickets_once("auto_escalate");
                    return Ok(0);
                }
                Err(error) => return Err(format!("Auto-escalate: {error}")),
            };
            escalated += rows.len() as i64;

            for t in &rows {
                if let Some(agent_id) = t.assigned_to {
                    if let Ok(Some(agent_email)) = self.agent_email(agent_id).await {
                        self.notifier
                            .queue_email(
                                Some(&t.tenant_id),
                                &agent_email,
                                &format!(
                                    "[ApexMail Support] Ticket #{:?} auto-escalated ({} overdue)",
                                    t.number, priority
                                ),
                                &format!(
                                    "Ticket \"{}\" exceeded its {} escalation threshold and was auto-escalated to level {}.\nIt has been waiting since {}.",
                                    sanitize_notification_text(&t.subject),
                                    priority,
                                    t.escalation_level,
                                    t.created_at
                                        .map(|ts| ts.to_rfc3339())
                                        .unwrap_or_else(|| "n/a".into()),
                                ),
                                "ticket_auto_escalated_assignee",
                            )
                            .await;
                    }
                }
            }
        }

        if escalated > 0 {
            info!(count = escalated, "Auto-escalated tickets");
        }
        Ok(escalated)
    }
}

/// Calculate auto-escalation thresholds in minutes
pub fn auto_escalation_thresholds() -> Vec<(&'static str, i64)> {
    vec![("critical", 30), ("high", 60), ("medium", 120)]
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_deadlines_all_priorities() {
        let (fr, res) = sla_deadlines("critical");
        assert_eq!(fr, 15);
        assert_eq!(res, 240);
        let (fr, res) = sla_deadlines("high");
        assert_eq!(fr, 60);
        assert_eq!(res, 480);
        let (fr, res) = sla_deadlines("medium");
        assert_eq!(fr, 240);
        assert_eq!(res, 1440);
        let (fr, res) = sla_deadlines("low");
        assert_eq!(fr, 480);
        assert_eq!(res, 4320);
    }

    #[test]
    fn test_sla_critical_is_fastest() {
        let (c_fr, _) = sla_deadlines("critical");
        let (h_fr, _) = sla_deadlines("high");
        assert!(c_fr < h_fr);
    }

    #[test]
    fn test_auto_escalation_thresholds() {
        let t = auto_escalation_thresholds();
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].0, "critical");
        assert_eq!(t[0].1, 30);
    }

    // ── lifecycle: valid transitions ────────────────────────────────────

    #[test]
    fn valid_lifecycle_walkthrough_is_accepted() {
        let steps = [
            ("new", "open"),
            ("open", "pending"),
            ("pending", "waiting_customer"),
            ("waiting_customer", "escalated"),
            ("escalated", "open"),
            ("open", "on_hold"),
            ("on_hold", "resolved"),
            ("resolved", "closed"),
            ("closed", "open"), // reopen
        ];
        for (from, to) in steps {
            assert!(
                is_valid_ticket_transition(from, to),
                "transition {from} → {to} must be valid"
            );
        }
    }

    #[test]
    fn invalid_lifecycle_transitions_are_rejected() {
        let invalid = [
            ("resolved", "pending"),
            ("resolved", "escalated"),
            ("resolved", "waiting_customer"),
            ("closed", "escalated"),
            ("closed", "resolved"),
            ("closed", "pending"),
            ("on_hold", "waiting_customer"),
            ("bogus", "open"),
            ("open", "bogus"),
        ];
        for (from, to) in invalid {
            assert!(
                !is_valid_ticket_transition(from, to),
                "transition {from} → {to} must be rejected"
            );
        }
    }

    #[test]
    fn same_status_update_is_a_no_op_not_a_transition_error() {
        for status in TICKET_STATUSES {
            assert!(is_valid_ticket_transition(status, status));
        }
    }

    #[test]
    fn enum_validation_rejects_unknown_values() {
        for s in TICKET_STATUSES {
            assert!(is_valid_status(s));
        }
        for s in ["in_progress", "done", "", "OPEN"] {
            assert!(!is_valid_status(s), "{s} must not be a status");
        }
        for p in TICKET_PRIORITIES {
            assert!(is_valid_priority(p));
        }
        for p in ["urgent", "", "CRITICAL", "sev1"] {
            assert!(!is_valid_priority(p), "{p} must not be a priority");
        }
        for a in TICKET_AUTHOR_TYPES {
            assert!(is_valid_author_type(a));
        }
        for a in ["admin", "", "bot"] {
            assert!(!is_valid_author_type(a), "{a} must not be an author type");
        }
    }

    #[test]
    fn terminal_tickets_cannot_be_escalated() {
        assert!(can_escalate("open"));
        assert!(can_escalate("new"));
        assert!(can_escalate("pending"));
        assert!(can_escalate("escalated"));
        assert!(!can_escalate("resolved"));
        assert!(!can_escalate("closed"));
    }

    #[test]
    fn closed_tickets_accept_internal_notes_only() {
        assert!(can_comment("closed", true));
        assert!(!can_comment("closed", false));
        assert!(can_comment("open", false));
        assert!(can_comment("resolved", false));
    }

    #[test]
    fn satisfaction_rating_bounds_match_schema_check() {
        for rating in SATISFACTION_RATING_MIN..=SATISFACTION_RATING_MAX {
            assert!((SATISFACTION_RATING_MIN..=SATISFACTION_RATING_MAX).contains(&rating));
        }
        for rating in [-1, 0, 6, 10, i32::MIN, i32::MAX] {
            assert!(!(SATISFACTION_RATING_MIN..=SATISFACTION_RATING_MAX).contains(&rating));
        }
    }

    // ── pagination cursor ───────────────────────────────────────────────

    #[test]
    fn ticket_cursor_parses_rfc3339_and_uuid() {
        let cursor = TicketCursor::parse("2026-08-21T12:00:00Z,0f0e0d0c-1111-4222-8333-444455556666")
            .expect("valid cursor");
        assert_eq!(cursor.id.to_string(), "0f0e0d0c-1111-4222-8333-444455556666");
        assert_eq!(cursor.created_at.to_rfc3339(), "2026-08-21T12:00:00+00:00");
    }

    #[test]
    fn ticket_cursor_rejects_malformed_input() {
        assert!(TicketCursor::parse("not-a-cursor").is_err());
        assert!(TicketCursor::parse("2026-08-21,not-a-uuid").is_err());
        assert!(TicketCursor::parse("yesterday,0f0e0d0c-1111-4222-8333-444455556666").is_err());
        assert!(TicketCursor::parse("").is_err());
    }

    // ── email sanity ────────────────────────────────────────────────────

    #[test]
    fn plausible_email_accepts_and_rejects_expected_shapes() {
        for good in ["user@example.com", "first.last+tag@sub.example.co.uk"] {
            assert!(is_plausible_email(good), "{good} must be accepted");
        }
        for bad in [
            "",
            "no-at-sign",
            "two@ats@here",
            "@example.com",
            "user@localhost",
            "user @example.com",
            "user@example.com\r\nBcc: attacker@evil.example",
            "user@@example.com",
        ] {
            assert!(!is_plausible_email(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn notification_text_strips_line_breaks_and_control_smuggling() {
        let dirty = "Subject\r\nBcc: attacker@evil.example";
        let clean = sanitize_notification_text(dirty);
        assert!(!clean.contains('\r'), "CR must be stripped");
        assert!(!clean.contains('\n'), "LF must be stripped");
        assert_eq!(clean, "Subject Bcc: attacker@evil.example");
    }

    #[test]
    fn notification_tenant_uuid_only_accepts_uuid_shaped_ids() {
        // email_queue.tenant_id is UUID-typed; enterprise tenants are
        // VARCHAR(26) ULIDs. A ULID must map to NULL (recorded in metadata
        // instead), never be bound as a string to the UUID column.
        assert_eq!(notification_tenant_uuid(None), None);
        assert_eq!(notification_tenant_uuid(Some("")), None);
        assert_eq!(notification_tenant_uuid(Some("   ")), None);
        assert_eq!(
            notification_tenant_uuid(Some("01ARZ3NDEKTSV4RRFFQ69G5FAV")),
            None,
            "ULID-shaped tenant ids are not UUIDs"
        );
        let uuid = "0f0e0d0c-1111-4222-8333-444455556666";
        assert_eq!(
            notification_tenant_uuid(Some(uuid)),
            Some(uuid.parse::<Uuid>().unwrap())
        );
    }

    #[test]
    fn like_wildcards_are_escaped_for_literal_search() {
        assert_eq!(escape_like_wildcards("plain"), "plain");
        assert_eq!(escape_like_wildcards("100%_done"), "100\\%\\_done");
        assert_eq!(escape_like_wildcards("back\\slash"), "back\\\\slash");
        assert_eq!(escape_like_wildcards(""), "");
    }

    #[test]
    fn auto_escalation_thresholds_rank_by_urgency() {
        let t = auto_escalation_thresholds();
        assert!(t.len() >= 3);
        // critical < high < medium — more urgent priorities escalate sooner.
        let get = |p: &str| {
            t.iter()
                .find(|(k, _)| *k == p)
                .map(|(_, m)| *m)
                .unwrap_or_else(|| panic!("missing threshold for {p}"))
        };
        assert!(get("critical") < get("high"));
        assert!(get("high") < get("medium"));
        for (_, minutes) in &t {
            assert!(*minutes > 0, "thresholds must be positive");
        }
    }

    #[test]
    fn satisfaction_write_is_guarded_to_first_submission_only() {
        assert!(
            SUBMIT_SATISFACTION_SQL.contains("AND satisfaction_rating IS NULL"),
            "satisfaction UPDATE must only fire while no rating exists (immutability)"
        );
    }

    #[test]
    fn escalation_only_prompts_working_tickets() {
        // The auto-escalation UPDATE only touches status = 'open' tickets —
        // this pins the domain rule that SQL encodes: only a working status
        // may enter 'escalated', never a terminal one.
        for from in ["open", "new", "pending", "waiting_customer"] {
            assert!(
                is_valid_ticket_transition(from, "escalated"),
                "{from} → escalated must be valid"
            );
        }
    }

    #[test]
    fn test_support_metrics_serialization() {
        let m = SupportMetrics {
            total_tickets: 100,
            open_tickets: 20,
            avg_first_response_minutes: 12.5,
            avg_resolution_minutes: 180.0,
            sla_compliance_rate: 95.2,
            satisfaction_avg: 4.5,
            tickets_by_priority: serde_json::json!({"critical": 5, "high": 15}),
            tickets_by_category: serde_json::json!({"delivery": 10, "billing": 10}),
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["total_tickets"], 100);
        assert_eq!(json["sla_compliance_rate"], 95.2);
    }

    #[test]
    fn test_ticket_comment_serialization() {
        let c = TicketComment {
            id: Uuid::new_v4(),
            ticket_id: Uuid::new_v4(),
            author_id: "user-123".into(),
            author_name: "John Doe".into(),
            author_type: "agent".into(),
            content: "We're looking into this.".into(),
            is_internal: false,
            attachments: None,
            created_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["author_type"], "agent");
        assert!(!json["is_internal"].as_bool().unwrap());
    }

    #[test]
    fn test_support_agent_serialization() {
        let a = SupportAgent {
            id: Uuid::new_v4(),
            user_id: "usr-001".into(),
            name: "John Doe".into(),
            email: "john@example.com".into(),
            team: Some("tier-1".into()),
            role: Some("senior".into()),
            max_tickets: 10,
            current_ticket_count: 3,
            specialties: Some(vec!["billing".into(), "technical".into()]),
            available: true,
            last_assignment_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["specialties"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_support_ticket_serialization() {
        let t = SupportTicket {
            id: Uuid::new_v4(),
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            number: Some(1001),
            subject: "Cannot send emails".into(),
            description: "Getting 500 errors".into(),
            category: "technical".into(),
            priority: "critical".into(),
            status: "open".into(),
            assigned_to: None,
            team: None,
            sla_first_response_due: Some(Utc::now()),
            sla_resolution_due: Some(Utc::now()),
            sla_breached: false,
            first_response_at: None,
            escalation_level: 0,
            escalated_at: None,
            created_by: "system".into(),
            contact_email: Some("user@test.com".into()),
            satisfaction_rating: None,
            tags: None,
            custom_fields: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["priority"], "critical");
        assert_eq!(json["status"], "open");
    }
}
