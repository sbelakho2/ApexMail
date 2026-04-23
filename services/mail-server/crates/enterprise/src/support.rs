use std::sync::Once;

use chrono::{Duration, TimeDelta, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

static SUPPORT_TICKETS_MISSING_WARNING: Once = Once::new();

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

/// Support Service:enterprise tickets, SLA tracking, agent assignment, escalation
pub struct SupportService {
    db: PgPool,
}

impl SupportService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

/// Create a support ticket with SLA deadline calculation
    pub async fn create_ticket(
        &self, tenant_id: Uuid, subject: &str, description: &str,
        priority: &str, category: &str, contact_email: Option<&str>,
    ) -> Result<ApiResult<SupportTicket>, String> {
        let id = Uuid::new_v4();

// Calculate SLA deadlines based on priority
        let (fr_minutes, res_minutes) = sla_deadlines(priority);
        let sla_first_response_due = Utc::now() + Duration::minutes(fr_minutes);
        let sla_resolution_due = Utc::now() + Duration::minutes(res_minutes);

// Auto-assign to least loaded agent with specialty matching
        let assigned_to = self.auto_assign_agent(category).await?;

        let row = sqlx::query_as::<_, SupportTicket>(
            "INSERT INTO ent_support_tickets (id, tenant_id, subject, description, status, priority, category, contact_email, assigned_to, sla_first_response_due, sla_resolution_due, sla_breached, escalation_level, created_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,'open',$5,$6,$7,$8,$9,$10,false,0,'system',NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_id).bind(subject).bind(description)
        .bind(priority).bind(category).bind(contact_email)
        .bind(assigned_to.as_ref())
        .bind(sla_first_response_due).bind(sla_resolution_due)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create ticket: {e}"))?;

        info!(ticket_id = %id, priority = priority, "Support ticket created");
        Ok(ApiResult::ok(row))
    }

/// Get a ticket by ID
    pub async fn get_ticket(&self, id: Uuid) -> Result<ApiResult<SupportTicket>, String> {
        let row = sqlx::query_as::<_, SupportTicket>(
            "SELECT * FROM ent_support_tickets WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get ticket: {e}"))?;

        match row {
            Some(t) => Ok(ApiResult::ok(t)),
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

/// List tickets with optional filters
    pub async fn list_tickets(
        &self, tenant_id: Uuid, status: Option<&str>, priority: Option<&str>,
        limit: i64, offset: i64,
    ) -> Result<ApiResult<Vec<SupportTicket>>, String> {
        let mut query = String::from("SELECT * FROM ent_support_tickets WHERE tenant_id = $1");
        let mut param_idx = 2u32;
        let mut params: Vec<String> = vec![];

        if let Some(s) = status {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
            params.push(s.to_string());
        }
        if let Some(p) = priority {
            query.push_str(&format!(" AND priority = ${param_idx}"));
            param_idx += 1;
            params.push(p.to_string());
        }
        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, SupportTicket>(&query).bind(tenant_id);
        for p in &params {
            q = q.bind(p.as_str());
        }
        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(&self.db).await.map_err(|e| format!("List tickets: {e}"))?;
        Ok(ApiResult::ok(rows))
    }

/// Update a ticket's status
    pub async fn update_ticket(
        &self, id: Uuid, status: Option<&str>, priority: Option<&str>,
        assigned_to: Option<Uuid>,
    ) -> Result<ApiResult<SupportTicket>, String> {
        let now = Utc::now();
        let row = sqlx::query_as::<_, SupportTicket>(
            "UPDATE ent_support_tickets SET
             status = COALESCE($2, status),
             priority = COALESCE($3, priority),
             assigned_to = COALESCE($4, assigned_to),
             first_response_at = CASE WHEN first_response_at IS NULL AND $2 IS NOT NULL THEN $5 ELSE first_response_at END,
             updated_at = $5
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(status).bind(priority)
        .bind(assigned_to).bind(now)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Update ticket: {e}"))?;

        match row {
            Some(t) => Ok(ApiResult::ok(t)),
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

/// Add a comment to a ticket
    pub async fn add_comment(
        &self, ticket_id: Uuid, author_id: &str, author_name: &str,
        author_type: &str, content: &str, is_internal: bool,
    ) -> Result<ApiResult<TicketComment>, String> {
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, TicketComment>(
            "INSERT INTO ent_ticket_comments (id, ticket_id, author_id, author_name, author_type, content, is_internal, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
             RETURNING *"
        )
        .bind(id).bind(ticket_id).bind(author_id).bind(author_name)
        .bind(author_type).bind(content).bind(is_internal)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Add comment: {e}"))?;

// Mark first response time if this is an agent reply
        if author_type == "agent" {
            if let Err(e) = sqlx::query(
                "UPDATE ent_support_tickets SET first_response_at = COALESCE(first_response_at, NOW()), updated_at = NOW() WHERE id = $1"
            )
            .bind(ticket_id)
            .execute(&self.db)
            .await
            {
                tracing::warn!(ticket_id = %ticket_id, error = %e, "Failed to update first_response_at");
            }
        }

        Ok(ApiResult::ok(row))
    }

/// Get comments for a ticket
    pub async fn get_comments(
        &self, ticket_id: Uuid, include_internal: bool,
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
        &self, id: Uuid, reason: &str, escalated_by: Uuid,
    ) -> Result<ApiResult<SupportTicket>, String> {
// #263:Store reason and escalated_by in the update
        let row = sqlx::query_as::<_, SupportTicket>(
            "UPDATE ent_support_tickets SET
             status = 'escalated',
             escalation_level = escalation_level + 1,
             escalated_at = NOW(),
             escalation_reason = $2,
             escalated_by = $3,
             updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .bind(reason)
        .bind(escalated_by)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Escalate ticket: {e}"))?;

        match row {
            Some(t) => {
                info!(ticket_id = %id, "Ticket escalated");
                Ok(ApiResult::ok(t))
            }
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

/// Submit customer satisfaction rating
    pub async fn submit_satisfaction(
        &self, id: Uuid, rating: i32, feedback: Option<&str>,
    ) -> Result<ApiResult<SupportTicket>, String> {
// #262:Store feedback in the satisfaction_feedback column
        let row = sqlx::query_as::<_, SupportTicket>(
            "UPDATE ent_support_tickets SET 
             satisfaction_rating = $2, 
             satisfaction_feedback = $3,
             updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(rating).bind(feedback)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Submit satisfaction: {e}"))?;

        match row {
            Some(t) => Ok(ApiResult::ok(t)),
            None => Ok(ApiResult::err("Ticket not found", "NOT_FOUND")),
        }
    }

/// Get aggregate support metrics for a tenant
    pub async fn get_metrics(&self, tenant_id: Uuid) -> Result<ApiResult<SupportMetrics>, String> {
        let row: (i64, i64, Option<f64>, Option<f64>, Option<f64>) = sqlx::query_as(
            "SELECT
             COUNT(*),
             COUNT(*) FILTER (WHERE status IN ('open','new','pending')),
             AVG(EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60.0)::float8,
             AVG(CASE WHEN status = 'resolved' THEN EXTRACT(EPOCH FROM (updated_at - created_at)) / 60.0 END)::float8,
             AVG(satisfaction_rating)::float8
             FROM ent_support_tickets WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Get metrics: {e}"))?;

// SLA compliance
        let sla_row: (i64, i64) = sqlx::query_as(
            "SELECT
             COUNT(*) FILTER (WHERE first_response_at IS NOT NULL AND first_response_at <= sla_first_response_due),
             COUNT(*) FILTER (WHERE first_response_at IS NOT NULL)
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

        Ok(rows.into_iter().map(|a| {
            let count = a.current_ticket_count as i64;
            (a, count)
        }).collect())
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
             RETURNING id"
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
             RETURNING id"
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
             )"
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
            if let Err(e) = sqlx::query("UPDATE ent_support_tickets SET sla_breached = true WHERE id = $1")
                .bind(ticket.id)
                .execute(&self.db)
                .await
            {
                tracing::error!(error = %e, ticket_id = %ticket.id, "Failed to mark SLA breach — ticket will be retried next cycle");
            }
            info!(ticket_id = %ticket.id, priority = %ticket.priority, "SLA breach detected");
        }
        Ok(tickets)
    }

/// Auto-escalation (background job)
    pub async fn auto_escalate(&self) -> Result<i64, String> {
        let now = Utc::now();
        let rules = vec![
            (
                "critical",
                TimeDelta::try_minutes(30).unwrap_or(TimeDelta::zero()),
            ),
            ("high", TimeDelta::try_hours(1).unwrap_or(TimeDelta::zero())),
            ("medium", TimeDelta::try_hours(2).unwrap_or(TimeDelta::zero())),
        ];

        let mut escalated = 0i64;
        for (priority, threshold) in rules {
            let cutoff = now - threshold;
            let result = match sqlx::query(
                "UPDATE ent_support_tickets SET status = 'escalated', escalation_level = escalation_level + 1, escalated_at = NOW(), updated_at = NOW()
                 WHERE status = 'open' AND priority = $1 AND escalation_level = 0 AND created_at < $2"
            )
            .bind(priority).bind(cutoff)
            .execute(&self.db)
            .await
            {
                Ok(result) => result,
                Err(error) if is_missing_relation_error(&error) => {
                    log_missing_support_tickets_once("auto_escalate");
                    return Ok(0);
                }
                Err(error) => return Err(format!("Auto-escalate: {error}")),
            };
            escalated += result.rows_affected() as i64;
        }

        if escalated > 0 {
            info!(count = escalated, "Auto-escalated tickets");
        }
        Ok(escalated)
    }
}

/// Calculate auto-escalation thresholds in minutes
pub fn auto_escalation_thresholds() -> Vec<(&'static str, i64)> {
    vec![
        ("critical", 30),
        ("high", 60),
        ("medium", 120),
    ]
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
            tenant_id: Uuid::new_v4(),
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
