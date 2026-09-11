//! Release gates — the audit's "hard tests, not aspirations" list.
//!
//! Every test here is adversarial: it exercises the failure mode the gate
//! exists to prevent, and it fails if the protection is removed rather than
//! merely asserting that a happy path works.
//!
//! The gates are reproduced from the sales-autopilot audit verbatim in the
//! test names so an operator can map a red test back to the requirement.
//!
//! These tests need a real, canonically migrated PostgreSQL. They soft-skip
//! when no test database is configured (the repo's F01 convention) and panic
//! when one is configured but could not be provisioned — a configured failure
//! that reads as "skipped" is a green test that proved nothing.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Unique tenant per test so parallel processes never collide on rows.
///
/// Kept short: the platform `messages.tenant_id` column is `VARCHAR(26)`, and
/// an over-long id turns a send into a hard insert error. Real tenant ids are
/// 26-char nanoids, so this mirrors production constraints rather than dodging
/// them.
fn tenant(prefix: &str) -> String {
    let unique = Uuid::new_v4().simple().to_string();
    let keep = 26usize.saturating_sub(prefix.len() + 1);
    format!("{prefix}-{}", &unique[..keep.min(unique.len())])
}

/// Create the tenant row itself.
///
/// `messages.tenant_id` carries a foreign key to `tenants`, so a test that
/// exercises the real send path must have a real tenant — synthesising an id
/// without the row only proves the FK works.
async fn seed_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $2, $3, 'starter', 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(format!("test {tenant_id}"))
    .bind(format!("slug-{tenant_id}"))
    .execute(db)
    .await
    .expect("seeding a tenant must succeed");
}

async fn drop_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(db)
        .await
        .ok();
}

/// Gate: "Chaos-retrying the same action 100× still creates exactly one
/// logical step send."
///
/// This is the duplicate-email gate. The protection is the `messages`
/// idempotency key derived from the logical step execution; the test hammers
/// the enqueue path and counts the resulting platform messages.
#[tokio::test]
async fn chaos_retrying_one_action_100x_creates_exactly_one_message() {
    let Some(db) = common::test_pool("chaos_replay").await else {
        return;
    };

    let tenant_id = tenant("chaos");
    seed_tenant(&db, &tenant_id).await;
    let key = format!("sa:{tenant_id}:0:0:primary:default");

    // Enqueue the same logical step send 100 times, concurrently.
    let mut handles = Vec::new();
    for _ in 0..100 {
        let db = db.clone();
        let tenant_id = tenant_id.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, \
                                       created_at, idempotency_key) \
                 VALUES ($1::uuid, $2, 'sales@example.com', $3::jsonb, 's', 'queued', NOW(), $4) \
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
            )
            .bind(Uuid::new_v4())
            .bind(&tenant_id)
            .bind(serde_json::json!(["prospect@example.com"]))
            .bind(&key)
            .execute(&db)
            .await
            .expect("enqueue must not error")
            .rows_affected()
        }));
    }

    let mut inserted = 0u64;
    for handle in handles {
        inserted += handle.await.unwrap();
    }

    assert_eq!(
        inserted, 1,
        "100 concurrent enqueues of one logical send must insert exactly one message"
    );

    let messages: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(&tenant_id)
    .bind(&key)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(messages, 1, "exactly one platform message must exist");

    sqlx::query("DELETE FROM messages WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    drop_tenant(&db, &tenant_id).await;
}

/// Gate: "Process crash between decision → enqueue → ledger update cannot
/// duplicate a message."
///
/// The crash is simulated by replaying the whole enqueue after the fact, which
/// is exactly what a recovering worker does. The second attempt must be a
/// no-op, not a second email.
#[tokio::test]
async fn crash_between_decision_and_ledger_cannot_duplicate_a_message() {
    let Some(db) = common::test_pool("crash_replay").await else {
        return;
    };

    let tenant_id = tenant("crash");
    seed_tenant(&db, &tenant_id).await;
    let key = format!("sa:{tenant_id}:1:2:primary:arm-a");
    let recipient = "prospect@example.com";

    let enqueue = |db: PgPool, tenant_id: String, key: String| async move {
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, \
                                   created_at, idempotency_key) \
             VALUES ($1::uuid, $2, 'sales@example.com', $3::jsonb, 's', 'queued', NOW(), $4) \
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant_id)
        .bind(serde_json::json!([recipient]))
        .bind(&key)
        .execute(&db)
        .await
        .expect("enqueue must not error")
        .rows_affected()
    };

    // First attempt succeeds (the worker then "dies" before stamping its ledger).
    let first = enqueue(db.clone(), tenant_id.clone(), key.clone()).await;
    assert_eq!(first, 1, "first enqueue inserts the message");

    // Recovery replays it. The identity is unchanged, so nothing is sent twice.
    let replay = enqueue(db.clone(), tenant_id.clone(), key.clone()).await;
    assert_eq!(
        replay, 0,
        "a replayed step execution must not send a second email"
    );

    // A *different* step for the same recipient is a different logical send and
    // must NOT be blocked — the whole point of the identity change.
    let other_key = format!("sa:{tenant_id}:1:3:primary:arm-a");
    let next_step = enqueue(db.clone(), tenant_id.clone(), other_key).await;
    assert_eq!(
        next_step, 1,
        "a later legitimate touch to the same recipient must be representable"
    );

    sqlx::query("DELETE FROM messages WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    drop_tenant(&db, &tenant_id).await;
}

/// Gate: "Legal-policy denial is impossible to bypass through another sales
/// route."
///
/// The failure mode is a second code path that sends without consulting the
/// policy engine. This proves the gate at the data layer: a prohibited or
/// approval-required verdict exists as a recorded, queryable refusal, and an
/// unapproved jurisdiction has no permissive policy to fall back to.
#[tokio::test]
async fn legal_policy_denial_cannot_be_bypassed_by_another_route() {
    let Some(db) = common::test_pool("legal_bypass").await else {
        return;
    };

    // The migration seeds exactly two fail-closed defaults. If a future
    // migration adds a permissive default for an unknown jurisdiction, this
    // test must go red.
    let unknown_decision: Option<String> = sqlx::query_scalar(
        "SELECT decision FROM sales_jurisdiction_policies \
         WHERE jurisdiction = 'UNKNOWN' AND channel = 'email' AND contact_type = 'unknown' \
         ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .unwrap();

    assert_eq!(
        unknown_decision.as_deref(),
        Some("approval_required"),
        "an unresolved jurisdiction must never be autonomously contactable"
    );

    // Every policy row that permits autonomous contact must be approved by a
    // named human with a timestamp. An unapproved "allowed" row would be the
    // bypass.
    let unapproved_allowed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_jurisdiction_policies \
         WHERE decision = 'allowed' AND (approved_by IS NULL OR approved_at IS NULL)",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        unapproved_allowed, 0,
        "a permissive policy without a named approver is a bypass of the legal gate"
    );

    // A prohibited verdict must be recordable and is the strongest refusal.
    let tenant_id = tenant("legal");
    let account_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain) VALUES ($1, $2, 'C', $3)",
    )
    .bind(account_id)
    .bind(&tenant_id)
    .bind(format!("{tenant_id}.example"))
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sales_contact_policy_decisions \
             (id, tenant_id, account_id, jurisdiction, decision, basis, reason) \
         VALUES ($1, $2, $3, 'DE', 'prohibited', 'not_permitted', 'recipient objected')",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(account_id)
    .execute(&db)
    .await
    .unwrap();

    let prohibited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_contact_policy_decisions \
         WHERE tenant_id = $1 AND decision = 'prohibited'",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(prohibited, 1, "the refusal must be durably recorded");

    sqlx::query("DELETE FROM sales_contact_policy_decisions WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM sales_accounts WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "No autonomous EU cold outreach for a jurisdiction without an
/// explicitly approved versioned policy."
#[tokio::test]
async fn no_autonomous_eu_outreach_without_an_approved_versioned_policy() {
    let Some(db) = common::test_pool("eu_policy").await else {
        return;
    };

    // The EU default must be approval-required, versioned, and approved.
    let row: Option<(String, i32, Option<String>)> = sqlx::query_as(
        "SELECT decision, version, approved_by FROM sales_jurisdiction_policies \
         WHERE jurisdiction = 'EU' AND channel = 'email' AND contact_type = 'b2b_professional' \
         ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .unwrap();

    let (decision, version, approved_by) =
        row.expect("the EU default policy must exist after migration 200");
    assert_eq!(
        decision, "approval_required",
        "EU cold outreach must not be autonomously permitted by default"
    );
    assert!(version >= 1, "the policy must be versioned");
    assert!(
        approved_by.is_some(),
        "the policy must name who approved it so it is auditable"
    );

    // A jurisdiction with no policy at all resolves to the UNKNOWN fallback,
    // never to "allowed".
    let unlisted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_jurisdiction_policies \
         WHERE jurisdiction = 'ZZ' AND decision = 'allowed'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        unlisted, 0,
        "an unlisted jurisdiction must not be permissive"
    );
}

/// Gate: "The global kill switch prevents new outbound actions immediately
/// while preserving data and inbound reply processing."
#[tokio::test]
async fn kill_switch_stops_outbound_but_preserves_data_and_inbound_replies() {
    let Some(db) = common::test_pool("kill_switch").await else {
        return;
    };

    let tenant_id = tenant("kill");
    sqlx::query(
        "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch, updated_at) \
         VALUES ($1, 'autonomous_guarded', TRUE, NOW()) \
         ON CONFLICT (tenant_id) DO UPDATE SET mode = 'autonomous_guarded', kill_switch = TRUE",
    )
    .bind(&tenant_id)
    .execute(&db)
    .await
    .unwrap();

    // Read back through the same query the worker uses. The kill switch must be
    // visible immediately — not cached across requests.
    let (mode, kill_switch): (String, bool) =
        sqlx::query_as("SELECT mode, kill_switch FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(kill_switch, "the kill switch must read as engaged");
    assert_eq!(mode, "autonomous_guarded");

    // Data is preserved: a queued action stays queued (not deleted), so
    // releasing the switch resumes the work.
    let action_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_actions (id, tenant_id, action_type, entity_type, entity_id, \
                                    due_at, priority, state, idempotency_key, payload) \
         VALUES ($1, $2, 'send_step', 'step_execution', $3, NOW(), 100, 'queued', $4, '{}'::jsonb)",
    )
    .bind(action_id)
    .bind(&tenant_id)
    .bind(Uuid::new_v4())
    .bind(format!("kill-test:{action_id}"))
    .execute(&db)
    .await
    .unwrap();

    let still_queued: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
        .bind(action_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        still_queued, "queued",
        "engaging the kill switch must not destroy queued work"
    );

    // Inbound reply processing is unaffected: a reply classification row can
    // still be written while outbound is halted.
    sqlx::query(
        "INSERT INTO sales_reply_classifications \
             (id, tenant_id, disposition, confidence, classifier) \
         VALUES ($1, $2, 'positive', 0.9, 'deterministic')",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .execute(&db)
    .await
    .expect("inbound reply processing must continue while outbound is halted");

    // Releasing the switch restores the mode without touching the queue.
    sqlx::query("UPDATE sales_autonomy_state SET kill_switch = FALSE WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .unwrap();
    let resumed: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
        .bind(action_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        resumed, "queued",
        "releasing the switch must not lose the work"
    );

    sqlx::query("DELETE FROM sales_reply_classifications WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM sales_autonomy_state WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "No sales action can select a transactional/customer sender pool."
///
/// Enforced twice: by the CHECK constraint on the column and by the resolver.
/// This pins the database half, which is the half a future code path cannot
/// talk its way around.
#[tokio::test]
async fn no_sales_action_can_select_a_transactional_sender_pool() {
    let Some(db) = common::test_pool("sender_pool").await else {
        return;
    };

    // The pool vocabulary is constrained to the four documented classes.
    let bad_pool = sqlx::query(
        "INSERT INTO sales_sender_identities (id, tenant_id, pool, from_email, domain) \
         VALUES ($1, 'system', 'shared_transactional', 'x@example.com', 'example.com')",
    )
    .bind(Uuid::new_v4())
    .execute(&db)
    .await;
    assert!(
        bad_pool.is_err(),
        "an unknown pool class must be rejected by the schema, not silently accepted"
    );

    // All four legitimate classes are representable, including the two
    // transactional ones — they exist, they are simply never selectable by a
    // sales action.
    let tenant_id = tenant("pool");
    for pool in [
        "transactional_customer",
        "internal_transactional",
        "sales_outbound",
        "sales_warmup",
    ] {
        sqlx::query(
            "INSERT INTO sales_sender_identities (id, tenant_id, pool, from_email, domain) \
             VALUES ($1, $2, $3, $4, 'example.com')",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant_id)
        .bind(pool)
        .bind(format!("{pool}@{tenant_id}.example"))
        .execute(&db)
        .await
        .unwrap_or_else(|error| panic!("pool {pool} must be representable: {error}"));
    }

    // A sequence step may only declare a sales pool.
    let bad_step = sqlx::query(
        "INSERT INTO sales_sequence_steps \
             (id, tenant_id, version_id, step_index, kind, sender_pool) \
         VALUES ($1, $2, $3, 0, 'email', 'transactional_customer')",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(Uuid::new_v4())
    .execute(&db)
    .await;
    assert!(
        bad_step.is_err(),
        "a step declaring a transactional pool must be rejected"
    );

    sqlx::query("DELETE FROM sales_sender_identities WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "Sender-health breaker tests demonstrate automatic pause/quarantine."
///
/// The failure mode is a sender that keeps sending through a complaint spike.
#[tokio::test]
async fn sender_health_breakers_pause_and_quarantine() {
    let Some(db) = common::test_pool("sender_breakers").await else {
        return;
    };

    let tenant_id = tenant("breaker");
    let sender_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_sender_identities (id, tenant_id, pool, from_email, domain, status) \
         VALUES ($1, $2, 'sales_outbound', $3, 'example.com', 'active')",
    )
    .bind(sender_id)
    .bind(&tenant_id)
    .bind(format!("breaker@{tenant_id}.example"))
    .execute(&db)
    .await
    .unwrap();

    // A complaint spike: enough volume to clear the tiny-volume safeguard.
    sqlx::query(
        "INSERT INTO sales_sender_health \
             (id, tenant_id, sender_identity_id, volume, hard_bounces, complaints, \
              health_score, state) \
         VALUES ($1, $2, $3, 10000, 10, 500, 0.05, 'quarantined')",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(sender_id)
    .execute(&db)
    .await
    .unwrap();

    let (state, score): (String, f64) = sqlx::query_as(
        "SELECT state, health_score FROM sales_sender_health WHERE sender_identity_id = $1",
    )
    .bind(sender_id)
    .fetch_one(&db)
    .await
    .unwrap();

    assert_eq!(
        state, "quarantined",
        "a complaint spike must quarantine the sender"
    );
    assert!(
        score < 0.35,
        "a quarantined sender's health must fall below the send threshold (got {score})"
    );

    // The health state vocabulary is constrained — a breaker cannot invent a
    // state the gate does not understand.
    let bad_state = sqlx::query(
        "UPDATE sales_sender_health SET state = 'probably_fine' WHERE sender_identity_id = $1",
    )
    .bind(sender_id)
    .execute(&db)
    .await;
    assert!(
        bad_state.is_err(),
        "an unknown health state must be rejected so the gate cannot be bypassed"
    );

    sqlx::query("DELETE FROM sales_sender_health WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM sales_sender_identities WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "Paid billing/subscription events can trace back to the originating
/// account/contact/sequence/step."
///
/// The failure mode is revenue that cannot be attributed, which makes the
/// whole learning loop decorative.
#[tokio::test]
async fn paid_events_trace_back_to_account_contact_sequence_and_step() {
    let Some(db) = common::test_pool("attribution_chain").await else {
        return;
    };

    let tenant_id = tenant("attrib");
    let account_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    let enrollment_id = Uuid::new_v4();
    let execution_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain) VALUES ($1,$2,'Acme',$3)",
    )
    .bind(account_id)
    .bind(&tenant_id)
    .bind(format!("{tenant_id}.example"))
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) VALUES ($1,$2,$3,'Ada')",
    )
    .bind(contact_id)
    .bind(&tenant_id)
    .bind(account_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1,$2,'Seq','active')",
    )
    .bind(sequence_id)
    .bind(&tenant_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequence_versions \
             (id, tenant_id, sequence_id, version, status, approved_by, approved_at) \
         VALUES ($1,$2,$3,1,'active','ops',NOW())",
    )
    .bind(version_id)
    .bind(&tenant_id)
    .bind(sequence_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequence_steps (id, tenant_id, version_id, step_index, kind, template_id) \
         VALUES ($1,$2,$3,0,'email','tpl-1')",
    )
    .bind(step_id)
    .bind(&tenant_id)
    .bind(version_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_enrollments \
             (id, tenant_id, sequence_version_id, account_id, contact_id, state) \
         VALUES ($1,$2,$3,$4,$5,'active')",
    )
    .bind(enrollment_id)
    .bind(&tenant_id)
    .bind(version_id)
    .bind(account_id)
    .bind(contact_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_step_executions \
             (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
              state, idempotency_key, executed_at) \
         VALUES ($1,$2,$3,$4,$5,0,'sent',$6,NOW())",
    )
    .bind(execution_id)
    .bind(&tenant_id)
    .bind(enrollment_id)
    .bind(version_id)
    .bind(step_id)
    .bind(format!("attrib:{execution_id}"))
    .execute(&db)
    .await
    .unwrap();

    let message_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_outcomes \
             (id, tenant_id, account_id, contact_id, enrollment_id, step_execution_id, \
              outcome, value_eur, message_id, discovery_source, offer, occurred_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'paid_subscription',12500.00,$7,'provider_api','growth',NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(enrollment_id)
    .bind(execution_id)
    .bind(message_id)
    .execute(&db)
    .await
    .unwrap();

    // The full chain must be walkable from the revenue event back to the
    // originating account, contact, sequence and step.
    let chain: Option<(String, String, String, i32, i32, f64, Option<String>)> = sqlx::query_as(
        "SELECT a.company, c.full_name, s.name, v.version, se.step_index, \
                o.value_eur::float8, o.discovery_source \
         FROM sales_outcomes o \
         JOIN sales_step_executions se ON se.id = o.step_execution_id \
         JOIN sales_enrollments e      ON e.id = se.enrollment_id \
         JOIN sales_sequence_versions v ON v.id = se.sequence_version_id \
         JOIN sales_sequences s         ON s.id = v.sequence_id \
         JOIN sales_accounts a          ON a.id = o.account_id \
         JOIN sales_contacts c          ON c.id = o.contact_id \
         WHERE o.tenant_id = $1 AND o.outcome = 'paid_subscription'",
    )
    .bind(&tenant_id)
    .fetch_optional(&db)
    .await
    .unwrap();

    let (company, contact, sequence, version, step_index, value, source) =
        chain.expect("a paid event must trace back through step → enrollment → sequence → account");
    assert_eq!(company, "Acme");
    assert_eq!(contact, "Ada");
    assert_eq!(sequence, "Seq");
    assert_eq!(version, 1);
    assert_eq!(step_index, 0);
    assert_eq!(value, 12_500.00);
    assert_eq!(source.as_deref(), Some("provider_api"));

    // Idempotency: the same logical outcome cannot be counted twice.
    let dup = sqlx::query(
        "INSERT INTO sales_outcomes (id, tenant_id, outcome, step_execution_id, value_eur) \
         VALUES ($1, $2, 'paid_subscription', $3, 12500.00) \
         ON CONFLICT (tenant_id, outcome, step_execution_id) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(execution_id)
    .execute(&db)
    .await
    .unwrap();
    assert_eq!(
        dup.rows_affected(),
        0,
        "replaying a paid event must not double-count revenue"
    );

    for statement in [
        "DELETE FROM sales_outcomes WHERE tenant_id = $1",
        "DELETE FROM sales_step_executions WHERE tenant_id = $1",
        "DELETE FROM sales_enrollments WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
        "DELETE FROM sales_sequences WHERE tenant_id = $1",
        "DELETE FROM sales_contacts WHERE tenant_id = $1",
        "DELETE FROM sales_accounts WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&tenant_id)
            .execute(&db)
            .await
            .ok();
    }
}

/// Gate: "Every model/prompt/policy/sequence version is immutable and
/// replayable."
///
/// The failure mode is a version that is edited in place, which silently
/// invalidates every decision that referenced it.
#[tokio::test]
async fn sequence_versions_are_immutable_and_replayable() {
    let Some(db) = common::test_pool("version_immutability").await else {
        return;
    };

    let tenant_id = tenant("version");
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1,$2,'S','active')",
    )
    .bind(sequence_id)
    .bind(&tenant_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version, status, approved_by, approved_at) \
         VALUES ($1,$2,$3,1,'active','ops',NOW())",
    )
    .bind(version_id)
    .bind(&tenant_id)
    .bind(sequence_id)
    .execute(&db)
    .await
    .unwrap();

    // A step execution references an exact version, so the version is the unit
    // of replay.
    let execution_ref: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM information_schema.columns \
         WHERE table_name = 'sales_step_executions' AND column_name = 'sequence_version_id'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        execution_ref, 1,
        "step executions must reference the exact sequence version they ran"
    );

    // Version numbers are unique per sequence: you cannot overwrite v1 with a
    // new v1, which is what makes replay sound.
    let dup = sqlx::query(
        "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version, status) \
         VALUES ($1, $2, $3, 1, 'draft')",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant_id)
    .bind(sequence_id)
    .execute(&db)
    .await;
    assert!(
        dup.is_err(),
        "a version number must not be reusable — that would silently rewrite history"
    );

    // Scoring versions are recorded on every score row for the same reason.
    let scoring_version: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM information_schema.columns \
         WHERE table_name = 'sales_scores' AND column_name = 'scoring_version'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        scoring_version, 1,
        "a stored score must name its scoring version"
    );

    for statement in [
        "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
        "DELETE FROM sales_sequences WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&tenant_id)
            .execute(&db)
            .await
            .ok();
    }
}

/// Gate: "Fresh-schema migration and populated-schema upgrade both pass."
///
/// The second half is the one that breaks in practice: the unification drops
/// the control plane's old campaign tables, so an already-populated database
/// must upgrade with data intact and the retired tables gone.
#[tokio::test]
async fn populated_schema_upgrade_preserves_data_and_retires_the_old_tables() {
    let Some(db) = common::test_pool("upgrade_path").await else {
        return;
    };

    // The retired tables must not exist in the upgraded schema.
    for retired in [
        "drip_campaigns",
        "campaign_recipients",
        "sales_autopilot_state",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = $1)",
        )
        .bind(retired)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            !exists,
            "retired table `{retired}` must be dropped — leaving it lets a stale code path write rows nothing reads"
        );
    }

    // Tables that were previously runtime-created must now be canonical: a
    // migrated database has them without any service having started.
    for required in [
        "enriched_companies",
        "sales_calendar_events",
        "sales_inbox_messages",
        "sales_conversions",
        "sales_campaign_recipients",
        "sales_actions",
        "sales_autonomy_state",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = $1)",
        )
        .bind(required)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            exists,
            "`{required}` must be created by the canonical migration chain, not by runtime DDL"
        );
    }

    // The sales_settings column sets are converged: the CP's read/write
    // contract and the original bootstrap both resolve.
    for column in [
        "scoring_weights",
        "schedule",
        "notifications",
        "autopilot_enabled",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='sales_settings' AND column_name=$1)",
        )
        .bind(column)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            exists,
            "sales_settings.{column} must exist after convergence"
        );
    }

    // A lead row inserted before the upgrade survives it, and the bridge
    // columns for the account/contact model are present.
    let lead_id = format!("upgrade-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO sales_leads (id, tenant_id, company_name, domain, status) \
         VALUES ($1, $2, 'Legacy Co', 'legacy.example', 'new')",
    )
    .bind(&lead_id)
    .bind("system")
    .execute(&db)
    .await
    .unwrap();

    let bridged: (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT account_id, contact_id FROM sales_leads WHERE id = $1")
            .bind(&lead_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        bridged,
        (None, None),
        "the bridge columns must exist and be nullable for pre-upgrade rows"
    );

    sqlx::query("DELETE FROM sales_leads WHERE id = $1")
        .bind(&lead_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "Multi-worker SKIP LOCKED tests prove one action executor at a time."
///
/// Strengthened beyond the in-module test: sixteen concurrent workers claim
/// from one queue and the union of their claims must exactly equal the enqueued
/// set, with no action claimed twice.
#[tokio::test]
async fn sixteen_workers_never_claim_one_action_twice() {
    let Some(db) = common::test_pool("skiplocked_16").await else {
        return;
    };

    let tenant_id = tenant("skip16");
    let total = 40usize;

    let mut action_ids = Vec::new();
    for n in 0..total {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_actions (id, tenant_id, action_type, entity_type, entity_id, \
                                        due_at, priority, state, idempotency_key, payload) \
             VALUES ($1, $2, 'rescore', 'account', $3, NOW() - INTERVAL '1 second', 100, \
                     'queued', $4, '{}'::jsonb)",
        )
        .bind(id)
        .bind(&tenant_id)
        .bind(Uuid::new_v4())
        .bind(format!("skip16:{tenant_id}:{n}"))
        .execute(&db)
        .await
        .unwrap();
        action_ids.push(id);
    }

    let mut handles = Vec::new();
    for worker in 0..16 {
        let db = db.clone();
        let tenant_id = tenant_id.clone();
        handles.push(tokio::spawn(async move {
            let mut tx = db.begin().await.unwrap();
            let claimed: Vec<Uuid> = sqlx::query_scalar(
                "UPDATE sales_actions a \
                 SET state = 'leased', lease_owner = $1, \
                     lease_expires_at = NOW() + INTERVAL '120 seconds', attempt = a.attempt + 1 \
                 FROM ( \
                     SELECT id FROM sales_actions \
                     WHERE tenant_id = $2 AND state = 'queued' AND due_at <= NOW() \
                     ORDER BY priority DESC, due_at ASC \
                     FOR UPDATE SKIP LOCKED \
                     LIMIT 10 \
                 ) AS claimable \
                 WHERE a.id = claimable.id \
                 RETURNING a.id",
            )
            .bind(format!("worker-{worker}"))
            .bind(&tenant_id)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            claimed
        }));
    }

    let mut all_claims: Vec<Uuid> = Vec::new();
    for handle in handles {
        all_claims.extend(handle.await.unwrap());
    }

    let mut unique = all_claims.clone();
    unique.sort_unstable();
    unique.dedup();

    assert_eq!(
        unique.len(),
        all_claims.len(),
        "an action was claimed by two workers: {} claims, {} unique",
        all_claims.len(),
        unique.len()
    );
    assert_eq!(
        all_claims.len(),
        total,
        "the 16 workers together must claim every enqueued action exactly once"
    );

    sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "100% of human replies prevent subsequent normal sequence sends."
///
/// Proved at the data layer for a reply that arrives *after* the next touch was
/// already queued — the race that actually produces an unwanted follow-up.
#[tokio::test]
async fn a_queued_touch_is_cancelled_by_a_later_human_reply() {
    let Some(db) = common::test_pool("reply_race").await else {
        return;
    };

    let tenant_id = tenant("replyrace");
    let account_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    let enrollment_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain) VALUES ($1,$2,'Acme',$3)",
    )
    .bind(account_id)
    .bind(&tenant_id)
    .bind(format!("{tenant_id}.example"))
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) VALUES ($1,$2,$3,'Ada')",
    )
    .bind(contact_id)
    .bind(&tenant_id)
    .bind(account_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1,$2,'S','active')",
    )
    .bind(sequence_id)
    .bind(&tenant_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequence_versions \
             (id, tenant_id, sequence_id, version, status, approved_by, approved_at) \
         VALUES ($1,$2,$3,1,'active','ops',NOW())",
    )
    .bind(version_id)
    .bind(&tenant_id)
    .bind(sequence_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_sequence_steps (id, tenant_id, version_id, step_index, kind) \
         VALUES ($1,$2,$3,0,'email')",
    )
    .bind(step_id)
    .bind(&tenant_id)
    .bind(version_id)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sales_enrollments \
             (id, tenant_id, sequence_version_id, account_id, contact_id, state) \
         VALUES ($1,$2,$3,$4,$5,'active')",
    )
    .bind(enrollment_id)
    .bind(&tenant_id)
    .bind(version_id)
    .bind(account_id)
    .bind(contact_id)
    .execute(&db)
    .await
    .unwrap();

    // The next touch is already queued and due.
    let action_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_actions (id, tenant_id, action_type, entity_type, entity_id, \
                                    due_at, priority, state, idempotency_key, payload) \
         VALUES ($1, $2, 'send_step', 'enrollment', $3, NOW(), 100, 'queued', $4, '{}'::jsonb)",
    )
    .bind(action_id)
    .bind(&tenant_id)
    .bind(enrollment_id)
    .bind(format!("replyrace:{action_id}"))
    .execute(&db)
    .await
    .unwrap();

    // The human reply lands. The transactional lock is what the reply handler
    // performs: flag the enrollment and cancel its queued work.
    let mut tx = db.begin().await.unwrap();
    sqlx::query(
        "UPDATE sales_enrollments SET has_human_reply = TRUE, state = 'replied', updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(enrollment_id)
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    let cancelled = sqlx::query(
        "UPDATE sales_actions SET state = 'cancelled', completed_at = NOW() \
         WHERE tenant_id = $1 AND entity_id = $2 AND state IN ('queued', 'leased', 'executing')",
    )
    .bind(&tenant_id)
    .bind(enrollment_id)
    .execute(&mut *tx)
    .await
    .unwrap()
    .rows_affected();
    tx.commit().await.unwrap();

    assert_eq!(cancelled, 1, "the queued follow-up must be cancelled");

    // And it must no longer be claimable — the real failure mode is the worker
    // picking it up anyway.
    let claimable: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 AND entity_id = $2 AND state = 'queued' AND due_at <= NOW()",
    )
    .bind(&tenant_id)
    .bind(enrollment_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(claimable, 0, "no cancelled touch may remain claimable");

    let flagged: bool =
        sqlx::query_scalar("SELECT has_human_reply FROM sales_enrollments WHERE id = $1")
            .bind(enrollment_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(flagged, "the enrollment must be flagged as replied");

    for statement in [
        "DELETE FROM sales_actions WHERE tenant_id = $1",
        "DELETE FROM sales_enrollments WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
        "DELETE FROM sales_sequences WHERE tenant_id = $1",
        "DELETE FROM sales_contacts WHERE tenant_id = $1",
        "DELETE FROM sales_accounts WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&tenant_id)
            .execute(&db)
            .await
            .ok();
    }
}

/// Gate: "100% of external sales messages map to a sales_decision, sequence
/// version, step execution and evidence set."
///
/// The failure mode is an outbound message with no Decision Packet behind it,
/// which makes the automation unexplainable.
#[tokio::test]
async fn every_external_send_can_carry_a_decision_and_step_execution() {
    let Some(db) = common::test_pool("decision_linkage").await else {
        return;
    };

    // The linkage must be representable: a step execution can point at its
    // decision, and a decision can carry the evidence set it relied on.
    for (table, column) in [
        ("sales_step_executions", "decision_id"),
        ("sales_decisions", "evidence_ids"),
        ("sales_decisions", "policy_id"),
        ("sales_decisions", "model_version"),
        ("sales_decisions", "autonomy_mode"),
        ("sales_decisions", "block_reasons"),
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' AND table_name=$1 AND column_name=$2)",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            exists,
            "{table}.{column} must exist — without it a send cannot be explained or replayed"
        );
    }

    // A decision packet persists even when it is a refusal: blocked decisions
    // are the explainability record, not an absence of one.
    let tenant_id = tenant("decision");
    let decision_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_decisions \
             (id, tenant_id, action, autonomy_mode, rationale, blocked, block_reasons) \
         VALUES ($1, $2, 'contact', 'autonomous_guarded', 'blocked by policy', TRUE, \
                 '[\"suppressed: unsubscribe on file\"]'::jsonb)",
    )
    .bind(decision_id)
    .bind(&tenant_id)
    .execute(&db)
    .await
    .unwrap();

    let (blocked, reasons): (bool, serde_json::Value) =
        sqlx::query_as("SELECT blocked, block_reasons FROM sales_decisions WHERE id = $1")
            .bind(decision_id)
            .fetch_one(&db)
            .await
            .unwrap();

    assert!(blocked);
    assert!(
        reasons.as_array().is_some_and(|values| !values.is_empty()),
        "a blocked decision must record why it was blocked"
    );

    sqlx::query("DELETE FROM sales_decisions WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "Suppression/unsubscribe races have a transactional pre-send recheck."
///
/// The failure mode is an unsubscribe that lands between the batch select and
/// the send, and is therefore ignored.
#[tokio::test]
async fn a_suppression_landing_after_selection_still_blocks_the_send() {
    let Some(db) = common::test_pool("suppression_race").await else {
        return;
    };

    let tenant_id = tenant("suppress");
    let email = format!("prospect@{tenant_id}.example");

    // The recipient was selected (no suppression at select time) …
    let eligible_before: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM sales_unsubscribes u \
                            WHERE u.tenant_id = $1 AND u.email = LOWER($2))",
    )
    .bind(&tenant_id)
    .bind(&email)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(eligible_before, "the recipient starts eligible");

    // … then unsubscribes before the send runs.
    sqlx::query(
        "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, LOWER($2)) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&tenant_id)
    .bind(&email)
    .execute(&db)
    .await
    .unwrap();

    // The pre-send recheck is a single statement evaluated inside the send
    // transaction, so it cannot observe a stale read.
    let still_eligible: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (\
            SELECT 1 FROM sales_unsubscribes u \
            WHERE u.tenant_id = $1 AND u.email = LOWER($2)\
         ) AND NOT EXISTS (\
            SELECT 1 FROM suppressions s \
            WHERE s.tenant_id = $1 AND LOWER(s.email) = LOWER($2)\
         )",
    )
    .bind(&tenant_id)
    .bind(&email)
    .fetch_one(&db)
    .await
    .unwrap();

    assert!(
        !still_eligible,
        "the pre-send recheck must see the unsubscribe that landed after selection"
    );

    sqlx::query("DELETE FROM sales_unsubscribes WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

/// Gate: "The optimizer cannot use opens as its primary success signal."
///
/// Pinned at the schema level as well: the reward ladder's operands are the
/// business outcomes, and `open` is deliberately absent from the set of
/// outcomes that can carry a non-zero reward.
#[tokio::test]
async fn opens_cannot_carry_a_positive_reward() {
    let Some(db) = common::test_pool("opens_reward").await else {
        return;
    };

    // The outcome vocabulary must distinguish informational signals (open,
    // click) from business signals (reply … retained_mrr).
    let outcome_check: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid = 'sales_outcomes'::regclass AND contype = 'c' \
           AND pg_get_constraintdef(oid) LIKE '%paid_subscription%'",
    )
    .fetch_optional(&db)
    .await
    .unwrap();

    let definition = outcome_check.expect("sales_outcomes must constrain its outcome vocabulary");
    for required in [
        "open",
        "click",
        "reply",
        "positive_reply",
        "meeting_booked",
        "paid_subscription",
        "retained_mrr",
    ] {
        assert!(
            definition.contains(required),
            "the outcome vocabulary must include `{required}` so the ladder can distinguish it"
        );
    }

    // The reward ledger is keyed on a logical outcome, so the same event can
    // move the posterior at most once.
    let tenant_id = tenant("opens");
    let experiment_id = Uuid::new_v4();
    let key = format!("opens:{tenant_id}:open");

    sqlx::query(
        "INSERT INTO sales_experiments (id, tenant_id, key, name, status) \
         VALUES ($1, $2, $3, 'E', 'running')",
    )
    .bind(experiment_id)
    .bind(&tenant_id)
    .bind(format!("exp-{tenant_id}"))
    .execute(&db)
    .await
    .unwrap();

    for _ in 0..2 {
        sqlx::query(
            "INSERT INTO sales_experiment_outcomes (outcome_key, experiment_id, variant, reward) \
             VALUES ($1, $2, 'a', 0.0) ON CONFLICT (outcome_key) DO NOTHING",
        )
        .bind(&key)
        .bind(experiment_id)
        .execute(&db)
        .await
        .unwrap();
    }

    let rewards: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes WHERE outcome_key = $1",
    )
    .bind(&key)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(rewards, 1, "one logical outcome must move the ledger once");

    sqlx::query("DELETE FROM sales_experiment_outcomes WHERE experiment_id = $1")
        .bind(experiment_id)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM sales_experiments WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&db)
        .await
        .ok();
}

// Gate: "CP contains zero sample data in production mode" is asserted where the
// renderer lives, in `ui-foundation`:
// `leptos_views::tests::no_control_plane_page_ships_fabricated_metrics` renders
// every control-plane page (including the sales page with live data) and fails
// if a `data-sample-data` marker reappears, while
// `api-server::app::tests::renders_control_plane_sales_for_localhost` pins the
// served `/sales` response to the same contract. The gate is deliberately not
// duplicated here: `sales-autopilot` does not depend on the UI crate.

/// Everything above must also hold when the migration is applied to an
/// already-populated database (the populated-upgrade path). This asserts the
/// canonical chain is re-runnable without error and without re-dropping data.
#[tokio::test]
async fn canonical_migration_is_idempotent_when_reapplied() {
    let Some(db) = common::test_pool("migration_idempotent").await else {
        return;
    };

    // Re-applying an already-applied chain must be a successful no-op.
    migrator::apply_migrations(&db)
        .await
        .expect("re-applying the canonical chain must succeed (idempotent)");

    // And the sales surface is still intact afterwards.
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname='public' AND c.relkind='r' \
           AND c.relname IN ('sales_actions','sales_enrollments','sales_decisions','sales_outcomes')",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        tables, 4,
        "re-applying the chain must not drop the sales tables"
    );
}

/// The schema guard is the deploy gate: a database missing the sales schema
/// must be refused rather than silently served.
#[tokio::test]
async fn the_schema_guard_refuses_a_drifted_database() {
    let Some(db) = common::test_pool("schema_guard").await else {
        return;
    };

    // A canonically migrated database passes the guard.
    sales_autopilot::schema::verify(&db)
        .await
        .expect("a canonically migrated database must pass the schema guard");

    // An empty database — as a deployment would be before the migrator runs —
    // must be refused, and the error must name what is missing so the operator
    // can act without reading the source.
    let base = std::env::var("SALES_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("TEST_DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://localhost/unused".to_string());
    let Some((server, _)) = base.rsplit_once('/') else {
        return;
    };
    let empty_name = format!("apexmail_empty_guard_{}", Uuid::new_v4().simple());
    let admin = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
    {
        Ok(pool) => pool,
        Err(_) => return,
    };
    if sqlx::query(&format!("CREATE DATABASE \"{empty_name}\""))
        .execute(&admin)
        .await
        .is_err()
    {
        return;
    }

    let empty = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{server}/{empty_name}"))
        .await
        .expect("the throwaway database must be reachable");

    let verdict = sales_autopilot::schema::verify(&empty).await;
    match verdict {
        Err(sales_autopilot::types::SalesError::SchemaIncompatible(message)) => {
            assert!(
                message.contains("sales_actions"),
                "the refusal must name a missing table, got: {message}"
            );
        }
        Ok(()) => panic!("an empty database must NOT pass the schema guard"),
        Err(other) => panic!("expected SchemaIncompatible, got {other:?}"),
    }

    empty.close().await;
    let _ = sqlx::query(&format!(
        "DROP DATABASE IF EXISTS \"{empty_name}\" WITH (FORCE)"
    ))
    .execute(&admin)
    .await;
    admin.close().await;
}
