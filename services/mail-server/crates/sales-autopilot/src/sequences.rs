//! Sequence read model and the corrected send identity.
//!
//! A sequence is versioned, and a version is immutable once active: every
//! step execution points at the exact version it ran, which is what makes
//! replay and attribution exact.
//!
//! The unit of send is a *logical step execution* — `(enrollment, sequence
//! version, step, attempt kind, variant)` — not `(campaign, recipient)`. Under
//! the old campaign key a second legitimate email to the same recipient
//! inside one sequence was an inherent idempotency collision; see
//! [`sales_step_idempotency_key`].
//!
//! Schedulability is approval-gated: [`load_active_version`] only returns a
//! version whose own status is `active`, whose `approved_by`/`approved_at` are
//! both set, and whose parent sequence is `active`. A draft or unapproved
//! version is never schedulable, so the caller gets
//! [`SalesError::ServiceUnavailable`] instead of a draft silently reaching the
//! worker.

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{SalesError, SenderPool};

/// Re-export of the dispatcher's canonical HTML escaping, so sequence
/// personalization has exactly one escaping implementation.
pub use crate::dispatcher::escape_html;

/// Step kinds the canonical schema's CHECK constraint permits.
///
/// `sales_sequence_steps.kind`
/// (`migrations/200_sales_autopilot_v2_unification.sql:365-367`).
pub const STEP_KINDS: [&str; 10] = [
    "email",
    "wait",
    "enrich",
    "research",
    "condition",
    "branch",
    "manual_task",
    "meeting_invite",
    "nurture",
    "stop",
];

/// A sequence version with its ordered steps, as consumed by the worker.
#[derive(Debug, Clone)]
pub struct SequenceVersionWithSteps {
    pub version_id: Uuid,
    pub sequence_id: Uuid,
    pub tenant_id: String,
    pub version: i32,
    pub locale: String,
    pub steps: Vec<SequenceStep>,
}

/// One step of a sequence version. Every field maps 1:1 to a column of
/// `sales_sequence_steps` (migration 200, lines 360-385).
#[derive(Debug, Clone)]
pub struct SequenceStep {
    pub id: Uuid,
    pub step_index: i32,
    pub kind: String,
    pub template_id: Option<String>,
    pub min_delay_secs: i64,
    pub max_delay_secs: i64,
    pub send_window: Value,
    pub recipient_timezone: bool,
    pub allowed_weekdays: Vec<i16>,
    pub experiment_key: Option<String>,
    pub tracking_policy: String,
    pub sender_pool: SenderPool,
    pub exit_conditions: Value,
    pub retry_policy: Value,
    pub branch_rules: Value,
    pub config: Value,
}

/// Raw `sales_sequence_versions` row.
#[derive(sqlx::FromRow)]
struct VersionRow {
    id: Uuid,
    sequence_id: Uuid,
    tenant_id: String,
    version: i32,
    locale: String,
}

/// Raw `sales_sequence_steps` row, kept private so the column list has one home.
#[derive(sqlx::FromRow)]
struct StepRow {
    id: Uuid,
    step_index: i32,
    kind: String,
    template_id: Option<String>,
    min_delay_secs: i64,
    max_delay_secs: i64,
    send_window: Value,
    recipient_timezone: bool,
    allowed_weekdays: Vec<i16>,
    experiment_key: Option<String>,
    tracking_policy: String,
    sender_pool: String,
    exit_conditions: Value,
    retry_policy: Value,
    branch_rules: Value,
    config: Value,
}

impl StepRow {
    /// Validate the persisted kind and sender pool.
    ///
    /// The database CHECK constraints already reject both, but a hand-edited
    /// row (constraint dropped, table patched out of band) must not be able to
    /// smuggle an unknown kind — or a non-sales sender pool — into the worker.
    fn into_step(self) -> Result<SequenceStep, SalesError> {
        if !STEP_KINDS.contains(&self.kind.as_str()) {
            return Err(SalesError::InvalidInput(format!(
                "sequence step {} has unknown kind '{}' (allowed: {})",
                self.id,
                self.kind,
                STEP_KINDS.join(", ")
            )));
        }

        let sender_pool = SenderPool::parse(&self.sender_pool).ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "sequence step {} has unknown sender_pool '{}' (allowed: sales_outbound, sales_warmup)",
                self.id, self.sender_pool
            ))
        })?;
        // The pool column is the reputation-isolation invariant: a sales step
        // may only ever select a sales pool. Reject a transactional pool even
        // if it parses, rather than letting it flow to sender selection.
        if !sender_pool.is_sales_pool() {
            return Err(SalesError::InvalidInput(format!(
                "sequence step {} has non-sales sender_pool '{}': sales steps may only select \
                 'sales_outbound' or 'sales_warmup'",
                self.id, sender_pool
            )));
        }

        Ok(SequenceStep {
            id: self.id,
            step_index: self.step_index,
            kind: self.kind,
            template_id: self.template_id,
            min_delay_secs: self.min_delay_secs,
            max_delay_secs: self.max_delay_secs,
            send_window: self.send_window,
            recipient_timezone: self.recipient_timezone,
            allowed_weekdays: self.allowed_weekdays,
            experiment_key: self.experiment_key,
            tracking_policy: self.tracking_policy,
            sender_pool,
            exit_conditions: self.exit_conditions,
            retry_policy: self.retry_policy,
            branch_rules: self.branch_rules,
            config: self.config,
        })
    }
}

/// Load the ACTIVE version of a sequence with its steps ordered by
/// `step_index`.
///
/// Requirements (all enforced in SQL):
/// * the sequence version is `status = 'active'`;
/// * the version has `approved_by IS NOT NULL AND approved_at IS NOT NULL` —
///   an unapproved version is not schedulable, even if someone flips its
///   status;
/// * the parent `sales_sequences.status = 'active'` (not paused/retired).
///
/// Returns [`SalesError::ServiceUnavailable`] when no such version exists, so
/// a draft is never scheduled. An active version with no steps is also
/// refused: there would be nothing to run.
pub async fn load_active_version(
    db: &PgPool,
    tenant_id: &str,
    sequence_id: Uuid,
) -> Result<SequenceVersionWithSteps, SalesError> {
    let row: Option<VersionRow> = sqlx::query_as(
        "SELECT v.id, v.sequence_id, v.tenant_id, v.version, v.locale \
         FROM sales_sequence_versions v \
         JOIN sales_sequences s \
           ON s.id = v.sequence_id AND s.tenant_id = v.tenant_id \
         WHERE v.tenant_id = $1 AND v.sequence_id = $2 \
           AND v.status = 'active' \
           AND v.approved_by IS NOT NULL \
           AND v.approved_at IS NOT NULL \
           AND s.status = 'active' \
         ORDER BY v.version DESC \
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(sequence_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let version = row.ok_or_else(|| {
        SalesError::ServiceUnavailable(format!(
            "sequence {sequence_id} has no approved active version for tenant {tenant_id}: \
             schedule refused (a draft or unapproved version is never schedulable)"
        ))
    })?;

    let steps = load_steps(db, &version.tenant_id, version.id).await?;
    if steps.is_empty() {
        return Err(SalesError::ServiceUnavailable(format!(
            "sequence {sequence_id} active version {} has no steps — nothing to schedule",
            version.version
        )));
    }

    Ok(SequenceVersionWithSteps {
        version_id: version.id,
        sequence_id: version.sequence_id,
        tenant_id: version.tenant_id,
        version: version.version,
        locale: version.locale,
        steps,
    })
}

/// Load a specific version by id (scoped to tenant). Unlike
/// [`load_active_version`] this does not require approval/active status — it
/// exists for preview and authoring. Unknown ids are reported as
/// [`SalesError::InvalidInput`].
pub async fn load_version(
    db: &PgPool,
    tenant_id: &str,
    version_id: Uuid,
) -> Result<SequenceVersionWithSteps, SalesError> {
    let row: Option<VersionRow> = sqlx::query_as(
        "SELECT id, sequence_id, tenant_id, version, locale \
         FROM sales_sequence_versions \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(version_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let version = row.ok_or_else(|| {
        SalesError::InvalidInput(format!(
            "sequence version {version_id} not found for tenant {tenant_id}"
        ))
    })?;

    let steps = load_steps(db, &version.tenant_id, version.id).await?;

    Ok(SequenceVersionWithSteps {
        version_id: version.id,
        sequence_id: version.sequence_id,
        tenant_id: version.tenant_id,
        version: version.version,
        locale: version.locale,
        steps,
    })
}

/// Load and validate the ordered steps of one version.
async fn load_steps(
    db: &PgPool,
    tenant_id: &str,
    version_id: Uuid,
) -> Result<Vec<SequenceStep>, SalesError> {
    let rows: Vec<StepRow> = sqlx::query_as(
        "SELECT id, step_index, kind, template_id, min_delay_secs, max_delay_secs, \
                send_window, recipient_timezone, allowed_weekdays, experiment_key, \
                tracking_policy, sender_pool, exit_conditions, retry_policy, \
                branch_rules, config \
         FROM sales_sequence_steps \
         WHERE version_id = $1 AND tenant_id = $2 \
         ORDER BY step_index ASC",
    )
    .bind(version_id)
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    rows.into_iter().map(StepRow::into_step).collect()
}

/// Which step follows `current_step_index` for this version, if any?
///
/// The step with the smallest `step_index` strictly greater than
/// `current_step_index`; `None` once the sequence is exhausted. Step indexes
/// are unique per version (`UNIQUE (version_id, step_index)`) but need not be
/// contiguous, so this is a min-greater-than search, not an array index.
pub fn next_step(
    version: &SequenceVersionWithSteps,
    current_step_index: i32,
) -> Option<&SequenceStep> {
    version
        .steps
        .iter()
        .filter(|step| step.step_index > current_step_index)
        .min_by_key(|step| step.step_index)
}

/// Choose the delay for a step execution. Uses the step's min/max with a
/// DETERMINISTIC derivation from the idempotency key, so a retry computes the
/// same schedule and cannot jitter into a different slot.
///
/// * both bounds are clamped to >= 0 (a hand-edited negative row reads as 0);
/// * when `max <= min` (including both zero) the result is `min`;
/// * otherwise the key is hashed with FNV-1a (64-bit, no new dependency) and
///   mapped into `[min, max]` inclusive.
pub fn schedule_delay_secs(step: &SequenceStep, idempotency_key: &str) -> i64 {
    let min = step.min_delay_secs.max(0);
    let max = step.max_delay_secs.max(0);
    if max <= min {
        return min;
    }
    // Both bounds are non-negative and max > min, so the span fits in u64/i64.
    let span = (max - min) as u64 + 1;
    let offset = fnv1a_64(idempotency_key.as_bytes()) % span;
    min + offset as i64
}

/// FNV-1a, 64-bit. Deterministic across processes and platforms, and cheap
/// enough to run per scheduling decision.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// THE corrected idempotency identity for one logical step execution.
///
/// Format: `sa:{enrollment_id}:{sequence_version_id}:{step_id}:{attempt_kind}:{variant}`
///
/// The unit is a logical sequence step execution — NOT (campaign, recipient),
/// which made a second legitimate email to one recipient in one campaign an
/// inherent collision. Every step in a sequence therefore has its own key,
/// and a retry of the same step/attempt/variant maps back to the same key.
pub fn sales_step_idempotency_key(
    enrollment_id: Uuid,
    sequence_version_id: Uuid,
    step_id: Uuid,
    attempt_kind: &str,
    variant: &str,
) -> String {
    format!("sa:{enrollment_id}:{sequence_version_id}:{step_id}:{attempt_kind}:{variant}")
}

/// Replace every `{{key}}` (whitespace-tolerant `{{ key }}`) occurrence in
/// `template` with the HTML-escaped `value`, using the dispatcher's canonical
/// [`escape_html`] so a contact named `<script>` can never inject markup.
///
/// Unknown placeholders are left untouched, matching the dispatcher's
/// personalization behavior so operators can see them in dry-run output.
pub fn replace_placeholder_html(template: &str, key: &str, value: &str) -> String {
    let escaped = escape_html(value);
    let mut out = template.to_string();
    for pattern in [format!("{{{{{key}}}}}"), format!("{{{{ {key} }}}}")] {
        if out.contains(&pattern) {
            out = out.replace(&pattern, &escaped);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_step(id: u128, index: i32, min: i64, max: i64) -> SequenceStep {
        SequenceStep {
            id: Uuid::from_u128(id),
            step_index: index,
            kind: "email".into(),
            template_id: Some("tpl-1".into()),
            min_delay_secs: min,
            max_delay_secs: max,
            send_window: serde_json::json!({}),
            recipient_timezone: true,
            allowed_weekdays: vec![1, 2, 3, 4, 5],
            experiment_key: None,
            tracking_policy: "standard".into(),
            sender_pool: SenderPool::SalesOutbound,
            exit_conditions: serde_json::json!([]),
            retry_policy: serde_json::json!({}),
            branch_rules: serde_json::json!([]),
            config: serde_json::json!({}),
        }
    }

    fn test_version(steps: Vec<SequenceStep>) -> SequenceVersionWithSteps {
        SequenceVersionWithSteps {
            version_id: Uuid::from_u128(0x2000),
            sequence_id: Uuid::from_u128(0x1000),
            tenant_id: "tenant-a".into(),
            version: 1,
            locale: "en".into(),
            steps,
        }
    }

    fn test_step_row() -> StepRow {
        StepRow {
            id: Uuid::from_u128(0x9000),
            step_index: 0,
            kind: "email".into(),
            template_id: Some("tpl-1".into()),
            min_delay_secs: 0,
            max_delay_secs: 0,
            send_window: serde_json::json!({}),
            recipient_timezone: true,
            allowed_weekdays: vec![1, 2, 3, 4, 5],
            experiment_key: None,
            tracking_policy: "standard".into(),
            sender_pool: "sales_outbound".into(),
            exit_conditions: serde_json::json!([]),
            retry_policy: serde_json::json!({}),
            branch_rules: serde_json::json!([]),
            config: serde_json::json!({}),
        }
    }

    // -----------------------------------------------------------------------
    // sales_step_idempotency_key
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_key_has_the_exact_contract_format() {
        let enrollment = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let version = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let step = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();

        assert_eq!(
            sales_step_idempotency_key(enrollment, version, step, "primary", "default"),
            "sa:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222:33333333-3333-3333-3333-333333333333:primary:default"
        );
    }

    #[test]
    fn idempotency_key_is_stable_for_the_same_inputs() {
        let enrollment = Uuid::new_v4();
        let version = Uuid::new_v4();
        let step = Uuid::new_v4();
        let a = sales_step_idempotency_key(enrollment, version, step, "primary", "default");
        let b = sales_step_idempotency_key(enrollment, version, step, "primary", "default");
        assert_eq!(a, b, "same logical execution must produce the same key");
    }

    #[test]
    fn idempotency_key_diverges_for_two_steps_of_one_enrollment() {
        // This is the regression the corrected identity exists for: a second
        // legitimate step (email) to the same recipient in the same sequence
        // must NOT collide with the first.
        let enrollment = Uuid::new_v4();
        let version = Uuid::new_v4();
        let first_step = Uuid::new_v4();
        let second_step = Uuid::new_v4();

        let first =
            sales_step_idempotency_key(enrollment, version, first_step, "primary", "default");
        let second =
            sales_step_idempotency_key(enrollment, version, second_step, "primary", "default");
        assert_ne!(first, second, "two different steps must not share a key");
    }

    #[test]
    fn idempotency_key_diverges_for_attempt_kind_and_variant() {
        let enrollment = Uuid::new_v4();
        let version = Uuid::new_v4();
        let step = Uuid::new_v4();

        let primary = sales_step_idempotency_key(enrollment, version, step, "primary", "default");
        let followup = sales_step_idempotency_key(enrollment, version, step, "followup", "default");
        let variant_a =
            sales_step_idempotency_key(enrollment, version, step, "primary", "variant-a");
        let variant_b =
            sales_step_idempotency_key(enrollment, version, step, "primary", "variant-b");

        assert_ne!(primary, followup);
        assert_ne!(primary, variant_a);
        assert_ne!(variant_a, variant_b);
    }

    #[test]
    fn idempotency_key_fits_an_indexable_length() {
        // Realistic UUID inputs plus the longest allowed attempt kind/variant.
        let key = sales_step_idempotency_key(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "meeting_invite",
            "default",
        );
        assert!(
            key.len() <= 255,
            "idempotency key must fit a 255-char index, got {} chars",
            key.len()
        );
    }

    // -----------------------------------------------------------------------
    // next_step
    // -----------------------------------------------------------------------

    #[test]
    fn next_step_returns_smallest_greater_index() {
        let version = test_version(vec![
            test_step(1, 0, 0, 0),
            test_step(2, 1, 0, 0),
            test_step(3, 2, 0, 0),
        ]);
        assert_eq!(next_step(&version, 0).map(|s| s.step_index), Some(1));
        assert_eq!(next_step(&version, 1).map(|s| s.step_index), Some(2));
        assert!(next_step(&version, 2).is_none());
    }

    #[test]
    fn next_step_handles_non_contiguous_indexes() {
        let version = test_version(vec![
            test_step(1, 0, 0, 0),
            test_step(2, 3, 0, 0),
            test_step(3, 7, 0, 0),
        ]);
        assert_eq!(next_step(&version, 0).map(|s| s.step_index), Some(3));
        assert_eq!(next_step(&version, 3).map(|s| s.step_index), Some(7));
        assert_eq!(next_step(&version, 4).map(|s| s.step_index), Some(7));
        assert!(next_step(&version, 7).is_none());
    }

    #[test]
    fn next_step_on_negative_index_returns_first_step() {
        let version = test_version(vec![test_step(1, 0, 0, 0), test_step(2, 1, 0, 0)]);
        assert_eq!(next_step(&version, -1).map(|s| s.step_index), Some(0));
    }

    #[test]
    fn next_step_on_empty_version_is_none() {
        let version = test_version(vec![]);
        assert!(next_step(&version, 0).is_none());
    }

    // -----------------------------------------------------------------------
    // schedule_delay_secs
    // -----------------------------------------------------------------------

    #[test]
    fn schedule_delay_is_deterministic_for_one_key() {
        let step = test_step(1, 0, 60, 600);
        let key = sales_step_idempotency_key(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "primary",
            "default",
        );
        let first = schedule_delay_secs(&step, &key);
        for _ in 0..100 {
            assert_eq!(schedule_delay_secs(&step, &key), first);
        }
    }

    #[test]
    fn schedule_delay_stays_within_bounds_for_many_keys() {
        let step = test_step(1, 0, 30, 45);
        for n in 0..2_000u32 {
            let key = format!("sa:enrollment:version:step:primary:{n}");
            let delay = schedule_delay_secs(&step, &key);
            assert!(
                (30..=45).contains(&delay),
                "delay {delay} outside [30, 45] for key {key}"
            );
        }
    }

    #[test]
    fn schedule_delay_uses_the_whole_range() {
        let step = test_step(1, 0, 0, 9);
        let mut seen = [false; 10];
        for n in 0..500u32 {
            let delay = schedule_delay_secs(&step, &format!("key-{n}"));
            seen[delay as usize] = true;
        }
        assert!(
            seen.iter().all(|hit| *hit),
            "FNV-1a mapping should cover [0,9]"
        );
    }

    #[test]
    fn schedule_delay_collapses_when_max_not_above_min() {
        let equal = test_step(1, 0, 120, 120);
        assert_eq!(schedule_delay_secs(&equal, "any-key"), 120);

        // max < min cannot exist under the CHECK constraint, but a hand-edited
        // row must still produce a sane schedule (min wins).
        let inverted = test_step(1, 0, 300, 60);
        assert_eq!(schedule_delay_secs(&inverted, "any-key"), 300);

        let zero = test_step(1, 0, 0, 0);
        assert_eq!(schedule_delay_secs(&zero, "any-key"), 0);
    }

    #[test]
    fn schedule_delay_clamps_negative_bounds() {
        let negative = test_step(1, 0, -60, -10);
        assert_eq!(schedule_delay_secs(&negative, "any-key"), 0);

        let mixed = test_step(1, 0, -5, 5);
        for n in 0..200u32 {
            let delay = schedule_delay_secs(&mixed, &format!("k{n}"));
            assert!((0..=5).contains(&delay));
        }
    }

    // -----------------------------------------------------------------------
    // Step validation
    // -----------------------------------------------------------------------

    #[test]
    fn step_row_accepts_known_kinds_and_sales_pools() {
        for kind in STEP_KINDS {
            let mut row = test_step_row();
            row.kind = kind.into();
            let step = row.into_step().unwrap();
            assert_eq!(step.kind, kind);
        }
        for pool in ["sales_outbound", "sales_warmup"] {
            let mut row = test_step_row();
            row.sender_pool = pool.into();
            let step = row.into_step().unwrap();
            assert!(step.sender_pool.is_sales_pool());
        }
    }

    #[test]
    fn step_row_rejects_unknown_kind_naming_the_value() {
        let mut row = test_step_row();
        row.kind = "telepathy".into();
        let err = row.into_step().unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, SalesError::InvalidInput(_)));
        assert!(
            message.contains("telepathy"),
            "message must name the bad value"
        );
    }

    #[test]
    fn step_row_rejects_unknown_sender_pool_naming_the_value() {
        let mut row = test_step_row();
        row.sender_pool = "marketing_blast".into();
        let err = row.into_step().unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, SalesError::InvalidInput(_)));
        assert!(message.contains("marketing_blast"));
    }

    #[test]
    fn step_row_rejects_transactional_sender_pool() {
        // Parses as a SenderPool but must never be selectable by a sales step.
        let mut row = test_step_row();
        row.sender_pool = "transactional_customer".into();
        let err = row.into_step().unwrap_err();
        assert!(matches!(err, SalesError::InvalidInput(_)));
        assert!(err.to_string().contains("non-sales sender_pool"));
    }

    // -----------------------------------------------------------------------
    // Personalization
    // -----------------------------------------------------------------------

    #[test]
    fn placeholder_replacement_escapes_html() {
        let rendered = replace_placeholder_html(
            "Hi {{first_name}}, welcome to {{company}}!",
            "first_name",
            "<script>alert('x')</script>",
        );
        assert_eq!(
            rendered,
            "Hi &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;, welcome to {{company}}!"
        );
    }

    #[test]
    fn placeholder_replacement_tolerates_spaced_form() {
        let rendered = replace_placeholder_html("Hi {{ name }}.", "name", "Alice & Bob");
        assert_eq!(rendered, "Hi Alice &amp; Bob.");
    }

    #[test]
    fn placeholder_replacement_leaves_unknown_keys_untouched() {
        assert_eq!(
            replace_placeholder_html("Hi {{ name }}.", "company", "Acme"),
            "Hi {{ name }}."
        );
    }
}
