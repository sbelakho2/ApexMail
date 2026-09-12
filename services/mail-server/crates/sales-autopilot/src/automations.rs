//! Automation execution engine (`/v1/automations` rules actually run here).
//!
//! # Why this module exists
//!
//! `crates/api-server/src/routes/automations.rs` is CRUD only: it persists
//! `automations.trigger_config`, `.conditions` and `.actions`. Until this
//! module there was NO executor anywhere in the workspace, so the audit item
//! "unify SendAdmissionService for REST + SMTP submission + Sales +
//! automations" documented the automation arm as a contract with no caller.
//!
//! This engine is the caller. Its tick:
//!
//! 1. **claims due work** from `automation_trigger_events` (migration 224)
//!    with `FOR UPDATE SKIP LOCKED` and a lease, bounded to
//!    [`AutomationExecutor::with_batch_size`] events per tick;
//! 2. **evaluates** every enabled rule of the event's tenant against the
//!    event — the trigger vocabulary is exactly what the product writes (see
//!    [`AutomationEventKind`] and [`resolve_trigger`]); a stored kind with no
//!    meaning is reported in the run log as an unsupported trigger, never
//!    silently ignored;
//! 3. **executes** the rule's actions in order, recording one
//!    `automation_run_actions` row per action (sent message id / skipped
//!    reason / failed error) so "why did nothing happen?" is answerable from
//!    the database alone;
//! 4. sends through the ONE shared admission gate
//!    ([`SendAdmissionService`]) and the platform pipeline (`messages` +
//!    `email_queue`), never a side channel.
//!
//! # Exactly-once (three derived identities, no random retry ids)
//!
//! * **Event** — `automation_trigger_events.event_key` is derived from the
//!   source row (migration 224 header), unique per tenant. A replayed
//!   platform event is a no-op at ingest.
//! * **Run** — `automation_runs` is unique on
//!   `(tenant_id, automation_id, trigger_event_key)`: one run per (rule,
//!   event) forever. A re-claimed event RESUMES its run; only actions without
//!   a terminal record are re-attempted.
//! * **Send** — `messages.idempotency_key = "autoact:{run_id}:{action_index}"`
//!   (unique per tenant). The `messages` + `email_queue` inserts share one
//!   transaction, and even if the process dies after that commit and before
//!   the `automation_run_actions` bookkeeping write, the retry's insert hits
//!   the idempotency key and reuses the existing message instead of sending
//!   again — the partial-commit window is closed by the derived key, not by
//!   hoping the two writes stay together.
//!
//! # Admission (audit implementation-order item 3)
//!
//! Every `send_email` action passes
//! [`SendAdmissionService::admit`](billing_service::send_admission::SendAdmissionService::admit)
//! with an EXPLICIT category:
//!
//! * [`AUTOMATION_MARKETING_CATEGORY`] (`marketing`) for every rule triggered
//!   by a contact lifecycle event — automation/nurture mail is commercial
//!   mail and gets no opt-out exemption;
//! * [`AUTOMATION_REPLY_CATEGORY`] (`transactional`) only for a 1:1 reply to
//!   a message the recipient sent (`message.received`).
//!
//! Refusals are classified: a suppression (or the server-owned category
//! failing validation) is a TERMINAL skip recorded in the action log, never a
//! retry; quota exhaustion and metering/suppression-store unavailability are
//! RETRYABLE deferrals that leave the event due for a later tick (still
//! exactly-once: the run and send identities above make the retry a resume).
//!
//! # Tenant isolation
//!
//! Every statement binds `tenant_id` from the claimed event row: rules,
//! contacts, templates, lists, webhooks, suppression checks and the enqueue
//! itself are all tenant-scoped. There is no cross-tenant read in this module.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use apexmail_lib::email_headers::message_category;
use billing_service::send_admission::{
    AdmissionMeter, SendAdmissionError, SendAdmissionRequest, SendAdmissionService,
};

use crate::dispatcher::{fetch_template, TemplateContent};
use crate::types::SalesError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Category of every automation send triggered by a contact lifecycle event.
///
/// Automations are CUSTOMER-configured, trigger-driven lifecycle mail
/// (welcome series, onboarding, re-engagement): commercial mail,
/// `marketing`-class under the platform's suppression semantics, and
/// deliberately NOT preference-exempt. Passed to admission EXPLICITLY — an
/// automation send must never acquire an opt-out exemption through a missing
/// field or a schema default.
pub const AUTOMATION_MARKETING_CATEGORY: &str = message_category::MARKETING;

/// Category of a 1:1 reply to a message the recipient sent (`message.received`).
///
/// The rule answers inbound correspondence: transactional-class, exactly like
/// the sales reply path. Global suppression still applies — admission checks
/// the canonical suppression list for every category.
pub const AUTOMATION_REPLY_CATEGORY: &str = message_category::TRANSACTIONAL;

/// Due events claimed per tick (bounded work, bounded memory).
pub const DEFAULT_BATCH_SIZE: i64 = 25;

/// Rule pages scanned per event; the loop pages until rules are exhausted so
/// a tenant with more enabled rules than one page still evaluates all of them.
const RULES_PAGE_SIZE: i64 = 200;

/// Lease held by a tick while it processes one claimed event.
const EVENT_LEASE_SECS: f64 = 120.0;

/// Per-action attempt cap for retryable failures.
const MAX_ACTION_ATTEMPTS: i32 = 5;

/// Settled inbox rows older than this are pruned (bounded slice per tick);
/// the run log keeps the durable audit (`source_event_id` detaches).
const EVENT_RETENTION_DAYS: i32 = 30;

/// Upper bound of the retention prune per tick.
const PRUNE_BATCH: i64 = 1000;

/// Bound on list-ish values copied into records/payloads.
const MAX_DETAIL_ITEMS: usize = 50;

// ---------------------------------------------------------------------------
// Event vocabulary
// ---------------------------------------------------------------------------

/// The event families the product actually stores.
///
/// * contact lifecycle events are emitted by the schema trigger on `contacts`
///   (migration 224) exactly as documented in
///   `docs/api/endpoints/automations.md` (`trigger.type: "event"`,
///   `event: "contact.created"`);
/// * [`Self::MessageReceived`] is emitted by the trigger on
///   `inbound_messages` and is the 1:1 inbound reply trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutomationEventKind {
    ContactCreated,
    ContactUpdated,
    ContactTagAdded,
    MessageReceived,
}

impl AutomationEventKind {
    /// Canonical event name (matches the documented `trigger.event` values).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContactCreated => "contact.created",
            Self::ContactUpdated => "contact.updated",
            Self::ContactTagAdded => "contact.tag_added",
            Self::MessageReceived => "message.received",
        }
    }

    /// Parse a stored event name. Both the documented dotted names and the
    /// underscore aliases that appear in-repo (`contact_created`,
    /// `tag_added`, ...) are accepted; anything else is not a vocabulary this
    /// product writes.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "contact.created" | "contact_created" => Some(Self::ContactCreated),
            "contact.updated" | "contact_updated" => Some(Self::ContactUpdated),
            "contact.tag_added" | "contact_tag_added" | "tag_added" => Some(Self::ContactTagAdded),
            "message.received" | "message_received" => Some(Self::MessageReceived),
            _ => None,
        }
    }

    /// The admission category this event's sends carry (see module docs).
    pub fn send_category(self) -> &'static str {
        match self {
            Self::MessageReceived => AUTOMATION_REPLY_CATEGORY,
            _ => AUTOMATION_MARKETING_CATEGORY,
        }
    }

    /// Whether the event carries a contact entity.
    fn is_contact_event(self) -> bool {
        !matches!(self, Self::MessageReceived)
    }
}

// ---------------------------------------------------------------------------
// Trigger evaluation
// ---------------------------------------------------------------------------

/// A rule trigger resolved to something the executor can evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerSpec {
    pub event: AutomationEventKind,
    /// `trigger_config.filters.tags` — the whole filter vocabulary the
    /// documented product shape contains.
    pub filter_tags: Vec<String>,
}

/// Outcome of reading `automations.trigger_config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerResolution {
    /// A trigger kind and configuration the executor supports.
    Supported(TriggerSpec),
    /// A stored kind/config with no meaning in this deployment. Reported as a
    /// skipped run (`unsupported trigger ...`) exactly once per rule, never
    /// silently ignored.
    Unsupported { kind: String, reason: String },
}

/// Read the ACTUAL stored shape of `trigger_config`:
///
/// * `{"type": "event", "event": "contact.created", "filters": {"tags": [...]}}`
///   (the documented shape; `docs/api/endpoints/automations.md`);
/// * `{"type": "contact_created"}` / `{"type": "tag_added"}` (the
///   in-repo underscore aliases);
/// * anything else — `schedule`, `webhook`, an unknown event name, a filter
///   key the product does not define — resolves to
///   [`TriggerResolution::Unsupported`] with a product-readable reason.
pub fn resolve_trigger(trigger: &Value) -> TriggerResolution {
    let Some(obj) = trigger.as_object() else {
        return TriggerResolution::Unsupported {
            kind: "<non-object>".into(),
            reason: "trigger_config is not a JSON object".into(),
        };
    };

    let raw_kind = obj
        .get("type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let event_kind = match raw_kind {
        Some("event") => {
            let Some(name) = obj
                .get("event")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return TriggerResolution::Unsupported {
                    kind: "event".into(),
                    reason: "event trigger has no 'event' name".into(),
                };
            };
            match AutomationEventKind::parse(name) {
                Some(kind) => kind,
                None => {
                    return TriggerResolution::Unsupported {
                        kind: "event".into(),
                        reason: format!("unsupported trigger event '{name}'"),
                    };
                }
            }
        }
        Some(other) => match AutomationEventKind::parse(other) {
            Some(kind) => kind,
            None => {
                return TriggerResolution::Unsupported {
                    kind: other.to_string(),
                    reason: format!("unsupported trigger kind '{other}'"),
                };
            }
        },
        None => {
            return TriggerResolution::Unsupported {
                kind: "<missing>".into(),
                reason: "trigger_config has no 'type'".into(),
            };
        }
    };

    let mut filter_tags = Vec::new();
    match obj.get("filters") {
        None | Some(Value::Null) => {}
        Some(Value::Object(filters)) => {
            for (key, value) in filters {
                if key != "tags" {
                    return TriggerResolution::Unsupported {
                        kind: raw_kind.unwrap_or("<missing>").to_string(),
                        reason: format!("unsupported trigger filter '{key}'"),
                    };
                }
                let Some(items) = value.as_array() else {
                    return TriggerResolution::Unsupported {
                        kind: raw_kind.unwrap_or("<missing>").to_string(),
                        reason: "trigger filter 'tags' must be an array of strings".into(),
                    };
                };
                for item in items {
                    match item.as_str().map(str::trim).filter(|tag| !tag.is_empty()) {
                        Some(tag) => filter_tags.push(tag.to_string()),
                        None => {
                            return TriggerResolution::Unsupported {
                                kind: raw_kind.unwrap_or("<missing>").to_string(),
                                reason: "trigger filter 'tags' must contain non-empty strings"
                                    .into(),
                            };
                        }
                    }
                }
            }
        }
        Some(_) => {
            return TriggerResolution::Unsupported {
                kind: raw_kind.unwrap_or("<missing>").to_string(),
                reason: "trigger_config.filters must be a JSON object".into(),
            };
        }
    }

    TriggerResolution::Supported(TriggerSpec {
        event: event_kind,
        filter_tags,
    })
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// Verdict of `automations.conditions` for one event context.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionVerdict {
    Met,
    NotMet(String),
    Unsupported(String),
}

/// Evaluate the documented condition shape
/// (`{"all": [{"field": "tags", "operator": "contains", "value": "active"}]}`).
///
/// Unknown group keys, fields and operators are `Unsupported` — reported in
/// the run log, never treated as a silent pass.
fn evaluate_conditions(conditions: Option<&Value>, ctx: &EventContext) -> ConditionVerdict {
    let Some(conditions) = conditions else {
        return ConditionVerdict::Met;
    };
    if conditions.is_null() {
        return ConditionVerdict::Met;
    }
    let Some(obj) = conditions.as_object() else {
        return ConditionVerdict::Unsupported("conditions must be a JSON object".into());
    };
    if obj.is_empty() {
        return ConditionVerdict::Met;
    }

    let mut saw_group = false;
    for (group, value) in obj {
        match group.as_str() {
            "all" => {
                saw_group = true;
                let Some(leaves) = value.as_array() else {
                    return ConditionVerdict::Unsupported("'all' must be an array".into());
                };
                for leaf in leaves {
                    match evaluate_condition_leaf(leaf, ctx) {
                        ConditionVerdict::Met => {}
                        ConditionVerdict::NotMet(reason) => {
                            return ConditionVerdict::NotMet(reason)
                        }
                        ConditionVerdict::Unsupported(reason) => {
                            return ConditionVerdict::Unsupported(reason);
                        }
                    }
                }
            }
            "any" => {
                saw_group = true;
                let Some(leaves) = value.as_array() else {
                    return ConditionVerdict::Unsupported("'any' must be an array".into());
                };
                if leaves.is_empty() {
                    return ConditionVerdict::NotMet("'any' has no conditions".into());
                }
                let mut matched = false;
                for leaf in leaves {
                    match evaluate_condition_leaf(leaf, ctx) {
                        ConditionVerdict::Met => {
                            matched = true;
                            break;
                        }
                        ConditionVerdict::NotMet(_) => {}
                        ConditionVerdict::Unsupported(reason) => {
                            return ConditionVerdict::Unsupported(reason);
                        }
                    }
                }
                if !matched {
                    return ConditionVerdict::NotMet("no condition in 'any' matched".into());
                }
            }
            other => {
                return ConditionVerdict::Unsupported(format!(
                    "unsupported condition group '{other}'"
                ));
            }
        }
    }

    if !saw_group {
        return ConditionVerdict::Unsupported(
            "conditions must contain an 'all' or 'any' group".into(),
        );
    }
    ConditionVerdict::Met
}

fn evaluate_condition_leaf(leaf: &Value, ctx: &EventContext) -> ConditionVerdict {
    let Some(obj) = leaf.as_object() else {
        return ConditionVerdict::Unsupported("condition entry must be a JSON object".into());
    };
    let Some(field) = obj.get("field").and_then(Value::as_str) else {
        return ConditionVerdict::Unsupported("condition entry has no 'field'".into());
    };
    let Some(operator) = obj.get("operator").and_then(Value::as_str) else {
        return ConditionVerdict::Unsupported(format!("condition on '{field}' has no 'operator'"));
    };

    let resolved = ctx.field(field);
    match operator {
        "exists" => {
            if resolved.is_some() {
                ConditionVerdict::Met
            } else {
                ConditionVerdict::NotMet(format!("field '{field}' does not exist"))
            }
        }
        "not_exists" => {
            if resolved.is_none() {
                ConditionVerdict::Met
            } else {
                ConditionVerdict::NotMet(format!("field '{field}' exists"))
            }
        }
        "equals" | "eq" | "not_equals" | "ne" | "contains" | "in" => {
            let Some(value) = obj.get("value") else {
                return ConditionVerdict::Unsupported(format!(
                    "condition on '{field}' is missing 'value'"
                ));
            };
            let Some(resolved) = resolved else {
                return ConditionVerdict::NotMet(format!("field '{field}' does not exist"));
            };
            match compare_condition(&resolved, operator, value) {
                Some(matched) => {
                    if matched {
                        ConditionVerdict::Met
                    } else {
                        ConditionVerdict::NotMet(format!(
                            "field '{field}' did not satisfy '{operator}'"
                        ))
                    }
                }
                None => ConditionVerdict::Unsupported(format!(
                    "operator '{operator}' is not defined for '{field}'"
                )),
            }
        }
        other => ConditionVerdict::Unsupported(format!("unsupported operator '{other}'")),
    }
}

/// `None` = the operator is not defined for this field type (unsupported, not
/// a silent false).
fn compare_condition(resolved: &FieldValue<'_>, operator: &str, expected: &Value) -> Option<bool> {
    match resolved {
        FieldValue::Scalar(actual) => match operator {
            "equals" | "eq" => Some(match expected.as_str() {
                Some(expected) => actual.eq_ignore_ascii_case(expected),
                None => false,
            }),
            "not_equals" | "ne" => Some(match expected.as_str() {
                Some(expected) => !actual.eq_ignore_ascii_case(expected),
                None => true,
            }),
            "contains" => expected.as_str().map(|needle| {
                actual
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            }),
            "in" => expected.as_array().map(|items| {
                items.iter().any(|item| {
                    item.as_str()
                        .is_some_and(|item| actual.eq_ignore_ascii_case(item))
                })
            }),
            _ => None,
        },
        FieldValue::Array(actual) => match operator {
            "contains" => {
                if let Some(needle) = expected.as_str() {
                    Some(actual.iter().any(|item| item.eq_ignore_ascii_case(needle)))
                } else {
                    expected.as_array().map(|needles| {
                        needles.iter().all(|needle| {
                            needle.as_str().is_some_and(|needle| {
                                actual.iter().any(|item| item.eq_ignore_ascii_case(needle))
                            })
                        })
                    })
                }
            }
            "equals" | "eq" => expected.as_array().map(|needles| {
                let mut expected_tags: Vec<String> = needles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|item| item.to_ascii_lowercase())
                    .collect();
                expected_tags.sort();
                let mut actual_tags: Vec<String> = actual
                    .iter()
                    .map(|item| item.to_ascii_lowercase())
                    .collect();
                actual_tags.sort();
                actual_tags == expected_tags
            }),
            "not_equals" | "ne" => {
                compare_condition(resolved, "equals", expected).map(|equal| !equal)
            }
            "in" => expected.as_array().map(|needles| {
                actual.iter().all(|item| {
                    needles.iter().any(|needle| {
                        needle
                            .as_str()
                            .is_some_and(|n| item.eq_ignore_ascii_case(n))
                    })
                })
            }),
            _ => None,
        },
    }
}

/// A condition field value borrowed from the event context.
enum FieldValue<'a> {
    Scalar(Cow<'a, str>),
    Array(&'a [String]),
}

/// The entity an event carries, resolved tenant-scoped from the canonical
/// tables (never from the event payload alone).
#[derive(Debug, Clone)]
pub struct AutomationContact {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub status: String,
    pub tags: Vec<String>,
}

/// Everything a rule can be evaluated/executed against.
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    pub contact: Option<AutomationContact>,
    pub tags_added: Vec<String>,
    pub from_email: Option<String>,
    pub to_email: Option<String>,
    pub subject: Option<String>,
}

impl EventContext {
    fn field(&self, field: &str) -> Option<FieldValue<'_>> {
        match field {
            "tags" | "contact.tags" => self
                .contact
                .as_ref()
                .map(|contact| FieldValue::Array(&contact.tags)),
            "tags_added" | "contact.tags_added" => Some(FieldValue::Array(&self.tags_added)),
            "email" | "contact.email" => self
                .contact
                .as_ref()
                .map(|contact| FieldValue::Scalar(Cow::Borrowed(contact.email.as_str()))),
            "name" | "contact.name" => self
                .contact
                .as_ref()
                .and_then(|contact| contact.name.as_deref())
                .map(|name| FieldValue::Scalar(Cow::Borrowed(name))),
            "status" | "contact.status" => self
                .contact
                .as_ref()
                .map(|contact| FieldValue::Scalar(Cow::Borrowed(contact.status.as_str()))),
            "id" | "contact.id" => self
                .contact
                .as_ref()
                .map(|contact| FieldValue::Scalar(Cow::Owned(contact.id.to_string()))),
            "from_email" | "message.from_email" => self
                .from_email
                .as_deref()
                .map(|value| FieldValue::Scalar(Cow::Borrowed(value))),
            "to_email" | "message.to_email" => self
                .to_email
                .as_deref()
                .map(|value| FieldValue::Scalar(Cow::Borrowed(value))),
            "subject" | "message.subject" => self
                .subject
                .as_deref()
                .map(|value| FieldValue::Scalar(Cow::Borrowed(value))),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// A due event claimed by the tick.
#[derive(Debug, sqlx::FromRow)]
struct DueEvent {
    id: Uuid,
    tenant_id: String,
    event_type: String,
    event_key: String,
    contact_id: Option<Uuid>,
    recipient_email: Option<String>,
    payload: Value,
    attempts: i32,
    max_attempts: i32,
}

/// An enabled rule as stored.
#[derive(Debug, sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    trigger_config: Option<Value>,
    conditions: Option<Value>,
    actions: Option<Value>,
    created_at: DateTime<Utc>,
}

/// Existing per-action state of a resumed run.
#[derive(Debug, sqlx::FromRow)]
struct ExistingAction {
    action_index: i32,
    status: String,
    retryable: bool,
    attempts: i32,
}

/// Existing run identity/state.
#[derive(Debug, sqlx::FromRow)]
struct RunState {
    id: Uuid,
    status: String,
    retryable: bool,
}

/// What one tick did (all counters are bounded by the batch size).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    pub events_claimed: u64,
    pub events_processed: u64,
    pub events_deferred: u64,
    pub events_failed: u64,
    pub runs_started: u64,
    pub runs_replayed: u64,
    pub runs_succeeded: u64,
    pub runs_skipped: u64,
    pub runs_failed: u64,
    pub actions_enqueued: u64,
    pub events_pruned: u64,
}

impl TickReport {
    fn merge(&mut self, other: TickReport) {
        self.events_claimed += other.events_claimed;
        self.events_processed += other.events_processed;
        self.events_deferred += other.events_deferred;
        self.events_failed += other.events_failed;
        self.runs_started += other.runs_started;
        self.runs_replayed += other.runs_replayed;
        self.runs_succeeded += other.runs_succeeded;
        self.runs_skipped += other.runs_skipped;
        self.runs_failed += other.runs_failed;
        self.actions_enqueued += other.actions_enqueued;
        self.events_pruned += other.events_pruned;
    }
}

/// Per-action execution outcome, persisted to `automation_run_actions`.
#[derive(Debug, Clone)]
struct ActionRecord {
    status: &'static str,
    reason: Option<String>,
    error: Option<String>,
    retryable: bool,
    message_id: Option<Uuid>,
    queue_id: Option<Uuid>,
    quota_event_id: Option<Uuid>,
    detail: Value,
}

impl ActionRecord {
    fn succeeded(
        message_id: Uuid,
        queue_id: Option<Uuid>,
        quota_event_id: Uuid,
        detail: Value,
    ) -> Self {
        Self {
            status: "succeeded",
            reason: None,
            error: None,
            retryable: false,
            message_id: Some(message_id),
            queue_id,
            quota_event_id: Some(quota_event_id),
            detail,
        }
    }

    /// A non-send action that changed local state.
    fn effect(detail: impl Into<String>) -> Self {
        Self {
            status: "succeeded",
            reason: None,
            error: None,
            retryable: false,
            message_id: None,
            queue_id: None,
            quota_event_id: None,
            detail: json!({ "effect": detail.into() }),
        }
    }

    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            status: "skipped",
            reason: Some(reason.into()),
            error: None,
            retryable: false,
            message_id: None,
            queue_id: None,
            quota_event_id: None,
            detail: json!({}),
        }
    }

    fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            status: "unsupported",
            reason: Some(reason.into()),
            error: None,
            retryable: false,
            message_id: None,
            queue_id: None,
            quota_event_id: None,
            detail: json!({}),
        }
    }

    fn failed_retryable(error: impl Into<String>) -> Self {
        Self {
            status: "failed",
            reason: None,
            error: Some(error.into()),
            retryable: true,
            message_id: None,
            queue_id: None,
            quota_event_id: None,
            detail: json!({}),
        }
    }

    fn failed_terminal(error: impl Into<String>) -> Self {
        Self {
            status: "failed",
            reason: None,
            error: Some(error.into()),
            retryable: false,
            message_id: None,
            queue_id: None,
            quota_event_id: None,
            detail: json!({}),
        }
    }

    fn is_enqueue(&self) -> bool {
        self.status == "succeeded" && self.message_id.is_some()
    }
}

/// The automation execution engine. Cheap to clone (pool + admission are
/// `Arc`-backed); construct once per process and tick it.
#[derive(Clone)]
pub struct AutomationExecutor {
    db: PgPool,
    admission: SendAdmissionService,
    worker_id: Arc<str>,
    batch_size: i64,
}

impl AutomationExecutor {
    pub fn new(db: PgPool, admission: SendAdmissionService, worker_id: impl Into<String>) -> Self {
        Self {
            db,
            admission,
            worker_id: Arc::from(worker_id.into().as_str()),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Bound the events claimed per tick (clamped to `1..=1000`).
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.clamp(1, 1000);
        self
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Ingest one platform event into the inbox. Idempotent by
    /// `(tenant_id, event_key)`: returns `true` only when this call inserted
    /// the event, `false` when it was already present (a replay — the
    /// executor will not process it twice).
    ///
    /// This is the public producer seam (the DB triggers call the same
    /// identity contract inline); tests and future producers use it.
    pub async fn ingest_event(
        &self,
        tenant_id: &str,
        event_type: &str,
        event_key: &str,
        contact_id: Option<Uuid>,
        recipient_email: Option<&str>,
        payload: Value,
    ) -> Result<bool, SalesError> {
        let inserted = sqlx::query(
            "INSERT INTO automation_trigger_events \
             (tenant_id, event_type, event_key, contact_id, recipient_email, payload) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (tenant_id, event_key) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(event_key)
        .bind(contact_id)
        .bind(recipient_email)
        .bind(&payload)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(inserted.rows_affected() == 1)
    }

    /// One scheduler tick: claim a bounded batch of due events, execute the
    /// matching rules of each event's tenant, settle the events, prune a
    /// bounded slice of settled inbox rows.
    pub async fn tick(&self) -> Result<TickReport, SalesError> {
        let due = self.claim_due_events().await?;
        let mut report = TickReport {
            events_claimed: due.len() as u64,
            ..TickReport::default()
        };

        for event in due {
            let outcome = self.process_event(&event).await?;
            report.merge(outcome);
            if let Err(error) = self.settle_event(&event, &outcome).await {
                tracing::error!(
                    error = %error,
                    event_id = %event.id,
                    tenant_id = %event.tenant_id,
                    "failed to settle automation event; the lease will expire and the event \
                     will be reclaimed"
                );
            }
        }

        report.events_pruned = self.prune_settled_events().await.unwrap_or_else(|error| {
            tracing::warn!(error = %error, "automation event prune failed (non-fatal)");
            0
        });

        Ok(report)
    }

    // -- Claiming ----------------------------------------------------------

    async fn claim_due_events(&self) -> Result<Vec<DueEvent>, SalesError> {
        sqlx::query_as::<_, DueEvent>(
            "UPDATE automation_trigger_events AS e \
             SET status = 'processing', \
                 locked_until = NOW() + make_interval(secs => $3::double precision), \
                 locked_by = $1, \
                 attempts = e.attempts + 1, \
                 updated_at = NOW() \
             WHERE e.id IN ( \
                 SELECT id FROM automation_trigger_events \
                 WHERE (status = 'pending' AND available_at <= NOW()) \
                    OR (status = 'processing' AND locked_until IS NOT NULL AND locked_until < NOW()) \
                 ORDER BY available_at, created_at, id \
                 LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING e.id, e.tenant_id, e.event_type, e.event_key, e.contact_id, \
                       e.recipient_email, e.payload, e.attempts, e.max_attempts",
        )
        .bind(&*self.worker_id)
        .bind(self.batch_size)
        .bind(EVENT_LEASE_SECS)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))
    }

    // -- Event processing --------------------------------------------------

    async fn process_event(&self, event: &DueEvent) -> Result<TickReport, SalesError> {
        let mut report = TickReport::default();

        let Some(kind) = AutomationEventKind::parse(&event.event_type) else {
            tracing::warn!(
                tenant_id = %event.tenant_id,
                event_type = %event.event_type,
                "unsupported automation event type in inbox"
            );
            report.events_failed = 1;
            return Ok(report);
        };

        let ctx = self.load_context(event, kind).await?;

        let mut retryable_error: Option<String> = None;
        let mut cursor: Option<(DateTime<Utc>, Uuid)> = None;
        loop {
            let rules = self.enabled_rules_page(&event.tenant_id, cursor).await?;
            let page_len = rules.len();
            if page_len == 0 {
                break;
            }
            cursor = rules.last().map(|rule| (rule.created_at, rule.id));

            for rule in &rules {
                match resolve_trigger(rule.trigger_config.as_ref().unwrap_or(&Value::Null)) {
                    TriggerResolution::Unsupported { kind, reason } => {
                        self.record_unsupported_trigger(rule, event, &kind, &reason)
                            .await?;
                    }
                    TriggerResolution::Supported(spec) if spec.event == kind => {
                        let Some(ctx) = ctx.as_ref() else {
                            self.record_skipped_run(
                                rule,
                                event,
                                kind,
                                "trigger_entity_missing",
                                "the event's contact no longer exists",
                            )
                            .await?;
                            report.runs_skipped += 1;
                            continue;
                        };
                        if !trigger_filter_matches(&spec, ctx, kind) {
                            self.record_skipped_run(
                                rule,
                                event,
                                kind,
                                "trigger_filter_not_met",
                                "the event does not satisfy the trigger filters",
                            )
                            .await?;
                            report.runs_skipped += 1;
                            continue;
                        }
                        match evaluate_conditions(rule.conditions.as_ref(), ctx) {
                            ConditionVerdict::Unsupported(reason) => {
                                self.record_skipped_run(
                                    rule,
                                    event,
                                    kind,
                                    "unsupported_condition",
                                    &reason,
                                )
                                .await?;
                                report.runs_skipped += 1;
                            }
                            ConditionVerdict::NotMet(reason) => {
                                self.record_skipped_run(
                                    rule,
                                    event,
                                    kind,
                                    "condition_not_met",
                                    &reason,
                                )
                                .await?;
                                report.runs_skipped += 1;
                            }
                            ConditionVerdict::Met => {
                                let (run_report, retryable) =
                                    self.execute_rule(rule, event, kind, ctx).await?;
                                report.merge(run_report);
                                if retryable_error.is_none() {
                                    retryable_error = retryable;
                                }
                            }
                        }
                    }
                    TriggerResolution::Supported(_) => {
                        // A supported trigger for a different event family.
                    }
                }
            }

            if page_len < RULES_PAGE_SIZE as usize {
                break;
            }
        }

        if retryable_error.is_some() {
            // Defer the whole event: every run is idempotent, so the retry
            // replays settled rules as no-ops and resumes failed ones.
            self.defer_event(event, retryable_error.as_deref().unwrap_or_default())
                .await?;
            report.events_deferred = 1;
        } else {
            report.events_processed = 1;
        }
        Ok(report)
    }

    /// Load the event's entity context, tenant-scoped and FRESH (the payload
    /// is not trusted for state; only for the tag delta).
    async fn load_context(
        &self,
        event: &DueEvent,
        kind: AutomationEventKind,
    ) -> Result<Option<EventContext>, SalesError> {
        let mut ctx = EventContext {
            from_email: event.recipient_email.clone().or_else(|| {
                event
                    .payload
                    .get("from_email")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }),
            to_email: event
                .payload
                .get("to_email")
                .and_then(Value::as_str)
                .map(str::to_string),
            subject: event
                .payload
                .get("subject")
                .and_then(Value::as_str)
                .map(str::to_string),
            ..EventContext::default()
        };

        ctx.tags_added = event
            .payload
            .get("tags_added")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .take(MAX_DETAIL_ITEMS)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        if !kind.is_contact_event() {
            return Ok(Some(ctx));
        }

        let Some(contact_id) = event.contact_id else {
            return Ok(None);
        };
        let row: Option<(Uuid, String, Option<String>, String, Value)> = sqlx::query_as(
            "SELECT id, email, name, status, tags FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(&event.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        let Some((id, email, name, status, tags)) = row else {
            return Ok(None);
        };
        let tags: Vec<String> = tags
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        ctx.contact = Some(AutomationContact {
            id,
            email,
            name,
            status,
            tags,
        });
        Ok(Some(ctx))
    }

    async fn enabled_rules_page(
        &self,
        tenant_id: &str,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<RuleRow>, SalesError> {
        match cursor {
            Some((created_at, id)) => sqlx::query_as::<_, RuleRow>(
                "SELECT id, name, trigger_config, conditions, actions, created_at \
                 FROM automations \
                 WHERE tenant_id = $1 AND status = 'enabled' \
                   AND (created_at, id) > ($2, $3) \
                 ORDER BY created_at, id LIMIT $4",
            )
            .bind(tenant_id)
            .bind(created_at)
            .bind(id)
            .bind(RULES_PAGE_SIZE)
            .fetch_all(&self.db)
            .await
            .map_err(|error| SalesError::Database(error.to_string())),
            None => sqlx::query_as::<_, RuleRow>(
                "SELECT id, name, trigger_config, conditions, actions, created_at \
                 FROM automations \
                 WHERE tenant_id = $1 AND status = 'enabled' \
                 ORDER BY created_at, id LIMIT $2",
            )
            .bind(tenant_id)
            .bind(RULES_PAGE_SIZE)
            .fetch_all(&self.db)
            .await
            .map_err(|error| SalesError::Database(error.to_string())),
        }
    }

    // -- Run lifecycle -----------------------------------------------------

    /// Insert the run row (or fetch the existing one). `Some(state)` when this
    /// call owns (or resumes) the run, `None` when the run is already
    /// terminal — the replay no-op.
    async fn get_or_create_run(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: AutomationEventKind,
        trigger_kind: &str,
    ) -> Result<Option<RunState>, SalesError> {
        let inserted: Option<RunState> = sqlx::query_as(
            "INSERT INTO automation_runs \
             (automation_id, automation_name, tenant_id, trigger_kind, trigger_event_type, \
              trigger_event_key, source_event_id, status, started_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'running', NOW()) \
             ON CONFLICT (tenant_id, automation_id, trigger_event_key) DO NOTHING \
             RETURNING id, status, retryable",
        )
        .bind(rule.id)
        .bind(&rule.name)
        .bind(&event.tenant_id)
        .bind(trigger_kind)
        .bind(kind.as_str())
        .bind(&event.event_key)
        .bind(event.id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        if let Some(state) = inserted {
            return Ok(Some(state));
        }

        let existing: Option<RunState> = sqlx::query_as(
            "SELECT id, status, retryable FROM automation_runs \
             WHERE tenant_id = $1 AND automation_id = $2 AND trigger_event_key = $3",
        )
        .bind(&event.tenant_id)
        .bind(rule.id)
        .bind(&event.event_key)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        match existing {
            Some(state)
                if state.status == "running" || (state.status == "failed" && state.retryable) =>
            {
                sqlx::query(
                    "UPDATE automation_runs SET status = 'running', retryable = FALSE, \
                     error = NULL, updated_at = NOW() \
                     WHERE id = $1 AND tenant_id = $2",
                )
                .bind(state.id)
                .bind(&event.tenant_id)
                .execute(&self.db)
                .await
                .map_err(|error| SalesError::Database(error.to_string()))?;
                Ok(Some(state))
            }
            _ => Ok(None),
        }
    }

    /// Returns the per-run report and, when the run hit a retryable
    /// deferral, the reason (the EVENT must be rescheduled in that case).
    async fn execute_rule(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: AutomationEventKind,
        ctx: &EventContext,
    ) -> Result<(TickReport, Option<String>), SalesError> {
        let mut report = TickReport::default();
        let trigger_kind = rule
            .trigger_config
            .as_ref()
            .and_then(|trigger| trigger.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("event");

        let Some(run) = self
            .get_or_create_run(rule, event, kind, trigger_kind)
            .await?
        else {
            report.runs_replayed = 1;
            return Ok((report, None));
        };
        report.runs_started = 1;

        let actions: Vec<Value> = rule
            .actions
            .as_ref()
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        if actions.is_empty() {
            self.finish_run(
                run.id,
                &event.tenant_id,
                "skipped",
                false,
                Some("no actions configured"),
                None,
            )
            .await?;
            report.runs_skipped = 1;
            return Ok((report, None));
        }

        let existing: HashMap<i32, ExistingAction> = sqlx::query_as::<_, ExistingAction>(
            "SELECT action_index, status, retryable, attempts FROM automation_run_actions \
             WHERE run_id = $1 AND tenant_id = $2",
        )
        .bind(run.id)
        .bind(&event.tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .into_iter()
        .map(|row| (row.action_index, row))
        .collect();

        let mut any_succeeded = false;
        let mut skipped_reasons: Vec<String> = Vec::new();
        let mut terminal_failure: Option<String> = None;
        let mut retryable_failure: Option<String> = None;

        for (index, action) in actions.iter().enumerate() {
            let index = index as i32;
            if let Some(previous) = existing.get(&index) {
                match previous.status.as_str() {
                    "succeeded" => {
                        any_succeeded = true;
                        continue;
                    }
                    "skipped" | "unsupported" => {
                        skipped_reasons.push(format!("action {index}"));
                        continue;
                    }
                    "failed" if !previous.retryable || previous.attempts >= MAX_ACTION_ATTEMPTS => {
                        terminal_failure =
                            Some(format!("action {index} previously failed terminally"));
                        break;
                    }
                    _ => {}
                }
            }

            let record = self
                .execute_action(rule, event, kind, ctx, run.id, index, action)
                .await;
            self.record_action(run.id, &event.tenant_id, index, action, &record)
                .await?;

            match record.status {
                "succeeded" => {
                    any_succeeded = true;
                    if record.is_enqueue() {
                        report.actions_enqueued += 1;
                    }
                }
                "skipped" | "unsupported" => skipped_reasons.push(format!("action {index}")),
                "failed" => {
                    let attempts_after = existing
                        .get(&index)
                        .map(|previous| previous.attempts + 1)
                        .unwrap_or(1);
                    if record.retryable && attempts_after < MAX_ACTION_ATTEMPTS {
                        retryable_failure = record
                            .error
                            .clone()
                            .or_else(|| Some(format!("action {index} failed (retryable)")));
                        break;
                    }
                    terminal_failure = record
                        .error
                        .clone()
                        .or_else(|| Some(format!("action {index} failed")));
                    break;
                }
                _ => {}
            }
        }

        if let Some(error) = retryable_failure {
            self.finish_run(run.id, &event.tenant_id, "failed", true, None, Some(&error))
                .await?;
            report.runs_failed = 1;
            return Ok((report, Some(error)));
        }
        if let Some(error) = terminal_failure {
            self.finish_run(
                run.id,
                &event.tenant_id,
                "failed",
                false,
                None,
                Some(&error),
            )
            .await?;
            report.runs_failed = 1;
            return Ok((report, None));
        }
        if any_succeeded {
            self.finish_run(run.id, &event.tenant_id, "succeeded", false, None, None)
                .await?;
            report.runs_succeeded = 1;
        } else {
            let reason = if skipped_reasons.is_empty() {
                "no actions executed".to_string()
            } else {
                format!("all actions skipped: {}", skipped_reasons.join(", "))
            };
            self.finish_run(
                run.id,
                &event.tenant_id,
                "skipped",
                false,
                Some(&reason),
                None,
            )
            .await?;
            report.runs_skipped = 1;
        }
        Ok((report, None))
    }

    async fn record_skipped_run(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: AutomationEventKind,
        skip_reason: &str,
        detail: &str,
    ) -> Result<(), SalesError> {
        let trigger_kind = rule
            .trigger_config
            .as_ref()
            .and_then(|trigger| trigger.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        sqlx::query(
            "INSERT INTO automation_runs \
             (automation_id, automation_name, tenant_id, trigger_kind, trigger_event_type, \
              trigger_event_key, source_event_id, status, skip_reason, finished_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'skipped', $8, NOW()) \
             ON CONFLICT (tenant_id, automation_id, trigger_event_key) DO NOTHING",
        )
        .bind(rule.id)
        .bind(&rule.name)
        .bind(&event.tenant_id)
        .bind(trigger_kind)
        .bind(kind.as_str())
        .bind(&event.event_key)
        .bind(event.id)
        .bind(format!("{skip_reason}: {detail}"))
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    /// Report an unsupported trigger kind ONCE per (rule, kind): the synthetic
    /// event key makes the run log itself the durable diagnosis.
    async fn record_unsupported_trigger(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: &str,
        reason: &str,
    ) -> Result<(), SalesError> {
        let key = format!("trigger.unsupported:{kind}");
        let inserted = sqlx::query(
            "INSERT INTO automation_runs \
             (automation_id, automation_name, tenant_id, trigger_kind, trigger_event_key, \
              source_event_id, status, skip_reason, finished_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'skipped', $7, NOW()) \
             ON CONFLICT (tenant_id, automation_id, trigger_event_key) DO NOTHING",
        )
        .bind(rule.id)
        .bind(&rule.name)
        .bind(&event.tenant_id)
        .bind(kind)
        .bind(&key)
        .bind(event.id)
        .bind(format!("unsupported trigger kind: {reason}"))
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        if inserted.rows_affected() > 0 {
            tracing::warn!(
                tenant_id = %event.tenant_id,
                automation_id = %rule.id,
                trigger_kind = %kind,
                "unsupported automation trigger kind reported in the run log"
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_run(
        &self,
        run_id: Uuid,
        tenant_id: &str,
        status: &str,
        retryable: bool,
        skip_reason: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), SalesError> {
        sqlx::query(
            "UPDATE automation_runs SET status = $2, retryable = $3, skip_reason = $4, \
             error = $5, finished_at = CASE WHEN $3 THEN NULL ELSE NOW() END, updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $6",
        )
        .bind(run_id)
        .bind(status)
        .bind(retryable)
        .bind(skip_reason)
        .bind(error)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    async fn record_action(
        &self,
        run_id: Uuid,
        tenant_id: &str,
        index: i32,
        action: &Value,
        record: &ActionRecord,
    ) -> Result<(), SalesError> {
        let action_type = action_type(action).unwrap_or("<missing>");
        sqlx::query(
            "INSERT INTO automation_run_actions \
             (run_id, tenant_id, action_index, action_type, status, reason, error, retryable, \
              attempts, message_id, queue_id, quota_event_id, detail, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $11, $12, NOW()) \
             ON CONFLICT (run_id, action_index) DO UPDATE SET \
               status = EXCLUDED.status, reason = EXCLUDED.reason, error = EXCLUDED.error, \
               retryable = EXCLUDED.retryable, \
               attempts = automation_run_actions.attempts + 1, \
               message_id = COALESCE(EXCLUDED.message_id, automation_run_actions.message_id), \
               queue_id = COALESCE(EXCLUDED.queue_id, automation_run_actions.queue_id), \
               quota_event_id = COALESCE(EXCLUDED.quota_event_id, automation_run_actions.quota_event_id), \
               detail = EXCLUDED.detail, updated_at = NOW()",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(index)
        .bind(action_type)
        .bind(record.status)
        .bind(&record.reason)
        .bind(&record.error)
        .bind(record.retryable)
        .bind(record.message_id)
        .bind(record.queue_id)
        .bind(record.quota_event_id)
        .bind(&record.detail)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    // -- Action execution --------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn execute_action(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: AutomationEventKind,
        ctx: &EventContext,
        run_id: Uuid,
        index: i32,
        action: &Value,
    ) -> ActionRecord {
        let Some(action_type) = action_type(action) else {
            return ActionRecord::unsupported("action has no 'type'");
        };
        let config = action
            .get("config")
            .filter(|config| config.is_object())
            .unwrap_or(action);

        match action_type {
            "send_email" => {
                self.execute_send_email(rule, event, kind, ctx, run_id, index, config)
                    .await
            }
            "add_tag" => self.execute_tag_action(ctx, event, config, true).await,
            "remove_tag" => self.execute_tag_action(ctx, event, config, false).await,
            "add_to_list" => self.execute_list_action(ctx, event, config, true).await,
            "remove_from_list" => self.execute_list_action(ctx, event, config, false).await,
            "webhook" => {
                self.execute_webhook_action(rule, event, run_id, index, config)
                    .await
            }
            other => ActionRecord::unsupported(format!(
                "unsupported action kind '{other}' — the action was not executed"
            )),
        }
    }

    /// THE send path: admission → sender-domain gate → one transaction that
    /// writes `messages` + `email_queue` (the action record follows; the
    /// derived message idempotency key closes the bookkeeping window).
    #[allow(clippy::too_many_arguments)]
    async fn execute_send_email(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        kind: AutomationEventKind,
        ctx: &EventContext,
        run_id: Uuid,
        index: i32,
        config: &Value,
    ) -> ActionRecord {
        // 1. Recipient — explicit `config.to` for addressable sends, else the
        //    triggering entity's address (contact email; the inbound sender
        //    for a reply).
        let recipient = match config
            .get("to")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => value.to_string(),
            None => match kind {
                AutomationEventKind::MessageReceived => match ctx.from_email.as_deref() {
                    Some(email) => email.to_string(),
                    None => return ActionRecord::skipped("no_recipient"),
                },
                _ => match ctx.contact.as_ref() {
                    Some(contact) => contact.email.clone(),
                    None => return ActionRecord::skipped("trigger_entity_missing"),
                },
            },
        };
        if recipient.contains(',')
            || recipient.contains('\n')
            || recipient.contains('\r')
            || !recipient.contains('@')
        {
            return ActionRecord::skipped("invalid_recipient");
        }

        // 2. Marketing sends only go to subscribed contacts (the delivery
        //    pipeline and admission enforce suppression separately; this is
        //    the contact-level gate).
        if kind != AutomationEventKind::MessageReceived {
            match ctx.contact.as_ref() {
                Some(contact) if contact.status == "subscribed" => {}
                Some(_) => return ActionRecord::skipped("contact_not_subscribed"),
                None => return ActionRecord::skipped("trigger_entity_missing"),
            }
        }

        // 3. Sender + template (both explicit: an automation send never
        //    silently borrows a default identity).
        let Some(from) = config
            .get("from")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return ActionRecord::skipped("missing_from");
        };
        let Some(template_id) = config
            .get("template_id")
            .or_else(|| config.get("template"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return ActionRecord::skipped("missing_template_id");
        };

        let template = match fetch_template(&self.db, &event.tenant_id, template_id).await {
            Ok(template) => template,
            Err(SalesError::InvalidInput(_)) => return ActionRecord::skipped("template_not_found"),
            Err(error) => return ActionRecord::failed_retryable(error.to_string()),
        };
        let rendered = render_template(&template, ctx);

        // 4. Admission — the ONE shared gate, explicit category.
        let category = kind.send_category();
        let quota_identity = format!("auto-run:{run_id}:{index}");
        let admission = match self
            .admission
            .admit(SendAdmissionRequest {
                tenant_id: &event.tenant_id,
                meter: AdmissionMeter::FilteredRecipients(std::slice::from_ref(&recipient)),
                idempotency_key: Some(&quota_identity),
                idempotency_item: None,
                category: Some(category),
            })
            .await
        {
            Ok(admission) => admission,
            Err(SendAdmissionError::Suppressed(_)) => {
                return ActionRecord::skipped("suppressed_recipient");
            }
            Err(SendAdmissionError::InvalidCategory { .. }) => {
                // Server-owned constant failed validation: a programming
                // error. Terminal, loud, never a retry loop.
                return ActionRecord::failed_terminal("invalid server-owned message category");
            }
            Err(SendAdmissionError::QuotaExceeded) => {
                return ActionRecord::failed_retryable("quota_exceeded");
            }
            Err(SendAdmissionError::MeteringUnavailable(error)) => {
                return ActionRecord::failed_retryable(format!("metering_unavailable: {error}"));
            }
            Err(SendAdmissionError::SuppressionUnavailable(error)) => {
                return ActionRecord::failed_retryable(format!(
                    "suppression_lookup_unavailable: {error}"
                ));
            }
        };
        let quota_event_id = admission.event_id();
        let admitted_category = admission.category().to_string();

        // 5. Enqueue + action record. The `messages` idempotency key is
        //    derived from (run, action index), so a crash/retry around this
        //    transaction can never double-send.
        let idempotency_key = format!("autoact:{run_id}:{index}");
        let message_id = Uuid::new_v4();
        let queue_id = Uuid::new_v4();
        let created_at = Utc::now();
        let metadata = json!({
            "source": "automations",
            "automation_id": rule.id.to_string(),
            "automation_name": rule.name,
            "run_id": run_id.to_string(),
            "action_index": index,
            "trigger_event_key": event.event_key,
            "quota_event_id": quota_event_id.to_string(),
        });

        let mut tx = match self.db.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                let _ = admission.rollback().await;
                return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
            }
        };

        let domain_id = match resolve_sender_domain_id(&mut tx, &event.tenant_id, from).await {
            Ok(Some(domain_id)) => domain_id,
            Ok(None) => {
                drop(tx);
                let _ = admission.rollback().await;
                return ActionRecord::skipped("sender_domain_not_ready");
            }
            Err(error) => {
                drop(tx);
                let _ = admission.rollback().await;
                return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
            }
        };

        let inserted = sqlx::query(
            "INSERT INTO messages \
             (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, \
              html_body, text_body, status, tags, metadata, scheduled_at, created_at, \
              idempotency_key, message_category) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10, $11, NULL, \
                     $12, $13, $14) \
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(message_id)
        .bind(&event.tenant_id)
        .bind(from)
        .bind(json!([recipient]))
        .bind(None::<Value>)
        .bind(None::<Value>)
        .bind(&rendered.subject)
        .bind(&rendered.html)
        .bind(&rendered.text)
        .bind(json!(rendered.tags))
        .bind(&metadata)
        .bind(created_at)
        .bind(&idempotency_key)
        .bind(&admitted_category)
        .execute(&mut *tx)
        .await;

        let inserted = match inserted {
            Ok(inserted) => inserted,
            Err(error) => {
                drop(tx);
                let _ = admission.rollback().await;
                return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
            }
        };

        if inserted.rows_affected() == 0 {
            // This exact action already enqueued in a previous attempt (the
            // bookkeeping-loss window): reuse the existing message.
            let existing: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
                "SELECT m.id, (SELECT q.id FROM email_queue q WHERE q.message_id = m.id LIMIT 1) \
                 FROM messages m WHERE m.tenant_id = $1 AND m.idempotency_key = $2",
            )
            .bind(&event.tenant_id)
            .bind(&idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
            if let Err(error) = tx.commit().await {
                let _ = admission.rollback().await;
                return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
            }
            admission.commit();
            let (existing_message_id, existing_queue_id) = existing.unwrap_or((message_id, None));
            return ActionRecord::succeeded(
                existing_message_id,
                existing_queue_id,
                quota_event_id,
                json!({ "category": category, "duplicate": true, "recipient": recipient }),
            );
        }

        let queued = sqlx::query(
            "INSERT INTO email_queue \
             (id, message_id, tenant_id, domain_id, from_address, to_addresses, subject, \
              \"from\", \"to\", html, text, tags, metadata, headers, scheduled_at, priority, \
              status, created_at, updated_at, message_category) \
             VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, ARRAY[$6], $7, $5, $6, $8, $9, \
                     $10, $11, $12, NULL, 5, 'pending', $13, $13, $14)",
        )
        .bind(queue_id)
        .bind(message_id)
        .bind(&event.tenant_id)
        .bind(&domain_id)
        .bind(from)
        .bind(&recipient)
        .bind(&rendered.subject)
        .bind(&rendered.html)
        .bind(&rendered.text)
        .bind(&rendered.tags)
        .bind(&metadata)
        .bind(json!({}))
        .bind(created_at)
        .bind(&admitted_category)
        .execute(&mut *tx)
        .await;

        if let Err(error) = queued {
            drop(tx);
            let _ = admission.rollback().await;
            return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
        }

        if let Err(error) = tx.commit().await {
            let _ = admission.rollback().await;
            return ActionRecord::failed_retryable(format!("enqueue_failed: {error}"));
        }
        admission.commit();

        ActionRecord::succeeded(
            message_id,
            Some(queue_id),
            quota_event_id,
            json!({ "category": category, "duplicate": false, "recipient": recipient }),
        )
    }

    async fn execute_tag_action(
        &self,
        ctx: &EventContext,
        event: &DueEvent,
        config: &Value,
        add: bool,
    ) -> ActionRecord {
        let Some(contact) = ctx.contact.as_ref() else {
            return ActionRecord::skipped("no_contact_context");
        };
        let mut tags: Vec<String> = Vec::new();
        if let Some(tag) = config.get("tag").and_then(Value::as_str) {
            let tag = tag.trim();
            if !tag.is_empty() {
                tags.push(tag.to_string());
            }
        }
        if let Some(items) = config.get("tags").and_then(Value::as_array) {
            for item in items {
                match item.as_str().map(str::trim).filter(|tag| !tag.is_empty()) {
                    Some(tag) => tags.push(tag.to_string()),
                    None => return ActionRecord::skipped("invalid_tag"),
                }
            }
        }
        if tags.is_empty() {
            return ActionRecord::skipped("missing_tag");
        }
        tags.truncate(MAX_DETAIL_ITEMS);
        let payload = json!(tags);

        let mut tx = match self.db.begin().await {
            Ok(tx) => tx,
            Err(error) => return ActionRecord::failed_retryable(error.to_string()),
        };
        // Executor-driven contact writes must not re-emit automation events,
        // or a tag rule could feed itself (the schema trigger honours this
        // transaction-local flag).
        if let Err(error) =
            sqlx::query("SELECT set_config('apexmail.automation_write', 'on', true)")
                .execute(&mut *tx)
                .await
        {
            return ActionRecord::failed_retryable(error.to_string());
        }
        let statement = if add {
            "UPDATE contacts SET tags = ( \
                 SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb) \
                 FROM jsonb_array_elements_text(COALESCE(tags, '[]'::jsonb) || $3::jsonb) AS t(value) \
             ), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2"
        } else {
            "UPDATE contacts SET tags = ( \
                 SELECT COALESCE(jsonb_agg(value), '[]'::jsonb) \
                 FROM jsonb_array_elements_text(COALESCE(tags, '[]'::jsonb)) AS t(value) \
                 WHERE NOT ($3::jsonb @> jsonb_build_array(value)) \
             ), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2"
        };
        let result = sqlx::query(statement)
            .bind(contact.id)
            .bind(&event.tenant_id)
            .bind(&payload)
            .execute(&mut *tx)
            .await;
        match result {
            Ok(done) if done.rows_affected() == 0 => ActionRecord::skipped("contact_not_found"),
            Ok(_) => match tx.commit().await {
                Ok(()) => ActionRecord::effect(format!(
                    "{} tags {}",
                    if add { "added" } else { "removed" },
                    tags.join(",")
                )),
                Err(error) => ActionRecord::failed_retryable(error.to_string()),
            },
            Err(error) => ActionRecord::failed_retryable(error.to_string()),
        }
    }

    async fn execute_list_action(
        &self,
        ctx: &EventContext,
        event: &DueEvent,
        config: &Value,
        add: bool,
    ) -> ActionRecord {
        let Some(contact) = ctx.contact.as_ref() else {
            return ActionRecord::skipped("no_contact_context");
        };
        let Some(list_ref) = config
            .get("list_id")
            .or_else(|| config.get("list"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return ActionRecord::skipped("missing_list_id");
        };

        let list_id: Option<Uuid> = match sqlx::query_scalar(
            "SELECT id FROM lists WHERE tenant_id = $1 AND (id::text = $2 OR name = $2) LIMIT 1",
        )
        .bind(&event.tenant_id)
        .bind(list_ref)
        .fetch_optional(&self.db)
        .await
        {
            Ok(list_id) => list_id,
            Err(error) => return ActionRecord::failed_retryable(error.to_string()),
        };
        let Some(list_id) = list_id else {
            return ActionRecord::skipped("list_not_found");
        };

        let result = if add {
            sqlx::query(
                "INSERT INTO list_subscribers (list_id, contact_id, status, created_at) \
                 VALUES ($1, $2, 'active', NOW()) \
                 ON CONFLICT (list_id, contact_id) DO UPDATE SET status = 'active'",
            )
            .bind(list_id)
            .bind(contact.id)
            .execute(&self.db)
            .await
        } else {
            sqlx::query("DELETE FROM list_subscribers WHERE list_id = $1 AND contact_id = $2")
                .bind(list_id)
                .bind(contact.id)
                .execute(&self.db)
                .await
        };
        match result {
            Ok(_) => ActionRecord::effect(format!(
                "{} list {list_id}",
                if add { "added to" } else { "removed from" }
            )),
            Err(error) => ActionRecord::failed_retryable(error.to_string()),
        }
    }

    async fn execute_webhook_action(
        &self,
        rule: &RuleRow,
        event: &DueEvent,
        run_id: Uuid,
        index: i32,
        config: &Value,
    ) -> ActionRecord {
        let target = config
            .get("webhook_id")
            .or_else(|| config.get("url"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(target) = target else {
            return ActionRecord::skipped("missing_webhook_target");
        };

        let webhook_id: Option<String> = match sqlx::query_scalar(
            "SELECT id FROM webhooks WHERE tenant_id = $1 AND enabled = true \
             AND (id = $2 OR url = $2) LIMIT 1",
        )
        .bind(&event.tenant_id)
        .bind(target)
        .fetch_optional(&self.db)
        .await
        {
            Ok(webhook_id) => webhook_id,
            Err(error) => return ActionRecord::failed_retryable(error.to_string()),
        };
        let Some(webhook_id) = webhook_id else {
            return ActionRecord::skipped("webhook_not_found");
        };

        let event_type = config
            .get("event_type")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 100)
            .unwrap_or("automation.action");

        let payload = json!({
            "id": format!("evt_{}", Uuid::new_v4().simple()),
            "type": event_type,
            "tenantId": event.tenant_id,
            "timestamp": Utc::now().to_rfc3339(),
            "data": {
                "automation_id": rule.id.to_string(),
                "automation_name": rule.name,
                "run_id": run_id.to_string(),
                "action_index": index,
                "trigger_event_key": event.event_key,
            },
        });
        let queue_id = format!("whj_{}", Uuid::new_v4().simple());

        // The existing worker webhook processor owns delivery (retries,
        // circuit breaker, SSRF guard): the action only enqueues.
        let result = sqlx::query(
            "INSERT INTO webhook_queue \
             (id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', 1, NOW())",
        )
        .bind(&queue_id)
        .bind(&webhook_id)
        .bind(&event.tenant_id)
        .bind(event_type)
        .bind(&payload)
        .execute(&self.db)
        .await;

        match result {
            Ok(_) => ActionRecord::effect(format!("queued webhook {webhook_id}")),
            Err(error) => ActionRecord::failed_retryable(error.to_string()),
        }
    }

    // -- Event settlement --------------------------------------------------

    async fn defer_event(&self, event: &DueEvent, reason: &str) -> Result<(), SalesError> {
        if event.attempts < event.max_attempts {
            sqlx::query(
                "UPDATE automation_trigger_events SET status = 'pending', \
                 available_at = NOW() + make_interval(secs => $2::double precision), \
                 locked_until = NULL, locked_by = NULL, last_error = $3, updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(event.id)
            .bind(backoff_secs(event.attempts))
            .bind(format!("retryable execution failure: {reason}"))
            .execute(&self.db)
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        } else {
            sqlx::query(
                "UPDATE automation_trigger_events SET status = 'failed', locked_until = NULL, \
                 locked_by = NULL, last_error = $2, processed_at = NOW(), updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(event.id)
            .bind(format!("retry budget exhausted: {reason}"))
            .execute(&self.db)
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        }
        Ok(())
    }

    async fn settle_event(&self, event: &DueEvent, outcome: &TickReport) -> Result<(), SalesError> {
        if outcome.events_deferred > 0 {
            // defer_event already rescheduled (or failed) the row.
            return Ok(());
        }
        let status = if outcome.events_failed > 0 {
            "failed"
        } else {
            "processed"
        };
        sqlx::query(
            "UPDATE automation_trigger_events SET status = $2, locked_until = NULL, \
             locked_by = NULL, last_error = NULL, processed_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(event.id)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(())
    }

    async fn prune_settled_events(&self) -> Result<u64, SalesError> {
        let deleted = sqlx::query(
            "DELETE FROM automation_trigger_events WHERE id IN ( \
                 SELECT id FROM automation_trigger_events \
                 WHERE status IN ('processed', 'failed') \
                   AND updated_at < NOW() - make_interval(days => $1) \
                 ORDER BY updated_at LIMIT $2 \
             )",
        )
        .bind(EVENT_RETENTION_DAYS)
        .bind(PRUNE_BATCH)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(deleted.rows_affected())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn action_type(action: &Value) -> Option<&str> {
    action
        .get("type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn backoff_secs(attempts: i32) -> f64 {
    let attempts = attempts.clamp(1, 120) as f64;
    (30.0 * attempts * attempts).min(3600.0)
}

/// `trigger_config.filters.tags` semantics:
/// * created/updated — the contact must carry ALL filter tags;
/// * tag_added — at least one ADDED tag must be in the filter (the filter
///   names the tag that fires the rule).
fn trigger_filter_matches(
    spec: &TriggerSpec,
    ctx: &EventContext,
    kind: AutomationEventKind,
) -> bool {
    if spec.filter_tags.is_empty() {
        return true;
    }
    match kind {
        AutomationEventKind::ContactTagAdded => spec.filter_tags.iter().any(|tag| {
            ctx.tags_added
                .iter()
                .any(|added| added.eq_ignore_ascii_case(tag))
        }),
        _ => {
            let Some(contact) = ctx.contact.as_ref() else {
                return false;
            };
            spec.filter_tags.iter().all(|tag| {
                contact
                    .tags
                    .iter()
                    .any(|actual| actual.eq_ignore_ascii_case(tag))
            })
        }
    }
}

struct RenderedTemplate {
    subject: String,
    html: Option<String>,
    text: Option<String>,
    tags: Vec<String>,
}

/// Minimal, HTML-escaped interpolation for the variables the product
/// templates use. Unknown `{{...}}` placeholders are left untouched (the
/// delivery pipeline substitutes `{{unsubscribe_url}}` itself for
/// non-preference-exempt categories, which automation mail always is).
fn render_template(template: &TemplateContent, ctx: &EventContext) -> RenderedTemplate {
    let email = ctx
        .contact
        .as_ref()
        .map(|contact| contact.email.clone())
        .or_else(|| ctx.from_email.clone())
        .unwrap_or_default();
    let name = ctx
        .contact
        .as_ref()
        .and_then(|contact| contact.name.clone())
        .unwrap_or_default();
    let first_name = name
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    let html_vars: Vec<(&str, String)> = vec![
        ("email", escape_html(&email)),
        ("name", escape_html(&name)),
        ("first_name", escape_html(&first_name)),
    ];
    let text_vars: Vec<(&str, String)> =
        vec![("email", email), ("name", name), ("first_name", first_name)];

    RenderedTemplate {
        subject: apply_vars(&template.subject, &text_vars),
        html: template
            .html_body
            .as_deref()
            .map(|body| apply_vars(body, &html_vars)),
        text: template
            .text_body
            .as_deref()
            .map(|body| apply_vars(body, &text_vars)),
        tags: vec!["automation".to_string()],
    }
}

fn apply_vars(body: &str, vars: &[(&str, String)]) -> String {
    let mut out = body.to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
    }
    out
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// SES/SMTP transport gate — identical semantics to the REST/sales paths.
fn ses_transport_enabled() -> bool {
    apexmail_lib::transport::email_transport_is_ses(
        std::env::var("EMAIL_TRANSPORT_TYPE").ok().as_deref(),
    )
}

fn sender_domain(from: &str) -> Option<String> {
    from.rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

/// Ready sender-domain resolution with a row lock held through the queue
/// insert — the exact SQL the REST and sales paths use.
async fn resolve_sender_domain_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    from: &str,
) -> Result<Option<String>, sqlx::Error> {
    let Some(sender_domain) = sender_domain(from) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT id::text FROM domains
                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                     AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 LIMIT 1 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
    .bind(ses_transport_enabled())
    .fetch_optional(&mut **tx)
    .await
}
