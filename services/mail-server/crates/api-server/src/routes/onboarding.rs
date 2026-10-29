//! The tenant onboarding state machine (`GET /v1/onboarding`, migration 277).
//!
//! Sixth external audit #15 (half A): a new tenant walks
//! `invited → configuring_domain → verifying_dns → sending_ready → active`,
//! with `blocked` absorbing — and until now no table, column or route
//! recorded that walk, so a stalled signup and a fully warmed sender were
//! indistinguishable rows in `tenants`.
//!
//! * [`advance`] is the PURE machine: an exhaustive [`LEGAL`] table over
//!   (state, event, next) decides every step. Re-receiving an event the
//!   machine has already absorbed is an idempotent no-op (`Ok(current)`,
//!   no database write), anything else is the typed
//!   [`OnboardingError::IllegalTransition`], and blocking a blocked tenant
//!   is [`OnboardingError::AlreadyBlocked`].
//! * [`advance_persisted`] is the optimistic write half: the UPDATE carries
//!   `WHERE id = $tenant AND onboarding_state = $expected`, so two
//!   concurrent advancements cannot interleave — the loser sees 0 rows and
//!   gets [`OnboardingError::Conflict`].
//! * [`attempt_onboarding_event`] is the hook the domains routes call:
//!   read → advance → persist, with EVERY error logged (`tracing::warn`)
//!   and swallowed as `Ok(())`. The create/verify that already succeeded
//!   must never fail because onboarding bookkeeping did not.
//! * `GET /v1/onboarding` answers `{state, nextAction}` for the
//!   AUTHENTICATED tenant — pinned by the principal like every other `/v1/*`
//!   surface, never by a request parameter.
//!
//! The `Block`/`Unblock` pair keeps its history in `tenants.onboarding_note`
//! (JSON `{"prior": "..."}`): `Block` records the state it interrupted so
//! `Unblock` restores it (`invited` when nothing was recorded). The pure
//! [`advance`] cannot read that note — it applies that default — and
//! [`advance_persisted`] substitutes the recorded prior; the tests pin both
//! halves.
//!
//! Scope: the owner/admin wildcard (`require_scopes(&auth, &["*"])`), the
//! same gate as the settings surface; the API-key scope registry
//! (`routes::auth`) mints no narrower scope for workspace-setup state.
//!
//! Control-plane read: `GET /v1/admin/tenants/:id/onboarding` would live in
//! `routes::admin::tenants`, whose files are outside this pass's ownership,
//! and a `/v1/admin/...` path must ride the admin router's system-tenant
//! gate — never this module's tenant router. The operator read is therefore
//! deliberately NOT mounted here; the separate tenant route above is the
//! surface this half ships.
//!
//! Events wired in this pass — exactly two hooks, both in `routes::domains`:
//! [`OnboardingEvent::DomainCreated`] after a successful create, and
//! [`OnboardingEvent::DomainVerified`] after a verification that reports
//! `verified`. The remaining events (`DnsLookup`, `FirstSendObserved`,
//! `Block`, `Unblock`) are accepted by the machine for the surfaces that
//! will emit them; nothing else is hooked here.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_onboarding))
}

// ─── Types ─────────────────────────────────────────────────────

/// The six states of the onboarding walk (migration 277's CHECK vocabulary,
/// verbatim). Serde is snake_case, exactly `onboarding_state`'s stored text,
/// so the wire answer, the column and the enum can never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingState {
    Invited,
    ConfiguringDomain,
    VerifyingDns,
    SendingReady,
    Active,
    Blocked,
}

impl OnboardingState {
    /// Every state, in walk order (`blocked` is the absorbing extra).
    pub const ALL: [OnboardingState; 6] = [
        OnboardingState::Invited,
        OnboardingState::ConfiguringDomain,
        OnboardingState::VerifyingDns,
        OnboardingState::SendingReady,
        OnboardingState::Active,
        OnboardingState::Blocked,
    ];

    /// The stored/wire text — the exact strings migration 277's CHECK admits.
    pub fn as_str(self) -> &'static str {
        match self {
            OnboardingState::Invited => "invited",
            OnboardingState::ConfiguringDomain => "configuring_domain",
            OnboardingState::VerifyingDns => "verifying_dns",
            OnboardingState::SendingReady => "sending_ready",
            OnboardingState::Active => "active",
            OnboardingState::Blocked => "blocked",
        }
    }

    /// Parse a stored value; `None` for anything outside the vocabulary
    /// (only reachable through a hand-edited row — the CHECK is the
    /// backstop, and an unknown value must be an honest error, not a
    /// silently invented state).
    pub fn parse(raw: &str) -> Option<OnboardingState> {
        match raw {
            "invited" => Some(OnboardingState::Invited),
            "configuring_domain" => Some(OnboardingState::ConfiguringDomain),
            "verifying_dns" => Some(OnboardingState::VerifyingDns),
            "sending_ready" => Some(OnboardingState::SendingReady),
            "active" => Some(OnboardingState::Active),
            "blocked" => Some(OnboardingState::Blocked),
            _ => None,
        }
    }
}

impl std::fmt::Display for OnboardingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The machine's inputs. `Block` carries the operator's reason; it never
/// changes WHERE the machine goes (the [`LEGAL`] table is keyed by
/// [`EventKind`]), only what the caller may log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingEvent {
    /// A sending domain row was created (the domains create hook).
    DomainCreated,
    /// The tenant asked for its DNS records (configuring → verifying).
    DnsLookup,
    /// Verification reported the domain `verified` (the domains verify hook).
    DomainVerified,
    /// The tenant's first send was observed (verifying → active).
    FirstSendObserved,
    /// Absorb into `blocked`, recording the prior state in `onboarding_note`.
    Block(String),
    /// Leave `blocked`, restoring the recorded prior state.
    Unblock,
}

/// The payload-free identity of an event: what the [`LEGAL`] table keys on,
/// so `Block("a reason")` and `Block("another reason")` are the same edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    DomainCreated,
    DnsLookup,
    DomainVerified,
    FirstSendObserved,
    Block,
    Unblock,
}

impl OnboardingEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            OnboardingEvent::DomainCreated => EventKind::DomainCreated,
            OnboardingEvent::DnsLookup => EventKind::DnsLookup,
            OnboardingEvent::DomainVerified => EventKind::DomainVerified,
            OnboardingEvent::FirstSendObserved => EventKind::FirstSendObserved,
            OnboardingEvent::Block(_) => EventKind::Block,
            OnboardingEvent::Unblock => EventKind::Unblock,
        }
    }
}

impl std::fmt::Display for OnboardingEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnboardingEvent::DomainCreated => f.write_str("domain_created"),
            OnboardingEvent::DnsLookup => f.write_str("dns_lookup"),
            OnboardingEvent::DomainVerified => f.write_str("domain_verified"),
            OnboardingEvent::FirstSendObserved => f.write_str("first_send_observed"),
            OnboardingEvent::Block(reason) if reason.is_empty() => f.write_str("block"),
            OnboardingEvent::Block(reason) => write!(f, "block({reason})"),
            OnboardingEvent::Unblock => f.write_str("unblock"),
        }
    }
}

/// Everything the machine can answer. `IllegalTransition` and
/// `AlreadyBlocked` come from the pure table; `Conflict` from the optimistic
/// write; `Database` from persistence; the two row-shape variants only ever
/// surface inside [`attempt_onboarding_event`], which logs them.
#[derive(Debug, thiserror::Error)]
pub enum OnboardingError {
    #[error("illegal onboarding transition: {from} + {event}")]
    IllegalTransition {
        from: OnboardingState,
        event: OnboardingEvent,
    },

    #[error("onboarding is already blocked")]
    AlreadyBlocked,

    #[error("onboarding state changed concurrently: expected {expected}")]
    Conflict { expected: OnboardingState },

    #[error("no tenants row carries this onboarding machine")]
    MissingTenant,

    #[error("unknown onboarding_state in the database: {0:?}")]
    UnknownState(String),

    #[error("onboarding persistence failed: {0}")]
    Database(#[from] sqlx::Error),
}

/// `GET /v1/onboarding`'s answer: where the tenant is and the literal next
/// action for that state (`null` once active — the walk is done).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingStatusResponse {
    pub state: OnboardingState,
    pub next_action: Option<&'static str>,
}

/// The literal per-state next action. `active` is `null` on purpose: a
/// finished onboarding has nothing to instruct, and inventing busy-work
/// there would be fiction.
fn next_action(state: OnboardingState) -> Option<&'static str> {
    match state {
        OnboardingState::Invited => Some("create your first sending domain"),
        OnboardingState::ConfiguringDomain => Some("request the DNS records"),
        OnboardingState::VerifyingDns => Some("run domain verification"),
        OnboardingState::SendingReady => Some("your first send activates this account"),
        OnboardingState::Active => None,
        OnboardingState::Blocked => Some("contact support"),
    }
}

// ─── The pure machine ──────────────────────────────────────────

/// The EXHAUSTIVE edge table: 4 progression edges + 5 `Block` edges (every
/// state but `blocked`) + the `Unblock` restore + 7 idempotent no-ops
/// (edges whose `next` equals their `from`, i.e. "legal to re-receive").
/// Anything absent from this table is an [`OnboardingError::IllegalTransition`]
/// — the matrix test sweeps ALL 6×6 state×event pairs and pins each outcome.
///
/// `blocked + Unblock` maps to its default (`invited`); the persisted half
/// substitutes the prior state `Block` recorded in `onboarding_note`.
// One edge per line: the table IS the specification, wrapped 3-line tuples
// would make it unreadable (the repo's `#[rustfmt::skip]` precedent).
#[rustfmt::skip]
pub const LEGAL: [(OnboardingState, OnboardingEvent, OnboardingState); 17] = [
    // The walk: invited → configuring_domain → verifying_dns → sending_ready → active.
    (OnboardingState::Invited, OnboardingEvent::DomainCreated, OnboardingState::ConfiguringDomain),
    (OnboardingState::ConfiguringDomain, OnboardingEvent::DnsLookup, OnboardingState::VerifyingDns),
    (OnboardingState::VerifyingDns, OnboardingEvent::DomainVerified, OnboardingState::SendingReady),
    (OnboardingState::SendingReady, OnboardingEvent::FirstSendObserved, OnboardingState::Active),
    // Block is legal from EVERY state (absorbing); the reason is carried on
    // the event but the edge is keyed by EventKind, so the table entry holds
    // the empty placeholder reason.
    (OnboardingState::Invited, OnboardingEvent::Block(String::new()), OnboardingState::Blocked),
    (OnboardingState::ConfiguringDomain, OnboardingEvent::Block(String::new()), OnboardingState::Blocked),
    (OnboardingState::VerifyingDns, OnboardingEvent::Block(String::new()), OnboardingState::Blocked),
    (OnboardingState::SendingReady, OnboardingEvent::Block(String::new()), OnboardingState::Blocked),
    (OnboardingState::Active, OnboardingEvent::Block(String::new()), OnboardingState::Blocked),
    // Unblock restores the recorded prior (default invited, applied by the
    // persisted half).
    (OnboardingState::Blocked, OnboardingEvent::Unblock, OnboardingState::Invited),
    // Idempotent no-ops: legal to re-receive, `next == from`, and
    // `advance_persisted` performs NO database write for them.
    (OnboardingState::ConfiguringDomain, OnboardingEvent::DomainCreated, OnboardingState::ConfiguringDomain),
    (OnboardingState::VerifyingDns, OnboardingEvent::DomainCreated, OnboardingState::VerifyingDns),
    (OnboardingState::SendingReady, OnboardingEvent::DomainCreated, OnboardingState::SendingReady),
    (OnboardingState::Active, OnboardingEvent::DomainCreated, OnboardingState::Active),
    (OnboardingState::SendingReady, OnboardingEvent::DomainVerified, OnboardingState::SendingReady),
    (OnboardingState::Active, OnboardingEvent::DomainVerified, OnboardingState::Active),
    (OnboardingState::Active, OnboardingEvent::FirstSendObserved, OnboardingState::Active),
];

/// The PURE transition: no I/O, no clock, no pool. `Ok(current)` with no
/// further effect is the idempotent no-op; an edge missing from [`LEGAL`] is
/// [`OnboardingError::IllegalTransition`]; blocking a blocked tenant is the
/// typed [`OnboardingError::AlreadyBlocked`] (not "illegal" — it is a
/// redundant fact, not a wrong move).
pub fn advance(
    current: OnboardingState,
    event: OnboardingEvent,
) -> Result<OnboardingState, OnboardingError> {
    // Checked before the table so the typed answer wins over the generic
    // one: `blocked + Block` is deliberately NOT an edge.
    if current == OnboardingState::Blocked && event.kind() == EventKind::Block {
        return Err(OnboardingError::AlreadyBlocked);
    }

    LEGAL
        .iter()
        .find(|(state, legal_event, _)| *state == current && legal_event.kind() == event.kind())
        .map(|(_, _, next)| *next)
        .ok_or_else(|| OnboardingError::IllegalTransition {
            from: current,
            event,
        })
}

// ─── Persistence ───────────────────────────────────────────────

/// Read the tenant's current state. `None` = no tenants row (only reachable
/// when the row vanished between authentication and this call).
async fn read_state(
    pool: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<Option<OnboardingState>, OnboardingError> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT onboarding_state FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;
    raw.map(|raw| OnboardingState::parse(&raw).ok_or_else(|| OnboardingError::UnknownState(raw)))
        .transpose()
}

/// The prior state `Block` recorded in `onboarding_note`
/// (`JSON {"prior": "..."}`), or `invited` when nothing usable was recorded
/// — the machine's documented default for an unblock with no history.
async fn recorded_prior(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    expected_state: OnboardingState,
) -> Result<OnboardingState, OnboardingError> {
    // Pinned by BOTH id and state: a row that moved since the caller read it
    // must not hand its note to a stale unblock (the UPDATE below would
    // conflict anyway; this keeps the restored value honest too).
    let note: Option<String> = sqlx::query_scalar(
        "SELECT onboarding_note FROM tenants WHERE id = $1 AND onboarding_state = $2",
    )
    .bind(tenant_id)
    .bind(expected_state.as_str())
    .fetch_optional(pool)
    .await?;

    Ok(note
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|value| {
            value
                .get("prior")
                .and_then(|prior| prior.as_str())
                .and_then(OnboardingState::parse)
        })
        .unwrap_or(OnboardingState::Invited))
}

/// The optimistic write half: advance from `expected_state` and persist, in
/// ONE conditional UPDATE —
/// `WHERE id = $tenant AND onboarding_state = $expected` — so a concurrent
/// advancement cannot be overwritten: 0 rows affected is
/// [`OnboardingError::Conflict`].
///
/// `onboarding_note` follows the event: `Block` records the interrupted
/// state as JSON `{"prior": "..."}`, `Unblock` consumes (clears) it, every
/// other event leaves it untouched. An idempotent no-op (`next == expected`)
/// performs NO write — but it still verifies the caller's expectation with a
/// read, so a stale caller gets the same `Conflict` instead of a false OK.
pub async fn advance_persisted(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    expected_state: OnboardingState,
    event: OnboardingEvent,
) -> Result<OnboardingState, OnboardingError> {
    // Bookkeeping derived from the event BEFORE the machine consumes it.
    let (note_set, note_value): (bool, Option<String>) = match &event {
        OnboardingEvent::Block(_) => (
            true,
            Some(serde_json::json!({ "prior": expected_state.as_str() }).to_string()),
        ),
        OnboardingEvent::Unblock => (true, None),
        _ => (false, None),
    };
    let restores_prior = matches!(event, OnboardingEvent::Unblock);

    // The PURE machine decides legality first — an illegal event never
    // touches the database.
    let next = advance(expected_state, event)?;

    // Unblock: the pure machine can only apply its default (`invited`), it
    // has no note to read; persistence substitutes the recorded prior.
    let next = if restores_prior {
        recorded_prior(pool, tenant_id, expected_state).await?
    } else {
        next
    };

    if next == expected_state {
        // Idempotent no-op: nothing to write, but the caller's expectation
        // must still hold — 0 rows means the state moved underneath it.
        let held: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM tenants WHERE id = $1 AND onboarding_state = $2")
                .bind(tenant_id)
                .bind(expected_state.as_str())
                .fetch_optional(pool)
                .await?;
        return if held.is_some() {
            Ok(next)
        } else {
            Err(OnboardingError::Conflict {
                expected: expected_state,
            })
        };
    }

    let result = sqlx::query(
        "UPDATE tenants \
         SET onboarding_state = $1, \
             onboarding_updated_at = NOW(), \
             onboarding_note = CASE WHEN $2 THEN $3::text ELSE onboarding_note END \
         WHERE id = $4 AND onboarding_state = $5",
    )
    .bind(next.as_str())
    .bind(note_set)
    .bind(note_value)
    .bind(tenant_id)
    .bind(expected_state.as_str())
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(OnboardingError::Conflict {
            expected: expected_state,
        });
    }

    Ok(next)
}

/// The domains hooks' entry point: read the current state, advance,
/// persist — and turn ANY error (a lost race, an illegal event, a dead
/// database) into `tracing::warn` + `Ok(())`. The create/verify that
/// already SUCCEEDED is the primary operation; onboarding bookkeeping can
/// never break it (the hook-never-breaks test asserts exactly that).
///
/// Returns `Result` by contract even though every path is `Ok`, so a future
/// caller that wants to propagate can opt in without a signature change.
pub async fn attempt_onboarding_event(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    event: OnboardingEvent,
) -> Result<(), OnboardingError> {
    let outcome = drive(pool, tenant_id, event.clone()).await;
    match outcome {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                event = ?event,
                error = %error,
                "onboarding event not applied; the primary operation is unaffected"
            );
            Ok(())
        }
    }
}

async fn drive(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    event: OnboardingEvent,
) -> Result<(), OnboardingError> {
    let current = read_state(pool, tenant_id)
        .await?
        .ok_or(OnboardingError::MissingTenant)?;
    advance_persisted(pool, tenant_id, current, event).await?;
    Ok(())
}

// ─── Handlers ──────────────────────────────────────────────────

/// `GET /v1/onboarding`: the AUTHENTICATED tenant's own machine — its state
/// and the literal next action. The row is read for `auth.tenant_id` only,
/// so there is no parameter that could ask for another tenant's walk; an
/// unknown stored value is an honest 500 (a drift the CHECK should make
/// impossible), a vanished row an honest 404.
async fn get_onboarding(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<OnboardingStatusResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;

    match read_state(&state.db, &auth.tenant_id).await {
        Ok(Some(current)) => Ok(Json(OnboardingStatusResponse {
            state: current,
            next_action: next_action(current),
        })),
        Ok(None) => Err(ApiError::NotFound("onboarding state not found".into())),
        Err(OnboardingError::Database(error)) => Err(error.into()),
        Err(OnboardingError::UnknownState(raw)) => Err(ApiError::Internal(format!(
            "unknown onboarding_state: {raw}"
        ))),
        Err(error) => Err(ApiError::Internal(error.to_string())),
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;
    use axum::http::StatusCode;

    /// The vocabulary the migration CHECK admits, pinned verbatim — the
    /// enum, its stored text and serde's wire form are ONE contract.
    #[test]
    fn state_vocabulary_is_the_migration_check_verbatim() {
        assert_eq!(
            OnboardingState::ALL.map(|state| state.as_str()),
            [
                "invited",
                "configuring_domain",
                "verifying_dns",
                "sending_ready",
                "active",
                "blocked",
            ],
        );
        for state in OnboardingState::ALL {
            // as_str and serde snake_case agree, round-trip included.
            assert_eq!(
                serde_json::to_string(&state).expect("serialize"),
                format!("\"{}\"", state.as_str()),
            );
            let parsed: OnboardingState = serde_json::from_str(&format!("\"{}\"", state.as_str()))
                .unwrap_or_else(|error| panic!("{} must deserialize: {error}", state.as_str()));
            assert_eq!(parsed, state);
            assert_eq!(OnboardingState::parse(state.as_str()), Some(state));
        }
        // And anything outside the vocabulary never invents a state.
        assert_eq!(OnboardingState::parse("paused"), None);
        assert_eq!(OnboardingState::parse(""), None);
    }

    /// The matrix: ALL 6 states × 6 events, every outcome pinned by hand
    /// (not derived from `LEGAL`, or the test would be vacuous).
    #[test]
    fn the_full_state_by_event_matrix_is_pinned() {
        #[derive(Debug)]
        enum Expected {
            Next(OnboardingState),
            IllegalTransition,
            AlreadyBlocked,
        }
        use Expected::{AlreadyBlocked, IllegalTransition, Next};
        use OnboardingEvent::{
            Block, DnsLookup, DomainCreated, DomainVerified, FirstSendObserved, Unblock,
        };
        use OnboardingState::{
            Active, Blocked, ConfiguringDomain, Invited, SendingReady, VerifyingDns,
        };

        let cases: [(OnboardingState, OnboardingEvent, Expected); 36] = [
            // invited
            (Invited, DomainCreated, Next(ConfiguringDomain)),
            (Invited, DnsLookup, IllegalTransition),
            (Invited, DomainVerified, IllegalTransition),
            (Invited, FirstSendObserved, IllegalTransition),
            (Invited, Block("tos".into()), Next(Blocked)),
            (Invited, Unblock, IllegalTransition),
            // configuring_domain
            (ConfiguringDomain, DomainCreated, Next(ConfiguringDomain)),
            (ConfiguringDomain, DnsLookup, Next(VerifyingDns)),
            (ConfiguringDomain, DomainVerified, IllegalTransition),
            (ConfiguringDomain, FirstSendObserved, IllegalTransition),
            (ConfiguringDomain, Block("tos".into()), Next(Blocked)),
            (ConfiguringDomain, Unblock, IllegalTransition),
            // verifying_dns
            (VerifyingDns, DomainCreated, Next(VerifyingDns)),
            (VerifyingDns, DnsLookup, IllegalTransition),
            (VerifyingDns, DomainVerified, Next(SendingReady)),
            (VerifyingDns, FirstSendObserved, IllegalTransition),
            (VerifyingDns, Block("tos".into()), Next(Blocked)),
            (VerifyingDns, Unblock, IllegalTransition),
            // sending_ready
            (SendingReady, DomainCreated, Next(SendingReady)),
            (SendingReady, DnsLookup, IllegalTransition),
            (SendingReady, DomainVerified, Next(SendingReady)),
            (SendingReady, FirstSendObserved, Next(Active)),
            (SendingReady, Block("tos".into()), Next(Blocked)),
            (SendingReady, Unblock, IllegalTransition),
            // active
            (Active, DomainCreated, Next(Active)),
            (Active, DnsLookup, IllegalTransition),
            (Active, DomainVerified, Next(Active)),
            (Active, FirstSendObserved, Next(Active)),
            (Active, Block("tos".into()), Next(Blocked)),
            (Active, Unblock, IllegalTransition),
            // blocked: absorbing, so every progression event is illegal and a
            // second Block is the TYPED AlreadyBlocked, not "illegal".
            (Blocked, DomainCreated, IllegalTransition),
            (Blocked, DnsLookup, IllegalTransition),
            (Blocked, DomainVerified, IllegalTransition),
            (Blocked, FirstSendObserved, IllegalTransition),
            (Blocked, Block("tos".into()), AlreadyBlocked),
            // Unblock's PURE default is invited; the recorded prior is the
            // persisted half's job (pinned by the DB test below).
            (Blocked, Unblock, Next(Invited)),
        ];
        assert_eq!(cases.len(), 36, "every state × every event");

        for (from, event, expected) in cases {
            let label = format!("advance({from:?}, {event:?})");
            let kind = event.kind();
            match expected {
                Next(next) => match advance(from, event) {
                    Ok(actual) => assert_eq!(actual, next, "{label}"),
                    Err(error) => panic!("{label} must advance to {next:?}, got: {error}"),
                },
                IllegalTransition => match advance(from, event) {
                    Err(OnboardingError::IllegalTransition {
                        from: actual_from,
                        event: actual_event,
                    }) => {
                        assert_eq!(actual_from, from, "{label}");
                        assert_eq!(actual_event.kind(), kind, "{label}");
                    }
                    other => panic!("{label} must be IllegalTransition, got: {other:?}"),
                },
                AlreadyBlocked => match advance(from, event) {
                    Err(OnboardingError::AlreadyBlocked) => {}
                    other => panic!("{label} must be AlreadyBlocked, got: {other:?}"),
                },
            }
        }
    }

    /// `LEGAL` itself must resolve: every listed edge advances to what the
    /// table promises (this is what catches a placeholder-reason `Block`
    /// entry drifting from the keyed lookup).
    #[test]
    fn every_legal_table_entry_resolves_exactly() {
        assert_eq!(
            LEGAL.len(),
            17,
            "4 progression + 5 Block + 1 Unblock + 7 idempotent no-op edges"
        );
        for (from, event, next) in LEGAL.iter() {
            let label = format!("advance({from:?}, {event:?})");
            match advance(*from, event.clone()) {
                Ok(actual) => assert_eq!(actual, *next, "{label}"),
                Err(error) => panic!("{label} must be a legal edge, got: {error}"),
            }
        }
        // And the idempotent edges are exactly the `next == from` ones —
        // those are what advance_persisted refuses to write.
        for (from, event, next) in LEGAL.iter() {
            if next == from {
                assert!(
                    matches!(
                        event.kind(),
                        EventKind::DomainCreated
                            | EventKind::DomainVerified
                            | EventKind::FirstSendObserved
                    ),
                    "only progression events are idempotent no-ops: {from:?} + {event:?}"
                );
            }
        }
    }

    /// The optimistic contract against a real (canonical-migration) pool:
    /// the happy path writes, a stale expectation conflicts on the WRITE
    /// path AND on the no-op path, and an idempotent re-receipt writes
    /// nothing at all.
    #[tokio::test]
    async fn advance_persisted_writes_and_refuses_stale_expectations() {
        let Some(pool) = crate::test_db::canonical_pool("onboarding_persist").await else {
            return;
        };
        let (_env, tenant_id) = AdvEnv::tenant(pool.clone(), &["*"]).await;

        // Happy path: invited + DomainCreated persists configuring_domain.
        let next = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::Invited,
            OnboardingEvent::DomainCreated,
        )
        .await
        .expect("persisted advance");
        assert_eq!(next, OnboardingState::ConfiguringDomain);

        let (stored, updated_at): (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT onboarding_state, onboarding_updated_at FROM tenants WHERE id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("stored state round-trip");
        assert_eq!(stored, "configuring_domain");

        // Stale expectation on the WRITE path: the row moved on, the caller
        // still claims `invited` → 0 rows → Conflict, and NOTHING is
        // written (the block never lands).
        let error = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::Invited,
            OnboardingEvent::Block("stale".into()),
        )
        .await
        .expect_err("a stale expectation must conflict");
        assert!(
            matches!(error, OnboardingError::Conflict { .. }),
            "expected Conflict, got: {error:?}"
        );
        let stored: String =
            sqlx::query_scalar("SELECT onboarding_state FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("stored state");
        assert_eq!(
            stored, "configuring_domain",
            "a refused advance must not write"
        );

        // Stale expectation on the NO-OP path: the event is a legal
        // idempotent re-receipt for the CLAIMED state, but the row is not in
        // it — still a Conflict, never a false OK.
        let error = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::VerifyingDns,
            OnboardingEvent::DomainCreated,
        )
        .await
        .expect_err("a stale expectation on a no-op must conflict too");
        assert!(
            matches!(error, OnboardingError::Conflict { .. }),
            "expected Conflict, got: {error:?}"
        );

        // The idempotent no-op for the TRUE state writes nothing — the
        // timestamp is byte-identical because no UPDATE ran.
        let next = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::ConfiguringDomain,
            OnboardingEvent::DomainCreated,
        )
        .await
        .expect("idempotent no-op");
        assert_eq!(next, OnboardingState::ConfiguringDomain);
        let (stored, updated_after): (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT onboarding_state, onboarding_updated_at FROM tenants WHERE id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("stored state round-trip");
        assert_eq!(stored, "configuring_domain");
        assert_eq!(
            updated_at, updated_after,
            "an idempotent no-op must not write"
        );
    }

    /// The Block bookkeeping round-trip: block records the interrupted state
    /// as JSON, unblock restores it and clears the note — and a second Block
    /// is AlreadyBlocked without touching the row.
    #[tokio::test]
    async fn block_records_the_prior_state_and_unblock_restores_it() {
        let Some(pool) = crate::test_db::canonical_pool("onboarding_block").await else {
            return;
        };
        let (_env, tenant_id) = AdvEnv::tenant(pool.clone(), &["*"]).await;

        for (expected, event) in [
            (OnboardingState::Invited, OnboardingEvent::DomainCreated),
            (
                OnboardingState::ConfiguringDomain,
                OnboardingEvent::DnsLookup,
            ),
        ] {
            advance_persisted(&pool, &tenant_id, expected, event)
                .await
                .expect("walk to verifying_dns");
        }

        let next = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::VerifyingDns,
            OnboardingEvent::Block("abuse review".into()),
        )
        .await
        .expect("block");
        assert_eq!(next, OnboardingState::Blocked);
        let note: Option<String> =
            sqlx::query_scalar("SELECT onboarding_note FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("note");
        assert_eq!(
            note.as_deref(),
            Some(r#"{"prior":"verifying_dns"}"#),
            "Block must record the interrupted state verbatim"
        );

        // Blocking the blocked is the typed error, and writes nothing.
        let error = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::Blocked,
            OnboardingEvent::Block("again".into()),
        )
        .await
        .expect_err("a second block must be refused");
        assert!(
            matches!(error, OnboardingError::AlreadyBlocked),
            "expected AlreadyBlocked, got: {error:?}"
        );

        // Unblock restores the recorded prior and consumes the note.
        let next = advance_persisted(
            &pool,
            &tenant_id,
            OnboardingState::Blocked,
            OnboardingEvent::Unblock,
        )
        .await
        .expect("unblock");
        assert_eq!(next, OnboardingState::VerifyingDns);
        let (stored, note): (String, Option<String>) =
            sqlx::query_as("SELECT onboarding_state, onboarding_note FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("restored state round-trip");
        assert_eq!(stored, "verifying_dns");
        assert!(note.is_none(), "the recorded prior is consumed");
    }

    /// The hook NEVER breaks the primary operation: against a pool that can
    /// not even connect, the wrapper logs and answers Ok(()) — exactly what
    /// the domains create/verify hooks rely on.
    #[tokio::test]
    async fn attempt_onboarding_event_never_breaks_the_primary_operation() {
        let unreachable = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("connect_lazy only parses the URL");

        let result = attempt_onboarding_event(
            &unreachable,
            "advt_onboarding0000000000",
            OnboardingEvent::DomainCreated,
        )
        .await;
        assert!(
            result.is_ok(),
            "the attempt wrapper must log-and-continue, not fail: {result:?}"
        );
    }

    /// The route: 200 with the literal next action for the PRINCIPAL's own
    /// machine (advancing tenant A never leaks into tenant B's answer), and
    /// 404 for anything off the one path the surface exposes.
    #[tokio::test]
    async fn get_onboarding_is_scoped_and_answers_200_or_404() {
        let Some(pool) = crate::test_db::canonical_pool("onboarding_route").await else {
            return;
        };
        let (env_a, tenant_a) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (env_b, _tenant_b) = AdvEnv::tenant(pool.clone(), &["*"]).await;

        // 200: a fresh tenant is invited, with the literal next action.
        let (status, body) = env_a.get("/v1/onboarding").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "invited");
        assert_eq!(body["nextAction"], "create your first sending domain");

        // Scoping: advancing A's machine never changes B's answer.
        advance_persisted(
            &pool,
            &tenant_a,
            OnboardingState::Invited,
            OnboardingEvent::DomainCreated,
        )
        .await
        .expect("advance tenant A");

        let (status, body) = env_a.get("/v1/onboarding").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "configuring_domain");
        assert_eq!(body["nextAction"], "request the DNS records");

        let (status, body) = env_b.get("/v1/onboarding").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["state"], "invited",
            "each principal answers for its own tenant only"
        );

        // 404: the surface is exactly one path; a subpath is no route.
        let (status, body) = env_a.get("/v1/onboarding/not-a-route").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
}
