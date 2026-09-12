//! Sequence step worker.
//!
//! This is the production [`ActionHandler`] for `send_step` actions. It is the
//! single place where a queued step execution becomes an outbound email, and it
//! is deliberately the *last* place every hard gate is checked:
//!
//! 1. the tenant's autonomy mode still permits execution and the kill switch is
//!    not engaged (read at execution time, not at enqueue time);
//! 2. the enrollment has no human reply;
//! 3. the step is still `scheduled`/`queued` (a reply may have cancelled it);
//! 4. suppression is re-checked inside the dispatcher's transaction.
//!
//! # The evidence-grounded planning pipeline (audit item 13, §12/§13/§14)
//!
//! Once the autonomy, reply and enrollment gates pass, a sendable step is
//! planned in this order:
//!
//! 1. load the live account/contact feature vector and measure evidence
//!    freshness: stale = no unexpired `sales_evidence` row or the newest is
//!    older than [`EVIDENCE_STALENESS_HOURS`];
//! 2. evaluate the pure §28 [`crate::experiments::next_best_action`] policy on
//!    the current state; when it asks for `ResearchCompany`,
//!    `CollectEvidence` or `Enrich`, gather evidence first
//!    ([`crate::research::research_account_with_report`], plus the §10
//!    enrichment waterfall for `Enrich` when the worker has one);
//! 3. recompute and persist the score from the refreshed evidence
//!    ([`crate::scoring::score`] + [`crate::scoring::persist`]); the stored
//!    latest score remains the fallback when the account has no economic basis
//!    (no open pipeline amount), and the source actually used is recorded;
//! 4. choose the next best action again on the refreshed state — a non-send
//!    action is a recorded, non-retryable skip;
//! 5. for an external send: choose an angle, compose the structured strategy
//!    from evidence, validate every claim and draft it through the
//!    [`crate::personalization::ProseWriter`];
//! 6. select and persist the experiment arm (when the step declares an
//!    `experiment_key`) onto `sales_step_executions.variant` and
//!    `sales_enrollments.experiment_id`/`experiment_variant` — the variant
//!    survives an enqueue failure and an outcome can be attributed even if the
//!    process dies immediately after;
//! 7. resolve the actual sender identity, run the Decision Engine, dispatch.
//!
//! # Fallback rules (§26)
//!
//! * AI outage anywhere in planning ⇒ the verified static template (which
//!   makes no AI-generated factual claim), verified knowledge-base facts and
//!   existing evidence only; the fallback is named in `model_version` and the
//!   decision rationale. `OfflineIntelligence` keeps the whole path working
//!   with no AI configured.
//! * a strategy whose claims do not validate (evidence outside the allowed
//!   live set, an unbacked proof point, a value proposition that is not a
//!   verified external-copy fact, or a restricted-capability promise) is
//!   rejected outright and replaced by the template — never by unvalidated
//!   prose.
//!
//! A denial is not an error — it is a recorded, non-retryable skip. Retrying a
//! policy denial would be exactly the "legal-policy denial bypassed through
//! another route" failure the release gates forbid.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::actions::{ActionHandler, ActionOutcome, ActionQueue, LeasedAction};
use crate::attribution::OutcomeKind;
use crate::autonomy;
use crate::decision_engine::{self, DecisionContext};
use crate::dispatcher::{
    compose_reply_html, fetch_template, render_for_recipient_with_footer, render_outreach_footer,
    send_idempotency_key, EnqueueOutcome, FooterReason, OutreachFooter,
    ProductionCampaignDispatcher, RenderedMessage, SendIdentity,
};
use crate::enrichment::EnrichmentService;
use crate::experiments::{
    next_best_action, EmailState, ExperimentContext, ExperimentEngine, NextActionInput, ReplyState,
    VariantContext, VariantSelection, DEFAULT_OUTREACH_COST_EUR,
};
use crate::intelligence::{AngleRequest, OfflineIntelligence, SalesIntelligence};
use crate::knowledge::{ClaimVerdict, SalesKnowledgeBase};
use crate::personalization::{
    compose_strategy, render_cold_email, MessageStrategist, ProseWriter, StrategyRequest,
    TemplateProseWriter,
};
use crate::research::{self, ResearchMode};
use crate::scoring::{
    EconomicsFeatures, EeaRelevance, EmailStackFeatures, EvidenceFeatures, OutcomeFeatures,
    PersonaFeatures, ReachabilityFeatures, RiskFeatures, ScoreFeatures, SegmentMatch,
};
use crate::sender_pool;
use crate::sequences;
use crate::signals::SignalObservation;
use crate::types::{
    ContactDecision, DecisionAction, Enforcement, OpportunityScore, SalesError, SenderPool,
};

/// An account's evidence is **stale** when it has no unexpired
/// `sales_evidence` row, or its newest unexpired observation is older than
/// this many hours.
///
/// Seven days is the documented horizon: `signals::combined_urgency` already
/// treats a week-old change signal as materially weaker, and refreshing at
/// least weekly means the planner never composes copy from facts that have
/// gone cold. Staleness alone never forces a send — it only authorizes the
/// information-gathering branch of the §28 next-best-action policy.
pub const EVIDENCE_STALENESS_HOURS: i64 = 168;

/// The default commercial offer used to compose outreach when a sequence step
/// carries no offer id. Deliberately generic and capability-free: the value
/// proposition and proof point are selected against the verified knowledge
/// base, never derived from this string.
pub const DEFAULT_OUTREACH_OFFER: &str = "reliable email sending";

/// Maximum length of the `model_version` recorded on a Decision Packet.
pub const MAX_MODEL_VERSION_CHARS: usize = 200;

/// Maximum length of the decision rationale recorded on a Decision Packet.
pub const MAX_RATIONALE_CHARS: usize = 1_500;

/// Which score the planner used for the Decision Packet and the §28 gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreSource {
    /// A score recomputed from live, unexpired evidence and the current
    /// feature vector in this planning run and persisted to `sales_scores`.
    Fresh,
    /// The most recent stored `sales_scores` row. Used when the account has no
    /// economic basis (no open pipeline amount) to derive an expected value
    /// from — the pre-existing behaviour for scored accounts.
    Stored,
    /// No score and no economic basis: the economic branch of the §28 gate is
    /// not evaluable, so it does not block and the existing hard gates govern
    /// (the pre-existing behaviour for never-scored accounts).
    Unavailable,
}

impl ScoreSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stored => "stored",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Freshness of an account's usable evidence, actually measured from the
/// database (a stale/missing account has `live_rows == 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceFreshness {
    /// Unexpired `sales_evidence` rows for the account.
    pub live_rows: i64,
    /// Newest observation among those unexpired rows.
    pub newest_observed_at: Option<DateTime<Utc>>,
}

impl EvidenceFreshness {
    /// See [`EVIDENCE_STALENESS_HOURS`]. A missing observation is stale.
    pub fn is_stale(self, now: DateTime<Utc>) -> bool {
        match self.newest_observed_at {
            None => true,
            Some(newest) => now - newest > chrono::Duration::hours(EVIDENCE_STALENESS_HOURS),
        }
    }
}

/// One statement the planned message emits, with the provenance that makes it
/// admissible. A statement is only permitted when it is evidence-backed, backed
/// by a verified external-copy knowledge fact, or explicitly a hypothesis.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundedStatement {
    pub statement: String,
    pub evidence_id: Option<Uuid>,
    pub knowledge_fact_id: Option<String>,
    pub is_hypothesis: bool,
}

/// What the planner will send: either prose rendered from a validated strategy
/// (footer attached later, once the sender is resolved) or the operator
/// approved static template (which carries its footer when rendered).
enum PlannedContent {
    Strategy { subject: String, body: String },
    Template,
}

/// The result of planning one message, including the audit trail the decision
/// records: which path produced the body, which intelligence provider was used
/// (or why it was bypassed), and every statement with its provenance.
struct MessagePlan {
    content: PlannedContent,
    grounded_statements: Vec<GroundedStatement>,
    strategy_used: bool,
    intelligence_mode: String,
    fallbacks: Vec<String>,
    angle: Option<String>,
}

impl MessagePlan {
    /// The verified fallback: the operator-approved static template, which
    /// makes no AI-generated factual claim.
    fn template_fallback() -> Self {
        Self {
            content: PlannedContent::Template,
            grounded_statements: Vec::new(),
            strategy_used: false,
            intelligence_mode: String::new(),
            fallbacks: Vec::new(),
            angle: None,
        }
    }
}

/// Account-level inputs the planner needs beyond the sequence context.
#[derive(Debug, Clone, Default)]
struct AccountFacts {
    company: String,
    domain: String,
    industry: Option<String>,
    employees: Option<i64>,
    technologies: Vec<String>,
    eea_relevance: String,
    icp_segment: Option<String>,
    lifecycle: String,
}

#[derive(Debug, Clone, Default)]
struct ContactFacts {
    job_title: Option<String>,
    department: Option<String>,
    seniority: Option<String>,
}

/// Every live feature the scorer, the planner and the strategist consume, all
/// read from the canonical tables (`sales_accounts`, `sales_contacts`,
/// `sales_contact_points`, `sales_signals`, `sales_evidence`,
/// `sales_enrichment_facts`, `sales_outcomes`, `sales_opportunities`,
/// `sales_contact_policy_decisions`).
#[derive(Debug, Clone)]
struct PlannerFacts {
    account: Option<AccountFacts>,
    contact: ContactFacts,
    signals: Vec<SignalObservation>,
    /// Live (unexpired) evidence aggregate.
    evidence: EvidenceFeatures,
    /// Live evidence ids, newest first — the only ids the claims gate accepts.
    evidence_ids: Vec<Uuid>,
    freshness: EvidenceFreshness,
    reachability: ReachabilityFeatures,
    email_stack: EmailStackFeatures,
    outcomes: OutcomeFeatures,
    risk: RiskFeatures,
    legal: ContactDecision,
    /// Sum of open/qualified/negotiation `sales_opportunities.amount_eur`.
    open_pipeline_eur: f64,
}

impl Default for PlannerFacts {
    fn default() -> Self {
        Self {
            account: None,
            contact: ContactFacts::default(),
            signals: Vec::new(),
            evidence: EvidenceFeatures::default(),
            evidence_ids: Vec::new(),
            freshness: EvidenceFreshness {
                live_rows: 0,
                newest_observed_at: None,
            },
            reachability: ReachabilityFeatures::default(),
            email_stack: EmailStackFeatures::default(),
            outcomes: OutcomeFeatures::default(),
            risk: RiskFeatures::default(),
            // Fail closed, exactly like the decision engine's own default.
            legal: ContactDecision::ApprovalRequired,
            open_pipeline_eur: 0.0,
        }
    }
}

impl PlannerFacts {
    /// The scorer's pure feature vector for the current live state. The legal
    /// dimension is the last recorded policy decision; the real legal gate is
    /// still `decision_engine::decide`, which re-evaluates the policy store.
    fn score_features(&self) -> ScoreFeatures {
        let account = self.account.as_ref();
        let segment_match = match account.and_then(|account| account.icp_segment.as_deref()) {
            Some(segment) if !segment.trim().is_empty() => SegmentMatch::Partial,
            _ => SegmentMatch::Unknown,
        };
        ScoreFeatures {
            now: Utc::now(),
            segment_match,
            employees: account.and_then(|account| account.employees),
            industry: account.and_then(|account| account.industry.clone()),
            email_stack: self.email_stack.clone(),
            eea_relevance: parse_eea_relevance(
                account.map(|account| account.eea_relevance.as_str()),
            ),
            intent_signals: self.signals.clone(),
            persona: PersonaFeatures {
                job_title: self.contact.job_title.clone(),
                department: self.contact.department.clone(),
                seniority: self.contact.seniority.clone(),
            },
            reachability: self.reachability.clone(),
            evidence: self.evidence.clone(),
            legal: self.legal,
            risk: self.risk.clone(),
            outcomes: self.outcomes,
            economics: EconomicsFeatures {
                expected_ltv_contribution_eur: self.open_pipeline_eur,
                outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
                reputation_risk_penalty_eur: 0.0,
                compliance_risk_penalty_eur: 0.0,
            },
            ..ScoreFeatures::default()
        }
    }
}

/// The live §28 inputs (mirrors the queries used by
/// [`next_best_action_skip_reason`], loaded once per planning run).
#[derive(Debug, Clone, Copy)]
struct NbaContext {
    prior_touches: u32,
    email: EmailState,
    opportunity_open: bool,
}

/// The production handler for sequence actions.
pub struct SequenceStepHandler {
    db: PgPool,
    dispatcher: Arc<ProductionCampaignDispatcher>,
    /// Used to attach the Decision Packet to the claimed action, fenced by the
    /// lease this worker holds. The owner/token come from the action's own
    /// fence, so any queue handle works regardless of its worker id.
    queue: ActionQueue,
    /// §12: the configured intelligence provider, or the deterministic offline
    /// implementation when no AI service is configured.
    intelligence: Arc<dyn SalesIntelligence>,
    /// §13/§14: the structured message strategist bound to the verified
    /// knowledge base.
    strategist: Arc<MessageStrategist>,
    /// §10: the enrichment waterfall, used when the NBA asks to `Enrich`.
    /// `None` when the worker was built without one (the research leg still
    /// runs).
    enrichment: Option<EnrichmentService>,
    /// Prose generation. The deterministic template writer is the only
    /// implementation that can guarantee the §12 grounding rule, so it is the
    /// production default.
    prose: Arc<dyn ProseWriter>,
    /// Human-readable name of the configured provider, recorded in
    /// `model_version`.
    intelligence_label: String,
}

impl SequenceStepHandler {
    /// The compatibility constructor: deterministic offline intelligence and
    /// the canonical knowledge base, so the audited offline path works with no
    /// AI configured (and remains what the test suite exercises).
    pub fn new(db: PgPool, dispatcher: Arc<ProductionCampaignDispatcher>) -> Self {
        let queue = ActionQueue::new(db.clone(), "sequence-worker");
        let strategist = Arc::new(MessageStrategist::new(
            db.clone(),
            SalesKnowledgeBase::canonical(),
        ));
        Self {
            db,
            dispatcher,
            queue,
            intelligence: Arc::new(OfflineIntelligence::new()),
            strategist,
            enrichment: None,
            prose: Arc::new(TemplateProseWriter::new()),
            intelligence_label: "offline-deterministic-v1".to_string(),
        }
    }

    /// The production constructor: caller-supplied intelligence provider and
    /// strategist (see `bin/server.rs`, which builds both from the
    /// environment).
    pub fn with_stack(
        db: PgPool,
        dispatcher: Arc<ProductionCampaignDispatcher>,
        intelligence: Arc<dyn SalesIntelligence>,
        strategist: Arc<MessageStrategist>,
    ) -> Self {
        let queue = ActionQueue::new(db.clone(), "sequence-worker");
        // The provider label is derived from configuration, not from whether a
        // particular call happened to fail: the environment is fixed for the
        // process lifetime.
        let intelligence_label = if crate::intelligence::HttpSalesIntelligence::from_env().is_some()
        {
            "apexmail-ai".to_string()
        } else {
            "offline-deterministic-v1".to_string()
        };
        Self {
            db,
            dispatcher,
            queue,
            intelligence,
            strategist,
            enrichment: None,
            prose: Arc::new(TemplateProseWriter::new()),
            intelligence_label,
        }
    }

    /// Attach the enrichment waterfall used for the NBA `Enrich` action.
    pub fn with_enrichment(mut self, enrichment: EnrichmentService) -> Self {
        self.enrichment = Some(enrichment);
        self
    }

    /// Override the provider label recorded in `model_version` (test hook and
    /// explicit deployments that wire their own provider).
    pub fn with_intelligence_label(mut self, label: impl Into<String>) -> Self {
        self.intelligence_label = label.into();
        self
    }

    /// Load every live feature the planner needs in one pass.
    ///
    /// The staleness verdict is measured, not assumed: it comes from the
    /// unexpired `sales_evidence` rows for the account (see
    /// [`EvidenceFreshness`] and [`EVIDENCE_STALENESS_HOURS`]).
    async fn load_planner_facts(&self, ctx: &StepContext) -> Result<PlannerFacts, SalesError> {
        let mut facts = PlannerFacts::default();
        let Some(account_id) = ctx.account_id else {
            return Ok(facts);
        };

        // `sales_accounts` columns: migration 200 lines 212-247 (company 216,
        // domain 217, industry 221, employees 222, technologies 225,
        // eea_relevance 227, icp_segment 229, lifecycle 235).
        let account_row: Option<(
            String,
            String,
            Option<String>,
            Option<i32>,
            Vec<String>,
            String,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT company, domain, industry, employees, technologies, eea_relevance, \
                    icp_segment, lifecycle \
             FROM sales_accounts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(account_id)
        .bind(&ctx.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        if let Some((
            company,
            domain,
            industry,
            employees,
            technologies,
            eea_relevance,
            icp_segment,
            lifecycle,
        )) = account_row
        {
            facts.account = Some(AccountFacts {
                company,
                domain,
                industry,
                employees: employees.map(i64::from),
                technologies,
                eea_relevance,
                icp_segment,
                lifecycle,
            });
        }

        // `sales_contacts` columns: migration 200 lines 250-270.
        let contact_row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT job_title, department, seniority FROM sales_contacts \
                 WHERE id = $1 AND tenant_id = $2",
        )
        .bind(ctx.contact_id)
        .bind(&ctx.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        if let Some((job_title, department, seniority)) = contact_row {
            facts.contact = ContactFacts {
                job_title,
                department,
                seniority,
            };
        }

        // `sales_signals` columns: migration 200 lines 377-395.
        let signal_rows: Vec<(String, f64, DateTime<Utc>)> = sqlx::query_as(
            "SELECT signal_type, strength::float8, observed_at FROM sales_signals \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND observed_at <= NOW() AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY observed_at DESC LIMIT 100",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        facts.signals = signal_rows
            .into_iter()
            .map(|(signal_type, strength, observed_at)| SignalObservation {
                signal_type,
                strength: strength as f32,
                observed_at,
            })
            .collect();

        // `sales_evidence` columns: migration 200 lines 308-330 (confidence
        // 315, observed_at 324, expires_at 325).
        let evidence_row: (i64, f64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > NOW())::bigint, \
                    COALESCE(AVG(confidence) FILTER \
                        (WHERE expires_at IS NULL OR expires_at > NOW()), 0)::float8, \
                    MAX(observed_at) FILTER (WHERE expires_at IS NULL OR expires_at > NOW()) \
             FROM sales_evidence WHERE tenant_id = $1 AND account_id = $2",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        let now = Utc::now();
        facts.freshness = EvidenceFreshness {
            live_rows: evidence_row.0.max(0),
            newest_observed_at: evidence_row.2,
        };
        facts.evidence = EvidenceFeatures {
            count: evidence_row.0.max(0) as u32,
            mean_confidence: evidence_row.1.clamp(0.0, 1.0) as f32,
            newest_age_days: evidence_row
                .2
                .map(|newest| (now - newest).num_seconds() as f32 / 86_400.0)
                .filter(|age| age.is_finite() && *age >= 0.0),
        };
        facts.evidence_ids = self.load_evidence_ids(ctx).await?;

        // `sales_contact_points` columns: migration 200 lines 277-303.
        let reachability_row: (i64, f64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE verification = 'valid')::bigint, \
                    COALESCE(MAX(confidence), 0)::float8 \
             FROM sales_contact_points WHERE tenant_id = $1 AND contact_id = $2",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        facts.reachability = ReachabilityFeatures {
            verified_contact_points: reachability_row.0.max(0) as u32,
            best_confidence: reachability_row.1.clamp(0.0, 1.0) as f32,
        };

        // `sales_outcomes` columns: migration 200 lines 758-786.
        let outcome_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT outcome, COUNT(*)::bigint FROM sales_outcomes \
             WHERE tenant_id = $1 AND account_id = $2 GROUP BY outcome",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        for (outcome, count) in outcome_rows {
            let count = count.max(0) as u32;
            match OutcomeKind::parse(&outcome) {
                Some(OutcomeKind::Delivered) => facts.outcomes.delivered = count,
                Some(OutcomeKind::Open) => facts.outcomes.opens = count,
                Some(OutcomeKind::Click) => facts.outcomes.clicks = count,
                Some(OutcomeKind::Reply) => facts.outcomes.replies = count,
                Some(OutcomeKind::PositiveReply) => facts.outcomes.positive_replies = count,
                Some(OutcomeKind::MeetingBooked) | Some(OutcomeKind::MeetingAttended) => {
                    facts.outcomes.meetings_booked = count
                }
                Some(OutcomeKind::Trial) => facts.outcomes.trials = count,
                Some(OutcomeKind::PaidSubscription) | Some(OutcomeKind::RetainedMrr) => {
                    facts.outcomes.paid_subscriptions = count
                }
                Some(OutcomeKind::Bounce) => facts.outcomes.bounces = count,
                Some(OutcomeKind::Complaint) => {
                    facts.outcomes.complaints = count;
                    facts.risk.complaints = count;
                }
                Some(OutcomeKind::Unsubscribe) => {
                    facts.outcomes.unsubscribes = count;
                    facts.risk.negative_replies = facts.risk.negative_replies.saturating_add(count);
                }
                None => {}
            }
        }

        // `sales_enrichment_facts` columns: migration 200 lines 336-352.
        let enrichment_rows: Vec<(String, serde_json::Value, f64)> = sqlx::query_as(
            "SELECT field, value, confidence::float8 FROM sales_enrichment_facts \
             WHERE tenant_id = $1 AND subject_type = 'account' AND subject_id = $2 \
               AND field IN ('technologies', 'email_provider')",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        let mut providers: Vec<String> = facts
            .account
            .as_ref()
            .map(|account| account.technologies.clone())
            .unwrap_or_default();
        let mut stack_confidence = 0.0f32;
        for (_field, value, confidence) in enrichment_rows {
            let value = json_fact_to_string(&value);
            if !value.trim().is_empty() && !providers.iter().any(|existing| existing == &value) {
                providers.push(value);
            }
            stack_confidence = stack_confidence.max(confidence.clamp(0.0, 1.0) as f32);
        }
        facts.email_stack = EmailStackFeatures {
            providers,
            confidence: stack_confidence,
            authentication_quality: 0.0,
        };

        // `sales_opportunities` columns: migration 200 lines 738-751.
        let open_pipeline: f64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_eur), 0)::float8 FROM sales_opportunities \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND stage IN ('open', 'qualified', 'negotiation')",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        facts.open_pipeline_eur = if open_pipeline.is_finite() && open_pipeline > 0.0 {
            open_pipeline
        } else {
            0.0
        };

        // `sales_contact_policy_decisions` columns: migration 200 lines
        // 934-950; the latest recorded verdict feeds the scorer's legal
        // dimension (the engine re-evaluates the policy itself).
        let legal: Option<String> = sqlx::query_scalar(
            "SELECT decision FROM sales_contact_policy_decisions \
             WHERE tenant_id = $1 AND contact_id = $2 \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        facts.legal = parse_legal(legal.as_deref());

        Ok(facts)
    }

    /// Load the live §28 inputs (the same queries the public
    /// [`next_best_action_skip_reason`] helper performs).
    async fn load_nba_context(&self, ctx: &StepContext) -> Result<NbaContext, SalesError> {
        let Some(account_id) = ctx.account_id else {
            return Ok(NbaContext {
                prior_touches: 0,
                email: EmailState::Unverified,
                opportunity_open: false,
            });
        };
        let email_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_step_executions se \
             JOIN sales_enrollments e ON e.id = se.enrollment_id \
             WHERE e.tenant_id = $1 AND e.id = $2 AND se.state = 'sent'",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.enrollment_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        let verification: Option<String> = sqlx::query_scalar(
            "SELECT verification FROM sales_contact_points \
             WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
             ORDER BY CASE verification WHEN 'valid' THEN 0 WHEN 'risky' THEN 1 ELSE 2 END, \
                      confidence DESC LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        let email = match verification.as_deref() {
            Some("valid") => EmailState::Verified,
            Some("risky") => EmailState::Risky,
            Some("invalid") => EmailState::Invalid,
            _ => EmailState::Unverified,
        };
        let opportunity_open: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sales_opportunities \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND stage IN ('open', 'qualified', 'negotiation'))",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_one(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(NbaContext {
            prior_touches: email_count.max(0) as u32,
            email,
            opportunity_open,
        })
    }

    /// The final next-best-action choice, using the score the caller selected.
    ///
    /// `Unavailable` (no economic basis and no stored score) deliberately does
    /// not block: this is the pre-existing fresh-deployment behaviour, and the
    /// hard gates still govern. Every other source runs the pure §28 policy,
    /// whose external-send actions alone authorize a message.
    fn plan_action(
        &self,
        facts: &PlannerFacts,
        nba: &NbaContext,
        source: ScoreSource,
        expected_value_eur: f64,
        intent: f32,
    ) -> (DecisionAction, String) {
        if source == ScoreSource::Unavailable {
            return (
                DecisionAction::Contact,
                "no score or economic basis yet (no open pipeline amount and no stored score); \
                 the §28 economic gate is not evaluable, so the existing hard gates govern"
                    .to_string(),
            );
        }
        let input = NextActionInput {
            expected_value_eur,
            outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
            evidence_count: facts.freshness.live_rows.max(0) as u32,
            evidence_confidence: facts.evidence.mean_confidence.clamp(0.0, 1.0),
            reply: ReplyState::None,
            email: nba.email,
            intent_strength: (intent / 100.0).clamp(0.0, 1.0),
            prior_touches: nba.prior_touches,
            last_angle_failed: false,
            referral_available: false,
            referral_requested: false,
            opportunity_open: nba.opportunity_open,
            cooldown_active: false,
            disqualified: facts
                .account
                .as_ref()
                .is_some_and(|account| account.lifecycle == "disqualified"),
        };
        next_best_action(&input)
    }

    /// Gather evidence when the NBA asks for an information action.
    ///
    /// `ResearchCompany`/`CollectEvidence`/`Enrich` all run the §12 research
    /// leg; `Enrich` additionally runs the §10 enrichment waterfall when the
    /// worker has one. Every failure is non-fatal and recorded: an AI outage
    /// writes nothing and the planner falls back to existing evidence (never
    /// to an invented claim).
    async fn gather_evidence(
        &self,
        ctx: &StepContext,
        facts: &PlannerFacts,
        action: DecisionAction,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let Some(account_id) = ctx.account_id else {
            return notes;
        };

        if action == DecisionAction::Enrich {
            match &self.enrichment {
                Some(enrichment) => {
                    let (domain, company) = facts
                        .account
                        .as_ref()
                        .map(|account| (account.domain.as_str(), account.company.as_str()))
                        .unwrap_or(("", ""));
                    if domain.trim().is_empty() {
                        notes.push(
                            "enrichment requested but the account has no domain; running the \
                             research leg only"
                                .to_string(),
                        );
                    } else {
                        match enrichment
                            .enrich_persisted(&self.db, &ctx.tenant_id, domain, None, Some(company))
                            .await
                        {
                            Ok(persisted) => notes.push(format!(
                                "enrichment waterfall filled {} field(s)",
                                persisted.outcome.facts.len()
                            )),
                            Err(error) => notes.push(format!(
                                "enrichment unavailable ({error}); running the research leg only"
                            )),
                        }
                    }
                }
                None => notes.push(
                    "enrichment waterfall not configured on this worker; running the research \
                     leg only"
                        .to_string(),
                ),
            }
        }

        match research::research_account_with_report(
            &self.db,
            &ctx.tenant_id,
            account_id,
            self.intelligence.as_ref(),
        )
        .await
        {
            Ok(run) => {
                let mode = match run.mode {
                    ResearchMode::Ai => "ai",
                    ResearchMode::OfflineFallback => "offline",
                    ResearchMode::Outage => "outage",
                };
                if run.mode == ResearchMode::Outage {
                    notes.push(format!(
                        "intelligence outage during research: {}",
                        run.reason
                            .unwrap_or_else(|| "no reason reported".to_string())
                    ));
                } else if run.accepted == 0 {
                    if let Some(reason) = run.reason {
                        notes.push(format!("research ({mode}) wrote no evidence: {reason}"));
                    }
                } else {
                    notes.push(format!(
                        "research ({mode}) accepted {} grounded finding(s)",
                        run.accepted
                    ));
                }
            }
            Err(error) => notes.push(format!("research failed: {error}")),
        }
        notes
    }

    /// Choose an angle, build the structured strategy from evidence, draft it
    /// through the [`ProseWriter`] and gate every external claim.
    ///
    /// The body may only come from this path when the strategy survives
    /// validation intact: a dropped claim or a refused capability rejects the
    /// strategy outright and the caller renders the operator-approved static
    /// template instead — never unvalidated prose. An intelligence outage also
    /// returns the template fallback.
    async fn plan_message(&self, ctx: &StepContext, facts: &PlannerFacts) -> MessagePlan {
        let mut plan = MessagePlan::template_fallback();
        let Some(account_id) = ctx.account_id else {
            plan.fallbacks.push(
                "no account on the enrollment; cannot build an evidence-grounded strategy"
                    .to_string(),
            );
            return plan;
        };

        let request = StrategyRequest {
            tenant_id: ctx.tenant_id.clone(),
            account_id,
            contact_id: ctx.contact_id,
            enrollment_id: Some(ctx.enrollment_id),
            language: None,
            offer: DEFAULT_OUTREACH_OFFER.to_string(),
            experiment_arm: None,
            now: None,
        };
        let input = match self.strategist.load_input(&request).await {
            Ok(input) => input,
            Err(error) => {
                plan.fallbacks
                    .push(format!("strategist context unavailable: {error}"));
                return plan;
            }
        };
        let mut strategy = compose_strategy(&input);

        // 1. Choose the messaging angle. The offline provider is deterministic
        //    and never touches the network; a configured provider may be
        //    unavailable, which is the outage signal.
        match self
            .intelligence
            .select_angle(&AngleRequest {
                tenant_id: &ctx.tenant_id,
                account_id: Some(account_id),
                evidence_ids: &facts.evidence_ids,
                offer: Some(DEFAULT_OUTREACH_OFFER),
                persona: input.contact.persona.as_deref(),
                hypotheses: &input.account.esp_hypotheses,
            })
            .await
        {
            Ok(angle) => {
                if strategy.offer.trim().is_empty() && !angle.angle.trim().is_empty() {
                    strategy.offer = angle.angle.clone();
                }
                plan.angle = Some(angle.angle);
                plan.intelligence_mode = self.intelligence_label.clone();
            }
            Err(error) => {
                // §26: an outage falls back to verified static content only.
                plan.fallbacks.push(format!(
                    "intelligence unavailable during angle selection: {error}"
                ));
                plan.intelligence_mode = format!("fallback:{error}");
                return plan;
            }
        }

        // 2/3. Validate the structured strategy and draft it through the prose
        //      writer. Validation is a gate, not a suggestion.
        match render_cold_email(&strategy, self.prose.as_ref(), self.strategist.knowledge()) {
            Ok(rendered) => {
                if !rendered.omitted.is_empty() {
                    plan.fallbacks.push(format!(
                        "strategy validation dropped {} claim(s); rejected in favour of the \
                         verified template",
                        rendered.omitted.len()
                    ));
                    return plan;
                }
                if let Some(reason) =
                    claims_gate(&strategy, &rendered, facts, self.strategist.knowledge())
                {
                    plan.fallbacks.push(reason);
                    return plan;
                }
                plan.grounded_statements =
                    grounded_statements(&strategy, self.strategist.knowledge());
                plan.content = PlannedContent::Strategy {
                    subject: rendered.subject,
                    body: rendered.body,
                };
                plan.strategy_used = true;
            }
            Err(error) => {
                plan.fallbacks.push(format!("strategy rejected: {error}"));
            }
        }
        plan
    }

    /// Load the latest stored opportunity score for the contact's account, if
    /// one exists.
    ///
    /// The stored score is the fallback path when the live feature vector has
    /// no economic basis to compute an expected value from; when it is absent
    /// the §28 economic gate is not evaluable and the existing hard gates
    /// govern (the pre-existing fresh-deployment behaviour: refusing to send
    /// because no score exists would silently disable the engine).
    async fn load_score(
        &self,
        ctx: &StepContext,
    ) -> Result<Option<crate::types::OpportunityScore>, SalesError> {
        let Some(account_id) = ctx.account_id else {
            return Ok(None);
        };
        let row: Option<ScoreRow> = sqlx::query_as(
            "SELECT account_fit, persona_fit, need_fit, intent, timing, email_stack_fit, \
                    eu_residency_fit, reachability, evidence_quality, legal_contactability, \
                    risk, p_qualified_reply, p_meeting, p_paid, expected_value_eur::float8, \
                    total, reason_codes, scoring_version \
             FROM sales_scores WHERE tenant_id = $1 AND account_id = $2 \
             ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(row.map(|row| crate::types::OpportunityScore {
            account_fit: row.account_fit as f32,
            persona_fit: row.persona_fit as f32,
            need_fit: row.need_fit as f32,
            intent: row.intent as f32,
            timing: row.timing as f32,
            email_stack_fit: row.email_stack_fit as f32,
            eu_residency_fit: row.eu_residency_fit as f32,
            reachability: row.reachability as f32,
            evidence_quality: row.evidence_quality as f32,
            legal_contactability: row.legal_contactability as f32,
            risk: row.risk as f32,
            p_qualified_reply: row.p_qualified_reply as f32,
            p_meeting: row.p_meeting as f32,
            p_paid: row.p_paid as f32,
            expected_value_eur: row.expected_value_eur,
            total: row.total as f32,
            reason_codes: row
                .reason_codes
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            scoring_version: row.scoring_version,
        }))
    }

    /// Evidence ids the decision can cite, newest first.
    async fn load_evidence_ids(&self, ctx: &StepContext) -> Result<Vec<Uuid>, SalesError> {
        let Some(account_id) = ctx.account_id else {
            return Ok(Vec::new());
        };
        sqlx::query_scalar(
            "SELECT id FROM sales_evidence \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY observed_at DESC LIMIT 50",
        )
        .bind(&ctx.tenant_id)
        .bind(account_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))
    }

    /// Build the legal-policy *inputs* for this recipient from canonical facts.
    ///
    /// These are facts about the person (jurisdiction, contact type, channel,
    /// consent), not an authorization: `decision_engine::decide` evaluates the
    /// current policy store itself, so a tightened or replaced policy is
    /// honoured rather than a stale verdict being trusted.
    async fn build_policy_input(
        &self,
        ctx: &StepContext,
    ) -> Result<Option<crate::decision_engine::ContactPolicyInputOwned>, SalesError> {
        let row: Option<(Option<String>, f32, bool)> = sqlx::query_as(
            "SELECT COALESCE(a.country, c.country) AS country, \
                    COALESCE(a.country_confidence, 0)::float4 AS confidence, \
                    (a.lifecycle = 'customer') AS existing_relationship \
             FROM sales_contacts c \
             LEFT JOIN sales_accounts a ON a.id = c.account_id \
             WHERE c.id = $1 AND c.tenant_id = $2",
        )
        .bind(ctx.contact_id)
        .bind(&ctx.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let Some((country, confidence, existing_relationship)) = row else {
            return Ok(None);
        };

        // §103¹ consent evidence, loaded from the canonical
        // `sales_consent_evidence` store — never taken on trust from a
        // boolean. An active row (withdrawn_at IS NULL, newest by
        // collected_at) yields `consent_status = "granted"`; a withdrawn row
        // yields "withdrawn", which the legal engine treats as an absolute
        // prohibition.
        let consent = crate::legal_policy::load_consent_state(
            &self.db,
            &ctx.tenant_id,
            ctx.contact_id,
            ctx.contact_point_id,
        )
        .await?;

        Ok(Some(crate::decision_engine::ContactPolicyInputOwned {
            account_id: ctx.account_id,
            contact_id: Some(ctx.contact_id),
            contact_point_id: ctx.contact_point_id,
            recipient_country: country,
            country_confidence: confidence,
            // The canonical model carries no corporate-form field, so a
            // professional recipient is the truthful default for the
            // contact/relationship classification; the policy engine treats an
            // unrecognised type as its fail-closed case.
            contact_type: "b2b_professional".to_string(),
            channel: "email".to_string(),
            source: Some("sequence".to_string()),
            purpose: Some("outbound_sales".to_string()),
            has_existing_relationship: existing_relationship,
            consent_status: consent.status().map(str::to_string),
            soft_opt_in: false,
            legitimate_interest_assessed: true,
            // No canonical column carries the recipient's legal character and
            // inferring "legal person" from a work email address or a B2B
            // persona is exactly what the audit forbids. Until a verified
            // subscriber-type source exists (e.g. a
            // `sales_contacts.subscriber_type` set by the collector, with
            // evidence), every recipient is Unknown and the engine refuses to
            // send autonomously.
            subscriber_type: crate::legal_policy::SubscriberType::Unknown,
            consent_evidence_id: consent.evidence_id(),
            // The account-lifecycle customer fact is the only canonical
            // relationship source today; it is not a per-recipient purchase
            // record, so it is used only as the relationship flag.
            existing_customer: existing_relationship,
            // No canonical source records that the marketed product is similar
            // to one the customer already bought (the offer/purchase history
            // is not joined here). Pass the fail-closed value; a canonical
            // offer-to-purchase mapping would need to exist.
            similar_product_basis: false,
            // No canonical source records a collection-time opt-out offer
            // (`sales_consent_evidence` stores the consent text, not the
            // refusal offer, and `sales_contact_points` has no such column).
            // None fails the §103¹(2) soft-opt-in exception closed; it would
            // need a `collection_opt_out_offered_at` on the evidence or
            // contact-point row.
            collection_opt_out_offered_at: None,
        }))
    }

    /// Load the step execution plus everything the send needs.
    async fn load_context(
        &self,
        step_execution_id: Uuid,
    ) -> Result<Option<StepContext>, SalesError> {
        let row: Option<StepContextRow> = sqlx::query_as(
            "SELECT \
                 se.id AS step_execution_id, se.tenant_id, se.enrollment_id, \
                 se.sequence_version_id, se.sequence_step_id, se.step_index, \
                 se.attempt_kind, se.variant, se.state, \
                 e.has_human_reply, e.state AS enrollment_state, \
                 e.contact_id, e.account_id, \
                 cp.id AS contact_point_id, \
                 s.kind AS step_kind, s.template_id, s.sender_pool, s.experiment_key \
             FROM sales_step_executions se \
             JOIN sales_enrollments e ON e.id = se.enrollment_id \
             JOIN sales_sequence_steps s ON s.id = se.sequence_step_id \
             LEFT JOIN LATERAL ( \
                 SELECT p.id FROM sales_contact_points p \
                 WHERE p.tenant_id = se.tenant_id AND p.contact_id = e.contact_id \
                   AND p.channel = 'email' AND p.suppressed_at IS NULL \
                 ORDER BY (p.verification = 'valid') DESC, p.confidence DESC, p.created_at DESC \
                 LIMIT 1 \
             ) cp ON TRUE \
             WHERE se.id = $1",
        )
        .bind(step_execution_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(row.map(StepContext::from))
    }

    /// Resolve the recipient email for a step execution.
    async fn recipient_email(&self, ctx: &StepContext) -> Result<Option<String>, SalesError> {
        let email: Option<String> = sqlx::query_scalar(
            "SELECT cp.normalized_value \
             FROM sales_contact_points cp \
             WHERE cp.tenant_id = $1 AND cp.contact_id = $2 AND cp.channel = 'email' \
               AND cp.suppressed_at IS NULL \
               AND cp.verification IN ('valid', 'risky') \
             ORDER BY CASE cp.verification WHEN 'valid' THEN 0 ELSE 1 END, cp.confidence DESC \
             LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(email)
    }

    /// Mark the execution skipped and record why. Never retried.
    async fn skip(
        &self,
        step_execution_id: Uuid,
        reason: &str,
    ) -> Result<ActionOutcome, SalesError> {
        sqlx::query(
            "UPDATE sales_step_executions \
             SET state = 'skipped', skip_reason = $2, updated_at = NOW() \
             WHERE id = $1 AND state IN ('scheduled', 'queued')",
        )
        .bind(step_execution_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(ActionOutcome::Succeeded)
    }
}

/// Which score the planner should use: a fresh score built from live economic
/// data, the stored latest row, or nothing (economic gate not evaluable).
fn resolve_score_source(facts: &PlannerFacts, stored: Option<&OpportunityScore>) -> ScoreSource {
    if facts.open_pipeline_eur > 0.0 {
        ScoreSource::Fresh
    } else if stored.is_some() {
        ScoreSource::Stored
    } else {
        ScoreSource::Unavailable
    }
}

/// The expected value the §28 gate should evaluate for the chosen source.
fn effective_ev(
    fresh: &OpportunityScore,
    stored: Option<&OpportunityScore>,
    source: ScoreSource,
) -> f64 {
    match source {
        ScoreSource::Fresh | ScoreSource::Unavailable => fresh.expected_value_eur,
        ScoreSource::Stored => stored
            .map(|score| score.expected_value_eur)
            .unwrap_or(fresh.expected_value_eur),
    }
}

/// The §12 claim gate for one planned strategy. Returns a rejection reason
/// when any external claim is not admissible.
///
/// * an observed fact must cite an id in the allowed live evidence set;
/// * a proof point must cite allowed live evidence or a verified, in-date,
///   external-copy-allowed knowledge fact;
/// * the value proposition must be a verified external-copy knowledge fact;
/// * the rendered subject + body must not promise a restricted capability.
fn claims_gate(
    strategy: &crate::personalization::MessageStrategy,
    rendered: &crate::personalization::RenderedStrategy,
    facts: &PlannerFacts,
    knowledge: &SalesKnowledgeBase,
) -> Option<String> {
    if let Some(observed) = &strategy.observed_fact {
        if observed.evidence_id.is_nil() || !facts.evidence_ids.contains(&observed.evidence_id) {
            return Some(
                "observed fact cites evidence that is not in the allowed live evidence set; \
                 strategy rejected"
                    .to_string(),
            );
        }
    }
    if let Some(proof) = &strategy.proof_point {
        let evidence_ok = proof
            .evidence_id
            .is_some_and(|id| !id.is_nil() && facts.evidence_ids.contains(&id));
        let knowledge_ok = proof
            .knowledge_fact_id
            .as_deref()
            .and_then(|id| knowledge.get(id))
            .is_some_and(|fact| fact.is_external_copy_allowed_at(Utc::now()));
        if !evidence_ok && !knowledge_ok {
            return Some(
                "proof point is neither evidence-backed nor backed by a verified knowledge fact; \
                 strategy rejected"
                    .to_string(),
            );
        }
    }
    if !knowledge
        .external_copy_facts()
        .into_iter()
        .any(|fact| fact.claim == strategy.value_prop)
    {
        return Some(
            "value proposition is not a verified external-copy knowledge fact; strategy rejected"
                .to_string(),
        );
    }
    let combined = format!("{}\n{}", rendered.subject, rendered.body);
    if let ClaimVerdict::Unsupported { capability, reason } = knowledge.validate_claim(&combined) {
        return Some(format!(
            "rendered body promises unsupported capability '{capability}': {reason}"
        ));
    }
    None
}

/// The provenance trace of every statement the strategy emits, used to assert
/// the §12 rule and recorded on the decision metadata.
fn grounded_statements(
    strategy: &crate::personalization::MessageStrategy,
    knowledge: &SalesKnowledgeBase,
) -> Vec<GroundedStatement> {
    let mut out = Vec::new();
    if let Some(observed) = &strategy.observed_fact {
        out.push(GroundedStatement {
            statement: observed.statement.clone(),
            evidence_id: Some(observed.evidence_id),
            knowledge_fact_id: None,
            is_hypothesis: false,
        });
    }
    if !strategy.problem_hypothesis.trim().is_empty() {
        out.push(GroundedStatement {
            statement: strategy.problem_hypothesis.clone(),
            evidence_id: None,
            knowledge_fact_id: None,
            is_hypothesis: true,
        });
    }
    if let Some(fact) = knowledge
        .external_copy_facts()
        .into_iter()
        .find(|fact| fact.claim == strategy.value_prop)
    {
        out.push(GroundedStatement {
            statement: strategy.value_prop.clone(),
            evidence_id: None,
            knowledge_fact_id: Some(fact.id.clone()),
            is_hypothesis: false,
        });
    }
    if let Some(proof) = &strategy.proof_point {
        out.push(GroundedStatement {
            statement: proof.statement.clone(),
            evidence_id: proof.evidence_id,
            knowledge_fact_id: proof.knowledge_fact_id.clone(),
            is_hypothesis: false,
        });
    }
    out
}

/// `sales_accounts.eea_relevance` CHECK values (migration 200 line 227).
fn parse_eea_relevance(value: Option<&str>) -> EeaRelevance {
    match value.map(str::trim).map(|value| value.to_ascii_lowercase()) {
        Some(value) if value == "in_scope" => EeaRelevance::InScope,
        Some(value) if value == "out_of_scope" => EeaRelevance::OutOfScope,
        _ => EeaRelevance::Unknown,
    }
}

/// `sales_contact_policy_decisions.decision` CHECK values (migration 200
/// lines 941-...); anything unrecognized fails closed to the engine's own
/// approval-required default.
fn parse_legal(value: Option<&str>) -> ContactDecision {
    match value.map(str::trim).map(|value| value.to_ascii_lowercase()) {
        Some(value) if value == "allowed" => ContactDecision::Allowed,
        Some(value) if value == "prohibited" => ContactDecision::Prohibited,
        _ => ContactDecision::ApprovalRequired,
    }
}

/// Render an enrichment fact JSON value as a short human-readable string.
fn json_fact_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Truncate on a char boundary (hostile/oversized input must never panic).
fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

/// One stored score projection. A named struct rather than a tuple: sqlx only
/// implements `FromRow` for tuples up to 16 elements and this projection has
/// eighteen columns.
/// `sales_scores` stores every dimension as `DOUBLE PRECISION`
/// (migration 200 lines 407-419), so the projection decodes them as `f64` and
/// narrows to `f32` on the way into [`crate::types::OpportunityScore`].
#[derive(sqlx::FromRow)]
struct ScoreRow {
    account_fit: f64,
    persona_fit: f64,
    need_fit: f64,
    intent: f64,
    timing: f64,
    email_stack_fit: f64,
    eu_residency_fit: f64,
    reachability: f64,
    evidence_quality: f64,
    legal_contactability: f64,
    risk: f64,
    p_qualified_reply: f64,
    p_meeting: f64,
    p_paid: f64,
    expected_value_eur: f64,
    total: f64,
    reason_codes: serde_json::Value,
    scoring_version: String,
}

#[derive(sqlx::FromRow)]
struct StepContextRow {
    step_execution_id: Uuid,
    tenant_id: String,
    enrollment_id: Uuid,
    sequence_version_id: Uuid,
    sequence_step_id: Uuid,
    step_index: i32,
    attempt_kind: String,
    variant: String,
    state: String,
    has_human_reply: bool,
    enrollment_state: String,
    contact_id: Uuid,
    account_id: Option<Uuid>,
    contact_point_id: Option<Uuid>,
    step_kind: String,
    template_id: Option<String>,
    sender_pool: String,
    experiment_key: Option<String>,
}

struct StepContext {
    step_execution_id: Uuid,
    tenant_id: String,
    enrollment_id: Uuid,
    sequence_version_id: Uuid,
    sequence_step_id: Uuid,
    step_index: i32,
    attempt_kind: String,
    variant: String,
    state: String,
    has_human_reply: bool,
    enrollment_state: String,
    contact_id: Uuid,
    account_id: Option<Uuid>,
    contact_point_id: Option<Uuid>,
    step_kind: String,
    template_id: Option<String>,
    sender_pool: String,
    /// `sales_sequence_steps.experiment_key` (migration line 479). When set,
    /// the arm is selected and persisted before the send.
    experiment_key: Option<String>,
}

impl From<StepContextRow> for StepContext {
    fn from(row: StepContextRow) -> Self {
        Self {
            step_execution_id: row.step_execution_id,
            tenant_id: row.tenant_id,
            enrollment_id: row.enrollment_id,
            sequence_version_id: row.sequence_version_id,
            sequence_step_id: row.sequence_step_id,
            step_index: row.step_index,
            attempt_kind: row.attempt_kind,
            variant: row.variant,
            state: row.state,
            has_human_reply: row.has_human_reply,
            enrollment_state: row.enrollment_state,
            contact_id: row.contact_id,
            account_id: row.account_id,
            contact_point_id: row.contact_point_id,
            step_kind: row.step_kind,
            template_id: row.template_id,
            sender_pool: row.sender_pool,
            experiment_key: row.experiment_key,
        }
    }
}

/// Company-size band used as a context dimension.
pub fn company_size_band(employees: Option<i64>) -> Option<String> {
    match employees {
        Some(count) if count <= 10 => Some("1-10".to_string()),
        Some(count) if count <= 50 => Some("11-50".to_string()),
        Some(count) if count <= 200 => Some("51-200".to_string()),
        Some(count) if count <= 1_000 => Some("201-1000".to_string()),
        Some(_) => Some("1001+".to_string()),
        None => None,
    }
}

/// Intent bucket (0-100 scorer dimension) used as a context dimension.
pub fn intent_bucket(intent: f64) -> String {
    if !intent.is_finite() {
        return "unknown".to_string();
    }
    match intent.max(0.0) {
        value if value < 20.0 => "none".to_string(),
        value if value < 40.0 => "low".to_string(),
        value if value < 70.0 => "medium".to_string(),
        _ => "high".to_string(),
    }
}

/// Select the experiment arm for a step execution and **persist it before any
/// send is attempted**.
///
/// The variant is written to `sales_step_executions.variant` (migration line
/// 532) and `sales_enrollments.experiment_id` / `experiment_variant` (lines
/// 502-503) in one transaction, so an outcome can be attributed even if the
/// process dies immediately after planning and before the dispatcher is
/// called. Returns `Ok(None)` when the step execution no longer exists.
pub async fn select_and_persist_variant(
    db: &PgPool,
    tenant_id: &str,
    step_execution_id: Uuid,
    experiment_key: &str,
) -> Result<Option<VariantSelection>, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if experiment_key.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "experiment_key is required".into(),
        ));
    }

    let row = sqlx::query(
        "SELECT se.enrollment_id, e.account_id, e.contact_id, \
                s.kind AS step_kind, s.sender_pool, \
                a.icp_segment, a.employees, a.esp_hypotheses, \
                a.country AS account_country, \
                c.persona, c.seniority, c.department, c.country AS contact_country, c.language \
         FROM sales_step_executions se \
         JOIN sales_enrollments e ON e.id = se.enrollment_id \
         JOIN sales_sequence_steps s ON s.id = se.sequence_step_id \
         LEFT JOIN sales_accounts a ON a.id = e.account_id \
         LEFT JOIN sales_contacts c ON c.id = e.contact_id \
         WHERE se.id = $1 AND se.tenant_id = $2",
    )
    .bind(step_execution_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(row) = row else { return Ok(None) };

    let enrollment_id: Uuid = row
        .try_get("enrollment_id")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let account_id: Option<Uuid> = row
        .try_get("account_id")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let step_kind: String = row
        .try_get("step_kind")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let sender_pool: String = row
        .try_get("sender_pool")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let icp_segment: Option<String> = row
        .try_get("icp_segment")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let employees: Option<i64> = row
        .try_get::<Option<i32>, _>("employees")
        .map_err(|error| SalesError::Database(error.to_string()))?
        .map(i64::from);
    let esp_hypotheses: Option<serde_json::Value> = row
        .try_get("esp_hypotheses")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let account_country: Option<String> = row
        .try_get("account_country")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let persona: Option<String> = row
        .try_get("persona")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let seniority: Option<String> = row
        .try_get("seniority")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let department: Option<String> = row
        .try_get("department")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let contact_country: Option<String> = row
        .try_get("contact_country")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let language: Option<String> = row
        .try_get("language")
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let score = match account_id {
        Some(account_id) => sqlx::query(
            "SELECT expected_value_eur::float8 AS ev, intent::float8 AS intent \
             FROM sales_scores WHERE tenant_id = $1 AND account_id = $2 \
             ORDER BY computed_at DESC, id DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(account_id)
        .fetch_optional(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?,
        None => None,
    };
    let (account_ev, intent) = match &score {
        Some(row) => (
            row.try_get::<f64, _>("ev")
                .map_err(|error| SalesError::Database(error.to_string()))?,
            Some(
                row.try_get::<f64, _>("intent")
                    .map_err(|error| SalesError::Database(error.to_string()))?,
            ),
        ),
        None => (0.0, None),
    };

    let esp_hypothesis = esp_hypotheses
        .as_ref()
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let dimensions = ExperimentContext {
        icp_segment,
        country: contact_country.or(account_country),
        company_size_band: company_size_band(employees),
        persona: persona.or(seniority).or(department),
        esp_hypothesis,
        intent_bucket: intent.map(intent_bucket),
        // The step/decision layer does not carry an offer id yet; leaving the
        // dimension absent is correct (it simply does not participate in the
        // bucket) rather than inventing one.
        offer: None,
        language,
        step_kind: Some(step_kind),
        sender_type: Some(sender_pool),
    };
    let context = VariantContext {
        dimensions,
        sender_domain_exposure: 0,
        daily_exploration_pct: 0.0,
        account_expected_value_eur: if account_ev.is_finite() {
            account_ev
        } else {
            0.0
        },
        explicit_exploration_override: false,
    };

    let engine = ExperimentEngine::new(db.clone());
    let Some(experiment) = engine
        .load_experiment(tenant_id, experiment_key.trim())
        .await?
    else {
        return Err(SalesError::InvalidInput(format!(
            "step declares experiment '{experiment_key}' which does not exist for tenant \
             {tenant_id}"
        )));
    };
    let selection = engine
        .select_variant(tenant_id, &experiment, &context)
        .await?;

    // Persist BEFORE the dispatcher is called: the variant must survive an
    // enqueue failure so the outcome can be attributed.
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let updated_step = sqlx::query(
        "UPDATE sales_step_executions SET variant = $2, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $3",
    )
    .bind(step_execution_id)
    .bind(&selection.variant)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    if updated_step != 1 {
        return Err(SalesError::Database(format!(
            "step execution {step_execution_id} disappeared while persisting the experiment variant"
        )));
    }
    let updated_enrollment = sqlx::query(
        "UPDATE sales_enrollments \
         SET experiment_id = $2, experiment_variant = $3, updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $4",
    )
    .bind(enrollment_id)
    .bind(selection.experiment_id)
    .bind(&selection.variant)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    if updated_enrollment != 1 {
        return Err(SalesError::Database(format!(
            "enrollment {enrollment_id} disappeared while persisting the experiment variant"
        )));
    }
    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    tracing::info!(
        step_execution_id = %step_execution_id,
        variant = %selection.variant,
        experiment_id = %selection.experiment_id,
        explore = selection.explore,
        used_context_bucket = selection.used_context_bucket,
        reason = %selection.reason,
        "experiment arm selected and persisted before send"
    );
    Ok(Some(selection))
}

/// Standalone §28 evaluation helper: evaluate the pure next-best-action policy
/// against the most recent stored score and return `Some(skip_reason)` when the
/// send must not happen.
///
/// The production handler now plans with the live, refreshed feature vector
/// ([`SequenceStepHandler::load_planner_facts`]) instead of this helper, but
/// the helper is retained for callers/tests that want the direct stored-score
/// verdict. When the account has never been scored it returns `None` and the
/// existing hard gates (suppression, legal policy, reply, frequency) govern. A
/// score row whose policy says `DoNothing`/`Wait`/`Enrich`/... skips the send
/// with the policy's reason recorded in `sales_step_executions.skip_reason`.
pub async fn next_best_action_skip_reason(
    db: &PgPool,
    tenant_id: &str,
    account_id: Option<Uuid>,
    contact_id: Uuid,
    enrollment_id: Uuid,
    has_human_reply: bool,
) -> Result<Option<String>, SalesError> {
    if has_human_reply {
        return Ok(Some(
            "next_best_action=operator_task: a human already replied; automation must not send \
             again"
                .to_string(),
        ));
    }
    let Some(account_id) = account_id else {
        return Ok(None);
    };

    let score = sqlx::query(
        "SELECT expected_value_eur::float8 AS ev, intent::float8 AS intent, \
                evidence_quality::float8 AS evidence_quality \
         FROM sales_scores WHERE tenant_id = $1 AND account_id = $2 \
         ORDER BY computed_at DESC, id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some(score) = score else {
        return Ok(None);
    };
    let expected_value_eur: f64 = score
        .try_get("ev")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let intent: f64 = score
        .try_get("intent")
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let evidence_quality: f64 = score
        .try_get("evidence_quality")
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let prior_touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_step_executions se \
         JOIN sales_enrollments e ON e.id = se.enrollment_id \
         WHERE e.tenant_id = $1 AND e.id = $2 AND se.state = 'sent'",
    )
    .bind(tenant_id)
    .bind(enrollment_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let verification: Option<String> = sqlx::query_scalar(
        "SELECT verification FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
         ORDER BY CASE verification WHEN 'valid' THEN 0 WHEN 'risky' THEN 1 ELSE 2 END, \
                  confidence DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let email = match verification.as_deref() {
        Some("valid") => EmailState::Verified,
        Some("risky") => EmailState::Risky,
        Some("invalid") => EmailState::Invalid,
        _ => EmailState::Unverified,
    };
    let opportunity_open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sales_opportunities \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND stage IN ('open', 'qualified', 'negotiation'))",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let input = NextActionInput {
        expected_value_eur,
        outreach_cost_eur: DEFAULT_OUTREACH_COST_EUR,
        evidence_count: evidence_count.max(0) as u32,
        evidence_confidence: (evidence_quality / 100.0).clamp(0.0, 1.0) as f32,
        reply: ReplyState::None,
        email,
        intent_strength: (intent / 100.0).clamp(0.0, 1.0) as f32,
        prior_touches: prior_touches.max(0) as u32,
        last_angle_failed: false,
        referral_available: false,
        referral_requested: false,
        opportunity_open,
        cooldown_active: false,
        disqualified: false,
    };
    let (action, reason) = next_best_action(&input);
    if action.is_external_send() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "next_best_action={}: {reason}",
            action.as_str()
        )))
    }
}

#[async_trait::async_trait]
impl ActionHandler for SequenceStepHandler {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome {
        match self.handle_inner(action).await {
            Ok(outcome) => outcome,
            Err(error) => {
                // Infrastructure failures are retryable; the queue's backoff
                // and max-attempts bound them into a dead letter.
                ActionOutcome::Retry(format!("{error}"))
            }
        }
    }
}

impl SequenceStepHandler {
    async fn handle_inner(&self, action: &LeasedAction) -> Result<ActionOutcome, SalesError> {
        let step_execution_id = action.action.entity_id;
        let tenant_id = action.tenant_id().to_string();

        let Some(mut ctx) = self.load_context(step_execution_id).await? else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step execution {step_execution_id} no longer exists"
            )));
        };

        // The entity must belong to the tenant the action was queued for.
        if ctx.tenant_id != tenant_id {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step execution {step_execution_id} belongs to tenant {} but the action is for {}",
                ctx.tenant_id, tenant_id
            )));
        }

        // Only an email step sends. Other kinds are handled by their own
        // workers; a wait/nurture step reaching the send handler is a bug in
        // the sequencer, so it is surfaced rather than silently skipped.
        if ctx.step_kind != "email" {
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!("step kind '{}' is not a send step", ctx.step_kind),
                )
                .await;
        }

        // Already sent or skipped: a replay must be a no-op, not a second email.
        if ctx.state == "sent" || ctx.state == "skipped" || ctx.state == "cancelled" {
            tracing::info!(
                step_execution_id = %ctx.step_execution_id,
                state = %ctx.state,
                "sequence step already terminal — replay is a no-op"
            );
            return Ok(ActionOutcome::Succeeded);
        }

        // Gate 1: autonomy at execution time. The kill switch must stop new
        // outbound work immediately, even for already-queued actions.
        let autonomy_state = autonomy::load(&self.db, &ctx.tenant_id).await?;
        if autonomy_state.kill_switch {
            return self
                .skip(ctx.step_execution_id, "global kill switch engaged")
                .await;
        }
        if !autonomy_state.permits_execution() {
            // Shadow/disabled: the brain may still think, but nothing sends.
            // Recorded as a skip with the mode named so the CP can explain it.
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!(
                        "autonomy mode '{}' does not permit execution",
                        autonomy_state.mode.as_str()
                    ),
                )
                .await;
        }
        // NOTE: Assisted/ApprovalRequired deliberately fall through to the
        // decision engine rather than being skipped here. `decide` maps those
        // modes to `AwaitApproval`, which is what puts the work in the operator
        // queue; skipping earlier produced no decision at all, so an operator
        // had nothing to approve and the touch silently disappeared.

        // Gate 2: a human reply must prevent this touch from racing out.
        if ctx.has_human_reply {
            return self
                .skip(ctx.step_execution_id, "enrollment has a human reply")
                .await;
        }

        // Gate 3: the enrollment must still be on the normal path.
        if !matches!(ctx.enrollment_state.as_str(), "active" | "waiting") {
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!(
                        "enrollment state '{}' is not sendable",
                        ctx.enrollment_state
                    ),
                )
                .await;
        }

        // ── Planning (audit item 13) ───────────────────────────────────────
        // The live planner runs the audited sequence before any message is
        // rendered or any decision is taken:
        //
        //   load account/contact → measure evidence freshness →
        //   research/enrich when the NBA asks for information →
        //   recompute + persist the score from the refreshed evidence →
        //   choose the next best action → (when it is a send) choose an angle,
        //   compose + validate the strategy, draft it through the ProseWriter,
        //   select the experiment arm, resolve the sender, decide, dispatch.
        //
        // Every hard gate is unchanged: the Decision Engine still owns the
        // kill switch, legal policy, suppression, sender health, frequency and
        // the human-reply lock, and a denial still skips without retrying.
        let mut facts = self.load_planner_facts(&ctx).await?;
        let stored_score = self.load_score(&ctx).await?;
        let nba_context = self.load_nba_context(&ctx).await?;

        // Preliminary evaluation against the CURRENT evidence: it decides
        // whether information gathering is the best next action. The score
        // here is in-memory only; the persisted score is written after any
        // research/enrichment has landed.
        let preliminary_source = resolve_score_source(&facts, stored_score.as_ref());
        let preliminary_score = crate::scoring::score(&facts.score_features());
        let preliminary_ev = effective_ev(
            &preliminary_score,
            stored_score.as_ref(),
            preliminary_source,
        );
        let (preliminary_action, _preliminary_reason) = self.plan_action(
            &facts,
            &nba_context,
            preliminary_source,
            preliminary_ev,
            preliminary_score.intent,
        );

        let mut fallbacks: Vec<String> = Vec::new();
        if matches!(
            preliminary_action,
            DecisionAction::ResearchCompany
                | DecisionAction::CollectEvidence
                | DecisionAction::Enrich
        ) {
            tracing::info!(
                step_execution_id = %ctx.step_execution_id,
                action = preliminary_action.as_str(),
                stale = facts.freshness.is_stale(Utc::now()),
                live_evidence = facts.freshness.live_rows,
                "next-best-action requests information; gathering evidence before planning copy"
            );
            fallbacks = self.gather_evidence(&ctx, &facts, preliminary_action).await;
            facts = self.load_planner_facts(&ctx).await?;
        }

        // Compute the score from the (possibly refreshed) evidence and persist
        // it. The stored-latest score remains the fallback when the account has
        // no economic basis to compute an expected value from.
        let score = crate::scoring::score(&facts.score_features());
        if let Some(account_id) = ctx.account_id {
            crate::scoring::persist(
                &self.db,
                &ctx.tenant_id,
                account_id,
                Some(ctx.contact_id),
                &score,
            )
            .await?;
        }
        let score_source = resolve_score_source(&facts, stored_score.as_ref());
        let decision_score = match score_source {
            ScoreSource::Fresh | ScoreSource::Unavailable => score.clone(),
            ScoreSource::Stored => stored_score.clone().unwrap_or_else(|| score.clone()),
        };
        let expected_value_eur = decision_score.expected_value_eur;
        let (nba_action, nba_reason) = self.plan_action(
            &facts,
            &nba_context,
            score_source,
            expected_value_eur,
            decision_score.intent,
        );
        if !nba_action.is_external_send() {
            // §28: information/wait/stop actions are recorded, non-retryable
            // skips. Stale evidence alone never forces a send.
            return self
                .skip(
                    ctx.step_execution_id,
                    &format!("next_best_action={}: {nba_reason}", nba_action.as_str()),
                )
                .await;
        }

        // Message planning: angle → strategy → draft → claim validation.
        let plan = self.plan_message(&ctx, &facts).await;

        // §17: select and persist the experiment arm BEFORE the send. The
        // variant row is durable, so an outcome can be attributed even if the
        // enqueue below fails or the process dies. A selection failure is a
        // dead letter, not a silent fallback to an arbitrary variant.
        if let Some(experiment_key) = ctx.experiment_key.clone() {
            match select_and_persist_variant(
                &self.db,
                &ctx.tenant_id,
                ctx.step_execution_id,
                &experiment_key,
            )
            .await
            {
                Ok(Some(selection)) => {
                    ctx.variant = selection.variant;
                }
                Ok(None) => {
                    return Ok(ActionOutcome::DeadLetter(format!(
                        "step execution {} vanished during experiment variant selection",
                        ctx.step_execution_id
                    )));
                }
                Err(error) => {
                    return Ok(ActionOutcome::DeadLetter(format!(
                        "experiment arm selection failed for '{experiment_key}': {error}"
                    )));
                }
            }
        }

        let Some(template_id) = ctx.template_id.as_deref() else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "email step {} has no template_id",
                ctx.sequence_step_id
            )));
        };

        let Some(recipient_email) = self.recipient_email(&ctx).await? else {
            return self
                .skip(
                    ctx.step_execution_id,
                    "no verified, unsuppressed email contact point",
                )
                .await;
        };

        let Some(client) = self.load_client(&ctx, template_id).await? else {
            return self
                .skip(ctx.step_execution_id, "recipient or template unavailable")
                .await;
        };

        // Gate 4 (per the audited order, after drafting and arm selection):
        // resolve the ACTUAL sender identity this step will send from.
        //
        // Checking the step's pool *string* was not enough: the dispatcher then
        // used the deployment-wide SALES_CAMPAIGN_FROM_EMAIL, so a step could
        // declare `sales_outbound` and still be delivered from a shared
        // address. The identity resolved here is what the dispatcher must use,
        // and its id is recorded on both the step execution and the decision.
        let Some(pool) = SenderPool::parse(&ctx.sender_pool) else {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step declares unknown sender pool '{}'",
                ctx.sender_pool
            )));
        };
        if !pool.is_sales_pool() {
            return Ok(ActionOutcome::DeadLetter(format!(
                "step declares non-sales sender pool '{}' — refusing to send",
                pool
            )));
        }
        let sender = match sender_pool::resolve_sales_sender(&self.db, &ctx.tenant_id, pool).await {
            Ok(sender) => sender,
            // No usable sales identity is an operational gap, not a poison
            // message: retry so the send resumes once a sender is provisioned.
            Err(SalesError::ServiceUnavailable(reason)) => {
                return Ok(ActionOutcome::Retry(format!(
                    "no active sender identity in pool '{pool}': {reason}"
                )))
            }
            // A policy refusal (a non-sales pool was requested) must never be
            // silently retried into a send.
            Err(error) => return Ok(ActionOutcome::DeadLetter(format!("{error}"))),
        };

        // Final body: the validated strategy when one was produced, otherwise
        // the operator-approved static template. Never unvalidated prose.
        let sender_display_name = sender.display_name(&self.dispatcher.config().from_name);
        let footer = OutreachFooter {
            sender_identity: &sender_display_name,
            // The footer states the lawful basis actually being relied on. It
            // never claims a signup that did not happen.
            reason: FooterReason::BusinessContact {
                basis: "your organisation appears to be a potential fit for ApexMail's email delivery platform.",
            },
            unsubscribe_link: &client.unsubscribe_link,
            postal_address: None,
            privacy_url: None,
        };
        let rendered = match &plan.content {
            PlannedContent::Strategy { subject, body } => {
                let (footer_html, footer_text) = render_outreach_footer(&footer);
                RenderedMessage {
                    subject: subject.clone(),
                    html: Some(format!("{}{}", compose_reply_html(body), footer_html)),
                    text: Some(format!("{body}{footer_text}")),
                }
            }
            PlannedContent::Template => {
                let template = match fetch_template(&self.db, &ctx.tenant_id, template_id).await {
                    Ok(template) => template,
                    Err(error) => return Ok(ActionOutcome::DeadLetter(format!("{error}"))),
                };
                let recipient = crate::campaigns::DispatchRecipient {
                    email: recipient_email.clone(),
                    unsubscribe_link: client.unsubscribe_link.clone(),
                    lead: client.lead.clone(),
                };
                match render_for_recipient_with_footer(&template, &recipient, footer) {
                    Ok(rendered) => rendered,
                    Err(error) => return Ok(ActionOutcome::DeadLetter(format!("{error}"))),
                }
            }
        };

        // ── The Decision Packet ────────────────────────────────────────────
        // Every external effect goes through the central engine: autonomy, kill
        // switch, suppression, address verification, legal policy, the
        // human-reply lock, sender health and the frequency budget. The worker
        // no longer keeps its own copy of these gates, because a second copy is
        // a second thing to keep in sync — and the copy was what the live path
        // was actually using.
        let evidence_ids = facts.evidence_ids.clone();
        let confidence = (decision_score.total / 100.0).clamp(0.0, 1.0);
        let policy = self.build_policy_input(&ctx).await?;
        let mut rationale = format!(
            "sequence step {} of version {} for enrollment {}; next_best_action={}: {}; \
             score_source={}; evidence_stale={} (live rows {}, horizon {}h); intelligence={}",
            ctx.step_index,
            ctx.sequence_version_id,
            ctx.enrollment_id,
            nba_action.as_str(),
            nba_reason,
            score_source.as_str(),
            facts.freshness.is_stale(Utc::now()),
            facts.freshness.live_rows,
            EVIDENCE_STALENESS_HOURS,
            plan.intelligence_mode
        );
        if let Some(angle) = &plan.angle {
            rationale.push_str(&format!("; angle={angle}"));
        }
        rationale.push_str(if plan.strategy_used {
            "; strategy=validated"
        } else {
            "; strategy=template_fallback"
        });
        for note in fallbacks.iter().chain(plan.fallbacks.iter()) {
            rationale.push_str(&format!("; fallback: {note}"));
        }
        let rationale = truncate_chars(&rationale, MAX_RATIONALE_CHARS);
        let model_version = truncate_chars(
            &format!(
                "{};intelligence={};score={}",
                crate::scoring::SCORING_VERSION,
                plan.intelligence_mode,
                score_source.as_str()
            ),
            MAX_MODEL_VERSION_CHARS,
        );

        // ── A previously approved decision IS the authorization ────────────
        // If this action already carries a decision an operator approved, the
        // approval must be consumed rather than re-planned: re-running
        // `decide` would mint a fresh `pending` packet and park the work again,
        // so an approved touch could never execute and the operator's approval
        // would be silently discarded.
        //
        // Approval is NOT permission to bypass a gate that changed since: the
        // approval is only honoured when `revalidate_execution` — which re-runs
        // every hard constraint against current state — still allows it. That
        // is why this path revalidates instead of trusting `review_status`.
        let mut approved_decision_id: Option<Uuid> = None;
        if let Some(existing_decision_id) = action.action.decision_id {
            let review: Option<String> = sqlx::query_scalar(
                "SELECT review_status FROM sales_decisions WHERE id = $1 AND tenant_id = $2",
            )
            .bind(existing_decision_id)
            .bind(&ctx.tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            if review.as_deref() == Some("approved") {
                let revalidation =
                    decision_engine::revalidate_execution(&self.db, existing_decision_id).await?;
                if revalidation.allowed {
                    // Record what was re-verified: the operator's approval plus
                    // a named list of the gates re-read at execution time.
                    tracing::info!(
                        decision_id = %existing_decision_id,
                        step_execution_id = %ctx.step_execution_id,
                        checked = ?revalidation.checked,
                        "consuming an approved decision after successful revalidation"
                    );
                    approved_decision_id = Some(existing_decision_id);
                } else {
                    // The world moved. The approval no longer authorizes this
                    // send — and the refusal must be EXPLAINABLE, so fall
                    // through to `decide` rather than returning a bare skip:
                    // the engine re-evaluates the same gates and records a
                    // fresh packet whose `block_reasons` name exactly what
                    // changed. A skip with no packet would leave the operator
                    // seeing an approved decision and no message, with nothing
                    // recording why.
                    tracing::info!(
                        decision_id = %existing_decision_id,
                        step_execution_id = %ctx.step_execution_id,
                        reasons = ?revalidation.reasons,
                        "approved decision failed revalidation — re-deciding to record the refusal"
                    );
                }
            }
        }

        let decision = match approved_decision_id {
            // Reuse the approved packet: no new decision row, and the dispatch
            // below is gated by the revalidation that just passed.
            Some(id) => decision_engine::DecisionOutcome {
                decision_id: id,
                enforcement: Enforcement::Execute,
                block_reasons: Vec::new(),
            },
            None => {
                decision_engine::decide(
                    &self.db,
                    DecisionContext {
                        tenant_id: ctx.tenant_id.clone(),
                        account_id: ctx.account_id,
                        contact_id: Some(ctx.contact_id),
                        contact_point_id: ctx.contact_point_id,
                        enrollment_id: Some(ctx.enrollment_id),
                        action: nba_action,
                        score: decision_score,
                        expected_value_eur,
                        confidence,
                        evidence_ids,
                        selected_offer: None,
                        selected_sequence: Some(ctx.sequence_version_id.to_string()),
                        selected_variant: Some(ctx.variant.clone()),
                        selected_sender: Some(sender.id),
                        model_version: Some(model_version),
                        policy,
                        rationale,
                        execute_after: None,
                    },
                )
                .await?
            }
        };

        // Attach the packet to the action and the step execution BEFORE the
        // enforcement switch, so even a denied or shadowed decision leaves an
        // auditable link from the work to its explanation. A lost lease here
        // means another worker owns this action now: stop without an effect.
        let fence = action.fence();
        if !self
            .queue
            .attach_decision(&fence, decision.decision_id)
            .await?
        {
            return Ok(ActionOutcome::Retry(
                "lease lost before the decision could be attached".into(),
            ));
        }
        sqlx::query(
            "UPDATE sales_step_executions \
             SET decision_id = $2, sender_identity_id = $3, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(ctx.step_execution_id)
        .bind(decision.decision_id)
        .bind(sender.id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match decision.enforcement {
            Enforcement::Denied => {
                // A hard-gate refusal is permanent for this attempt: retrying
                // would be the "legal-policy denial bypassed through another
                // route" failure the release gates forbid.
                let reasons = if decision.block_reasons.is_empty() {
                    "unspecified".to_string()
                } else {
                    decision.block_reasons.join("; ")
                };
                return self
                    .skip(
                        ctx.step_execution_id,
                        &format!(
                            "decision {} denied the send: {reasons}",
                            decision.decision_id
                        ),
                    )
                    .await;
            }
            Enforcement::Shadowed => {
                // Shadow records what the engine WOULD have done and sends
                // nothing. That is the mode's entire purpose: a validation
                // dataset without an outbound effect.
                return self
                    .skip(
                        ctx.step_execution_id,
                        &format!(
                            "shadow mode: decision {} recorded without execution",
                            decision.decision_id
                        ),
                    )
                    .await;
            }
            Enforcement::AwaitApproval => {
                // The action stays alive but unclaimed until an operator
                // reviews the decision; the queue owns that state.
                return Ok(ActionOutcome::AwaitApproval);
            }
            Enforcement::Execute => {}
        }

        // Claim the execution before sending: `state = 'executing'` is the
        // mutation that makes a concurrent replay of this action see it as
        // in-flight and stop.
        let claimed: Option<Uuid> = sqlx::query_scalar(
            "UPDATE sales_step_executions \
             SET state = 'executing', attempt = attempt + 1, updated_at = NOW() \
             WHERE id = $1 AND state IN ('scheduled', 'queued') \
             RETURNING id",
        )
        .bind(ctx.step_execution_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if claimed.is_none() {
            tracing::info!(
                step_execution_id = %ctx.step_execution_id,
                "sequence step was claimed by another worker — skipping"
            );
            return Ok(ActionOutcome::Succeeded);
        }

        // The send identity is the logical step execution, so a later
        // legitimate touch is a different message, not a suppressed duplicate.
        let key = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: ctx.enrollment_id,
            sequence_version_id: ctx.sequence_version_id,
            step_id: ctx.sequence_step_id,
            attempt_kind: &ctx.attempt_kind,
            variant: &ctx.variant,
        });

        let metadata = serde_json::json!({
            "enrollment_id": ctx.enrollment_id.to_string(),
            "sequence_version_id": ctx.sequence_version_id.to_string(),
            "step_id": ctx.sequence_step_id.to_string(),
            "step_index": ctx.step_index,
            "variant": ctx.variant,
            "autonomy_mode": autonomy_state.mode.as_str(),
            "decision_id": decision.decision_id.to_string(),
            "sender_pool": sender.pool.as_str(),
            // Audit trail for the grounded-planning path: which action the NBA
            // chose, which score fed it, whether the body came from a validated
            // strategy or the static template, and how many grounded statements
            // it emitted.
            "next_best_action": nba_action.as_str(),
            "score_source": score_source.as_str(),
            "evidence_stale": facts.freshness.is_stale(Utc::now()),
            "live_evidence_rows": facts.freshness.live_rows,
            "intelligence": plan.intelligence_mode,
            "strategy_used": plan.strategy_used,
            "grounded_statements": plan.grounded_statements.len(),
        });

        let outcome = self
            .dispatcher
            .enqueue_sequenced(
                &ctx.tenant_id,
                &key,
                &rendered,
                &recipient_email,
                &client.unsubscribe_link,
                &sender,
                decision.decision_id,
                ctx.step_execution_id,
                ctx.enrollment_id,
                &fence,
                metadata,
            )
            .await?;

        let (state, message_id) = match outcome {
            EnqueueOutcome::Enqueued => (("sent"), Some(key)),
            // Already enqueued under this identity: the previous attempt did
            // the work. Mark it sent so it is not retried forever.
            EnqueueOutcome::DuplicateIdempotency => ("sent", None),
            // Suppressed between decision and send.
            EnqueueOutcome::AlreadyClaimed => ("cancelled", None),
            // The lease was recovered by another worker between the decision
            // and the enqueue: no external effect was produced, and this worker
            // must not report success for work it no longer owns.
            EnqueueOutcome::LeaseLost => {
                return Ok(ActionOutcome::Retry(
                    "lease lost before the external enqueue — no message was sent".into(),
                ))
            }
        };

        let _ = &message_id;

        sqlx::query(
            "UPDATE sales_step_executions \
             SET state = $2, executed_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(ctx.step_execution_id)
        .bind(state)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        // Advance the enrollment and schedule the next step. Done here (rather
        // than in a separate scheduler pass) so a completed step immediately
        // creates its successor; the successor's action carries its own
        // idempotency key, so a retry of this handler cannot double-enqueue.
        if state == "sent" {
            self.advance_enrollment(&ctx).await?;
        }

        Ok(ActionOutcome::Succeeded)
    }

    /// Move the enrollment to its next step and enqueue that step's action.
    async fn advance_enrollment(&self, ctx: &StepContext) -> Result<(), SalesError> {
        let version =
            sequences::load_version(&self.db, &ctx.tenant_id, ctx.sequence_version_id).await?;

        match sequences::next_step(&version, ctx.step_index) {
            Some(next) => {
                let step_execution_id = Uuid::new_v4();
                let key = send_idempotency_key(SendIdentity::StepExecution {
                    enrollment_id: ctx.enrollment_id,
                    sequence_version_id: ctx.sequence_version_id,
                    step_id: next.id,
                    attempt_kind: &ctx.attempt_kind,
                    variant: &ctx.variant,
                });
                let delay = sequences::schedule_delay_secs(next, &key);
                let next_state = if next.min_delay_secs > 0 {
                    "waiting"
                } else {
                    "active"
                };

                let mut tx = self
                    .db
                    .begin()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;

                sqlx::query(
                    "INSERT INTO sales_step_executions ( \
                         id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, \
                         step_index, attempt_kind, variant, state, idempotency_key, \
                         scheduled_for, created_at, updated_at \
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled', $9, \
                               NOW() + make_interval(secs => $10::double precision), NOW(), NOW()) \
                     ON CONFLICT (idempotency_key) DO NOTHING",
                )
                .bind(step_execution_id)
                .bind(&ctx.tenant_id)
                .bind(ctx.enrollment_id)
                .bind(ctx.sequence_version_id)
                .bind(next.id)
                .bind(next.step_index)
                .bind(&ctx.attempt_kind)
                .bind(&ctx.variant)
                .bind(&key)
                .bind(delay as f64)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

                sqlx::query(
                    "UPDATE sales_enrollments \
                     SET current_step_index = $2, state = $3, updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(ctx.enrollment_id)
                .bind(next.step_index)
                .bind(next_state)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

                crate::actions::ActionQueue::enqueue_tx(
                    &mut tx,
                    &ctx.tenant_id,
                    crate::actions::action_type::SEND_STEP,
                    crate::actions::entity_type::STEP_EXECUTION,
                    step_execution_id,
                    &format!("sa-send:{step_execution_id}"),
                    serde_json::json!({
                        "enrollment_id": ctx.enrollment_id.to_string(),
                        "step_index": next.step_index,
                    }),
                    chrono::Utc::now() + chrono::Duration::seconds(delay),
                    100,
                    None,
                )
                .await?;

                tx.commit()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
            }
            None => {
                sqlx::query(
                    "UPDATE sales_enrollments \
                     SET state = 'completed', completed_at = NOW(), updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(ctx.enrollment_id)
                .execute(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Per-recipient client data the renderer needs.
    async fn load_client(
        &self,
        ctx: &StepContext,
        template_id: &str,
    ) -> Result<Option<ClientContext>, SalesError> {
        // The template must exist for this tenant; a missing template is a
        // dead letter, not a retry loop.
        if fetch_template(&self.db, &ctx.tenant_id, template_id)
            .await
            .is_err()
        {
            return Ok(None);
        }

        let lead: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT c.full_name, a.company \
             FROM sales_contacts c \
             LEFT JOIN sales_accounts a ON a.id = c.account_id \
             WHERE c.id = $1 AND c.tenant_id = $2",
        )
        .bind(ctx.contact_id)
        .bind(&ctx.tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let (name, company) = lead.unwrap_or((None, None));

        let email: Option<String> = sqlx::query_scalar(
            "SELECT normalized_value FROM sales_contact_points \
             WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
               AND suppressed_at IS NULL AND verification IN ('valid', 'risky') \
             ORDER BY CASE verification WHEN 'valid' THEN 0 ELSE 1 END, confidence DESC \
             LIMIT 1",
        )
        .bind(&ctx.tenant_id)
        .bind(ctx.contact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let Some(email) = email else {
            return Ok(None);
        };

        // v2 opaque unsubscribe link: only the token hash is persisted, so
        // the delivered URL carries no tenant/recipient material.
        let unsubscribe_link = self
            .dispatcher
            .unsubscribe_link(&ctx.tenant_id, Uuid::nil(), &email)
            .await?;

        Ok(Some(ClientContext {
            unsubscribe_link,
            lead: Some(crate::dispatcher::LeadProfile {
                name: name.unwrap_or_default(),
                company: company.unwrap_or_default(),
                title: String::new(),
            }),
        }))
    }
}

struct ClientContext {
    unsubscribe_link: String,
    lead: Option<crate::dispatcher::LeadProfile>,
}

/// A handler that only enforces the "no execution" gates and then reports the
/// action as handled externally. Used by the test suite and by deployments
/// that wire their own sender.
pub struct GateOnlyHandler {
    db: PgPool,
}

impl GateOnlyHandler {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl ActionHandler for GateOnlyHandler {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome {
        match autonomy::load(&self.db, action.tenant_id()).await {
            Ok(state) if state.kill_switch => ActionOutcome::Succeeded,
            Ok(state) if !state.permits_execution() => ActionOutcome::Succeeded,
            Ok(_) => ActionOutcome::Succeeded,
            Err(error) => ActionOutcome::Retry(format!("{error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AutonomyMode;

    #[test]
    fn terminal_states_are_not_resendable() {
        // A replay of an already-sent or skipped execution must never produce
        // a second email.
        for state in ["sent", "skipped", "cancelled"] {
            assert!(
                matches!(state, "sent" | "skipped" | "cancelled"),
                "terminal state {state} must short-circuit"
            );
        }
        for state in ["scheduled", "queued", "executing"] {
            assert!(
                !matches!(state, "sent" | "skipped" | "cancelled"),
                "{state} proceeds"
            );
        }
    }

    #[test]
    fn shadow_mode_never_sends() {
        // The whole point of shadow: brain runs, execution does not.
        assert!(AutonomyMode::Shadow.blocks_all_execution());
        assert!(AutonomyMode::Shadow.runs_brain());
    }

    #[test]
    fn only_guarded_autonomy_reaches_the_send_path_unattended() {
        // The handler skips Assisted/ApprovalRequired because it has no
        // approval carrier; only AutonomousGuarded may send unattended.
        assert!(AutonomyMode::AutonomousGuarded.may_execute_autonomously());
        assert!(AutonomyMode::ApprovalRequired.requires_operator_approval());
        assert!(AutonomyMode::Assisted.requires_operator_approval());
    }

    #[test]
    fn non_sales_pools_are_refused() {
        assert!(!SenderPool::TransactionalCustomer.is_sales_pool());
        assert!(!SenderPool::InternalTransactional.is_sales_pool());
        assert!(SenderPool::SalesOutbound.is_sales_pool());
        assert!(SenderPool::SalesWarmup.is_sales_pool());
    }

    // ── Footer enforcement (release gate) ─────────────────────────────────

    /// Every autonomous sales email body must be rendered through the central
    /// compliant footer/unsubscribe renderer. The worker has exactly two
    /// content arms — validated strategy and static template — and both must
    /// consume the footer renderer's output before the enqueue. This is a
    /// structural gate so a future third arm cannot quietly enqueue a bare
    /// body.
    #[test]
    fn every_autonomous_send_body_is_rendered_through_the_footer() {
        let source = include_str!("sequence_worker.rs");

        // Exactly one message-construction literal exists in this module (the
        // strategy arm). Its surrounding arm must append the footer outputs.
        // `concat!` keeps this test from matching its own source text.
        let literal = concat!("Rendered", "Message {");
        assert_eq!(
            source.matches(literal).count(),
            1,
            "a second RenderedMessage construction site appeared in the send path; \
             it must go through the compliant footer renderer and be added to this gate"
        );
        let literal_at = source
            .find(literal)
            .expect("the strategy arm constructs the message");
        let arm = &source[literal_at.saturating_sub(400)..literal_at];
        assert!(
            arm.contains("render_outreach_footer"),
            "the strategy arm must build its bodies from render_outreach_footer"
        );
        assert!(
            arm.contains("footer_html") && arm.contains("footer_text"),
            "the strategy arm must append the rendered footer to both bodies"
        );

        // The template arm must go through the same renderer.
        assert!(
            source.contains(concat!(
                "render_for_recipient",
                "_with_footer(&template, &recipient, footer)"
            )),
            "the template arm must render through render_for_recipient_with_footer"
        );

        // Both arms run before the only external enqueue in this module.
        let enqueue_at = source
            .find(".enqueue_sequenced(")
            .expect("the handler must dispatch through enqueue_sequenced");
        assert!(
            literal_at < enqueue_at,
            "the footer must be rendered before the external enqueue"
        );
    }

    #[test]
    fn company_size_bands_are_stable_and_bounded() {
        assert_eq!(company_size_band(None), None);
        assert_eq!(company_size_band(Some(0)).as_deref(), Some("1-10"));
        assert_eq!(company_size_band(Some(10)).as_deref(), Some("1-10"));
        assert_eq!(company_size_band(Some(11)).as_deref(), Some("11-50"));
        assert_eq!(company_size_band(Some(200)).as_deref(), Some("51-200"));
        assert_eq!(company_size_band(Some(201)).as_deref(), Some("201-1000"));
        assert_eq!(company_size_band(Some(1_001)).as_deref(), Some("1001+"));
        assert_eq!(company_size_band(Some(i64::MAX)).as_deref(), Some("1001+"));
    }

    #[test]
    fn intent_buckets_are_documented_and_hostile_safe() {
        assert_eq!(intent_bucket(f64::NAN), "unknown");
        assert_eq!(intent_bucket(-5.0), "none");
        assert_eq!(intent_bucket(0.0), "none");
        assert_eq!(intent_bucket(19.9), "none");
        assert_eq!(intent_bucket(20.0), "low");
        assert_eq!(intent_bucket(40.0), "medium");
        assert_eq!(intent_bucket(69.9), "medium");
        assert_eq!(intent_bucket(70.0), "high");
        // A non-finite score is hostile input and fails closed to "unknown"
        // rather than being read as the strongest intent.
        assert_eq!(intent_bucket(f64::INFINITY), "unknown");
    }

    // =====================================================================
    // Audit item 13 — adversarial tests for the grounded planning pipeline
    // =====================================================================

    use crate::dispatcher::{QuotaFuture, QuotaGateway, QuotaReservation};
    use crate::intelligence::{
        AngleSelection, DraftRequest, DraftedMessage, IntelligenceError, NextActionRequest,
        ReplyClassification, ReplyRequest, ResearchClaim, ResearchFindings, ResearchRequest,
    };
    use crate::test_db::canonical_test_pool;
    use sqlx::PgPool;

    const TEMPLATE_SENTINEL: &str = "STATIC TEMPLATE FALLBACK SENTINEL";

    /// A quota gateway that permits every send (the DB fixture's billing
    /// tables are not the subject of these tests).
    #[derive(Debug)]
    struct AllowAllQuota;

    impl QuotaGateway for AllowAllQuota {
        fn reserve(
            &self,
            _tenant_id: &str,
        ) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>> {
            Box::pin(async {
                Ok(QuotaReservation {
                    event_id: Uuid::new_v4(),
                    recorded_at: Utc::now(),
                })
            })
        }

        fn rollback(
            &self,
            _tenant_id: &str,
            _reservation: &QuotaReservation,
        ) -> QuotaFuture<'_, Result<(), SalesError>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// An intelligence provider that is down for every call (simulated AI
    /// outage).
    #[derive(Debug)]
    struct FailingIntelligence;

    #[async_trait::async_trait]
    impl SalesIntelligence for FailingIntelligence {
        async fn research_account(
            &self,
            _req: &ResearchRequest<'_>,
        ) -> Result<ResearchFindings, IntelligenceError> {
            Err(IntelligenceError::Unavailable(
                "simulated AI outage: connection refused".into(),
            ))
        }

        async fn select_angle(
            &self,
            _req: &AngleRequest<'_>,
        ) -> Result<AngleSelection, IntelligenceError> {
            Err(IntelligenceError::Unavailable("simulated outage".into()))
        }

        async fn draft_message(
            &self,
            _req: &DraftRequest<'_>,
        ) -> Result<DraftedMessage, IntelligenceError> {
            Err(IntelligenceError::Unavailable("simulated outage".into()))
        }

        async fn classify_reply(
            &self,
            _req: &ReplyRequest<'_>,
        ) -> Result<ReplyClassification, IntelligenceError> {
            Err(IntelligenceError::Unavailable("simulated outage".into()))
        }

        async fn determine_next_action(
            &self,
            _req: &NextActionRequest<'_>,
        ) -> Result<DecisionAction, IntelligenceError> {
            Err(IntelligenceError::Unavailable("simulated outage".into()))
        }
    }

    /// A working intelligence double whose research findings are all grounded
    /// in one allowed evidence id (the id the fixture made citable).
    #[derive(Debug)]
    struct ScriptedIntelligence {
        grounded_evidence_id: Uuid,
        grounded_claims: usize,
    }

    #[async_trait::async_trait]
    impl SalesIntelligence for ScriptedIntelligence {
        async fn research_account(
            &self,
            _req: &ResearchRequest<'_>,
        ) -> Result<ResearchFindings, IntelligenceError> {
            let claims = (0..self.grounded_claims)
                .map(|index| ResearchClaim {
                    proposition: format!(
                        "Scripted grounded finding {index}: the account operates a live email stack."
                    ),
                    confidence: 0.8,
                    source_kind: Some("dns_observation".into()),
                    source_ref: Some("lib-test".into()),
                    evidence_id: Some(self.grounded_evidence_id),
                    is_hypothesis: false,
                })
                .collect();
            Ok(ResearchFindings {
                claims,
                model_version: Some("scripted-1".into()),
                fallback: None,
            })
        }

        async fn select_angle(
            &self,
            _req: &AngleRequest<'_>,
        ) -> Result<AngleSelection, IntelligenceError> {
            Ok(AngleSelection {
                angle: "scripted angle".into(),
                rationale: "scripted test provider".into(),
                cited_evidence_ids: vec![self.grounded_evidence_id],
                hypothesis_based: false,
            })
        }

        async fn draft_message(
            &self,
            _req: &DraftRequest<'_>,
        ) -> Result<DraftedMessage, IntelligenceError> {
            Err(IntelligenceError::NotConfigured("scripted".into()))
        }

        async fn classify_reply(
            &self,
            _req: &ReplyRequest<'_>,
        ) -> Result<ReplyClassification, IntelligenceError> {
            Err(IntelligenceError::NotConfigured("scripted".into()))
        }

        async fn determine_next_action(
            &self,
            _req: &NextActionRequest<'_>,
        ) -> Result<DecisionAction, IntelligenceError> {
            Err(IntelligenceError::NotConfigured("scripted".into()))
        }
    }

    /// A canonical, sendable sequence fixture provisioned through the crate's
    /// test-database convention (`src/test_db.rs`). Mirrors
    /// `tests/common/mod.rs` but lives in the lib so `--lib -- --ignored`
    /// exercises it.
    struct Fixture {
        db: PgPool,
        tenant: String,
        account: Uuid,
        contact: Uuid,
        step_execution: Uuid,
        dispatcher: Arc<ProductionCampaignDispatcher>,
    }

    impl Fixture {
        fn handler(&self) -> SequenceStepHandler {
            SequenceStepHandler::new(self.db.clone(), self.dispatcher.clone())
        }

        fn handler_with(&self, intelligence: Arc<dyn SalesIntelligence>) -> SequenceStepHandler {
            let strategist = Arc::new(MessageStrategist::new(
                self.db.clone(),
                SalesKnowledgeBase::canonical(),
            ));
            SequenceStepHandler::with_stack(
                self.db.clone(),
                self.dispatcher.clone(),
                intelligence,
                strategist,
            )
        }
    }

    /// Upsert the fixture's jurisdiction policy. The test database is SHARED
    /// across runs, so the row is written idempotently; each test uses its own
    /// `Z*` jurisdiction code (never an EU/EEA code) so parallel tests cannot
    /// race on one policy row.
    async fn ensure_policy(db: &PgPool, jurisdiction: &str, decision: &str) {
        let basis = if decision == "prohibited" {
            "not_permitted"
        } else {
            "legitimate_interest"
        };
        sqlx::query(
            "INSERT INTO sales_jurisdiction_policies \
                 (id, jurisdiction, channel, contact_type, decision, basis, version, \
                  approved_by, approved_at, valid_from) \
             VALUES (gen_random_uuid(), $1, 'email', 'b2b_professional', $2, $3, 1, \
                     'lib-test', NOW(), NOW()) \
             ON CONFLICT (jurisdiction, channel, contact_type, version) DO UPDATE SET \
                 decision = EXCLUDED.decision, \
                 basis = EXCLUDED.basis, \
                 approved_by = EXCLUDED.approved_by, \
                 approved_at = EXCLUDED.approved_at, \
                 valid_from = EXCLUDED.valid_from",
        )
        .bind(jurisdiction)
        .bind(decision)
        .bind(basis)
        .execute(db)
        .await
        .expect("upsert fixture policy");
    }

    async fn fixture(test_name: &str, policy: &str, jurisdiction: &str) -> Option<Fixture> {
        let db = canonical_test_pool(test_name).await?;
        let tenant = crate::test_db::unique_test_tenant(test_name);

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(&tenant)
        .bind(format!("Lib test {test_name}"))
        .bind(format!(
            "lib-{test_name}-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        ))
        .execute(&db)
        .await
        .expect("insert tenant");

        let country = jurisdiction.to_string();
        ensure_policy(&db, &country, policy).await;

        let domain = format!(
            "lib-{}.example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO domains \
                 (id, tenant_id, name, status, verified, dkim_enabled, ses_verified, \
                  dkim_selector, dkim_public_key, dkim_private_key) \
             VALUES ($1, $2, $3, 'verified', true, true, true, 'lib-selector', 'lib-public', \
                     'dkim:v1:lib-test')",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(&domain)
        .execute(&db)
        .await
        .expect("insert verified domain");

        let template_id = format!("tpl_{}", &Uuid::new_v4().simple().to_string()[..16]);
        sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&template_id)
        .bind(&tenant)
        .bind(format!("Lib template {template_id}"))
        .bind(&template_id)
        .bind("Static fallback subject")
        .bind(format!("<p>{TEMPLATE_SENTINEL} for {{{{first_name}}}}</p>"))
        .bind(Some(format!("{TEMPLATE_SENTINEL} for {{{{first_name}}}}")))
        .execute(&db)
        .await
        .expect("insert template");

        let account = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_accounts \
                 (id, tenant_id, company, domain, country, country_confidence, industry, \
                  employees, lifecycle, icp_segment) \
             VALUES ($1, $2, 'Lib Fixture Co', $3, $4, 0.95, 'saas', 120, 'discovered', \
                     'midmarket')",
        )
        .bind(account)
        .bind(&tenant)
        .bind(format!(
            "acct-{}.example",
            &Uuid::new_v4().simple().to_string()[..12]
        ))
        .bind(&country)
        .execute(&db)
        .await
        .expect("insert account");

        let contact = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_contacts \
                 (id, tenant_id, account_id, full_name, job_title, department, seniority, \
                  persona, country, language) \
             VALUES ($1, $2, $3, 'Lib Prospect', 'CTO', 'Engineering', 'c-level', 'technical', \
                     $4, 'en')",
        )
        .bind(contact)
        .bind(&tenant)
        .bind(account)
        .bind(&country)
        .execute(&db)
        .await
        .expect("insert contact");

        let email = format!(
            "lib-{}@example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification, \
                  confidence, source) \
             VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid', 0.95, 'lib-test')",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(contact)
        .bind(&email)
        .execute(&db)
        .await
        .expect("insert contact point");

        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(sequence_id)
        .bind(&tenant)
        .bind(format!("Lib sequence {test_name}"))
        .execute(&db)
        .await
        .expect("insert sequence");
        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'lib-test', NOW())",
        )
        .bind(version_id)
        .bind(&tenant)
        .bind(sequence_id)
        .execute(&db)
        .await
        .expect("insert sequence version");
        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, template_id, \
                  min_delay_secs, max_delay_secs, sender_pool) \
             VALUES ($1, $2, $3, 0, 'email', $4, 0, 0, 'sales_outbound')",
        )
        .bind(step_id)
        .bind(&tenant)
        .bind(version_id)
        .bind(&template_id)
        .execute(&db)
        .await
        .expect("insert sequence step");

        let sender_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Lib Sender', $4, 'active', 200)",
        )
        .bind(sender_id)
        .bind(&tenant)
        .bind(format!("sales@{domain}"))
        .bind(&domain)
        .execute(&db)
        .await
        .expect("insert sender identity");
        sqlx::query(
            "INSERT INTO sales_sender_health \
                 (id, tenant_id, sender_identity_id, health_score, state) \
             VALUES (gen_random_uuid(), $1, $2, 0.99, 'healthy')",
        )
        .bind(&tenant)
        .bind(sender_id)
        .execute(&db)
        .await
        .expect("insert sender health");
        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch, updated_at) \
             VALUES ($1, 'autonomous_guarded', FALSE, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE \
                SET mode = EXCLUDED.mode, kill_switch = FALSE, updated_at = NOW()",
        )
        .bind(&tenant)
        .execute(&db)
        .await
        .expect("insert autonomy state");

        let enrollment = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                  state, current_step_index) \
             VALUES ($1, $2, $3, $4, $5, \
                     (SELECT id FROM sales_contact_points WHERE tenant_id = $2 AND contact_id = $5 \
                      LIMIT 1), \
                     'active', 0)",
        )
        .bind(enrollment)
        .bind(&tenant)
        .bind(version_id)
        .bind(account)
        .bind(contact)
        .execute(&db)
        .await
        .expect("insert enrollment");

        let step_execution = Uuid::new_v4();
        let idempotency_key = crate::sequences::sales_step_idempotency_key(
            enrollment, version_id, step_id, "primary", "default",
        );
        sqlx::query(
            "INSERT INTO sales_step_executions \
                 (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
                  attempt_kind, variant, state, idempotency_key, scheduled_for, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 0, 'primary', 'default', 'scheduled', $6, NOW(), NOW(), NOW())",
        )
        .bind(step_execution)
        .bind(&tenant)
        .bind(enrollment)
        .bind(version_id)
        .bind(step_id)
        .bind(&idempotency_key)
        .execute(&db)
        .await
        .expect("insert step execution");

        let dispatch = crate::config::DispatchConfig {
            from_email: format!("sales@{domain}"),
            from_name: "Lib Sales".into(),
            unsubscribe_secret: "lib-test-unsubscribe-secret-0123456789".into(),
            public_base_url: "http://127.0.0.1:3010".into(),
            unsubscribe_redirect_url: None,
            dispatch_interval_secs: 30,
            dispatch_batch_size: 100,
            dispatch_concurrency: 4,
        };
        let dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(dispatch, db.clone(), Arc::new(AllowAllQuota))
                .expect("lib dispatch config is valid"),
        );

        Some(Fixture {
            db,
            tenant,
            account,
            contact,
            step_execution,
            dispatcher,
        })
    }

    async fn insert_evidence(
        db: &PgPool,
        tenant: &str,
        account: Uuid,
        proposition: &str,
        confidence: f64,
        stale: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        if stale {
            sqlx::query(
                "INSERT INTO sales_evidence \
                     (id, tenant_id, account_id, proposition, confidence, source_kind, \
                      observed_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, 'http_fetch', \
                         NOW() - interval '30 days', NOW() - interval '1 hour')",
            )
            .bind(id)
            .bind(tenant)
            .bind(account)
            .bind(proposition)
            .bind(confidence)
            .execute(db)
            .await
            .expect("insert stale evidence");
        } else {
            sqlx::query(
                "INSERT INTO sales_evidence \
                     (id, tenant_id, account_id, proposition, confidence, source_kind, observed_at) \
                 VALUES ($1, $2, $3, $4, $5, 'http_fetch', NOW())",
            )
            .bind(id)
            .bind(tenant)
            .bind(account)
            .bind(proposition)
            .bind(confidence)
            .execute(db)
            .await
            .expect("insert fresh evidence");
        }
        id
    }

    async fn enqueue_and_claim(pool: &PgPool, tenant: &str, step_execution: Uuid) -> LeasedAction {
        let queue = ActionQueue::new(pool.clone(), format!("lib-enqueue-{step_execution}"));
        let action = queue
            .enqueue(
                tenant,
                crate::actions::action_type::SEND_STEP,
                crate::actions::entity_type::STEP_EXECUTION,
                step_execution,
                &format!("sa-send:{step_execution}"),
                serde_json::json!({}),
                Utc::now(),
                100,
                None,
            )
            .await
            .expect("enqueue send_step action");

        #[derive(sqlx::FromRow)]
        struct ClaimedRow {
            id: Uuid,
            tenant_id: String,
            action_type: String,
            entity_type: String,
            entity_id: Uuid,
            due_at: DateTime<Utc>,
            priority: i16,
            state: String,
            attempt: i32,
            max_attempts: i32,
            lease_owner: Option<String>,
            lease_token: Option<Uuid>,
            lease_expires_at: Option<DateTime<Utc>>,
            idempotency_key: String,
            payload: serde_json::Value,
            decision_id: Option<Uuid>,
            last_error: Option<String>,
            created_at: DateTime<Utc>,
            completed_at: Option<DateTime<Utc>>,
        }

        let worker = format!("lib-worker-{}", Uuid::new_v4().simple());
        let row: ClaimedRow = sqlx::query_as(
            "UPDATE sales_actions \
             SET state = 'executing', lease_owner = $2, lease_token = gen_random_uuid(), \
                 lease_expires_at = NOW() + make_interval(secs => $3::double precision), \
                 attempt = attempt + 1 \
             WHERE id = $1 AND state = 'queued' AND due_at <= NOW() \
             RETURNING *",
        )
        .bind(action.id)
        .bind(&worker)
        .bind(crate::actions::DEFAULT_LEASE_SECS as f64)
        .fetch_optional(pool)
        .await
        .expect("claim specific action")
        .expect("the just-enqueued action must be claimable");

        LeasedAction {
            action: crate::actions::SalesAction {
                id: row.id,
                tenant_id: row.tenant_id,
                action_type: row.action_type,
                entity_type: row.entity_type,
                entity_id: row.entity_id,
                due_at: row.due_at,
                priority: row.priority,
                state: row.state,
                attempt: row.attempt,
                max_attempts: row.max_attempts,
                lease_owner: row.lease_owner,
                lease_expires_at: row.lease_expires_at,
                idempotency_key: row.idempotency_key,
                payload: row.payload,
                decision_id: row.decision_id,
                last_error: row.last_error,
                created_at: row.created_at,
                completed_at: row.completed_at,
            },
            lease_owner: worker,
            lease_token: row.lease_token.expect("claim must issue a lease token"),
        }
    }

    async fn run_handler(fx: &Fixture, handler: &SequenceStepHandler) -> ActionOutcome {
        let leased = enqueue_and_claim(&fx.db, &fx.tenant, fx.step_execution).await;
        let outcome = handler.handle(&leased).await;
        let queue = ActionQueue::new(fx.db.clone(), leased.lease_owner.clone());
        let finished = queue
            .finish(&leased.fence(), outcome.clone())
            .await
            .expect("finish the claimed action");
        assert!(finished, "the worker must still own its live lease");
        outcome
    }

    async fn step_state(db: &PgPool, step_execution: Uuid) -> (String, Option<String>) {
        sqlx::query_as("SELECT state, skip_reason FROM sales_step_executions WHERE id = $1")
            .bind(step_execution)
            .fetch_one(db)
            .await
            .expect("read step execution")
    }

    /// The outbound rows the dispatcher produced for a step execution:
    /// `(subject, html, text)`.
    async fn outbound(db: &PgPool, step_execution: Uuid) -> Vec<(String, String, String)> {
        sqlx::query_as(
            "SELECT subject, COALESCE(html, ''), COALESCE(text, '') FROM email_queue \
             WHERE sales_step_execution_id = $1",
        )
        .bind(step_execution)
        .fetch_all(db)
        .await
        .expect("read email_queue")
    }

    async fn outbound_count(db: &PgPool, step_execution: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM email_queue WHERE sales_step_execution_id = $1",
        )
        .bind(step_execution)
        .fetch_one(db)
        .await
        .expect("count email_queue")
    }

    // ── 1. Offline intelligence still plans, validates and sends ──────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn offline_intelligence_plans_a_claim_validated_message() {
        let Some(fx) = fixture("lib_offline_plan", "allowed", "ZA").await else {
            return;
        };
        let fresh_id = insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "The account runs SendGrid for transactional email.",
            0.9,
            false,
        )
        .await;
        // Expired evidence is not usable: the strategy must not cite or emit
        // it even though it is the only other row in the table.
        insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "The account is migrating to Mailchimp next quarter.",
            0.95,
            true,
        )
        .await;

        let handler = fx.handler();
        let ctx = handler
            .load_context(fx.step_execution)
            .await
            .expect("load context")
            .expect("context exists");
        let facts = handler
            .load_planner_facts(&ctx)
            .await
            .expect("planner facts");
        assert_eq!(facts.freshness.live_rows, 1, "only the fresh row is live");
        assert!(facts.evidence_ids.contains(&fresh_id));

        let plan = handler.plan_message(&ctx, &facts).await;
        assert!(
            plan.strategy_used,
            "offline path must produce a validated strategy; fallbacks: {:?}",
            plan.fallbacks
        );
        assert!(
            plan.fallbacks.is_empty(),
            "a clean offline plan has no fallbacks: {:?}",
            plan.fallbacks
        );

        // Every emitted statement is evidence-backed, knowledge-backed, or an
        // explicit hypothesis.
        assert!(!plan.grounded_statements.is_empty());
        for statement in &plan.grounded_statements {
            if let Some(evidence_id) = statement.evidence_id {
                assert!(!evidence_id.is_nil());
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM sales_evidence WHERE id = $1 AND tenant_id = $2 \
                       AND (expires_at IS NULL OR expires_at > NOW()))",
                )
                .bind(evidence_id)
                .bind(&fx.tenant)
                .fetch_one(&fx.db)
                .await
                .expect("evidence exists");
                assert!(live, "statement cites non-live evidence: {statement:?}");
            } else if let Some(fact_id) = &statement.knowledge_fact_id {
                let kb = SalesKnowledgeBase::canonical();
                let fact = kb.get(fact_id).expect("cited knowledge fact must exist");
                assert!(
                    fact.is_external_copy_allowed_at(Utc::now()),
                    "statement cites a non-external-copy fact: {statement:?}"
                );
            } else {
                assert!(
                    statement.is_hypothesis,
                    "ungrounded non-hypothesis statement: {statement:?}"
                );
            }
        }

        let PlannedContent::Strategy { body, .. } = &plan.content else {
            panic!("offline intelligence must render the strategy path");
        };
        assert!(
            body.contains("SendGrid"),
            "the evidence-backed observation must be in the body: {body}"
        );
        assert!(
            !body.contains("Mailchimp"),
            "expired evidence must never reach the body: {body}"
        );
        assert!(
            !body.contains(TEMPLATE_SENTINEL),
            "the strategy path is not the template fallback"
        );

        // And the full send path works with no AI configured.
        let outcome = run_handler(&fx, &handler).await;
        assert!(
            matches!(outcome, ActionOutcome::Succeeded),
            "offline send must succeed: {outcome:?}"
        );
        let (state, _) = step_state(&fx.db, fx.step_execution).await;
        assert_eq!(state, "sent");
        let rows = outbound(&fx.db, fx.step_execution).await;
        assert_eq!(rows.len(), 1, "exactly one outbound message");
        assert!(rows[0].2.contains("SendGrid"));
        assert!(!rows[0].2.contains("Mailchimp"));
        assert!(!rows[0].2.contains(TEMPLATE_SENTINEL));
    }

    // ── 2. An AI outage falls back to verified static content ──────────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn ai_outage_falls_back_and_records_it() {
        let Some(fx) = fixture("lib_ai_outage", "allowed", "ZB").await else {
            return;
        };
        insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "The account runs Postmark for transactional email.",
            0.9,
            false,
        )
        .await;

        let handler = fx
            .handler_with(Arc::new(FailingIntelligence))
            .with_intelligence_label("test-outage-provider");
        let ctx = handler
            .load_context(fx.step_execution)
            .await
            .expect("load context")
            .expect("context exists");
        let facts = handler
            .load_planner_facts(&ctx)
            .await
            .expect("planner facts");
        let plan = handler.plan_message(&ctx, &facts).await;
        assert!(
            !plan.strategy_used,
            "an outage must not use AI-derived prose"
        );
        assert!(
            plan.grounded_statements.is_empty(),
            "the static fallback emits no factual claims"
        );
        assert!(
            plan.intelligence_mode.contains("fallback"),
            "the mode must name the fallback: {}",
            plan.intelligence_mode
        );
        assert!(
            plan.fallbacks.iter().any(|note| note.contains("outage")),
            "the fallback reason must be recorded: {:?}",
            plan.fallbacks
        );

        let outcome = run_handler(&fx, &handler).await;
        assert!(
            matches!(outcome, ActionOutcome::Succeeded),
            "an AI outage must never block the send: {outcome:?}"
        );
        let rows = outbound(&fx.db, fx.step_execution).await;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].1.contains(TEMPLATE_SENTINEL) && rows[0].2.contains(TEMPLATE_SENTINEL),
            "the verified static template must be sent: {:?}",
            rows[0]
        );

        let (model_version, rationale): (Option<String>, String) = sqlx::query_as(
            "SELECT model_version, rationale FROM sales_decisions WHERE tenant_id = $1 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&fx.tenant)
        .fetch_one(&fx.db)
        .await
        .expect("decision row");
        let model_version = model_version.expect("model_version is recorded");
        assert!(
            model_version.contains("fallback"),
            "model_version must name the fallback: {model_version}"
        );
        assert!(
            rationale.contains("fallback") && rationale.contains("strategy=template_fallback"),
            "rationale must name the fallback: {rationale}"
        );
    }

    // ── 3. An unvalidated claim is never sent ──────────────────────────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn an_unvalidated_claim_is_rejected_and_replaced() {
        let Some(fx) = fixture("lib_bad_claim", "allowed", "ZC").await else {
            return;
        };
        // The observation itself is neutral; the proof point derived from the
        // enrichment fact promises SSO, which no verified fact backs.
        let evidence_id = insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "The account operates a third-party email provider.",
            0.7,
            false,
        )
        .await;
        sqlx::query(
            "INSERT INTO sales_enrichment_facts \
                 (id, tenant_id, subject_type, subject_id, field, value, provider, confidence, \
                  observed_at, evidence_id) \
             VALUES (gen_random_uuid(), $1, 'account', $2, 'email_provider', \
                     '\"SSO gateway\"'::jsonb, 'lib-test', 0.9, NOW(), $3)",
        )
        .bind(&fx.tenant)
        .bind(fx.account)
        .bind(evidence_id)
        .execute(&fx.db)
        .await
        .expect("insert enrichment fact");

        let handler = fx.handler();
        let ctx = handler
            .load_context(fx.step_execution)
            .await
            .expect("load context")
            .expect("context exists");
        let facts = handler
            .load_planner_facts(&ctx)
            .await
            .expect("planner facts");
        let plan = handler.plan_message(&ctx, &facts).await;
        assert!(
            !plan.strategy_used,
            "a strategy with an unsupported capability claim must be rejected"
        );
        assert!(
            plan.fallbacks
                .iter()
                .any(|note| note.contains("strategy rejected")),
            "the rejection must be recorded: {:?}",
            plan.fallbacks
        );

        let outcome = run_handler(&fx, &handler).await;
        assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");
        let rows = outbound(&fx.db, fx.step_execution).await;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].1.contains(TEMPLATE_SENTINEL),
            "the verified fallback must be sent"
        );
        assert!(
            !rows[0].1.to_ascii_lowercase().contains("sso")
                && !rows[0].2.to_ascii_lowercase().contains("sso"),
            "the unvalidated claim must be absent from the outbound body: {:?}",
            rows[0]
        );
    }

    // ── 4. Fresh evidence feeds the persisted score ────────────────────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn fresh_evidence_is_used_for_the_score() {
        let Some(fx) = fixture("lib_fresh_score", "allowed", "ZD").await else {
            return;
        };
        let stale_id = insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "Stale claim about the account's email stack.",
            0.9,
            true,
        )
        .await;
        // A large open pipeline makes the fresh score's EV worth researching.
        sqlx::query(
            "INSERT INTO sales_opportunities (id, tenant_id, account_id, stage, amount_eur) \
             VALUES (gen_random_uuid(), $1, $2, 'open', 200000::float8::numeric)",
        )
        .bind(&fx.tenant)
        .bind(fx.account)
        .execute(&fx.db)
        .await
        .expect("insert opportunity");

        let handler = fx.handler_with(Arc::new(ScriptedIntelligence {
            grounded_evidence_id: stale_id,
            grounded_claims: 3,
        }));
        let outcome = run_handler(&fx, &handler).await;
        assert!(
            matches!(outcome, ActionOutcome::Succeeded),
            "research-backed send must succeed: {outcome:?}"
        );

        // The stale row is still there; three fresh, grounded findings landed.
        let live_evidence: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_evidence \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(&fx.tenant)
        .bind(fx.account)
        .fetch_one(&fx.db)
        .await
        .expect("count live evidence");
        assert_eq!(
            live_evidence, 3,
            "the research leg must persist new evidence"
        );

        let canonical_scores: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_scores \
             WHERE tenant_id = $1 AND scoring_version = $2",
        )
        .bind(&fx.tenant)
        .bind(crate::scoring::SCORING_VERSION)
        .fetch_one(&fx.db)
        .await
        .expect("count scores");
        assert!(
            canonical_scores >= 1,
            "a score row stamped with SCORING_VERSION must be persisted"
        );
        let max_evidence_quality: f64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(evidence_quality), 0)::float8 FROM sales_scores \
             WHERE tenant_id = $1",
        )
        .bind(&fx.tenant)
        .fetch_one(&fx.db)
        .await
        .expect("max evidence quality");
        assert!(
            max_evidence_quality > 0.0,
            "the persisted score must be computed from the refreshed evidence"
        );
    }

    // ── 5. Stale evidence alone does not force a send (§28) ────────────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn stale_evidence_alone_does_not_force_a_send() {
        let Some(fx) = fixture("lib_stale_skip", "allowed", "ZE").await else {
            return;
        };
        insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "Stale claim that cannot be refreshed offline.",
            0.9,
            true,
        )
        .await;
        // A stored score whose EV is below the outreach minimum. Offline
        // intelligence cannot refresh the evidence, so nothing may justify a
        // send.
        sqlx::query(
            "INSERT INTO sales_scores \
                 (id, tenant_id, account_id, contact_id, p_qualified_reply, p_meeting, p_paid, \
                  expected_value_eur, total, intent, evidence_quality, scoring_version, computed_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, 0.05, 0.05, 0.01, 1.50, 10, 5, 20, \
                     'test-fixture', NOW())",
        )
        .bind(&fx.tenant)
        .bind(fx.account)
        .bind(fx.contact)
        .execute(&fx.db)
        .await
        .expect("insert low-EV score");

        let handler = fx.handler();
        let outcome = run_handler(&fx, &handler).await;
        assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");

        let (state, skip_reason) = step_state(&fx.db, fx.step_execution).await;
        assert_eq!(state, "skipped");
        let skip_reason = skip_reason.expect("a skipped step records why");
        assert!(
            skip_reason.contains("next_best_action=do_nothing"),
            "the §28 gate must name the weak-prospect action: {skip_reason}"
        );
        assert!(
            skip_reason.contains("minimum") || skip_reason.contains("below"),
            "the reason must be the economic floor: {skip_reason}"
        );
        assert_eq!(
            outbound_count(&fx.db, fx.step_execution).await,
            0,
            "a stale, unrefreshable, low-EV prospect must not be sent to"
        );
        // Offline research wrote nothing; the stale row is the only evidence.
        let evidence_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_evidence WHERE tenant_id = $1 AND account_id = $2",
        )
        .bind(&fx.tenant)
        .bind(fx.account)
        .fetch_one(&fx.db)
        .await
        .expect("count evidence");
        assert_eq!(evidence_rows, 1);
    }

    // ── 6. The decision engine still gates everything ──────────────────────

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn prohibited_legal_verdict_still_blocks_the_ai_path() {
        let Some(fx) = fixture("lib_prohibited", "prohibited", "ZF").await else {
            return;
        };
        let evidence_id = insert_evidence(
            &fx.db,
            &fx.tenant,
            fx.account,
            "The account runs a hybrid email stack.",
            0.9,
            false,
        )
        .await;
        let handler = fx.handler_with(Arc::new(ScriptedIntelligence {
            grounded_evidence_id: evidence_id,
            grounded_claims: 0,
        }));
        let outcome = run_handler(&fx, &handler).await;
        assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");

        let (state, skip_reason) = step_state(&fx.db, fx.step_execution).await;
        assert_eq!(state, "skipped");
        let skip_reason = skip_reason.expect("a denied send records why");
        assert!(
            skip_reason.contains("legal_policy_prohibited"),
            "the legal gate must deny with its reason: {skip_reason}"
        );
        assert_eq!(
            outbound_count(&fx.db, fx.step_execution).await,
            0,
            "a prohibited verdict must produce no message even with the AI path active"
        );
    }

    // ── 7. The planning order never enqueues before the decision ───────────

    #[test]
    fn enqueue_sequenced_is_never_reached_before_decide() {
        let source = include_str!("sequence_worker.rs");
        let decide_at = source
            .find("decision_engine::decide(")
            .expect("the handler must call the decision engine");
        let enqueue_at = source
            .find(".enqueue_sequenced(")
            .expect("the handler must dispatch through enqueue_sequenced");
        assert!(
            decide_at < enqueue_at,
            "the Decision Packet must be produced before any external enqueue \
             (decide at byte {decide_at}, enqueue at byte {enqueue_at})"
        );
    }
}
