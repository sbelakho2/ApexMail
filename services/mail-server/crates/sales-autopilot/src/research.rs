//! §12/§26 — account research that produces grounded evidence, and the AI
//! outage rule.
//!
//! Research never writes bare prose. Every accepted finding becomes a
//! `sales_evidence` row (migration 200_sales_autopilot_v2_unification.sql:
//! 308-328) with a proposition, a confidence and **a named source kind**, and
//! only after [`intelligence::validate_claims`] has verified that a factual
//! claim cites an allowed `evidence_id` or is explicitly a hypothesis.
//!
//! # §26 — the outage rule
//!
//! When AI is unavailable the engine falls back to **verified static
//! content**, never to hallucination. Concretely, an outage:
//!
//! * writes **zero** new `sales_evidence` rows;
//! * fabricates no claim;
//! * returns a [`ResearchRun::reason`] that says exactly why.
//!
//! [`research_account_with_report`] exposes that reason; [`research_account`]
//! is the ids-only convenience used by the pipeline.
//!
//! Accepted hypotheses are still evidence rows, but their proposition is
//! prefixed with [`HYPOTHESIS_PREFIX`] so no downstream reader can mistake a
//! hypothesis for a grounded fact.

use sqlx::PgPool;
use uuid::Uuid;

use crate::intelligence::{
    ClaimValidation, EvidenceBrief, IntelligenceError, OmittedClaim, ResearchRequest,
    SalesIntelligence, ValidatedClaim,
};
use crate::types::SalesError;

/// Prefix applied to a hypothesis proposition before it is stored, so the
/// distinction survives in `sales_evidence`.
pub const HYPOTHESIS_PREFIX: &str = "HYPOTHESIS: ";

/// Maximum existing evidence rows handed to the AI as citable context.
pub const MAX_EVIDENCE_BRIEFS: i64 = 50;

/// Source kinds accepted by the `sales_evidence.source_kind` CHECK constraint
/// (migration 200_sales_autopilot_v2_unification.sql:316-319).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResearchSourceKind {
    DnsObservation,
    HttpFetch,
    ProviderApi,
    FirstParty,
    PublicRegistry,
    Manual,
}

impl ResearchSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsObservation => "dns_observation",
            Self::HttpFetch => "http_fetch",
            Self::ProviderApi => "provider_api",
            Self::FirstParty => "first_party",
            Self::PublicRegistry => "public_registry",
            Self::Manual => "manual",
        }
    }

    /// Parse a source kind. `None` for absent or unknown values — the caller
    /// must omit the finding rather than guess a provenance.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.map(|value| value.trim().to_ascii_lowercase()) {
            Some(value) if value == "dns_observation" => Some(Self::DnsObservation),
            Some(value) if value == "http_fetch" => Some(Self::HttpFetch),
            Some(value) if value == "provider_api" => Some(Self::ProviderApi),
            Some(value) if value == "first_party" => Some(Self::FirstParty),
            Some(value) if value == "public_registry" => Some(Self::PublicRegistry),
            Some(value) if value == "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl std::fmt::Display for ResearchSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a research run produced its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchMode {
    /// The AI service answered; claims were validated and grounded.
    Ai,
    /// No AI configured; verified static content only, zero new evidence.
    OfflineFallback,
    /// The AI service was unavailable or returned an unusable response; zero
    /// new evidence, reason recorded.
    Outage,
}

/// A validated finding ready to become a `sales_evidence` row.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingEvidence {
    pub proposition: String,
    pub confidence: f64,
    pub source_kind: ResearchSourceKind,
    pub source_ref: Option<String>,
}

/// The complete result of one research run.
#[derive(Debug, Clone, PartialEq)]
pub struct ResearchRun {
    pub evidence_ids: Vec<Uuid>,
    pub accepted: usize,
    pub omitted: Vec<OmittedClaim>,
    pub mode: ResearchMode,
    /// Why the run took this path (outage/fallback reason, or a note about
    /// omitted claims). Never `None` for an outage.
    pub reason: Option<String>,
    pub model_version: Option<String>,
}

/// Convert one validated claim into a pending evidence row, enforcing the
/// storage constraints in code so a hostile value becomes a clear omission
/// instead of a Postgres error.
pub fn claim_to_pending(claim: &ValidatedClaim) -> Result<PendingEvidence, String> {
    let proposition = claim.proposition.trim();
    if proposition.is_empty() {
        return Err("empty proposition".to_string());
    }
    if !claim.confidence.is_finite() || !(0.0..=1.0).contains(&claim.confidence) {
        return Err(format!("confidence {} outside 0..=1", claim.confidence));
    }
    let source_kind = ResearchSourceKind::parse(claim.source_kind.as_deref()).ok_or_else(|| {
        format!(
            "finding does not name a valid source kind (got {:?}); omitted",
            claim.source_kind
        )
    })?;
    let proposition = if claim.is_hypothesis {
        format!("{HYPOTHESIS_PREFIX}{proposition}")
    } else {
        proposition.to_string()
    };
    Ok(PendingEvidence {
        proposition,
        confidence: claim.confidence,
        source_kind,
        source_ref: claim.source_ref.clone(),
    })
}

/// The run produced when the AI is unavailable: zero rows, explicit reason.
pub fn outage_run(error: &IntelligenceError) -> ResearchRun {
    ResearchRun {
        evidence_ids: Vec::new(),
        accepted: 0,
        omitted: Vec::new(),
        mode: ResearchMode::Outage,
        reason: Some(format!(
            "AI unavailable ({error}); no evidence written and no claim fabricated — falling back \
             to verified static content only"
        )),
        model_version: None,
    }
}

/// Existing evidence for an account, as citable briefs for the AI.
pub async fn load_evidence_briefs(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<Vec<EvidenceBrief>, SalesError> {
    let rows = sqlx::query_as::<_, (Uuid, String, f64, String)>(
        "SELECT id, proposition, confidence::float8, source_kind \
         FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2 \
         ORDER BY observed_at DESC, id \
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(account_id)
    .bind(MAX_EVIDENCE_BRIEFS)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(rows
        .into_iter()
        .map(
            |(evidence_id, proposition, confidence, source_kind)| EvidenceBrief {
                evidence_id,
                proposition,
                confidence,
                source_kind,
            },
        )
        .collect())
}

/// Allowed evidence ids for an account (the set that survives validation).
pub async fn existing_evidence_ids(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<Vec<Uuid>, SalesError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2 \
         ORDER BY observed_at DESC, id",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(ids)
}

/// Research one account and persist every accepted finding as
/// `sales_evidence`, returning the created ids.
///
/// Delegates to [`research_account_with_report`], which also exposes the
/// outage/fallback reason. An AI outage is **not** an error: it is a
/// successful run that writes nothing and says why.
pub async fn research_account(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    intelligence: &dyn SalesIntelligence,
) -> Result<Vec<Uuid>, SalesError> {
    Ok(
        research_account_with_report(db, tenant_id, account_id, intelligence)
            .await?
            .evidence_ids,
    )
}

/// Research one account, returning the full run (ids, omissions, mode, why).
pub async fn research_account_with_report(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    intelligence: &dyn SalesIntelligence,
) -> Result<ResearchRun, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }

    let account = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT domain, company, country, industry FROM sales_accounts \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    let Some((domain, company, country, industry)) = account else {
        return Err(SalesError::InvalidInput(format!(
            "account {account_id} not found for tenant {tenant_id}"
        )));
    };

    let briefs = load_evidence_briefs(db, tenant_id, account_id).await?;
    let allowed: Vec<Uuid> = briefs.iter().map(|brief| brief.evidence_id).collect();

    let findings = match intelligence
        .research_account(&ResearchRequest {
            tenant_id,
            account_id: Some(account_id),
            domain: &domain,
            company: Some(company.as_str()).filter(|value| !value.is_empty()),
            country: country.as_deref(),
            industry: industry.as_deref(),
            evidence: &briefs,
        })
        .await
    {
        Ok(findings) => findings,
        // §26: outage → zero writes, explicit reason. Never an invention.
        Err(error) => {
            tracing::warn!(
                tenant_id,
                %account_id,
                error = %error,
                "AI research unavailable; writing no evidence and using static content only"
            );
            return Ok(outage_run(&error));
        }
    };

    let ClaimValidation { accepted, omitted } =
        crate::intelligence::validate_claims(&findings.claims, &allowed);

    let mut pending: Vec<PendingEvidence> = Vec::new();
    let mut omitted = omitted;
    for claim in &accepted {
        match claim_to_pending(claim) {
            Ok(pending_claim) => pending.push(pending_claim),
            Err(reason) => omitted.push(OmittedClaim {
                proposition: claim.proposition.clone(),
                reason,
            }),
        }
    }

    let mode = if findings.fallback.is_some() {
        ResearchMode::OfflineFallback
    } else {
        ResearchMode::Ai
    };

    if pending.is_empty() {
        return Ok(ResearchRun {
            evidence_ids: Vec::new(),
            accepted: 0,
            omitted,
            mode,
            reason: Some(match &findings.fallback {
                Some(fallback) => fallback.clone(),
                None => format!(
                    "{} finding(s) were all unevidenced, uncited or unsourced; refusing to write \
                     bare prose as evidence",
                    findings.claims.len()
                ),
            }),
            model_version: findings.model_version,
        });
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    let mut evidence_ids = Vec::with_capacity(pending.len());
    for claim in &pending {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_evidence \
                 (id, tenant_id, account_id, contact_id, proposition, confidence, source_kind, \
                  source_ref, source_hash, observed_at, expires_at, created_at) \
             VALUES (gen_random_uuid(), $1, $2, NULL, $3, $4, $5, $6, NULL, NOW(), NULL, NOW()) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(account_id)
        .bind(&claim.proposition)
        .bind(claim.confidence)
        .bind(claim.source_kind.as_str())
        .bind(claim.source_ref.as_deref())
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
        evidence_ids.push(id);
    }
    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let accepted = evidence_ids.len();
    Ok(ResearchRun {
        evidence_ids,
        accepted,
        omitted,
        mode,
        reason: findings.fallback,
        model_version: findings.model_version,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{IntelligenceError, ResearchFindings};

    fn validated(
        proposition: &str,
        source_kind: Option<&str>,
        is_hypothesis: bool,
    ) -> ValidatedClaim {
        ValidatedClaim {
            proposition: proposition.to_string(),
            confidence: 0.6,
            source_kind: source_kind.map(|value| value.to_string()),
            source_ref: Some("unit-test".to_string()),
            evidence_ids: Vec::new(),
            is_hypothesis,
        }
    }

    #[test]
    fn source_kind_must_be_named_and_known() {
        assert_eq!(
            ResearchSourceKind::parse(Some("provider_api")),
            Some(ResearchSourceKind::ProviderApi)
        );
        assert_eq!(
            ResearchSourceKind::parse(Some("Provider_API ")),
            Some(ResearchSourceKind::ProviderApi)
        );
        assert_eq!(ResearchSourceKind::parse(Some("guessed")), None);
        assert_eq!(ResearchSourceKind::parse(None), None);

        let missing = claim_to_pending(&validated("They use SendGrid", None, false))
            .expect_err("a finding without a source kind must be refused");
        assert!(missing.contains("source kind"), "{missing}");
        assert!(claim_to_pending(&validated("", Some("provider_api"), false)).is_err());
        let mut overconfident = validated("Claim", Some("provider_api"), false);
        overconfident.confidence = 1.5;
        assert!(claim_to_pending(&overconfident).is_err());
        let mut nan = validated("Claim", Some("provider_api"), false);
        nan.confidence = f64::NAN;
        assert!(claim_to_pending(&nan).is_err());
    }

    #[test]
    fn hypotheses_are_stored_prefixed() {
        let pending = claim_to_pending(&validated(
            "They may be replatforming",
            Some("provider_api"),
            true,
        ))
        .expect("hypothesis is storable");
        assert!(pending.proposition.starts_with(HYPOTHESIS_PREFIX));
        let factual = claim_to_pending(&validated(
            "They use SendGrid",
            Some("dns_observation"),
            false,
        ))
        .expect("factual claim is storable");
        assert!(!factual.proposition.starts_with(HYPOTHESIS_PREFIX));
        assert_eq!(factual.source_kind, ResearchSourceKind::DnsObservation);
    }

    #[test]
    fn outage_run_writes_nothing_and_says_why() {
        let run = outage_run(&IntelligenceError::Unavailable("connection refused".into()));
        assert!(run.evidence_ids.is_empty());
        assert_eq!(run.accepted, 0);
        assert_eq!(run.mode, ResearchMode::Outage);
        let reason = run.reason.expect("outage must carry a reason");
        assert!(reason.contains("connection refused"), "{reason}");
        assert!(reason.contains("no evidence written"), "{reason}");
    }

    #[test]
    fn offline_findings_are_never_written_as_claims() {
        // The offline provider returns no claims and a fallback reason; the
        // conversion path must yield zero pending rows.
        let findings = ResearchFindings {
            claims: Vec::new(),
            model_version: Some("offline".into()),
            fallback: Some(crate::intelligence::OFFLINE_RESEARCH_REASON.into()),
        };
        let validation = crate::intelligence::validate_claims(&findings.claims, &[]);
        assert!(validation.accepted.is_empty());
        assert!(findings.fallback.is_some());
    }
}
