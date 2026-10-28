//! Security questionnaire automation for Enterprise security reviews.
//!
//! This module generates ApexMail-owned answer packs mapped to common buyer
//! review frameworks (SIG, CAIQ, and HECVAT). It does not reproduce proprietary
//! questionnaire text; instead it emits normalized control questions, answers,
//! SOC 2 control mappings, and Trust Portal evidence references that can be
//! exported into a customer's preferred questionnaire format.

use std::{collections::BTreeSet, collections::HashMap, fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    soc2::{required_evidence_types, Control, ControlEvidence, AUTOMATED_EVIDENCE_TYPES},
    trust_portal::{Document, Incident, Subprocessor},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionnaireFramework {
    Sig,
    Caiq,
    Hecvat,
}

impl QuestionnaireFramework {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sig => "sig",
            Self::Caiq => "caiq",
            Self::Hecvat => "hecvat",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Sig => "SIG",
            Self::Caiq => "CAIQ",
            Self::Hecvat => "HECVAT",
        }
    }

    pub fn version(self) -> &'static str {
        match self {
            Self::Sig => "ApexMail SIG Core 2026.05",
            Self::Caiq => "ApexMail CAIQ v4-mapped 2026.05",
            Self::Hecvat => "ApexMail HECVAT Full-mapped 2026.05",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::Sig, Self::Caiq, Self::Hecvat]
    }
}

impl fmt::Display for QuestionnaireFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QuestionnaireFramework {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sig" | "standardized-information-gathering" => Ok(Self::Sig),
            "caiq" | "cloud-controls-matrix" | "ccm" => Ok(Self::Caiq),
            "hecvat" | "higher-education-community-vendor-assessment-tool" => Ok(Self::Hecvat),
            other => Err(format!("unsupported questionnaire framework '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireFrameworkInfo {
    pub framework: QuestionnaireFramework,
    pub display_name: String,
    pub version: String,
    pub generated_from: Vec<String>,
    pub export_formats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuestionnaireGenerationRequest {
    pub tenant_id: Option<String>,
    pub requester_company: Option<String>,
    pub include_private_documents: Option<bool>,
    pub include_markdown_report: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireContext {
    pub tenant_id: Option<String>,
    pub controls: Vec<Control>,
    pub documents: Vec<Document>,
    pub subprocessors: Vec<Subprocessor>,
    pub incidents: Vec<Incident>,
    pub hipaa_baa_active: bool,
    pub generated_at: DateTime<Utc>,
    /// Latest evidence rows per `(control, evidence_type, period)`.
    ///
    /// A questionnaire answer is automated only from these rows: the SOC 2
    /// control-catalog entry itself is a mapping, never evidence.
    #[serde(default)]
    pub evidence: Vec<ControlEvidence>,
    /// Cadence (days) used to judge whether an evidence row is fresh. Set
    /// from `Soc2Service::attestation_period_days`.
    #[serde(default = "default_freshness_days")]
    pub freshness_days: i64,
}

fn default_freshness_days() -> i64 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedQuestionnaire {
    pub id: String,
    pub framework: QuestionnaireFramework,
    pub framework_version: String,
    pub tenant_id: Option<String>,
    pub requester_company: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub questionnaire_hash: String,
    pub completion: QuestionnaireCompletion,
    pub answers: Vec<QuestionnaireAnswer>,
    pub evidence_manifest: Vec<EvidenceReference>,
    pub report_md: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReviewReport {
    pub id: String,
    pub tenant_id: Option<String>,
    pub requester_company: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub report_hash: String,
    pub frameworks: Vec<GeneratedQuestionnaire>,
    pub report_md: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireCompletion {
    pub total_questions: usize,
    pub automated_answers: usize,
    pub needs_review: usize,
    pub not_applicable: usize,
    pub source_control_count: usize,
    pub document_count: usize,
    pub subprocessor_count: usize,
    pub hipaa_baa_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireAnswer {
    pub id: String,
    pub domain: String,
    pub normalized_question: String,
    pub answer: String,
    pub status: AnswerStatus,
    pub confidence: f32,
    pub owner: String,
    pub source_controls: Vec<String>,
    pub evidence: Vec<EvidenceReference>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerStatus {
    Automated,
    NeedsReview,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub kind: String,
    pub id: String,
    pub title: String,
    pub hash: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum AnswerKind {
    Governance,
    AccessControl,
    Encryption,
    AuditLogging,
    IncidentResponse,
    VulnerabilityManagement,
    ChangeManagement,
    BusinessContinuity,
    PrivacyRights,
    Consent,
    Subprocessors,
    DataRetention,
    HipaaBaa,
    TrustPortal,
    NetworkSecurity,
    SecurityTraining,
    AssetManagement,
    VendorRisk,
}

#[derive(Debug, Clone, Copy)]
struct AnswerSpec {
    id: &'static str,
    domain: &'static str,
    question: &'static str,
    kind: AnswerKind,
    controls: &'static [&'static str],
    doc_keywords: &'static [&'static str],
}

pub fn framework_catalog() -> Vec<QuestionnaireFrameworkInfo> {
    QuestionnaireFramework::all()
        .iter()
        .copied()
        .map(|framework| QuestionnaireFrameworkInfo {
            framework,
            display_name: framework.display_name().to_string(),
            version: framework.version().to_string(),
            generated_from: vec![
                "SOC 2 control catalog".to_string(),
                "SOC 2 evidence records".to_string(),
                "HIPAA BAA lifecycle".to_string(),
                "GDPR DSR and consent workflows".to_string(),
                "Trust Portal documents, subprocessors, and incidents".to_string(),
            ],
            export_formats: vec!["json".to_string(), "markdown".to_string()],
        })
        .collect()
}

pub fn generate_questionnaire(
    framework: QuestionnaireFramework,
    request: QuestionnaireGenerationRequest,
    context: QuestionnaireContext,
) -> GeneratedQuestionnaire {
    let specs = specs_for(framework);
    let answers: Vec<QuestionnaireAnswer> = specs
        .iter()
        .map(|spec| build_answer(spec, &context))
        .collect();
    let evidence_manifest = collect_evidence_manifest(&answers);
    let completion = completion(&answers, &context);
    let report_md = request.include_markdown_report.unwrap_or(true).then(|| {
        render_questionnaire_markdown(framework, &request, &context, &completion, &answers)
    });
    let hash_payload = serde_json::json!({
        "framework": framework,
        "version": framework.version(),
        "tenant_id": request.tenant_id,
        "requester_company": request.requester_company,
        "answers": answers,
        "evidence_manifest": evidence_manifest,
        "generated_at": context.generated_at,
    });
    let questionnaire_hash = sha256_json(&hash_payload);
    GeneratedQuestionnaire {
        id: format!("qnr-{}-{}", framework.as_str(), &questionnaire_hash[..16]),
        framework,
        framework_version: framework.version().to_string(),
        tenant_id: request.tenant_id,
        requester_company: request.requester_company,
        generated_at: context.generated_at,
        questionnaire_hash,
        completion,
        answers,
        evidence_manifest,
        report_md,
    }
}

pub fn generate_security_review_report(
    request: QuestionnaireGenerationRequest,
    context: QuestionnaireContext,
) -> SecurityReviewReport {
    let frameworks: Vec<GeneratedQuestionnaire> = QuestionnaireFramework::all()
        .iter()
        .copied()
        .map(|framework| {
            generate_questionnaire(
                framework,
                QuestionnaireGenerationRequest {
                    include_markdown_report: Some(false),
                    ..request.clone()
                },
                context.clone(),
            )
        })
        .collect();
    let report_md = render_security_review_markdown(&request, &context, &frameworks);
    let hash_payload = serde_json::json!({
        "tenant_id": request.tenant_id,
        "requester_company": request.requester_company,
        "frameworks": frameworks,
        "report_md": report_md,
        "generated_at": context.generated_at,
    });
    let report_hash = sha256_json(&hash_payload);
    SecurityReviewReport {
        id: format!("security-review-{}", &report_hash[..16]),
        tenant_id: request.tenant_id,
        requester_company: request.requester_company,
        generated_at: context.generated_at,
        report_hash,
        frameworks,
        report_md,
    }
}

fn specs_for(framework: QuestionnaireFramework) -> &'static [AnswerSpec] {
    match framework {
        QuestionnaireFramework::Sig => SIG_SPECS,
        QuestionnaireFramework::Caiq => CAIQ_SPECS,
        QuestionnaireFramework::Hecvat => HECVAT_SPECS,
    }
}

fn build_answer(spec: &AnswerSpec, context: &QuestionnaireContext) -> QuestionnaireAnswer {
    let source_controls = present_controls(spec.controls, &context.controls);
    let gate = assess_evidence_gate(spec, context);
    let status = answer_status(spec, context, &gate);
    // Confidence is derived from evidence coverage, never a fixed constant:
    // fresh+valid required evidence divided by all required evidence.
    let confidence = match status {
        AnswerStatus::NotApplicable => 1.0,
        _ => gate.coverage().clamp(0.0, 1.0),
    };
    let mut evidence = evidence_for(spec, context, &source_controls);
    let answer = render_answer(spec.kind, context, &source_controls, &evidence, status);
    if matches!(spec.kind, AnswerKind::Subprocessors) && context.subprocessors.is_empty() {
        evidence.push(EvidenceReference {
            kind: "trust_portal".to_string(),
            id: "subprocessor-registry".to_string(),
            title: "Subprocessor registry has no active public entries".to_string(),
            hash: None,
            location: Some("/trust/subprocessors".to_string()),
        });
    }
    QuestionnaireAnswer {
        id: spec.id.to_string(),
        domain: spec.domain.to_string(),
        normalized_question: spec.question.to_string(),
        answer,
        status,
        confidence,
        owner: owner_for(spec.kind).to_string(),
        source_controls,
        evidence,
        notes: notes_for(status, spec.kind, context, &gate),
    }
}

/// What a control's evidence set actually supports. Every answer must earn
/// `Automated` from real evidence rows; the control-catalog entry is a
/// mapping, not evidence.
#[derive(Debug, Clone, Default)]
struct EvidenceGate {
    active_controls: Vec<String>,
    missing_controls: Vec<String>,
    inactive_controls: Vec<String>,
    controls_without_requirements: Vec<String>,
    required_total: usize,
    fresh_total: usize,
    missing_evidence: Vec<String>,
    manual_missing: Vec<String>,
    stale_evidence: Vec<String>,
    invalid_evidence: Vec<String>,
    legal_review_required: bool,
}

impl EvidenceGate {
    /// Fraction of required evidence items that are present, valid and fresh.
    fn coverage(&self) -> f32 {
        if self.required_total == 0 {
            0.0
        } else {
            self.fresh_total as f32 / self.required_total as f32
        }
    }

    /// An answer is automatable only when its mapped controls are active, every
    /// required evidence item exists (latest row), verifies against its hash,
    /// is fresh for the cadence, no manual evidence is missing, and no
    /// legal/contract judgment is required.
    fn complete(&self) -> bool {
        !self.legal_review_required
            && self.required_total > 0
            && !self.active_controls.is_empty()
            && self.missing_controls.is_empty()
            && self.inactive_controls.is_empty()
            && self.controls_without_requirements.is_empty()
            && self.missing_evidence.is_empty()
            && self.manual_missing.is_empty()
            && self.stale_evidence.is_empty()
            && self.invalid_evidence.is_empty()
            && self.fresh_total == self.required_total
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.missing_controls.is_empty() {
            parts.push(format!(
                "mapped controls absent from the catalog: {}",
                self.missing_controls.join(", ")
            ));
        }
        if !self.inactive_controls.is_empty() {
            parts.push(format!(
                "mapped controls not active: {}",
                self.inactive_controls.join(", ")
            ));
        }
        if !self.controls_without_requirements.is_empty() {
            parts.push(format!(
                "controls with no configured required evidence: {}",
                self.controls_without_requirements.join(", ")
            ));
        }
        if !self.missing_evidence.is_empty() {
            parts.push(format!(
                "missing required evidence: {}",
                self.missing_evidence.join(", ")
            ));
        }
        if !self.manual_missing.is_empty() {
            parts.push(format!(
                "required manual evidence missing: {}",
                self.manual_missing.join(", ")
            ));
        }
        if !self.stale_evidence.is_empty() {
            parts.push(format!(
                "stale evidence: {}",
                self.stale_evidence.join(", ")
            ));
        }
        if !self.invalid_evidence.is_empty() {
            parts.push(format!(
                "evidence failed hash verification: {}",
                self.invalid_evidence.join(", ")
            ));
        }
        if self.legal_review_required {
            parts.push("legal/contract review required".to_string());
        }
        if parts.is_empty() {
            "all required evidence is present, valid and fresh".to_string()
        } else {
            parts.join("; ")
        }
    }
}

fn latest_evidence(context: &QuestionnaireContext) -> HashMap<(String, String), &ControlEvidence> {
    let mut latest: HashMap<(String, String), &ControlEvidence> = HashMap::new();
    for row in &context.evidence {
        let key = (row.control_id.clone(), row.evidence_type.clone());
        match latest.get(&key) {
            Some(existing) if evidence_is_newer(existing, row) => {}
            _ => {
                latest.insert(key, row);
            }
        }
    }
    latest
}

/// Latest-row tie-break: `collected_at DESC, id DESC`, matching the SQL
/// readers. A later correction therefore supersedes an earlier row.
fn evidence_is_newer(candidate: &ControlEvidence, current: &ControlEvidence) -> bool {
    candidate.collected_at > current.collected_at
        || (candidate.collected_at == current.collected_at && candidate.id > current.id)
}

fn assess_evidence_gate(spec: &AnswerSpec, context: &QuestionnaireContext) -> EvidenceGate {
    let latest = latest_evidence(context);
    let cutoff = context.generated_at - Duration::days(context.freshness_days.max(0));
    let mut gate = EvidenceGate {
        legal_review_required: requires_legal_review(spec.kind),
        ..EvidenceGate::default()
    };

    for control_id in spec.controls {
        let Some(control) = context
            .controls
            .iter()
            .find(|control| control.control_id == *control_id)
        else {
            // An unavailable control contributes one unmet evidence basis so
            // the derived coverage cannot read 1.0 for a blocked answer.
            gate.required_total += 1;
            gate.missing_controls.push((*control_id).to_string());
            continue;
        };
        if control.status != "in_scope" {
            gate.required_total += 1;
            gate.inactive_controls
                .push(format!("{} ({})", control.control_id, control.status));
            continue;
        }
        gate.active_controls.push(control.control_id.clone());

        let required = match required_evidence_types(control) {
            Ok(required) if !required.is_empty() => required,
            _ => {
                gate.required_total += 1;
                gate.controls_without_requirements
                    .push(control.control_id.clone());
                continue;
            }
        };

        for evidence_type in required {
            gate.required_total += 1;
            let key = (control.control_id.clone(), evidence_type.clone());
            let item = format!("{}:{}", control.control_id, evidence_type);
            match latest.get(&key) {
                None => {
                    gate.missing_evidence.push(item.clone());
                    if !AUTOMATED_EVIDENCE_TYPES.contains(&evidence_type.as_str()) {
                        gate.manual_missing.push(item);
                    }
                }
                Some(row) => {
                    let valid = sha256_json(&row.payload) == row.sha256_hash;
                    if !valid {
                        gate.invalid_evidence.push(item.clone());
                    }
                    let fresh = row.collected_at >= cutoff;
                    if !fresh {
                        gate.stale_evidence.push(item.clone());
                    }
                    if valid && fresh {
                        gate.fresh_total += 1;
                    }
                }
            }
        }
    }

    gate
}

/// Contract/legal answers always need a human, even when operational
/// evidence is complete: the HIPAA/BAA answer asserts a contractual position.
fn requires_legal_review(kind: AnswerKind) -> bool {
    matches!(kind, AnswerKind::HipaaBaa)
}

fn answer_status(
    spec: &AnswerSpec,
    context: &QuestionnaireContext,
    gate: &EvidenceGate,
) -> AnswerStatus {
    if matches!(spec.kind, AnswerKind::HipaaBaa) && !context.hipaa_baa_active {
        return AnswerStatus::NeedsReview;
    }
    if gate.complete() {
        AnswerStatus::Automated
    } else {
        AnswerStatus::NeedsReview
    }
}

fn present_controls(expected: &[&str], controls: &[Control]) -> Vec<String> {
    expected
        .iter()
        .filter(|expected_id| {
            controls
                .iter()
                .any(|control| control.control_id == **expected_id && control.status == "in_scope")
        })
        .map(|id| (*id).to_string())
        .collect()
}

fn evidence_for(
    spec: &AnswerSpec,
    context: &QuestionnaireContext,
    source_controls: &[String],
) -> Vec<EvidenceReference> {
    let mut evidence = BTreeSet::new();
    let latest = latest_evidence(context);

    // Only captured evidence rows back an answer. The control-catalog entry
    // is a mapping and is deliberately NOT added as evidence.
    for control_id in source_controls {
        let Some(control) = context
            .controls
            .iter()
            .find(|control| control.control_id == *control_id)
        else {
            continue;
        };
        let Ok(required) = required_evidence_types(control) else {
            continue;
        };
        for evidence_type in required {
            if let Some(row) = latest.get(&(control.control_id.clone(), evidence_type.clone())) {
                evidence.insert(EvidenceReference {
                    kind: "soc2_evidence".to_string(),
                    id: row.id.clone(),
                    title: format!(
                        "{} {} evidence collected {}",
                        control.control_id, row.evidence_type, row.collected_at
                    ),
                    hash: Some(row.sha256_hash.clone()),
                    location: Some(format!(
                        "/v1/admin/soc2/controls/{}/evidence",
                        control.control_id
                    )),
                });
            }
        }
    }

    for keyword in spec.doc_keywords {
        let needle = keyword.to_ascii_lowercase();
        for doc in &context.documents {
            let haystack =
                format!("{} {} {}", doc.slug, doc.title, doc.document_type).to_ascii_lowercase();
            if haystack.contains(&needle) {
                evidence.insert(EvidenceReference {
                    kind: "trust_document".to_string(),
                    id: format!("{}@{}", doc.slug, doc.version),
                    title: doc.title.clone(),
                    hash: Some(doc.sha256_hash.clone()),
                    location: doc
                        .storage_url
                        .clone()
                        .or_else(|| Some(format!("/trust/documents/{}", doc.slug))),
                });
            }
        }
    }
    match spec.kind {
        AnswerKind::Subprocessors | AnswerKind::VendorRisk => {
            for subprocessor in &context.subprocessors {
                evidence.insert(EvidenceReference {
                    kind: "subprocessor".to_string(),
                    id: subprocessor.id.clone(),
                    title: subprocessor.name.clone(),
                    hash: None,
                    location: subprocessor.dpa_url.clone(),
                });
            }
        }
        AnswerKind::IncidentResponse => {
            for incident in context.incidents.iter().take(5) {
                evidence.insert(EvidenceReference {
                    kind: "incident".to_string(),
                    id: incident.id.clone(),
                    title: incident.title.clone(),
                    hash: None,
                    location: Some(format!("/trust/incidents#{}", incident.slug)),
                });
            }
        }
        _ => {}
    }
    evidence.into_iter().collect()
}

const HIPAA_INACTIVE_ANSWER: &str = "ApexMail does not currently offer HIPAA/BAA service. Do not represent the service as HIPAA-enabled.";

fn hipaa_answer(context: &QuestionnaireContext) -> String {
    if !context.hipaa_baa_active {
        return HIPAA_INACTIVE_ANSWER.to_string();
    }
    match &context.tenant_id {
        Some(tenant_id) => format!(
            "A HIPAA BAA is active for the requested tenant ({tenant_id}). ApexMail tracks BAA request, customer signature, ApexMail countersignature, activation, termination, and hash-chained BAA events."
        ),
        None => "A HIPAA BAA is active for the requested tenant. ApexMail tracks BAA request, customer signature, ApexMail countersignature, activation, termination, and hash-chained BAA events.".to_string(),
    }
}

fn render_answer(
    kind: AnswerKind,
    context: &QuestionnaireContext,
    source_controls: &[String],
    evidence: &[EvidenceReference],
    status: AnswerStatus,
) -> String {
    // The HIPAA answer is state-dependent, not review-state-dependent: an
    // inactive deployment must never advertise an obtainable service.
    if matches!(kind, AnswerKind::HipaaBaa) {
        return hipaa_answer(context);
    }

    if status == AnswerStatus::NeedsReview {
        return format!(
            "ApexMail has a configured review workflow for this domain, but this generated answer requires ApexMail review because the expected control or evidence source was not present in the current evidence set. Expected controls: {}.",
            if source_controls.is_empty() {
                "not currently in scope".to_string()
            } else {
                source_controls.join(", ")
            }
        );
    }

    match kind {
        AnswerKind::Governance => format!(
            "ApexMail maintains a SOC 2 control catalog covering governance, oversight, roles, responsibilities, policy communication, and monitoring. This answer is backed by {} mapped controls and {} evidence items.",
            source_controls.len(), evidence.len()
        ),
        AnswerKind::AccessControl => "Access control is enforced through SSO/SAML, SCIM provisioning where configured, role-based access, API keys, IP allowlisting, and audit logs for administrative actions. Access control evidence maps to the CC6 control family.".to_string(),
        AnswerKind::Encryption => "ApexMail uses encrypted transport for customer-facing APIs and mail security controls, encrypted storage controls for sensitive service data, and secret-management workflows with rotation evidence. Customer-managed key options are reviewed for dedicated deployments.".to_string(),
        AnswerKind::AuditLogging => "Security-relevant API calls, admin operations, configuration changes, GDPR workflow events, and HIPAA BAA lifecycle events are written to audit logs. SOC 2 evidence collectors can sample and hash-lock audit-log evidence for review periods.".to_string(),
        AnswerKind::IncidentResponse => format!(
            "ApexMail tracks incident status, public updates, impact, root-cause fields, and customer-data impact through the Trust Portal incident model. The current generated pack references {} recent incident record(s).",
            context.incidents.len().min(5)
        ),
        AnswerKind::VulnerabilityManagement => "Vulnerability and risk-management answers are mapped to SOC 2 risk assessment, monitoring, content-scanning, and remediation controls. Evidence collection can include risk profile snapshots and scan-result summaries.".to_string(),
        AnswerKind::ChangeManagement => "Production change management maps to SOC 2 CC8 controls. ApexMail tracks change approvals, deployment review evidence, and audit-log records for administrative configuration changes.".to_string(),
        AnswerKind::BusinessContinuity => "Availability answers map to A1 controls covering monitoring, capacity, recovery objectives, incident communication, and SLA review. Enterprise contracts can add negotiated SLA terms.".to_string(),
        AnswerKind::PrivacyRights => "ApexMail supports GDPR data subject request workflows for access, erasure, portability, restriction, and objection, with verification steps and audit records for each request lifecycle.".to_string(),
        AnswerKind::Consent => "Consent records, double opt-in tokens, consent certificates, and revocation history are maintained by the GDPR automation layer and can be queried for review evidence.".to_string(),
        AnswerKind::Subprocessors => format!(
            "ApexMail maintains a Trust Portal subprocessor registry with purpose, location, data categories, DPA URL, and certification metadata. Active subprocessors in this pack: {}.",
            context.subprocessors.len()
        ),
        AnswerKind::DataRetention => "Retention controls are plan-based and configurable for Enterprise review. GDPR erasure workflows and audit records support retention and disposal review.".to_string(),
        // The HIPAA branch returns above; this arm keeps the match total.
        AnswerKind::HipaaBaa => hipaa_answer(context),
        AnswerKind::TrustPortal => "The Trust Portal exposes public documents, policy summaries, subprocessor records, incident history, and NDA-gated access requests for private security artifacts. Admin routes support document versioning and supersedence.".to_string(),
        AnswerKind::NetworkSecurity => "Network security answers map to SOC 2 logical access, transport security, provider throttling, WAF/IDS controls where enabled, and dedicated deployment architecture review for Enterprise customers.".to_string(),
        AnswerKind::SecurityTraining => "Security awareness and role training are tracked as governance controls in the SOC 2 catalog and included in questionnaire packs as ApexMail attestation items.".to_string(),
        AnswerKind::AssetManagement => "Asset and service ownership maps to SOC 2 structure, responsibility, monitoring, and change controls. Questionnaire answers include owner fields so stale ownership can be reviewed.".to_string(),
        AnswerKind::VendorRisk => "Vendor risk is represented through the Trust Portal subprocessor registry, DPA URLs, certification metadata, and reviewable data-category mapping for each active subprocessor.".to_string(),
    }
}

/// Every generated answer is owned by the company itself (external audit
/// 2026-10-27, finding 18): an org chart of named departments ("Compliance",
/// "Security Engineering", "Operations") would be a fictional team, and the
/// owner directive forbids inventing one just as it forbids disclosing the
/// real operating structure. Internal accountability lives in the SOC 2
/// control seeds' owner fields, not in customer-facing questionnaires.
fn owner_for(kind: AnswerKind) -> &'static str {
    let _ = kind;
    "ApexMail"
}

fn notes_for(
    status: AnswerStatus,
    kind: AnswerKind,
    context: &QuestionnaireContext,
    gate: &EvidenceGate,
) -> Option<String> {
    match status {
        AnswerStatus::NeedsReview => {
            if matches!(kind, AnswerKind::HipaaBaa) && !context.hipaa_baa_active {
                Some(
                    "HIPAA/BAA service is not offered; do not represent the service as HIPAA-enabled."
                        .to_string(),
                )
            } else {
                Some(format!("Requires ApexMail review: {}.", gate.describe()))
            }
        }
        AnswerStatus::Automated => match kind {
            AnswerKind::HipaaBaa => Some(
                "Tenant-specific answer depends on the tenant_id supplied during generation."
                    .to_string(),
            ),
            _ => None,
        },
        AnswerStatus::NotApplicable => None,
    }
}

fn completion(
    answers: &[QuestionnaireAnswer],
    context: &QuestionnaireContext,
) -> QuestionnaireCompletion {
    QuestionnaireCompletion {
        total_questions: answers.len(),
        automated_answers: answers
            .iter()
            .filter(|a| a.status == AnswerStatus::Automated)
            .count(),
        needs_review: answers
            .iter()
            .filter(|a| a.status == AnswerStatus::NeedsReview)
            .count(),
        not_applicable: answers
            .iter()
            .filter(|a| a.status == AnswerStatus::NotApplicable)
            .count(),
        source_control_count: context.controls.len(),
        document_count: context.documents.len(),
        subprocessor_count: context.subprocessors.len(),
        hipaa_baa_active: context.hipaa_baa_active,
    }
}

fn collect_evidence_manifest(answers: &[QuestionnaireAnswer]) -> Vec<EvidenceReference> {
    let mut evidence = BTreeSet::new();
    for answer in answers {
        for item in &answer.evidence {
            evidence.insert(item.clone());
        }
    }
    evidence.into_iter().collect()
}

fn render_questionnaire_markdown(
    framework: QuestionnaireFramework,
    request: &QuestionnaireGenerationRequest,
    context: &QuestionnaireContext,
    completion: &QuestionnaireCompletion,
    answers: &[QuestionnaireAnswer],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {} Answer Pack\n\n", framework.display_name()));
    out.push_str(&format!("Generated: {}\n\n", context.generated_at));
    if let Some(company) = &request.requester_company {
        out.push_str(&format!("Requester: {}\n\n", company));
    }
    if let Some(tenant_id) = &request.tenant_id {
        out.push_str(&format!("Tenant: {}\n\n", tenant_id));
    }
    out.push_str(&format!(
        "Automated answers: {}/{}; needs review: {}; source controls: {}; documents: {}; subprocessors: {}; HIPAA BAA active: {}.\n\n",
        completion.automated_answers,
        completion.total_questions,
        completion.needs_review,
        completion.source_control_count,
        completion.document_count,
        completion.subprocessor_count,
        completion.hipaa_baa_active
    ));
    for answer in answers {
        out.push_str(&format!("## {} - {}\n\n", answer.id, answer.domain));
        out.push_str(&format!("**Question:** {}\n\n", answer.normalized_question));
        out.push_str(&format!("**Status:** {:?}\n\n", answer.status));
        out.push_str(&format!("**Answer:** {}\n\n", answer.answer));
        if !answer.source_controls.is_empty() {
            out.push_str(&format!(
                "**Mapped controls:** {}\n\n",
                answer.source_controls.join(", ")
            ));
        }
    }
    out
}

fn render_security_review_markdown(
    request: &QuestionnaireGenerationRequest,
    context: &QuestionnaireContext,
    frameworks: &[GeneratedQuestionnaire],
) -> String {
    let mut out = String::new();
    out.push_str("# ApexMail Security Review Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", context.generated_at));
    if let Some(company) = &request.requester_company {
        out.push_str(&format!("Requester: {}\n\n", company));
    }
    if let Some(tenant_id) = &request.tenant_id {
        out.push_str(&format!("Tenant: {}\n\n", tenant_id));
    }
    out.push_str("## Coverage\n\n");
    for pack in frameworks {
        out.push_str(&format!(
            "- {}: {}/{} automated answers, {} needs review, hash `{}`\n",
            pack.framework.display_name(),
            pack.completion.automated_answers,
            pack.completion.total_questions,
            pack.completion.needs_review,
            pack.questionnaire_hash
        ));
    }
    out.push_str("\n## Evidence Sources\n\n");
    out.push_str(&format!(
        "- SOC 2 controls in scope: {}\n",
        context.controls.len()
    ));
    out.push_str(&format!(
        "- Trust Portal documents: {}\n",
        context.documents.len()
    ));
    out.push_str(&format!(
        "- Active subprocessors: {}\n",
        context.subprocessors.len()
    ));
    out.push_str(&format!(
        "- Recent incidents included: {}\n",
        context.incidents.len()
    ));
    out.push_str(&format!(
        "- HIPAA BAA active for tenant: {}\n",
        context.hipaa_baa_active
    ));
    out
}

fn sha256_json(value: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

const SIG_SPECS: &[AnswerSpec] = &[
    AnswerSpec { id: "SIG-GOV-01", domain: "Governance", question: "Describe the security governance program, policy ownership, oversight, and review cadence.", kind: AnswerKind::Governance, controls: &["CC1.1", "CC1.2", "CC1.3", "CC2.2"], doc_keywords: &["security", "policy"] },
    AnswerSpec { id: "SIG-IAM-01", domain: "Identity and Access", question: "Describe how workforce and administrative access is provisioned, reviewed, changed, and revoked.", kind: AnswerKind::AccessControl, controls: &["CC6.1", "CC6.2", "CC6.3", "CC6.4"], doc_keywords: &["access", "sso"] },
    AnswerSpec { id: "SIG-ENC-01", domain: "Encryption", question: "Describe encryption controls for data in transit, stored data, secrets, and customer-managed key review.", kind: AnswerKind::Encryption, controls: &["CC6.3", "C1.1", "C1.2"], doc_keywords: &["encryption", "key"] },
    AnswerSpec { id: "SIG-LOG-01", domain: "Logging and Monitoring", question: "Describe audit logging, log integrity, monitoring, alerting, and evidence collection.", kind: AnswerKind::AuditLogging, controls: &["CC2.1", "CC4.1", "CC7.2"], doc_keywords: &["audit", "logging"] },
    AnswerSpec { id: "SIG-IR-01", domain: "Incident Response", question: "Describe incident response, customer communications, public updates, impact tracking, and post-incident review.", kind: AnswerKind::IncidentResponse, controls: &["CC7.3", "CC7.4", "CC7.5"], doc_keywords: &["incident", "status"] },
    AnswerSpec { id: "SIG-VM-01", domain: "Vulnerability Management", question: "Describe vulnerability intake, risk scoring, scanning, triage, remediation, and exception handling.", kind: AnswerKind::VulnerabilityManagement, controls: &["CC3.2", "CC4.2", "CC7.1"], doc_keywords: &["vulnerability", "risk"] },
    AnswerSpec { id: "SIG-CHG-01", domain: "Change Management", question: "Describe production change review, approval, testing, deployment, and rollback controls.", kind: AnswerKind::ChangeManagement, controls: &["CC8.1", "CC2.1"], doc_keywords: &["change", "release"] },
    AnswerSpec { id: "SIG-BCP-01", domain: "Business Continuity", question: "Describe availability monitoring, backup, recovery, capacity, and continuity controls.", kind: AnswerKind::BusinessContinuity, controls: &["A1.1", "A1.2", "A1.3"], doc_keywords: &["continuity", "sla"] },
    AnswerSpec { id: "SIG-PRI-01", domain: "Privacy", question: "Describe data subject request handling, consent, retention, deletion, and privacy control evidence.", kind: AnswerKind::PrivacyRights, controls: &["P2.1", "P4.1", "P5.1", "P6.1"], doc_keywords: &["privacy", "gdpr"] },
    AnswerSpec { id: "SIG-TPRM-01", domain: "Third Party Risk", question: "Describe subprocessor governance, review, data categories, locations, and notification process.", kind: AnswerKind::VendorRisk, controls: &["CC9.2", "P8.1"], doc_keywords: &["subprocessor", "dpa"] },
];

const CAIQ_SPECS: &[AnswerSpec] = &[
    AnswerSpec { id: "CAIQ-AIS-01", domain: "Application and Interface Security", question: "Describe how API access, request validation, authentication, authorization, and abuse controls are enforced.", kind: AnswerKind::AccessControl, controls: &["CC6.1", "CC6.6", "CC6.8"], doc_keywords: &["api", "security"] },
    AnswerSpec { id: "CAIQ-AAC-01", domain: "Audit and Assurance", question: "Describe audit log coverage, evidence collection, control mapping, and independent review readiness.", kind: AnswerKind::AuditLogging, controls: &["CC2.1", "CC4.1", "CC4.2"], doc_keywords: &["audit", "soc"] },
    AnswerSpec { id: "CAIQ-BCR-01", domain: "Business Continuity", question: "Describe backup, recovery, resilience, incident escalation, and continuity review controls.", kind: AnswerKind::BusinessContinuity, controls: &["A1.1", "A1.2", "A1.3"], doc_keywords: &["continuity", "recovery"] },
    AnswerSpec { id: "CAIQ-CCC-01", domain: "Change Control", question: "Describe change authorization, deployment controls, testing, and change evidence.", kind: AnswerKind::ChangeManagement, controls: &["CC8.1"], doc_keywords: &["change"] },
    AnswerSpec { id: "CAIQ-CEK-01", domain: "Cryptography, Encryption, and Key Management", question: "Describe encryption and key-management controls for customer data, secrets, and dedicated deployment reviews.", kind: AnswerKind::Encryption, controls: &["CC6.3", "C1.1", "C1.2"], doc_keywords: &["encryption", "key"] },
    AnswerSpec { id: "CAIQ-DSP-01", domain: "Data Security and Privacy", question: "Describe privacy rights, deletion, retention, portability, restriction, and consent workflows.", kind: AnswerKind::PrivacyRights, controls: &["P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1"], doc_keywords: &["privacy", "gdpr"] },
    AnswerSpec { id: "CAIQ-GRC-01", domain: "Governance, Risk, and Compliance", question: "Describe governance, risk management, policy review, control ownership, and evidence review.", kind: AnswerKind::Governance, controls: &["CC1.1", "CC1.2", "CC3.1", "CC3.2"], doc_keywords: &["policy", "risk"] },
    AnswerSpec { id: "CAIQ-HRS-01", domain: "Human Resources Security", question: "Describe workforce security responsibilities, training, access acknowledgement, and disciplinary controls.", kind: AnswerKind::SecurityTraining, controls: &["CC1.1", "CC1.3", "CC2.2"], doc_keywords: &["training", "code"] },
    AnswerSpec { id: "CAIQ-IVS-01", domain: "Infrastructure and Virtualization Security", question: "Describe network security, tenant isolation, monitoring, dedicated deployment review, and infrastructure controls.", kind: AnswerKind::NetworkSecurity, controls: &["CC6.6", "CC6.7", "A1.1"], doc_keywords: &["network", "private"] },
    AnswerSpec { id: "CAIQ-STA-01", domain: "Supply Chain", question: "Describe subprocessor registry, due diligence, DPA tracking, data categories, and customer-facing disclosure.", kind: AnswerKind::Subprocessors, controls: &["CC9.2", "P8.1"], doc_keywords: &["subprocessor", "dpa"] },
];

const HECVAT_SPECS: &[AnswerSpec] = &[
    AnswerSpec { id: "HECVAT-GEN-01", domain: "Company and Product", question: "Summarize the ApexMail service boundary, operational ownership, customer responsibilities, and support channels.", kind: AnswerKind::Governance, controls: &["CC1.3", "CC2.2"], doc_keywords: &["terms", "support"] },
    AnswerSpec { id: "HECVAT-IAM-01", domain: "Identity and Access Management", question: "Describe SSO, SCIM, MFA, role-based access, API key handling, and access review controls.", kind: AnswerKind::AccessControl, controls: &["CC6.1", "CC6.2", "CC6.3", "CC6.4"], doc_keywords: &["sso", "access"] },
    AnswerSpec { id: "HECVAT-DAT-01", domain: "Data Protection", question: "Describe customer-data encryption, data classification, retention, deletion, and export controls.", kind: AnswerKind::DataRetention, controls: &["C1.1", "C1.2", "P4.1", "P5.1"], doc_keywords: &["retention", "privacy"] },
    AnswerSpec { id: "HECVAT-PRI-01", domain: "Privacy", question: "Describe GDPR rights, consent records, double opt-in, privacy notices, and data subject communication workflows.", kind: AnswerKind::PrivacyRights, controls: &["P1.1", "P2.1", "P3.1", "P4.1", "P6.1"], doc_keywords: &["privacy", "gdpr"] },
    AnswerSpec { id: "HECVAT-CON-01", domain: "Consent", question: "Describe consent capture, consent status lookup, revocation, evidence retention, and consent certificate generation.", kind: AnswerKind::Consent, controls: &["P3.1", "P6.1", "P7.1"], doc_keywords: &["consent"] },
    AnswerSpec { id: "HECVAT-HIPAA-01", domain: "Regulated Data", question: "Describe HIPAA BAA availability, BAA lifecycle evidence, PHI implementation review, and tenant-specific activation state.", kind: AnswerKind::HipaaBaa, controls: &["P1.1", "C1.1", "CC2.1"], doc_keywords: &["hipaa", "baa"] },
    AnswerSpec { id: "HECVAT-LOG-01", domain: "Logging and Monitoring", question: "Describe event logging, security monitoring, audit export, log integrity, and retention for security events.", kind: AnswerKind::AuditLogging, controls: &["CC2.1", "CC4.1", "CC7.2"], doc_keywords: &["audit", "logging"] },
    AnswerSpec { id: "HECVAT-IR-01", domain: "Incident Management", question: "Describe incident intake, classification, updates, customer data impact tracking, resolution, and RCA process.", kind: AnswerKind::IncidentResponse, controls: &["CC7.3", "CC7.4", "CC7.5"], doc_keywords: &["incident"] },
    AnswerSpec { id: "HECVAT-VEN-01", domain: "Third Parties", question: "Describe subprocessors, cloud providers, DPA tracking, location, certification metadata, and customer notification.", kind: AnswerKind::VendorRisk, controls: &["CC9.2", "P8.1"], doc_keywords: &["subprocessor"] },
    AnswerSpec { id: "HECVAT-TRUST-01", domain: "Evidence and Trust Portal", question: "Describe how customers can access security policies, reports, questionnaires, subprocessor data, incidents, and NDA-gated artifacts.", kind: AnswerKind::TrustPortal, controls: &["CC2.2", "CC4.1", "P8.1"], doc_keywords: &["trust", "security", "policy"] },
    AnswerSpec { id: "HECVAT-BCP-01", domain: "Continuity", question: "Describe availability, monitoring, capacity, recovery objectives, and continuity evidence for enterprise reviews.", kind: AnswerKind::BusinessContinuity, controls: &["A1.1", "A1.2", "A1.3"], doc_keywords: &["sla", "continuity"] },
    AnswerSpec { id: "HECVAT-AST-01", domain: "Asset and Configuration", question: "Describe asset ownership, configuration management, change records, and administrative action evidence.", kind: AnswerKind::AssetManagement, controls: &["CC1.3", "CC5.1", "CC8.1"], doc_keywords: &["asset", "configuration"] },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn control(id: &str) -> Control {
        control_with_requirements(id, &[])
    }

    fn control_with_requirements(id: &str, required: &[&str]) -> Control {
        Control {
            id: format!("control-{id}"),
            control_id: id.to_string(),
            category: "test".to_string(),
            title: format!("Control {id}"),
            description: "test".to_string(),
            owner: "Founder / System Operator".to_string(),
            status: "in_scope".to_string(),
            evidence_required: serde_json::json!(required),
            automation: "automated".to_string(),
            last_attested_at: None,
            next_attestation_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn evidence_row(
        control_id: &str,
        evidence_type: &str,
        payload: serde_json::Value,
        collected_at: DateTime<Utc>,
    ) -> ControlEvidence {
        ControlEvidence {
            id: format!(
                "ev-{control_id}-{evidence_type}-{}",
                collected_at.timestamp_micros()
            ),
            control_id: control_id.to_string(),
            evidence_type: evidence_type.to_string(),
            source: "test".to_string(),
            sha256_hash: sha256_json(&payload),
            payload,
            storage_url: None,
            period_start: collected_at - Duration::days(1),
            period_end: collected_at,
            collected_at,
            collected_by: "test".to_string(),
        }
    }

    fn base_context(
        controls: Vec<Control>,
        evidence: Vec<ControlEvidence>,
    ) -> QuestionnaireContext {
        QuestionnaireContext {
            tenant_id: Some("tenant-1".to_string()),
            controls,
            documents: Vec::new(),
            subprocessors: Vec::new(),
            incidents: Vec::new(),
            hipaa_baa_active: true,
            generated_at: Utc::now(),
            evidence,
            freshness_days: 90,
        }
    }

    fn context() -> QuestionnaireContext {
        base_context(
            [
                "CC1.1", "CC1.2", "CC1.3", "CC2.1", "CC2.2", "CC3.1", "CC3.2", "CC4.1", "CC4.2",
                "CC5.1", "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.6", "CC6.7", "CC6.8", "CC7.1",
                "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "CC9.2", "A1.1", "A1.2", "A1.3",
                "C1.1", "C1.2", "P1.1", "P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1", "P8.1",
            ]
            .into_iter()
            .map(control)
            .collect(),
            Vec::new(),
        )
    }

    fn spec(kind: AnswerKind, controls: &'static [&'static str]) -> AnswerSpec {
        AnswerSpec {
            id: "TEST-01",
            domain: "Test",
            question: "test question",
            kind,
            controls,
            doc_keywords: &[],
        }
    }

    #[test]
    fn parses_framework_aliases() {
        assert_eq!(
            "sig".parse::<QuestionnaireFramework>().unwrap(),
            QuestionnaireFramework::Sig
        );
        assert_eq!(
            "ccm".parse::<QuestionnaireFramework>().unwrap(),
            QuestionnaireFramework::Caiq
        );
        assert_eq!(
            "hecvat".parse::<QuestionnaireFramework>().unwrap(),
            QuestionnaireFramework::Hecvat
        );
        assert!("unknown".parse::<QuestionnaireFramework>().is_err());
    }

    #[test]
    fn generates_all_frameworks_with_stable_hashes() {
        for framework in QuestionnaireFramework::all().iter().copied() {
            let generated = generate_questionnaire(
                framework,
                QuestionnaireGenerationRequest {
                    tenant_id: Some("tenant-1".to_string()),
                    requester_company: Some("Acme".to_string()),
                    include_private_documents: Some(true),
                    include_markdown_report: Some(true),
                },
                context(),
            );
            assert!(!generated.answers.is_empty());
            assert_eq!(
                generated.completion.automated_answers, 0,
                "{framework:?}: no evidence means no automated answers"
            );
            assert_eq!(
                generated.completion.needs_review,
                generated.answers.len(),
                "{framework:?}"
            );
            assert!(generated.questionnaire_hash.len() == 64);
            assert!(generated
                .report_md
                .unwrap()
                .contains(framework.display_name()));
        }
    }

    #[test]
    fn control_present_without_evidence_needs_review_naming_the_gap() {
        let context = base_context(
            vec![control_with_requirements(
                "CC2.1",
                &["audit_log_sample", "audit_chain_verification"],
            )],
            Vec::new(),
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        assert_eq!(answer.confidence, 0.0);
        let notes = answer.notes.expect("gap is explained");
        assert!(notes.contains("missing required evidence"), "{notes}");
        assert!(notes.contains("CC2.1:audit_log_sample"), "{notes}");
        assert!(notes.contains("CC2.1:audit_chain_verification"), "{notes}");
        assert!(
            answer
                .evidence
                .iter()
                .all(|item| item.kind != "soc2_control"),
            "a catalog entry must never be presented as evidence"
        );
    }

    #[test]
    fn fresh_complete_evidence_automates_with_derived_confidence() {
        let payload = serde_json::json!({"entries": 3, "window": "24h"});
        let context = base_context(
            vec![control_with_requirements("CC2.1", &["audit_log_sample"])],
            vec![evidence_row(
                "CC2.1",
                "audit_log_sample",
                payload.clone(),
                Utc::now(),
            )],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::Automated);
        assert!(
            (answer.confidence - 1.0).abs() < f32::EPSILON,
            "confidence must equal the derived coverage, got {}",
            answer.confidence
        );
        assert!(
            answer
                .evidence
                .iter()
                .any(|item| item.kind == "soc2_evidence"
                    && item.hash.as_deref() == Some(sha256_json(&payload).as_str())),
            "the captured evidence row is the reference"
        );
        assert!(answer
            .evidence
            .iter()
            .all(|item| item.kind != "soc2_control"));
        assert!(answer.notes.is_none());
    }

    #[test]
    fn partial_evidence_coverage_derives_a_fractional_confidence() {
        let context = base_context(
            vec![control_with_requirements(
                "CC2.1",
                &["audit_log_sample", "audit_chain_verification"],
            )],
            vec![evidence_row(
                "CC2.1",
                "audit_log_sample",
                serde_json::json!({"entries": 1}),
                Utc::now(),
            )],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        assert!(
            (answer.confidence - 0.5).abs() < 0.001,
            "one of two required items is fresh: got {}",
            answer.confidence
        );
        let notes = answer.notes.expect("gap is explained");
        assert!(notes.contains("audit_chain_verification"), "{notes}");
    }

    #[test]
    fn stale_evidence_needs_review() {
        let context = base_context(
            vec![control_with_requirements("CC2.1", &["audit_log_sample"])],
            vec![evidence_row(
                "CC2.1",
                "audit_log_sample",
                serde_json::json!({"entries": 1}),
                Utc::now() - Duration::days(120),
            )],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        assert_eq!(answer.confidence, 0.0);
        let notes = answer.notes.expect("gap is explained");
        assert!(notes.contains("stale evidence"), "{notes}");
        assert!(notes.contains("audit_log_sample"), "{notes}");
    }

    #[test]
    fn tampered_evidence_fails_hash_verification_and_blocks_automation() {
        let mut row = evidence_row(
            "CC2.1",
            "audit_log_sample",
            serde_json::json!({"entries": 1}),
            Utc::now(),
        );
        row.sha256_hash = "deadbeef".to_string();
        let context = base_context(
            vec![control_with_requirements("CC2.1", &["audit_log_sample"])],
            vec![row],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        let notes = answer.notes.expect("gap is explained");
        assert!(notes.contains("hash verification"), "{notes}");
        assert!(notes.contains("audit_log_sample"), "{notes}");
    }

    #[test]
    fn latest_evidence_row_wins_for_questionnaire_answers() {
        let old = evidence_row(
            "CC2.1",
            "audit_log_sample",
            serde_json::json!({"entries": 1, "generation": "old"}),
            Utc::now() - Duration::days(2),
        );
        let new = evidence_row(
            "CC2.1",
            "audit_log_sample",
            serde_json::json!({"entries": 2, "generation": "new"}),
            Utc::now(),
        );
        let context = base_context(
            vec![control_with_requirements("CC2.1", &["audit_log_sample"])],
            vec![old.clone(), new.clone()],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::Automated);
        let reference = answer
            .evidence
            .iter()
            .find(|item| item.kind == "soc2_evidence")
            .expect("evidence reference");
        assert_eq!(reference.id, new.id, "a later correction supersedes");
        assert_ne!(reference.id, old.id);
    }

    #[test]
    fn inactive_mapped_control_blocks_automation() {
        let mut inactive = control_with_requirements("CC2.1", &["audit_log_sample"]);
        inactive.status = "not_applicable".to_string();
        let context = base_context(
            vec![inactive],
            vec![evidence_row(
                "CC2.1",
                "audit_log_sample",
                serde_json::json!({"entries": 1}),
                Utc::now(),
            )],
        );
        let answer = build_answer(&spec(AnswerKind::AuditLogging, &["CC2.1"]), &context);
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        let notes = answer.notes.expect("gap is explained");
        assert!(notes.contains("not active"), "{notes}");
    }

    #[test]
    fn hipaa_inactive_answer_is_exact_and_does_not_advertise_the_service() {
        let mut context = context();
        context.hipaa_baa_active = false;
        let generated = generate_questionnaire(
            QuestionnaireFramework::Hecvat,
            QuestionnaireGenerationRequest::default(),
            context,
        );
        let hipaa = generated
            .answers
            .iter()
            .find(|answer| answer.id == "HECVAT-HIPAA-01")
            .expect("HIPAA answer exists");
        assert_eq!(hipaa.status, AnswerStatus::NeedsReview);
        assert_eq!(hipaa.answer, HIPAA_INACTIVE_ANSWER);
        assert!(hipaa.answer.contains("does not currently offer"));
        assert!(!hipaa.answer.contains("Complete request"));
        assert!(!hipaa.answer.contains("signature"));
        assert!(!hipaa.answer.contains("activation"));
    }

    #[test]
    fn hipaa_active_answer_keeps_tenant_specific_wording() {
        let context = base_context(
            vec![control_with_requirements(
                "P1.1",
                &["privacy_policy_version"],
            )],
            vec![evidence_row(
                "P1.1",
                "privacy_policy_version",
                serde_json::json!({"version": "2026-10"}),
                Utc::now(),
            )],
        );
        let answer = build_answer(&spec(AnswerKind::HipaaBaa, &["P1.1"]), &context);
        assert!(answer
            .answer
            .contains("A HIPAA BAA is active for the requested tenant"));
        assert!(answer.answer.contains("tenant-1"));
        assert!(!answer.answer.contains("does not currently offer"));
        // Representing a tenant as HIPAA-active is a legal/contract judgment.
        assert_eq!(answer.status, AnswerStatus::NeedsReview);
        let notes = answer.notes.expect("legal review is named");
        assert!(notes.contains("legal/contract review required"), "{notes}");
    }

    #[test]
    fn automated_confidence_is_not_the_old_hardcoded_constant() {
        let source = include_str!("security_questionnaires.rs");
        // Split so this assertion's own text cannot satisfy the search.
        let old_constant = concat!("0.", "92");
        assert!(
            !source.contains(old_constant),
            "automated answers must derive confidence from evidence coverage"
        );
    }

    #[test]
    fn security_review_report_includes_all_frameworks() {
        let report = generate_security_review_report(
            QuestionnaireGenerationRequest {
                tenant_id: Some("tenant-1".to_string()),
                requester_company: Some("Acme".to_string()),
                include_private_documents: Some(true),
                include_markdown_report: Some(true),
            },
            context(),
        );
        assert_eq!(report.frameworks.len(), 3);
        assert!(report.report_md.contains("SIG"));
        assert!(report.report_md.contains("CAIQ"));
        assert!(report.report_md.contains("HECVAT"));
    }
}
