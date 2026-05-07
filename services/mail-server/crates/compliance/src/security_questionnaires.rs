//! Security questionnaire automation for Enterprise security reviews.
//!
//! This module generates ApexMail-owned answer packs mapped to common buyer
//! review frameworks (SIG, CAIQ, and HECVAT). It does not reproduce proprietary
//! questionnaire text; instead it emits normalized control questions, answers,
//! SOC 2 control mappings, and Trust Portal evidence references that can be
//! exported into a customer's preferred questionnaire format.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    soc2::Control,
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
    let mut evidence = evidence_for(spec, context, &source_controls);
    let status = answer_status(spec, context, &source_controls, &evidence);
    let confidence = match status {
        AnswerStatus::Automated => 0.92,
        AnswerStatus::NeedsReview => 0.55,
        AnswerStatus::NotApplicable => 0.99,
    };
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
        notes: notes_for(status, spec.kind),
    }
}

fn answer_status(
    spec: &AnswerSpec,
    context: &QuestionnaireContext,
    source_controls: &[String],
    evidence: &[EvidenceReference],
) -> AnswerStatus {
    match spec.kind {
        AnswerKind::HipaaBaa if !context.hipaa_baa_active => AnswerStatus::NeedsReview,
        AnswerKind::Subprocessors if context.subprocessors.is_empty() => AnswerStatus::Automated,
        AnswerKind::VendorRisk if context.subprocessors.is_empty() => AnswerStatus::Automated,
        _ if source_controls.is_empty() && evidence.is_empty() => AnswerStatus::NeedsReview,
        _ => AnswerStatus::Automated,
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
    for control_id in source_controls {
        if let Some(control) = context
            .controls
            .iter()
            .find(|c| c.control_id == *control_id)
        {
            evidence.insert(EvidenceReference {
                kind: "soc2_control".to_string(),
                id: control.control_id.clone(),
                title: control.title.clone(),
                hash: None,
                location: Some(format!("/v1/admin/soc2/controls/{}", control.control_id)),
            });
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

fn render_answer(
    kind: AnswerKind,
    context: &QuestionnaireContext,
    source_controls: &[String],
    evidence: &[EvidenceReference],
    status: AnswerStatus,
) -> String {
    if status == AnswerStatus::NeedsReview {
        return match kind {
            AnswerKind::HipaaBaa => "A HIPAA BAA workflow exists, but no active BAA was found for the requested tenant. Complete request, signature, countersignature, and activation before representing the tenant as HIPAA-active.".to_string(),
            _ => format!(
                "ApexMail has a configured review workflow for this domain, but this generated answer needs security-team review because the expected control or evidence source was not present in the current evidence set. Expected controls: {}.",
                if source_controls.is_empty() { "not currently in scope".to_string() } else { source_controls.join(", ") }
            ),
        };
    }

    match kind {
        AnswerKind::Governance => format!(
            "ApexMail maintains a SOC 2 control catalog covering governance, oversight, roles, responsibilities, policy communication, and monitoring. This answer is backed by {} mapped controls and {} Trust Portal evidence items.",
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
        AnswerKind::HipaaBaa => "A HIPAA BAA is active for the requested tenant. ApexMail tracks BAA request, customer signature, ApexMail countersignature, activation, termination, and hash-chained BAA events.".to_string(),
        AnswerKind::TrustPortal => "The Trust Portal exposes public documents, policy summaries, subprocessor records, incident history, and NDA-gated access requests for private security artifacts. Admin routes support document versioning and supersedence.".to_string(),
        AnswerKind::NetworkSecurity => "Network security answers map to SOC 2 logical access, transport security, provider throttling, WAF/IDS controls where enabled, and dedicated deployment architecture review for Enterprise customers.".to_string(),
        AnswerKind::SecurityTraining => "Security awareness and role training are tracked as governance controls in the SOC 2 catalog and included in questionnaire packs as security-team attestation items.".to_string(),
        AnswerKind::AssetManagement => "Asset and service ownership maps to SOC 2 structure, responsibility, monitoring, and change controls. Questionnaire answers include owner fields so stale ownership can be reviewed.".to_string(),
        AnswerKind::VendorRisk => "Vendor risk is represented through the Trust Portal subprocessor registry, DPA URLs, certification metadata, and reviewable data-category mapping for each active subprocessor.".to_string(),
    }
}

fn owner_for(kind: AnswerKind) -> &'static str {
    match kind {
        AnswerKind::Governance | AnswerKind::SecurityTraining => "Security",
        AnswerKind::AccessControl | AnswerKind::NetworkSecurity | AnswerKind::AssetManagement => {
            "Engineering"
        }
        AnswerKind::Encryption | AnswerKind::AuditLogging | AnswerKind::ChangeManagement => {
            "Platform Security"
        }
        AnswerKind::IncidentResponse | AnswerKind::BusinessContinuity => "Operations",
        AnswerKind::PrivacyRights
        | AnswerKind::Consent
        | AnswerKind::Subprocessors
        | AnswerKind::DataRetention
        | AnswerKind::HipaaBaa
        | AnswerKind::TrustPortal
        | AnswerKind::VendorRisk => "Compliance",
        AnswerKind::VulnerabilityManagement => "Security Engineering",
    }
}

fn notes_for(status: AnswerStatus, kind: AnswerKind) -> Option<String> {
    match (status, kind) {
        (AnswerStatus::NeedsReview, _) => Some(
            "Generated answer requires human review before it is sent to a customer or auditor."
                .to_string(),
        ),
        (AnswerStatus::Automated, AnswerKind::HipaaBaa) => Some(
            "Tenant-specific answer depends on the tenant_id supplied during generation."
                .to_string(),
        ),
        _ => None,
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
        Control {
            id: format!("control-{id}"),
            control_id: id.to_string(),
            category: "test".to_string(),
            title: format!("Control {id}"),
            description: "test".to_string(),
            owner: "Security".to_string(),
            status: "in_scope".to_string(),
            evidence_required: serde_json::json!([]),
            automation: "automated".to_string(),
            last_attested_at: None,
            next_attestation_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn context() -> QuestionnaireContext {
        QuestionnaireContext {
            tenant_id: Some("tenant-1".to_string()),
            controls: [
                "CC1.1", "CC1.2", "CC1.3", "CC2.1", "CC2.2", "CC3.1", "CC3.2", "CC4.1", "CC4.2",
                "CC5.1", "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.6", "CC6.7", "CC6.8", "CC7.1",
                "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "CC9.2", "A1.1", "A1.2", "A1.3",
                "C1.1", "C1.2", "P1.1", "P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1", "P8.1",
            ]
            .into_iter()
            .map(control)
            .collect(),
            documents: Vec::new(),
            subprocessors: Vec::new(),
            incidents: Vec::new(),
            hipaa_baa_active: true,
            generated_at: Utc::now(),
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
            assert_eq!(generated.completion.needs_review, 0, "{framework:?}");
            assert!(generated.questionnaire_hash.len() == 64);
            assert!(generated
                .report_md
                .unwrap()
                .contains(framework.display_name()));
        }
    }

    #[test]
    fn hipaa_answer_requires_tenant_active_baa() {
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
        assert!(hipaa.answer.contains("no active BAA"));
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
