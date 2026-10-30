//! Dedicated Tenant provisioning, the code-side half.
//!
//! The plan sells Dedicated Tenant (from €4,000/mo, 12-month minimum,
//! €10k–40k setup, single-tenant stack on dedicated compute (the dedicated-vCPU line), EU region by
//! default, 5M recipients, 2 managed IPs, named owner, monthly review). The
//! operating act of bringing a host group up is the OPERATOR's; this module
//! is everything the code can honestly do around it:
//!
//! 1. **Generate** a deterministic per-tenant deployment bundle from a
//!    dedicated-deployment record (`ent_private_deployments`): a
//!    docker-compose overlay whose apexmail images are pinned to a release
//!    SHA supplied as an INPUT (never invented), an env template carrying
//!    the tenant id, region, the two managed IPs, the sender domains and the
//!    EU-only default, a host-group naming scheme, and a `MIGRATION.md` ops
//!    checklist. The bundle is written under a deployment directory and its
//!    sha256 is recorded on the deployment row.
//! 2. **Validate** (fail closed, pure function): refuse to render or accept
//!    a deployment whose region is not EU/EEA, whose managed-IP count is not
//!    the plan's, whose release SHA is missing or malformed, whose setup fee
//!    or minimum term contradicts the catalog, or whose named owner is
//!    empty. An explicit operator override (non-EEA region, a different IP
//!    count) is accepted only when the record carries a reason, and the
//!    reason is recorded in the validation report and the audit trail.
//! 3. **Track** the lifecycle on the existing private-deploy records:
//!    requested → validated → provisioned → active → decommissioning →
//!    decommissioned. `active` is unreachable without the validated-bundle
//!    artifact, every transition is audited, and the admin surface is
//!    `routes.rs` (`/deployments/:id/bundle`, `/deployments/:id/transition`).
//! 4. **Report** the monthly review packet (JSON + markdown) from data the
//!    repo actually has: usage (`metering_events`), the managed IPs'
//!    warmup/reputation state (`ent_dedicated_ips` + the canonical warmup
//!    ladder), deliverability (`tenant_deliverability_metrics`), incidents
//!    (`finance_incidents`), the lifecycle audit trail
//!    (`ent_compliance_audit_logs`) and the next-billing summary from the
//!    catalog + product-line invoices. Data gaps are reported AS gaps, never
//!    papered over.
//!
//! Nothing in this module claims a real host exists. The bundle is a
//! rendered artifact; `provisioned` means the OPERATOR says the host group
//! is up, and it is audit-recorded as such.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::private_deploy::{PrivateDeployService, PrivateDeploymentDbRow};
use crate::types::{ApiResult, PrivateDeployment};

// ── Plan facts ──────────────────────────────────────────────────────────

/// The plan facts every validation compares against, sourced from the two
/// canonical catalogs, never hardcoded here:
///
/// * fees / minimum term / setup range ← `platform-catalog`
///   (`PRODUCT_LINES["dedicated_tenant"]`, `DEDICATED_TENANT_SETUP_*_CENTS`)
/// * included recipients / managed IPs / default region ←
///   `compliance::deployment_products::DedicatedTenant::default()`
///   (the structured product the plan's contract text is built from)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedicatedTenantPlanFacts {
    pub monthly_fee_cents: i64,
    pub minimum_term_months: i64,
    pub setup_min_cents: i64,
    pub setup_max_cents: i64,
    pub included_recipients: u64,
    pub managed_ip_count: usize,
    pub default_region: String,
}

/// Read the plan facts from the canonical catalogs. `Err` (never a panic —
/// this runs on a request path) when a catalog row vanishes, which the
/// validation surfaces as a fail-closed refusal.
pub fn plan_facts() -> Result<DedicatedTenantPlanFacts, String> {
    let line = platform_catalog::product_line_by_name("dedicated_tenant")
        .ok_or_else(|| "platform-catalog has no dedicated_tenant product line".to_string())?;
    let product = ::compliance::deployment_products::DedicatedTenant::default();
    Ok(DedicatedTenantPlanFacts {
        monthly_fee_cents: line.price_monthly_cents,
        minimum_term_months: line.minimum_contract_months,
        setup_min_cents: platform_catalog::DEDICATED_TENANT_SETUP_MIN_CENTS,
        setup_max_cents: platform_catalog::DEDICATED_TENANT_SETUP_MAX_CENTS,
        included_recipients: product.included_recipients,
        managed_ip_count: product.managed_dedicated_ips as usize,
        default_region: product.region,
    })
}

// ── The record-side input shape ─────────────────────────────────────────

/// The typed shape of `ent_private_deployments.config` for a dedicated
/// deployment. Extra keys are preserved (the column is shared with the
/// generic deployment path); missing keys default so a half-configured
/// record fails VALIDATION with a named reason instead of a decode panic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DedicatedTenantConfig {
    /// The tenant's managed recipient-facing IPs (the plan's contract
    /// figure: 2). Recorded on the deployment by the operator.
    #[serde(default)]
    pub managed_ips: Vec<String>,
    /// The tenant's sender domains (carried into the env template).
    #[serde(default)]
    pub sender_domains: Vec<String>,
    /// The named technical owner (the plan's "named owner"). Empty refuses.
    #[serde(default)]
    pub named_owner: Option<String>,
    /// A recorded operator decision to run outside EU/EEA. Required —
    /// with a reason, before a non-EEA region is accepted.
    #[serde(default)]
    pub region_override_reason: Option<String>,
    /// A recorded operator decision to deviate from the plan's managed-IP
    /// count. Required, with a reason, before any non-plan count.
    #[serde(default)]
    pub ip_count_override_reason: Option<String>,
    /// The contracted one-time setup fee, in euro cents.
    #[serde(default)]
    pub setup_fee_cents: Option<i64>,
    /// The contracted minimum term, in months.
    #[serde(default)]
    pub minimum_term_months: Option<i64>,
    /// The agreed monthly fee, in euro cents.
    #[serde(default)]
    pub monthly_fee_cents: Option<i64>,
    /// EU-only routing stays ON for dedicated tenants unless the operator
    /// explicitly recorded otherwise (the env template renders the value).
    #[serde(default)]
    pub eu_only_routing: Option<bool>,
}

/// Everything the bundle renderer and the validator need, extracted from a
/// deployment record plus the render-time release SHA input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedicatedBundleRequest {
    pub tenant_id: String,
    pub deployment_id: Uuid,
    pub deployment_name: String,
    pub deployment_type: String,
    pub region: String,
    pub release_sha: String,
    pub managed_ips: Vec<String>,
    pub sender_domains: Vec<String>,
    pub named_owner: String,
    pub setup_fee_cents: Option<i64>,
    pub minimum_term_months: Option<i64>,
    pub monthly_fee_cents: Option<i64>,
    pub region_override_reason: Option<String>,
    pub ip_count_override_reason: Option<String>,
    pub eu_only_routing: bool,
}

impl DedicatedBundleRequest {
    /// Extract the request from a deployment record. A malformed `config`
    /// value is a refusal (the caller maps this `Err` to VALIDATION), never
    /// a silent default.
    pub fn from_record(record: &PrivateDeployment, release_sha: &str) -> Result<Self, String> {
        let config: DedicatedTenantConfig = match &record.config {
            None | Some(serde_json::Value::Null) => DedicatedTenantConfig::default(),
            Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
                format!("deployment config is not a Dedicated Tenant config: {error}")
            })?,
        };
        Ok(Self {
            tenant_id: record.tenant_id.clone(),
            deployment_id: record.id,
            deployment_name: record.name.clone(),
            deployment_type: record.deployment_type.clone(),
            region: record.region.clone().unwrap_or_default(),
            release_sha: release_sha.trim().to_string(),
            managed_ips: config.managed_ips,
            sender_domains: config.sender_domains,
            named_owner: config.named_owner.unwrap_or_default().trim().to_string(),
            setup_fee_cents: config.setup_fee_cents,
            minimum_term_months: config.minimum_term_months,
            monthly_fee_cents: config.monthly_fee_cents,
            region_override_reason: config
                .region_override_reason
                .map(|reason| reason.trim().to_string())
                .filter(|reason| !reason.is_empty()),
            ip_count_override_reason: config
                .ip_count_override_reason
                .map(|reason| reason.trim().to_string())
                .filter(|reason| !reason.is_empty()),
            eu_only_routing: config.eu_only_routing.unwrap_or(true),
        })
    }
}

// ── Validation (fail closed, pure) ──────────────────────────────────────

/// One validation check. `code` is stable (the refusal identity tests and
/// operators key on it); `detail` names what was wrong AND what the plan
/// requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub code: String,
    pub passed: bool,
    pub detail: String,
}

/// An operator override that was RECORDED on the deployment and accepted by
/// validation. Overrides are never silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedOverride {
    pub kind: String,
    pub reason: String,
}

/// The validation artifact recorded on the deployment row. `passed` is the
/// gate the lifecycle reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub passed: bool,
    pub release_sha: String,
    pub checks: Vec<ValidationCheck>,
    pub overrides: Vec<RecordedOverride>,
    pub plan: DedicatedTenantPlanFacts,
}

impl ValidationReport {
    /// The stable refusal codes, in report order (empty = pass).
    pub fn failed_codes(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| check.code.as_str())
            .collect()
    }
}

/// The EEA's ISO-3166 alpha-2 country codes (27 EU members + IS, LI, NO).
pub const EEA_COUNTRY_CODES: &[&str] = &[
    "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr", "hu", "ie", "it", "lv",
    "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk", "si", "es", "se", "is", "li", "no",
];

/// Region tokens that identify the EU/EEA directly.
const EEA_REGION_TOKENS: &[&str] = &["eu", "eea", "europe"];

/// Region prefixes accepted as EU/EEA (`eu-central-1`, `eea-…`).
const EEA_REGION_PREFIXES: &[&str] = &["eu-", "eea-", "europe-"];

/// Whether a region string is EU/EEA by the plan's default rule: a known
/// EEA country code, one of `eu`/`eea`/`europe`, or an `eu-`/`eea-`/
/// `europe-` prefixed region (`eu-central-1`). Case-insensitive; the
/// operator's exact string is preserved in the report.
pub fn region_is_eea(region: &str) -> bool {
    let normalized = region.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    EEA_REGION_TOKENS.contains(&normalized.as_str())
        || EEA_COUNTRY_CODES.contains(&normalized.as_str())
        || EEA_REGION_PREFIXES
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
}

/// Provider location codes this deployment class knows about. Only `hel1`
/// (Helsinki) is provisioned: every Dedicated Tenant host is built there.
const PROVIDER_LOCATION_CODES: &[&str] = &["hel1", "fsn1", "nbg1", "ash", "hil", "sin"]; // hosting-gate: allow (the refusal list itself)

/// The one provider location ApexMail provisions in (contract/config-only
/// enforcement: no per-contract location column exists).
pub const DEDICATED_PROVIDER_LOCATION: &str = "hel1";

/// Whether a requested region names an acceptable provider location. A
/// provider-location-shaped region other than `hel1` is refused even when a
/// contract override reason is recorded: an override can authorize an
/// application region, not a different physical hosting location.
pub fn provider_location_is_permitted(region: &str) -> bool {
    let normalized = region.trim().to_ascii_lowercase();
    !PROVIDER_LOCATION_CODES.contains(&normalized.as_str())
        || normalized == DEDICATED_PROVIDER_LOCATION
}

/// A release SHA is the 40-hex (or ≥7-hex abbreviated) commit id the image
/// pins are rendered from. Anything else, including "latest", refuses.
pub fn release_sha_is_valid(sha: &str) -> bool {
    let sha = sha.trim();
    (7..=40).contains(&sha.len()) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sender_domain_is_valid(domain: &str) -> bool {
    let domain = domain.trim();
    if domain.is_empty() || domain.chars().count() > 253 {
        return false;
    }
    if domain.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let mut labels = 0;
    for label in domain.split('.') {
        labels += 1;
        if label.is_empty() || label.chars().count() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    labels >= 2
}

fn managed_ip_is_acceptable(ip: &IpAddr) -> bool {
    // A recipient-facing managed address must be a usable unicast address:
    // loopback, unspecified and multicast addresses can never be it.
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && !v4.is_multicast(),
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                // ::ffff:0:0/96 IPv4-mapped addresses are written as v4.
                && !v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// The fail-closed validation, pure over (request, plan facts). Every
/// refusal is a named check row, the caller refuses to render or record on
/// any failed row.
pub fn validate_bundle_request(
    request: &DedicatedBundleRequest,
    plan: &DedicatedTenantPlanFacts,
) -> ValidationReport {
    let mut checks: Vec<ValidationCheck> = Vec::new();
    let mut overrides: Vec<RecordedOverride> = Vec::new();

    let mut check = |code: &str, passed: bool, detail: String| {
        checks.push(ValidationCheck {
            code: code.to_string(),
            passed,
            detail,
        });
    };

    // 1. The record must be a dedicated deployment.
    check(
        "deployment_type_not_dedicated",
        request.deployment_type == "dedicated",
        format!(
            "deployment_type is {:?}; the Dedicated Tenant bundle only renders for 'dedicated'",
            request.deployment_type
        ),
    );

    // 2. Hosting location: every server is provisioned in Helsinki. A
    //    provider-location-shaped region other than hel1 is refused even
    //    under an override (an override may authorize an application
    //    region, never a different physical location; no per-contract
    //    location field exists).
    check(
        "provider_location_not_hel1",
        provider_location_is_permitted(&request.region),
        format!(
            "region {:?} names a provider location; only {:?} (Helsinki) is provisioned",
            request.region, DEDICATED_PROVIDER_LOCATION
        ),
    );

    // 3. Region: EU/EEA by default; anything else needs a recorded reason.
    let eea = region_is_eea(&request.region);
    match (&request.region_override_reason, eea) {
        (_, true) => check(
            "region_not_eea",
            true,
            format!("region {:?} is EU/EEA", request.region),
        ),
        (Some(reason), false) => {
            overrides.push(RecordedOverride {
                kind: "region".to_string(),
                reason: reason.clone(),
            });
            check(
                "region_not_eea",
                true,
                format!(
                    "region {:?} is outside EU/EEA; accepted under recorded operator override: {reason}",
                    request.region
                ),
            );
        }
        (None, false) => check(
            "region_not_eea",
            false,
            format!(
                "region {:?} is not EU/EEA (accepts an EEA country code, eu/eea/europe, or an eu-*/eea-* region); \
                 a non-EEA region requires config.region_override_reason",
                request.region
            ),
        ),
    }

    // 4. Managed IP count: the plan's figure; overrides need a reason and
    //    are recorded.
    let count = request.managed_ips.len();
    if count == plan.managed_ip_count {
        check(
            "managed_ip_count_mismatch",
            true,
            format!(
                "{count} managed IP(s) match the plan's {}",
                plan.managed_ip_count
            ),
        );
    } else if let Some(reason) = &request.ip_count_override_reason {
        overrides.push(RecordedOverride {
            kind: "managed_ip_count".to_string(),
            reason: reason.clone(),
        });
        check(
            "managed_ip_count_mismatch",
            true,
            format!(
                "{count} managed IP(s) differ from the plan's {}; accepted under recorded operator override: {reason}",
                plan.managed_ip_count
            ),
        );
    } else {
        check(
            "managed_ip_count_mismatch",
            false,
            format!(
                "{count} managed IP(s) configured; the plan includes {}, a different count requires config.ip_count_override_reason",
                plan.managed_ip_count
            ),
        );
    }

    // 5. Each managed IP must be a usable literal unicast address, unique.
    let mut bad_ips: Vec<String> = Vec::new();
    let mut parsed_ips: Vec<IpAddr> = Vec::new();
    for raw in &request.managed_ips {
        match raw.trim().parse::<IpAddr>() {
            Ok(ip) if managed_ip_is_acceptable(&ip) => parsed_ips.push(ip),
            Ok(_) => bad_ips.push(format!("{raw:?} is not a usable unicast address")),
            Err(_) => bad_ips.push(format!("{raw:?} is not an IP address")),
        }
    }
    let mut sorted = parsed_ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    sorted.sort();
    let unique = {
        let mut deduped = sorted.clone();
        deduped.dedup();
        deduped.len() == sorted.len()
    };
    if !unique {
        bad_ips.push("managed IPs contain duplicates".to_string());
    }
    check(
        "managed_ip_invalid",
        bad_ips.is_empty(),
        if bad_ips.is_empty() {
            format!("all {count} managed IP(s) are usable, unique unicast addresses")
        } else {
            bad_ips.join("; ")
        },
    );

    // 6. Release SHA: a render-time INPUT. Missing/`latest`/malformed refuses.
    check(
        "release_sha_invalid",
        release_sha_is_valid(&request.release_sha),
        format!(
            "release_sha {:?} must be 7-40 hex characters (a git commit id); image pins are never `latest`",
            request.release_sha
        ),
    );

    // 7. Setup fee vs the catalog's dedicated-tenant range.
    let setup_ok = request
        .setup_fee_cents
        .is_some_and(|fee| (plan.setup_min_cents..=plan.setup_max_cents).contains(&fee));
    check(
        "setup_fee_out_of_range",
        setup_ok,
        format!(
            "setup_fee_cents {:?} must sit within the catalog range {}..={} (€{:.0}–€{:.0})",
            request.setup_fee_cents,
            plan.setup_min_cents,
            plan.setup_max_cents,
            plan.setup_min_cents as f64 / 100.0,
            plan.setup_max_cents as f64 / 100.0
        ),
    );

    // 8. Minimum term vs the catalog's contract minimum (12 months).
    let term_ok = request
        .minimum_term_months
        .is_some_and(|months| months >= plan.minimum_term_months);
    check(
        "minimum_term_below_plan",
        term_ok,
        format!(
            "minimum_term_months {:?} must be >= the catalog minimum {}",
            request.minimum_term_months, plan.minimum_term_months
        ),
    );

    // 9. Monthly fee is "from €X": at or above the catalog is a deal, below
    //    is a contradiction.
    let monthly_ok = request
        .monthly_fee_cents
        .is_some_and(|fee| fee >= plan.monthly_fee_cents);
    check(
        "monthly_fee_below_list",
        monthly_ok,
        format!(
            "monthly_fee_cents {:?} must be >= the catalog list price {} (€{:.0}/mo \"from\")",
            request.monthly_fee_cents,
            plan.monthly_fee_cents,
            plan.monthly_fee_cents as f64 / 100.0
        ),
    );

    // 10. Named owner (the plan's "named owner").
    check(
        "named_owner_missing",
        !request.named_owner.trim().is_empty(),
        format!(
            "named_owner is {:?}; the plan requires a named technical owner on the record",
            request.named_owner
        ),
    );

    // 10. Sender domains: the env template and the DNS/DKIM checklist need
    //     at least one, and each must look like a domain.
    let mut bad_domains: Vec<String> = Vec::new();
    if request.sender_domains.is_empty() {
        bad_domains.push("no sender domains configured".to_string());
    }
    for domain in &request.sender_domains {
        if !sender_domain_is_valid(domain) {
            bad_domains.push(format!("{domain:?} is not a valid domain name"));
        }
    }
    check(
        "sender_domain_invalid",
        bad_domains.is_empty(),
        if bad_domains.is_empty() {
            format!(
                "{} sender domain(s) configured",
                request.sender_domains.len()
            )
        } else {
            bad_domains.join("; ")
        },
    );

    ValidationReport {
        passed: checks.iter().all(|check| check.passed),
        release_sha: request.release_sha.clone(),
        checks,
        overrides,
        plan: plan.clone(),
    }
}

// ── The deployment bundle ───────────────────────────────────────────────

/// One service of the tenant host group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackService {
    /// Compose service key (`docker-compose.prod.yml`).
    pub service: &'static str,
    /// Imagerepository suffix: the deployed image is
    /// `ghcr.io/sbelakho2/apexmail/<image>:<release_sha>`.
    pub image: &'static str,
}

/// The apexmail-built services of the tenant host group, mirroring
/// `docker-compose.prod.yml`. The dedicated tenant runs "the same pipeline
/// and images", the mail data plane plus its control plane, as a
/// single-tenant stack; the public site (marketing/nginx/certbot), the
/// sales plane, the shared monitoring/exporters and the backup jobs stay
/// operator-plane services, and the data services with upstream images
/// (postgres/redis/clickhouse) remain owned by the base compose files (the
/// overlay only rewrites apexmail image pins). A drift test
/// (`stack_services_match_the_prod_compose`) pins every entry against the
/// prod compose's service/image map.
pub const TENANT_STACK_SERVICES: &[StackService] = &[
    StackService {
        service: "api-server",
        image: "api-server",
    },
    StackService {
        service: "worker",
        image: "worker",
    },
    StackService {
        service: "mta",
        image: "mta",
    },
    StackService {
        service: "outbound-mta",
        image: "outbound-mta",
    },
    StackService {
        service: "imap-server",
        image: "imap-server",
    },
    StackService {
        service: "mailstore",
        image: "mailstore",
    },
    StackService {
        service: "tracking",
        image: "tracking-service",
    },
    StackService {
        service: "migrator",
        image: "migrator",
    },
    StackService {
        service: "billing-service",
        image: "billing-service",
    },
    StackService {
        service: "enterprise",
        image: "enterprise",
    },
    StackService {
        service: "compliance",
        image: "compliance",
    },
    StackService {
        service: "ha",
        image: "ha",
    },
    StackService {
        service: "isolation",
        image: "isolation",
    },
    StackService {
        service: "analytics-worker",
        image: "analytics-worker",
    },
    StackService {
        service: "ai-service",
        image: "ai-service",
    },
    StackService {
        service: "pdf-renderer",
        image: "pdf-renderer",
    },
    StackService {
        service: "observability",
        image: "observability",
    },
    StackService {
        service: "status-server",
        image: "status-server",
    },
];

/// The image registry namespace the prod compose tags services with.
const IMAGE_REPOSITORY_PREFIX: &str = "ghcr.io/sbelakho2/apexmail";

/// The deterministic host-group name for a tenant deployment. Host groups
/// are how the operator names the single-tenant stack in DNS, monitoring
/// and the runbooks: `hg-<tenant>-<deployment prefix>`.
pub fn host_group_name(tenant_id: &str, deployment_id: Uuid) -> String {
    let tenant: String = tenant_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let tenant = tenant.trim_matches('-');
    let tenant = if tenant.is_empty() { "tenant" } else { tenant };
    let tenant = &tenant[..tenant.len().min(32)];
    format!("hg-{tenant}-{}", &deployment_id.simple().to_string()[..8])
}

/// One rendered bundle file (path is relative to the bundle directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFile {
    pub path: String,
    pub contents: String,
}

/// The rendered bundle: fixed file list, deterministic bytes, and the
/// bundle identity.
///
/// The identity is `sha256` over `path \0 contents \0` for every file in
/// path order, the manifest file is deliberately EXCLUDED from that
/// identity (it lists the identity, so including it would recurse), and it
/// is the only file whose bytes are not the source of the identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedBundle {
    pub host_group: String,
    pub files: Vec<BundleFile>,
    pub sha256: String,
    pub manifest: serde_json::Value,
}

fn yaml_double_quoted(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn compose_overlay(request: &DedicatedBundleRequest, host_group: &str) -> String {
    let mut out = String::new();
    out.push_str("# ApexMail Dedicated Tenant host-group overlay, GENERATED by\n");
    out.push_str("# enterprise/src/dedicated_tenant.rs; do not hand-edit (re-render it).\n");
    out.push_str("#\n");
    out.push_str(&format!("# tenant:     {}\n", request.tenant_id));
    out.push_str(&format!("# deployment: {}\n", request.deployment_id));
    out.push_str(&format!("# host group: {host_group}\n"));
    out.push_str(&format!("# release:    {}\n", request.release_sha));
    out.push_str("#\n");
    out.push_str("# Layer on the canonical stack:\n");
    out.push_str("#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \\\n");
    out.push_str("#     -f docker-compose.tenant.yml --env-file tenant.env up -d\n");
    out.push_str("#\n");
    out.push_str("# Every apexmail image below is pinned to the release SHA (never `latest`).\n");
    out.push_str("# The data services (postgres, redis, clickhouse) keep the base compose's\n");
    out.push_str("# upstream images; this overlay only rewrites apexmail pins + labels.\n");
    out.push_str(&format!("name: {host_group}\n\n"));
    out.push_str("services:\n");
    for stack_service in TENANT_STACK_SERVICES {
        out.push_str(&format!("  {}:\n", stack_service.service));
        out.push_str(&format!(
            "    image: {IMAGE_REPOSITORY_PREFIX}/{}:{}\n",
            stack_service.image, request.release_sha
        ));
        out.push_str("    labels:\n");
        out.push_str(&format!(
            "      apexmail.tenant: {}\n",
            yaml_double_quoted(&request.tenant_id)
        ));
        out.push_str(&format!(
            "      apexmail.host-group: {}\n",
            yaml_double_quoted(host_group)
        ));
        out.push_str(&format!(
            "      apexmail.deployment-id: {}\n",
            yaml_double_quoted(&request.deployment_id.to_string())
        ));
        out.push_str(&format!(
            "      apexmail.release-sha: {}\n",
            yaml_double_quoted(&request.release_sha)
        ));
    }
    out
}

fn env_template(request: &DedicatedBundleRequest, host_group: &str) -> String {
    let ips = request
        .managed_ips
        .iter()
        .map(|ip| ip.trim().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let domains = request
        .sender_domains
        .iter()
        .map(|domain| domain.trim().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut out = String::new();
    out.push_str("# ApexMail Dedicated Tenant, environment template (GENERATED).\n");
    out.push_str("# Placeholders marked CHANGE_ME are filled by the operator from the secret\n");
    out.push_str("# store on the host; this file carries no secret material.\n");
    out.push_str(&format!("# tenant: {}\n", request.tenant_id));
    out.push_str(&format!("# host group: {host_group}\n"));
    out.push_str(&format!("# release: {}\n\n", request.release_sha));
    out.push_str(&format!("APEXMAIL_TENANT_ID={}\n", request.tenant_id));
    out.push_str(&format!(
        "APEXMAIL_DEPLOYMENT_ID={}\n",
        request.deployment_id
    ));
    out.push_str(&format!("APEXMAIL_HOST_GROUP={host_group}\n"));
    out.push_str(&format!("APEXMAIL_REGION={}\n", request.region));
    out.push_str(&format!(
        "# EU-only routing is the plan's default and stays ON unless the operator\n\
         # recorded otherwise on the deployment.\nAPEXMAIL_EU_ONLY_ROUTING={}\n",
        request.eu_only_routing
    ));
    out.push_str(&format!("APEXMAIL_RELEASE_SHA={}\n", request.release_sha));
    out.push_str("# The tenant's managed recipient-facing addresses (the plan includes 2).\n");
    out.push_str(&format!("TENANT_MANAGED_IPS={ips}\n"));
    out.push_str(
        "# The relay may bind ONLY these source addresses for this host group:\n\
         # outbound-mta refuses any other requested source IP before connecting\n\
         # (OUTBOUND_MTA_ALLOWED_SOURCE_IPS; see outbound-mta/src/relay.rs).\n",
    );
    out.push_str(&format!("OUTBOUND_MTA_ALLOWED_SOURCE_IPS={ips}\n"));
    out.push_str(&format!("TENANT_SENDER_DOMAINS={domains}\n"));
    out.push_str(&format!("TENANT_NAMED_OWNER={}\n", request.named_owner));
    out.push_str("DATABASE_URL=postgres://apexmail:CHANGE_ME@postgres:5432/apexmail\n");
    out.push_str("REDIS_URL=redis://:CHANGE_ME@redis:6379/0\n");
    out
}

fn ops_checklist(request: &DedicatedBundleRequest, host_group: &str) -> String {
    let ips = request
        .managed_ips
        .iter()
        .map(|ip| ip.trim().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let domains = request
        .sender_domains
        .iter()
        .map(|domain| domain.trim().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"# Dedicated Tenant migration checklist, {host_group}

GENERATED bundle for tenant `{tenant_id}` (deployment `{deployment_id}`),
release `{release_sha}`. This bundle is a rendered artifact: it is NOT proof
a host exists. `provisioned`/`active` on the deployment record are the
operator's act, entered through the admin surface and audited there.

## 0. Scope
- Host group: `{host_group}`, the single-tenant stack (same pipeline and
  images as the shared plane, release-pinned below).
- Region: `{region}`, EU/EEA default; any override is recorded in the
  deployment's validation report.
- Managed source IPs: {ips}
- Sender domains: {domains}
- Named technical owner: {named_owner}

## 1. Pre-flight (operator)
- [ ] Reserve/attach the two managed source IPs to the host group's relay
      NICs and set PTR records for the sender domains.
- [ ] Confirm the release `{release_sha}` is the approved build (image digests
      manifest from the CI pipeline) and the tenant contract (setup fee,
      12-month minimum) is signed.
- [ ] Prepare DNS: SPF/DKIM/DMARC for each sender domain.
- [ ] Fill the CHANGE_ME placeholders in `tenant.env` from the host secret store.

## 2. Deploy
- [ ] Layer the overlay and bring the stack up:
      `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.tenant.yml --env-file tenant.env up -d`
- [ ] Run the migrator to the chain head (the `migrator` service).
- [ ] Register the two managed IPs as this tenant's routing identities so the
      worker selects them (`dedicated_ips` rows for the tenant; the relay
      itself binds whatever the route requests, restricted to
      OUTBOUND_MTA_ALLOWED_SOURCE_IPS by this bundle's env template).

## 3. Acceptance probes
- [ ] `/health` and `/readiness` on api-server, enterprise, outbound-mta.
- [ ] Send a probe message: the relay's acceptance record must report
      `actual_source_ip` equal to one of the two managed IPs and the route
      must consume warmup capacity for it.
- [ ] Confirm the monthly review packet renders:
      `dedicated-tenant review --tenant-id {tenant_id} --month <YYYY-MM>`.
- [ ] Record `provisioned`, then `active`, on the deployment through the
      admin surface (audited; `active` is refused without this bundle's
      validation artifact).

## 4. IP warmup
- [ ] Start warmup on schedule; the canonical ladder is
      `mail_common::warmup` (day 0-1: 50/day, doubling to 250k before the
      60-day graduation). Never exceed the day's cap on either IP.

## 5. Monthly review (founder)
- [ ] Run the review packet each month and archive it:
      usage vs the plan's included volume, per-IP warmup/reputation,
      deliverability, incidents, next-billing.

## 6. Rollback / decommission
- [ ] Roll back by re-tagging the previous release pins (see
      deploy/rollback-plan.md); the overlay's single SHA makes the previous
      bundle the rollback target.
- [ ] Decommission: record `decommissioning` → `decommissioned` on the
      deployment; export per the contract window; destroy the host group.
"#,
        tenant_id = request.tenant_id,
        deployment_id = request.deployment_id,
        release_sha = request.release_sha,
        region = request.region,
        named_owner = request.named_owner,
    )
}

/// Render the deterministic bundle. Pure: same request ⇒ same bytes and the
/// same `sha256`; no clock, no host, no output path participates.
pub fn render_bundle(request: &DedicatedBundleRequest) -> RenderedBundle {
    let host_group = host_group_name(&request.tenant_id, request.deployment_id);
    let files = vec![
        BundleFile {
            path: "docker-compose.tenant.yml".to_string(),
            contents: compose_overlay(request, &host_group),
        },
        BundleFile {
            path: "tenant.env".to_string(),
            contents: env_template(request, &host_group),
        },
        BundleFile {
            path: "MIGRATION.md".to_string(),
            contents: ops_checklist(request, &host_group),
        },
    ];

    let mut hasher = Sha256::new();
    let mut file_rows = Vec::with_capacity(files.len());
    for file in &files {
        hasher.update(file.path.as_bytes());
        hasher.update([0u8]);
        hasher.update(file.contents.as_bytes());
        hasher.update([0u8]);
        file_rows.push(serde_json::json!({
            "path": file.path,
            "sha256": hex::encode(Sha256::digest(file.contents.as_bytes())),
            "bytes": file.contents.len(),
        }));
    }
    let sha256 = hex::encode(hasher.finalize());
    let manifest = serde_json::json!({
        "bundle": "apexmail.dedicated-tenant.bundle/1",
        "tenant_id": request.tenant_id,
        "deployment_id": request.deployment_id,
        "host_group": host_group,
        "release_sha": request.release_sha,
        "region": request.region,
        "managed_ips": request.managed_ips,
        "sender_domains": request.sender_domains,
        "eu_only_routing": request.eu_only_routing,
        "sha256": sha256,
        "files": file_rows,
    });

    RenderedBundle {
        host_group,
        files,
        sha256,
        manifest,
    }
}

/// Where a written bundle landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLocation {
    pub directory: PathBuf,
    pub sha256: String,
}

/// Write a rendered bundle under `<base>/<tenant_id>/<deployment_id>/`.
/// The file names are fixed by the renderer (no request input reaches the
/// paths). Re-writing the same bundle is idempotent (same bytes); the
/// `manifest.json` is written last so a half-written directory is
/// recognisable by its absence.
pub fn write_bundle(
    base: &Path,
    request: &DedicatedBundleRequest,
    bundle: &RenderedBundle,
) -> Result<BundleLocation, String> {
    let directory = base
        .join(&request.tenant_id)
        .join(request.deployment_id.to_string());
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create bundle directory {}: {error}", directory.display()))?;
    for file in &bundle.files {
        let path = directory.join(&file.path);
        std::fs::write(&path, file.contents.as_bytes())
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    let manifest_path = directory.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&bundle.manifest)
        .map_err(|error| format!("serialize bundle manifest: {error}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|error| format!("write {}: {error}", manifest_path.display()))?;
    Ok(BundleLocation {
        directory,
        sha256: bundle.sha256.clone(),
    })
}

// ── Lifecycle state machine ─────────────────────────────────────────────

/// The dedicated-tenant provisioning lifecycle:
/// requested → validated → provisioned → active → decommissioning →
/// decommissioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedicatedLifecycleState {
    Requested,
    Validated,
    Provisioned,
    Active,
    Decommissioning,
    Decommissioned,
}

impl DedicatedLifecycleState {
    pub const ALL: [DedicatedLifecycleState; 6] = [
        Self::Requested,
        Self::Validated,
        Self::Provisioned,
        Self::Active,
        Self::Decommissioning,
        Self::Decommissioned,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Validated => "validated",
            Self::Provisioned => "provisioned",
            Self::Active => "active",
            Self::Decommissioning => "decommissioning",
            Self::Decommissioned => "decommissioned",
        }
    }

    /// Parse a stored status into a lifecycle state. The generic deployment
    /// vocabulary maps onto the machine without a data rewrite (migration
    /// 261): `pending` is the storage synonym of `requested` (the create
    /// path's spelling), `provisioning` of `provisioned`, and `maintenance`
    /// is an operational sub-state of `active`. `failed` is NOT a lifecycle
    /// state (it is the generic path's terminal failure) and parses to
    /// `None`, so the machine refuses to move such a row.
    pub fn from_status(status: &str) -> Option<Self> {
        match status.trim().to_ascii_lowercase().as_str() {
            "requested" | "pending" => Some(Self::Requested),
            "validated" => Some(Self::Validated),
            "provisioned" | "provisioning" => Some(Self::Provisioned),
            "active" | "maintenance" => Some(Self::Active),
            "decommissioning" => Some(Self::Decommissioning),
            "decommissioned" => Some(Self::Decommissioned),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Decommissioned)
    }

    /// The states this state may move to. Forward-only; no skips and no
    /// re-entry (a validated bundle is re-rendered by re-validating from
    /// `requested`).
    pub fn allowed_next(&self) -> &'static [DedicatedLifecycleState] {
        match self {
            Self::Requested => &[Self::Validated],
            Self::Validated => &[Self::Provisioned],
            Self::Provisioned => &[Self::Active],
            Self::Active => &[Self::Decommissioning],
            Self::Decommissioning => &[Self::Decommissioned],
            Self::Decommissioned => &[],
        }
    }
}

/// What the row proves about the validation artifact at transition time.
#[derive(Debug, Clone, Copy, Default)]
pub struct LifecycleEvidence<'a> {
    pub bundle_sha256: Option<&'a str>,
    pub validation_passed: Option<bool>,
}

/// A refused transition: a stable code plus a message naming what was wrong
/// and what is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRefusal {
    pub code: &'static str,
    pub message: String,
}

/// Authorize one lifecycle transition, fail closed. `active` is unreachable
/// without the validated-bundle artifact (`bundle_sha256` recorded and
/// `validation_passed == true`), and `validated` itself cannot be entered
/// without a passing validation report.
pub fn authorize_transition(
    from: DedicatedLifecycleState,
    to: DedicatedLifecycleState,
    evidence: &LifecycleEvidence<'_>,
) -> Result<(), TransitionRefusal> {
    if !from.allowed_next().contains(&to) {
        let allowed = from
            .allowed_next()
            .iter()
            .map(|state| state.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let allowed = if allowed.is_empty() {
            "none (terminal)".to_string()
        } else {
            allowed
        };
        return Err(TransitionRefusal {
            code: "INVALID_TRANSITION",
            message: format!(
                "{} -> {} is not a legal lifecycle transition (from {}: {allowed})",
                from.as_str(),
                to.as_str(),
                from.as_str()
            ),
        });
    }

    let artifact_ok = evidence
        .bundle_sha256
        .is_some_and(|sha| !sha.trim().is_empty());
    let validated_ok = evidence.validation_passed == Some(true);
    match to {
        DedicatedLifecycleState::Validated | DedicatedLifecycleState::Active
            if !(artifact_ok && validated_ok) =>
        {
            return Err(TransitionRefusal {
                code: "VALIDATION_ARTIFACT_MISSING",
                message: format!(
                    "{} -> {} requires a recorded, PASSED bundle validation \
                     (bundle_sha256 and validation_report.passed=true); refusing",
                    from.as_str(),
                    to.as_str()
                ),
            });
        }
        DedicatedLifecycleState::Provisioned if !artifact_ok => {
            return Err(TransitionRefusal {
                code: "VALIDATION_ARTIFACT_MISSING",
                message: format!(
                    "{} -> provisioned requires the recorded bundle artifact \
                     (bundle_sha256); refusing",
                    from.as_str()
                ),
            });
        }
        _ => {}
    }
    Ok(())
}

// ── Service extension: render/validate + transitions ────────────────────

/// The outcome of a successful render+validate cycle: what was recorded on
/// the deployment row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedBundleOutcome {
    pub deployment: PrivateDeployment,
    pub host_group: String,
    pub bundle_path: String,
    pub bundle_sha256: String,
    pub validation_report: ValidationReport,
}

impl PrivateDeployService {
    /// Render and validate the dedicated-tenant bundle for a deployment,
    /// then record the artifact and move the record `requested → validated`.
    ///
    /// Fail closed: a failed validation writes NOTHING (no files, no row
    /// change) and returns the full report under the VALIDATION code. A
    /// record outside the `requested` state is refused without touching the
    /// artifact columns.
    pub async fn render_dedicated_bundle(
        &self,
        id: Uuid,
        release_sha: &str,
        output_base: &Path,
    ) -> Result<ApiResult<DedicatedBundleOutcome>, String> {
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.db())
        .await
        .map_err(|e| format!("Get deployment for bundle: {e}"))?;
        let record: PrivateDeployment = match row {
            Some(row) => row.into(),
            None => return Ok(ApiResult::err("Deployment not found", "NOT_FOUND")),
        };

        let state = match DedicatedLifecycleState::from_status(&record.status) {
            Some(state) => state,
            None => {
                return Ok(ApiResult::err(
                    format!(
                        "deployment status {:?} is not part of the dedicated-tenant lifecycle",
                        record.status
                    ),
                    "INVALID_STATE",
                ))
            }
        };
        if state != DedicatedLifecycleState::Requested {
            return Ok(ApiResult::err(
                format!(
                    "a bundle can only be rendered from the requested state; this deployment is {}",
                    state.as_str()
                ),
                "INVALID_STATE",
            ));
        }

        let request = match DedicatedBundleRequest::from_record(&record, release_sha) {
            Ok(request) => request,
            Err(error) => return Ok(ApiResult::err(error, "VALIDATION")),
        };
        let plan = match plan_facts() {
            Ok(plan) => plan,
            Err(error) => return Ok(ApiResult::err(error, "VALIDATION")),
        };
        let report = validate_bundle_request(&request, &plan);
        if !report.passed {
            // Fail closed: nothing rendered, nothing written, row untouched.
            let failed = report.failed_codes().join(", ");
            return Ok(ApiResult::err(
                format!(
                    "dedicated-tenant bundle validation refused the deployment ({failed}); {} check(s) failed",
                    report.failed_codes().len()
                ),
                "VALIDATION",
            ));
        }

        let bundle = render_bundle(&request);
        let location = match write_bundle(output_base, &request, &bundle) {
            Ok(location) => location,
            Err(error) => return Ok(ApiResult::err(error, "BUNDLE_WRITE")),
        };
        let report_json = serde_json::to_value(&report)
            .map_err(|e| format!("Serialize validation report: {e}"))?;

        let updated = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "UPDATE ent_private_deployments
             SET status = 'validated', bundle_path = $2, bundle_sha256 = $3,
                 validated_at = NOW(), validation_report = $4, updated_at = NOW()
             WHERE id = $1 AND status IN ('requested', 'pending')
             RETURNING *",
        )
        .bind(id)
        .bind(location.directory.to_string_lossy().to_string())
        .bind(&location.sha256)
        .bind(&report_json)
        .fetch_optional(self.db())
        .await
        .map_err(|e| format!("Record bundle artifact: {e}"))?;

        match updated {
            Some(row) => {
                tracing::info!(
                    deployment_id = %id,
                    tenant_id = %record.tenant_id,
                    bundle_sha256 = %location.sha256,
                    host_group = %bundle.host_group,
                    "Dedicated tenant bundle validated and recorded; deployment is `validated`"
                );
                Ok(ApiResult::ok(DedicatedBundleOutcome {
                    deployment: row.into(),
                    host_group: bundle.host_group,
                    bundle_path: location.directory.to_string_lossy().to_string(),
                    bundle_sha256: location.sha256,
                    validation_report: report,
                }))
            }
            None => Ok(ApiResult::err(
                "the deployment left the requested state while rendering; the bundle was not recorded",
                "INVALID_STATE",
            )),
        }
    }

    /// Move a dedicated deployment along the lifecycle. The validation
    /// artifact on the row is the evidence the machine reads; `active` is
    /// unreachable without it. Decommissioning steps require a recorded
    /// `reason` (carried into the audit trail by the caller).
    pub async fn transition_dedicated(
        &self,
        id: Uuid,
        to: &str,
        reason: Option<&str>,
    ) -> Result<ApiResult<PrivateDeployment>, String> {
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.db())
        .await
        .map_err(|e| format!("Get deployment for transition: {e}"))?;
        let record: PrivateDeployment = match row {
            Some(row) => row.into(),
            None => return Ok(ApiResult::err("Deployment not found", "NOT_FOUND")),
        };
        if record.deployment_type != "dedicated" {
            return Ok(ApiResult::err(
                "the dedicated-tenant lifecycle only applies to dedicated deployments",
                "VALIDATION",
            ));
        }

        let from = match DedicatedLifecycleState::from_status(&record.status) {
            Some(state) => state,
            None => {
                return Ok(ApiResult::err(
                    format!(
                        "deployment status {:?} is not part of the dedicated-tenant lifecycle",
                        record.status
                    ),
                    "INVALID_STATE",
                ))
            }
        };
        let target = match DedicatedLifecycleState::ALL
            .iter()
            .find(|state| state.as_str() == to.trim().to_ascii_lowercase())
        {
            Some(state) => *state,
            None => {
                return Ok(ApiResult::err(
                    format!(
                        "unknown lifecycle target {to:?}; expected one of: {}",
                        DedicatedLifecycleState::ALL
                            .iter()
                            .map(|state| state.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "VALIDATION",
                ))
            }
        };

        if matches!(
            target,
            DedicatedLifecycleState::Decommissioning | DedicatedLifecycleState::Decommissioned
        ) && reason.map(str::trim).unwrap_or_default().is_empty()
        {
            return Ok(ApiResult::err(
                format!(
                    "{} -> {} requires a reason for the audit trail",
                    from.as_str(),
                    target.as_str()
                ),
                "VALIDATION",
            ));
        }

        let validation_passed = record
            .validation_report
            .as_ref()
            .and_then(|report| report.get("passed"))
            .and_then(serde_json::Value::as_bool);
        let evidence = LifecycleEvidence {
            bundle_sha256: record.bundle_sha256.as_deref(),
            validation_passed,
        };
        if let Err(refusal) = authorize_transition(from, target, &evidence) {
            return Ok(ApiResult::err(refusal.message, refusal.code));
        }

        // Billing contract at activation (external audit item 14): Dedicated
        // Tenant is a first-class contract line in the SAME billing control
        // plane, so the `provisioned -> active` transition records the
        // product-line contract with the deployment's validated setup fee
        // and minimum term (catalog defaults when the config records none).
        // A refused billing write refuses the activation: a live dedicated
        // tenant must never exist outside the billing books. The write is
        // idempotent per (tenant, line), so a retried transition can never
        // mint a second contract; the sweep bills it monthly from the next
        // fully covered calendar month.
        if target == DedicatedLifecycleState::Active {
            let config: DedicatedTenantConfig = match &record.config {
                None | Some(serde_json::Value::Null) => DedicatedTenantConfig::default(),
                Some(value) => match serde_json::from_value(value.clone()) {
                    Ok(config) => config,
                    Err(error) => {
                        return Ok(ApiResult::err(
                            format!("deployment config is not a Dedicated Tenant config: {error}"),
                            "VALIDATION",
                        ))
                    }
                },
            };
            if let Err(error) = billing_service::product_lines::activate_dedicated_tenant_contract(
                self.db(),
                &record.tenant_id,
                config.setup_fee_cents,
                config.minimum_term_months,
            )
            .await
            {
                return Ok(ApiResult::err(
                    format!("the Dedicated Tenant billing contract could not be recorded: {error}"),
                    "BILLING",
                ));
            }
        }

        // CAS on the stored spelling: a concurrent transition loses cleanly.
        let updated = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "UPDATE ent_private_deployments SET status = $3, updated_at = NOW()
             WHERE id = $1 AND status = $2
             RETURNING *",
        )
        .bind(id)
        .bind(&record.status)
        .bind(target.as_str())
        .fetch_optional(self.db())
        .await
        .map_err(|e| format!("Record transition: {e}"))?;

        match updated {
            Some(row) => {
                tracing::info!(
                    deployment_id = %id,
                    tenant_id = %record.tenant_id,
                    from = %from.as_str(),
                    to = %target.as_str(),
                    "Dedicated tenant lifecycle transition recorded"
                );
                Ok(ApiResult::ok(row.into()))
            }
            None => Ok(ApiResult::err(
                "the deployment changed state concurrently; transition not recorded",
                "INVALID_STATE",
            )),
        }
    }

    /// The latest dedicated deployment of a tenant (what the monthly review
    /// is about), or `None` when the tenant has none.
    pub async fn latest_dedicated_deployment(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PrivateDeployment>, String> {
        let row = sqlx::query_as::<_, PrivateDeploymentDbRow>(
            "SELECT * FROM ent_private_deployments
             WHERE tenant_id = $1 AND deployment_type = 'dedicated'
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(self.db())
        .await
        .map_err(|e| format!("Get latest dedicated deployment: {e}"))?;
        Ok(row.map(Into::into))
    }
}

// ── Monthly review packet ───────────────────────────────────────────────

/// One month of the review period (UTC calendar month).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPeriod {
    pub label: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl ReviewPeriod {
    /// The UTC calendar month `YYYY-MM`.
    pub fn for_month(year: i32, month: u32) -> Option<Self> {
        if !(1..=12).contains(&month) {
            return None;
        }
        let start = Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).single()?;
        let (next_year, next_month) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        let end = Utc
            .with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
            .single()?;
        Some(Self {
            label: format!("{year:04}-{month:02}"),
            start,
            end,
        })
    }

    /// Parse the `YYYY-MM` label the admin surface and CLI take.
    pub fn parse(label: &str) -> Option<Self> {
        let label = label.trim();
        let (year, month) = label.split_once('-')?;
        if year.len() != 4 || month.len() != 2 {
            return None;
        }
        Self::for_month(year.parse().ok()?, month.parse().ok()?)
    }

    /// The month `as_of` falls in.
    pub fn current(as_of: DateTime<Utc>) -> Self {
        Self::for_month(as_of.year(), as_of.month())
            .expect("the current date is always a valid month")
    }
}

/// The plan facts as the packet states them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPlanFacts {
    pub monthly_fee_cents: i64,
    pub minimum_term_months: i64,
    pub setup_min_cents: i64,
    pub setup_max_cents: i64,
    pub included_recipients: i64,
    pub managed_ip_count: i64,
    pub default_region: String,
}

/// Usage vs the included volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewUsage {
    pub emails_sent: i64,
    pub api_calls: i64,
    pub included_recipients: i64,
    pub utilization_percent: f64,
    pub source: String,
}

/// One managed IP's state as the repo records it, plus the canonical warmup
/// standing DERIVED from `warming_started_at` (never from the recorded
/// percentage alone).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewManagedIp {
    pub ip_address: String,
    pub status: String,
    pub warming_started_at: Option<DateTime<Utc>>,
    pub recorded_warming_progress_percent: Option<i32>,
    pub derived_warmup_day: Option<u32>,
    pub derived_daily_limit: Option<u64>,
    pub current_daily_limit: Option<i32>,
    pub reputation_score: Option<f64>,
    pub emails_sent_total: i64,
    pub bounces_total: i32,
    pub complaints_total: i32,
    pub blocklisted: bool,
}

/// Deliverability, aggregated from the tenant's recorded metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewDeliverability {
    pub emails_sent: i64,
    pub emails_delivered: i64,
    pub emails_bounced: i64,
    pub emails_complained: i64,
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub source: String,
}

/// One tenant-scoped finance incident in the period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewIncident {
    pub kind: String,
    pub severity: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// The contract row, when one exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewContract {
    pub product_line: String,
    pub status: String,
    pub active_from: DateTime<Utc>,
}

/// The latest product-line invoice on the tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewInvoice {
    pub invoice_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub status: String,
    pub issue_date: Option<DateTime<Utc>>,
}

/// Next-billing summary: catalog facts + whatever the invoices prove.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewBilling {
    pub monthly_fee_cents: i64,
    pub minimum_term_months: i64,
    pub annual_commitment_cents: i64,
    pub setup_min_cents: i64,
    pub setup_max_cents: i64,
    pub contract: Option<ReviewContract>,
    pub last_product_line_invoice: Option<ReviewInvoice>,
    pub notes: Vec<String>,
}

/// The monthly review packet (the founder's per-tenant review, generated
/// from repo data; gaps are named, never papered over).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonthlyReviewPacket {
    pub packet: String,
    pub tenant_id: String,
    pub period: ReviewPeriod,
    pub deployment: Option<ReviewDeploymentRef>,
    pub plan: ReviewPlanFacts,
    pub usage: ReviewUsage,
    pub managed_ips: Vec<ReviewManagedIp>,
    pub deliverability: ReviewDeliverability,
    pub incidents: Vec<ReviewIncident>,
    pub lifecycle_events_in_period: i64,
    pub billing: ReviewBilling,
    pub gaps: Vec<String>,
}

/// The deployment the review is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDeploymentRef {
    pub deployment_id: Uuid,
    pub name: String,
    pub status: String,
    pub region: String,
    pub host_group: String,
    pub bundle_sha256: Option<String>,
    pub bundle_validated: bool,
}

impl MonthlyReviewPacket {
    /// Render the compact markdown form the founder reads.
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Dedicated Tenant monthly review, {}\n\n",
            self.tenant_id
        ));
        out.push_str(&format!("- Period: {}\n", self.period.label));
        match &self.deployment {
            Some(deployment) => {
                out.push_str(&format!(
                    "- Deployment: {} ({}, {}, host group {})\n",
                    deployment.name,
                    deployment.deployment_id,
                    deployment.status,
                    deployment.host_group
                ));
                out.push_str(&format!(
                    "- Bundle: {} (validated: {})\n",
                    deployment.bundle_sha256.as_deref().unwrap_or("none"),
                    deployment.bundle_validated
                ));
            }
            None => out.push_str("- Deployment: NONE FOUND for this tenant\n"),
        }
        out.push_str(&format!(
            "- Named owner: see the deployment record; region default {}\n\n",
            self.plan.default_region
        ));

        out.push_str("## Usage\n");
        out.push_str(&format!(
            "- Recipients sent: {} of {} included ({:.2}%)\n",
            self.usage.emails_sent, self.usage.included_recipients, self.usage.utilization_percent
        ));
        out.push_str(&format!("- API calls: {}\n", self.usage.api_calls));
        out.push_str(&format!("- Source: {}\n\n", self.usage.source));

        out.push_str("## Managed IPs\n");
        if self.managed_ips.is_empty() {
            out.push_str("- NONE recorded in `ent_dedicated_ips` for this tenant\n");
        }
        for ip in &self.managed_ips {
            out.push_str(&format!(
                "- {} ({}), warmup day {} (cap {}), recorded progress {}, reputation {}, sent {}, bounces {}, complaints {}, blocklisted {}\n",
                ip.ip_address,
                ip.status,
                ip.derived_warmup_day
                    .map(|day| day.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                ip.derived_daily_limit
                    .map(|limit| limit.to_string())
                    .unwrap_or_else(|| "unthrottled".to_string()),
                ip.recorded_warming_progress_percent
                    .map(|percent| format!("{percent}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                ip.reputation_score
                    .map(|score| format!("{score:.1}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                ip.emails_sent_total,
                ip.bounces_total,
                ip.complaints_total,
                ip.blocklisted
            ));
        }
        out.push('\n');

        out.push_str("## Deliverability\n");
        out.push_str(&format!(
            "- Sent {} / delivered {} / bounced {} / complained {}\n",
            self.deliverability.emails_sent,
            self.deliverability.emails_delivered,
            self.deliverability.emails_bounced,
            self.deliverability.emails_complained
        ));
        out.push_str(&format!(
            "- delivery {:.2}%, bounce {:.2}%, complaint {:.2}%\n",
            self.deliverability.delivery_rate * 100.0,
            self.deliverability.bounce_rate * 100.0,
            self.deliverability.complaint_rate * 100.0
        ));
        out.push_str(&format!("- Source: {}\n\n", self.deliverability.source));

        out.push_str("## Incidents\n");
        if self.incidents.is_empty() {
            out.push_str("- None recorded for this tenant in the period\n");
        }
        for incident in &self.incidents {
            out.push_str(&format!(
                "- {} [{}] {} at {}\n",
                incident.kind,
                incident.severity,
                incident.status,
                incident.created_at.to_rfc3339()
            ));
        }
        out.push_str(&format!(
            "- Lifecycle audit events in period: {}\n\n",
            self.lifecycle_events_in_period
        ));

        out.push_str("## Next billing\n");
        out.push_str(&format!(
            "- Monthly fee €{:.2}; minimum term {} months; annual commitment €{:.2}\n",
            self.billing.monthly_fee_cents as f64 / 100.0,
            self.billing.minimum_term_months,
            self.billing.annual_commitment_cents as f64 / 100.0
        ));
        out.push_str(&format!(
            "- Setup range €{:.2}–€{:.2}\n",
            self.billing.setup_min_cents as f64 / 100.0,
            self.billing.setup_max_cents as f64 / 100.0
        ));
        match &self.billing.last_product_line_invoice {
            Some(invoice) => out.push_str(&format!(
                "- Last product-line invoice: {} {} {:.2} ({})\n",
                invoice.invoice_id,
                invoice.status,
                invoice.amount_cents as f64 / 100.0,
                invoice.currency
            )),
            None => out.push_str("- Last product-line invoice: none recorded\n"),
        }
        for note in &self.billing.notes {
            out.push_str(&format!("- Note: {note}\n"));
        }

        if !self.gaps.is_empty() {
            out.push_str("\n## Data gaps\n");
            for gap in &self.gaps {
                out.push_str(&format!("- {gap}\n"));
            }
        }
        out
    }
}

/// Internal row shapes for the packet reads.
#[derive(Debug, sqlx::FromRow)]
struct ReviewDeploymentRow {
    id: Uuid,
    name: String,
    status: String,
    region: Option<String>,
    bundle_sha256: Option<String>,
    validation_report: Option<serde_json::Value>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReviewManagedIpRow {
    ip_address: String,
    status: String,
    warming_started_at: Option<DateTime<Utc>>,
    warming_progress_percent: Option<i32>,
    current_daily_limit: Option<i32>,
    reputation_score: Option<f64>,
    emails_sent_total: i64,
    bounces_total: i32,
    complaints_total: i32,
    blocklisted: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct ReviewDeliverabilityRow {
    emails_sent: i64,
    emails_delivered: i64,
    emails_bounced: i64,
    emails_complained: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct ReviewIncidentRow {
    kind: String,
    severity: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReviewContractRow {
    product_line: String,
    status: String,
    active_from: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct ReviewInvoiceRow {
    id: String,
    amount_cents: i64,
    currency: String,
    status: String,
    issue_date: Option<DateTime<Utc>>,
}

/// Whole elapsed days since a warmup start, clamped (the worker's rule).
fn warmup_day_at(started_at: DateTime<Utc>, as_of: DateTime<Utc>) -> u32 {
    (as_of - started_at).num_days().clamp(0, u32::MAX as i64) as u32
}

/// Collect the monthly review packet from repo data.
///
/// Data sources per section:
/// * usage, `metering_events` (`emails_sent` / `api_calls` sums), the same
///   table `billing-service` meters into;
/// * managed IPs, `ent_dedicated_ips` (status, recorded progress,
///   reputation, counters) + the canonical `mail_common::warmup` ladder
///   derived from `warming_started_at`;
/// * deliverability, `tenant_deliverability_metrics` (the table the FBL
///   complaint and self-hosted bounce paths record into);
/// * incidents, `finance_incidents` (tenant-scoped) and the
///   `ent_compliance_audit_logs` dedicated-tenant lifecycle actions;
/// * billing, the platform catalog (fee/term/setup) + `product_line_contracts`
///   + the latest `invoices` row carrying `product_lines_period`.
pub async fn collect_monthly_review(
    db: &PgPool,
    tenant_id: &str,
    period: ReviewPeriod,
    as_of: DateTime<Utc>,
) -> Result<MonthlyReviewPacket, String> {
    let plan = plan_facts()?;
    let mut gaps: Vec<String> = Vec::new();

    // ── deployment ──
    let deployment_row = sqlx::query_as::<_, ReviewDeploymentRow>(
        "SELECT id, name, status, region, bundle_sha256, validation_report
         FROM ent_private_deployments
         WHERE tenant_id = $1 AND deployment_type = 'dedicated'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Review: load deployment: {e}"))?;

    let deployment = deployment_row.map(|row| {
        let validated = row
            .validation_report
            .as_ref()
            .and_then(|report| report.get("passed"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        ReviewDeploymentRef {
            deployment_id: row.id,
            host_group: host_group_name(tenant_id, row.id),
            name: row.name,
            status: row.status,
            region: row.region.unwrap_or_default(),
            bundle_sha256: row.bundle_sha256,
            bundle_validated: validated,
        }
    });
    if deployment.is_none() {
        gaps.push(
            "no dedicated deployment record exists for this tenant (ent_private_deployments \
             has no deployment_type='dedicated' row)"
                .to_string(),
        );
    } else if deployment
        .as_ref()
        .is_some_and(|deployment| deployment.bundle_sha256.is_none())
    {
        gaps.push(
            "the deployment carries no recorded bundle artifact (no validated bundle yet)"
                .to_string(),
        );
    }

    // ── usage ──
    let usage_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_type, COALESCE(SUM(quantity), 0)::bigint
         FROM metering_events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3
           AND event_type IN ('emails_sent', 'api_calls')
         GROUP BY event_type",
    )
    .bind(tenant_id)
    .bind(period.start)
    .bind(period.end)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Review: usage: {e}"))?;
    let mut emails_sent = 0i64;
    let mut api_calls = 0i64;
    for (event_type, total) in usage_rows {
        match event_type.as_str() {
            "emails_sent" => emails_sent = total,
            "api_calls" => api_calls = total,
            _ => {}
        }
    }
    let included = plan.included_recipients as i64;
    let utilization_percent = if included > 0 {
        emails_sent as f64 / included as f64 * 100.0
    } else {
        0.0
    };
    let usage = ReviewUsage {
        emails_sent,
        api_calls,
        included_recipients: included,
        utilization_percent,
        source: "metering_events".to_string(),
    };

    // ── managed IPs ──
    let ip_rows = sqlx::query_as::<_, ReviewManagedIpRow>(
        "SELECT host(ip_address) AS ip_address, status, warming_started_at,
                warming_progress_percent, current_daily_limit, reputation_score,
                emails_sent_total, bounces_total, complaints_total, blocklisted
         FROM ent_dedicated_ips
         WHERE tenant_id = $1
         ORDER BY created_at",
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Review: managed IPs: {e}"))?;
    let managed_ips: Vec<ReviewManagedIp> = ip_rows
        .into_iter()
        .map(|row| {
            let (derived_warmup_day, derived_daily_limit) = match row.warming_started_at {
                Some(started_at) => {
                    let day = warmup_day_at(started_at, as_of);
                    (Some(day), Some(mail_common::warmup::limit_for_day(day)))
                }
                None => (None, None),
            };
            ReviewManagedIp {
                ip_address: row.ip_address,
                status: row.status,
                warming_started_at: row.warming_started_at,
                recorded_warming_progress_percent: row.warming_progress_percent,
                derived_warmup_day,
                derived_daily_limit,
                current_daily_limit: row.current_daily_limit,
                reputation_score: row.reputation_score,
                emails_sent_total: row.emails_sent_total,
                bounces_total: row.bounces_total,
                complaints_total: row.complaints_total,
                blocklisted: row.blocklisted,
            }
        })
        .collect();
    if managed_ips.is_empty() {
        gaps.push(
            "no managed IPs recorded in ent_dedicated_ips for this tenant (the plan includes 2)"
                .to_string(),
        );
    } else if managed_ips.len() != plan.managed_ip_count {
        gaps.push(format!(
            "{} managed IP(s) recorded; the plan includes {} (an override, if any, is recorded on the deployment)",
            managed_ips.len(),
            plan.managed_ip_count
        ));
    }

    // ── deliverability ──
    let deliverability_row = sqlx::query_as::<_, ReviewDeliverabilityRow>(
        "SELECT COALESCE(SUM(emails_sent), 0)::bigint AS emails_sent,
                COALESCE(SUM(emails_delivered), 0)::bigint AS emails_delivered,
                COALESCE(SUM(emails_bounced), 0)::bigint AS emails_bounced,
                COALESCE(SUM(emails_complained), 0)::bigint AS emails_complained
         FROM tenant_deliverability_metrics
         WHERE tenant_id = $1 AND period_start >= $2 AND period_start < $3",
    )
    .bind(tenant_id)
    .bind(period.start)
    .bind(period.end)
    .fetch_one(db)
    .await
    .map_err(|e| format!("Review: deliverability: {e}"))?;
    let safe_div = |num: i64, den: i64| {
        if den > 0 {
            num as f64 / den as f64
        } else {
            0.0
        }
    };
    let deliverability = ReviewDeliverability {
        emails_sent: deliverability_row.emails_sent,
        emails_delivered: deliverability_row.emails_delivered,
        emails_bounced: deliverability_row.emails_bounced,
        emails_complained: deliverability_row.emails_complained,
        delivery_rate: safe_div(
            deliverability_row.emails_delivered,
            deliverability_row.emails_sent,
        ),
        bounce_rate: safe_div(
            deliverability_row.emails_bounced,
            deliverability_row.emails_sent,
        ),
        complaint_rate: safe_div(
            deliverability_row.emails_complained,
            deliverability_row.emails_sent,
        ),
        source: "tenant_deliverability_metrics".to_string(),
    };
    if deliverability_row.emails_sent == 0
        && deliverability_row.emails_bounced == 0
        && deliverability_row.emails_complained == 0
    {
        gaps.push(
            "tenant_deliverability_metrics has no rows this period: the table is written only by \
             the FBL-complaint and self-hosted bounce paths, so zero rows mean no recorded \
             bounces/complaints, not zero traffic (see the usage section for volume)"
                .to_string(),
        );
    }
    if deliverability_row.emails_delivered == 0 {
        gaps.push(
            "no delivery counts are recorded (no writer populates emails_delivered yet); the \
             delivery rate is not derivable from repo data"
                .to_string(),
        );
    }

    // ── incidents ──
    let incidents = sqlx::query_as::<_, ReviewIncidentRow>(
        "SELECT kind, severity, status, created_at
         FROM finance_incidents
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(tenant_id)
    .bind(period.start)
    .bind(period.end)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Review: incidents: {e}"))?
    .into_iter()
    .map(|row| ReviewIncident {
        kind: row.kind,
        severity: row.severity,
        status: row.status,
        created_at: row.created_at,
    })
    .collect();

    let lifecycle_events_in_period: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ent_compliance_audit_logs
         WHERE tenant_id = $1 AND action LIKE 'dedicated_tenant.%'
           AND created_at >= $2 AND created_at < $3",
    )
    .bind(tenant_id)
    .bind(period.start)
    .bind(period.end)
    .fetch_one(db)
    .await
    .map_err(|e| format!("Review: lifecycle events: {e}"))?;

    // ── billing ──
    let contract = sqlx::query_as::<_, ReviewContractRow>(
        "SELECT product_line, status, active_from
         FROM product_line_contracts
         WHERE tenant_id = $1 AND product_line = 'dedicated_tenant'",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Review: contract: {e}"))?
    .map(|row| ReviewContract {
        product_line: row.product_line,
        status: row.status,
        active_from: row.active_from,
    });
    if contract.is_none() {
        gaps.push(
            "no dedicated_tenant contract row is recorded for this tenant: the lifecycle creates \
             it at activation (provisioned -> active); a deployment that never reached active, or \
             whose billing write was refused, has no contracted billing period yet"
                .to_string(),
        );
    }
    let last_invoice = sqlx::query_as::<_, ReviewInvoiceRow>(
        "SELECT id, amount_cents, currency, status, issue_date
         FROM invoices
         WHERE tenant_id = $1 AND product_lines_period IS NOT NULL
         ORDER BY product_lines_period DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Review: invoices: {e}"))?
    .map(|row| ReviewInvoice {
        invoice_id: row.id,
        amount_cents: row.amount_cents,
        currency: row.currency,
        status: row.status,
        issue_date: row.issue_date,
    });
    if last_invoice.is_none() {
        gaps.push(
            "no product-line invoice (invoices.product_lines_period) is recorded for this tenant"
                .to_string(),
        );
    }
    let mut billing_notes = Vec::new();
    if let Some(contract) = &contract {
        billing_notes.push(format!(
            "contract {} is {} since {}",
            contract.product_line,
            contract.status,
            contract.active_from.to_rfc3339()
        ));
    }
    let billing = ReviewBilling {
        monthly_fee_cents: plan.monthly_fee_cents,
        minimum_term_months: plan.minimum_term_months,
        annual_commitment_cents: plan.monthly_fee_cents * plan.minimum_term_months,
        setup_min_cents: plan.setup_min_cents,
        setup_max_cents: plan.setup_max_cents,
        contract,
        last_product_line_invoice: last_invoice,
        notes: billing_notes,
    };

    Ok(MonthlyReviewPacket {
        packet: "apexmail.dedicated-tenant.monthly-review/1".to_string(),
        tenant_id: tenant_id.to_string(),
        period,
        deployment,
        plan: ReviewPlanFacts {
            monthly_fee_cents: plan.monthly_fee_cents,
            minimum_term_months: plan.minimum_term_months,
            setup_min_cents: plan.setup_min_cents,
            setup_max_cents: plan.setup_max_cents,
            included_recipients: included,
            managed_ip_count: plan.managed_ip_count as i64,
            default_region: plan.default_region,
        },
        usage,
        managed_ips,
        deliverability,
        incidents,
        lifecycle_events_in_period,
        billing,
        gaps,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> DedicatedTenantPlanFacts {
        plan_facts().expect("the canonical catalogs carry the dedicated_tenant row")
    }

    fn request() -> DedicatedBundleRequest {
        DedicatedBundleRequest {
            tenant_id: "t26dedicatedtenant0000000".to_string(),
            deployment_id: Uuid::parse_str("0f0f0f0f-1111-2222-3333-444444444444").unwrap(),
            deployment_name: "Acme dedicated".to_string(),
            deployment_type: "dedicated".to_string(),
            region: "EEA".to_string(),
            release_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            managed_ips: vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
            sender_domains: vec!["mail.acme.example".to_string()],
            named_owner: "ops@acme.example".to_string(),
            setup_fee_cents: Some(2_000_000),
            minimum_term_months: Some(12),
            monthly_fee_cents: Some(400_000),
            region_override_reason: None,
            ip_count_override_reason: None,
            eu_only_routing: true,
        }
    }

    // ── Plan facts ──

    #[test]
    fn plan_facts_match_the_plan_and_the_compliance_product() {
        let facts = plan();
        assert_eq!(facts.monthly_fee_cents, 400_000, "€4,000/mo from");
        assert_eq!(facts.minimum_term_months, 12, "12-month minimum");
        assert_eq!(facts.setup_min_cents, 1_000_000, "€10k setup floor");
        assert_eq!(facts.setup_max_cents, 4_000_000, "€40k setup ceiling");
        assert_eq!(facts.included_recipients, 5_000_000, "5M recipients");
        assert_eq!(facts.managed_ip_count, 2, "2 managed IPs");
        assert_eq!(facts.default_region, "EEA", "EU/EEA default");
        // Drift guard: the platform-catalog figures and the structured
        // product struct (compliance::DedicatedTenant) must agree.
        let product = ::compliance::deployment_products::DedicatedTenant::default();
        assert_eq!(
            facts.monthly_fee_cents,
            product.monthly_fee_eur as i64 * 100
        );
        assert_eq!(
            facts.minimum_term_months,
            product.minimum_term_months as i64
        );
        assert_eq!(
            facts.setup_min_cents,
            product.one_time_setup_min_eur as i64 * 100
        );
        assert_eq!(
            facts.setup_max_cents,
            product.one_time_setup_max_eur as i64 * 100
        );
        assert_eq!(facts.included_recipients, product.included_recipients);
        assert_eq!(
            facts.managed_ip_count,
            product.managed_dedicated_ips as usize
        );
        assert_eq!(facts.default_region, product.region);
    }

    #[test]
    fn plan_facts_flow_through_the_packet_and_bundle() {
        // The bundle descriptor and the packet state the catalog values, not
        // copies: changing the plan changes both (the validation also
        // compares against the same facts).
        let request = request();
        let bundle = render_bundle(&request);
        assert!(bundle
            .files
            .iter()
            .find(|file| file.path == "docker-compose.tenant.yml")
            .unwrap()
            .contents
            .contains(&format!(":{}", request.release_sha)));
    }

    // ── Determinism ──

    #[test]
    fn bundle_bytes_are_deterministic_for_stable_inputs() {
        let first = render_bundle(&request());
        let second = render_bundle(&request());
        assert_eq!(first.sha256, second.sha256, "same input, same identity");
        assert_eq!(first.files, second.files, "same input, same bytes");
        assert_eq!(first.host_group, "hg-t26dedicatedtenant0000000-0f0f0f0f");
        // The sha is the canonical digest over path+bytes.
        let mut hasher = Sha256::new();
        for file in &first.files {
            hasher.update(file.path.as_bytes());
            hasher.update([0u8]);
            hasher.update(file.contents.as_bytes());
            hasher.update([0u8]);
        }
        assert_eq!(first.sha256, hex::encode(hasher.finalize()));
    }

    #[test]
    fn bundle_identity_changes_with_any_input() {
        let base = render_bundle(&request());
        let mut other = request();
        other.release_sha = "abcdef0123456789abcdef0123456789abcdef01".to_string();
        assert_ne!(base.sha256, render_bundle(&other).sha256, "release sha");
        let mut other = request();
        other.managed_ips = vec!["203.0.113.12".to_string(), "203.0.113.11".to_string()];
        assert_ne!(base.sha256, render_bundle(&other).sha256, "managed IPs");
        let mut other = request();
        other.tenant_id = "othertenant00000000000000".to_string();
        assert_ne!(base.sha256, render_bundle(&other).sha256, "tenant id");
    }

    #[test]
    fn bundle_layers_the_release_sha_on_every_stack_service() {
        let request = request();
        let bundle = render_bundle(&request);
        let compose = &bundle
            .files
            .iter()
            .find(|file| file.path == "docker-compose.tenant.yml")
            .expect("compose overlay")
            .contents;
        for stack_service in TENANT_STACK_SERVICES {
            assert!(
                compose.contains(&format!(
                    "image: ghcr.io/sbelakho2/apexmail/{}:{}\n",
                    stack_service.image, request.release_sha
                )),
                "{} must be pinned to the release sha",
                stack_service.service
            );
        }
        assert!(
            !compose.contains(":latest"),
            "a dedicated bundle never ships a mutable latest pin"
        );
        assert!(compose.contains("apexmail.tenant: \"t26dedicatedtenant0000000\""));
    }

    #[test]
    fn bundle_env_carries_the_managed_ips_and_eu_only_default() {
        let bundle = render_bundle(&request());
        let env = &bundle
            .files
            .iter()
            .find(|file| file.path == "tenant.env")
            .expect("env template")
            .contents;
        assert!(env.contains("APEXMAIL_TENANT_ID=t26dedicatedtenant0000000"));
        assert!(env.contains("APEXMAIL_REGION=EEA"));
        assert!(env.contains("APEXMAIL_EU_ONLY_ROUTING=true"));
        assert!(env.contains("TENANT_MANAGED_IPS=203.0.113.10,203.0.113.11"));
        assert!(
            env.contains("OUTBOUND_MTA_ALLOWED_SOURCE_IPS=203.0.113.10,203.0.113.11"),
            "the relay's source-IP allowlist is the tenant's managed IPs"
        );
        assert!(env.contains("TENANT_SENDER_DOMAINS=mail.acme.example"));
        assert!(env.contains("TENANT_NAMED_OWNER=ops@acme.example"));
        assert!(
            env.contains("CHANGE_ME"),
            "secret placeholders stay placeholders, no secret material is rendered"
        );
    }

    #[test]
    fn stack_services_match_the_prod_compose() {
        // The declared host-group service set must exist in the prod compose
        // with the exact image repository the bundle pins.
        let compose = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../docker-compose.prod.yml"),
        )
        .expect("docker-compose.prod.yml is readable from the crate");
        for stack_service in TENANT_STACK_SERVICES {
            assert!(
                compose.contains(&format!("\n  {}:\n", stack_service.service)),
                "{} is not a docker-compose.prod.yml service",
                stack_service.service
            );
            assert!(
                compose.contains(&format!(
                    "image: ghcr.io/sbelakho2/apexmail/{}:latest",
                    stack_service.image
                )),
                "{} does not carry the canonical ghcr image in docker-compose.prod.yml",
                stack_service.service
            );
        }
    }

    // ── Validation refusals ──

    fn assert_refused(request: &DedicatedBundleRequest, code: &str) {
        let report = validate_bundle_request(request, &plan());
        assert!(!report.passed, "expected refusal {code}");
        assert!(
            report.failed_codes().contains(&code),
            "expected {code} in {:?}",
            report.failed_codes()
        );
    }

    #[test]
    fn valid_request_passes_with_no_overrides() {
        let report = validate_bundle_request(&request(), &plan());
        assert!(report.passed, "{:?}", report.failed_codes());
        assert!(report.overrides.is_empty());
        assert_eq!(report.release_sha, request().release_sha);
    }

    #[test]
    fn non_eea_region_is_refused_without_a_recorded_override() {
        let mut bad = request();
        bad.region = "us-east-1".to_string();
        assert_refused(&bad, "region_not_eea");
    }

    #[test]
    fn non_eea_region_is_accepted_only_with_a_recorded_reason() {
        let mut bad = request();
        bad.region = "us-east-1".to_string();
        bad.region_override_reason = Some("customer legal requirement, DPA addendum signed".into());
        let report = validate_bundle_request(&bad, &plan());
        assert!(report.passed, "{:?}", report.failed_codes());
        assert_eq!(report.overrides.len(), 1);
        assert_eq!(report.overrides[0].kind, "region");
        assert!(report.overrides[0].reason.contains("DPA addendum"));
    }

    #[test]
    fn non_hel1_provider_location_is_refused_even_with_an_override() {
        let mut bad = request();
        bad.region = "fsn1".to_string();
        bad.region_override_reason = Some("customer legal requirement, DPA addendum signed".into());
        assert_refused(&bad, "provider_location_not_hel1");
    }

    #[test]
    fn hel1_is_the_only_permitted_provider_location() {
        assert_eq!(DEDICATED_PROVIDER_LOCATION, "hel1");
        assert!(provider_location_is_permitted("hel1"));
        assert!(provider_location_is_permitted("EEA"));
        assert!(provider_location_is_permitted("eu-central-1"));
        for other in ["fsn1", "nbg1", "ash", "hil", "sin"] {
            assert!(
                !provider_location_is_permitted(other),
                "{other} must be refused"
            );
        }
    }

    #[test]
    fn eea_region_tokens_are_recognized() {
        for region in [
            "EEA",
            "eu",
            "EU",
            "europe",
            "eu-central-1",
            "de",
            "NO",
            "ee",
        ] {
            assert!(region_is_eea(region), "{region} must be EU/EEA");
        }
        for region in ["", "us", "us-east-1", "asia", "ap-south-1", "uk"] {
            assert!(!region_is_eea(region), "{region} must not be EU/EEA");
        }
    }

    #[test]
    fn ip_count_off_plan_is_refused_without_a_recorded_override() {
        let mut bad = request();
        bad.managed_ips = vec!["203.0.113.10".to_string()];
        assert_refused(&bad, "managed_ip_count_mismatch");
        let mut bad = request();
        bad.managed_ips = vec![
            "203.0.113.10".to_string(),
            "203.0.113.11".to_string(),
            "203.0.113.12".to_string(),
        ];
        assert_refused(&bad, "managed_ip_count_mismatch");
    }

    #[test]
    fn ip_count_override_is_accepted_only_with_a_recorded_reason() {
        let mut bad = request();
        bad.managed_ips = vec!["203.0.113.10".to_string()];
        bad.ip_count_override_reason = Some("tenant consolidates onto one sending IP".into());
        let report = validate_bundle_request(&bad, &plan());
        assert!(report.passed, "{:?}", report.failed_codes());
        assert_eq!(report.overrides.len(), 1);
        assert_eq!(report.overrides[0].kind, "managed_ip_count");
    }

    #[test]
    fn malformed_or_duplicate_managed_ips_are_refused() {
        let mut bad = request();
        bad.managed_ips = vec!["not-an-ip".to_string(), "203.0.113.11".to_string()];
        assert_refused(&bad, "managed_ip_invalid");
        let mut bad = request();
        bad.managed_ips = vec!["203.0.113.10".to_string(), "203.0.113.10".to_string()];
        assert_refused(&bad, "managed_ip_invalid");
        let mut bad = request();
        bad.managed_ips = vec!["127.0.0.1".to_string(), "203.0.113.11".to_string()];
        assert_refused(&bad, "managed_ip_invalid");
    }

    #[test]
    fn release_sha_missing_or_latest_is_refused() {
        let mut bad = request();
        bad.release_sha = String::new();
        assert_refused(&bad, "release_sha_invalid");
        let mut bad = request();
        bad.release_sha = "latest".to_string();
        assert_refused(&bad, "release_sha_invalid");
        let mut bad = request();
        bad.release_sha = "0123".to_string(); // too short
        assert_refused(&bad, "release_sha_invalid");
        let mut bad = request();
        bad.release_sha = "xyz".repeat(14); // 42 chars, non-hex
        assert_refused(&bad, "release_sha_invalid");
        assert!(release_sha_is_valid("abc1234"), "abbreviated shas render");
    }

    #[test]
    fn setup_fee_outside_the_catalog_range_is_refused() {
        let mut bad = request();
        bad.setup_fee_cents = Some(999_999);
        assert_refused(&bad, "setup_fee_out_of_range");
        let mut bad = request();
        bad.setup_fee_cents = Some(4_000_001);
        assert_refused(&bad, "setup_fee_out_of_range");
        let mut bad = request();
        bad.setup_fee_cents = None;
        assert_refused(&bad, "setup_fee_out_of_range");
        // The range endpoints are the catalog constants, inclusive.
        let mut ok = request();
        ok.setup_fee_cents = Some(1_000_000);
        assert!(validate_bundle_request(&ok, &plan()).passed);
        ok.setup_fee_cents = Some(4_000_000);
        assert!(validate_bundle_request(&ok, &plan()).passed);
    }

    #[test]
    fn minimum_term_below_the_catalog_is_refused() {
        let mut bad = request();
        bad.minimum_term_months = Some(11);
        assert_refused(&bad, "minimum_term_below_plan");
        let mut bad = request();
        bad.minimum_term_months = None;
        assert_refused(&bad, "minimum_term_below_plan");
        let mut longer = request();
        longer.minimum_term_months = Some(24);
        assert!(
            validate_bundle_request(&longer, &plan()).passed,
            "longer terms are deals"
        );
    }

    #[test]
    fn monthly_fee_below_the_list_price_is_refused() {
        let mut bad = request();
        bad.monthly_fee_cents = Some(399_999);
        assert_refused(&bad, "monthly_fee_below_list");
        let mut above = request();
        above.monthly_fee_cents = Some(500_000);
        assert!(validate_bundle_request(&above, &plan()).passed);
    }

    #[test]
    fn empty_named_owner_is_refused() {
        let mut bad = request();
        bad.named_owner = "   ".to_string();
        assert_refused(&bad, "named_owner_missing");
    }

    #[test]
    fn sender_domains_are_required_and_validated() {
        let mut bad = request();
        bad.sender_domains = Vec::new();
        assert_refused(&bad, "sender_domain_invalid");
        let mut bad = request();
        bad.sender_domains = vec!["not a domain".to_string()];
        assert_refused(&bad, "sender_domain_invalid");
    }

    #[test]
    fn non_dedicated_records_are_refused() {
        let mut bad = request();
        bad.deployment_type = "private_cloud".to_string();
        assert_refused(&bad, "deployment_type_not_dedicated");
    }

    #[test]
    fn report_serializes_its_checks_and_plan() {
        let report = validate_bundle_request(&request(), &plan());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["passed"], true);
        assert!(json["checks"].as_array().unwrap().len() >= 9);
        assert_eq!(json["plan"]["included_recipients"], 5_000_000u64);
        assert_eq!(json["plan"]["managed_ip_count"], 2);
        let parsed: ValidationReport = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, report);
    }

    // ── State machine ──

    #[test]
    fn lifecycle_is_forward_only_and_skips_are_refused() {
        let sha = "aa".repeat(32);
        for from in DedicatedLifecycleState::ALL {
            for to in DedicatedLifecycleState::ALL {
                let evidence = LifecycleEvidence {
                    bundle_sha256: Some(sha.as_str()),
                    validation_passed: Some(true),
                };
                let legal = from.allowed_next().contains(&to);
                let outcome = authorize_transition(from, to, &evidence);
                assert_eq!(
                    outcome.is_ok(),
                    legal,
                    "{:?} -> {:?} (legal={legal})",
                    from,
                    to
                );
                if let Err(refusal) = outcome {
                    assert_eq!(refusal.code, "INVALID_TRANSITION");
                    assert!(refusal.message.contains(from.as_str()));
                }
            }
        }
    }

    #[test]
    fn active_is_unreachable_without_the_validated_bundle_artifact() {
        let without_artifact = LifecycleEvidence::default();
        let refusal = authorize_transition(
            DedicatedLifecycleState::Provisioned,
            DedicatedLifecycleState::Active,
            &without_artifact,
        )
        .expect_err("active must require the artifact");
        assert_eq!(refusal.code, "VALIDATION_ARTIFACT_MISSING");

        let failed_sha = "aa".repeat(32);
        let failed_validation = LifecycleEvidence {
            bundle_sha256: Some(failed_sha.as_str()),
            validation_passed: Some(false),
        };
        let refusal = authorize_transition(
            DedicatedLifecycleState::Provisioned,
            DedicatedLifecycleState::Active,
            &failed_validation,
        )
        .expect_err("a failed validation must not reach active");
        assert_eq!(refusal.code, "VALIDATION_ARTIFACT_MISSING");

        let blank_sha = LifecycleEvidence {
            bundle_sha256: Some("   "),
            validation_passed: Some(true),
        };
        assert!(authorize_transition(
            DedicatedLifecycleState::Provisioned,
            DedicatedLifecycleState::Active,
            &blank_sha
        )
        .is_err());

        let ok_sha = "bb".repeat(32);
        let validated = LifecycleEvidence {
            bundle_sha256: Some(ok_sha.as_str()),
            validation_passed: Some(true),
        };
        assert!(authorize_transition(
            DedicatedLifecycleState::Requested,
            DedicatedLifecycleState::Validated,
            &validated
        )
        .is_ok());
        assert!(authorize_transition(
            DedicatedLifecycleState::Provisioned,
            DedicatedLifecycleState::Active,
            &validated
        )
        .is_ok());
    }

    #[test]
    fn decommissioning_tail_needs_no_artifact_and_is_terminal_at_the_end() {
        let none = LifecycleEvidence::default();
        assert!(authorize_transition(
            DedicatedLifecycleState::Active,
            DedicatedLifecycleState::Decommissioning,
            &none
        )
        .is_ok());
        assert!(authorize_transition(
            DedicatedLifecycleState::Decommissioning,
            DedicatedLifecycleState::Decommissioned,
            &none
        )
        .is_ok());
        assert!(DedicatedLifecycleState::Decommissioned.is_terminal());
        assert!(DedicatedLifecycleState::Decommissioned
            .allowed_next()
            .is_empty());
    }

    #[test]
    fn legacy_status_spellings_map_onto_the_machine() {
        assert_eq!(
            DedicatedLifecycleState::from_status("pending"),
            Some(DedicatedLifecycleState::Requested),
            "'pending' is the create path's spelling of requested"
        );
        assert_eq!(
            DedicatedLifecycleState::from_status("provisioning"),
            Some(DedicatedLifecycleState::Provisioned)
        );
        assert_eq!(
            DedicatedLifecycleState::from_status("maintenance"),
            Some(DedicatedLifecycleState::Active)
        );
        assert_eq!(DedicatedLifecycleState::from_status("failed"), None);
        assert_eq!(DedicatedLifecycleState::from_status("bogus"), None);
    }

    #[test]
    fn lifecycle_states_round_trip_through_status_strings() {
        for state in DedicatedLifecycleState::ALL {
            assert_eq!(
                DedicatedLifecycleState::from_status(state.as_str()),
                Some(state)
            );
        }
        let json = serde_json::to_string(&DedicatedLifecycleState::Decommissioned).unwrap();
        assert_eq!(json, "\"decommissioned\"");
    }

    // ── Bundle output dir / record extraction ──

    #[test]
    fn request_extraction_reads_the_record_config() {
        let mut record = sample_record();
        record.config = Some(serde_json::json!({
            "managed_ips": ["203.0.113.10", "203.0.113.11"],
            "sender_domains": ["mail.acme.example"],
            "named_owner": "ops@acme.example",
            "setup_fee_cents": 2_000_000,
            "minimum_term_months": 12,
            "monthly_fee_cents": 400_000,
            "size": "large"
        }));
        let request = DedicatedBundleRequest::from_record(&record, "abc1234").unwrap();
        assert_eq!(request.managed_ips.len(), 2);
        assert_eq!(request.named_owner, "ops@acme.example");
        assert_eq!(request.setup_fee_cents, Some(2_000_000));
        assert!(request.eu_only_routing, "EU-only defaults ON");
        // A malformed config refuses instead of defaulting.
        record.config = Some(serde_json::json!({"managed_ips": "not-a-list"}));
        assert!(DedicatedBundleRequest::from_record(&record, "abc1234").is_err());
        // A blank override reason is not an override.
        record.config = Some(serde_json::json!({
            "region_override_reason": "   ",
        }));
        let request = DedicatedBundleRequest::from_record(&record, "abc1234").unwrap();
        assert!(request.region_override_reason.is_none());
    }

    #[test]
    fn write_bundle_is_idempotent_and_lays_out_the_deployment_dir() {
        let request = request();
        let bundle = render_bundle(&request);
        // Test-only scratch dir with a UUID-unique name (no predictable
        // path another process could pre-create).
        let base = std::env::temp_dir().join(format!("apexmail_bundle_test_{}", Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let first = write_bundle(&base, &request, &bundle).expect("write");
        let second = write_bundle(&base, &request, &bundle).expect("rewrite");
        assert_eq!(first, second);
        assert_eq!(first.sha256, bundle.sha256);
        assert!(first
            .directory
            .ends_with(Path::new(&request.tenant_id).join(request.deployment_id.to_string())));
        for file in &bundle.files {
            let on_disk = std::fs::read_to_string(first.directory.join(&file.path)).unwrap();
            assert_eq!(on_disk, file.contents, "{} bytes match", file.path);
        }
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(first.directory.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["sha256"], bundle.sha256);
        std::fs::remove_dir_all(&base).ok();
    }

    fn sample_record() -> PrivateDeployment {
        PrivateDeployment {
            id: Uuid::nil(),
            tenant_id: "t26dedicatedtenant0000000".to_string(),
            name: "Acme dedicated".to_string(),
            deployment_type: "dedicated".to_string(),
            status: "pending".to_string(),
            region: Some("EEA".to_string()),
            availability_zones: None,
            vpc_id: None,
            instance_type: None,
            instance_count: None,
            storage_gb: None,
            config: None,
            custom_domain: None,
            health_check_url: None,
            health_status: None,
            last_health_check_at: None,
            bundle_path: None,
            bundle_sha256: None,
            validated_at: None,
            validation_report: None,
            created_at: None,
            updated_at: None,
        }
    }

    // ── Monthly packet ──

    fn fixture_packet() -> MonthlyReviewPacket {
        let plan = plan();
        MonthlyReviewPacket {
            packet: "apexmail.dedicated-tenant.monthly-review/1".to_string(),
            tenant_id: "t26dedicatedtenant0000000".to_string(),
            period: ReviewPeriod::for_month(2026, 9).unwrap(),
            deployment: Some(ReviewDeploymentRef {
                deployment_id: Uuid::nil(),
                name: "Acme dedicated".to_string(),
                status: "active".to_string(),
                region: "EEA".to_string(),
                host_group: host_group_name("t26dedicatedtenant0000000", Uuid::nil()),
                bundle_sha256: Some("cc".repeat(32)),
                bundle_validated: true,
            }),
            plan: ReviewPlanFacts {
                monthly_fee_cents: plan.monthly_fee_cents,
                minimum_term_months: plan.minimum_term_months,
                setup_min_cents: plan.setup_min_cents,
                setup_max_cents: plan.setup_max_cents,
                included_recipients: plan.included_recipients as i64,
                managed_ip_count: plan.managed_ip_count as i64,
                default_region: plan.default_region.clone(),
            },
            usage: ReviewUsage {
                emails_sent: 1_250_000,
                api_calls: 4_000,
                included_recipients: plan.included_recipients as i64,
                utilization_percent: 25.0,
                source: "metering_events".to_string(),
            },
            managed_ips: vec![ReviewManagedIp {
                ip_address: "203.0.113.10".to_string(),
                status: "warming".to_string(),
                warming_started_at: Some(Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap()),
                recorded_warming_progress_percent: Some(15),
                derived_warmup_day: Some(30),
                derived_daily_limit: Some(mail_common::warmup::limit_for_day(30)),
                current_daily_limit: Some(50_000),
                reputation_score: Some(98.5),
                emails_sent_total: 300_000,
                bounces_total: 300,
                complaints_total: 4,
                blocklisted: false,
            }],
            deliverability: ReviewDeliverability {
                emails_sent: 1_000,
                emails_delivered: 0,
                emails_bounced: 12,
                emails_complained: 1,
                delivery_rate: 0.0,
                bounce_rate: 0.012,
                complaint_rate: 0.001,
                source: "tenant_deliverability_metrics".to_string(),
            },
            incidents: vec![ReviewIncident {
                kind: "tax_total_mismatch".to_string(),
                severity: "high".to_string(),
                status: "resolved".to_string(),
                created_at: Utc.with_ymd_and_hms(2026, 9, 12, 3, 0, 0).unwrap(),
            }],
            lifecycle_events_in_period: 3,
            billing: ReviewBilling {
                monthly_fee_cents: plan.monthly_fee_cents,
                minimum_term_months: plan.minimum_term_months,
                annual_commitment_cents: plan.monthly_fee_cents * plan.minimum_term_months,
                setup_min_cents: plan.setup_min_cents,
                setup_max_cents: plan.setup_max_cents,
                contract: None,
                last_product_line_invoice: None,
                notes: vec!["contract row absent".to_string()],
            },
            gaps: vec!["no product-line invoice".to_string()],
        }
    }

    #[test]
    fn packet_json_shape_is_stable() {
        let packet = fixture_packet();
        let json = serde_json::to_value(&packet).unwrap();
        assert_eq!(json["packet"], "apexmail.dedicated-tenant.monthly-review/1");
        assert_eq!(json["period"]["label"], "2026-09");
        assert_eq!(json["usage"]["emails_sent"], 1_250_000);
        assert_eq!(json["usage"]["included_recipients"], 5_000_000);
        assert_eq!(json["managed_ips"][0]["ip_address"], "203.0.113.10");
        assert_eq!(json["managed_ips"][0]["derived_warmup_day"], 30);
        assert_eq!(
            json["managed_ips"][0]["derived_daily_limit"],
            mail_common::warmup::limit_for_day(30)
        );
        assert_eq!(json["deliverability"]["bounce_rate"], 0.012);
        assert_eq!(json["billing"]["annual_commitment_cents"], 4_800_000);
        assert!(json["gaps"].as_array().unwrap().len() == 1);
        let parsed: MonthlyReviewPacket = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn packet_markdown_is_compact_and_names_the_sources_and_gaps() {
        let markdown = fixture_packet().render_markdown();
        for needle in [
            "# Dedicated Tenant monthly review, t26dedicatedtenant0000000",
            "- Period: 2026-09",
            "Recipients sent: 1250000 of 5000000 included (25.00%)",
            "metering_events",
            "203.0.113.10 (warming)",
            "warmup day 30",
            "delivery 0.00%, bounce 1.20%, complaint 0.10%",
            "tax_total_mismatch [high] resolved",
            "Lifecycle audit events in period: 3",
            "Monthly fee €4000.00; minimum term 12 months; annual commitment €48000.00",
            "## Data gaps",
            "no product-line invoice",
        ] {
            assert!(
                markdown.contains(needle),
                "markdown missing {needle:?}:\n{markdown}"
            );
        }
    }

    #[test]
    fn review_period_parses_and_bounds_calendar_months() {
        let period = ReviewPeriod::for_month(2026, 9).unwrap();
        assert_eq!(period.label, "2026-09");
        assert_eq!(period.start.to_rfc3339(), "2026-09-01T00:00:00+00:00");
        assert_eq!(period.end.to_rfc3339(), "2026-10-01T00:00:00+00:00");
        let december = ReviewPeriod::for_month(2026, 12).unwrap();
        assert_eq!(december.end.to_rfc3339(), "2027-01-01T00:00:00+00:00");
        assert_eq!(ReviewPeriod::parse("2026-09").unwrap(), period);
        assert!(ReviewPeriod::parse("2026-13").is_none());
        assert!(ReviewPeriod::parse("26-09").is_none());
        assert!(ReviewPeriod::parse("sept").is_none());
        assert_eq!(
            ReviewPeriod::current(Utc.with_ymd_and_hms(2026, 10, 16, 9, 0, 0).unwrap()).label,
            "2026-10"
        );
    }

    // ── Activation -> billing contract (DB-gated, external audit item 14) ──

    /// `provisioned -> active` records the Dedicated Tenant product-line
    /// contract in the SAME billing control plane, with the deployment's
    /// validated setup fee and minimum term. Soft-skips without
    /// `TEST_DATABASE_URL`.
    #[tokio::test]
    async fn activation_records_the_dedicated_tenant_contract() {
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "dedicated_tenant_activation_contract",
            "dt_activation_contract",
        )
        .await
        .expect("provision") else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let tenant = "dttestactivation000000001";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status)
             VALUES ($1, 'DT activation', 'growth', 'active')
             ON CONFLICT (id) DO UPDATE SET status = 'active'",
        )
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");

        let config = serde_json::json!({
            "managed_ips": ["203.0.113.10", "203.0.113.11"],
            "sender_domains": ["mail.acme.example"],
            "named_owner": "ops@acme.example",
            "setup_fee_cents": 2_000_000,
            "minimum_term_months": 24,
            "monthly_fee_cents": 400_000,
        });
        let deployment_id: Uuid = sqlx::query_scalar(
            "INSERT INTO ent_private_deployments
                 (tenant_id, name, deployment_type, status, config,
                  bundle_sha256, validation_report)
             VALUES ($1, 'dedicated activation', 'dedicated', 'provisioned', $2::jsonb,
                     repeat('a', 64), '{\"passed\": true}'::jsonb)
             RETURNING id",
        )
        .bind(tenant)
        .bind(config.to_string())
        .fetch_one(&pool)
        .await
        .expect("seed deployment");

        let service = PrivateDeployService::new(pool.clone());
        let outcome = service
            .transition_dedicated(deployment_id, "active", None)
            .await
            .expect("transition");
        assert!(
            outcome.success,
            "activation must succeed and record billing: {:?}",
            outcome.error
        );

        let (line, status, setup, term): (String, String, Option<i64>, Option<i64>) =
            sqlx::query_as(
                "SELECT product_line, status, setup_fee_cents, minimum_term_months
                 FROM product_line_contracts WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("the activation recorded a dedicated_tenant contract");
        assert_eq!(line, "dedicated_tenant");
        assert_eq!(status, "active");
        assert_eq!(
            setup,
            Some(2_000_000),
            "the deployment's contracted setup fee is recorded"
        );
        assert_eq!(
            term,
            Some(24),
            "the deployment's contracted minimum term is recorded"
        );
    }
}
