//! The domains DNS-record report: what a switching customer must KEEP, what
//! they can DELETE from the old provider, and what must be EDITED.
//!
//! This kind is **read-only output**: it writes nothing, calls no provider API
//! and performs no DNS lookups. Everything it answers with is generated from
//! the SAME sources the product itself uses:
//!
//! * the KEEP set is [`crate::routes::domains::required_sender_dns_records`] —
//!   the exact records `GET /v1/domains/:id/dns-records` serves (single source
//!   of truth, so this report can never drift from the product's guidance);
//! * the DELETE candidates are the records the OLD provider's documented
//!   sender-authentication setup publishes (pattern-level, "if present" — we
//!   hold no zone file, so each row says exactly which provider pattern it
//!   describes and why it is obsolete after the cutover);
//! * the EDITS are the records that must not simply be deleted (an SPF TXT
//!   that must lose the old `include:`, a DMARC policy to reconcile).
//!
//! The report never claims a record EXISTS — it cannot know without a DNS
//! lookup, which this surface deliberately does not perform. Every delete row
//! is a candidate to check, which is why the fields are `hostname` patterns
//! and the notes say "if present".

use super::{
    sha256_hex, DomainReport, ImportFormat, ImportKind, ImportMode, ImportProvider, ImportReport,
    RecordInstruction,
};
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::domains::{effective_dkim_selector, required_sender_dns_records};
use crate::state::AppState;

/// The provider-specific records an old setup published. `em<id>` / `url<id>`
/// / `s1` / `s2` are SendGrid's documented domain-authentication CNAMEs; the
/// `<id>` placeholders are named as such because the actual values differ per
/// account.
fn delete_candidates(provider: ImportProvider, domain: &str) -> Vec<RecordInstruction> {
    let row = |record_type: &str, hostname: String, value: &str, note: &str| RecordInstruction {
        action: "delete".into(),
        record_type: record_type.into(),
        hostname,
        value: value.into(),
        priority: None,
        note: note.into(),
    };
    match provider {
        ImportProvider::SendGrid => vec![
            row(
                "CNAME",
                format!("em<account-id>.{domain}"),
                "sendgrid.net",
                "SendGrid link branding / return-path host: delete after the cutover (if present)",
            ),
            row(
                "CNAME",
                format!("url<account-id>.{domain}"),
                "sendgrid.net",
                "SendGrid click-tracking host: delete after the cutover (if present)",
            ),
            row(
                "CNAME",
                format!("s1._domainkey.{domain}"),
                "s1.domainkey.u<account-id>.wl.sendgrid.net",
                "SendGrid DKIM key 1: delete after the cutover (if present)",
            ),
            row(
                "CNAME",
                format!("s2._domainkey.{domain}"),
                "s2.domainkey.u<account-id>.wl.sendgrid.net",
                "SendGrid DKIM key 2: delete after the cutover (if present)",
            ),
        ],
        ImportProvider::Mailgun => vec![
            row(
                "MX",
                domain.to_string(),
                "mxa.mailgun.org",
                "Mailgun inbound/receiving MX: delete only if you did not use Mailgun for inbound \
                 mail (if present)",
            ),
            row(
                "MX",
                domain.to_string(),
                "mxb.mailgun.org",
                "Mailgun inbound/receiving MX (secondary): delete with its primary (if present)",
            ),
            row(
                "CNAME",
                format!("email.{domain}"),
                "mailgun.org",
                "Mailgun tracking host: delete after the cutover (if present)",
            ),
            row(
                "TXT",
                format!("mailo._domainkey.{domain}"),
                "k=rsa; p=<mailgun-public-key>",
                "Mailgun legacy DKIM key: delete after the cutover (if present)",
            ),
            row(
                "CNAME",
                format!("k1._domainkey.{domain}"),
                "dkim.mailgun.org",
                "Mailgun DKIM host (current layout): delete after the cutover (if present)",
            ),
        ],
        ImportProvider::Postmark => vec![
            row(
                "CNAME",
                format!("pm-bounces.{domain}"),
                "pm.mtasv.net",
                "Postmark return-path / bounce host: delete after the cutover (if present)",
            ),
            row(
                "CNAME",
                format!("pm._domainkey.{domain}"),
                "pm.mtasv.net",
                "Postmark DKIM host: delete after the cutover (if present)",
            ),
        ],
        ImportProvider::Resend => vec![
            // Resend runs on SES; its records live on the `send.` subdomain.
            row(
                "MX",
                format!("send.{domain}"),
                "feedback-smtp.<region>.amazonses.com",
                "Resend's SES return-path MX on the send subdomain: delete after the cutover (if \
                 present)",
            ),
            row(
                "TXT",
                format!("send.{domain}"),
                "v=spf1 include:amazonses.com ~all",
                "Resend's SPF on the send subdomain: delete after the cutover if nothing else uses \
                 that subdomain (if present)",
            ),
            row(
                "TXT",
                format!("resend._domainkey.{domain}"),
                "p=<resend-public-key>",
                "Resend DKIM key: delete after the cutover (if present)",
            ),
        ],
    }
}

/// The records that must not simply be deleted: the shared root-domain SPF
/// (one TXT per domain — a second SPF record breaks SPF entirely) and the
/// DMARC policy (ours if the customer has none).
fn edit_instructions(provider: ImportProvider, domain: &str) -> Vec<RecordInstruction> {
    let include = match provider {
        ImportProvider::SendGrid => "include:sendgrid.net",
        ImportProvider::Mailgun => "include:mailgun.org",
        ImportProvider::Postmark => "include:spf.mtasv.net",
        ImportProvider::Resend => "include:amazonses.com",
    };
    vec![
        RecordInstruction {
            action: "edit".into(),
            record_type: "TXT".into(),
            hostname: domain.to_string(),
            value: format!("remove {include} from the v=spf1 record"),
            priority: None,
            note: format!(
                "the root SPF record is shared: edit the EXISTING TXT record to drop {include} \
                 instead of creating a second SPF record, then confirm the remaining mechanisms \
                 still cover every sender you use"
            ),
        },
        RecordInstruction {
            action: "edit".into(),
            record_type: "TXT".into(),
            hostname: format!("_dmarc.{domain}"),
            value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@<your-report-address>".into(),
            priority: None,
            note: "keep exactly one DMARC record; if a policy already exists, keep it and only \
                   reconcile the report address if you want our guidance's mailbox"
                .into(),
        },
    ]
}

pub(crate) async fn import_domain_report(
    state: &AppState,
    auth: &AuthUser,
    provider: ImportProvider,
    mode: ImportMode,
    domain: &str,
) -> Result<ImportReport, ApiError> {
    let mut report =
        ImportReport::base(provider, ImportKind::Domains, mode, ImportFormat::Json, &[]);
    // The file hash of a read-only report is the domain it describes, so the
    // report is still identifiable across replays.
    report.file_sha256 = sha256_hex(domain.as_bytes());

    let query = domain.trim().trim_end_matches('.');
    if query.is_empty() {
        return Err(ApiError::BadRequest(
            "?domain= must name a domain (or its id)".into(),
        ));
    }

    // Accept a domain id or a name; the row must belong to the caller's tenant.
    //
    // domains.id is UUID (canonical schema): parse the query as a UUID and
    // compare `id = $3::uuid` natively, so the primary key is usable. A query
    // that is not UUID-shaped (a domain name, or garbage) binds NULL there and
    // resolves through `name = $2` — the same rows the old
    // `id::text = $2 OR name = $2` predicate matched, with the id arm now
    // indexable and normalized (uuid spellings are compared as UUIDs).
    let domain_id = uuid::Uuid::parse_str(query).ok();
    let row: Option<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id::text, name, dkim_selector, dkim_public_key, dkim_private_key
             FROM domains
             WHERE tenant_id = $1 AND (id = $3::uuid OR name = $2)
             LIMIT 1",
    )
    .bind(&auth.tenant_id)
    .bind(query)
    .bind(domain_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((_id, name, selector, public_key, private_key)) = row else {
        return Err(ApiError::NotFound(format!(
            "domain '{query}' not found in this tenant; add it first (POST /v1/domains)"
        )));
    };

    let selector = effective_dkim_selector(selector.as_deref()).to_string();
    let public_key = public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .filter(|_| {
            private_key
                .as_deref()
                .is_some_and(|key| !key.trim().is_empty())
        })
        .unwrap_or("<not provisioned yet — POST /v1/domains/:id/verify>");

    let keep: Vec<RecordInstruction> = required_sender_dns_records(
        &name,
        &selector,
        public_key,
        &state.config.aws_region,
        crate::config::Config::ses_transport_enabled(),
    )
    .into_iter()
    .map(|record| {
        let first_label = record.hostname.split('.').next().unwrap_or("").to_string();
        let note = if first_label == selector {
            "ApexMail DKIM: must stay published for signed sending".to_string()
        } else if first_label == "_dmarc" {
            "DMARC policy: keep one record per domain".to_string()
        } else if first_label == "bounce" && record.record_type == "MX" {
            "ApexMail return-path MX (bounce handling): keep".to_string()
        } else if first_label == "bounce" {
            "ApexMail return-path SPF: keep".to_string()
        } else {
            "ApexMail-required record: keep".to_string()
        };
        RecordInstruction {
            action: "keep".into(),
            record_type: record.record_type,
            hostname: record.hostname,
            value: record.value,
            priority: record.priority,
            note,
        }
    })
    .collect();

    let delete_candidates = delete_candidates(provider, &name);
    let edits = edit_instructions(provider, &name);

    let mut conflicts = Vec::new();
    // The old provider's DKIM hostnames are on `_domainkey` too; a customer
    // who keeps them alongside ours has two keys published, which is fine —
    // but a selector collision is not.
    for candidate in &delete_candidates {
        let candidate_selector = candidate
            .hostname
            .split("._domainkey.")
            .next()
            .filter(|_prefix| candidate.hostname.contains("._domainkey."));
        if let Some(candidate_selector) = candidate_selector {
            if candidate_selector == selector {
                conflicts.push(format!(
                    "your ApexMail DKIM selector is `{selector}` and the old {provider} setup \
                     published a DKIM record on the SAME hostname `{}` — the new key must replace \
                     the old value, not sit beside it",
                    candidate.hostname,
                    provider = provider.name()
                ));
            }
        }
    }
    if conflicts.is_empty() {
        conflicts.push(
            "no hostname collision between your ApexMail DKIM selector and the old provider's \
             patterns; the delete rows above are safe to remove once signing is verified here"
                .to_string(),
        );
    }

    report.counts.rows = keep.len() + delete_candidates.len() + edits.len();
    report.counts.imported = 0;
    report.warnings.push(
        "the domains report is read-only: no domain or provider state was touched and no \
         provider API or DNS lookup ran (only this receipt is stored, and only on commit) — the \
         delete rows are the old provider's documented patterns, to check against your actual \
         zone"
            .to_string(),
    );
    report.domain = Some(DomainReport {
        domain: name,
        from_provider: provider.name().to_string(),
        keep,
        delete_candidates,
        edits,
        conflicts,
    });
    Ok(report)
}
