//! Shared internal email-header contract (audit F74) and message-category
//! model (audit F55).
//!
//! The worker emits `X-ApexMail-Message-ID` / `X-ApexMail-Tenant-ID` on every
//! outgoing message; earlier revisions of the SES callback handler looked up
//! `X-ApexMail-MessageId` / `X-ApexMail-TenantId` with a case-sensitive
//! `==`, losing attribution, while the reserved-header lists blocked only the
//! hyphenated spellings — letting caller-supplied aliases through to be
//! trusted as tenant authority. This module is the ONE shared source of truth
//! for those names, the namespace reservation rule, and the compatibility
//! alias parser used when reading provider-echoed headers.

// ─────────────────────────────────────────────────────────────────────────────
// F74: internal identity headers
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical worker-emitted platform message-id header. Generated
/// exclusively from authenticated persisted job context by the worker's
/// `prepare_email`; callers can never set it (the whole `X-ApexMail-*`
/// namespace is reserved at every submission boundary).
pub const HEADER_MESSAGE_ID: &str = "X-ApexMail-Message-ID";

/// Canonical worker-emitted platform tenant-id header.
pub const HEADER_TENANT_ID: &str = "X-ApexMail-Tenant-ID";

/// Canonical worker-emitted platform campaign-id header.
pub const HEADER_CAMPAIGN_ID: &str = "X-ApexMail-Campaign-ID";

/// Historical spellings that appear in provider-echoed header lists. They are
/// PARSE-ONLY compatibility aliases: reservation still blocks them at every
/// submission boundary, and callbacks must never authorize anything from
/// them alone (provider signature ≠ header trustworthiness — the caller
/// controls the submitted custom headers).
pub const HEADER_ALIASES_MESSAGE_ID: &[&str] = &["X-ApexMail-MessageId"];
pub const HEADER_ALIASES_TENANT_ID: &[&str] = &["X-ApexMail-TenantId"];
pub const HEADER_ALIASES_CAMPAIGN_ID: &[&str] = &["X-ApexMail-CampaignId"];

/// The reserved internal header namespace prefix (lowercased comparison).
const RESERVED_NAMESPACE_PREFIX: &str = "x-apexmail-";

/// True when `name` falls inside the reserved `X-ApexMail-*` namespace,
/// compared case-insensitively. Every external submission boundary (send API
/// custom headers, worker custom-header merge) AND the pre-transport filter
/// must reject these — the platform generates the namespace exclusively from
/// authenticated persisted job context.
pub fn is_reserved_internal_header(name: &str) -> bool {
    name.to_ascii_lowercase()
        .starts_with(RESERVED_NAMESPACE_PREFIX)
}

/// Outcome of looking one logical identity header up in a provider-echoed
/// header list.
#[derive(Debug)]
pub enum IdentityHeaderLookup<'a> {
    /// No header with that logical name is present.
    Missing,
    /// Exactly one (case-insensitive) spelling matched.
    Found(&'a str),
    /// Two or more headers map to the same logical identity header with
    /// different values — ambiguous, must be rejected rather than guessed.
    Ambiguous,
}

/// Find the value of one logical identity header in a provider-echoed header
/// list, matching the canonical spelling AND the compatibility aliases
/// case-insensitively, and rejecting ambiguous duplicates. Used for
/// diagnostics/correlation only: tenant/message authority comes from the
/// stored provider-message mapping, never from these headers alone.
pub fn find_identity_header<'a, I>(
    headers: I,
    canonical: &str,
    aliases: &[&str],
) -> IdentityHeaderLookup<'a>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let canonical_lower = canonical.to_ascii_lowercase();
    let alias_lowers: Vec<String> = aliases
        .iter()
        .map(|alias| alias.to_ascii_lowercase())
        .collect();
    let mut found: Option<&'a str> = None;
    for (name, value) in headers {
        let name_lower = name.to_ascii_lowercase();
        if name_lower != canonical_lower && !alias_lowers.contains(&name_lower) {
            continue;
        }
        match found {
            None => found = Some(value),
            Some(previous) if previous == value => { /* same value repeated */ }
            Some(_) => return IdentityHeaderLookup::Ambiguous,
        }
    }
    match found {
        Some(value) => IdentityHeaderLookup::Found(value),
        None => IdentityHeaderLookup::Missing,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// F55: server-owned message category
// ─────────────────────────────────────────────────────────────────────────────

/// Bounded model for the message category carried through enqueue and
/// dispatch (`messages.message_category` / `email_queue.message_category`).
pub mod message_category {
    /// Default category for sends that do not request one explicitly.
    pub const MARKETING: &str = "marketing";

    /// Operational category: invoices, password resets, security notices.
    /// EXEMPT from per-category preference opt-outs (but never from global
    /// suppression) — recipients must receive transactional mail they
    /// triggered even after a marketing opt-out.
    pub const TRANSACTIONAL: &str = "transactional";

    /// Platform/service notices category. Same exemption rule as
    /// [`TRANSACTIONAL`].
    pub const SERVICE: &str = "service";

    /// Categories exempt from subscription_preferences enforcement.
    pub const PREFERENCE_EXEMPT: &[&str] = &[TRANSACTIONAL, SERVICE];

    /// Longest accepted category (matches subscription_preferences.category
    /// VARCHAR(100)).
    const MAX_LEN: usize = 100;

    /// Validate and normalize a caller-supplied category into the
    /// server-owned form: trimmed, ASCII-lowercased, non-empty, at most 100
    /// bytes, and restricted to a conservative identifier charset so the
    /// value is a safe map key for subscription_preferences lookups.
    /// Returns `None` for values that cannot be normalized.
    pub fn validate(raw: &str) -> Option<String> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || normalized.len() > MAX_LEN {
            return None;
        }
        if !normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b' ')
        {
            return None;
        }
        Some(normalized)
    }

    /// True when `category` is exempt from per-category preference
    /// enforcement (see [`PREFERENCE_EXEMPT`]). Global suppression always
    /// applies regardless.
    pub fn is_preference_exempt(category: &str) -> bool {
        PREFERENCE_EXEMPT.contains(&category)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// F25/F75: shared parent-progress reconciliation contract
// ─────────────────────────────────────────────────────────────────────────────

/// THE tenant/message-scoped parent-progress reconciliation (audit F25/F75).
/// One canonical statement shared by the worker (after every durable
/// recipient transition) and the SES callback handler (after every confirmed
/// recipient transition). Parameters: `$1` = message uuid, `$2` = tenant id.
///
/// Parent-state model, derived from ALL recipient rows (`email_queue`) —
/// never from the single recipient that just transitioned:
///
/// * some recipient rows terminal AND some still non-terminal → `partial`
///   (partial progress: delivery work is still owed);
/// * no recipient row terminal yet and some non-terminal → `processing`
///   (mid-flight, still cancellable — a soft-bounce requeue must NOT
///   strand the parent in a non-cancellable state);
/// * every recipient row terminal AND at least one
///   `bounced`/`failed`/`suppressed`/`cancelled` → `partial`
///   (final partial success — including the all-failed case, which
///   previously stayed `processing` forever because only successes
///   reconciled);
/// * every recipient row `sent` and at least one not yet confirmed
///   delivered (`delivered_at IS NULL`) → `sent` (provider ACCEPTANCE for
///   every recipient), stamping `sent_at` at the actual event;
/// * every recipient row `sent` AND confirmed delivered → `delivered`,
///   stamping `messages.delivered_at` (the aggregate: ALL recipients
///   confirmed delivered) at the actual event.
///
/// Provider acceptance (`sent_at`) and confirmed delivery (`delivered_at`)
/// are distinct events with distinct timestamps; each is stamped only once
/// (the `m.<col> IS NULL` guard preserves the original event time under
/// concurrent or replayed transitions). A parent with NO recipient rows is
/// never touched (the EXISTS guard) — there is nothing to aggregate.
///
/// Concurrency safety: a single derived UPDATE is atomic per parent row, so
/// concurrently finishing recipients each recompute the aggregate from the
/// complete recipient set and converge. Terminal states set elsewhere
/// (`cancelled`) are not crouched.
pub const RECONCILE_MESSAGE_PROGRESS_SQL: &str = r#"
    UPDATE messages m SET
        status = CASE
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status NOT IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')
            ) AND EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')
            ) THEN 'partial'
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status NOT IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')
            ) THEN 'processing'
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status IN ('bounced', 'failed', 'suppressed', 'cancelled')
            ) THEN 'partial'
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status = 'sent'
                  AND q.delivered_at IS NULL
            ) THEN 'sent'
            ELSE 'delivered'
        END,
        sent_at = CASE
            WHEN m.sent_at IS NULL
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status NOT IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')
                )
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status IN ('bounced', 'failed', 'suppressed', 'cancelled')
                )
            THEN NOW() ELSE m.sent_at
        END,
        delivered_at = CASE
            WHEN m.delivered_at IS NULL
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status <> 'sent'
                )
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status = 'sent'
                      AND q.delivered_at IS NULL
                )
            THEN NOW() ELSE m.delivered_at
        END,
        updated_at = NOW()
    WHERE m.id = $1::uuid AND m.tenant_id = $2
      AND EXISTS (SELECT 1 FROM email_queue q WHERE q.message_id = m.id)
      AND m.status IN ('queued', 'scheduled', 'processing', 'partial', 'sent')
"#;

/// Restart/missed-event reconciliation (audit F25): the same derivation
/// applied to every parent whose recipient rows are ALL terminal but whose
/// aggregate status is not — the exact residue of a crash between a
/// recipient transition and its parent reconciliation. The worker runs this
/// on start and periodically; it is idempotent.
pub const RECONCILE_STUCK_PARENTS_SQL: &str = r#"
    UPDATE messages m SET
        status = CASE
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status IN ('bounced', 'failed', 'suppressed', 'cancelled')
            ) THEN 'partial'
            WHEN EXISTS (
                SELECT 1 FROM email_queue q
                WHERE q.message_id = m.id
                  AND q.status = 'sent'
                  AND q.delivered_at IS NULL
            ) THEN 'sent'
            ELSE 'delivered'
        END,
        sent_at = CASE
            WHEN m.sent_at IS NULL THEN NOW() ELSE m.sent_at
        END,
        delivered_at = CASE
            WHEN m.delivered_at IS NULL
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status <> 'sent'
                )
              AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.message_id = m.id
                      AND q.status = 'sent'
                      AND q.delivered_at IS NULL
                )
            THEN NOW() ELSE m.delivered_at
        END,
        updated_at = NOW()
    WHERE m.status IN ('processing', 'partial')
      AND EXISTS (SELECT 1 FROM email_queue q WHERE q.message_id = m.id)
      AND NOT EXISTS (
            SELECT 1 FROM email_queue q
            WHERE q.message_id = m.id
              AND q.status NOT IN ('sent', 'bounced', 'failed', 'suppressed', 'cancelled')
        )
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_reservation_is_case_insensitive() {
        for name in [
            "X-ApexMail-Message-ID",
            "x-apexmail-message-id",
            "X-ApexMail-MessageId",
            "x-apexmail-anything",
            "X-APExmail-Custom",
        ] {
            assert!(is_reserved_internal_header(name), "{name} must be reserved");
        }
        for name in ["X-Mailer", "X-Custom", "Message-ID", "Reply-To", "x-other"] {
            assert!(
                !is_reserved_internal_header(name),
                "{name} must NOT be reserved"
            );
        }
    }

    #[test]
    fn identity_header_lookup_matches_case_insensitive_and_aliases() {
        let headers = [("x-apexmail-message-id", "m-1")];
        match find_identity_header(
            headers.iter().copied(),
            HEADER_MESSAGE_ID,
            HEADER_ALIASES_MESSAGE_ID,
        ) {
            IdentityHeaderLookup::Found(v) => assert_eq!(v, "m-1"),
            other => panic!("expected Found, got {other:?}"),
        }

        let headers = [("X-ApexMail-MessageId", "m-2")];
        match find_identity_header(
            headers.iter().copied(),
            HEADER_MESSAGE_ID,
            HEADER_ALIASES_MESSAGE_ID,
        ) {
            IdentityHeaderLookup::Found(v) => assert_eq!(v, "m-2"),
            other => panic!("expected Found, got {other:?}"),
        }

        let headers: Vec<(&str, &str)> = vec![];
        assert!(matches!(
            find_identity_header(
                headers.iter().copied(),
                HEADER_MESSAGE_ID,
                HEADER_ALIASES_MESSAGE_ID
            ),
            IdentityHeaderLookup::Missing
        ));
    }

    #[test]
    fn identity_header_lookup_rejects_ambiguous_duplicates() {
        let headers = [
            ("X-ApexMail-Message-ID", "m-1"),
            ("X-ApexMail-MessageId", "m-2"),
        ];
        assert!(matches!(
            find_identity_header(
                headers.iter().copied(),
                HEADER_MESSAGE_ID,
                HEADER_ALIASES_MESSAGE_ID
            ),
            IdentityHeaderLookup::Ambiguous
        ));

        // Same value repeated is not ambiguous.
        let headers = [
            ("X-ApexMail-Message-ID", "m-1"),
            ("x-apexmail-messageid", "m-1"),
        ];
        assert!(matches!(
            find_identity_header(
                headers.iter().copied(),
                HEADER_MESSAGE_ID,
                HEADER_ALIASES_MESSAGE_ID
            ),
            IdentityHeaderLookup::Found(_)
        ));
    }

    #[test]
    fn category_validation_normalizes() {
        assert_eq!(
            message_category::validate(" Marketing "),
            Some("marketing".into())
        );
        assert_eq!(
            message_category::validate("News-Letter_2026"),
            Some("news-letter_2026".into())
        );
        assert_eq!(message_category::validate(""), None);
        assert_eq!(message_category::validate("   "), None);
        assert_eq!(message_category::validate("cat\ngory"), None);
        assert_eq!(message_category::validate("cat\x1bgory"), None);
        assert_eq!(message_category::validate(&"x".repeat(101)), None);
        assert_eq!(
            message_category::validate(&"x".repeat(100)),
            Some("x".repeat(100))
        );
    }

    #[test]
    fn category_exemptions_are_explicit() {
        assert!(message_category::is_preference_exempt("transactional"));
        assert!(message_category::is_preference_exempt("service"));
        assert!(!message_category::is_preference_exempt("marketing"));
        assert!(!message_category::is_preference_exempt("newsletter"));
    }
}
