//! Shared deployment-wide email transport selection.
//!
//! Customer domains are always provisioned for the transport selected for the
//! deployment. Keeping this parser in the shared crate prevents the API's
//! readiness gate and the worker's delivery path from disagreeing.

/// Whether a configured transport value selects AWS SES.
///
/// Only an explicit `smtp` value selects SMTP. Missing, empty, and unrecognized
/// values select SES, matching the production deployment default.
pub fn email_transport_is_ses(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("smtp")
    )
}

#[cfg(test)]
mod tests {
    use super::email_transport_is_ses;

    #[test]
    fn only_explicit_smtp_selects_smtp() {
        assert!(!email_transport_is_ses(Some("smtp")));
        assert!(!email_transport_is_ses(Some(" SMTP ")));

        assert!(email_transport_is_ses(None));
        assert!(email_transport_is_ses(Some("")));
        assert!(email_transport_is_ses(Some("ses")));
        assert!(email_transport_is_ses(Some("self-hosted")));
        assert!(email_transport_is_ses(Some("direct")));
        assert!(email_transport_is_ses(Some("unexpected")));
    }
}