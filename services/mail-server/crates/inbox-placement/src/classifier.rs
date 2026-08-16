use crate::types::ProviderName;

/// Canonical inbox folder types used for delivery classification.
#[derive(Debug, Clone, PartialEq)]
pub enum InboxFolder {
    Inbox,
    Promotions,
    Social,
    Updates,
    Spam,
    Junk,
    Bulk,
    Archive,
    Other(String),
}

/// Maps an IMAP folder name to a canonical [`InboxFolder`] variant based on
/// provider-specific folder naming conventions.
///
/// Matching is case-insensitive. Unrecognised folders fall back to
/// `InboxFolder::Other`.
pub fn classify_folder(folder_name: &str, provider: &ProviderName) -> InboxFolder {
    let lower = folder_name.to_lowercase();

    match provider {
        ProviderName::Gmail => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower.contains("[gmail]") {
                if lower.contains("promotions") {
                    return InboxFolder::Promotions;
                }
                if lower.contains("social") {
                    return InboxFolder::Social;
                }
                if lower.contains("updates") || lower.contains("notifications") {
                    return InboxFolder::Updates;
                }
                if lower.contains("spam") || lower.contains("junk") {
                    return InboxFolder::Spam;
                }
                if lower.contains("all mail") || lower.contains("archive") {
                    return InboxFolder::Archive;
                }
                if lower.contains("bulk") {
                    return InboxFolder::Bulk;
                }
            }
            generic_match(&lower)
        }
        ProviderName::Outlook | ProviderName::Other(_) => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "junk" || lower == "junkemail" {
                return InboxFolder::Spam;
            }
            if lower == "clutter" {
                return InboxFolder::Promotions;
            }
            if lower == "archive" {
                return InboxFolder::Archive;
            }
            if lower == "sent" || lower == "drafts" || lower == "deleted" || lower == "outbox" {
                return InboxFolder::Other(folder_name.to_string());
            }
            generic_match(&lower)
        }
        ProviderName::Yahoo => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "bulk" || lower == "spam" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Icloud => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "junk" || lower == "spam" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Aol => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "spam" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Zoho => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "spam" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Protonmail => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "spam" || lower == "junk" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Gmx => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "spam" || lower == "junk" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
        ProviderName::Yandex => {
            if lower == "inbox" {
                return InboxFolder::Inbox;
            }
            if lower == "spam" || lower == "junk" {
                return InboxFolder::Spam;
            }
            generic_match(&lower)
        }
    }
}

/// Fallback generic matching based on common IMAP folder names.
fn generic_match(lower: &str) -> InboxFolder {
    if lower == "inbox" {
        return InboxFolder::Inbox;
    }
    if lower.contains("spam") || lower.contains("junk") || lower == "bulk" {
        return InboxFolder::Spam;
    }
    if lower.contains("promotions") || lower.contains("offers") || lower.contains("deals") {
        return InboxFolder::Promotions;
    }
    if lower.contains("social") {
        return InboxFolder::Social;
    }
    if lower.contains("updates") || lower.contains("notification") {
        return InboxFolder::Updates;
    }
    if lower.contains("archive") || lower.contains("all mail") {
        return InboxFolder::Archive;
    }
    InboxFolder::Other(lower.to_string())
}

/// Returns a delivery-category label suitable for storage or display.
///
/// Maps to one of: `"inbox"`, `"promotions"`, `"spam"`, `"absent"`.
pub fn delivery_category(folder: &InboxFolder) -> &'static str {
    match folder {
        InboxFolder::Inbox => "inbox",
        InboxFolder::Promotions => "promotions",
        InboxFolder::Social => "promotions",
        InboxFolder::Updates => "promotions",
        InboxFolder::Spam | InboxFolder::Junk | InboxFolder::Bulk => "spam",
        InboxFolder::Archive => "inbox",
        InboxFolder::Other(_) => "absent",
    }
}

/// Classify an IMAP folder name into the placement value stored per message.
///
/// Deterministic rules first, provider classifier as fallback:
/// 1. `INBOX` under any casing → `"inbox"` (RFC 3501 interprets INBOX
///    case-insensitively).
/// 2. Folders matching `(?i)spam|junk|bulk|promotions` → `"spam"`.
/// 3. Anything else → [`classify_folder`] + [`delivery_category`] for the
///    provider (e.g. Gmail Social/Updates tabs, Archive, custom folders).
pub fn placement_from_folder(folder_name: &str, provider: &ProviderName) -> String {
    if folder_name.eq_ignore_ascii_case("inbox") {
        return "inbox".to_string();
    }
    let lower = folder_name.to_lowercase();
    if lower.contains("spam")
        || lower.contains("junk")
        || lower.contains("bulk")
        || lower.contains("promotions")
    {
        return "spam".to_string();
    }
    let folder = classify_folder(folder_name, provider);
    delivery_category(&folder).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Gmail ────────────────────────────────────────────────────

    #[test]
    fn test_gmail_inbox() {
        assert_eq!(
            classify_folder("INBOX", &ProviderName::Gmail),
            InboxFolder::Inbox
        );
    }

    #[test]
    fn test_gmail_promotions() {
        assert_eq!(
            classify_folder("[Gmail]/Promotions", &ProviderName::Gmail),
            InboxFolder::Promotions
        );
    }

    #[test]
    fn test_gmail_social() {
        assert_eq!(
            classify_folder("[Gmail]/Social", &ProviderName::Gmail),
            InboxFolder::Social
        );
    }

    #[test]
    fn test_gmail_spam() {
        assert_eq!(
            classify_folder("[Gmail]/Spam", &ProviderName::Gmail),
            InboxFolder::Spam
        );
    }

    // ── Outlook ──────────────────────────────────────────────────

    #[test]
    fn test_outlook_inbox() {
        assert_eq!(
            classify_folder("Inbox", &ProviderName::Outlook),
            InboxFolder::Inbox
        );
    }

    #[test]
    fn test_outlook_junk() {
        assert_eq!(
            classify_folder("Junk", &ProviderName::Outlook),
            InboxFolder::Spam
        );
    }

    #[test]
    fn test_outlook_clutter() {
        assert_eq!(
            classify_folder("Clutter", &ProviderName::Outlook),
            InboxFolder::Promotions
        );
    }

    // ── Yahoo ────────────────────────────────────────────────────

    #[test]
    fn test_yahoo_inbox() {
        assert_eq!(
            classify_folder("Inbox", &ProviderName::Yahoo),
            InboxFolder::Inbox
        );
    }

    #[test]
    fn test_yahoo_bulk() {
        assert_eq!(
            classify_folder("Bulk", &ProviderName::Yahoo),
            InboxFolder::Spam
        );
    }

    // ── iCloud ───────────────────────────────────────────────────

    #[test]
    fn test_icloud_inbox() {
        assert_eq!(
            classify_folder("INBOX", &ProviderName::Icloud),
            InboxFolder::Inbox
        );
    }

    #[test]
    fn test_icloud_junk() {
        assert_eq!(
            classify_folder("Junk", &ProviderName::Icloud),
            InboxFolder::Spam
        );
    }

    // ── AOL ──────────────────────────────────────────────────────

    #[test]
    fn test_aol_inbox() {
        assert_eq!(
            classify_folder("Inbox", &ProviderName::Aol),
            InboxFolder::Inbox
        );
    }

    #[test]
    fn test_aol_spam() {
        assert_eq!(
            classify_folder("Spam", &ProviderName::Aol),
            InboxFolder::Spam
        );
    }

    // ── Zoho ─────────────────────────────────────────────────────

    #[test]
    fn test_zoho_inbox() {
        assert_eq!(
            classify_folder("Inbox", &ProviderName::Zoho),
            InboxFolder::Inbox
        );
    }

    // ── Generic (Other) ──────────────────────────────────────────

    #[test]
    fn test_other_unknown() {
        let result = classify_folder("CustomFolder", &ProviderName::Other("test".into()));
        assert!(matches!(result, InboxFolder::Other(_)));
    }

    // ── delivery_category ────────────────────────────────────────

    #[test]
    fn test_delivery_category_inbox() {
        assert_eq!(delivery_category(&InboxFolder::Inbox), "inbox");
    }

    #[test]
    fn test_delivery_category_promotions() {
        assert_eq!(delivery_category(&InboxFolder::Promotions), "promotions");
    }

    #[test]
    fn test_delivery_category_social_as_promotions() {
        assert_eq!(delivery_category(&InboxFolder::Social), "promotions");
    }

    #[test]
    fn test_delivery_category_spam() {
        assert_eq!(delivery_category(&InboxFolder::Spam), "spam");
    }

    #[test]
    fn test_delivery_category_absent() {
        assert_eq!(delivery_category(&InboxFolder::Other("x".into())), "absent");
    }

    // ── placement_from_folder ────────────────────────────────────

    #[test]
    fn test_placement_from_folder_inbox_any_case() {
        for name in ["INBOX", "Inbox", "inbox"] {
            assert_eq!(
                placement_from_folder(name, &ProviderName::Gmail),
                "inbox",
                "folder {name} should classify as inbox"
            );
        }
    }

    #[test]
    fn test_placement_from_folder_spam_conventions() {
        for name in [
            "[Gmail]/Spam",
            "Junk",
            "JUNK",
            "Bulk Mail",
            "[Gmail]/Promotions",
        ] {
            assert_eq!(
                placement_from_folder(name, &ProviderName::Other("prov".into())),
                "spam",
                "folder {name} should classify as spam"
            );
        }
    }

    #[test]
    fn test_placement_from_folder_other_uses_classifier_fallback() {
        // Gmail tabs fall back to the provider classifier ("promotions").
        assert_eq!(
            placement_from_folder("[Gmail]/Social", &ProviderName::Gmail),
            "promotions"
        );
        // Archive falls back to "inbox" via the classifier.
        assert_eq!(
            placement_from_folder("Archive", &ProviderName::Gmail),
            "inbox"
        );
        // Unknown custom folders fall back to "absent".
        assert_eq!(
            placement_from_folder("MyFolder", &ProviderName::Gmail),
            "absent"
        );
    }
}
