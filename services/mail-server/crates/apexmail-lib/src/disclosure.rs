//! Disclosure governance: who is allowed to know a fact.
//!
//! The root defect behind three successive external audits (2026-10-26) is
//! that ApexMail has no single authoritative answer to "who may know this
//! fact?" — the same provider name, city, or topology had to be scrubbed
//! from marketing, AI prompts, receipts, health endpoints, timelines and
//! build artifacts one surface at a time. This module is that authority:
//!
//! ```text
//! enum DisclosureClass { Public, Customer, SecurityReview, Internal }
//! struct GovernedFact<T> { value, visibility, purpose }
//! ```
//!
//! Classification table (the canonical examples — new facts MUST choose):
//!
//! | Fact                                            | Class         |
//! |-------------------------------------------------|---------------|
//! | ApexMail provides EU/EEA deployment             | Public        |
//! | Supported API/SMTP endpoints, pricing           | Public        |
//! | A customer's own message ids, sending stats     | Customer      |
//! | A customer's own dedicated IP, receipts         | Customer      |
//! | Sanitized backup/DR summary, pen-test summary   | SecurityReview|
//! | Infrastructure provider identity                | Internal      |
//! | Facility, city beyond the country commitment    | Internal      |
//! | Host counts, topology, DB/cache/queue products  | Internal      |
//! | CI/CD implementation, backup mechanics           | Internal      |
//! | Organisation size, ownership, staffing          | Internal      |
//!
//! The one contractual carve-out (provider identity → contracting customer
//! under GDPR Art. 28) is recorded in
//! `docs/operations/disclosure-exceptions.json` with its exact allowed
//! surface — an exception must be LISTED, never implicit.
//!
//! Every outward path (website, assistant, mailbot, customer API,
//! questionnaire, receipts, status, generated documents) should consume
//! [`GovernedFact::visible_to`] with the audience it actually serves, never
//! the raw internal value. Order is privilege order: an audience at least
//! as privileged as the fact's class sees it.

/// Who may learn a fact. Order = privilege order (`Public` least,
/// `Internal` most); the derived `PartialOrd` is load-bearing for
/// [`GovernedFact::visible_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisclosureClass {
    /// Anonymous internet: marketing, docs, status, unauthenticated health.
    Public,
    /// Authenticated tenant users: API responses, the console assistant,
    /// customer receipts and timeline views.
    Customer,
    /// Contracting customers and auditors under a review process:
    /// questionnaires, the TOM/DPA, executive summaries.
    SecurityReview,
    /// Never leaves the platform: infrastructure identity, topology,
    /// stack, backup mechanics, organisation size.
    Internal,
}

impl DisclosureClass {
    /// Stable lowercase label for logs, evidence and manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Customer => "customer",
            Self::SecurityReview => "security_review",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for DisclosureClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A fact whose visibility is part of its type: the value cannot be read
/// without naming an audience, and [`GovernedFact::visible_to`] is the only
/// reading path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernedFact<T> {
    value: T,
    visibility: DisclosureClass,
    /// Why the fact exists / which obligation answers it (e.g.
    /// "residency commitment", "own attestation", "registry identity") —
    /// carried into evidence so a disclosure audit can ask WHY, not just WHO.
    purpose: &'static str,
}

impl<T> GovernedFact<T> {
    /// Classify a fact at construction. `const fn` so module-level constants
    /// can be governed facts.
    pub const fn new(value: T, visibility: DisclosureClass, purpose: &'static str) -> Self {
        Self {
            value,
            visibility,
            purpose,
        }
    }

    /// The fact's class (writing the class again at read time is
    /// deliberately impossible — it is constructor state).
    pub const fn visibility(&self) -> DisclosureClass {
        self.visibility
    }

    /// Why this fact exists.
    pub const fn purpose(&self) -> &'static str {
        self.purpose
    }

    /// The external view: `Some` only when `audience` is at least as
    /// privileged as the fact's class. This is the ONLY read path an
    /// outward surface should use.
    pub fn visible_to(&self, audience: DisclosureClass) -> Option<&T> {
        if audience >= self.visibility {
            Some(&self.value)
        } else {
            None
        }
    }

    /// Owning read for audiences that consume by value.
    pub fn into_visible(self, audience: DisclosureClass) -> Option<T> {
        if audience >= self.visibility {
            Some(self.value)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_follows_privilege_order() {
        let public = GovernedFact::new("EU/EEA deployment", DisclosureClass::Public, "residency");
        for audience in [
            DisclosureClass::Public,
            DisclosureClass::Customer,
            DisclosureClass::SecurityReview,
            DisclosureClass::Internal,
        ] {
            assert_eq!(public.visible_to(audience), Some(&"EU/EEA deployment"));
        }

        let internal = GovernedFact::new("provider-name", DisclosureClass::Internal, "hosting");
        for audience in [
            DisclosureClass::Public,
            DisclosureClass::Customer,
            DisclosureClass::SecurityReview,
        ] {
            assert_eq!(
                internal.visible_to(audience),
                None,
                "{audience} must not see an internal fact"
            );
        }
        assert_eq!(
            internal.visible_to(DisclosureClass::Internal),
            Some(&"provider-name")
        );

        // Customer facts reach customers but not anonymous visitors.
        let own = GovernedFact::new("msg_1", DisclosureClass::Customer, "message identity");
        assert_eq!(own.visible_to(DisclosureClass::Public), None);
        assert_eq!(own.visible_to(DisclosureClass::Customer), Some(&"msg_1"));
    }

    #[test]
    fn purpose_is_carried_for_evidence() {
        let fact = GovernedFact::new(42, DisclosureClass::SecurityReview, "dr summary");
        assert_eq!(fact.purpose(), "dr summary");
        assert_eq!(fact.visibility(), DisclosureClass::SecurityReview);
        assert_eq!(fact.into_visible(DisclosureClass::Customer), None);
        assert_eq!(fact.into_visible(DisclosureClass::Internal), Some(42));
    }

    #[test]
    fn class_labels_are_stable() {
        assert_eq!(DisclosureClass::Public.as_str(), "public");
        assert_eq!(DisclosureClass::Customer.as_str(), "customer");
        assert_eq!(DisclosureClass::SecurityReview.as_str(), "security_review");
        assert_eq!(DisclosureClass::Internal.as_str(), "internal");
        assert_eq!(DisclosureClass::Public.to_string(), "public");
        assert!(DisclosureClass::Public < DisclosureClass::Customer);
        assert!(DisclosureClass::Customer < DisclosureClass::SecurityReview);
        assert!(DisclosureClass::SecurityReview < DisclosureClass::Internal);
    }
}
