//! The quarantine selection of the marks plane (change.md 1.3 and
//! 3.3.4).
//!
//! Quarantine is a decision disposition, never a ladder rung: the
//! decision plane emits it on top of the Allow action for a
//! server-confirmed spam identity, and the wire stays indistinguishable
//! from allow end to end (same challenge bytes shape, same difficulty,
//! same timing within the noise floor). The app accepts the submission
//! and withholds it from publication; the app-facing surfaces carry the
//! flag (`quarantined` on the decision struct), never the HTTP
//! responses.
//!
//! The selection rule is exact: every in-TTL own-dimension mark of the
//! request carries the server-confirmed spam kind (`spamReported`, the
//! mark the outcomes plane writes for the SpamReported outcome), at
//! least one such mark exists, no target-dimension mark is in TTL, and
//! the request carries no corroborating attacker evidence. Under those
//! conditions and a plain Allow decision the marks stage quarantines
//! instead of escalating.
//!
//! The precedence is severity-monotonic, so the more severe disposition
//! always wins:
//!
//! | inputs                                   | disposition        |
//! |------------------------------------------|--------------------|
//! | spam marks only, plain Allow, clean      | quarantine         |
//! | corroborating evidence + any own mark    | deny               |
//! | any non-spam own mark in TTL             | the marked-identity rung floor |
//! | target mark in TTL                       | step-up (victim ceiling) |
//! | plain action above Allow                 | that action        |
//! | mark outside its TTL window              | plain allow, never quarantine |
//! | a later stage raises the action          | the raised action, quarantine dropped |
//!
//! A mixed picture (a spam mark next to a fraudConfirmed mark, or a
//! target mark) is never a quarantine: the stronger treatment of the
//! other mark wins. A spam mark alone above the Allow band changes
//! nothing: the plain action stands and the stage only adds its
//! marked-identity reason, exactly like the legacy rules. The legacy
//! corpus (attacker-denial-vectors.json) pins rules 1 to 3 of the marks
//! stage with the selection off; the quarantine corpus
//! (quarantine-vectors.json, see `tests/quarantine_vectors.rs`) pins
//! the selection and its precedence with it on.

use crate::marks::MarksView;

/// The mark kind the outcomes plane writes for the SpamReported outcome.
pub const SPAM_MARK_KIND: &str = "spamReported";

/// True when the view selects quarantine: at least one in-TTL own mark,
/// every in-TTL own mark of the spam kind, no in-TTL target mark and no
/// corroboration. The plain Allow requirement is the caller's (the marks
/// stage checks it against the decision).
pub fn selects(view: &MarksView, corroborated: bool, now_ms: u64, mark_ttl_ms: u64) -> bool {
    if corroborated {
        return false;
    }
    spam_only(view, now_ms, mark_ttl_ms) && view.target_in_ttl(now_ms, mark_ttl_ms).is_none()
}

/// True when the identity's live mark set is spam-only: at least one
/// in-TTL own mark and every in-TTL own mark of the spam kind. The
/// stage uses this to keep the Argon64 floor a non-spam treatment: a
/// spam-only identity above the Allow band keeps its plain action.
pub fn spam_only(view: &MarksView, now_ms: u64, mark_ttl_ms: u64) -> bool {
    let own = view.own_in_ttl(now_ms, mark_ttl_ms);
    if own.is_empty() {
        return false;
    }
    own.iter().all(|(_, record)| record.kind == SPAM_MARK_KIND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marks::MarksView;
    use crate::outcomes::{MarkDimension, MarkRecord};

    const T0: u64 = 1_700_000_000_000;
    const TTL: u64 = 7_776_000_000;

    fn mark(kind: &str, last_ms: i64) -> MarkRecord {
        MarkRecord {
            kind: kind.to_string(),
            last_kind: kind.to_string(),
            count: 1,
            first_ms: last_ms,
            last_ms,
        }
    }

    #[test]
    fn selection_rule_is_exact() {
        let own = vec![(MarkDimension::Session, mark(SPAM_MARK_KIND, T0 as i64))];
        // Spam-only live set selects.
        assert!(selects(
            &MarksView::from_parts(own.clone(), None),
            false,
            T0,
            TTL
        ));
        // Corroboration never selects.
        assert!(!selects(
            &MarksView::from_parts(own.clone(), None),
            true,
            T0,
            TTL
        ));
        // A target mark never selects.
        let target = Some(mark("accountBanned", T0 as i64));
        assert!(!selects(
            &MarksView::from_parts(own.clone(), target),
            false,
            T0,
            TTL
        ));
        // A non-spam mark in the live set never selects.
        let mixed = vec![
            (MarkDimension::Session, mark(SPAM_MARK_KIND, T0 as i64)),
            (MarkDimension::Asn, mark("fraudConfirmed", T0 as i64)),
        ];
        assert!(!selects(
            &MarksView::from_parts(mixed.clone(), None),
            false,
            T0,
            TTL
        ));
        // Expired marks are inert, never a quarantine.
        assert!(!selects(
            &MarksView::from_parts(own.clone(), None),
            false,
            T0 + TTL,
            TTL
        ));
        // No live marks at all never selects.
        assert!(!selects(&MarksView::default(), false, T0, TTL));
        // The spam-only classification drives the stage's floor skip.
        assert!(spam_only(&MarksView::from_parts(own, None), T0, TTL));
        assert!(!spam_only(&MarksView::from_parts(mixed, None), T0, TTL));
    }
}
