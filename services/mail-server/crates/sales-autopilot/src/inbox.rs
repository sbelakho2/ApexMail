use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;
use uuid::Uuid;

use crate::types::{InboxMessage, MessageCategory};

/// Inbox monitoring / sentinel service.
///
/// Categorises inbound messages into Lead / Customer / Support / Spam / Other
/// using simple keyword heuristics (production would use an ML classifier).
#[derive(Debug, Clone)]
pub struct InboxManager {
    messages: Arc<RwLock<Vec<InboxMessage>>>,
}

impl Default for InboxManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InboxManager {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Classify and store a message, returning the assigned category.
    pub fn categorize_message(
        &self,
        from: String,
        subject: String,
    ) -> InboxMessage {
        let category = Self::classify(&subject, &from);
        let msg = InboxMessage {
            id: Uuid::new_v4(),
            from,
            subject,
            received_at: Utc::now(),
            category,
            replied: false,
        };
        self.messages.write().push(msg.clone());
        msg
    }

    /// Heuristic classification.
    fn classify(subject: &str, from: &str) -> MessageCategory {
        let s = subject.to_lowercase();
        let f = from.to_lowercase();

        if s.contains("unsubscribe")
            || s.contains("viagra")
            || s.contains("lottery")
            || f.contains("noreply")
        {
            return MessageCategory::Spam;
        }
        if s.contains("support")
            || s.contains("help")
            || s.contains("ticket")
            || s.contains("issue")
        {
            return MessageCategory::Support;
        }
        if s.contains("invoice")
            || s.contains("payment")
            || s.contains("subscription")
            || s.contains("renewal")
        {
            return MessageCategory::Customer;
        }
        if s.contains("demo")
            || s.contains("pricing")
            || s.contains("interested")
            || s.contains("trial")
        {
            return MessageCategory::Lead;
        }
        MessageCategory::Other
    }

    /// List messages belonging to a given category.
    pub fn list_by_category(&self, cat: MessageCategory) -> Vec<InboxMessage> {
        self.messages
            .read()
            .iter()
            .filter(|m| m.category == cat)
            .cloned()
            .collect()
    }

    /// List all messages regardless of category.
    pub fn list_all(&self) -> Vec<InboxMessage> {
        self.messages.read().clone()
    }

    /// Mark a message as replied.
    pub fn mark_replied(&self, id: Uuid) -> bool {
        let mut store = self.messages.write();
        if let Some(msg) = store.iter_mut().find(|m| m.id == id) {
            msg.replied = true;
            true
        } else {
            false
        }
    }

    /// Return the reply rate (0.0–1.0) across *all* messages.
    pub fn get_reply_rate(&self) -> f64 {
        let store = self.messages.read();
        if store.is_empty() {
            return 0.0;
        }
        let replied = store.iter().filter(|m| m.replied).count() as f64;
        replied / store.len() as f64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorization() {
        let mgr = InboxManager::new();
        let m1 = mgr.categorize_message("alice@x.com".into(), "Interested in a demo".into());
        assert_eq!(m1.category, MessageCategory::Lead);

        let m2 = mgr.categorize_message("noreply@spam.biz".into(), "You won the lottery!".into());
        assert_eq!(m2.category, MessageCategory::Spam);

        let m3 = mgr.categorize_message("bob@y.com".into(), "Support ticket #1234".into());
        assert_eq!(m3.category, MessageCategory::Support);

        let m4 = mgr.categorize_message("billing@co.com".into(), "Invoice for subscription".into());
        assert_eq!(m4.category, MessageCategory::Customer);
    }

    #[test]
    fn test_list_by_category_and_mark_replied() {
        let mgr = InboxManager::new();
        let m = mgr.categorize_message("a@b.com".into(), "Pricing inquiry".into());
        assert_eq!(m.category, MessageCategory::Lead);

        let leads = mgr.list_by_category(MessageCategory::Lead);
        assert_eq!(leads.len(), 1);

        assert!(mgr.mark_replied(m.id));
        assert!(!mgr.mark_replied(Uuid::new_v4())); // non-existent
    }

    #[test]
    fn test_reply_rate() {
        let mgr = InboxManager::new();
        assert_eq!(mgr.get_reply_rate(), 0.0);

        let m1 = mgr.categorize_message("a@b.com".into(), "Hello".into());
        let _m2 = mgr.categorize_message("c@d.com".into(), "World".into());
        mgr.mark_replied(m1.id);

        let rate = mgr.get_reply_rate();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }
}
