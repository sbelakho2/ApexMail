//! Pre-built spam detection patterns as reusable rule sets.

use crate::rules::{Rule, RuleCategory, RuleSet, Severity};

/// Build a rule set for common spam phrase detection.
pub fn spam_rules() -> RuleSet {
    let rules = vec![
        // Urgency / scarcity tactics
        Rule::new(
            "act now",
            "spam:urgency:act_now",
            RuleCategory::Spam,
            Severity::Medium,
            3,
        ),
        Rule::new(
            "limited time offer",
            "spam:urgency:limited_time",
            RuleCategory::Spam,
            Severity::Medium,
            4,
        ),
        Rule::new(
            "don't miss out",
            "spam:urgency:fomo",
            RuleCategory::Spam,
            Severity::Low,
            2,
        ),
        Rule::new(
            "expires soon",
            "spam:urgency:expires",
            RuleCategory::Spam,
            Severity::Low,
            2,
        ),
        Rule::new(
            "last chance",
            "spam:urgency:last_chance",
            RuleCategory::Spam,
            Severity::Medium,
            3,
        ),
        Rule::new(
            "hurry up",
            "spam:urgency:hurry",
            RuleCategory::Spam,
            Severity::Medium,
            3,
        ),
        Rule::new(
            "while supplies last",
            "spam:urgency:supplies",
            RuleCategory::Spam,
            Severity::Medium,
            3,
        ),
        // Financial spam
        Rule::new(
            "you have been selected",
            "spam:financial:selected",
            RuleCategory::Spam,
            Severity::High,
            6,
        ),
        Rule::new(
            "claim your prize",
            "spam:financial:prize",
            RuleCategory::Spam,
            Severity::High,
            7,
        ),
        Rule::new(
            "congratulations you won",
            "spam:financial:won",
            RuleCategory::Spam,
            Severity::High,
            7,
        ),
        Rule::new(
            "earn extra cash",
            "spam:financial:cash",
            RuleCategory::Spam,
            Severity::Medium,
            4,
        ),
        Rule::new(
            "make money fast",
            "spam:financial:money",
            RuleCategory::Spam,
            Severity::High,
            6,
        ),
        Rule::new(
            "double your income",
            "spam:financial:income",
            RuleCategory::Spam,
            Severity::High,
            6,
        ),
        Rule::new(
            "risk-free investment",
            "spam:financial:investment",
            RuleCategory::Spam,
            Severity::High,
            7,
        ),
        Rule::new(
            "no credit check",
            "spam:financial:credit",
            RuleCategory::Spam,
            Severity::Medium,
            4,
        ),
        Rule::new(
            "100% free",
            "spam:financial:free100",
            RuleCategory::Spam,
            Severity::Medium,
            3,
        ),
        // Pharmaceutical spam
        Rule::new(
            "buy cheap",
            "spam:pharma:cheap",
            RuleCategory::Spam,
            Severity::Medium,
            4,
        ),
        Rule::new(
            "order now",
            "spam:pharma:order",
            RuleCategory::Spam,
            Severity::Low,
            2,
        ),
        Rule::new(
            "no prescription",
            "spam:pharma:no_rx",
            RuleCategory::Spam,
            Severity::High,
            6,
        ),
        // Phishing indicators
        Rule::new(
            "verify your account",
            "phishing:verify_account",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "confirm your identity",
            "phishing:confirm_identity",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "your account has been compromised",
            "phishing:compromised",
            RuleCategory::Phishing,
            Severity::Critical,
            10,
        ),
        Rule::new(
            "unusual activity",
            "phishing:unusual_activity",
            RuleCategory::Phishing,
            Severity::High,
            6,
        ),
        Rule::new(
            "reset your password",
            "phishing:reset_password",
            RuleCategory::Phishing,
            Severity::Medium,
            4,
        ),
        Rule::new(
            "click here to verify",
            "phishing:click_verify",
            RuleCategory::Phishing,
            Severity::Critical,
            9,
        ),
        Rule::new(
            "suspended account",
            "phishing:suspended",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "unauthorized login",
            "phishing:unauthorized",
            RuleCategory::Phishing,
            Severity::High,
            6,
        ),
        Rule::new(
            "security alert",
            "phishing:security_alert",
            RuleCategory::Phishing,
            Severity::Medium,
            5,
        ),
        // Content policy
        Rule::new(
            "unsubscribe",
            "policy:unsubscribe",
            RuleCategory::ContentPolicy,
            Severity::Low,
            0,
        ),
        Rule::new(
            "click here",
            "policy:click_here",
            RuleCategory::ContentPolicy,
            Severity::Low,
            1,
        ),
        Rule::new(
            "buy now",
            "policy:buy_now",
            RuleCategory::ContentPolicy,
            Severity::Low,
            1,
        ),
        Rule::new(
            "free trial",
            "policy:free_trial",
            RuleCategory::ContentPolicy,
            Severity::Low,
            1,
        ),
    ];
    RuleSet::new(rules)
}

/// Build a rule set specifically for phishing detection (high-severity subset).
pub fn phishing_rules() -> RuleSet {
    let rules = vec![
        Rule::new(
            "verify your account",
            "phishing:verify_account",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "confirm your identity",
            "phishing:confirm_identity",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "your account has been compromised",
            "phishing:compromised",
            RuleCategory::Phishing,
            Severity::Critical,
            10,
        ),
        Rule::new(
            "click here to verify",
            "phishing:click_verify",
            RuleCategory::Phishing,
            Severity::Critical,
            9,
        ),
        Rule::new(
            "suspended account",
            "phishing:suspended",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
        Rule::new(
            "unauthorized login",
            "phishing:unauthorized",
            RuleCategory::Phishing,
            Severity::High,
            6,
        ),
        Rule::new(
            "update your payment",
            "phishing:update_payment",
            RuleCategory::Phishing,
            Severity::Critical,
            9,
        ),
        Rule::new(
            "your account will be closed",
            "phishing:account_closed",
            RuleCategory::Phishing,
            Severity::Critical,
            9,
        ),
        Rule::new(
            "verify your identity immediately",
            "phishing:verify_urgent",
            RuleCategory::Phishing,
            Severity::Critical,
            10,
        ),
        Rule::new(
            "you must respond within",
            "phishing:respond_deadline",
            RuleCategory::Phishing,
            Severity::High,
            7,
        ),
    ];
    RuleSet::new(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spam_rules_count() {
        let rs = spam_rules();
        assert!(
            rs.rule_count() >= 30,
            "Expected 30+ rules, got {}",
            rs.rule_count()
        );
    }

    #[test]
    fn test_spam_rules_detect_financial() {
        let rs = spam_rules();
        let matches =
            rs.evaluate("Congratulations you won a million dollars! Claim your prize now!");
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_spam_rules_detect_phishing() {
        let rs = spam_rules();
        let matches =
            rs.evaluate("Your account has been compromised. Click here to verify your identity.");
        let critical = matches.iter().any(|m| m.severity == Severity::Critical);
        assert!(critical, "Should detect critical phishing pattern");
    }

    #[test]
    fn test_spam_rules_clean_text() {
        let rs = spam_rules();
        let matches =
            rs.evaluate("Hi John, here's the quarterly report you requested. Best regards.");
        let score: f64 = matches.iter().map(|m| m.score).sum();
        assert!(score == 0.0, "Clean text should have 0 spam score");
    }

    #[test]
    fn test_spam_rules_urgency_detection() {
        let rs = spam_rules();
        let matches = rs.evaluate("Act now! Limited time offer - hurry up before it expires soon!");
        assert!(matches.len() >= 3, "Should match multiple urgency patterns");
    }

    #[test]
    fn test_phishing_rules_count() {
        let rs = phishing_rules();
        assert_eq!(rs.rule_count(), 10);
    }

    #[test]
    fn test_phishing_rules_has_critical() {
        let rs = phishing_rules();
        let matches = rs.evaluate(
            "Your account has been compromised. Update your payment information immediately.",
        );
        assert!(
            matches.iter().any(|m| m.severity == Severity::Critical),
            "Should have critical match"
        );
    }

    #[test]
    fn test_phishing_rules_score() {
        let rs = phishing_rules();
        let matches = rs.evaluate(
            "Verify your account or your account will be closed. Click here to verify now.",
        );
        let total: f64 = matches.iter().map(|m| m.score).sum();
        assert!(
            total >= 16.0,
            "Multiple phishing patterns should yield high score, got {total}"
        );
    }
}
