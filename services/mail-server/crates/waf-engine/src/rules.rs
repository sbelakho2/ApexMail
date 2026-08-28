//! WAF rule definitions (OWASP CRS-compatible rule IDs)

use serde::{Deserialize, Serialize};

/// A WAF rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    /// Rule ID (OWASP CRS compatible numbering)
    pub id: u32,
    /// Human-readable description
    pub description: String,
    /// Attack category
    pub category: RuleCategory,
    /// Severity score this rule adds to the anomaly total
    pub severity: u32,
    /// Minimum paranoia level to activate this rule
    pub paranoia_level: u8,
    /// Whether this rule is currently enabled
    pub enabled: bool,
}

/// Rule category (serializable)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleCategory {
    /// SQL Injection rules (942xxx)
    SqlInjection,
    /// XSS rules (941xxx)
    Xss,
    /// Path Traversal / LFI rules (930xxx)
    PathTraversal,
    /// Command Injection rules (932xxx)
    CommandInjection,
    /// RCE rules (932xxx)
    Rce,
    /// Protocol violation rules (911xxx-920xxx)
    ProtocolViolation,
    /// Request anomaly rules (920xxx)
    RequestAnomaly,
}

/// Minimum paranoia level required to activate a rule, per the default
/// catalog above (OWASP CRS semantics: a rule fires only when the engine's
/// configured `paranoia_level` >= the rule's level).
///
/// Rules that are not present in the catalog default to level 1, so they
/// are active at every configured level. This table mirrors
/// `default_ruleset()` — `test_rule_paranoia_table_matches_catalog` keeps
/// the two in sync.
pub fn rule_paranoia_level(rule_id: u32) -> u8 {
    match rule_id {
        942400 | 942600 | 941400 | 941500 | 932200 | 920300 => 2,
        _ => 1,
    }
}

/// The highest paranoia level present in the default catalog. Filtering is
/// a no-op at (or above) this level, so the common configuration (level 2)
/// skips the retain pass entirely.
pub const MAX_CATALOG_PARANOIA_LEVEL: u8 = 2;

/// Default OWASP CRS-compatible ruleset
pub fn default_ruleset() -> Vec<WafRule> {
    vec![
        // SQL Injection rules
        WafRule {
            id: 942100,
            description: "SQL tautology (1=1, 'a'='a')".into(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 942200,
            description: "UNION-based SQL injection".into(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 942300,
            description: "Stacked SQL queries".into(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 942400,
            description: "SQL comment-based evasion".into(),
            category: RuleCategory::SqlInjection,
            severity: 3,
            paranoia_level: 2,
            enabled: true,
        },
        WafRule {
            id: 942500,
            description: "Blind/time-based SQL injection".into(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 942600,
            description: "SQL string termination with logic".into(),
            category: RuleCategory::SqlInjection,
            severity: 4,
            paranoia_level: 2,
            enabled: true,
        },
        WafRule {
            id: 942700,
            description: "Dangerous SQL functions".into(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        // XSS rules
        WafRule {
            id: 941100,
            description: "Script tag injection".into(),
            category: RuleCategory::Xss,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 941200,
            description: "Event handler attribute injection".into(),
            category: RuleCategory::Xss,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 941300,
            description: "JavaScript/VBScript URI scheme".into(),
            category: RuleCategory::Xss,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 941400,
            description: "Dangerous HTML tags (SVG, IFRAME)".into(),
            category: RuleCategory::Xss,
            severity: 4,
            paranoia_level: 2,
            enabled: true,
        },
        WafRule {
            id: 941500,
            description: "CSS expression injection".into(),
            category: RuleCategory::Xss,
            severity: 4,
            paranoia_level: 2,
            enabled: true,
        },
        // Path Traversal rules
        WafRule {
            id: 930100,
            description: "Directory traversal sequences".into(),
            category: RuleCategory::PathTraversal,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 930200,
            description: "Sensitive file access attempt".into(),
            category: RuleCategory::PathTraversal,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        // Command Injection rules
        WafRule {
            id: 932100,
            description: "Shell command with metacharacter chaining".into(),
            category: RuleCategory::CommandInjection,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 932200,
            description: "Backtick command substitution".into(),
            category: RuleCategory::CommandInjection,
            severity: 4,
            paranoia_level: 2,
            enabled: true,
        },
        // Protocol violation rules
        WafRule {
            id: 911100,
            description: "Invalid HTTP method".into(),
            category: RuleCategory::ProtocolViolation,
            severity: 3,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 911200,
            description: "TRACE method (XST risk)".into(),
            category: RuleCategory::ProtocolViolation,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 920200,
            description: "Missing Host header".into(),
            category: RuleCategory::ProtocolViolation,
            severity: 3,
            paranoia_level: 1,
            enabled: true,
        },
        WafRule {
            id: 920300,
            description: "Missing Content-Type for body".into(),
            category: RuleCategory::ProtocolViolation,
            severity: 2,
            paranoia_level: 2,
            enabled: true,
        },
        WafRule {
            id: 920400,
            description: "Null byte in URL".into(),
            category: RuleCategory::RequestAnomaly,
            severity: 5,
            paranoia_level: 1,
            enabled: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_paranoia_table_matches_catalog() {
        for rule in default_ruleset() {
            assert_eq!(
                rule_paranoia_level(rule.id),
                rule.paranoia_level,
                "rule {} catalog level {} must match rule_paranoia_level()",
                rule.id,
                rule.paranoia_level
            );
            assert!(rule.paranoia_level <= MAX_CATALOG_PARANOIA_LEVEL);
        }
    }

    #[test]
    fn test_uncatalogued_rules_default_to_level_1() {
        // Rules emitted by analyzers but absent from the catalog (e.g.
        // 932050, 934300, 944110) must stay active at every level.
        assert_eq!(rule_paranoia_level(932050), 1);
        assert_eq!(rule_paranoia_level(934300), 1);
        assert_eq!(rule_paranoia_level(999999), 1);
    }
}
