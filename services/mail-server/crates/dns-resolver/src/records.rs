//! Parsed DNS record types for email infrastructure.

use serde::{Deserialize, Serialize};

/// Parsed MX record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MxRecord {
    /// Priority (lower = preferred).
    pub priority: u16,
    /// Mail exchange hostname.
    pub exchange: String,
}

impl MxRecord {
    pub fn new(priority: u16, exchange: impl Into<String>) -> Self {
        Self {
            priority,
            exchange: exchange.into(),
        }
    }
}

impl Ord for MxRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for MxRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Parsed SPF record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfRecord {
    /// Raw TXT record.
    pub raw: String,
    /// SPF version (typically "spf1").
    pub version: String,
    /// Mechanisms (e.g., "ip4:1.2.3.4", "include:example.com", "a", "mx").
    pub mechanisms: Vec<String>,
    /// Qualifier for the `all` mechanism (+, -, ~, ?).
    pub all_qualifier: Option<char>,
}

impl SpfRecord {
    /// Parse an SPF TXT record value.
    pub fn parse(txt: &str) -> Option<Self> {
        let txt = txt.trim();
        if !txt.starts_with("v=spf1") {
            return None;
        }

        let parts: Vec<&str> = txt.split_whitespace().collect();
        let version = "spf1".to_string();

        let mut mechanisms = Vec::with_capacity(parts.len().saturating_sub(1));
        let mut all_qualifier = None;

        for part in &parts[1..] {
            let part = part.to_lowercase();
            // #186: Only match bare `all` (optionally with qualifier prefix),
            // not `mx:all.example.com` etc.
            if part == "all" || part == "+all" || part == "-all" || part == "~all" || part == "?all" {
                all_qualifier = part.chars().next();
                if all_qualifier == Some('a') {
                    all_qualifier = Some('+'); // bare "all" = +all
                }
            }
            mechanisms.push(part);
        }

        Some(Self {
            raw: txt.to_string(),
            version,
            mechanisms,
            all_qualifier,
        })
    }

    /// Whether this SPF record has a hard fail (-all).
    pub fn is_hard_fail(&self) -> bool {
        self.all_qualifier == Some('-')
    }

    /// Whether this SPF record has a soft fail (~all).
    pub fn is_soft_fail(&self) -> bool {
        self.all_qualifier == Some('~')
    }
}

/// Parsed DKIM selector record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRecord {
    /// Raw TXT record.
    pub raw: String,
    /// DKIM version (should be "DKIM1").
    pub version: Option<String>,
    /// Key type (default: "rsa").
    pub key_type: String,
    /// Public key (base64).
    pub public_key: String,
    /// Hash algorithms.
    pub hash_algorithms: Vec<String>,
    /// Service type.
    pub service_type: Option<String>,
    /// Flags.
    pub flags: Vec<String>,
}

impl DkimRecord {
    /// Parse a DKIM TXT record value.
    pub fn parse(txt: &str) -> Option<Self> {
        let cleaned: String = txt.chars().filter(|c| *c != '"').collect();
        let parts: Vec<&str> = cleaned.split(';').map(|s| s.trim()).collect();

        let mut version = None;
        let mut key_type = "rsa".to_string();
        let mut public_key = String::new();
        let mut hash_algorithms = Vec::with_capacity(parts.len());
        let mut service_type = None;
        let mut flags = Vec::with_capacity(parts.len());

        for part in &parts {
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "v" => version = Some(v.to_string()),
                    "k" => key_type = v.to_string(),
                    "p" => public_key = v.replace(' ', ""),
                    "h" => {
                        hash_algorithms = v.split(':').map(|s| s.trim().to_string()).collect();
                    }
                    "s" => service_type = Some(v.to_string()),
                    "t" => flags = v.split(':').map(|s| s.trim().to_string()).collect(),
                    _ => {}
                }
            }
        }

        if public_key.is_empty() {
            return None;
        }

        Some(Self {
            raw: txt.to_string(),
            version,
            key_type,
            public_key,
            hash_algorithms,
            service_type,
            flags,
        })
    }

    /// Whether this is a revoked key (empty public key per RFC 6376 §3.6.1).
    /// Note: `t=y` means "testing mode" (RFC 6376 §3.6.1), NOT revocation.
    pub fn is_revoked(&self) -> bool {
        self.public_key.is_empty()
    }

    /// Whether this key is in testing mode (t=y flag present per RFC 6376 §3.6.1).
    pub fn is_testing(&self) -> bool {
        self.flags.contains(&"y".to_string())
    }
}

/// Parsed DMARC record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcPolicy {
    /// Raw TXT record.
    pub raw: String,
    /// Policy for the domain (none, quarantine, reject).
    pub policy: String,
    /// Subdomain policy (defaults to domain policy).
    pub subdomain_policy: Option<String>,
    /// Percentage of messages to apply policy to.
    pub pct: u8,
    /// Reporting URI for aggregate reports.
    pub rua: Vec<String>,
    /// Reporting URI for forensic reports.
    pub ruf: Vec<String>,
    /// DKIM alignment mode (r=relaxed, s=strict).
    pub adkim: char,
    /// SPF alignment mode.
    pub aspf: char,
}

impl DmarcPolicy {
    /// Parse a DMARC TXT record value.
    pub fn parse(txt: &str) -> Option<Self> {
        let txt = txt.trim();
        if !txt.starts_with("v=DMARC1") {
            return None;
        }

        let parts: Vec<&str> = txt.split(';').map(|s| s.trim()).collect();

        let mut policy = "none".to_string();
        let mut subdomain_policy = None;
        let mut pct = 100u8;
        let mut rua = Vec::with_capacity(parts.len());
        let mut ruf = Vec::with_capacity(parts.len());
        let mut adkim = 'r';
        let mut aspf = 'r';

        for part in &parts {
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "p" => policy = v.to_lowercase(),
                    "sp" => subdomain_policy = Some(v.to_lowercase()),
                    "pct" => pct = v.parse().unwrap_or(100),
                    "rua" => rua = v.split(',').map(|s| s.trim().to_string()).collect(),
                    "ruf" => ruf = v.split(',').map(|s| s.trim().to_string()).collect(),
                    "adkim" => adkim = v.chars().next().unwrap_or('r'),
                    "aspf" => aspf = v.chars().next().unwrap_or('r'),
                    _ => {}
                }
            }
        }

        Some(Self {
            raw: txt.to_string(),
            policy,
            subdomain_policy,
            pct,
            rua,
            ruf,
            adkim,
            aspf,
        })
    }

    /// Whether the policy is "reject".
    pub fn is_reject(&self) -> bool {
        self.policy == "reject"
    }

    /// Whether the policy is "quarantine".
    pub fn is_quarantine(&self) -> bool {
        self.policy == "quarantine"
    }

    /// Whether the policy is "none".
    pub fn is_none_policy(&self) -> bool {
        self.policy == "none"
    }

    /// Effective subdomain policy.
    pub fn effective_subdomain_policy(&self) -> &str {
        self.subdomain_policy.as_deref().unwrap_or(&self.policy)
    }
}

/// Parsed TLSA (DANE) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsaRecord {
    /// Certificate usage (0-3).
    pub usage: u8,
    /// Selector (0=full cert, 1=public key).
    pub selector: u8,
    /// Matching type (0=exact, 1=SHA-256, 2=SHA-512).
    pub matching_type: u8,
    /// Certificate association data (hex).
    pub data: String,
}

impl TlsaRecord {
    pub fn new(usage: u8, selector: u8, matching_type: u8, data: impl Into<String>) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            data: data.into(),
        }
    }

    /// Whether this is a DANE-TA(2) or DANE-EE(3) record.
    pub fn is_dane(&self) -> bool {
        self.usage == 2 || self.usage == 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MX ───────────────────────────────────────────────────────────

    #[test]
    fn test_mx_ordering() {
        let mut records = vec![
            MxRecord::new(20, "backup.example.com"),
            MxRecord::new(5, "primary.example.com"),
            MxRecord::new(10, "secondary.example.com"),
        ];
        records.sort();
        assert_eq!(records[0].priority, 5);
        assert_eq!(records[1].priority, 10);
        assert_eq!(records[2].priority, 20);
    }

    #[test]
    fn test_mx_equality() {
        let a = MxRecord::new(10, "mx.example.com");
        let b = MxRecord::new(10, "mx.example.com");
        assert_eq!(a, b);
    }

    // ── SPF ──────────────────────────────────────────────────────────

    #[test]
    fn test_spf_parse_basic() {
        let spf = SpfRecord::parse("v=spf1 include:_spf.google.com ~all");
        assert_eq!(spf.as_ref().map(|record| record.version.as_str()), Some("spf1"));
        assert!(spf
            .as_ref()
            .is_some_and(|record| record.mechanisms.contains(&"include:_spf.google.com".to_string())));
        assert!(spf.as_ref().is_some_and(SpfRecord::is_soft_fail));
        assert!(spf.as_ref().is_some_and(|record| !record.is_hard_fail()));
    }

    #[test]
    fn test_spf_parse_hard_fail() {
        let spf = SpfRecord::parse("v=spf1 ip4:192.168.1.0/24 -all");
        assert!(spf.as_ref().is_some_and(SpfRecord::is_hard_fail));
    }

    #[test]
    fn test_spf_parse_invalid() {
        assert!(SpfRecord::parse("not-an-spf-record").is_none());
    }

    // ── DKIM ─────────────────────────────────────────────────────────

    #[test]
    fn test_dkim_parse() {
        let dkim = DkimRecord::parse("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==");
        assert_eq!(dkim.as_ref().and_then(|record| record.version.clone()), Some("DKIM1".into()));
        assert_eq!(dkim.as_ref().map(|record| record.key_type.as_str()), Some("rsa"));
        assert!(dkim.as_ref().is_some_and(|record| !record.public_key.is_empty()));
        assert!(dkim.as_ref().is_some_and(|record| !record.is_revoked()));
    }

    #[test]
    fn test_dkim_parse_no_key() {
        assert!(DkimRecord::parse("v=DKIM1; k=rsa; p=").is_none());
    }

    #[test]
    fn test_dkim_revoked() {
        let mut dkim = DkimRecord::parse("v=DKIM1; k=rsa; t=y; p=AAAA");
        assert!(dkim.as_ref().is_some_and(|record| !record.is_revoked())); // t=y is testing mode, not revocation
        assert!(dkim.as_ref().is_some_and(DkimRecord::is_testing));
        if let Some(ref mut record) = dkim {
            record.flags.clear();
            record.public_key.clear();
        }
        assert!(dkim.as_ref().is_some_and(DkimRecord::is_revoked)); // empty key
    }

    // ── DMARC ────────────────────────────────────────────────────────

    #[test]
    fn test_dmarc_parse_reject() {
        let dmarc = DmarcPolicy::parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100");
        assert!(dmarc.as_ref().is_some_and(DmarcPolicy::is_reject));
        assert_eq!(dmarc.as_ref().map(|policy| policy.pct), Some(100));
        assert_eq!(
            dmarc.as_ref().map(|policy| policy.rua.clone()),
            Some(vec!["mailto:dmarc@example.com".to_string()])
        );
        assert_eq!(dmarc.as_ref().map(|policy| policy.adkim), Some('r'));
    }

    #[test]
    fn test_dmarc_parse_quarantine_with_subdomain() {
        let dmarc = DmarcPolicy::parse("v=DMARC1; p=quarantine; sp=reject; adkim=s");
        assert!(dmarc.as_ref().is_some_and(DmarcPolicy::is_quarantine));
        assert_eq!(
            dmarc.as_ref().map(|policy| policy.effective_subdomain_policy()),
            Some("reject")
        );
        assert_eq!(dmarc.as_ref().map(|policy| policy.adkim), Some('s'));
    }

    #[test]
    fn test_dmarc_parse_none() {
        let dmarc = DmarcPolicy::parse("v=DMARC1; p=none");
        assert!(dmarc.as_ref().is_some_and(DmarcPolicy::is_none_policy));
        assert_eq!(
            dmarc.as_ref().map(|policy| policy.effective_subdomain_policy()),
            Some("none")
        );
    }

    #[test]
    fn test_dmarc_parse_invalid() {
        assert!(DmarcPolicy::parse("not-a-dmarc-record").is_none());
    }

    // ── TLSA ─────────────────────────────────────────────────────────

    #[test]
    fn test_tlsa_dane() {
        let record = TlsaRecord::new(3, 1, 1, "abcdef0123456789");
        assert!(record.is_dane());
    }

    #[test]
    fn test_tlsa_not_dane() {
        let record = TlsaRecord::new(0, 0, 0, "data");
        assert!(!record.is_dane());
    }

    // ── Serialization ────────────────────────────────────────────────

    #[test]
    fn test_mx_serialization() {
        let mx = MxRecord::new(10, "mx.example.com");
        let json = serde_json::to_string(&mx);
        assert!(json.is_ok());
        let parsed: Result<MxRecord, _> = json
            .as_ref()
            .ok()
            .map(|value| serde_json::from_str(value))
            .unwrap_or_else(|| Err(serde_json::Error::io(std::io::Error::other("serialize failed"))));
        assert!(parsed.is_ok());
        if let Ok(record) = parsed {
            assert_eq!(record.priority, 10);
            assert_eq!(record.exchange, "mx.example.com");
        }
    }
}
