//! Bot and security-scanner detection for tracking requests.
//!
//! Uses AhoCorasick for O(n) substring matching — no backtracking possible,
//! immune to ReDoS attacks regardless of User-Agent content.
//!
//! IP-range checks use exact CIDR matching via `ipnetwork`, also O(1) per range.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

/// Known bot User-Agent substrings (case-folded before matching).
/// ORDER MATTERS:keep dense, well-known prefixes first for early exit in
/// the AhoCorasick automaton (the `LeftmostFirst` semantics find the leftmost
/// longest match, but for a pure `is_bot` predicate any match suffices).
/// Patterns replicate *exactly* the combined regex in `routes.ts`:/// GoogleImageProxy | YahooMailProxy | Barracuda | Mimecast | FireEye |
/// ProofPoint | Symantec | MessageLabs | Trend Micro | Sophos |
/// \bbot\b | \bcrawler\b | \bscanner\b | \bspider\b | \bprefetch\b |
/// link preview | Microsoft Office | ms-office
/// … plus all entries from `analytics/src/bot-detection.ts`'s
/// `BOT_USER_AGENT_PATTERNS` array.
/// Word-boundary patterns (\bbot\b etc.) are approximated with the shortest
/// unambiguous substring that avoids common false positives.
static BOT_UA_PATTERNS: &[&str] = &[
// Email security gateways
    "googleimageproxy",
    "yahooimageproxy",
    "yahooproxy",
    "yahoomailproxy",
    "barracuda",
    "mimecast",
    "fireeye",
    "proofpoint",
    "symantec",
    "messagelabs",
    "trendmicro",
    "trend micro",
    "sophos",
    "cisco",
    "ironport",
    "forcepoint",
    "websense",
    "mcafee",
    "zscaler",
// Social link-preview crawlers
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "slackbot",
    "telegrambot",
    "whatsapp",
    "discord",
// Generic bot indicators (word-boundary safe substrings)
    " bot ",
    " bot/",
    "(bot)",
    " bot;",
    "crawler",
    "scanner",
    " spider",
    "(spider",
    "spider/",
    "scraper",
    "prefetch",
    "link preview",
    "microsoft office",
    "ms-office",
// Automation tools / headless browsers
    "headlesschrome",
    "headless",
    "phantom",
    "selenium",
    "puppeteer",
    "node-fetch",
    "python-requests",
    "python/",
    "go-http-client",
// wget / curl (word-boundary safe)
    "wget/",
    " wget ",
    "curl/",
    " curl ",
    "axios/",
    "axios ",
// Minimal / clearly non-browser UA (single token)
    "httpie",
    "java/",
    "ruby",
    "perl",
    "libwww",
];

/// Known security-gateway IP ranges (CIDR notation).
/// This list covers the same ranges referenced in `bot-detection.ts`'s
/// `KNOWN_BOT_IP_PATTERNS` plus additional Barracuda, Mimecast, Proofpoint
/// and Microsoft Defender ranges published in their respective IP disclosures.
static BOT_IP_CIDRS: &[&str] = &[
// Barracuda Networks
    "64.235.144.0/20",
    "64.235.160.0/19",
// Mimecast
    "91.220.42.0/24",
    "195.130.217.0/24",
    "207.211.30.0/24",
    "207.211.31.0/24",
// Proofpoint (67.231.144-159.*)
    "67.231.144.0/20",
// Microsoft Defender for Office 365 / EOP scanning
    "40.94.0.0/16",
    "52.100.0.0/14",
// Google image proxy
    "66.102.0.0/20",
    "209.85.128.0/17",
// Yahoo Mail Proxy
    "98.137.64.0/18",
];

/// Pre-compiled bot-detector state, constructed once at startup.
pub struct BotDetector {
    ua_ac: Option<AhoCorasick>,
    ip_ranges: Vec<IpNetwork>,
}

impl BotDetector {
/// Build the detector. This is the only expensive operation; call once
/// and share the result behind an `Arc`.
    pub fn new() -> Self {
        let ua_ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(BOT_UA_PATTERNS)
            .ok();

        let ip_ranges = BOT_IP_CIDRS
            .iter()
            .filter_map(|s| IpNetwork::from_str(s).ok())
            .collect();

        Self { ua_ac, ip_ranges }
    }

/// Returns `true` if `user_agent` matches any known bot pattern.
/// The match is O(len(user_agent)) regardless of pattern count —
/// AhoCorasick visits each byte exactly once.
    pub fn is_bot_ua(&self, user_agent: Option<&str>) -> bool {
        match user_agent {
            None | Some("") => false,
            Some(ua) => {
// Reject obviously minimal / curl-like UAs that might not
// be caught by substring matching alone.
                if ua.len() < 8 {
                    return true;
                }
                self.ua_ac.as_ref().map(|ac| ac.is_match(ua)).unwrap_or(false)
            }
        }
    }

/// Returns `true` if `ip` falls within any known bot CIDR range.
/// If the address is an IPv4-mapped IPv6 (::ffff:a.b.c.d), it is
/// unwrapped to the bare IPv4 before the CIDR check.
    pub fn is_bot_ip(&self, ip: &str) -> bool {
// Strip IPv4-mapped IPv6 prefix
        let bare = if let Some(stripped) = ip.strip_prefix("::ffff:") {
            stripped
        } else {
            ip
        };

        let addr = match IpAddr::from_str(bare) {
            Ok(a) => a,
            Err(_) => return false,
        };

        self.ip_ranges.iter().any(|net| net.contains(addr))
    }

/// Combined check:returns `true` if either the UA or IP is a known bot.
    pub fn is_bot(&self, user_agent: Option<&str>, ip: Option<&str>) -> bool {
        self.is_bot_ua(user_agent) || ip.map(|i| self.is_bot_ip(i)).unwrap_or(false)
    }
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> BotDetector {
        BotDetector::new()
    }

    #[test]
    fn known_security_gateways_detected() {
        let d = detector();
        for ua in &[
            "Barracuda Email Security Gateway/3.1",
            "Proofpoint Email Security Scanner",
            "Mimecast Proxy/1.0",
            "FireEye MPS Crawler",
            "Sophos Email Scanner 2.0",
            "Symantec Email Threat Isolation",
        ] {
            assert!(d.is_bot_ua(Some(ua)), "expected bot: {ua}");
        }
    }

    #[test]
    fn social_link_preview_detected() {
        let d = detector();
        for ua in &[
            "facebookexternalhit/1.1",
            "Twitterbot/1.0",
            "LinkedInBot/1.0 +http://www.linkedin.com/",
            "Slackbot-LinkExpanding 1.0",
        ] {
            assert!(d.is_bot_ua(Some(ua)), "expected bot: {ua}");
        }
    }

    #[test]
    fn real_browser_not_detected() {
        let d = detector();
        for ua in &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
            "Outlook/16.0 (Office 365)", // NOTE:"Microsoft Office" in UA would be a bot
        ] {
            assert!(!d.is_bot_ua(Some(ua)), "expected human: {ua}");
        }
    }

    #[test]
    fn none_ua_is_not_bot() {
        let d = detector();
        assert!(!d.is_bot_ua(None));
    }

    #[test]
    fn known_bot_ip_detected() {
        let d = detector();
// Barracuda range 64.235.144.0/20
        assert!(d.is_bot_ip("64.235.150.1"));
// Mimecast
        assert!(d.is_bot_ip("91.220.42.100"));
// Proofpoint
        assert!(d.is_bot_ip("67.231.150.5"));
    }

    #[test]
    fn normal_ip_not_detected() {
        let d = detector();
        assert!(!d.is_bot_ip("1.2.3.4"));
        assert!(!d.is_bot_ip("192.168.1.100")); // Private but not in bot ranges
    }

    #[test]
    fn ipv4_mapped_ipv6_unwrapped() {
        let d = detector();
// 64.235.150.1 mapped as ::ffff:64.235.150.1 should still be detected
        assert!(d.is_bot_ip("::ffff:64.235.150.1"));
    }
}
