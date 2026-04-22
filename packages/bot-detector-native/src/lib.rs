//! bot-detector-native – Native Node.js bindings for ApexMail bot detection.
//!
//! Uses Aho-Corasick automaton for O(n) user-agent pattern matching.
//! Pre-loaded with 70+ known bot/crawler/scanner patterns across
//! search engines, social crawlers, email gateways, automation tools,
//! and security scanners.

#![deny(clippy::unwrap_used)]
#![allow(clippy::needless_pass_by_value)]

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::{OnceLock, RwLock};

// ─── Pattern Database ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct PatternEntry {
    pattern: String,
    category: String,
    label: String,
}

const BUILTIN_PATTERNS: &[(&str, &str, &str)] = &[
    // Search engine bots
    ("googlebot", "search_engine", "bot:google"),
    ("google-inspectiontool", "search_engine", "bot:google"),
    ("bingbot", "search_engine", "bot:bing"),
    ("msnbot", "search_engine", "bot:bing"),
    ("yandexbot", "search_engine", "bot:yandex"),
    ("baiduspider", "search_engine", "bot:baidu"),
    ("duckduckbot", "search_engine", "bot:duckduckgo"),
    ("slurp", "search_engine", "bot:yahoo"),
    // Social crawlers
    ("facebookexternalhit", "social_crawler", "crawler:facebook"),
    ("twitterbot", "social_crawler", "crawler:twitter"),
    ("linkedinbot", "social_crawler", "crawler:linkedin"),
    ("whatsapp", "social_crawler", "crawler:whatsapp"),
    ("telegrambot", "social_crawler", "crawler:telegram"),
    ("slackbot", "social_crawler", "crawler:slack"),
    ("discordbot", "social_crawler", "crawler:discord"),
    ("pinterestbot", "social_crawler", "crawler:pinterest"),
    // Email gateways
    ("barracuda", "email_gateway", "gateway:barracuda"),
    ("mimecast", "email_gateway", "gateway:mimecast"),
    ("proofpoint", "email_gateway", "gateway:proofpoint"),
    ("ironport", "email_gateway", "gateway:ironport"),
    ("messagelabs", "email_gateway", "gateway:messagelabs"),
    ("forcepoint", "email_gateway", "gateway:forcepoint"),
    ("sophos", "email_gateway", "gateway:sophos"),
    ("spamhaus", "email_gateway", "gateway:spamhaus"),
    // Automation / CLI tools
    ("curl/", "automation", "tool:curl"),
    ("wget/", "automation", "tool:wget"),
    ("python-requests", "automation", "tool:python"),
    ("python-urllib", "automation", "tool:python"),
    ("httpx", "automation", "tool:httpx"),
    ("go-http-client", "automation", "tool:go"),
    ("java/", "automation", "tool:java"),
    ("okhttp/", "automation", "tool:okhttp"),
    ("node-fetch", "automation", "tool:node"),
    ("axios/", "automation", "tool:axios"),
    ("scrapy", "automation", "tool:scrapy"),
    ("phantomjs", "automation", "tool:phantomjs"),
    ("headless", "automation", "tool:headless"),
    ("selenium", "automation", "tool:selenium"),
    ("puppeteer", "automation", "tool:puppeteer"),
    ("playwright", "automation", "tool:playwright"),
    // Preview services
    ("embedly", "preview", "preview:embedly"),
    ("redditbot", "preview", "preview:reddit"),
    ("rogerbot", "preview", "preview:moz"),
    ("outbrain", "preview", "preview:outbrain"),
    // SEO tools
    ("semrush", "seo", "seo:semrush"),
    ("ahrefs", "seo", "seo:ahrefs"),
    ("majestic", "seo", "seo:majestic"),
    ("dotbot", "seo", "seo:moz"),
    // Monitoring
    ("uptimerobot", "monitoring", "monitor:uptimerobot"),
    ("pingdom", "monitoring", "monitor:pingdom"),
    ("site24x7", "monitoring", "monitor:site24x7"),
    ("newrelic", "monitoring", "monitor:newrelic"),
    ("datadog", "monitoring", "monitor:datadog"),
    // Security scanners
    ("nmap", "security_scanner", "scanner:nmap"),
    ("nikto", "security_scanner", "scanner:nikto"),
    ("sqlmap", "security_scanner", "scanner:sqlmap"),
    ("wpscan", "security_scanner", "scanner:wpscan"),
    ("nuclei", "security_scanner", "scanner:nuclei"),
    // Generic indicators
    ("bot/", "generic", "generic:bot"),
    ("spider/", "generic", "generic:spider"),
    ("crawler", "generic", "generic:crawler"),
];

struct PatternStore {
    patterns: Vec<PatternEntry>,
    automaton: Option<AhoCorasick>,
}

impl PatternStore {
    fn new(patterns: Vec<PatternEntry>) -> Result<Self> {
        let sources: Vec<&str> = patterns.iter().map(|p| p.pattern.as_str()).collect();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&sources)
            .map_err(|err| Error::from_reason(format!("Failed to build automaton: {err}")))?;
        Ok(Self {
            patterns,
            automaton: Some(automaton),
        })
    }
}

static PATTERN_STORE: OnceLock<RwLock<PatternStore>> = OnceLock::new();

fn load_builtin_patterns() -> Vec<PatternEntry> {
    BUILTIN_PATTERNS
        .iter()
        .map(|(pattern, category, label)| PatternEntry {
            pattern: (*pattern).to_string(),
            category: (*category).to_string(),
            label: (*label).to_string(),
        })
        .collect()
}

fn get_store() -> &'static RwLock<PatternStore> {
    PATTERN_STORE.get_or_init(|| {
        let store = PatternStore::new(load_builtin_patterns()).unwrap_or(PatternStore {
            patterns: Vec::new(),
            automaton: None,
        });
        RwLock::new(store)
    })
}

fn rebuild_store(patterns: Vec<PatternEntry>) -> Result<()> {
    let store = PatternStore::new(patterns)?;
    let Ok(mut guard) = get_store().write() else {
        return Err(Error::from_reason("Pattern store lock poisoned"));
    };
    *guard = store;
    Ok(())
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[napi(object)]
pub struct BotDetectionResult {
    pub is_bot: bool,
    pub user_agent: String,
    pub matches: Vec<BotMatch>,
    pub confidence: f64,
    pub category: Option<String>,
}

#[napi(object)]
pub struct BotMatch {
    pub pattern: String,
    pub label: String,
    pub category: String,
    pub position: u32,
}

#[napi(object)]
pub struct BotPatternInput {
    pub pattern: String,
    pub category: String,
    pub label: String,
}

#[napi(object)]
pub struct BatchBotResult {
    pub results: Vec<BotDetectionResult>,
    pub bot_count: u32,
    pub human_count: u32,
}

// ─── Exported Functions ───────────────────────────────────────────────────────

/// Detect whether a user-agent string is from a bot.
#[napi]
pub fn detect_bot(user_agent: String) -> BotDetectionResult {
    let store_guard = match get_store().read() {
        Ok(guard) => guard,
        Err(_) => {
            return BotDetectionResult {
                is_bot: false,
                user_agent,
                matches: vec![BotMatch {
                    pattern: "<lock-poisoned>".to_string(),
                    label: "internal:lock-poisoned".to_string(),
                    category: "internal_error".to_string(),
                    position: 0,
                }],
                confidence: 0.0,
                category: Some("internal_error".to_string()),
            };
        }
    };

    let ua_lower = user_agent.to_lowercase();

    let mut matches = Vec::new();

    if let Some(automaton) = &store_guard.automaton {
        for mat in automaton.find_iter(&ua_lower) {
            let idx = mat.pattern().as_usize();
            if idx < store_guard.patterns.len() {
                let entry = &store_guard.patterns[idx];
                matches.push(BotMatch {
                    pattern: entry.pattern.clone(),
                    label: entry.label.clone(),
                    category: entry.category.clone(),
                    position: mat.start() as u32,
                });
            }
        }
    }

    let is_bot = !matches.is_empty();
    let confidence = if matches.is_empty() {
        0.0
    } else if matches.len() == 1 {
        match matches[0].category.as_str() {
            "generic" => 0.6,
            "automation" => 0.7,
            "preview" => 0.75,
            _ => 0.85,
        }
    } else {
        (0.85 + (matches.len() as f64 - 1.0) * 0.05).min(0.99)
    };

    let category = matches.first().map(|m| m.category.clone());

    BotDetectionResult {
        is_bot,
        user_agent,
        matches,
        confidence,
        category,
    }
}

/// Batch detect bots from multiple user-agents.
#[napi]
pub fn detect_bots_batch(user_agents: Vec<String>) -> BatchBotResult {
    let results: Vec<BotDetectionResult> = user_agents.into_iter().map(detect_bot).collect();
    let bot_count = results.iter().filter(|r| r.is_bot).count() as u32;
    let human_count = results.len() as u32 - bot_count;
    BatchBotResult {
        results,
        bot_count,
        human_count,
    }
}

/// Check if a specific pattern is in the database.
#[napi]
pub fn is_known_bot_pattern(pattern: String) -> bool {
    let p = pattern.to_lowercase();
    let Ok(store) = get_store().read() else {
        return false;
    };
    store.patterns.iter().any(|entry| p.contains(&entry.pattern))
}

/// Get all known bot patterns grouped by category.
#[napi]
pub fn get_bot_patterns() -> std::collections::HashMap<String, Vec<String>> {
    let mut categories: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let Ok(store) = get_store().read() else {
        return categories;
    };
    for entry in store.patterns.iter() {
        categories
            .entry(entry.category.clone())
            .or_default()
            .push(entry.pattern.clone());
    }
    categories
}

/// Get the total number of known patterns.
#[napi]
pub fn pattern_count() -> u32 {
    let Ok(store) = get_store().read() else {
        return 0;
    };
    store.patterns.len() as u32
}

/// Get categories and their pattern counts.
#[napi]
pub fn get_categories() -> String {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let Ok(store) = get_store().read() else {
        return "{}".to_string();
    };
    for entry in store.patterns.iter() {
        *counts.entry(entry.category.as_str()).or_default() += 1;
    }
    serde_json::to_string(&counts).unwrap_or_else(|_| "{}".to_string())
}

/// Pre-warm the automaton to avoid first-call latency spikes.
#[napi]
pub fn warmup() -> bool {
    let _ = get_store();
    true
}

/// Replace or extend the pattern database at runtime.
#[napi]
pub fn set_custom_patterns(patterns: Vec<BotPatternInput>, replace: bool) -> Result<u32> {
    let mut merged = if replace {
        Vec::new()
    } else {
        load_builtin_patterns()
    };

    for entry in patterns {
        if entry.pattern.trim().is_empty() {
            continue;
        }
        merged.push(PatternEntry {
            pattern: entry.pattern.to_lowercase(),
            category: entry.category,
            label: entry.label,
        });
    }

    rebuild_store(merged.clone())?;
    Ok(merged.len() as u32)
}

#[napi::module_init]
fn module_init() {
    let _ = get_store();
}
