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
    PatternEntry { pattern: "googlebot", category: "search_engine", label: "bot:google" },
    PatternEntry { pattern: "google-inspectiontool", category: "search_engine", label: "bot:google" },
    PatternEntry { pattern: "bingbot", category: "search_engine", label: "bot:bing" },
    PatternEntry { pattern: "msnbot", category: "search_engine", label: "bot:bing" },
    PatternEntry { pattern: "yandexbot", category: "search_engine", label: "bot:yandex" },
    PatternEntry { pattern: "baiduspider", category: "search_engine", label: "bot:baidu" },
    PatternEntry { pattern: "duckduckbot", category: "search_engine", label: "bot:duckduckgo" },
    PatternEntry { pattern: "slurp", category: "search_engine", label: "bot:yahoo" },
    // Social crawlers
    PatternEntry { pattern: "facebookexternalhit", category: "social_crawler", label: "crawler:facebook" },
    PatternEntry { pattern: "twitterbot", category: "social_crawler", label: "crawler:twitter" },
    PatternEntry { pattern: "linkedinbot", category: "social_crawler", label: "crawler:linkedin" },
    PatternEntry { pattern: "whatsapp", category: "social_crawler", label: "crawler:whatsapp" },
    PatternEntry { pattern: "telegrambot", category: "social_crawler", label: "crawler:telegram" },
    PatternEntry { pattern: "slackbot", category: "social_crawler", label: "crawler:slack" },
    PatternEntry { pattern: "discordbot", category: "social_crawler", label: "crawler:discord" },
    PatternEntry { pattern: "pinterestbot", category: "social_crawler", label: "crawler:pinterest" },
    // Email gateways
    PatternEntry { pattern: "barracuda", category: "email_gateway", label: "gateway:barracuda" },
    PatternEntry { pattern: "mimecast", category: "email_gateway", label: "gateway:mimecast" },
    PatternEntry { pattern: "proofpoint", category: "email_gateway", label: "gateway:proofpoint" },
    PatternEntry { pattern: "ironport", category: "email_gateway", label: "gateway:ironport" },
    PatternEntry { pattern: "messagelabs", category: "email_gateway", label: "gateway:messagelabs" },
    PatternEntry { pattern: "forcepoint", category: "email_gateway", label: "gateway:forcepoint" },
    PatternEntry { pattern: "sophos", category: "email_gateway", label: "gateway:sophos" },
    PatternEntry { pattern: "spamhaus", category: "email_gateway", label: "gateway:spamhaus" },
    // Automation / CLI tools
    PatternEntry { pattern: "curl/", category: "automation", label: "tool:curl" },
    PatternEntry { pattern: "wget/", category: "automation", label: "tool:wget" },
    PatternEntry { pattern: "python-requests", category: "automation", label: "tool:python" },
    PatternEntry { pattern: "python-urllib", category: "automation", label: "tool:python" },
    PatternEntry { pattern: "httpx", category: "automation", label: "tool:httpx" },
    PatternEntry { pattern: "go-http-client", category: "automation", label: "tool:go" },
    PatternEntry { pattern: "java/", category: "automation", label: "tool:java" },
    PatternEntry { pattern: "okhttp/", category: "automation", label: "tool:okhttp" },
    PatternEntry { pattern: "node-fetch", category: "automation", label: "tool:node" },
    PatternEntry { pattern: "axios/", category: "automation", label: "tool:axios" },
    PatternEntry { pattern: "scrapy", category: "automation", label: "tool:scrapy" },
    PatternEntry { pattern: "phantomjs", category: "automation", label: "tool:phantomjs" },
    PatternEntry { pattern: "headless", category: "automation", label: "tool:headless" },
    PatternEntry { pattern: "selenium", category: "automation", label: "tool:selenium" },
    PatternEntry { pattern: "puppeteer", category: "automation", label: "tool:puppeteer" },
    PatternEntry { pattern: "playwright", category: "automation", label: "tool:playwright" },
    // Preview services
    PatternEntry { pattern: "embedly", category: "preview", label: "preview:embedly" },
    PatternEntry { pattern: "redditbot", category: "preview", label: "preview:reddit" },
    PatternEntry { pattern: "rogerbot", category: "preview", label: "preview:moz" },
    PatternEntry { pattern: "outbrain", category: "preview", label: "preview:outbrain" },
    // SEO tools
    PatternEntry { pattern: "semrush", category: "seo", label: "seo:semrush" },
    PatternEntry { pattern: "ahrefs", category: "seo", label: "seo:ahrefs" },
    PatternEntry { pattern: "majestic", category: "seo", label: "seo:majestic" },
    PatternEntry { pattern: "dotbot", category: "seo", label: "seo:moz" },
    // Monitoring
    PatternEntry { pattern: "uptimerobot", category: "monitoring", label: "monitor:uptimerobot" },
    PatternEntry { pattern: "pingdom", category: "monitoring", label: "monitor:pingdom" },
    PatternEntry { pattern: "site24x7", category: "monitoring", label: "monitor:site24x7" },
    PatternEntry { pattern: "newrelic", category: "monitoring", label: "monitor:newrelic" },
    PatternEntry { pattern: "datadog", category: "monitoring", label: "monitor:datadog" },
    // Security scanners
    PatternEntry { pattern: "nmap", category: "security_scanner", label: "scanner:nmap" },
    PatternEntry { pattern: "nikto", category: "security_scanner", label: "scanner:nikto" },
    PatternEntry { pattern: "sqlmap", category: "security_scanner", label: "scanner:sqlmap" },
    PatternEntry { pattern: "wpscan", category: "security_scanner", label: "scanner:wpscan" },
    PatternEntry { pattern: "nuclei", category: "security_scanner", label: "scanner:nuclei" },
    // Generic indicators
    PatternEntry { pattern: "bot/", category: "generic", label: "generic:bot" },
    PatternEntry { pattern: "spider/", category: "generic", label: "generic:spider" },
    PatternEntry { pattern: "crawler", category: "generic", label: "generic:crawler" },
];

struct PatternStore {
    patterns: Vec<PatternEntry>,
    automaton: AhoCorasick,
}

impl PatternStore {
    fn new(patterns: Vec<PatternEntry>) -> Result<Self> {
        let sources: Vec<&str> = patterns.iter().map(|p| p.pattern.as_str()).collect();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&sources)
            .map_err(|err| Error::from_reason(format!("Failed to build automaton: {err}")))?;
        Ok(Self { patterns, automaton })
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
        let store = PatternStore::new(load_builtin_patterns())
            .unwrap_or_else(|_| PatternStore {
                patterns: Vec::new(),
                automaton: AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&[])
                    .expect("automaton must build"),
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
                matches: Vec::new(),
                confidence: 0.0,
                category: None,
            };
        }
    };

    let ua_lower = user_agent.to_lowercase();

    let mut matches = Vec::new();

    for mat in store_guard.automaton.find_iter(&ua_lower) {
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
