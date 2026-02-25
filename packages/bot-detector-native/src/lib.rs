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
use std::sync::OnceLock;

// ─── Pattern Database ─────────────────────────────────────────────────────────

struct PatternEntry {
    pattern: &'static str,
    category: &'static str,
    label: &'static str,
}

const PATTERNS: &[PatternEntry] = &[
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

static AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();

fn get_automaton() -> &'static AhoCorasick {
    AUTOMATON.get_or_init(|| {
        let patterns: Vec<&str> = PATTERNS.iter().map(|p| p.pattern).collect();
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("automaton must build")
    })
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
pub struct BatchBotResult {
    pub results: Vec<BotDetectionResult>,
    pub bot_count: u32,
    pub human_count: u32,
}

// ─── Exported Functions ───────────────────────────────────────────────────────

/// Detect whether a user-agent string is from a bot.
#[napi]
pub fn detect_bot(user_agent: String) -> BotDetectionResult {
    let automaton = get_automaton();
    let ua_lower = user_agent.to_lowercase();

    let mut matches = Vec::new();

    for mat in automaton.find_iter(&ua_lower) {
        let idx = mat.pattern().as_usize();
        if idx < PATTERNS.len() {
            let entry = &PATTERNS[idx];
            matches.push(BotMatch {
                pattern: entry.pattern.to_string(),
                label: entry.label.to_string(),
                category: entry.category.to_string(),
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
    PATTERNS.iter().any(|entry| p.contains(entry.pattern))
}

/// Get all known bot patterns grouped by category.
#[napi]
pub fn get_bot_patterns() -> std::collections::HashMap<String, Vec<String>> {
    let mut categories: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for entry in PATTERNS {
        categories
            .entry(entry.category.to_string())
            .or_default()
            .push(entry.pattern.to_string());
    }
    categories
}

/// Get the total number of known patterns.
#[napi]
pub fn pattern_count() -> u32 {
    PATTERNS.len() as u32
}

/// Get categories and their pattern counts.
#[napi]
pub fn get_categories() -> String {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for entry in PATTERNS {
        *counts.entry(entry.category).or_default() += 1;
    }
    serde_json::to_string(&counts).unwrap_or_else(|_| "{}".to_string())
}
