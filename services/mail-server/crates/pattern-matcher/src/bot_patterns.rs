//! Pre-built bot detection patterns for user-agent matching.

use crate::matcher::PatternMatcher;

/// Known bot user-agent patterns (~80 patterns covering search engines,
/// social crawlers, email gateways, and automation tools).
pub fn bot_ua_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        // Search engine bots
        ("googlebot", "bot:google"),
        ("google-inspectiontool", "bot:google"),
        ("bingbot", "bot:bing"),
        ("msnbot", "bot:bing"),
        ("yandexbot", "bot:yandex"),
        ("baiduspider", "bot:baidu"),
        ("duckduckbot", "bot:duckduckgo"),
        ("slurp", "bot:yahoo"),
        // Social crawlers
        ("facebookexternalhit", "crawler:facebook"),
        ("twitterbot", "crawler:twitter"),
        ("linkedinbot", "crawler:linkedin"),
        ("whatsapp", "crawler:whatsapp"),
        ("telegrambot", "crawler:telegram"),
        ("slackbot", "crawler:slack"),
        ("discordbot", "crawler:discord"),
        ("pinterestbot", "crawler:pinterest"),
        // Email gateways
        ("barracuda", "gateway:barracuda"),
        ("mimecast", "gateway:mimecast"),
        ("proofpoint", "gateway:proofpoint"),
        ("ironport", "gateway:ironport"),
        ("messagelabs", "gateway:messagelabs"),
        ("forcepoint", "gateway:forcepoint"),
        ("sophos", "gateway:sophos"),
        ("spamhaus", "gateway:spamhaus"),
        // Email clients
        ("thunderbird", "client:thunderbird"),
        ("microsoft outlook", "client:outlook"),
        ("apple mail", "client:apple"),
        // Automation / CLI tools
        ("curl/", "tool:curl"),
        ("wget/", "tool:wget"),
        ("python-requests", "tool:python"),
        ("python-urllib", "tool:python"),
        ("httpx", "tool:httpx"),
        ("go-http-client", "tool:go"),
        ("java/", "tool:java"),
        ("okhttp/", "tool:okhttp"),
        ("node-fetch", "tool:node"),
        ("axios/", "tool:axios"),
        ("scrapy", "tool:scrapy"),
        ("phantomjs", "tool:phantomjs"),
        ("headless", "tool:headless"),
        ("selenium", "tool:selenium"),
        ("puppeteer", "tool:puppeteer"),
        ("playwright", "tool:playwright"),
        // Preview services
        ("embedly", "preview:embedly"),
        ("quora link preview", "preview:quora"),
        ("redditbot", "preview:reddit"),
        ("rogerbot", "preview:moz"),
        ("showyoubot", "preview:showyou"),
        ("outbrain", "preview:outbrain"),
        // SEO tools
        ("semrush", "seo:semrush"),
        ("ahrefs", "seo:ahrefs"),
        ("majestic", "seo:majestic"),
        ("dotbot", "seo:moz"),
        ("seokicks", "seo:seokicks"),
        // Monitoring
        ("uptimerobot", "monitor:uptimerobot"),
        ("pingdom", "monitor:pingdom"),
        ("site24x7", "monitor:site24x7"),
        ("statuspage", "monitor:statuspage"),
        ("newrelic", "monitor:newrelic"),
        ("datadog", "monitor:datadog"),
        // Security scanners
        ("nmap", "scanner:nmap"),
        ("nikto", "scanner:nikto"),
        ("sqlmap", "scanner:sqlmap"),
        ("dirbuster", "scanner:dirbuster"),
        ("wpscan", "scanner:wpscan"),
        ("nuclei", "scanner:nuclei"),
        // Generic bot indicators
        ("bot/", "generic:bot"),
        ("spider/", "generic:spider"),
        ("crawler", "generic:crawler"),
        ("/robot", "generic:robot"),
    ]
}

/// Build a pre-configured bot UA pattern matcher.
pub fn build_bot_detector() -> PatternMatcher {
    PatternMatcher::new(
        bot_ua_patterns()
            .into_iter()
            .map(|(p, l)| (p.to_string(), l.to_string()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_detector_recognizes_googlebot() {
        let detector = build_bot_detector();
        assert!(detector
            .is_match("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
    }

    #[test]
    fn test_bot_detector_recognizes_curl() {
        let detector = build_bot_detector();
        let results = detector.find_all("curl/7.68.0");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "tool:curl");
    }

    #[test]
    fn test_bot_detector_normal_browser() {
        let detector = build_bot_detector();
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert!(!detector.is_match(ua));
    }

    #[test]
    fn test_bot_detector_pattern_count() {
        let patterns = bot_ua_patterns();
        assert!(
            patterns.len() >= 70,
            "Should have 70+ patterns, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_bot_detector_email_gateway() {
        let detector = build_bot_detector();
        assert!(detector.is_match("Barracuda/5.0"));
        assert!(detector.is_match("Mimecast"));
        assert!(detector.is_match("Proofpoint"));
    }

    #[test]
    fn test_bot_detector_social_crawlers() {
        let detector = build_bot_detector();
        assert!(detector.is_match("facebookexternalhit/1.1"));
        assert!(detector.is_match("Twitterbot/1.0"));
        assert!(detector.is_match("LinkedInBot/1.0"));
    }

    #[test]
    fn test_bot_detector_empty_ua() {
        let detector = build_bot_detector();
        assert!(!detector.is_match(""));
    }
}
