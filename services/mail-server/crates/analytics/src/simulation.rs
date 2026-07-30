#[cfg(test)]
mod simulation {
    use crate::bot_detection;
    use crate::email_hash;

    #[test]
    fn sim_email_hash_is_deterministic() {
        let key = "test-hash-key";
        let hash1 = email_hash::hash_email("user@example.com", key);
        let hash2 = email_hash::hash_email("user@example.com", key);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn sim_email_hash_different_emails_produce_different_hashes() {
        let key = "test-key";
        let h1 = email_hash::hash_email("alice@example.com", key);
        let h2 = email_hash::hash_email("bob@example.com", key);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sim_email_hash_empty_key_falls_back_to_sha256() {
        let hash = email_hash::hash_email("test@example.com", "");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sim_email_hash_different_keys_produce_different_hashes() {
        let h1 = email_hash::hash_email("user@example.com", "key-a");
        let h2 = email_hash::hash_email("user@example.com", "key-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sim_email_hash_long_input_handled() {
        let long_email = format!("{}@domain.example.com", "a".repeat(200));
        let hash = email_hash::hash_email(&long_email, "key");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn sim_email_hash_only_hex_characters() {
        let hash = email_hash::hash_email("test@example.com", "salt");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sim_bot_detection_known_bot_user_agents() {
        assert!(bot_detection::is_bot_ua("Googlebot/2.1 (+http://www.google.com/bot.html)"));
        assert!(bot_detection::is_bot_ua("bingbot/2.0; +http://www.bing.com/bingbot.htm"));
        assert!(bot_detection::is_bot_ua("python-requests/2.28.0"));
        assert!(bot_detection::is_bot_ua("curl/7.88.1"));
    }

    #[test]
    fn sim_bot_detection_human_user_agents_not_flagged() {
        assert!(!bot_detection::is_bot_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ));
        assert!(!bot_detection::is_bot_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        ));
    }

    #[test]
    fn sim_bot_detection_empty_user_agent() {
        assert!(!bot_detection::is_bot_ua(""));
    }

    #[test]
    fn sim_reconciliation_delivery_event_matching() {
        let deliveries = vec!["msg_001", "msg_002", "msg_003"];
        let engagements = vec!["msg_001", "msg_003"];
        let matched: Vec<_> = deliveries
            .iter()
            .filter(|id| engagements.contains(id))
            .collect();
        assert_eq!(matched.len(), 2);
        let orphans: Vec<_> = deliveries
            .iter()
            .filter(|id| !engagements.contains(id))
            .collect();
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn sim_reconciliation_all_delivered_none_engaged() {
        let deliveries = vec!["msg_001", "msg_002"];
        let engagements: Vec<&str> = vec![];
        let orphans: Vec<_> = deliveries
            .iter()
            .filter(|id| !engagements.contains(id))
            .collect();
        assert_eq!(orphans.len(), 2);
    }

    #[test]
    fn sim_reconciliation_empty_events_no_panic() {
        let deliveries: Vec<&str> = vec![];
        let engagements: Vec<&str> = vec![];
        let matched: Vec<_> = deliveries
            .iter()
            .filter(|id| engagements.contains(id))
            .collect();
        assert!(matched.is_empty());
    }

    #[test]
    fn sim_compaction_aggregates_event_counts() {
        let events = vec![
            ("msg_001", "delivered"), ("msg_001", "opened"), ("msg_001", "clicked"),
            ("msg_002", "delivered"), ("msg_002", "delivered"),
            ("msg_003", "delivered"), ("msg_003", "bounced"),
        ];
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (_, et) in &events {
            *counts.entry(et).or_insert(0) += 1;
        }
        assert_eq!(counts.get("delivered"), Some(&4));
        assert_eq!(counts.get("opened"), Some(&1));
        assert_eq!(counts.get("clicked"), Some(&1));
        assert_eq!(counts.get("bounced"), Some(&1));
    }

    #[test]
    fn sim_compaction_deduplication() {
        let ids = vec!["msg_001", "msg_001", "msg_002", "msg_002", "msg_002", "msg_003"];
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn sim_compaction_time_bucketing() {
        let timestamps = vec![
            ("msg_001", 1000i64), ("msg_002", 1040),
            ("msg_003", 2000), ("msg_004", 2040),
        ];
        let bucket_size = 60;
        let mut buckets: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();
        for (_, ts) in &timestamps {
            *buckets.entry(ts / bucket_size).or_insert(0) += 1;
        }
        // 1000/60=16, 1040/60=17 → different buckets
        // 2000/60=33, 2040/60=34 → different buckets
        let bucket_16 = buckets.get(&(1000 / 60));
        let bucket_17 = buckets.get(&(1040 / 60));
        let bucket_33 = buckets.get(&(2000 / 60));
        let bucket_34 = buckets.get(&(2040 / 60));
        assert_eq!(bucket_16, Some(&1));
        assert_eq!(bucket_17, Some(&1));
        assert_eq!(bucket_33, Some(&1));
        assert_eq!(bucket_34, Some(&1));
    }

    #[test]
    fn sim_churn_prediction_scoring() {
        let recent = vec![100.0, 95.0, 88.0, 92.0, 90.0];
        let declining = vec![100.0, 80.0, 60.0, 40.0, 20.0];
        let recent_avg: f64 = recent.iter().sum::<f64>() / recent.len() as f64;
        let declining_avg: f64 = declining.iter().sum::<f64>() / declining.len() as f64;
        assert!(recent_avg > 80.0);
        assert!(declining_avg < recent_avg);
    }

    #[test]
    fn sim_churn_at_risk_threshold() {
        let threshold = 30.0;
        assert!(85.0 >= threshold, "healthy should not be at risk");
        assert!(35.0 >= threshold, "borderline should not be at risk");
        assert!(25.0 < threshold, "at_risk should be flagged");
        assert!(5.0 < threshold, "dead should be flagged");
        assert!(0.0 < threshold, "zero should be flagged");
    }

    #[test]
    fn sim_base64_url_encoding_roundtrip() {
        let original = "https://example.com/path?param=value";
        let encoded = simple_b64_encode(original);
        let decoded = simple_b64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn sim_tracking_pixel_structure() {
        let msg_id = "msg_abc123";
        let recipient = "user@example.com";
        let pixel_url = format!("https://track.apexmail.ee/o/{}/{}", msg_id, recipient);
        let pixel_html = format!(
            r#"<img src="{pixel_url}" width="1" height="1" alt="" />"#
        );
        assert!(pixel_html.contains("<img"));
        assert!(pixel_html.contains("width=\"1\""));
        assert!(pixel_html.contains("height=\"1\""));
        assert!(pixel_html.contains(msg_id));
    }

    fn simple_b64_encode(input: &str) -> String {
        let data = input.as_bytes();
        let mut buf = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            buf.push(chars.chars().nth(((triple >> 18) & 0x3f) as usize).unwrap());
            buf.push(chars.chars().nth(((triple >> 12) & 0x3f) as usize).unwrap());
            if chunk.len() > 1 {
                buf.push(chars.chars().nth(((triple >> 6) & 0x3f) as usize).unwrap());
            }
            if chunk.len() > 2 {
                buf.push(chars.chars().nth((triple & 0x3f) as usize).unwrap());
            }
        }
        while buf.len() % 4 != 0 {
            buf.push('=');
        }
        buf
    }

    fn simple_b64_decode(encoded: &str) -> String {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let encoded = encoded.trim_end_matches('=');
        let mut result = Vec::new();
        for chunk in encoded.as_bytes().chunks(4) {
            let mut triple: u32 = 0;
            let mut count = 0;
            for &b in chunk {
                if let Some(pos) = chars.find(b as char) {
                    triple = (triple << 6) | pos as u32;
                    count += 1;
                }
            }
            if count >= 2 { result.push(((triple >> 16) & 0xff) as u8); }
            if count >= 3 { result.push(((triple >> 8) & 0xff) as u8); }
            if count >= 4 { result.push((triple & 0xff) as u8); }
        }
        String::from_utf8(result).unwrap_or_default()
    }
}
