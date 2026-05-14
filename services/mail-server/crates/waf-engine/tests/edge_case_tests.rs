//! Edge-case and adversarial tests for WAF engine
//!
//! These tests are designed to catch bugs, not confirm happy paths.
//! They target boundary conditions, encoding edge cases, and bypass attempts.

use waf_engine::fast_path::fast_path_check;
use waf_engine::json_graphql::{extract_graphql_values, extract_json_values};

mod fast_path_edge_cases {
    use super::*;

    /// Empty input should pass fast-path without panic
    #[test]
    fn test_empty_input() {
        let result = fast_path_check("");
        assert!(!result.has_sqli_patterns);
        assert!(!result.has_xss_patterns);
        assert!(!result.has_cmdi_patterns);
    }

    /// Very long input should not cause stack overflow or OOM
    #[test]
    fn test_very_long_input() {
        // 10MB of clean input
        let input = "a".repeat(10_000_000);
        let result = fast_path_check(&input);
        assert!(!result.has_sqli_patterns);
    }

    /// Unicode that looks like ASCII keywords
    #[test]
    fn test_unicode_look_alikes() {
        // Using look-alike Unicode chars (confusables)
        // "SELECT" using Cyrillic 'Ѕ' (U+0405) and 'Е' (U+0415)
        let fake_select = "ЅЕLЕCT * FROM users";
        let result = fast_path_check(fake_select);
        // Should NOT detect because we use ASCII case-insensitive matching
        assert!(!result.has_sqli_patterns);
    }

    /// Null bytes in input
    #[test]
    fn test_null_bytes() {
        let input = "safe\x00SELECT * FROM users";
        let result = fast_path_check(input);
        // Should still detect after null byte
        assert!(result.has_sqli_patterns);
    }

    /// Input with only whitespace
    #[test]
    fn test_whitespace_only() {
        let result = fast_path_check("   \t\n\r   ");
        assert!(!result.has_sqli_patterns);
    }

    /// Mixed case with unusual capitalization
    #[test]
    fn test_alternating_case() {
        let result = fast_path_check("sElEcT * fRoM users");
        // Should detect due to case-insensitive matching
        assert!(result.has_sqli_patterns);
    }

    /// Keywords split across lines
    #[test]
    fn test_newline_split() {
        let input = "sel\nect * from users";
        let result = fast_path_check(input);
        // Newline breaks "select", and "from" alone is too common to be in patterns
        // This should NOT match since neither "select" nor "from" is in patterns
        // as separate common words are excluded to reduce false positives
        assert!(!result.has_sqli_patterns);
    }

    /// Tab characters in keywords
    #[test]
    fn test_tab_in_keyword() {
        let input = "uni\ton from x";
        let result = fast_path_check(input);
        // "union" is split by tab, shouldn't match
        // "from" alone is not in patterns (too common as English word)
        assert!(!result.has_sqli_patterns);
    }
}

mod json_edge_cases {
    use super::*;

    /// Empty JSON object
    #[test]
    fn test_empty_object() {
        let result = extract_json_values("{}");
        assert!(result.parsed_ok);
        assert!(result.string_values.is_empty());
    }

    /// Empty JSON array
    #[test]
    fn test_empty_array() {
        let result = extract_json_values("[]");
        assert!(result.parsed_ok);
        assert!(result.string_values.is_empty());
    }

    /// Invalid JSON should gracefully fail
    #[test]
    fn test_invalid_json() {
        let result = extract_json_values("{not valid json");
        assert!(!result.parsed_ok);
        assert!(result.error.is_some());
    }

    /// Truncated JSON
    #[test]
    fn test_truncated_json() {
        let result = extract_json_values("{\"key\": \"val");
        assert!(!result.parsed_ok);
    }

    /// Very deeply nested JSON (potential stack overflow)
    #[test]
    fn test_deeply_nested_json() {
        // 1000 levels of nesting - should be rejected to prevent DoS
        let mut json = String::new();
        for _ in 0..1000 {
            json.push_str("{\"a\":");
        }
        json.push_str("\"value\"");
        for _ in 0..1000 {
            json.push('}');
        }
        let result = extract_json_values(&json);
        // Should fail with depth limit error, not stack overflow
        assert!(!result.parsed_ok);
        assert!(result
            .error
            .as_ref()
            .map(|e| e.contains("depth"))
            .unwrap_or(false));
    }

    /// JSON with all types
    #[test]
    fn test_mixed_types() {
        let json = r#"{
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": true,
            "null": null,
            "array": [1, "two", 3]
        }"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        // Should extract "hello" and "two"
        let values: Vec<&str> = result
            .string_values
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert!(values.contains(&"hello"));
        assert!(values.contains(&"two"));
    }

    /// JSON with unicode escapes
    #[test]
    fn test_unicode_escapes() {
        let json = r#"{"msg": "\u003cscript\u003e"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        // Should decode to "<script>"
        let values: Vec<&str> = result
            .string_values
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert!(values.iter().any(|v| v.contains("<script>")));
    }

    /// JSON with escaped characters
    #[test]
    fn test_escaped_chars() {
        let json = r#"{"msg": "line1\nline2\ttab\\backslash\"quote"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
    }

    /// Empty string values
    #[test]
    fn test_empty_strings() {
        let json = r#"{"a": "", "b": "nonempty", "c": ""}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
    }

    /// JSON numbers that look like injection
    #[test]
    fn test_numeric_injection_attempt() {
        // Numbers shouldn't be extracted as strings
        let json = r#"{"id": 1234567890, "price": 99.99}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        // No string values
        assert!(result.string_values.is_empty());
    }
}

mod graphql_edge_cases {
    use super::*;

    /// Empty GraphQL query
    #[test]
    fn test_empty_graphql() {
        let result = extract_graphql_values("");
        // Empty input is not a valid GraphQL query
        assert!(!result.looks_like_graphql);
    }

    /// GraphQL with no string arguments
    #[test]
    fn test_no_string_args() {
        let query = "query { users(limit: 10) { id name } }";
        let result = extract_graphql_values(query);
        assert!(result.looks_like_graphql);
    }

    /// GraphQL with injection in string argument
    #[test]
    fn test_string_arg_injection() {
        let query = r#"query { user(name: "admin' OR '1'='1") { id } }"#;
        let result = extract_graphql_values(query);
        assert!(result.looks_like_graphql);
        let values: Vec<&str> = result
            .string_arguments
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert!(values.iter().any(|v: &&str| v.contains("OR '1'='1")));
    }

    /// GraphQL mutation
    #[test]
    fn test_mutation() {
        let query =
            r#"mutation { createUser(input: {name: "test", email: "test@test.com"}) { id } }"#;
        let result = extract_graphql_values(query);
        assert!(result.looks_like_graphql);
    }

    /// GraphQL with fragments
    #[test]
    fn test_fragments() {
        let query = r#"
            fragment UserFields on User {
                name
                email
            }
            query { users { ...UserFields } }
        "#;
        let result = extract_graphql_values(query);
        assert!(result.looks_like_graphql);
    }

    /// GraphQL batch query (array)
    #[test]
    fn test_batch_query() {
        // Some GraphQL implementations support batches as array
        let query = r#"[{"query":"query{user{id}}"}, {"query":"query{post{id}}"}]"#;
        // This is actually JSON, not GraphQL directly
        let result = extract_json_values(query);
        assert!(result.parsed_ok);
    }
}

mod adversarial_bypass_attempts {
    use super::*;

    /// WAF bypass:double URL encoding
    /// Note:Fast-path doesn't decode URL encoding - the full WAF pipeline should decode first
    #[test]
    fn test_double_url_encoding() {
        // %27 is ', %2527 is %27 after one decode
        // Fast-path operates on raw input without decoding
        let input = "%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd";
        let result = fast_path_check(input);
        // Fast-path won't see "passwd" because it's URL-encoded
        // This is by design - the full WAF pipeline should decode first
        // The test just verifies no crash and documents the behavior
        let _ = result.has_cmdi_patterns;
    }

    /// WAF bypass:SQL comment obfuscation
    #[test]
    fn test_sql_comment_bypass() {
        let input = "sel/**/ect * fr/*inline*/om users";
        let result = fast_path_check(input);
        // Should detect comment indicators
        assert!(result.has_sqli_patterns);
    }

    /// WAF bypass:JSON key with injection
    #[test]
    fn test_json_key_injection() {
        // Some parsers might not check keys
        let json = r#"{"SELECT * FROM users": "value"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        // Our extractor should NOT extract keys as values
        let values: Vec<&str> = result
            .string_values
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert!(!values.iter().any(|v| v.contains("SELECT")));
    }

    /// WAF bypass:Hex encoded SQL
    #[test]
    fn test_hex_bypass() {
        let input = "0x53454c454354"; // "SELECT" in hex
        let result = fast_path_check(input);
        // Should detect "0x" indicator
        assert!(result.has_sqli_patterns);
    }

    /// WAF bypass:Scientific notation in JSON
    #[test]
    fn test_scientific_notation() {
        let json = r#"{"amount": 1e308}"#; // Max double
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
    }

    /// WAF bypass:BOM at start of JSON
    #[test]
    fn test_bom_prefix() {
        let json = "\u{FEFF}{\"key\": \"value\"}";
        let result = extract_json_values(json);
        // Should handle BOM gracefully
        assert!(result.parsed_ok);
    }

    /// WAF bypass:concatenated injection pieces
    #[test]
    fn test_concat_bypass() {
        let input = format!("{}AT('sel','ect')", "CONC");
        let result = fast_path_check(&input);
        // Should detect concat-based SQLi obfuscation.
        assert!(result.has_sqli_patterns);
    }

    /// Stress test:many small matches
    #[test]
    fn test_many_matches() {
        // Input with many potential SQL keywords
        let input = "select union select union select union ".repeat(1000);
        let result = fast_path_check(&input);
        assert!(result.has_sqli_patterns);
    }

    /// Edge case:backslash at end of string
    #[test]
    fn test_trailing_backslash() {
        let json = r#"{"path": "C:\\Users\\test\\"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
    }

    /// XSS in JSON value
    #[test]
    fn test_xss_in_json() {
        let json = r#"{"html": "<script>alert(1)</script>"}"#;
        let result = extract_json_values(json);
        assert!(result.parsed_ok);
        let values: Vec<&str> = result
            .string_values
            .iter()
            .map(|v| v.value.as_str())
            .collect();
        assert!(values.iter().any(|v| v.contains("<script>")));
    }
}

mod concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Concurrent fast-path checks should be thread-safe
    #[test]
    fn test_concurrent_fast_path() {
        let patterns = [
            "SELECT * FROM users",
            "<script>alert(1)</script>",
            "; cat /etc/passwd",
            "normal safe input",
        ];

        let handles: Vec<_> = (0..100)
            .map(|i| {
                let pattern = patterns[i % patterns.len()].to_string();
                thread::spawn(move || {
                    for _ in 0..100 {
                        let _ = fast_path_check(&pattern);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    /// Concurrent JSON parsing
    #[test]
    fn test_concurrent_json_parsing() {
        let json = Arc::new(r#"{"user": "test", "query": "SELECT * FROM x"}"#.to_string());

        let handles: Vec<_> = (0..50)
            .map(|_| {
                let j = Arc::clone(&json);
                thread::spawn(move || {
                    for _ in 0..50 {
                        let result = extract_json_values(&j);
                        assert!(result.parsed_ok);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }
}
