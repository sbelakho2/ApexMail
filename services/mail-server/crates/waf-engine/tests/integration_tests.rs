//! Integration tests verifying security module interactions
//!
//! These tests verify that multiple security components work correctly together.

use waf_engine::fast_path::fast_path_check;
use waf_engine::json_graphql::{extract_json_values, extract_graphql_values};

mod waf_pipeline_integration {
    use super::*;

    /// Test the full WAF inspection pipeline: fast-path -> JSON parsing -> detection
    #[test]
    fn test_full_pipeline_json_request() {
        // A realistic JSON API request with embedded attack
        let request_body = r#"{
            "user": {
                "name": "John Doe",
                "query": "SELECT * FROM users WHERE name = 'test'",
                "comment": "Normal comment"
            }
        }"#;
        
        // Step 1: Fast-path check
        let fast_result = fast_path_check(request_body);
        assert!(fast_result.has_sqli_patterns, "Fast path should detect SQLi keywords");
        
        // Step 2: Since fast-path flagged it, do deep JSON inspection
        let json_result = extract_json_values(request_body);
        assert!(json_result.parsed_ok, "JSON should parse successfully");
        
        // Step 3: Check extracted values for the attack
        let sqli_values: Vec<_> = json_result.string_values.iter()
            .filter(|v| v.value.to_lowercase().contains("select"))
            .collect();
        assert!(!sqli_values.is_empty(), "Should extract the SQLi payload");
        assert_eq!(sqli_values[0].path, "$.user.query", "Correct path to attack");
    }

    #[test]
    fn test_full_pipeline_graphql_request() {
        // A realistic GraphQL request with potential injection
        let request_body = r#"{
            "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
            "variables": {
                "id": "1'; DROP TABLE users; --"
            }
        }"#;
        
        // Step 1: Fast-path check
        let fast_result = fast_path_check(request_body);
        assert!(fast_result.has_sqli_patterns, "Fast path should detect DROP TABLE");
        
        // Step 2: GraphQL inspection
        let gql_result = extract_graphql_values(request_body);
        assert!(gql_result.looks_like_graphql, "Should recognize as GraphQL");
        
        // Step 3: Check variables for injection
        let dangerous_vars: Vec<_> = gql_result.variables.iter()
            .filter(|v| v.value.contains("DROP"))
            .collect();
        assert!(!dangerous_vars.is_empty(), "Should extract the injected variable");
    }

    #[test]
    fn test_pipeline_clean_request() {
        let request_body = r#"{
            "user": {
                "name": "Alice",
                "email": "alice@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            }
        }"#;
        
        // Fast-path intentionally flags input with quotes for deeper inspection
        // This is by design - it's a pre-filter, not a final determination
        let fast_result = fast_path_check(request_body);
        // The fast path will likely flag this due to quotes in JSON
        // The important thing is that deep inspection clears it
        
        // JSON inspection should succeed and extract benign values
        let json_result = extract_json_values(request_body);
        assert!(json_result.parsed_ok);
        
        // Verify extracted values are actually clean (no attack in the values)
        // Note: fast_path_check will flag quotes, but actual values don't contain attacks
        for value in &json_result.string_values {
            assert!(!value.value.to_lowercase().contains("select "));
            assert!(!value.value.to_lowercase().contains("union "));
            assert!(!value.value.contains("<script>"));
        }
    }
}

mod nested_attack_detection {
    use super::*;

    #[test]
    fn test_deeply_nested_attack() {
        // Attack hidden deep in JSON structure
        let payload = r#"{
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "attack": "<script>alert('XSS')</script>"
                        }
                    }
                }
            }
        }"#;
        
        let json_result = extract_json_values(payload);
        assert!(json_result.parsed_ok);
        
        // Should find the attack at the deep level
        let xss_values: Vec<_> = json_result.string_values.iter()
            .filter(|v| v.value.contains("<script>"))
            .collect();
        assert!(!xss_values.is_empty(), "Should find XSS in deep nesting");
        assert!(
            xss_values[0].path.contains("level4"),
            "Should track the correct path"
        );
    }

    #[test]
    fn test_array_with_attack() {
        let payload = r#"{
            "items": [
                "safe value 1",
                "safe value 2",
                "'; DELETE FROM items; --",
                "safe value 3"
            ]
        }"#;
        
        let json_result = extract_json_values(payload);
        assert!(json_result.parsed_ok);
        
        // Should find the attack in the array
        let sqli_values: Vec<_> = json_result.string_values.iter()
            .filter(|v| v.value.contains("DELETE"))
            .collect();
        assert!(!sqli_values.is_empty(), "Should find SQLi in array");
        assert!(
            sqli_values[0].path.contains("[2]") || sqli_values[0].path.contains(".items"),
            "Should have array index in path: {}",
            sqli_values[0].path
        );
    }
}

mod graphql_attack_vectors {
    use super::*;

    #[test]
    fn test_graphql_mutation_with_injection() {
        let payload = r#"{
            "query": "mutation UpdateUser($input: UpdateInput!) { updateUser(input: $input) { id } }",
            "variables": {
                "input": {
                    "name": "John",
                    "bio": "<img src=x onerror=alert(document.cookie)>"
                }
            }
        }"#;
        
        let gql_result = extract_graphql_values(payload);
        assert!(gql_result.looks_like_graphql);
        
        // The XSS should be in variables
        let has_xss = gql_result.variables.iter()
            .any(|v| v.value.contains("onerror"));
        assert!(has_xss, "Should detect XSS in GraphQL variables");
    }

    #[test]
    fn test_raw_graphql_introspection() {
        // Introspection query sent as raw GraphQL
        let payload = "{ __schema { types { name } queryType { name } mutationType { name } } }";
        
        let gql_result = extract_graphql_values(payload);
        assert!(gql_result.looks_like_graphql, "Should recognize raw GraphQL");
        assert_eq!(gql_result.operation_type, Some("query".to_string()));
    }

    #[test]
    fn test_graphql_batch_operations() {
        // Multiple operations in one query
        let payload = r#"{
            "query": "query A { user { id } } query B { posts { title } }"
        }"#;
        
        let gql_result = extract_graphql_values(payload);
        assert!(gql_result.looks_like_graphql);
    }
}

mod evasion_detection {
    use super::*;

    #[test]
    fn test_json_key_as_attack_vector() {
        // Attack in the key itself, not the value
        // Note: Current implementation may not catch this - documenting for future
        let payload = r#"{"<script>evil()</script>": "innocentvalue"}"#;
        
        // Fast path should still catch it
        let fast_result = fast_path_check(payload);
        assert!(fast_result.has_xss_patterns, "Should detect XSS in key");
    }

    #[test]
    fn test_unicode_in_json() {
        // Unicode escapes in JSON that decode to dangerous content
        let payload = r#"{"message": "\u003cscript\u003ealert(1)\u003c/script\u003e"}"#;
        
        let json_result = extract_json_values(payload);
        assert!(json_result.parsed_ok);
        
        // Check if the decoded value contains the attack
        // Note: depends on whether our parser decodes unicode escapes
    }

    #[test]
    fn test_mixed_content_types() {
        // Request that could be interpreted as JSON or GraphQL
        let payload = r#"{"query":"{ user { name } }"}"#;
        
        // Should be recognized as GraphQL
        let gql_result = extract_graphql_values(payload);
        assert!(gql_result.looks_like_graphql);
        
        // But also parseable as JSON
        let json_result = extract_json_values(payload);
        assert!(json_result.parsed_ok);
    }
}

mod performance_edge_cases {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pipeline_performance_large_json() {
        // Large but clean JSON - should be fast
        let mut json = String::from(r#"{"items": ["#);
        for i in 0..1000 {
            if i > 0 {
                json.push_str(", ");
            }
            json.push_str(&format!(r#"{{"id": {}, "name": "item{}"}}"#, i, i));
        }
        json.push_str("]}");
        
        let start = Instant::now();
        
        let _fast_result = fast_path_check(&json);
        let json_result = extract_json_values(&json);
        
        let elapsed = start.elapsed();
        
        // Should complete quickly (< 1 second for 1000 items)
        assert!(elapsed.as_millis() < 1000, "Processing took too long: {:?}", elapsed);
        // Fast path will flag due to quotes, but JSON parsing should succeed
        assert!(json_result.parsed_ok);
        assert!(json_result.string_values.len() == 1000, "Should extract all item names");
    }

    #[test]
    fn test_many_small_requests() {
        // Simulate many small requests
        let payloads: Vec<String> = (0..100)
            .map(|i| format!(r#"{{"id": {}, "action": "view"}}"#, i))
            .collect();
        
        for payload in &payloads {
            let _fast = fast_path_check(payload);
            let _json = extract_json_values(payload);
        }
        
        // Just ensure no crashes or resource exhaustion
    }
}

mod error_handling {
    use super::*;

    #[test]
    fn test_malformed_json_doesnt_crash() {
        let malformed_payloads = vec![
            r#"{"unclosed": "#,
            r#"["array", "without", "end"#,
            r#"{"key": undefined}"#,
            r#"{"key": NaN}"#,
            r#"{key: "missing quotes"}"#,
            r#"{"trailing": "comma",}"#,
        ];
        
        for payload in malformed_payloads {
            // Should not panic
            let result = extract_json_values(payload);
            assert!(!result.parsed_ok || result.string_values.is_empty(),
                "Should fail gracefully for: {}", payload);
        }
    }

    #[test]
    fn test_malformed_graphql_doesnt_crash() {
        let malformed_payloads = vec![
            "{ unclosed",
            "query { user(",
            "mutation { create",
            "fragment X on { }",
            "{ ... on }",
        ];
        
        for payload in malformed_payloads {
            // Should not panic
            let result = extract_graphql_values(payload);
            // May or may not be recognized as GraphQL, but shouldn't crash
            let _ = result.looks_like_graphql;
        }
    }

    #[test]
    fn test_empty_inputs() {
        assert!(fast_path_check("").is_clean());
        
        let json_result = extract_json_values("");
        assert!(json_result.parsed_ok);
        assert!(json_result.string_values.is_empty());
        
        let gql_result = extract_graphql_values("");
        assert!(!gql_result.looks_like_graphql);
    }

    #[test]
    fn test_whitespace_only() {
        let inputs = vec!["   ", "\t\t\t", "\n\n", "  \t  \n  "];
        
        for input in inputs {
            assert!(fast_path_check(input).is_clean());
            let _ = extract_json_values(input);
            let _ = extract_graphql_values(input);
        }
    }
}
