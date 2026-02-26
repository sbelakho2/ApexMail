//! WAF Engine — main entry point that orchestrates all analyzers

use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, warn};

use crate::config::WafConfig;
use crate::decoder;
use crate::detection;
use crate::fast_path;
use crate::json_graphql;
use crate::sql_analyzer;
use crate::xss_analyzer;
use crate::{MatchLocation, RuleMatch};

/// WAF engine
pub struct WafEngine {
    config: Arc<WafConfig>,
    /// Per-IP hit counters for adaptive blocking
    hit_counters: Arc<dashmap::DashMap<IpAddr, u32>>,
}

/// Decision the middleware should take
#[derive(Debug, Clone)]
pub enum WafDecision {
    /// Allow the request through
    Allow,
    /// Block the request with the given HTTP status code
    Block(u16),
    /// Log/monitor only (allow but emit alert)
    Monitor,
}

/// Detailed threat information for logging
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// Total anomaly score
    pub total_score: u32,
    /// All rule matches
    pub matches: Vec<RuleMatch>,
    /// Decision made
    pub decision: WafDecision,
}

/// HTTP request to inspect
pub struct HttpRequest<'a> {
    /// Client IP
    pub client_ip: IpAddr,
    /// HTTP method
    pub method: &'a str,
    /// URL path
    pub path: &'a str,
    /// Query string (raw, after ?)
    pub query_string: Option<&'a str>,
    /// Headers (name, value)
    pub headers: &'a [(String, String)],
    /// Request body (if inspectable)
    pub body: Option<&'a str>,
}

impl WafEngine {
    /// Create a new WAF engine
    pub fn new(config: WafConfig) -> Self {
        Self {
            config: Arc::new(config),
            hit_counters: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Inspect an HTTP request and return a verdict
    pub fn inspect(&self, req: &HttpRequest<'_>) -> ThreatInfo {
        let mut all_matches: Vec<RuleMatch> = Vec::new();

        // Check IP-level allow-lists — IP allowlist = full bypass (trusted internal scanners etc.)
        let ip_str = req.client_ip.to_string();
        if self.config.allowlist_ips.iter().any(|a| *a == ip_str) {
            return ThreatInfo {
                total_score: 0,
                matches: Vec::new(),
                decision: WafDecision::Allow,
            };
        }

        // Path allowlist: trusted paths skip PATH TRAVERSAL on the path itself,
        // but query params, headers and body are STILL inspected to prevent
        // allowlist exploitation (e.g. GET /health?id=1+OR+1=1).
        let is_path_allowlisted = self.config.allowlist_paths.iter()
            .any(|p| req.path.starts_with(p.as_str()));

        // 1. Decode and inspect URL path
        let decoded_path = decoder::decode_payload(req.path, self.config.max_decode_depth);
        
        // Fast-path pre-filter: only run expensive parsers if suspicious keywords found
        let path_fast_check = fast_path::fast_path_check(&decoded_path);
        
        // Path traversal: skip for allowlisted paths (e.g. /static/) but still inspect params
        if !is_path_allowlisted {
            all_matches.extend(detection::analyze_path_traversal(&decoded_path, MatchLocation::Path));
        }
        if self.config.enable_sqli && path_fast_check.has_sqli_patterns {
            all_matches.extend(sql_analyzer::analyze_sqli(&decoded_path, MatchLocation::Path));
        }
        if self.config.enable_xss && path_fast_check.has_xss_patterns {
            all_matches.extend(xss_analyzer::analyze_xss(&decoded_path, MatchLocation::Path));
        }

        // 2. Decode and inspect query parameters
        if let Some(qs) = req.query_string {
            for pair in qs.split('&') {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("");
                let value = parts.next().unwrap_or("");
                let decoded_value = decoder::decode_payload(value, self.config.max_decode_depth);
                let loc = MatchLocation::QueryParam(key.to_string());

                // Fast-path pre-filter for query parameters
                let param_fast_check = fast_path::fast_path_check(&decoded_value);

                if self.config.enable_sqli && param_fast_check.has_sqli_patterns {
                    all_matches.extend(sql_analyzer::analyze_sqli(&decoded_value, loc.clone()));
                }
                if self.config.enable_xss && param_fast_check.has_xss_patterns {
                    all_matches.extend(xss_analyzer::analyze_xss(&decoded_value, loc.clone()));
                }
                if self.config.enable_command_injection && param_fast_check.has_cmdi_patterns {
                    all_matches.extend(detection::analyze_command_injection(&decoded_value, loc.clone()));
                }
                if self.config.enable_path_traversal {
                    all_matches.extend(detection::analyze_path_traversal(&decoded_value, loc));
                }
            }
        }

        // 3. Inspect headers
        for (name, value) in req.headers {
            let decoded_value = decoder::decode_payload(value, self.config.max_decode_depth);
            let loc = MatchLocation::Header(name.clone());
            
            // Fast-path pre-filter for headers
            let header_fast_check = fast_path::fast_path_check(&decoded_value);

            if self.config.enable_xss && header_fast_check.has_xss_patterns {
                all_matches.extend(xss_analyzer::analyze_xss(&decoded_value, loc.clone()));
            }
            if self.config.enable_sqli && header_fast_check.has_sqli_patterns {
                all_matches.extend(sql_analyzer::analyze_sqli(&decoded_value, loc.clone()));
            }
            // Command injection in headers (e.g. X-Custom-Header: ; cat /etc/passwd)
            if self.config.enable_command_injection && header_fast_check.has_cmdi_patterns {
                all_matches.extend(detection::analyze_command_injection(&decoded_value, loc));
            }
        }

        // 4. Inspect body (truncated to max_body_size)
        if let Some(body) = req.body {
            let truncated = if body.len() > self.config.max_body_size {
                &body[..self.config.max_body_size]
            } else {
                body
            };
            let decoded_body = decoder::decode_payload(truncated, self.config.max_decode_depth);
            
            // Fast-path pre-filter for body
            let body_fast_check = fast_path::fast_path_check(&decoded_body);
            
            // Also check for JSON/GraphQL payloads and extract nested values
            if let Some(content_type) = req.headers.iter().find(|(n, _)| n.to_lowercase() == "content-type") {
                let ct_lower = content_type.1.to_lowercase();
                if ct_lower.contains("application/json") || ct_lower.contains("application/graphql") {
                    // Extract values from JSON/GraphQL and inspect them
                    let json_result = json_graphql::extract_json_values(&decoded_body);
                    for jpv in &json_result.string_values {
                        let val_fast_check = fast_path::fast_path_check(&jpv.value);
                        let loc = MatchLocation::Body; // Could be more specific: JsonPath(jpv.path.clone())
                        
                        if self.config.enable_sqli && val_fast_check.has_sqli_patterns {
                            all_matches.extend(sql_analyzer::analyze_sqli(&jpv.value, loc.clone()));
                        }
                        if self.config.enable_xss && val_fast_check.has_xss_patterns {
                            all_matches.extend(xss_analyzer::analyze_xss(&jpv.value, loc.clone()));
                        }
                        if self.config.enable_command_injection && val_fast_check.has_cmdi_patterns {
                            all_matches.extend(detection::analyze_command_injection(&jpv.value, loc));
                        }
                    }
                    
                    // Also check GraphQL queries
                    let gql_result = json_graphql::extract_graphql_values(&decoded_body);
                    for arg in &gql_result.string_arguments {
                        let arg_fast_check = fast_path::fast_path_check(&arg.value);
                        let loc = MatchLocation::Body;
                        
                        if self.config.enable_sqli && arg_fast_check.has_sqli_patterns {
                            all_matches.extend(sql_analyzer::analyze_sqli(&arg.value, loc.clone()));
                        }
                        if self.config.enable_xss && arg_fast_check.has_xss_patterns {
                            all_matches.extend(xss_analyzer::analyze_xss(&arg.value, loc));
                        }
                    }
                }
            }

            if self.config.enable_sqli && body_fast_check.has_sqli_patterns {
                all_matches.extend(sql_analyzer::analyze_sqli(&decoded_body, MatchLocation::Body));
            }
            if self.config.enable_xss && body_fast_check.has_xss_patterns {
                all_matches.extend(xss_analyzer::analyze_xss(&decoded_body, MatchLocation::Body));
            }
            if self.config.enable_command_injection && body_fast_check.has_cmdi_patterns {
                all_matches.extend(detection::analyze_command_injection(&decoded_body, MatchLocation::Body));
            }
        }

        // 5. Protocol-level checks
        if self.config.enable_protocol_checks {
            all_matches.extend(detection::analyze_protocol_anomalies(
                req.method,
                req.path,
                req.headers,
                req.body.map(|b| b.len()).unwrap_or(0),
                MatchLocation::Path,
            ));
        }

        // Calculate total anomaly score
        let total_score: u32 = all_matches.iter().map(|m| m.score).sum();

        // Make decision
        let decision = if total_score >= self.config.blocking_threshold {
            warn!(
                score = total_score,
                matches = all_matches.len(),
                ip = %req.client_ip,
                path = req.path,
                "WAF: Request blocked"
            );
            WafDecision::Block(403)
        } else if total_score >= self.config.detection_threshold {
            debug!(
                score = total_score,
                matches = all_matches.len(),
                "WAF: Request flagged for monitoring"
            );
            WafDecision::Monitor
        } else {
            WafDecision::Allow
        };

        ThreatInfo {
            total_score,
            matches: all_matches,
            decision,
        }
    }

    fn is_allowlisted(&self, req: &HttpRequest<'_>) -> bool {
        // IP allowlist only — path allowlisting is handled inline above
        // to ensure query params/headers/body are still inspected.
        let ip_str = req.client_ip.to_string();
        self.config.allowlist_ips.iter().any(|a| *a == ip_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_engine() -> WafEngine {
        WafEngine::new(WafConfig::default())
    }

    #[test]
    fn test_sqli_in_query_param() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/users",
            query_string: Some("id=1+OR+1%3D1"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(info.total_score >= 5);
        assert!(matches!(info.decision, WafDecision::Block(_)));
    }

    #[test]
    fn test_xss_in_body() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ],
            body: Some("comment=<script>alert(document.cookie)</script>"),
        };
        let info = engine.inspect(&req);
        assert!(info.total_score >= 5);
    }

    #[test]
    fn test_clean_request() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/v1/health",
            query_string: None,
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert_eq!(info.total_score, 0);
        assert!(matches!(info.decision, WafDecision::Allow));
    }

    #[test]
    fn test_path_traversal_in_url() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/static/../../etc/passwd",
            query_string: None,
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(info.total_score >= 5);
    }

    #[test]
    fn test_path_allowlist_still_inspects_query_params() {
        // After the allowlist fix: path is allowed but query-string injection must still be caught.
        let mut config = WafConfig::default();
        config.allowlist_paths.push("/health".to_string());
        let engine = WafEngine::new(config);
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/health",
            query_string: Some("id=1+OR+1%3D1"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        // Query-string injection must be caught even on allowlisted paths
        assert!(info.total_score >= 5,
            "SQLi in query string must be caught on allowlisted path, score={}", info.total_score);
    }

    #[test]
    fn test_ip_allowlist_full_bypass() {
        // IP allowlisting still allows full bypass (trusted internal tools)
        let mut config = WafConfig::default();
        config.allowlist_ips.push("10.0.0.1".to_string());
        let engine = WafEngine::new(config);
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api",
            query_string: Some("id=1+OR+1%3D1"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert_eq!(info.total_score, 0, "IP allowlisted request must bypass WAF");
    }

    #[test]
    fn test_cmdi_injected_in_header() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.2".parse().expect("valid IP"),
            method: "GET",
            path: "/api/v1/data",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("X-Custom-Cmd".into(), "; cat /etc/passwd".into()),
            ],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(info.total_score >= 5,
            "Command injection in header must be detected, score={}", info.total_score);
    }
}
