//! WAF Engine — main entry point that orchestrates all analyzers

use std::net::IpAddr;
use std::sync::Arc;

use mail_common::{
    CorrelationContext, SecurityAction, SecurityEvent, SecuritySeverity, SecuritySystem,
};
use tracing::{debug, warn};

use crate::config::WafConfig;
use crate::decoder;
use crate::detection;
use crate::fast_path;
use crate::json_graphql;
use crate::rules;
use crate::sql_analyzer;
use crate::xss_analyzer;
use crate::{AttackCategory, MatchLocation, RuleMatch};

/// WAF engine
pub struct WafEngine {
    config: Arc<WafConfig>,
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
        }
    }

    /// Inspect an HTTP request and return a verdict
    pub fn inspect(&self, req: &HttpRequest<'_>) -> ThreatInfo {
        let mut all_matches: Vec<RuleMatch> = Vec::with_capacity(16);

        // Check IP-level allow-lists — IP allowlist = full bypass (trusted internal scanners etc.)
        let ip_str = req.client_ip.to_string();
        if self.config.allowlist_ips.contains(&ip_str) {
            return ThreatInfo {
                total_score: 0,
                matches: Vec::new(),
                decision: WafDecision::Allow,
            };
        }

        // Path allowlist:trusted paths skip the PATH analyzers,
        // but query params, headers and body are STILL inspected to prevent
        // allowlist exploitation (e.g. GET /health?id=1+OR+1=1).
        // Matching is exact-or-segment-prefix so `/staticX/...` cannot ride
        // on an entry named `/static`.
        let is_path_allowlisted = is_allowlisted_path(req.path, &self.config.allowlist_paths);

        // 0. Enforce configured request size/shape limits (fail-closed).
        // These were previously dead configuration; oversized requests are
        // rejected with HTTP 400 (see `block_status_for`).
        let url_len = req.path.len() + req.query_string.map(|q| q.len() + 1).unwrap_or(0);
        if url_len > self.config.max_url_length {
            all_matches.push(RuleMatch {
                rule_id: 920160,
                category: AttackCategory::RequestAnomaly,
                score: 5,
                message: format!(
                    "URL length {} exceeds configured maximum {}",
                    url_len, self.config.max_url_length
                ),
                location: MatchLocation::Path,
                matched_data: truncate_str(req.path, 80),
            });
        }
        if let Some(qs) = req.query_string {
            let param_count = qs.split('&').filter(|p| !p.is_empty()).count();
            if param_count > self.config.max_query_params {
                all_matches.push(RuleMatch {
                    rule_id: 920170,
                    category: AttackCategory::RequestAnomaly,
                    score: 5,
                    message: format!(
                        "Query parameter count {} exceeds configured maximum {}",
                        param_count, self.config.max_query_params
                    ),
                    location: MatchLocation::Path,
                    matched_data: format!("param_count={param_count}"),
                });
            }
        }
        if req.headers.len() > self.config.max_headers {
            all_matches.push(RuleMatch {
                rule_id: 920180,
                category: AttackCategory::RequestAnomaly,
                score: 5,
                message: format!(
                    "Header count {} exceeds configured maximum {}",
                    req.headers.len(),
                    self.config.max_headers
                ),
                location: MatchLocation::Path,
                matched_data: format!("header_count={}", req.headers.len()),
            });
        }
        if let Some((name, _)) = req
            .headers
            .iter()
            .find(|(_, v)| v.len() > self.config.max_header_value_length)
        {
            all_matches.push(RuleMatch {
                rule_id: 920190,
                category: AttackCategory::RequestAnomaly,
                score: 5,
                message: format!(
                    "Header '{}' value exceeds configured maximum length {}",
                    name, self.config.max_header_value_length
                ),
                location: MatchLocation::Header(name.clone()),
                matched_data: truncate_str(name, 80),
            });
        }

        // Null bytes anywhere in the raw request are rejected (rule 920400).
        // NUL bytes are canonicalized away before the analyzers run, so the
        // raw surfaces are checked here explicitly (query/body/headers).
        if let Some(qs) = req.query_string {
            if qs.contains('\0') || qs.contains("%00") {
                all_matches.push(null_byte_match(
                    MatchLocation::QueryParam("query-string".to_string()),
                    qs,
                ));
            }
        }
        if let Some(body) = req.body {
            if body.contains('\0') || body.contains("%00") {
                all_matches.push(null_byte_match(MatchLocation::Body, body));
            }
        }
        if let Some((name, value)) = req
            .headers
            .iter()
            .find(|(_, v)| v.contains('\0') || v.contains("%00"))
        {
            all_matches.push(null_byte_match(MatchLocation::Header(name.clone()), value));
        }

        // 1. Decode and inspect URL path
        let decoded_path = decoder::canonicalize_input(
            req.path,
            self.config.max_decode_depth,
            self.config.enable_unicode_normalization,
        );

        // Fast-path pre-filter:only run expensive parsers if suspicious keywords found
        let path_fast_check = fast_path::fast_path_check(&decoded_path);

        // Path traversal is checked ALWAYS — even on allowlisted paths.
        // Skipping it for a prefix like `/static` let `/static/../../etc`
        // escape the allowlist intent, and `..` after decoding is a jail
        // break regardless of which route serves the path.
        if self.config.enable_path_traversal {
            all_matches.extend(detection::analyze_path_traversal(
                &decoded_path,
                MatchLocation::Path,
            ));
        }
        // Allowlisted paths skip the full SQL/XSS inspection of the path
        // itself (query params, headers and body are still fully inspected
        // below).
        if !is_path_allowlisted {
            if self.config.enable_sqli && path_fast_check.has_sqli_patterns {
                all_matches.extend(sql_analyzer::analyze_sqli(
                    &decoded_path,
                    MatchLocation::Path,
                ));
            }
            if self.config.enable_xss && path_fast_check.has_xss_patterns {
                all_matches.extend(xss_analyzer::analyze_xss(
                    &decoded_path,
                    MatchLocation::Path,
                ));
            }
        }

        // 2. Decode and inspect query parameters
        if let Some(qs) = req.query_string {
            let mut inspect_query_fragment = |decoded_fragment: &str, loc: MatchLocation| {
                let param_fast_check = fast_path::fast_path_check(decoded_fragment);

                if self.config.enable_sqli && param_fast_check.has_sqli_patterns {
                    all_matches.extend(sql_analyzer::analyze_sqli(decoded_fragment, loc.clone()));
                }
                if self.config.enable_xss && param_fast_check.has_xss_patterns {
                    all_matches.extend(xss_analyzer::analyze_xss(decoded_fragment, loc.clone()));
                }
                if self.config.enable_command_injection && param_fast_check.has_cmdi_patterns {
                    all_matches.extend(detection::analyze_command_injection(
                        decoded_fragment,
                        loc.clone(),
                    ));
                }
                if self.config.enable_path_traversal {
                    all_matches.extend(detection::analyze_path_traversal(
                        decoded_fragment,
                        loc.clone(),
                    ));
                }
                if self.config.enable_nosqli {
                    all_matches.extend(detection::analyze_ldap_injection(decoded_fragment, loc));
                }
            };

            for pair in qs.split('&') {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("");
                let value = parts.next().unwrap_or("");
                let decoded_pair = decoder::canonicalize_input(
                    pair,
                    self.config.max_decode_depth,
                    self.config.enable_unicode_normalization,
                );
                let decoded_key = decoder::canonicalize_input(
                    key,
                    self.config.max_decode_depth,
                    self.config.enable_unicode_normalization,
                );
                let decoded_value = decoder::canonicalize_input(
                    value,
                    self.config.max_decode_depth,
                    self.config.enable_unicode_normalization,
                );
                let loc = MatchLocation::QueryParam(key.to_string());

                inspect_query_fragment(
                    &decoded_pair,
                    MatchLocation::QueryParam(format!("{} (raw)", key)),
                );

                if value.is_empty() {
                    inspect_query_fragment(&decoded_key, loc);
                } else {
                    inspect_query_fragment(
                        &decoded_key,
                        MatchLocation::QueryParam(format!("{} (key)", key)),
                    );
                    inspect_query_fragment(&decoded_value, loc);
                }
            }
        }

        // 3. Inspect headers
        for (name, value) in req.headers {
            let decoded_value = decoder::canonicalize_input(
                value,
                self.config.max_decode_depth,
                self.config.enable_unicode_normalization,
            );
            let loc = MatchLocation::Header(name.clone());

            // Fast-path pre-filter for headers
            let header_fast_check = fast_path::fast_path_check(&decoded_value);

            if self.config.enable_xss && header_fast_check.has_xss_patterns {
                all_matches.extend(xss_analyzer::analyze_xss(&decoded_value, loc.clone()));
            }
            if self.config.enable_sqli && header_fast_check.has_sqli_patterns {
                all_matches.extend(sql_analyzer::analyze_sqli(&decoded_value, loc.clone()));
            }
            // Command injection in headers (e.g. X-Custom-Header:; cat /etc/passwd)
            if self.config.enable_command_injection && header_fast_check.has_cmdi_patterns {
                all_matches.extend(detection::analyze_command_injection(&decoded_value, loc));
            }
        }

        // 4. Inspect body (truncated to the FIRST max_body_size bytes).
        // The truncated head is computed ONCE here and reused by every body
        // consumer below (steps 4, 7 and 8) so no analyzer ever sees the
        // bytes beyond the cap — that is the whole point of the CPU bound.
        let truncated_body: Option<&str> = req.body.map(|body| {
            if body.len() > self.config.max_body_size {
                // Keep the HEAD of the body (attacks overwhelmingly live at
                // the start of a payload). The cut lands on a UTF-8 char
                // boundary: `head_char_boundary` steps back when the byte
                // limit falls mid-character, so slicing never panics.
                &body[..head_char_boundary(body, self.config.max_body_size)]
            } else {
                body
            }
        });

        if let Some(truncated) = truncated_body {
            let decoded_body = decoder::canonicalize_input(
                truncated,
                self.config.max_decode_depth,
                self.config.enable_unicode_normalization,
            );

            // Fast-path pre-filter for body
            let body_fast_check = fast_path::fast_path_check(&decoded_body);

            // Also check for JSON/GraphQL payloads and extract nested values
            if let Some(content_type) = req
                .headers
                .iter()
                .find(|(n, _)| n.to_lowercase() == "content-type")
            {
                let ct_lower = content_type.1.to_lowercase();
                if ct_lower.contains("application/json") || ct_lower.contains("application/graphql")
                {
                    // Extract values from JSON/GraphQL and inspect them
                    let json_result = json_graphql::extract_json_values(&decoded_body);
                    if !json_result.parsed_ok {
                        if let Some(err) = &json_result.error {
                            if err.contains("Maximum") {
                                all_matches.push(RuleMatch {
                                    rule_id: 920330,
                                    category: AttackCategory::RequestAnomaly,
                                    score: 6,
                                    message: format!("JSON complexity limit exceeded: {}", err),
                                    location: MatchLocation::Body,
                                    matched_data: "json_complexity_limit".to_string(),
                                });
                            }
                        }
                    }
                    for jpv in &json_result.string_values {
                        let val_fast_check = fast_path::fast_path_check(&jpv.value);
                        let loc = MatchLocation::Body; // Could be more specific:JsonPath(jpv.path.clone)

                        if self.config.enable_sqli && val_fast_check.has_sqli_patterns {
                            all_matches.extend(sql_analyzer::analyze_sqli(&jpv.value, loc.clone()));
                        }
                        if self.config.enable_xss && val_fast_check.has_xss_patterns {
                            all_matches.extend(xss_analyzer::analyze_xss(&jpv.value, loc.clone()));
                        }
                        if self.config.enable_command_injection && val_fast_check.has_cmdi_patterns
                        {
                            all_matches
                                .extend(detection::analyze_command_injection(&jpv.value, loc));
                        }
                        if self.config.enable_nosqli {
                            all_matches.extend(detection::analyze_ldap_injection(
                                &jpv.value,
                                MatchLocation::Body,
                            ));
                        }
                    }

                    // Also check GraphQL queries
                    let gql_result = json_graphql::extract_graphql_values(&decoded_body);
                    if gql_result.limit_exceeded {
                        all_matches.push(RuleMatch {
                            rule_id: 944260,
                            category: AttackCategory::RequestAnomaly,
                            score: 6,
                            message: format!(
                                "GraphQL complexity limit exceeded: depth={} fields={}",
                                gql_result.max_depth, gql_result.field_count
                            ),
                            location: MatchLocation::Body,
                            matched_data: "graphql_complexity_limit".to_string(),
                        });
                    }
                    for arg in &gql_result.string_arguments {
                        let arg_fast_check = fast_path::fast_path_check(&arg.value);
                        let loc = MatchLocation::Body;

                        if self.config.enable_sqli && arg_fast_check.has_sqli_patterns {
                            all_matches.extend(sql_analyzer::analyze_sqli(&arg.value, loc.clone()));
                        }
                        if self.config.enable_xss && arg_fast_check.has_xss_patterns {
                            all_matches.extend(xss_analyzer::analyze_xss(&arg.value, loc));
                        }
                        if self.config.enable_nosqli {
                            all_matches.extend(detection::analyze_ldap_injection(
                                &arg.value,
                                MatchLocation::Body,
                            ));
                        }
                    }
                }
            }

            if self.config.enable_sqli && body_fast_check.has_sqli_patterns {
                all_matches.extend(sql_analyzer::analyze_sqli(
                    &decoded_body,
                    MatchLocation::Body,
                ));
            }
            if self.config.enable_xss && body_fast_check.has_xss_patterns {
                all_matches.extend(xss_analyzer::analyze_xss(
                    &decoded_body,
                    MatchLocation::Body,
                ));
            }
            if self.config.enable_command_injection && body_fast_check.has_cmdi_patterns {
                all_matches.extend(detection::analyze_command_injection(
                    &decoded_body,
                    MatchLocation::Body,
                ));
            }
            if self.config.enable_nosqli {
                all_matches.extend(detection::analyze_ldap_injection(
                    &decoded_body,
                    MatchLocation::Body,
                ));
            }
            all_matches.extend(detection::analyze_ssti(&decoded_body, MatchLocation::Body));
            all_matches.extend(detection::analyze_xxe(&decoded_body, MatchLocation::Body));
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

        // 6. HTTP Request Smuggling detection
        if self.config.enable_smuggling {
            all_matches.extend(detection::analyze_request_smuggling(
                req.headers,
                req.body,
                MatchLocation::Header("Transfer-Encoding/Content-Length".to_string()),
            ));
        }

        // 7. NoSQL injection detection across all decoded inputs
        // (body analysis uses the SAME truncated head computed in step 4 —
        // the size cap would be meaningless if this step re-scanned the
        // full body).
        if self.config.enable_nosqli {
            if let Some(truncated) = truncated_body {
                let decoded_body = decoder::canonicalize_input(
                    truncated,
                    self.config.max_decode_depth,
                    self.config.enable_unicode_normalization,
                );
                all_matches.extend(detection::analyze_nosql_injection(
                    &decoded_body,
                    MatchLocation::Body,
                ));
            }
            if let Some(qs) = req.query_string {
                for pair in qs.split('&') {
                    let value = pair.split_once('=').map(|x| x.1).unwrap_or("");
                    let decoded = decoder::canonicalize_input(
                        value,
                        self.config.max_decode_depth,
                        self.config.enable_unicode_normalization,
                    );
                    all_matches.extend(detection::analyze_nosql_injection(
                        &decoded,
                        MatchLocation::QueryParam(pair.to_string()),
                    ));
                }
            }
        }

        // 8. SSRF detection
        if self.config.enable_ssrf {
            let decoded_path = decoder::canonicalize_input(
                req.path,
                self.config.max_decode_depth,
                self.config.enable_unicode_normalization,
            );
            all_matches.extend(detection::analyze_ssrf(&decoded_path, MatchLocation::Path));
            if let Some(qs) = req.query_string {
                for pair in qs.split('&') {
                    let value = pair.split_once('=').map(|x| x.1).unwrap_or("");
                    let decoded = decoder::canonicalize_input(
                        value,
                        self.config.max_decode_depth,
                        self.config.enable_unicode_normalization,
                    );
                    all_matches.extend(detection::analyze_ssrf(
                        &decoded,
                        MatchLocation::QueryParam(pair.to_string()),
                    ));
                }
            }
            if let Some(truncated) = truncated_body {
                let decoded_body = decoder::canonicalize_input(
                    truncated,
                    self.config.max_decode_depth,
                    self.config.enable_unicode_normalization,
                );
                all_matches.extend(detection::analyze_ssrf(&decoded_body, MatchLocation::Body));
            }
        }

        // 9. Paranoia-level filtering (OWASP CRS semantics): rules whose
        // catalog paranoia level exceeds the configured level are skipped.
        // Uncatalogued rules default to level 1 (always active).
        if self.config.paranoia_level < rules::MAX_CATALOG_PARANOIA_LEVEL {
            let level = self.config.paranoia_level;
            all_matches.retain(|m| rules::rule_paranoia_level(m.rule_id) <= level);
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
            WafDecision::Block(block_status_for(&all_matches))
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

    /// Inspect request and also emit a normalized security event.
    pub fn inspect_with_event(
        &self,
        req: &HttpRequest<'_>,
        correlation: Option<CorrelationContext>,
    ) -> (ThreatInfo, SecurityEvent) {
        let info = self.inspect(req);
        let correlation = correlation.unwrap_or_else(CorrelationContext::generated);

        let (action, severity) = match info.decision {
            WafDecision::Allow => (SecurityAction::Allow, SecuritySeverity::Info),
            WafDecision::Monitor => (SecurityAction::Monitor, SecuritySeverity::Medium),
            WafDecision::Block(_) => (SecurityAction::Block, SecuritySeverity::High),
        };

        let risk_score = if self.config.blocking_threshold == 0 {
            10.0
        } else {
            ((info.total_score as f64 / self.config.blocking_threshold as f64) * 10.0).min(10.0)
        };

        let mut event = SecurityEvent::new(
            SecuritySystem::Waf,
            action,
            severity,
            risk_score,
            format!(
                "WAF decision={:?} score={} matches={} path={}",
                info.decision,
                info.total_score,
                info.matches.len(),
                req.path
            ),
            correlation,
        )
        .with_metadata("client_ip", req.client_ip.to_string())
        .with_metadata("src_ip", req.client_ip.to_string())
        .with_metadata("http_method", req.method.to_string())
        .with_metadata("path", req.path.to_string());

        if let Some(alert) = mail_common::ingest_security_event(event.clone()) {
            event
                .metadata
                .insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (info, event)
    }
}

/// Rule IDs that represent malformed request structure (oversized URL,
/// parameter/header floods, oversized headers). These are client errors and
/// are rejected with HTTP 400 instead of 403.
const REQUEST_SHAPE_RULES: [u32; 4] = [920160, 920170, 920180, 920190];

/// Pick the block status code for a set of matches: malformed/oversized
/// requests are a 400 (bad request), behavioral detections a 403.
fn block_status_for(matches: &[RuleMatch]) -> u16 {
    if matches
        .iter()
        .any(|m| REQUEST_SHAPE_RULES.contains(&m.rule_id))
    {
        400
    } else {
        403
    }
}

/// Build a rule 920400 match for a raw NUL byte (`\0` or `%00`).
fn null_byte_match(location: MatchLocation, raw: &str) -> RuleMatch {
    RuleMatch {
        rule_id: 920400,
        category: AttackCategory::RequestAnomaly,
        score: 5,
        message: "Null byte in request".to_string(),
        location,
        matched_data: truncate_str(raw, 80),
    }
}

/// Check whether `path` is allowlisted by `entries`.
///
/// An entry matches only the exact path or a full path-segment prefix:
/// `/static` matches `/static` and `/static/css/app.css` but NOT
/// `/staticX/admin` (which would otherwise inherit the allowlist through a
/// naive `starts_with`).
fn is_allowlisted_path(path: &str, entries: &[String]) -> bool {
    entries
        .iter()
        .any(|entry| path == entry.as_str() || path.starts_with(&format!("{entry}/")))
}

/// Largest index `<= index` that is a UTF-8 character boundary of `s`.
///
/// Manual implementation of the (still unstable) `str::floor_char_boundary`.
/// Used to truncate request bodies without panicking when the cut point
/// lands inside a multi-byte character.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// End index for a HEAD slice of at most `index` bytes: the largest char
/// boundary `<= index`. When the byte limit lands in the middle of a
/// multi-byte character the boundary steps BACK (never forward, so the
/// scanned head never exceeds the configured cap and never panics).
fn head_char_boundary(s: &str, index: usize) -> usize {
    floor_char_boundary(s, index)
}

/// Truncate a string to at most `max_chars` characters for match payloads.
fn truncate_str(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => format!("{}...", &s[..byte_idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_quoted_sqli_in_query_param() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/users",
            query_string: Some("id=1%27%20OR%20%271%27%3D%271"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.total_score >= 5,
            "quoted SQLi must be detected, score={}",
            info.total_score
        );
        assert!(matches!(info.decision, WafDecision::Block(_)));
    }

    #[test]
    fn test_sqli_in_raw_query_string_without_equals() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/users",
            query_string: Some("%27%20OR%201%3D1 --"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.total_score >= 5,
            "parameterless SQLi query strings must be detected, score={}",
            info.total_score
        );
        assert!(matches!(info.decision, WafDecision::Block(_)));
    }

    #[test]
    fn test_sqli_in_raw_query_string_with_equals() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/users",
            query_string: Some("' OR 1=1 --"),
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };
        let info = engine.inspect(&req);
        assert!(
            info.total_score >= 5,
            "raw SQLi query fragments with '=' must be detected, score={}",
            info.total_score
        );
        assert!(matches!(info.decision, WafDecision::Block(_)));
    }

    #[test]
    fn test_inspect_with_event_has_correlation() {
        let engine = make_engine();
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "GET",
            path: "/api/v1/health",
            query_string: None,
            headers: &[("Host".into(), "example.com".into())],
            body: None,
        };

        let (_info, event) = engine.inspect_with_event(&req, None);
        assert_eq!(event.system, SecuritySystem::Waf);
        assert!(!event.correlation.correlation_id.is_empty());
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
                (
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
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
        // After the allowlist fix:path is allowed but query-string injection must still be caught.
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
        assert!(
            info.total_score >= 5,
            "SQLi in query string must be caught on allowlisted path, score={}",
            info.total_score
        );
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
        assert_eq!(
            info.total_score, 0,
            "IP allowlisted request must bypass WAF"
        );
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
        assert!(
            info.total_score >= 5,
            "Command injection in header must be detected, score={}",
            info.total_score
        );
    }

    #[test]
    fn test_floor_char_boundary_helpers() {
        // ASCII: any index is a boundary
        assert_eq!(floor_char_boundary("abcdef", 3), 3);
        assert_eq!(floor_char_boundary("abcdef", 100), 6);
        // 3-byte chars: boundary at 3 lands mid-char → floors to 0
        assert_eq!(floor_char_boundary("日本語", 1), 0);
        assert_eq!(floor_char_boundary("日本語", 2), 0);
        assert_eq!(floor_char_boundary("日本語", 3), 3);
        assert_eq!(floor_char_boundary("日本語", 4), 3);
        assert_eq!(floor_char_boundary("日本語", 5), 3);
        assert_eq!(floor_char_boundary("日本語", 6), 6);
        // Empty and zero
        assert_eq!(floor_char_boundary("", 0), 0);
        assert_eq!(floor_char_boundary("日本", 0), 0);
    }

    #[test]
    fn test_oversized_body_leading_content_is_inspected() {
        // Bug (fail-first): body truncation kept the bytes AFTER the cap, so
        // an attack placed in the FIRST bytes of an oversized body was never
        // inspected (and a 100MB body with a 1MB cap yielded a 99MB scan).
        let engine = WafEngine::new(WafConfig {
            max_body_size: 1024,
            ..WafConfig::default()
        });
        let body = format!(
            "<script>alert(document.cookie)</script>{}",
            "A".repeat(8192)
        );
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/comments",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some(&body),
        };
        let info = engine.inspect(&req);
        assert!(
            matches!(info.decision, WafDecision::Block(_)),
            "attack in the first max_body_size bytes must be blocked, score={} matches={:?}",
            info.total_score,
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_oversized_body_scan_is_bounded() {
        // The tail beyond max_body_size must NOT be inspected (CPU bound) —
        // content that only appears after the cap cannot be flagged.
        let engine = WafEngine::new(WafConfig {
            max_body_size: 1024,
            ..WafConfig::default()
        });
        // SSRF + NoSQL operators only AFTER the cap.
        let body = format!(
            "{}http://169.254.169.254/latest/meta-data",
            "B".repeat(4096)
        );
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/urls",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some(&body),
        };
        let info = engine.inspect(&req);
        assert!(
            !matches!(info.decision, WafDecision::Block(_)),
            "content beyond the cap must not be scanned (got score={} matches={:?})",
            info.total_score,
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_oversized_body_tail_sql_not_scanned() {
        // Step-1 analyzers (SQLi) must also only see the head of the body.
        let engine = WafEngine::new(WafConfig {
            max_body_size: 1024,
            ..WafConfig::default()
        });
        let body = format!("{}' OR 1=1 --", "C".repeat(4096));
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/search",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some(&body),
        };
        let info = engine.inspect(&req);
        assert!(
            !matches!(info.decision, WafDecision::Block(_)),
            "SQLi payload placed after the cap must not be flagged, score={} matches={:?}",
            info.total_score,
            info.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_multibyte_char_at_truncation_boundary_does_not_panic() {
        // The cut point must land on a UTF-8 char boundary even when the
        // body is multi-byte text (3-byte CJK chars around the cap).
        // 1025 is intentionally mid-char for the 3-byte CJK run.
        let engine = WafEngine::new(WafConfig {
            max_body_size: 1025,
            ..WafConfig::default()
        });
        let body = "x".repeat(1024) + &"日本語テスト".repeat(500);
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/notes",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some(&body),
        };
        let info = engine.inspect(&req); // must not panic
        assert!(info.total_score < u32::MAX);
    }

    #[test]
    fn test_paranoia_level_skips_high_level_rules() {
        // 942400 (SQL comment evasion) is a PL2 rule in the catalog: at
        // paranoia_level 1 it must be skipped, at the default level 2 kept.
        let payload = "UN/**/ION SE/**/LECT 1,2,3";
        let engine = WafEngine::new(WafConfig {
            paranoia_level: 1,
            ..WafConfig::default()
        });
        let req = HttpRequest {
            client_ip: "10.0.0.1".parse().expect("valid IP"),
            method: "POST",
            path: "/api/search",
            query_string: None,
            headers: &[
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: Some(payload),
        };
        let info = engine.inspect(&req);
        assert!(
            !info.matches.iter().any(|m| m.rule_id == 942400),
            "PL2 rule 942400 must be skipped at paranoia level 1"
        );

        let engine2 = make_engine(); // default paranoia_level = 2
        let info2 = engine2.inspect(&req);
        assert!(
            info2.matches.iter().any(|m| m.rule_id == 942400),
            "PL2 rule 942400 must fire at the default paranoia level 2"
        );
    }

    #[test]
    fn test_is_allowlisted_path_segment_prefix_only() {
        let entries = vec!["/static".to_string(), "/health".to_string()];
        assert!(is_allowlisted_path("/static", &entries));
        assert!(is_allowlisted_path("/static/", &entries));
        assert!(is_allowlisted_path("/static/css/app.css", &entries));
        assert!(is_allowlisted_path("/health", &entries));
        assert!(!is_allowlisted_path("/staticX/admin", &entries));
        assert!(!is_allowlisted_path("/staticsecret", &entries));
        assert!(!is_allowlisted_path("/", &entries));
        assert!(!is_allowlisted_path("/api", &entries));
    }
}
