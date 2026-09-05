//! WAF request screening (audit F-WIRING-1 remediation, first integration).
//!
//! The `waf-engine` crate (SQLi/XSS/traversal/command-injection/SSRF/
//! protocol-anomaly rules) was previously compiled into nothing. This
//! middleware wires it into the public request path in **monitor mode by
//! default**: every decision the engine would block is logged with its rule
//! matches, and only `WAF_ENFORCE=true` turns those into 403 responses.
//! Monitor-first is deliberate — the engine's rules are broad and the cost
//! of a false positive on a transactional email API is a failed customer
//! send, so operators watch the logs and then opt into enforcement.
//!
//! Scope of inspection (v1): method, path, query string and headers.
//! Request BODIES are not inspected — buffering every JSON body through the
//! middleware would tax the hot path, and the API surface validates bodies
//! structurally at the handler layer. Query-string and header attacks are
//! the surfaces handlers do NOT re-validate, which is what the WAF adds
//! here.

use std::net::{IpAddr, Ipv4Addr};

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use waf_engine::{HttpRequest as WafHttpRequest, ThreatInfo, WafDecision};

use crate::state::AppState;

pub async fn waf_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(engine) = state.waf_engine.as_ref() else {
        return next.run(req).await;
    };

    let threat = {
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(str::to_string);
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        // The middleware runs behind the same ConnectInfo wiring as the
        // ddos middleware; without it (tests), the loopback identity is
        // used — the WAF has no IP allowlist entries by default so this
        // only affects which bucket an allowlisted client would hit.
        let client_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let waf_req = WafHttpRequest {
            client_ip,
            method: &method,
            path: &path,
            query_string: query.as_deref(),
            headers: &headers,
            body: None,
        };
        engine.inspect(&waf_req)
    };

    match threat.decision {
        WafDecision::Allow => next.run(req).await,
        WafDecision::Monitor => {
            log_threat("WAF monitor", &threat);
            next.run(req).await
        }
        WafDecision::Block(status) => {
            if state.config.waf_enforce {
                log_threat("WAF block", &threat);
                blocked_response(status, &threat)
            } else {
                // Monitor mode: the engine WOULD have blocked; record it
                // at WARN so operators can size the false-positive rate
                // before flipping WAF_ENFORCE.
                log_threat("WAF would-block (monitor mode)", &threat);
                next.run(req).await
            }
        }
    }
}

/// Bounded threat summary for logs — the matches' rule ids, never the raw
/// request bytes (headers can carry PII).
fn log_threat(label: &str, threat: &ThreatInfo) {
    let rules: Vec<u32> = threat.matches.iter().map(|m| m.rule_id).take(16).collect();
    tracing::warn!(
        decision = label,
        score = threat.total_score,
        rules = ?rules,
        "WAF screening verdict"
    );
}

fn blocked_response(status: u16, threat: &ThreatInfo) -> Response {
    let code = if (400..599).contains(&status) {
        axum::http::StatusCode::from_u16(status)
            .unwrap_or(axum::http::StatusCode::FORBIDDEN)
    } else {
        axum::http::StatusCode::FORBIDDEN
    };
    (
        code,
        axum::Json(serde_json::json!({
            "error": {
                "code": "WAF_BLOCKED",
                "message": "request blocked by security screening",
                "anomaly_score": threat.total_score
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_engine::{WafConfig, WafEngine};

    fn engine() -> WafEngine {
        WafEngine::new(WafConfig::default())
    }

    #[test]
    fn clean_request_is_allowed() {
        let e = engine();
        let threat = e.inspect(&WafHttpRequest {
            client_ip: "203.0.113.9".parse().unwrap(),
            method: "GET",
            path: "/v1/messages",
            query_string: Some("limit=20&status=sent"),
            headers: &[],
            body: None,
        });
        assert!(matches!(threat.decision, WafDecision::Allow));
    }

    #[test]
    fn xss_query_string_is_flagged() {
        let e = engine();
        let threat = e.inspect(&WafHttpRequest {
            client_ip: "203.0.113.9".parse().unwrap(),
            method: "GET",
            path: "/v1/messages",
            query_string: Some("q=<script>alert(1)</script>"),
            headers: &[],
            body: None,
        });
        assert!(
            !matches!(threat.decision, WafDecision::Allow),
            "XSS payload in the query must at least monitor: {:?}",
            threat.decision
        );
        assert!(!threat.matches.is_empty());
    }

    #[test]
    fn sql_injection_path_is_flagged() {
        let e = engine();
        let threat = e.inspect(&WafHttpRequest {
            client_ip: "203.0.113.9".parse().unwrap(),
            method: "GET",
            path: "/v1/contacts/1%20OR%201%3D1--",
            query_string: None,
            headers: &[],
            body: None,
        });
        assert!(!matches!(threat.decision, WafDecision::Allow));
    }

    #[test]
    fn blocked_response_uses_engine_status() {
        let resp = blocked_response(403, &ThreatInfo {
            total_score: 9,
            matches: vec![],
            decision: WafDecision::Block(403),
        });
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        // Out-of-range engine statuses degrade to 403, never panic.
        let resp = blocked_response(999, &ThreatInfo {
            total_score: 9,
            matches: vec![],
            decision: WafDecision::Block(999),
        });
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }
}
