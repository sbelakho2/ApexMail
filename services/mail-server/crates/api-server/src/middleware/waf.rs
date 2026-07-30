use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, State};
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::state::AppState;
use waf_engine::{HttpRequest, WafDecision};

const WAF_MAX_BODY_SIZE: usize = 1_048_576;

pub async fn waf_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let engine = &state.waf_engine;



    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|s| s.to_string());
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();

    let socket_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let client_ip: IpAddr = if let Some(socket_ip) = socket_ip {
        extract_public_client_ip(req.headers(), socket_ip, &state.config.trusted_proxies)
            .parse::<IpAddr>()
            .unwrap_or(socket_ip)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };

    let is_mutation = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH
    );

    if is_mutation {
        let (parts, body) = req.into_parts();
        let body_bytes = to_bytes(body, WAF_MAX_BODY_SIZE)
            .await
            .unwrap_or_default();
        let body_str = std::str::from_utf8(&body_bytes).ok();

        let waf_req = HttpRequest {
            client_ip,
            method: method.as_str(),
            path: &path,
            query_string: query.as_deref(),
            headers: &headers,
            body: body_str,
        };

        let info = engine.inspect(&waf_req);
        match info.decision {
            WafDecision::Block(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "data": null,
                        "error": {
                            "code": "WAF_BLOCKED",
                            "message": "request blocked by web application firewall"
                        },
                        "meta": null
                    })),
                )
                    .into_response();
            }
            WafDecision::Allow | WafDecision::Monitor => {}
        }

        let req = Request::from_parts(parts, Body::from(body_bytes));
        next.run(req).await
    } else {
        let waf_req = HttpRequest {
            client_ip,
            method: method.as_str(),
            path: &path,
            query_string: query.as_deref(),
            headers: &headers,
            body: None,
        };

        let info = engine.inspect(&waf_req);
        match info.decision {
            WafDecision::Block(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "data": null,
                        "error": {
                            "code": "WAF_BLOCKED",
                            "message": "request blocked by web application firewall"
                        },
                        "meta": null
                    })),
                )
                    .into_response();
            }
            WafDecision::Allow | WafDecision::Monitor => {}
        }

        next.run(req).await
    }
}
