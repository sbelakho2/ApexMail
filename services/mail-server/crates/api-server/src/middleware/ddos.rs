use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ddos_protection::{evaluate_request, MiddlewareAction, RequestContextBuilder};

use crate::middleware::auth::AuthUser;
use crate::middleware::rate_limiter::extract_public_client_ip;
use crate::state::AppState;

pub async fn ddos_protection_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ctx = build_request_context(&req, &state);

    match evaluate_request(&state.ddos_protector, &ctx).await {
        MiddlewareAction::Allow => next.run(req).await,
        MiddlewareAction::Challenge { status, body } => (
            status_code(status, StatusCode::TOO_MANY_REQUESTS),
            [(CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        MiddlewareAction::RateLimit {
            status,
            retry_after_secs,
        } => {
            let mut response = (
                status_code(status, StatusCode::TOO_MANY_REQUESTS),
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "DDOS_RATE_LIMITED",
                        "message": "request temporarily rate limited"
                    }
                })),
            )
                .into_response();
            response
                .headers_mut()
                .insert("Retry-After", retry_after_secs.into());
            response
        }
        MiddlewareAction::Block { status } => (
            status_code(status, StatusCode::FORBIDDEN),
            axum::Json(serde_json::json!({
                "error": {
                    "code": "DDOS_BLOCKED",
                    "message": "request blocked"
                }
            })),
        )
            .into_response(),
    }
}

fn build_request_context(req: &Request<Body>, state: &AppState) -> ddos_protection::RequestContext {
    let socket_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let ip = if let Some(socket_ip) = socket_ip {
        extract_public_client_ip(req.headers(), socket_ip, &state.config.trusted_proxies)
            .parse::<IpAddr>()
            .unwrap_or(socket_ip)
    } else {
        tracing::warn!(path = %req.uri().path(), "ddos middleware missing ConnectInfo; using loopback placeholder");
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };

    let mut builder = RequestContextBuilder::new(ip, req.uri().path(), req.method().as_str());

    if let Some(user_agent) = req.headers().get(USER_AGENT).and_then(|value| value.to_str().ok()) {
        builder = builder.user_agent(user_agent);
    }

    if let Some(body_size) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        builder = builder.body_size(body_size);
    }

    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        builder = builder.tenant_id(&auth_user.tenant_id);
        if let Some(api_key_id) = auth_user.api_key_id.as_deref() {
            builder = builder.api_key_id(api_key_id);
        }
    }

    builder.build()
}

fn status_code(raw: u16, fallback: StatusCode) -> StatusCode {
    StatusCode::from_u16(raw).unwrap_or(fallback)
}