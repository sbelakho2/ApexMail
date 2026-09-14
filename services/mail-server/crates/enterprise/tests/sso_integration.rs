//! End-to-end SSO integration tests.
//!
//! These tests validate the public API of the SSO module across both SAML and OIDC
//! flows. Every test provisions a canonical test database (soft-skipping only
//! when TEST_DATABASE_URL is unset), so the workspace suite runs them — they
//! used to be `#[ignore]`d and CI never executed them. Pure unit tests (PKCE,
//! token generation, serde round-trips) run unconditionally.
//!
//! # Running database-backed tests
//!
//! ```bash
//! # Start a test Postgres + Redis, then:
//! cargo test --test sso_integration -- --ignored
//! ```

use chrono::{TimeDelta, Utc};
use enterprise::config::Config;
use enterprise::sso::{
    generate_pkce_challenge, generate_pkce_verifier, generate_random_token, SSOService,
};
use enterprise::types::*;
use uuid::Uuid;

fn is_pkce_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

// ═══════════════════════════════════════════════════════════════════════════════
// PKCE helpers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn integration_pkce_verifier_generation() {
    // Verify PKCE verifier meets RFC 7636 requirements.
    let verifier = generate_pkce_verifier();
    assert!(
        verifier.len() >= 43,
        "PKCE verifier must be ≥ 43 chars per RFC 7636"
    );
    assert!(
        verifier.len() <= 128,
        "PKCE verifier must be ≤ 128 chars per RFC 7636"
    );
    assert!(
        verifier.chars().all(is_pkce_unreserved),
        "PKCE verifier must contain only unreserved characters"
    );
}

#[test]
fn integration_pkce_challenge_is_deterministic() {
    // Verify same verifier always produces same challenge.
    let verifier = "test-verifier-12345";
    let challenge1 = generate_pkce_challenge(verifier);
    let challenge2 = generate_pkce_challenge(verifier);
    assert_eq!(challenge1, challenge2);
}

#[test]
fn integration_pkce_challenge_differs_for_different_verifiers() {
    // Verify different verifiers produce different challenges.
    let c1 = generate_pkce_challenge("verifier-a");
    let c2 = generate_pkce_challenge("verifier-b");
    assert_ne!(c1, c2);
}

#[test]
fn integration_pkce_challenge_is_base64url() {
    // Verify challenge uses base64url encoding (no +, /, or =).
    let challenge = generate_pkce_challenge("some-verifier-value");
    assert!(!challenge.contains('+'), "base64url must not contain '+'");
    assert!(!challenge.contains('/'), "base64url must not contain '/'");
    assert!(
        !challenge.contains('='),
        "base64url must not contain padding '='"
    );
}

#[test]
fn integration_pkce_challenge_length() {
    // SHA-256 → 32 bytes → base64url encodes to 43 chars (no padding).
    let challenge = generate_pkce_challenge("test-verifier");
    assert_eq!(
        challenge.len(),
        43,
        "SHA-256 base64url challenge must be 43 chars"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Random token generation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn integration_random_token_length() {
    // Verify token byte length → hex string length: bytes * 2.
    for byte_len in [8, 16, 32, 64] {
        let token = generate_random_token(byte_len);
        assert_eq!(
            token.len(),
            byte_len * 2,
            "hex token length mismatch for byte_len={byte_len}"
        );
    }
}

#[test]
fn integration_random_token_is_valid_hex() {
    // Verify token contains only hex characters.
    let token = generate_random_token(32);
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "token must be valid hexadecimal"
    );
}

#[test]
fn integration_random_tokens_are_unique() {
    // Verify unique tokens for each call.
    let t1 = generate_random_token(32);
    let t2 = generate_random_token(32);
    let t3 = generate_random_token(32);
    assert_ne!(t1, t2);
    assert_ne!(t2, t3);
    assert_ne!(t1, t3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSO data type serde round-trips (no DB needed)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn integration_sso_login_redirect_serde_roundtrip() {
    // Verify SSOLoginRedirect serializes and deserializes correctly.
    let original = SSOLoginRedirect {
        redirect_url: "https://idp.example.com/sso?SAMLRequest=abc123".into(),
        request_id: "_saml_550e8400-e29b-41d4-a716-446655440000".into(),
    };
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: SSOLoginRedirect = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.redirect_url, original.redirect_url);
    assert_eq!(deserialized.request_id, original.request_id);
}

#[test]
fn integration_sso_session_info_serde_roundtrip() {
    // Verify SSOSessionInfo round-trips with all fields populated.
    let original = SSOSessionInfo {
        session_token: "tok_abc123def456".into(),
        email: "alice@example.com".into(),
        display_name: Some("Alice Smith".into()),
        groups: Some(vec!["admin".into(), "engineering".into()]),
        expires_at: Utc::now() + TimeDelta::try_hours(8).unwrap(),
    };
    let json = serde_json::to_value(&original).unwrap();
    assert_eq!(json["email"], "alice@example.com");
    assert_eq!(json["session_token"], "tok_abc123def456");

    let deserialized: SSOSessionInfo = serde_json::from_value(json).unwrap();
    assert_eq!(deserialized.email, original.email);
    assert_eq!(deserialized.display_name, original.display_name);
    assert_eq!(deserialized.groups, original.groups);
}

#[test]
fn integration_sso_callback_result_serde() {
    // Verify SSOCallbackResult round-trips for both new and existing users.
    for is_new in [true, false] {
        let result = SSOCallbackResult {
            session: SSOSessionInfo {
                session_token: format!("session_{}", Uuid::new_v4()),
                email: "user@example.com".into(),
                display_name: None,
                groups: None,
                expires_at: Utc::now() + TimeDelta::try_hours(8).unwrap(),
            },
            is_new_user: is_new,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["is_new_user"], serde_json::Value::Bool(is_new));
        let deserialized: SSOCallbackResult = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.is_new_user, is_new);
    }
}

#[test]
fn integration_sso_configure_request_all_fields() {
    // Verify SSOConfigureRequest with all fields populated.
    let req = SSOConfigureRequest {
        tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
        provider_type: "oidc".into(),
        domain: "company.com".into(),
        enabled: Some(true),
        entity_id: Some("urn:company:okta".into()),
        sso_url: Some("https://company.okta.com/sso".into()),
        certificate: Some(TEST_IDP_CERT_B64.into()),
        oidc_client_id: Some("0oa12345".into()),
        oidc_client_secret: Some("secret_value".into()),
        oidc_issuer: Some("https://company.okta.com".into()),
        attribute_mapping: Some(serde_json::json!({
            "email": "email",
            "firstName": "given_name",
            "lastName": "family_name",
        })),
        enforce_sso: Some(true),
        session_duration_hours: Some(24),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("oidc"));
    assert!(json.contains("attribute_mapping"));

    let deserialized: SSOConfigureRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.tenant_id, req.tenant_id);
    assert_eq!(deserialized.session_duration_hours, Some(24));
    assert!(deserialized.enforce_sso.unwrap_or(false));
}

#[test]
fn integration_sso_configure_request_minimal() {
    // Verify SSOConfigureRequest round-trips with only required fields.
    let req = SSOConfigureRequest {
        tenant_id: "tenant_abc".into(),
        provider_type: "saml".into(),
        domain: "example.com".into(),
        enabled: None,
        entity_id: None,
        sso_url: None,
        certificate: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        oidc_issuer: None,
        attribute_mapping: None,
        enforce_sso: None,
        session_duration_hours: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: SSOConfigureRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.provider_type, "saml");
    assert!(deserialized.enabled.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSOConfiguration serde (DB-row type)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn integration_sso_configuration_serde() {
    // Verify SSOConfiguration can be serialized/deserialized (used in API responses).
    let config = SSOConfiguration {
        id: Uuid::new_v4(),
        tenant_id: "tenant_01HZ".into(),
        provider_type: "saml".into(),
        enabled: true,
        domain: "mycorp.com".into(),
        metadata_url: Some("https://mycorp.com/sso/metadata".into()),
        entity_id: Some("urn:mycorp:saml".into()),
        sso_url: Some("https://mycorp.okta.com/sso".into()),
        slo_url: Some("https://mycorp.okta.com/slo".into()),
        certificate: Some(TEST_IDP_CERT_B64.into()),
        private_key_encrypted: None,
        oidc_client_id: None,
        oidc_client_secret_encrypted: None,
        oidc_issuer: None,
        oidc_redirect_uri: None,
        oidc_scopes: None,
        attribute_mapping: None,
        enforce_sso: true,
        allow_idp_initiated: false,
        session_duration_hours: 8,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
    };
    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(json["domain"], "mycorp.com");
    assert_eq!(json["provider_type"], "saml");
    assert_eq!(json["enabled"], true);

    let deserialized: SSOConfiguration = serde_json::from_value(json).unwrap();
    assert_eq!(deserialized.tenant_id, config.tenant_id);
    assert_eq!(deserialized.session_duration_hours, 8);
}

// ═══════════════════════════════════════════════════════════════════════════════
// OidcStateData
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn integration_oidc_state_data_construct() {
    // Verify OidcStateData can be constructed with both Some and None tenant_id.
    let with_tenant = OidcStateData {
        code_verifier: "abc".into(),
        domain: "example.com".into(),
        tenant_id: Some("t1".into()),
    };
    assert_eq!(with_tenant.tenant_id, Some("t1".into()));

    let without_tenant = OidcStateData {
        code_verifier: "xyz".into(),
        domain: "other.com".into(),
        tenant_id: None,
    };
    assert!(without_tenant.tenant_id.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration scenario tests (require database — run with --ignored)
// ═══════════════════════════════════════════════════════════════════════════════

/// Helper to create an SSOService on a CANONICAL, freshly provisioned test
/// database (the `ent_sso_*` tables come from the real migration chain).
///
/// `None` when TEST_DATABASE_URL is unset: the tests soft-skip instead of
/// connecting to an ambient database that may not exist. They used to be
/// `#[ignore]`d and demanded a hard-coded `apexmail_test`, so CI never ran
/// them.
/// A unique tenant id that FITS `VARCHAR(26)`, the canonical width every
/// `tenant_id` column in this schema uses. The fixtures used to build
/// `format!("test_saml_{uuid_simple}")` (42 characters), so every SSO
/// configuration insert failed with "value too long for type character
/// varying(26)" — invisible because the tests were `#[ignore]`d and CI never
/// ran them.
/// A REAL self-signed X.509 certificate (base64 DER), generated for these
/// tests only and embedded so the SAML validator can reach its SIGNATURE
/// check. The previous fixtures used placeholder strings ("MIID...test-cert"),
/// which the validator rejected as "certificate is too short" before any
/// signature logic ran — the tests were `#[ignore]`d, so nobody noticed.
/// The matching private key is deliberately NOT in the repository: signing a
/// valid assertion requires an IdP, which is what the signed unit tests in
/// `sso.rs` simulate.
const TEST_IDP_CERT_B64: &str = "\
MIIDZzCCAk+gAwIBAgIUHY0SPDdXQ7b0jyDDsSIN6sMaj7owDQYJKoZIhvcNAQELBQAwQzEpMCcG\
A1UEAwwgc3NvLWludGVncmF0aW9uLXRlc3QuZXhhbXBsZS5jb20xFjAUBgNVBAoMDUFwZXhNYWls\
IFRlc3QwHhcNMjYwOTE0MDk0ODA3WhcNMzYwOTExMDk0ODA3WjBDMSkwJwYDVQQDDCBzc28taW50\
ZWdyYXRpb24tdGVzdC5leGFtcGxlLmNvbTEWMBQGA1UECgwNQXBleE1haWwgVGVzdDCCASIwDQYJ\
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+TPEM/hPx0CqBm3LQy0zz07/adaI5UCI/CMsS1z+gu\
2qSdpZ/9v9zLqFaV/1Ic/HkJtd2qup4Khgs8q5x6GJF8gZpfXH1Zbw3JvcxYlS//pW9LTci3c3B8\
/9jZJumgQq4nvzJS0z4j4ONrbg2cgIdvrcZXSWQHucgpMZLUJKSUdhpOamL+h8VqesiUrCXxiE3/\
FTtPtBwZL7OLLE29RtQCJ5Yxw86bEEg4thDAVF904ZwL6cibcpM02xRvaavs+x3vwmn9KCoAQ0pa\
+xXS5tKAQhhGZRMZwCxUPJdWKB5qdm1gjk8B8uuGFg7pmBz7LBCDsWry29EWfl/sBr8BId8CAwEA\
AaNTMFEwHQYDVR0OBBYEFGDyyompGHXM0ow2M9n1fU29CS8qMB8GA1UdIwQYMBaAFGDyyompGHXM\
0ow2M9n1fU29CS8qMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKGveiTi9R/h\
TjtlvK1Ig75Q9pEPGbvGBUewoBAET6zAdgUmRZNr31KmPZ+UX80TedCsdUXJ2wfGknLAEUIIj9vZ\
JJjBT2GVb4azGddYLnQ2Ak6f4kRdzjZ8IqnX8ir6kR3pINV47jYAkRMaItLQ5LLNPLcfacCUElBr\
99W0hhsMs/9uxDjhWxvqgNeLUGy1rOYAxLXqBEfvKW2dl9i5ZoOpQcjToRrxBNqyIdBYWqkTlWeg\
fP7yLk9QCuz9hAwN4s56pK+5vTYcFotlL3bYhLg64tv5nnC7sX//LUOkiY7b5MsL2dPm81mRpjUg\
JK6JS6oEpSj9ibp3vFpP7xSWHwg=";

fn test_tenant(tag: &str) -> String {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let keep = 26usize.saturating_sub(tag.len() + 1);
    format!("{tag}_{}", &unique[..keep.min(unique.len())])
}

async fn setup_sso_service(test_name: &str) -> Option<(SSOService, sqlx::PgPool)> {
    // The SSO flows encrypt stored client secrets, so the service needs a
    // key: `SSO_ENCRYPTION_KEY` used to be left unset, which is why these
    // tests were `#[ignore]`d ("secret must not be empty"). A test-only key is
    // set here, before Config::from_env reads it.
    if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
        std::env::set_var("SSO_ENCRYPTION_KEY", "sso-integration-test-key-0123456789");
    }
    if std::env::var("LOG_STREAM_ENCRYPTION_KEY").is_err() {
        std::env::set_var(
            "LOG_STREAM_ENCRYPTION_KEY",
            "log-stream-test-key-0123456789",
        );
    }
    let pool =
        match migrator::test_support::fresh_canonical_pool(test_name, &format!("sso_{test_name}"))
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }?;
    let config = Config::from_env().expect("Config::from_env() should work in test env");
    Some((SSOService::new(pool.clone(), config), pool))
}

#[tokio::test]
async fn integration_full_saml_login_flow() {
    // Full SAML login flow:
    // 1. Configure SAML for a tenant
    // 2. Initiate SAML login (get redirect URL with AuthnRequest)
    // 3. Parse and validate SAML response
    // 4. Create SSO session
    // 5. Validate session token
    //
    // Requires a running test database.
    let Some((service, _pool)) = setup_sso_service("integration_full_saml_login_flow").await else {
        eprintln!("skipping integration_full_saml_login_flow: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_saml");
    let domain = "test-saml.example.com";

    // 1. Configure SAML
    let config = service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some(TEST_IDP_CERT_B64.into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(8),
        })
        .await
        .expect("Configure SAML");

    assert!(config.success);
    assert_eq!(config.data.as_ref().unwrap().domain, domain);

    // 2. Initiate SAML login
    let redirect = service
        .initiate_saml_login(domain)
        .await
        .expect("Initiate SAML login")
        .data
        .expect("Should get redirect");

    assert!(redirect.redirect_url.contains("SAMLRequest="));
    assert!(redirect.redirect_url.contains("RelayState="));
    assert!(redirect.request_id.starts_with("_saml_"));

    // 3. Construct a valid SAML response and validate it
    let valid_saml_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_test-response" Version="2.0" IssueInstant="{}" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:test</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_test-assertion" IssueInstant="{}">
    <saml:Issuer>urn:apexmail:test</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@test-saml.example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="{}">
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
        Utc::now().to_rfc3339(),
        Utc::now().to_rfc3339(),
        (Utc::now() + TimeDelta::try_hours(1).unwrap()).to_rfc3339(),
    );

    // The response above carries NO XML signature. The validator requires one
    // (the IdP's configured certificate is a hard precondition), so this is
    // the security contract to assert: an unsigned assertion never yields a
    // session. Reason-specific rejections (expired / wrong audience / wrong
    // issuer) are covered by the unit tests in `sso.rs`, which sign their
    // assertions.
    let refused = service
        .parse_and_validate_saml_response(&valid_saml_xml, domain)
        .await;
    assert!(
        refused.is_err(),
        "an unsigned SAML assertion must never validate (err expected)"
    );

    // 4. Handle SAML callback (create session)
    let callback = service
        .handle_saml_callback(
            &tenant_id,
            "alice@test-saml.example.com",
            Some("Alice"),
            "ext-alice-001",
            None,
            None,
        )
        .await
        .expect("Handle SAML callback")
        .data
        .expect("Should get callback result");

    assert_eq!(callback.session.email, "alice@test-saml.example.com");
    assert!(callback.is_new_user);
    assert!(!callback.session.session_token.is_empty());

    // 5. Validate the session token
    let session = service
        .validate_session(&callback.session.session_token)
        .await
        .expect("Validate session")
        .expect("Session should be valid");

    assert_eq!(session.email, "alice@test-saml.example.com");
    assert_eq!(session.external_user_id, "ext-alice-001");
    assert_eq!(session.provider_type, "saml");
}

#[tokio::test]
async fn integration_full_oidc_login_flow() {
    // Full OIDC login flow:
    // 1. Configure OIDC for a tenant
    // 2. Initiate OIDC login (get auth URL with PKCE params)
    // 3. Validate OIDC state
    // 4. Handle OIDC callback (create session)
    // 5. Validate session token
    //
    // Requires a running test database and Redis.
    let Some((service, _pool)) = setup_sso_service("integration_full_oidc_login_flow").await else {
        eprintln!("skipping integration_full_oidc_login_flow: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_oidc");
    let domain = "test-oidc.example.com";

    // 1. Configure OIDC
    let config = service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "oidc".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: None,
            certificate: None,
            oidc_client_id: Some("test-client-id".into()),
            oidc_client_secret: Some("test-client-secret".into()),
            oidc_issuer: Some("https://test-idp.example.com".into()),
            attribute_mapping: Some(serde_json::json!({
                "email": "email",
                "name": "name",
            })),
            enforce_sso: Some(true),
            session_duration_hours: Some(8),
        })
        .await
        .expect("Configure OIDC");

    assert!(config.success);

    // 2. Initiate OIDC login (will use DB fallback since no Redis)
    let redirect = service
        .initiate_oidc_login(domain)
        .await
        .expect("Initiate OIDC login")
        .data
        .expect("Should get redirect");

    assert!(redirect.redirect_url.contains("/authorize?"));
    assert!(redirect.redirect_url.contains("client_id="));
    assert!(redirect.redirect_url.contains("response_type=code"));
    assert!(redirect.redirect_url.contains("code_challenge="));
    assert!(redirect.redirect_url.contains("code_challenge_method=S256"));
    assert!(redirect.redirect_url.contains("state="));

    // 3. Validate the OIDC state from DB
    let state = &redirect.request_id;
    let state_data = service
        .validate_oidc_state(state)
        .await
        .expect("Validate OIDC state")
        .expect("State should exist in DB");

    assert_eq!(state_data.domain, domain);
    assert!(!state_data.code_verifier.is_empty());
    // PKCE: verify the challenge matches
    let expected_challenge = generate_pkce_challenge(&state_data.code_verifier);
    assert!(redirect.redirect_url.contains(&expected_challenge));

    // 4. Handle OIDC callback (mock token exchange → create session)
    let callback = service
        .handle_oidc_callback(
            &tenant_id,
            "bob@test-oidc.example.com",
            Some("Bob"),
            "ext-bob-001",
            Some(serde_json::json!(["admin", "users"])),
        )
        .await
        .expect("Handle OIDC callback")
        .data
        .expect("Should get callback result");

    assert_eq!(callback.session.email, "bob@test-oidc.example.com");
    assert!(callback.is_new_user);
    assert_eq!(
        callback.session.groups,
        Some(vec!["admin".into(), "users".into()])
    );

    // 5. Validate the session token
    let session = service
        .validate_session(&callback.session.session_token)
        .await
        .expect("Validate session")
        .expect("Session should be valid");

    assert_eq!(session.email, "bob@test-oidc.example.com");
    assert_eq!(session.external_user_id, "ext-bob-001");
    assert_eq!(session.provider_type, "oidc");
}

#[tokio::test]
async fn integration_session_expiry() {
    // A session that has outlived its duration must stop validating. The test
    // used `session_duration_hours: Some(0)` and a 100ms sleep with a
    // "may or may not be expired" assertion — the schema rejects 0
    // (`CHECK (session_duration_hours > 0)`) and the assertion could not
    // fail, so it proved nothing. It now configures the minimum legal
    // duration, then moves the stored expiry into the past: elapsed time is
    // simulated exactly instead of raced.
    let Some((service, pool)) = setup_sso_service("integration_session_expiry").await else {
        eprintln!("skipping integration_session_expiry: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_expiry");
    let domain = "test-expiry.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some(TEST_IDP_CERT_B64.into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(1),
        })
        .await
        .expect("Configure");

    let callback = service
        .handle_saml_callback(
            &tenant_id,
            "expired@test.com",
            Some("Expired User"),
            "ext-expired-001",
            None,
            None,
        )
        .await
        .expect("Handle callback")
        .data
        .expect("Should get callback result");
    let session_token = callback.session.session_token;

    assert!(
        service
            .validate_session(&session_token)
            .await
            .expect("Validate session")
            .is_some(),
        "a fresh session must validate"
    );

    // Simulate the session's hour having elapsed.
    sqlx::query(
        "UPDATE ent_sso_sessions SET expires_at = NOW() - interval '1 minute' \
         WHERE session_token = $1",
    )
    .bind(&session_token)
    .execute(&pool)
    .await
    .expect("expire the session");

    let expired = service
        .validate_session(&session_token)
        .await
        .expect("Validate session after expiry");
    assert!(
        expired.is_none(),
        "an expired session must not validate: {expired:?}"
    );
}

#[tokio::test]
async fn integration_saml_rejects_expired_assertion() {
    // Verify that an expired SAML assertion (NotOnOrAfter in the past) is rejected.
    //
    // Requires a running test database.
    let Some((service, _pool)) =
        setup_sso_service("integration_saml_rejects_expired_assertion").await
    else {
        eprintln!("skipping integration_saml_rejects_expired_assertion: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_expired_assert");
    let domain = "test-expired-assert.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some(TEST_IDP_CERT_B64.into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(8),
        })
        .await
        .expect("Configure");

    // SAML response with NotOnOrAfter set to a past date (already expired)
    let expired_saml_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_test-expired" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:test</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_expired-assertion" IssueInstant="2020-01-01T00:00:01Z">
    <saml:Issuer>urn:apexmail:test</saml:Issuer>
    <saml:Subject>
      <saml:NameID>old@test.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="2020-06-01T00:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#.to_string();

    let result = service
        .parse_and_validate_saml_response(&expired_saml_xml, domain)
        .await;

    // Refused. Because the fixture is UNSIGNED and the signature is verified
    // before any claim is read, the refusal is the signature precondition; the
    // expiry branch itself is asserted by the SIGNED unit tests in `sso.rs`.
    // Reproducing a reason-specific rejection here would require an IdP to sign
    // the fixture, which is exactly why this file was `#[ignore]`d.
    let error = result.err().expect("an unsigned assertion must be refused");
    assert!(
        error.contains("signature")
            || error.contains("Signature")
            || error.contains("No IdP certificate"),
        "an unsigned assertion must be refused on its signature, got: {error}"
    );
}

#[tokio::test]
async fn integration_saml_rejects_issuer_mismatch() {
    // Verify that a SAML response with mismatched Issuer is rejected.
    //
    // Requires a running test database.
    let Some((service, _pool)) =
        setup_sso_service("integration_saml_rejects_issuer_mismatch").await
    else {
        eprintln!("skipping integration_saml_rejects_issuer_mismatch: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_issuer_mismatch");
    let domain = "test-issuer-mismatch.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:correct-id".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some(TEST_IDP_CERT_B64.into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(8),
        })
        .await
        .expect("Configure");

    // SAML response with wrong Issuer
    let bad_issuer_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_test-bad-issuer" Version="2.0" IssueInstant="{}" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:evil:attacker</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion-bad" IssueInstant="{}">
    <saml:Issuer>urn:evil:attacker</saml:Issuer>
    <saml:Subject>
      <saml:NameID>hacker@evil.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="{}">
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
        Utc::now().to_rfc3339(),
        Utc::now().to_rfc3339(),
        (Utc::now() + TimeDelta::try_hours(1).unwrap()).to_rfc3339(),
    );

    let result = service
        .parse_and_validate_saml_response(&bad_issuer_xml, domain)
        .await;
    // Refused on the signature precondition (unsigned fixture); the issuer
    // branch is asserted by the signed unit tests in `sso.rs`.
    let error = result.err().expect("an unsigned assertion must be refused");
    assert!(
        error.contains("signature")
            || error.contains("Signature")
            || error.contains("No IdP certificate"),
        "an unsigned assertion must be refused on its signature, got: {error}"
    );
}

#[tokio::test]
async fn integration_saml_rejects_audience_mismatch() {
    // Verify that a SAML response with mismatched AudienceRestriction is rejected.
    //
    // Requires a running test database.
    let Some((service, _pool)) =
        setup_sso_service("integration_saml_rejects_audience_mismatch").await
    else {
        eprintln!("skipping integration_saml_rejects_audience_mismatch: set TEST_DATABASE_URL");
        return;
    };
    let tenant_id = test_tenant("t_aud_mismatch");
    let domain = "test-aud-mismatch.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some(TEST_IDP_CERT_B64.into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(8),
        })
        .await
        .expect("Configure");

    let bad_audience_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_test-bad-aud" Version="2.0" IssueInstant="{}" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:test</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion-bad-aud" IssueInstant="{}">
    <saml:Issuer>urn:apexmail:test</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@test.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="{}">
      <saml:AudienceRestriction>
        <saml:Audience>https://evil.com/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
        Utc::now().to_rfc3339(),
        Utc::now().to_rfc3339(),
        (Utc::now() + TimeDelta::try_hours(1).unwrap()).to_rfc3339(),
    );

    let result = service
        .parse_and_validate_saml_response(&bad_audience_xml, domain)
        .await;

    // Refused on the signature precondition (unsigned fixture); the audience
    // branch is asserted by the signed unit tests in `sso.rs`.
    let error = result.err().expect("an unsigned assertion must be refused");
    assert!(
        error.contains("signature")
            || error.contains("Signature")
            || error.contains("No IdP certificate"),
        "an unsigned assertion must be refused on its signature, got: {error}"
    );
}

#[tokio::test]
async fn integration_saml_not_configured_for_domain() {
    // Verify that SAML operations for an unconfigured domain return appropriate errors.
    let Some((service, _pool)) =
        setup_sso_service("integration_saml_not_configured_for_domain").await
    else {
        eprintln!("skipping integration_saml_not_configured_for_domain: set TEST_DATABASE_URL");
        return;
    };
    let unknown_domain = "unknown.example.com";

    let result = service.initiate_saml_login(unknown_domain).await;
    assert!(
        result.is_ok(),
        "Should return OK with error result, not fail"
    );
    let api_result = result.unwrap();
    assert!(!api_result.success);
}
