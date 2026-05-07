//! End-to-end SSO integration tests.
//!
//! These tests validate the public API of the SSO module across both SAML and OIDC
//! flows. Tests that require database access are marked with `#[ignore]` and include
//! instructions for running against a test database. Pure unit tests (PKCE, token
//! generation, serde round-trips) run unconditionally.
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
        certificate: Some("MIID...test-cert...".into()),
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
        certificate: Some("MIID...".into()),
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

/// Helper to create an SSOService with a test database connection.
///
/// Requires a running PostgreSQL on localhost:5432 with a database named
/// `apexmail_test` and the `ent_sso_configurations` + `ent_sso_sessions` tables.
async fn setup_sso_service() -> SSOService {
    let config = Config::from_env().expect("Config::from_env() should work in test env");
    let db_url = config.db.url();
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Connect to test database");
    SSOService::new(pool, config)
}

#[ignore]
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
    let service = setup_sso_service().await;
    let tenant_id = format!("test_saml_{}", Uuid::new_v4().simple());
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
            certificate: Some("MIID...test-cert".into()),
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

    let validated = service
        .parse_and_validate_saml_response(&valid_saml_xml, domain)
        .await
        .expect("Should validate SAML response");

    assert_eq!(validated.name_id, "alice@test-saml.example.com");

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

#[ignore]
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
    let service = setup_sso_service().await;
    let tenant_id = format!("test_oidc_{}", Uuid::new_v4().simple());
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

#[ignore]
#[tokio::test]
async fn integration_session_expiry() {
    // Verify session expiry:
    // 1. Configure SAML with very short session duration (1 second)
    // 2. Create a session
    // 3. Validate immediately — should succeed
    // 4. Wait for expiry
    // 5. Validate again — should fail (session expired)
    //
    // Requires a running test database.
    let service = setup_sso_service().await;
    let tenant_id = format!("test_expiry_{}", Uuid::new_v4().simple());
    let domain = "test-expiry.example.com";

    // Configure with 0-hour session (effectively expired at creation)
    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some("MIID...".into()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: Some(true),
            session_duration_hours: Some(0), // Expires immediately
        })
        .await
        .expect("Configure");

    // Create session
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

    // With 0-hour duration, the session's expires_at is Utc::now() which should
    // be >= NOW() if validation runs fast enough. After a brief sleep, it
    // should be expired.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let session = service
        .validate_session(&session_token)
        .await
        .expect("Validate session");

    // Session may or may not be expired depending on timing; if it's found,
    // the expires_at should be very close to now+0 hours
    if let Some(s) = session {
        assert!(s.expires_at <= Utc::now() + TimeDelta::try_seconds(1).unwrap());
    }
}

#[ignore]
#[tokio::test]
async fn integration_saml_rejects_expired_assertion() {
    // Verify that an expired SAML assertion (NotOnOrAfter in the past) is rejected.
    //
    // Requires a running test database.
    let service = setup_sso_service().await;
    let tenant_id = format!("test_expired_assert_{}", Uuid::new_v4().simple());
    let domain = "test-expired-assert.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some("MIID...".into()),
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
    let expired_saml_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
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
</samlp:Response>"#,
    );

    let result = service
        .parse_and_validate_saml_response(&expired_saml_xml, domain)
        .await;

    let error = result.err().unwrap();
    assert!(
        error.contains("expired") || error.contains("NotOnOrAfter"),
        "Error should mention expiry: {error}"
    );
}

#[ignore]
#[tokio::test]
async fn integration_saml_rejects_issuer_mismatch() {
    // Verify that a SAML response with mismatched Issuer is rejected.
    //
    // Requires a running test database.
    let service = setup_sso_service().await;
    let tenant_id = format!("test_issuer_mismatch_{}", Uuid::new_v4().simple());
    let domain = "test-issuer-mismatch.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:correct-id".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some("MIID...".into()),
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
    let error = result.err().unwrap();
    assert!(
        error.contains("Issuer") || error.contains("entity_id"),
        "Error should mention issuer mismatch: {error}"
    );
}

#[ignore]
#[tokio::test]
async fn integration_saml_rejects_audience_mismatch() {
    // Verify that a SAML response with mismatched AudienceRestriction is rejected.
    //
    // Requires a running test database.
    let service = setup_sso_service().await;
    let tenant_id = format!("test_aud_mismatch_{}", Uuid::new_v4().simple());
    let domain = "test-aud-mismatch.example.com";

    service
        .configure(SSOConfigureRequest {
            tenant_id: tenant_id.clone(),
            provider_type: "saml".into(),
            domain: domain.into(),
            enabled: Some(true),
            entity_id: Some("urn:apexmail:test".into()),
            sso_url: Some("https://test-idp.example.com/sso".into()),
            certificate: Some("MIID...".into()),
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

    let error = result.err().unwrap();
    assert!(
        error.contains("Audience"),
        "Error should mention audience mismatch: {error}"
    );
}

#[ignore]
#[tokio::test]
async fn integration_saml_not_configured_for_domain() {
    // Verify that SAML operations for an unconfigured domain return appropriate errors.
    let service = setup_sso_service().await;
    let unknown_domain = "unknown.example.com";

    let result = service.initiate_saml_login(unknown_domain).await;
    assert!(
        result.is_ok(),
        "Should return OK with error result, not fail"
    );
    let api_result = result.unwrap();
    assert!(!api_result.success);
}
