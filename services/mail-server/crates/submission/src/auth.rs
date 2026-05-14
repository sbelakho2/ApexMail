//! Authentication Handler
//!
//! Handles SMTP AUTH mechanisms (PLAIN, LOGIN).

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use moka::sync::Cache;
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, warn};
use zeroize::Zeroize;

/// #174:Rate limiter for authentication attempts per IP.
/// Tracks failure count per IP; rejects after MAX_AUTH_FAILURES within the TTL window.
const MAX_AUTH_FAILURES: u64 = 5;
static AUTH_FAIL_CACHE: LazyLock<Cache<IpAddr, u64>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(50_000)
        .time_to_live(Duration::from_secs(300)) // 5-minute window
        .build()
});

// O-2.3:Per-username lockout tracking — prevents repeated auth attempts against the same account
const MAX_USERNAME_FAILURES: u64 = 5;
/// Tracks authentication failures per username to prevent credential stuffing.
static USERNAME_FAIL_CACHE: LazyLock<Cache<String, u64>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(300)) // 5-minute window
        .build()
});

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub success: bool,
    pub account_id: Option<uuid::Uuid>,
    pub email: Option<String>,
    pub error: Option<String>,
}

/// Authenticate with PLAIN mechanism
/// Format:\0username\0password (base64 encoded)
pub async fn auth_plain(credentials: &str, pool: &PgPool, peer_ip: IpAddr) -> Result<AuthResult> {
    // #174:Check rate limit before processing
    if is_rate_limited(peer_ip) {
        warn!(peer = %peer_ip, "Auth rate limited");
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Too many authentication failures; try again later".to_string()),
        });
    }

    let mut decoded = BASE64
        .decode(credentials)
        .map_err(|e| anyhow!("Invalid base64: {}", e))?;

    // O-2.2:Reject oversized SASL payload (> 4 KiB) to prevent injection
    if decoded.len() > 4096 {
        decoded.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Authentication payload too large".to_string()),
        });
    }

    // O-2.2:Validate that the decoded payload contains only printable ASCII and null separators
    if !decoded
        .iter()
        .all(|&b| b == 0 || b.is_ascii_graphic() || b == b' ')
    {
        decoded.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid characters in authentication payload".to_string()),
        });
    }

    let decoded_str = String::from_utf8_lossy(&decoded).into_owned();
    let parts: Vec<&str> = decoded_str.split('\0').collect();

    // PLAIN format:[authzid]\0authcid\0passwd
    let (username, password) = match parts.as_slice() {
        [_, user, pass] => (*user, *pass),
        [user, pass] => (*user, *pass),
        _ => {
            decoded.zeroize();
            return Ok(AuthResult {
                success: false,
                account_id: None,
                email: None,
                error: Some("Invalid PLAIN credentials format".to_string()),
            });
        }
    };

    if !is_valid_sasl_field(username) || !is_valid_sasl_field(password) {
        decoded.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid characters in authentication payload".to_string()),
        });
    }

    // O-2.3:Check per-username lockout before verifying
    if is_username_rate_limited(username) {
        warn!(peer = %peer_ip, username = %username, "Username auth rate limited");
        decoded.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Too many authentication failures; try again later".to_string()),
        });
    }

    let result = verify_credentials(username, password, pool).await?;
    // O-2.1:Zeroize the decoded buffer after use
    decoded.zeroize();
    if !result.success {
        record_auth_failure(peer_ip);
        record_username_failure(username);
    } else {
        // Reset on success
        AUTH_FAIL_CACHE.invalidate(&peer_ip);
        USERNAME_FAIL_CACHE.invalidate(username);
    }
    Ok(result)
}

/// Authenticate with LOGIN mechanism
/// Two-step:username then password (both base64 encoded)
pub async fn auth_login(
    username_b64: &str,
    password_b64: &str,
    pool: &PgPool,
    peer_ip: IpAddr,
) -> Result<AuthResult> {
    // #174:Check rate limit before processing
    if is_rate_limited(peer_ip) {
        warn!(peer = %peer_ip, "Auth rate limited");
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Too many authentication failures; try again later".to_string()),
        });
    }

    let username_bytes = BASE64
        .decode(username_b64)
        .map_err(|e| anyhow!("Invalid base64 username: {}", e))?;

    let password_bytes = BASE64
        .decode(password_b64)
        .map_err(|e| anyhow!("Invalid base64 password: {}", e))?;

    // O-2.1:Convert password bytes to String (consumes the Vec to avoid a clone),
    // then after verification convert back to Vec<u8> and zeroize.
    // Using `into_bytes()` gives us a Vec<u8> which implements Zeroize.
    let password =
        String::from_utf8(password_bytes).map_err(|e| anyhow!("Invalid UTF-8 password: {}", e))?;

    let username =
        String::from_utf8(username_bytes).map_err(|e| anyhow!("Invalid UTF-8 username: {}", e))?;

    // O-2.2:Validate field lengths to prevent injection
    if username.len() > 255 || password.len() > 255 {
        // O-2.1:Zeroize password String before early return
        let mut pw_vec = password.into_bytes();
        pw_vec.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid credential field length".to_string()),
        });
    }

    if !is_valid_sasl_field(&username) || !is_valid_sasl_field(&password) {
        let mut pw_vec = password.into_bytes();
        pw_vec.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid characters in authentication payload".to_string()),
        });
    }

    // O-2.3:Check per-username lockout before verifying
    if is_username_rate_limited(&username) {
        warn!(peer = %peer_ip, username = %username, "Username auth rate limited");
        // O-2.1:Zeroize password String before early return
        let mut pw_vec = password.into_bytes();
        pw_vec.zeroize();
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Too many authentication failures; try again later".to_string()),
        });
    }

    let result = verify_credentials(&username, &password, pool).await?;
    // O-2.1:Zeroize password after credential verification by converting back to Vec<u8>
    let mut pw_vec = password.into_bytes();
    pw_vec.zeroize();
    if !result.success {
        record_auth_failure(peer_ip);
        record_username_failure(&username);
    } else {
        AUTH_FAIL_CACHE.invalidate(&peer_ip);
        USERNAME_FAIL_CACHE.invalidate(&username);
    }
    Ok(result)
}

/// Verify credentials against database
async fn verify_credentials(username: &str, password: &str, pool: &PgPool) -> Result<AuthResult> {
    debug!(username = %username, "Verifying credentials");

    // Look up user in database
    let row = sqlx::query(
        r#"
        SELECT id, email, password_hash, is_active 
        FROM mail_accounts 
        WHERE email = $1
    "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => {
            warn!(username = %username, "User not found");
            return Ok(AuthResult {
                success: false,
                account_id: None,
                email: None,
                error: Some("Invalid credentials".to_string()),
            });
        }
    };

    let is_active: bool = sqlx::Row::get(&row, "is_active");
    if !is_active {
        warn!(username = %username, "Account disabled");
        return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Account disabled".to_string()),
        });
    }

    let stored_hash: String = sqlx::Row::get(&row, "password_hash");

    let verification = match apexmail_lib::crypto::verify_password_for_login(password, &stored_hash)
    {
        Ok(verification) => verification,
        Err(error) => {
            warn!(username = %username, error = %error, "Password verification failed");
            return Ok(AuthResult {
                success: false,
                account_id: None,
                email: None,
                error: Some("Invalid credentials".to_string()),
            });
        }
    };

    if verification.valid {
        let account_id: uuid::Uuid = sqlx::Row::get(&row, "id");
        let email: String = sqlx::Row::get(&row, "email");

        if let Some(migrated_hash) = verification.migrated_hash {
            if let Err(error) =
                migrate_password_hash(pool, account_id, &stored_hash, &migrated_hash).await
            {
                warn!(username = %username, account_id = %account_id, error = %error, "Failed to migrate bcrypt password hash to Argon2id");
            }
        }

        debug!(username = %username, "Authentication successful");
        Ok(AuthResult {
            success: true,
            account_id: Some(account_id),
            email: Some(email),
            error: None,
        })
    } else {
        warn!(username = %username, "Invalid password");
        Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid credentials".to_string()),
        })
    }
}

async fn migrate_password_hash(
    pool: &PgPool,
    account_id: uuid::Uuid,
    old_hash: &str,
    new_hash: &str,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE mail_accounts
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2 AND password_hash = $3
        "#,
    )
    .bind(new_hash)
    .bind(account_id)
    .bind(old_hash)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        debug!(account_id = %account_id, "Migrated bcrypt password hash to Argon2id");
    }
    Ok(rows_affected)
}

fn is_valid_sasl_field(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// #174:Check if an IP is rate-limited for authentication.
fn is_rate_limited(ip: IpAddr) -> bool {
    AUTH_FAIL_CACHE.get(&ip).unwrap_or(0) >= MAX_AUTH_FAILURES
}

/// #174:Record an authentication failure for the given IP.
/// Uses saturating arithmetic to prevent counter wrapping at u64::MAX.
fn record_auth_failure(ip: IpAddr) {
    let count = AUTH_FAIL_CACHE.get(&ip).unwrap_or(0);
    AUTH_FAIL_CACHE.insert(ip, count.saturating_add(1));
}

// O-2.3:Per-username lockout — prevents credential stuffing against the same account
/// Check if a username is rate-limited for authentication.
fn is_username_rate_limited(username: &str) -> bool {
    USERNAME_FAIL_CACHE.get(username).unwrap_or(0) >= MAX_USERNAME_FAILURES
}

/// Record an authentication failure for the given username.
/// Uses saturating arithmetic to prevent counter wrapping at u64::MAX.
fn record_username_failure(username: &str) {
    let count = USERNAME_FAIL_CACHE.get(username).unwrap_or(0);
    USERNAME_FAIL_CACHE.insert(username.to_string(), count.saturating_add(1));
}

/// Generate a password hash
#[expect(
    dead_code,
    reason = "public helper kept for submission account provisioning flows"
)]
pub fn hash_password(password: &str) -> Result<String> {
    apexmail_lib::crypto::hash_password(password)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sasl_field_rejects_control_characters() {
        assert!(is_valid_sasl_field("user@example.com"));
        assert!(is_valid_sasl_field("correct horse battery staple"));
        assert!(!is_valid_sasl_field("user\n@example.com"));
        assert!(!is_valid_sasl_field("pass\0word"));
        assert!(!is_valid_sasl_field("pass\u{7f}word"));
    }

    #[test]
    fn bcrypt_hash_validation_requires_full_mcf_length() {
        let hash = bcrypt::hash("secret", 4).expect("bcrypt hash");
        assert!(apexmail_lib::crypto::is_valid_bcrypt_hash(&hash));
        assert!(
            apexmail_lib::crypto::verify_password_for_login("secret", &hash)
                .expect("verify bcrypt")
                .valid
        );

        let truncated = &hash[..hash.len() - 1];
        assert!(!apexmail_lib::crypto::is_valid_bcrypt_hash(truncated));
        assert!(
            !apexmail_lib::crypto::verify_password_for_login("secret", truncated)
                .expect("reject truncated bcrypt")
                .valid
        );

        let extended = format!("{hash}a");
        assert!(!apexmail_lib::crypto::is_valid_bcrypt_hash(&extended));
        assert!(
            !apexmail_lib::crypto::verify_password_for_login("secret", &extended)
                .expect("reject extended bcrypt")
                .valid
        );
    }

    #[test]
    fn bcrypt_hash_validation_rejects_control_characters() {
        let mut hash = bcrypt::hash("secret", 4).expect("bcrypt hash").into_bytes();
        hash[10] = b'\n';
        let hash = String::from_utf8(hash).expect("test hash utf8");

        assert!(!apexmail_lib::crypto::is_valid_bcrypt_hash(&hash));
        assert!(
            !apexmail_lib::crypto::verify_password_for_login("secret", &hash)
                .expect("reject control bcrypt")
                .valid
        );
    }
}
