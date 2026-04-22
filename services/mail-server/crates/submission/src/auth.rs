//! Authentication Handler
//!
//! Handles SMTP AUTH mechanisms (PLAIN, LOGIN).

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use argon2::password_hash::{PasswordHasher, SaltString};
use moka::sync::Cache;
use rand::rngs::OsRng;
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, warn};

/// #174:Rate limiter for authentication attempts per IP.
/// Tracks failure count per IP; rejects after MAX_AUTH_FAILURES within the TTL window.
const MAX_AUTH_FAILURES: u32 = 5;
static AUTH_FAIL_CACHE: LazyLock<Cache<IpAddr, u32>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(50_000)
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

    let decoded = BASE64.decode(credentials)
        .map_err(|e| anyhow!("Invalid base64: {}", e))?;
    
    let decoded_str = String::from_utf8_lossy(&decoded);
    let parts: Vec<&str> = decoded_str.split('\0').collect();
    
// PLAIN format:[authzid]\0authcid\0passwd
    let (username, password) = match parts.as_slice() {
        [_, user, pass] => (*user, *pass),
        [user, pass] => (*user, *pass),
        _ => return Ok(AuthResult {
            success: false,
            account_id: None,
            email: None,
            error: Some("Invalid PLAIN credentials format".to_string()),
        }),
    };
    
    let result = verify_credentials(username, password, pool).await?;
    if !result.success {
        record_auth_failure(peer_ip);
    } else {
// Reset on success
        AUTH_FAIL_CACHE.invalidate(&peer_ip);
    }
    Ok(result)
}

/// Authenticate with LOGIN mechanism
/// Two-step:username then password (both base64 encoded)
pub async fn auth_login(username_b64: &str, password_b64: &str, pool: &PgPool, peer_ip: IpAddr) -> Result<AuthResult> {
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

    let username = String::from_utf8(
        BASE64.decode(username_b64).map_err(|e| anyhow!("Invalid base64 username: {}", e))?
    ).map_err(|e| anyhow!("Invalid UTF-8 username: {}", e))?;
    
    let password = String::from_utf8(
        BASE64.decode(password_b64).map_err(|e| anyhow!("Invalid base64 password: {}", e))?
    ).map_err(|e| anyhow!("Invalid UTF-8 password: {}", e))?;
    
    let result = verify_credentials(&username, &password, pool).await?;
    if !result.success {
        record_auth_failure(peer_ip);
    } else {
        AUTH_FAIL_CACHE.invalidate(&peer_ip);
    }
    Ok(result)
}

/// Verify credentials against database
async fn verify_credentials(username: &str, password: &str, pool: &PgPool) -> Result<AuthResult> {
    debug!(username = %username, "Verifying credentials");
    
// Look up user in database
    let row = sqlx::query(r#"
        SELECT id, email, password_hash, is_active 
        FROM mail_accounts 
        WHERE email = $1
    "#)
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
    
// Verify password hash using Argon2.
    let password_valid = verify_password_hash(password, &stored_hash);
    
    if password_valid {
        let account_id: uuid::Uuid = sqlx::Row::get(&row, "id");
        let email: String = sqlx::Row::get(&row, "email");
        
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

/// #173:Verify password against hash
/// Supports bcrypt ($2a$, $2b$, $2y$) and argon2 ($argon2id$, $argon2i$, $argon2d$)
fn verify_password_hash(password: &str, hash: &str) -> bool {
    if hash.starts_with("$argon2") {
        let parsed = match PasswordHash::new(hash) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }

// #173:Actual bcrypt support for $2a$, $2b$, $2y$ prefixed hashes
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
        return bcrypt::verify(password, hash).unwrap_or(false);
    }

    warn!("Unrecognized password hash format");
    false
}

/// #174:Check if an IP is rate-limited for authentication.
fn is_rate_limited(ip: IpAddr) -> bool {
    AUTH_FAIL_CACHE.get(&ip).unwrap_or(0) >= MAX_AUTH_FAILURES
}

/// #174:Record an authentication failure for the given IP.
fn record_auth_failure(ip: IpAddr) {
    let count = AUTH_FAIL_CACHE.get(&ip).unwrap_or(0);
    AUTH_FAIL_CACHE.insert(ip, count + 1);
}

/// Generate a password hash
#[allow(unused)]
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?
        .to_string();

    Ok(hash)
}
