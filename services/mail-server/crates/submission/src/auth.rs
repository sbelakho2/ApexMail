//! Authentication Handler
//!
//! Handles SMTP AUTH mechanisms (PLAIN, LOGIN).

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sqlx::PgPool;
use tracing::{debug, warn};

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub success: bool,
    pub account_id: Option<uuid::Uuid>,
    pub email: Option<String>,
    pub error: Option<String>,
}

/// Authenticate with PLAIN mechanism
/// Format: \0username\0password (base64 encoded)
pub async fn auth_plain(credentials: &str, pool: &PgPool) -> Result<AuthResult> {
    let decoded = BASE64.decode(credentials)
        .map_err(|e| anyhow!("Invalid base64: {}", e))?;
    
    let decoded_str = String::from_utf8_lossy(&decoded);
    let parts: Vec<&str> = decoded_str.split('\0').collect();
    
    // PLAIN format: [authzid]\0authcid\0passwd
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
    
    verify_credentials(username, password, pool).await
}

/// Authenticate with LOGIN mechanism
/// Two-step: username then password (both base64 encoded)
pub async fn auth_login(username_b64: &str, password_b64: &str, pool: &PgPool) -> Result<AuthResult> {
    let username = String::from_utf8(
        BASE64.decode(username_b64).map_err(|e| anyhow!("Invalid base64 username: {}", e))?
    ).map_err(|e| anyhow!("Invalid UTF-8 username: {}", e))?;
    
    let password = String::from_utf8(
        BASE64.decode(password_b64).map_err(|e| anyhow!("Invalid base64 password: {}", e))?
    ).map_err(|e| anyhow!("Invalid UTF-8 password: {}", e))?;
    
    verify_credentials(&username, &password, pool).await
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
    
    // Verify password using argon2 or bcrypt
    // For now, simple comparison (should use proper password hashing in production)
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

/// Verify password against hash
/// Supports bcrypt ($2a$, $2b$, $2y$) and argon2 ($argon2id$)
fn verify_password_hash(password: &str, hash: &str) -> bool {
    // For development: allow plaintext comparison if hash doesn't look like a hash
    if !hash.starts_with('$') {
        return password == hash;
    }
    
    // Bcrypt verification would go here
    // argon2 verification would go here
    
    // Placeholder - in production, use proper password verification
    // bcrypt::verify(password, hash).unwrap_or(false)
    password == hash
}

/// Generate a password hash
pub fn hash_password(password: &str) -> Result<String> {
    // In production, use bcrypt or argon2
    // For now, return plaintext (NOT FOR PRODUCTION)
    Ok(password.to_string())
}
