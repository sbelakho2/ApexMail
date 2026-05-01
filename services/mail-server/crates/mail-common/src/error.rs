//! Error types for the mail server.

use thiserror::Error;

/// Mail server error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("DKIM error: {0}")]
    Dkim(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Rate limit exceeded")]
    RateLimit,

    #[error("Message too large")]
    MessageTooLarge,

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Delivery failed: {0}")]
    DeliveryFailed(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::Database(err.to_string())
    }
}
