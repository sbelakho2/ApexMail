//! ApexMail shared library — crypto, logging, caching, IDs, validation, HTTP client, error codes.

#![deny(unsafe_code)]
pub mod cache;
pub mod config;
pub mod crypto;
pub mod dkim;
pub mod error_codes;
pub mod http_client;
pub mod http_error;
pub mod id;
pub mod mfa;
pub mod pii;
pub mod result;
pub mod secret_at_rest;
pub mod time;
pub mod transport;
pub mod validation;

pub use crypto::{
    create_hmac_signature, detect_api_key_hash_version, hash_api_key, hash_api_key_argon2,
    hash_api_key_with_secret, hash_password, timing_safe_compare, verify_api_key_hash,
    verify_password, ApiKeyHashVersion,
};
pub use error_codes::ErrorCode;
pub use http_error::{ErrorDetail, ErrorEnvelope};
pub use id::{generate_api_key, generate_id, generate_verification_token};
