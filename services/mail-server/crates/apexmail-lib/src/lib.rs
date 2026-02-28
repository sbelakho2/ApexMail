//! ApexMail shared library — crypto, logging, caching, IDs, validation, HTTP client, error codes.

pub mod crypto;
pub mod id;
pub mod error_codes;
pub mod cache;
pub mod http_client;
pub mod validation;
pub mod time;
pub mod result;
pub mod config;

pub use crypto::{create_hmac_signature, timing_safe_compare, hash_api_key, hash_api_key_with_secret, verify_password, hash_password};
pub use id::{generate_id, generate_api_key, generate_verification_token};
pub use error_codes::ErrorCode;
