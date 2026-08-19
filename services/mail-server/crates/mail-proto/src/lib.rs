//! Mail Protocol Definitions
//!
//! gRPC/Protobuf definitions for inter-service communication.

#![deny(unsafe_code)]
#![allow(clippy::large_enum_variant)]
use prost::Message;
use std::fmt;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataValue};

/// Generated protobuf types and gRPC service definitions
pub mod generated {
    tonic::include_proto!("apexmail.mail.v1");
}

// Re-export all generated types at the crate root for convenience
pub use generated::*;

// Re-export service servers
pub use generated::mailstore_service_server::MailstoreServiceServer;
pub use generated::outbound_service_server::OutboundServiceServer;

// Re-export service clients
pub use generated::mailstore_service_client::MailstoreServiceClient;
pub use generated::outbound_service_client::OutboundServiceClient;

/// Name of the process environment variable that carries the shared secret
/// used for mailstore gRPC authentication.
pub const INTERNAL_SERVICE_TOKEN_ENV: &str = "INTERNAL_SERVICE_TOKEN";

/// Alternative file-based environment variable. Docker deployments mount the
/// secret as a 0400 file and reference it here; the plain variable takes
/// precedence when both are set.
pub const INTERNAL_SERVICE_TOKEN_FILE_ENV: &str = "INTERNAL_SERVICE_TOKEN_FILE";

/// A shared service token must be long enough to contain meaningful entropy.
/// The production secret generator creates at least 32 random bytes.
pub const MIN_INTERNAL_SERVICE_TOKEN_LENGTH: usize = 32;

/// Errors returned while loading or validating the internal service token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalServiceTokenError {
    NotUnicode,
    TooShort,
    InvalidCharacters,
    InvalidMetadata,
    FileUnreadable,
}

impl fmt::Display for InternalServiceTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicode => write!(
                formatter,
                "{INTERNAL_SERVICE_TOKEN_ENV} must contain valid UTF-8 text"
            ),
            Self::TooShort => write!(
                formatter,
                "{INTERNAL_SERVICE_TOKEN_ENV} must contain at least {MIN_INTERNAL_SERVICE_TOKEN_LENGTH} characters"
            ),
            Self::InvalidCharacters => write!(
                formatter,
                "{INTERNAL_SERVICE_TOKEN_ENV} must contain only visible ASCII characters"
            ),
            Self::InvalidMetadata => write!(
                formatter,
                "{INTERNAL_SERVICE_TOKEN_ENV} cannot be encoded as gRPC authorization metadata"
            ),
            Self::FileUnreadable => write!(
                formatter,
                "{INTERNAL_SERVICE_TOKEN_FILE_ENV} could not be read"
            ),
        }
    }
}

impl std::error::Error for InternalServiceTokenError {}

/// A validated shared service token.
///
/// The token intentionally does not implement `Debug` so it cannot be
/// accidentally written to logs. An unset token is represented by `None` to
/// support loopback-only local development.
#[derive(Clone)]
pub struct InternalServiceToken(Arc<str>);

impl InternalServiceToken {
    /// Load an optional token from the environment. If the variable is set,
    /// reject weak or metadata-unsafe values instead of silently disabling
    /// authentication on client requests. When the plain variable is absent,
    /// `INTERNAL_SERVICE_TOKEN_FILE` is read as a fallback so container
    /// deployments can mount the secret as a file.
    pub fn from_env() -> Result<Option<Self>, InternalServiceTokenError> {
        match std::env::var(INTERNAL_SERVICE_TOKEN_ENV) {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Self::new(value).map(Some),
            Err(std::env::VarError::NotPresent) => Self::from_env_file(),
            Err(std::env::VarError::NotUnicode(_)) => Err(InternalServiceTokenError::NotUnicode),
        }
    }

    fn from_env_file() -> Result<Option<Self>, InternalServiceTokenError> {
        let path = match std::env::var(INTERNAL_SERVICE_TOKEN_FILE_ENV) {
            Ok(value) if value.is_empty() => return Ok(None),
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(InternalServiceTokenError::NotUnicode)?,
        };
        let value = std::fs::read_to_string(&path)
            .map_err(|_| InternalServiceTokenError::FileUnreadable)?;
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        Self::new(value.to_owned()).map(Some)
    }

    /// Validate a configured token.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, InternalServiceTokenError> {
        let value = value.into();
        if value.len() < MIN_INTERNAL_SERVICE_TOKEN_LENGTH {
            return Err(InternalServiceTokenError::TooShort);
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(InternalServiceTokenError::InvalidCharacters);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InternalServiceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InternalServiceToken([REDACTED])")
    }
}

/// Client-side interceptor for the internal mailstore service contract.
///
/// Constructing it validates the authorization metadata once at startup;
/// requests therefore cannot silently omit a malformed configured token.
#[derive(Clone, Debug)]
pub struct InternalServiceAuthInterceptor {
    authorization: Option<MetadataValue<Ascii>>,
}

impl InternalServiceAuthInterceptor {
    pub fn new(token: Option<&InternalServiceToken>) -> Result<Self, InternalServiceTokenError> {
        let authorization = token
            .map(|token| {
                format!("Bearer {}", token.as_str())
                    .parse::<MetadataValue<Ascii>>()
                    .map_err(|_| InternalServiceTokenError::InvalidMetadata)
            })
            .transpose()?;

        Ok(Self { authorization })
    }

    pub fn from_env() -> Result<Self, InternalServiceTokenError> {
        let token = InternalServiceToken::from_env()?;
        Self::new(token.as_ref())
    }
}

impl tonic::service::Interceptor for InternalServiceAuthInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(authorization) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", authorization.clone());
        }
        Ok(request)
    }
}

// O-3.1:Maximum protobuf message size (64 MB) to prevent OOM from oversized payloads
const MAX_PROTO_MESSAGE_LENGTH: usize = 64 * 1024 * 1024;

/// Decode a protobuf message with enforced size limits.
///
/// Returns `None` if the input exceeds `MAX_PROTO_MESSAGE_LENGTH` or decoding fails.
pub fn decode_with_limits<M: Message + Default>(bytes: &[u8]) -> Option<M> {
    if bytes.len() > MAX_PROTO_MESSAGE_LENGTH {
        return None;
    }
    M::decode(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use tonic::service::Interceptor;

    #[test]
    fn test_decode_within_limits() {
        // A minimal valid message
        let msg = generated::StoreMessageRequest {
            account_id: "test-account".into(),
            mailbox: "test-mailbox".into(),
            raw_message: vec![1, 2, 3].into(),
            ..Default::default()
        };
        let encoded = msg.encode_to_vec();
        assert!(encoded.len() < MAX_PROTO_MESSAGE_LENGTH);
        let decoded: Option<generated::StoreMessageRequest> = decode_with_limits(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().account_id, "test-account");
    }

    #[test]
    fn test_decode_exceeds_limit() {
        let oversized = vec![0u8; MAX_PROTO_MESSAGE_LENGTH + 1];
        let decoded: Option<generated::StoreMessageRequest> = decode_with_limits(&oversized);
        assert!(decoded.is_none());
    }

    #[test]
    fn internal_service_token_rejects_weak_or_unsafe_values() {
        assert!(matches!(
            InternalServiceToken::new("too-short"),
            Err(InternalServiceTokenError::TooShort)
        ));
        assert!(matches!(
            InternalServiceToken::new("a".repeat(31) + "\n"),
            Err(InternalServiceTokenError::InvalidCharacters)
        ));
    }

    #[test]
    fn internal_service_auth_interceptor_attaches_valid_bearer_metadata() {
        let token = InternalServiceToken::new("a".repeat(MIN_INTERNAL_SERVICE_TOKEN_LENGTH))
            .expect("fixture token must be valid");
        let mut interceptor =
            InternalServiceAuthInterceptor::new(Some(&token)).expect("header must be valid");

        let request = interceptor
            .call(tonic::Request::new(()))
            .expect("interceptor must accept request");

        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn internal_service_token_loads_from_file_fallback() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        let previous_token = std::env::var(INTERNAL_SERVICE_TOKEN_ENV).ok();
        let previous_file = std::env::var(INTERNAL_SERVICE_TOKEN_FILE_ENV).ok();
        std::env::remove_var(INTERNAL_SERVICE_TOKEN_ENV);

        let dir =
            std::env::temp_dir().join(format!("mail-proto-token-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("internal_service_token.txt");
        std::fs::write(
            &path,
            format!("{}\n", "b".repeat(MIN_INTERNAL_SERVICE_TOKEN_LENGTH)),
        )
        .unwrap();
        std::env::set_var(INTERNAL_SERVICE_TOKEN_FILE_ENV, &path);

        let token = InternalServiceToken::from_env().expect("file token must load");
        assert_eq!(
            token.as_ref().map(InternalServiceToken::as_str),
            Some("b".repeat(MIN_INTERNAL_SERVICE_TOKEN_LENGTH).as_str())
        );

        std::fs::remove_dir_all(&dir).ok();
        std::env::remove_var(INTERNAL_SERVICE_TOKEN_FILE_ENV);
        match previous_token {
            Some(value) => std::env::set_var(INTERNAL_SERVICE_TOKEN_ENV, value),
            None => std::env::remove_var(INTERNAL_SERVICE_TOKEN_ENV),
        }
        match previous_file {
            Some(value) => std::env::set_var(INTERNAL_SERVICE_TOKEN_FILE_ENV, value),
            None => {}
        }
    }

    #[test]
    fn internal_service_auth_interceptor_keeps_local_requests_tokenless() {
        let mut interceptor =
            InternalServiceAuthInterceptor::new(None).expect("empty optional token is valid");
        let request = interceptor
            .call(tonic::Request::new(()))
            .expect("interceptor must accept request");

        assert!(request.metadata().get("authorization").is_none());
    }
}
