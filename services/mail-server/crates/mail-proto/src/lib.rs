//! Mail Protocol Definitions
//!
//! gRPC/Protobuf definitions for inter-service communication.

use prost::Message;

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
}
