//! Mail Protocol Definitions
//!
//! gRPC/Protobuf definitions for inter-service communication.

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
