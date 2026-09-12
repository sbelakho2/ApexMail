//! SMTP servers:inbound, bounce, feedback‑loop, submission.

pub mod bounce;
pub mod fbl_registry;
pub mod feedback_loop;
pub mod inbound;
pub mod inbound_delivery;
pub mod submission;
pub(crate) mod util;

pub use bounce::BounceServer;
pub use feedback_loop::FeedbackLoopServer;
pub use inbound::InboundServer;
pub use inbound_delivery::InboundDeliveryWorker;
pub use submission::SubmissionServer;
