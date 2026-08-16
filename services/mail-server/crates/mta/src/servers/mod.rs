//! SMTP servers:inbound, bounce, feedback‑loop, submission.

pub mod bounce;
pub mod feedback_loop;
pub mod inbound;
pub mod submission;
pub(crate) mod util;

pub use bounce::BounceServer;
pub use feedback_loop::FeedbackLoopServer;
pub use inbound::InboundServer;
pub use submission::SubmissionServer;
