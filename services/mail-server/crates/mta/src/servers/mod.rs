//! SMTP servers:inbound, bounce, feedback‑loop, submission.

pub mod bounce;
pub(crate) mod content_security;
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

/// Fuzz/test seam over the SCALAR SMTP command-line tokenizer: the exact
/// `split_verb` splitter the submission and inbound servers run on every
/// command line (verb + raw argument tail). Kept out of the public product
/// surface with `#[doc(hidden)]`; the fuzz workspace (a separate crate tree)
/// needs a stable link point, and duplicating the splitter in the fuzzer
/// would fuzz a copy instead of the shipped parser.
#[doc(hidden)]
pub fn fuzz_smtp_command_line(line: &str) -> (String, String) {
    let (verb, args) = util::split_verb(line);
    (verb, args.to_string())
}

/// Fuzz/test seam over the SMTP envelope-address extractor: the exact
/// `MAIL FROM:` / `RCPT TO:` address grammar (`extract_addr_safe`) the
/// servers apply to envelope commands.
#[doc(hidden)]
pub fn fuzz_smtp_envelope_address(line: &str) -> Option<String> {
    util::extract_addr_safe(line).map(str::to_string)
}
