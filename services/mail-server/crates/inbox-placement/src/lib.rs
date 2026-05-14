#![deny(unsafe_code)]
pub mod classifier;
pub mod config;
pub mod engine;
pub mod imap_poller;
pub mod routes;
pub mod scheduler;
pub mod seed_manager;
pub mod sender;
pub mod types;

pub use classifier::{classify_folder, delivery_category, InboxFolder};
pub use config::PlacementConfig;
pub use engine::PlacementEngine;
pub use imap_poller::{ImapPoller, InboxPollResult};
pub use routes::PlacementState;
pub use scheduler::PlacementScheduler;
pub use seed_manager::SeedManager;
pub use sender::send_test_email;
pub use types::*;
