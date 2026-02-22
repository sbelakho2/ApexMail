//! Email authentication: SPF, DKIM, DMARC, ARC, BIMI, DANE, MTA‑STS.

pub mod arc;
pub mod bimi;
pub mod dane;
pub mod email_authentication;
pub mod mta_sts;

pub use arc::*;
pub use bimi::*;
pub use dane::*;
pub use email_authentication::*;
pub use mta_sts::*;
