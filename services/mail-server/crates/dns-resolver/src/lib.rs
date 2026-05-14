//! Reusable DNS resolver with caching for ApexMail.
//!
//! Provides://! - Cached MX record lookups
//! - SPF TXT record parsing
//! - DKIM selector resolution
//! - DMARC policy lookups
//! - TLSA (DANE) record lookups
//! - Generic A/AAAA/CNAME queries

#![deny(unsafe_code)]
pub mod cache;
pub mod config;
pub mod lookup;
pub mod records;
pub mod resolver;

pub use cache::DnsCache;
pub use config::DnsConfig;
pub use lookup::DnsLookup;
pub use records::{DkimRecord, DmarcPolicy, MxRecord, SpfRecord, TlsaRecord};
pub use resolver::CachedDnsResolver;
