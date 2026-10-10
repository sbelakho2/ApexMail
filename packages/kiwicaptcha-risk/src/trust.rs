//! Context-bound session trust (risk-v1 network plane): trust earned by
//! a session is stored per ASN bucket, `trust[session][asn_bucket]`.
//!
//! A session presenting from a bucket where it earned nothing gets zero
//! credit there, full credit in its home bucket(s). This defeats
//! shared-cookie botnets without reducing a real user's cross-network
//! experience: a stolen cookie replayed from a thousand foreign networks
//! earns nothing, while a genuine home-to-mobile commute keeps every
//! unit of home credit (a foreign presentation is a read of the foreign
//! record only and never reduces the home entry).
//!
//! Storage rides the additive `trust.lua` record surface beside the
//! frozen risk-v1 observation wire (like the marks surface): the
//! canonical risk-v1 state script keeps owning the aggregate session
//! trust channel, and the bucket layer is its own store surface the
//! policy consults when the request context carries an ASN bucket.
//!
//! # Engine wiring
//!
//! The risk-v1 observation argv is frozen by fixtures and tests, so the
//! engine takes the optional trust source beside the frozen wire (the
//! same `with_*` precedent as the marks reader and the price context):
//! when an assessment request carries the session pseudonym plus a
//! source IP, the engine replaces the aggregate `trust_credit`
//! contribution with the bucket-local [`bucket_trust_credit`] over the
//! record read through [`ContextBoundTrust`]. The engine-facing seam is
//! [`ContextTrustSource`], and [`RiskEngine::with_context_trust`] is
//! the wiring point; unwired, the assessment path is byte-identical to
//! the aggregate channel.

use std::net::IpAddr;

use crate::asn::AsnDataset;
use crate::store::RiskStoreError;
use crate::RiskError;

/// The raw fixed-point saturation of one bucket record: 10000 raw units
/// normalize to the full 1000-per-mille credit, the same saturation the
/// risk-v1 trust channel uses (`trust.lua` clamps writes at it).
pub const BUCKET_TRUST_SATURATION: u32 = 10_000;

/// Normalizes a raw bucket trust value to the 0..1000 signal band, the
/// identical `floor(value * 1000 / saturation)` rule the risk-v1 state
/// script applies to its trust channel.
pub fn normalize_bucket_trust(raw: u32) -> u16 {
    (raw.min(BUCKET_TRUST_SATURATION) / 10) as u16
}

/// The applied trust credit of one request: the bucket-local record
/// only. An absent record (the session never earned in that bucket)
/// reads as raw 0 and yields zero credit; a record with residue yields
/// exactly that residue's credit. Cross-bucket earns nothing, and a
/// foreign bucket never consults the home record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketTrustCredit {
    /// The request's ASN bucket id.
    pub bucket: String,
    /// True when the session carries earned trust in this bucket.
    pub is_home: bool,
    /// The bucket record's decayed raw trust (0 when absent).
    pub raw_trust: u32,
    /// The applied credit, 0..1000.
    pub credit: u16,
}

/// The policy computation: the credit applied to a request presenting
/// from `bucket` is the bucket-local record only.
pub fn bucket_trust_credit(bucket: &str, raw_trust: Option<u32>) -> BucketTrustCredit {
    let raw = raw_trust.unwrap_or(0);
    BucketTrustCredit {
        bucket: bucket.to_string(),
        is_home: raw > 0,
        raw_trust: raw,
        credit: normalize_bucket_trust(raw),
    }
}

/// The additive context-bound trust store surface, mirror of the PHP
/// `SessionBucketTrustStoreInterface`. The Redis store implements it
/// with the canonical `trust.lua`; the trait keeps the facade testable
/// against any trust-capable store.
pub trait SessionBucketTrustStore: Send + Sync {
    /// The exact record key of one session and bucket.
    fn bucket_trust_key(&self, session_id: &str, bucket: &str) -> Result<String, RiskError>;
    /// The decayed bucket-local trust of the session (0 when no record);
    /// a pure read that never mutates the record.
    fn read_bucket_trust(&self, session_id: &str, bucket: &str) -> Result<u32, RiskError>;
    /// Credits the bucket the request presents from and returns the
    /// record's new raw trust.
    fn credit_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskError>;
    /// Decays the bucket record and returns its new raw trust.
    fn decay_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskError>;
}

pub(crate) fn store_err(e: RiskStoreError) -> RiskError {
    RiskError::Store(e.to_string())
}

impl SessionBucketTrustStore for crate::redis::RedisRiskStateStore {
    fn bucket_trust_key(&self, session_id: &str, bucket: &str) -> Result<String, RiskError> {
        crate::redis::RedisRiskStateStore::bucket_trust_key(self, session_id, bucket)
            .map_err(store_err)
    }

    fn read_bucket_trust(&self, session_id: &str, bucket: &str) -> Result<u32, RiskError> {
        crate::redis::RedisRiskStateStore::read_bucket_trust(self, session_id, bucket)
            .map_err(store_err)
    }

    fn credit_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskError> {
        crate::redis::RedisRiskStateStore::credit_bucket_trust(self, session_id, bucket, delta)
            .map_err(store_err)
    }

    fn decay_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskError> {
        crate::redis::RedisRiskStateStore::decay_bucket_trust(self, session_id, bucket, delta)
            .map_err(store_err)
    }
}

/// The engine-facing seam of the context-bound trust: the exact read
/// the assessment performs when the engine is wired with a trust
/// source. `ContextBoundTrust` implements it over one dataset and one
/// trust-capable store; tests implement it over fixtures.
pub trait ContextTrustSource: Send + Sync {
    /// The applied trust credit of one request: the bucket resolved
    /// from `source_ip` and the session's record in that bucket only.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the record read fails.
    fn credit_for(
        &self,
        session_id: &str,
        source_ip: IpAddr,
    ) -> Result<BucketTrustCredit, RiskError>;
}

impl<'a> ContextTrustSource for ContextBoundTrust<'a> {
    fn credit_for(
        &self,
        session_id: &str,
        source_ip: IpAddr,
    ) -> Result<BucketTrustCredit, RiskError> {
        ContextBoundTrust::credit_for(self, session_id, source_ip)
    }
}

/// The caller-facing surface: resolves the request's bucket from its
/// source IP through the ASN dataset, then reads (or earns) the
/// session's trust in exactly that bucket. All state stays bucket
/// local: a foreign presentation reads the foreign record (absent:
/// zero credit) and never touches the home record, so home credit is
/// fully effective the moment the session presents from home again.
pub struct ContextBoundTrust<'a> {
    dataset: &'a AsnDataset,
    store: &'a dyn SessionBucketTrustStore,
}

impl<'a> ContextBoundTrust<'a> {
    /// Builds the facade over one dataset and one trust-capable store.
    pub fn new(dataset: &'a AsnDataset, store: &'a dyn SessionBucketTrustStore) -> Self {
        ContextBoundTrust { dataset, store }
    }

    /// The applied trust credit of one request: the bucket resolved from
    /// `source_ip` and the session's record in that bucket only.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the record read fails; an invalid
    /// session id or bucket id is rejected before any backend call.
    pub fn credit_for(
        &self,
        session_id: &str,
        source_ip: IpAddr,
    ) -> Result<BucketTrustCredit, RiskError> {
        let bucket = self.dataset.bucket_id(source_ip);
        let raw = self.store.read_bucket_trust(session_id, &bucket)?;
        Ok(bucket_trust_credit(&bucket, Some(raw)))
    }

    /// Credits the bucket the request presents from (trust is earned in
    /// the bucket it is earned from) and returns the resulting credit.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the record write fails; an invalid
    /// session id or bucket id is rejected before any backend call.
    pub fn earn(
        &self,
        session_id: &str,
        source_ip: IpAddr,
        delta: u32,
    ) -> Result<BucketTrustCredit, RiskError> {
        let bucket = self.dataset.bucket_id(source_ip);
        let raw = self.store.credit_bucket_trust(session_id, &bucket, delta)?;
        Ok(bucket_trust_credit(&bucket, Some(raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_matches_the_fixed_point_rule() {
        assert_eq!(normalize_bucket_trust(0), 0);
        assert_eq!(normalize_bucket_trust(1), 0);
        assert_eq!(normalize_bucket_trust(9), 0);
        assert_eq!(normalize_bucket_trust(10), 1);
        assert_eq!(normalize_bucket_trust(2_500), 250);
        assert_eq!(normalize_bucket_trust(9_999), 999);
        assert_eq!(normalize_bucket_trust(BUCKET_TRUST_SATURATION), 1000);
        assert_eq!(normalize_bucket_trust(BUCKET_TRUST_SATURATION + 1), 1000);
        assert_eq!(normalize_bucket_trust(u32::MAX), 1000);
    }

    #[test]
    fn an_absent_or_zero_bucket_earns_nothing() {
        let absent = bucket_trust_credit("u4/51968", None);
        assert_eq!(absent.credit, 0);
        assert!(!absent.is_home);
        assert_eq!(absent.raw_trust, 0);

        let zeroed = bucket_trust_credit("a64496", Some(0));
        assert_eq!(zeroed.credit, 0);
        assert!(!zeroed.is_home);

        let home = bucket_trust_credit("a64496", Some(4_000));
        assert_eq!(home.credit, 400);
        assert!(home.is_home);
    }
}
