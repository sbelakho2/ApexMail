//! The risk-v2 identity vector (change.md 3.1.1): the seven pseudonym
//! dimensions of the identity contract, derived once per request.
//!
//! Every dimension delegates to the existing derivations of
//! [`RiskIdentityFactory`] (source, subnet, session, principal, target)
//! plus the asn and agent derivations the contract file declares. The
//! contract file `protocol/risk-v2/identity.json` is the machine-checked
//! source of truth for the per-dimension context string, granularity,
//! epoch policy, TTL and cardinality bound; the reader test
//! `tests/identity_vectors.rs` re-derives every dimension straight from
//! the file's declared values and must reproduce this vector.
//!
//! The value object is computed once at the request boundary and cloned
//! cheaply for every plane that reads it. No plane recomputes a
//! pseudonym, and no raw input is stored on the object: only hex
//! pseudonyms, with `None` for an absent optional dimension.

use std::net::IpAddr;

use crate::asn::AsnDataset;
use crate::identity::RiskIdentityFactory;

/// The dimension names in contract order (change.md 1.1).
pub const DIMENSIONS: [&str; 7] = [
    "source",
    "subnet",
    "asn",
    "session",
    "principal",
    "target",
    "agent",
];

/// The request descriptor one identity vector derives from.
///
/// `client_ip` is the canonical request source address; the mapped and
/// compatible v6 spellings normalize inside the derivations.
/// `session_cookie` is the decoded 16-byte cookie value. The optional
/// principal, agent and target fields carry the app user id, the
/// configured verified-agent key id and the already-normalized target
/// identifier; each absent field yields an absent dimension. The ASN
/// dataset handle resolves the client IP to its bucket. `now_unix_secs`
/// is the integer every rotated epoch derives from, per the contract's
/// floor-division windows.
#[derive(Debug, Clone, Copy)]
pub struct IdentityVectorInput<'a> {
    pub client_ip: IpAddr,
    pub session_cookie: Option<&'a [u8; 16]>,
    pub principal_id: Option<&'a [u8]>,
    pub agent_key_id: Option<&'a str>,
    pub target_normalized: Option<&'a str>,
    pub asn_dataset: &'a AsnDataset,
    pub now_unix_secs: i64,
}

/// The seven dimension pseudonyms of one request as lowercase hex (the
/// target dimension keeps its full 32-byte digest; every other
/// dimension is 16 bytes).
///
/// Optional dimensions are `None` when the request carried no such
/// identity, and [`IdentityVector::dimension`] reports that absence by
/// name so consumers never touch a value to learn it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityVector {
    source: String,
    subnet: String,
    asn: String,
    session: Option<String>,
    principal: Option<String>,
    target: Option<String>,
    agent: Option<String>,
}

impl IdentityVector {
    /// Derives the full vector once, delegating every dimension to the
    /// factory's existing derivations. An empty normalized target is
    /// absent (the same rule the engine's target side channel applies).
    pub fn derive(
        input: &IdentityVectorInput<'_>,
        factory: &RiskIdentityFactory,
    ) -> IdentityVector {
        IdentityVector {
            source: factory.source_id(input.client_ip, input.now_unix_secs),
            subnet: factory.subnet_id(input.client_ip, input.now_unix_secs),
            asn: factory.asn_id(
                &input.asn_dataset.bucket_id(input.client_ip),
                input.now_unix_secs,
            ),
            session: input
                .session_cookie
                .map(|raw| hex::encode(factory.session_id(raw))),
            principal: input
                .principal_id
                .map(|raw| hex::encode(factory.principal_id(raw))),
            target: input
                .target_normalized
                .filter(|t| !t.is_empty())
                .map(|t| factory.target_id(t)),
            agent: input
                .agent_key_id
                .filter(|k| !k.is_empty())
                .map(|k| hex::encode(factory.agent_id(k))),
        }
    }

    /// The source pseudonym (32 hex chars).
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The subnet pseudonym (32 hex chars).
    pub fn subnet(&self) -> &str {
        &self.subnet
    }

    /// The ASN pseudonym (32 hex chars).
    pub fn asn(&self) -> &str {
        &self.asn
    }

    /// The session pseudonym, or `None` when the request carried no
    /// session cookie.
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// The principal pseudonym, or `None` when no principal was
    /// supplied.
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// The target pseudonym (64 hex chars), or `None` when the request
    /// carried no target identifier.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// The agent pseudonym, or `None` when no verified-agent key id was
    /// supplied.
    pub fn agent(&self) -> Option<&str> {
        self.agent.as_deref()
    }

    /// One dimension's pseudonym by contract name, or `None` when the
    /// dimension is absent or unknown.
    pub fn dimension(&self, name: &str) -> Option<&str> {
        match name {
            "source" => Some(self.source()),
            "subnet" => Some(self.subnet()),
            "asn" => Some(self.asn()),
            "session" => self.session(),
            "principal" => self.principal(),
            "target" => self.target(),
            "agent" => self.agent(),
            _ => None,
        }
    }

    /// The contract names of the present dimensions, in contract
    /// order. Names only: the pseudonym values stay behind
    /// [`IdentityVector::dimension`].
    pub fn present_dimensions(&self) -> Vec<&'static str> {
        DIMENSIONS
            .iter()
            .copied()
            .filter(|name| self.dimension(name).is_some())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RiskKeys;

    fn dataset() -> AsnDataset {
        AsnDataset::open(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../protocol/asn/sample-asn.tsv"),
        )
        .expect("sample dataset opens")
    }

    fn input<'a>(ip: &str, now: i64, asn: &'a AsnDataset) -> IdentityVectorInput<'a> {
        IdentityVectorInput {
            client_ip: ip.parse().unwrap(),
            session_cookie: None,
            principal_id: None,
            agent_key_id: None,
            target_normalized: None,
            asn_dataset: asn,
            now_unix_secs: now,
        }
    }

    #[test]
    fn dimension_names_are_the_contract_order() {
        assert_eq!(
            DIMENSIONS,
            [
                "source",
                "subnet",
                "asn",
                "session",
                "principal",
                "target",
                "agent"
            ]
        );
    }

    #[test]
    fn absent_optional_dimensions_are_none() {
        let asn = dataset();
        let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
        let vector = IdentityVector::derive(&input("203.0.113.27", 1_700_000_000, &asn), &factory);
        assert_eq!(vector.session(), None);
        assert_eq!(vector.principal(), None);
        assert_eq!(vector.target(), None);
        assert_eq!(vector.agent(), None);
        assert_eq!(vector.present_dimensions(), vec!["source", "subnet", "asn"]);
        // The always-present dimensions stay 32 lowercase hex chars.
        for name in ["source", "subnet", "asn"] {
            let value = vector.dimension(name).unwrap();
            assert_eq!(value.len(), 32);
            assert!(value.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn empty_optional_material_is_absent() {
        let asn = dataset();
        let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
        let mut descriptor = input("203.0.113.27", 1_700_000_000, &asn);
        descriptor.agent_key_id = Some("");
        descriptor.target_normalized = Some("");
        let vector = IdentityVector::derive(&descriptor, &factory);
        assert_eq!(vector.agent(), None);
        assert_eq!(vector.target(), None);
    }

    #[test]
    fn present_dimensions_report_every_dimension() {
        let asn = dataset();
        let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
        let cookie = [0x5au8; 16];
        let descriptor = IdentityVectorInput {
            client_ip: "192.0.2.44".parse().unwrap(),
            session_cookie: Some(&cookie),
            principal_id: Some(b"principal-42"),
            agent_key_id: Some("agent-key-7"),
            target_normalized: Some("user@example.com"),
            asn_dataset: &asn,
            now_unix_secs: 1_700_000_000,
        };
        let vector = IdentityVector::derive(&descriptor, &factory);
        assert_eq!(vector.present_dimensions(), DIMENSIONS.to_vec());
        assert_eq!(vector.target().unwrap().len(), 64);
        // An unknown dimension name reports absent, never a value.
        assert_eq!(vector.dimension("device"), None);
    }
}
