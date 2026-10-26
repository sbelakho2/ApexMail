//! Signed routing receipts, Ed25519 proof for every accepted send.
//!
//! The delivery acceptance ledger (`sales_delivery_acceptances`) records the
//! transport's per-message acceptance. The ledger row alone is only as
//! trustworthy as the database it lives in; the sovereign promise ("the
//! proof is signed per message") needs a signature a THIRD PARTY can verify
//! without trusting this platform's database, API surface or TLS stack.
//!
//! # Scheme
//!
//! * Algorithm: **Ed25519** (RFC 8032), signature 64 bytes.
//! * Secret key: `RECEIPT_SIGNING_KEY`, the 32-byte seed as **64 hex
//!   characters** or **base64** (standard or URL-safe, padding optional).
//!   Same shape as the repo's other 32-byte secrets
//!   (`.env.production.example`'s `openssl rand -hex 32` convention).
//! * Public key: base64 / hex of the 32-byte Ed25519 public key, served
//!   unauthenticated at `GET /v1/routing/receipts/public-key`.
//! * Key id: `hex(sha256(public_key))[..16]`, recorded next to every
//!   signature so a key rotation is auditable.
//!
//! # Canonical payload (the exact bytes that are signed)
//!
//! UTF-8, LF-separated, no trailing newline, no padding, no canonicalization
//! library, a verifier re-derives these bytes from the published fields:
//!
//! ```text
//! apexmail-routing-receipt/v1
//! message_id=<platform message id>
//! tenant_id=<tenant id>
//! transport=<transport label>
//! accepted_at=<RFC 3339 UTC, e.g. 2026-10-15T12:34:56.789+00:00>
//! actual_source_ip=<ip>            ← present ONLY when the transport reported one
//! ```
//!
//! Field values must not contain `\n` or `\r` (enforced, a receipt whose
//! canonical form would be ambiguous is REFUSED rather than escaped, so the
//! wire format stays trivially recomputable by any Ed25519 library).
//!
//! # Fail-closed
//!
//! [`RoutingReceiptSigner::from_env`] returns `Ok(None)` when the key is
//! unset, but a **receipt write without a signer is refused** by the
//! acceptance path (the ledger row is not marked `accepted`, and the failure
//! is loud), and the services that own the acceptance path refuse to boot in
//! production without a key. An unsigned receipt must never silently exist
//! ("no claim without evidence").

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

/// Environment variable holding the Ed25519 seed.
pub const RECEIPT_SIGNING_KEY_ENV: &str = "RECEIPT_SIGNING_KEY";

/// Environment variable holding ONLY the Ed25519 PUBLIC key (base64 or hex),
/// for services that publish/verify receipts but must never hold the signing
/// seed (the api-server serves `GET /v1/routing/receipts/public-key` and the
/// stateless verify endpoint). When unset, [`verification_key_from_env`]
/// falls back to deriving the public half of `RECEIPT_SIGNING_KEY`, a
/// convenience for single-process dev setups, NOT the recommended production
/// custody (the API process should not be able to sign).
pub const RECEIPT_PUBLIC_KEY_ENV: &str = "RECEIPT_PUBLIC_KEY";

/// The signature scheme label recorded next to every stored signature.
pub const RECEIPT_SIGNATURE_SCHEME: &str = "ed25519";

/// First line of the canonical payload (the version tag).
pub const RECEIPT_PAYLOAD_VERSION: &str = "apexmail-routing-receipt/v1";

/// Length of an Ed25519 seed (and public key) in bytes.
pub const RECEIPT_KEY_BYTES: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const RECEIPT_SIGNATURE_BYTES: usize = 64;

/// First line of the CUSTOMER-PROOF canonical payload (v2). The v1
/// receipt is the INTERNAL record (ledger, enterprise audits) and carries
/// tenant/transport/source-IP fields; what a CUSTOMER verifies is this
/// minimal proof: an opaque receipt id, the routing policy in force, that
/// the policy was satisfied, the residency class, and when the message was
/// accepted. Nothing about transports, providers, hosts or IPs (external
/// audit 2026-10-26: a trustworthy receipt does not need to disclose
/// routing internals to be a proof).
pub const PROOF_PAYLOAD_VERSION: &str = "apexmail-routing-proof/v2";

/// The signed fields of one customer-facing routing proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomerProofFields<'a> {
    /// Opaque receipt identity. NOT the platform message id and NOT the
    /// tenant id: derive it (e.g. `hex(sha256(version + message_id +
    /// tenant_id))[..32]`) so the proof is correlatable only by the party
    /// that already knows the message.
    pub receipt_id: &'a str,
    /// The routing policy in force for the message (e.g. `eu_only`).
    pub routing_policy: &'a str,
    /// Whether the acceptance satisfied the policy (always `true` on a
    /// signed proof: a policy violation never mints one).
    pub policy_satisfied: bool,
    /// The residency class of the accepted route (e.g. `EEA`).
    pub residency_class: &'a str,
    /// RFC 3339 UTC acceptance time, the same value as the internal
    /// receipt's `accepted_at`.
    pub accepted_at: &'a str,
}

/// Build the canonical customer-proof payload bytes that are signed.
/// Same determinism and newline-refusal contract as
/// [`canonical_payload`].
pub fn canonical_customer_proof(
    fields: &CustomerProofFields<'_>,
) -> Result<String, ReceiptPayloadError> {
    for (name, value) in [
        ("receipt_id", fields.receipt_id),
        ("routing_policy", fields.routing_policy),
        ("residency_class", fields.residency_class),
        ("accepted_at", fields.accepted_at),
    ] {
        if value.contains('\n') || value.contains('\r') {
            return Err(ReceiptPayloadError { field: name });
        }
    }
    Ok(format!(
        "{PROOF_PAYLOAD_VERSION}\nreceipt_id={}\nrouting_policy={}\npolicy_satisfied={}\nresidency_class={}\naccepted_at={}",
        fields.receipt_id,
        fields.routing_policy,
        fields.policy_satisfied,
        fields.residency_class,
        fields.accepted_at,
    ))
}

/// The opaque receipt id for a (message, tenant) pair: 32 hex chars of
/// sha256 over the version tag and both identities. Customers correlate
/// proofs only with knowledge they already have; the platform can always
/// re-derive the mapping.
pub fn customer_proof_receipt_id(message_id: &str, tenant_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(PROOF_PAYLOAD_VERSION.as_bytes());
    h.update(b"\0");
    h.update(message_id.as_bytes());
    h.update(b"\0");
    h.update(tenant_id.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// Reason a receipt key could not be used. Deliberately does NOT echo key
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptKeyError {
    /// `RECEIPT_SIGNING_KEY` is not 32 bytes in either accepted encoding.
    InvalidEncoding {
        /// The accepted encodings, for the operator-facing message.
        expected: &'static str,
    },
    /// The bytes decoded, but ring refused the key (e.g. not a valid seed).
    Rejected(String),
}

impl std::fmt::Display for ReceiptKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding { expected } => write!(
                f,
                "{RECEIPT_SIGNING_KEY_ENV} must be a 32-byte Ed25519 seed ({expected}); \
                 generate one with `openssl rand -hex 32`"
            ),
            Self::Rejected(reason) => {
                write!(f, "{RECEIPT_SIGNING_KEY_ENV} was rejected: {reason}")
            }
        }
    }
}

impl std::error::Error for ReceiptKeyError {}

/// The signed fields of one routing receipt. Every field is borrowed text
/// because the acceptance path already owns these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingReceiptFields<'a> {
    /// The platform message id (`email_queue.message_id` / the API-visible
    /// message identity), one receipt per message.
    pub message_id: &'a str,
    /// The tenant the message belongs to.
    pub tenant_id: &'a str,
    /// Which transport/route carried the message (the ledger's `transport`
    /// label, e.g. `ses-shared` / `dedicated`).
    pub transport: &'a str,
    /// When the transport accepted the message, RFC 3339 UTC, the SAME
    /// value persisted on the ledger row.
    pub accepted_at: &'a str,
    /// The recipient-facing source IP the transport actually used, when it
    /// reported one. `None` = not reported (see `DeliveryReceipt`).
    pub actual_source_ip: Option<&'a str>,
}

/// Error building the canonical payload: a field carried an LF/CR, which
/// would make the canonical form ambiguous. Refused, never escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptPayloadError {
    /// Which canonical field was rejected.
    pub field: &'static str,
}

impl std::fmt::Display for ReceiptPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "routing-receipt field `{}` contains a newline; refusing to build an \
             ambiguous canonical payload",
            self.field
        )
    }
}

impl std::error::Error for ReceiptPayloadError {}

/// Build the canonical payload bytes that are signed and stored verbatim.
///
/// Deterministic: the same fields always produce the same bytes, so an
/// external verifier re-derives them from the published values with no
/// canonicalization library.
pub fn canonical_payload(fields: &RoutingReceiptFields<'_>) -> Result<String, ReceiptPayloadError> {
    for (name, value) in [
        ("message_id", fields.message_id),
        ("tenant_id", fields.tenant_id),
        ("transport", fields.transport),
        ("accepted_at", fields.accepted_at),
    ] {
        if value.contains('\n') || value.contains('\r') {
            return Err(ReceiptPayloadError { field: name });
        }
    }
    if let Some(ip) = fields.actual_source_ip {
        if ip.contains('\n') || ip.contains('\r') {
            return Err(ReceiptPayloadError {
                field: "actual_source_ip",
            });
        }
    }

    let mut payload = String::with_capacity(192);
    payload.push_str(RECEIPT_PAYLOAD_VERSION);
    payload.push('\n');
    payload.push_str("message_id=");
    payload.push_str(fields.message_id);
    payload.push('\n');
    payload.push_str("tenant_id=");
    payload.push_str(fields.tenant_id);
    payload.push('\n');
    payload.push_str("transport=");
    payload.push_str(fields.transport);
    payload.push('\n');
    payload.push_str("accepted_at=");
    payload.push_str(fields.accepted_at);
    // Present only when the transport reported a source IP, the absence
    // itself is part of the signed statement.
    if let Some(ip) = fields.actual_source_ip {
        payload.push('\n');
        payload.push_str("actual_source_ip=");
        payload.push_str(ip);
    }
    Ok(payload)
}

/// Parse the `RECEIPT_SIGNING_KEY` value: 64 hex characters, or base64
/// (standard/URL-safe, padded or not) decoding to exactly 32 bytes.
pub fn parse_signing_seed(raw: &str) -> Result<[u8; RECEIPT_KEY_BYTES], ReceiptKeyError> {
    let trimmed = raw.trim();
    let expected = "64 hex characters or base64 of 32 bytes";
    if trimmed.is_empty() {
        return Err(ReceiptKeyError::InvalidEncoding { expected });
    }

    let decoded: Vec<u8> = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex::decode(trimmed).map_err(|_| ReceiptKeyError::InvalidEncoding { expected })?
    } else {
        decode_base64_candidates(trimmed).ok_or(ReceiptKeyError::InvalidEncoding { expected })?
    };

    if decoded.len() != RECEIPT_KEY_BYTES {
        return Err(ReceiptKeyError::InvalidEncoding { expected });
    }
    let mut seed = [0u8; RECEIPT_KEY_BYTES];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

/// Object-safe view over base64 engines so the candidate list can be
/// iterated without repeating the padding dance. Every accepted flavour
/// decodes to the same bytes for valid input; the first successful decode
/// wins.
trait EngineDispatch {
    fn decode_checked(&self, input: &str) -> Result<Vec<u8>, base64::DecodeError>;
}

impl EngineDispatch for base64::engine::general_purpose::GeneralPurpose {
    fn decode_checked(&self, input: &str) -> Result<Vec<u8>, base64::DecodeError> {
        self.decode(input)
    }
}

/// Try every accepted base64 flavour; `None` when none decoded.
fn decode_base64_candidates(input: &str) -> Option<Vec<u8>> {
    let engines: [&dyn EngineDispatch; 4] = [
        &B64_STANDARD,
        &STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &URL_SAFE_NO_PAD,
    ];
    engines
        .iter()
        .find_map(|engine| engine.decode_checked(input).ok())
}

/// Derive the 32-byte Ed25519 public key from a 32-byte seed.
pub fn public_key_from_seed(seed: &[u8; RECEIPT_KEY_BYTES]) -> [u8; RECEIPT_KEY_BYTES] {
    // `from_seed_unchecked` performs the scalar multiplication; the keypair
    // is used only to read the public half back out.
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).expect("ring accepts any 32-byte Ed25519 seed");
    let mut public = [0u8; RECEIPT_KEY_BYTES];
    public.copy_from_slice(pair.public_key().as_ref());
    public
}

/// The signed receipt: canonical payload + signature + scheme + key id. The
/// byte-for-byte text is what gets persisted next to the ledger row and what
/// the public verify endpoint accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoutingReceipt {
    /// The exact canonical payload bytes (UTF-8).
    pub payload: String,
    /// Base64 (standard, no padding) of the 64-byte signature.
    pub signature: String,
    /// Always [`RECEIPT_SIGNATURE_SCHEME`].
    pub scheme: &'static str,
    /// `hex(sha256(public_key))[..16]`.
    pub key_id: String,
}

/// An Ed25519 signing key for routing receipts. Not `Clone` (ring's keypair
/// holds the expanded secret); share it behind an `Arc`. The seed itself is
/// not retained.
pub struct RoutingReceiptSigner {
    key_pair: Ed25519KeyPair,
    public_key: [u8; RECEIPT_KEY_BYTES],
    key_id: String,
}

impl std::fmt::Debug for RoutingReceiptSigner {
    /// Never debug-print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingReceiptSigner")
            .field("scheme", &RECEIPT_SIGNATURE_SCHEME)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl RoutingReceiptSigner {
    /// Build from a raw 32-byte seed.
    pub fn from_seed(seed: &[u8; RECEIPT_KEY_BYTES]) -> Result<Self, ReceiptKeyError> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|error| ReceiptKeyError::Rejected(format!("{error:?}")))?;
        let mut public_key = [0u8; RECEIPT_KEY_BYTES];
        public_key.copy_from_slice(key_pair.public_key().as_ref());
        // Hard check (cheap, once per signer): the published key is the
        // seed's derivation, so a broken ring round trip cannot publish a
        // different key than the operator's seed implies.
        assert_eq!(public_key, public_key_from_seed(seed));
        Ok(Self {
            key_pair,
            key_id: key_id_for(&public_key),
            public_key,
        })
    }

    /// Build from the `RECEIPT_SIGNING_KEY` string form.
    pub fn from_secret_key_str(raw: &str) -> Result<Self, ReceiptKeyError> {
        Self::from_seed(&parse_signing_seed(raw)?)
    }

    /// Resolve the signer from the process environment.
    ///
    /// * key set + valid → `Ok(Some(signer))`
    /// * key set + malformed → `Err` (always fatal: a malformed key must
    ///   never silently degrade into unsigned receipts)
    /// * key unset → `Ok(None)`; the CALLER decides whether absence is
    ///   acceptable (dev) or fatal (production, see
    ///   [`receipt_signer_required_in_production`]).
    pub fn from_env() -> Result<Option<Self>, ReceiptKeyError> {
        match std::env::var(RECEIPT_SIGNING_KEY_ENV) {
            Ok(raw) if !raw.trim().is_empty() => Self::from_secret_key_str(&raw).map(Some),
            _ => Ok(None),
        }
    }

    /// Generate a fresh keypair (development / test fixtures only).
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("system RNG must produce an Ed25519 keypair");
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("freshly generated PKCS#8 parses");
        let mut public_key = [0u8; RECEIPT_KEY_BYTES];
        public_key.copy_from_slice(key_pair.public_key().as_ref());
        Self {
            key_pair,
            key_id: key_id_for(&public_key),
            public_key,
        }
    }

    /// The 32-byte public half.
    pub fn public_key(&self) -> [u8; RECEIPT_KEY_BYTES] {
        self.public_key
    }

    /// Base64 (standard, no padding) public key, the published form.
    pub fn public_key_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.public_key)
    }

    /// Lowercase hex public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// `hex(sha256(public_key))[..16]`, recorded with every signature.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The scheme label (`ed25519`).
    pub fn scheme(&self) -> &'static str {
        RECEIPT_SIGNATURE_SCHEME
    }

    /// Sign a canonical payload.
    pub fn sign_payload(&self, payload: &str) -> SignedRoutingReceipt {
        let signature = self.key_pair.sign(payload.as_bytes());
        SignedRoutingReceipt {
            payload: payload.to_string(),
            signature: STANDARD_NO_PAD.encode(signature.as_ref()),
            scheme: RECEIPT_SIGNATURE_SCHEME,
            key_id: self.key_id.clone(),
        }
    }

    /// Canonicalize + sign in one step (the acceptance-path helper).
    pub fn sign_fields(
        &self,
        fields: &RoutingReceiptFields<'_>,
    ) -> Result<SignedRoutingReceipt, ReceiptPayloadError> {
        let payload = canonical_payload(fields)?;
        Ok(self.sign_payload(&payload))
    }

    /// Canonicalize + sign the CUSTOMER-PROOF form (v2). Same key, same
    /// key id, a different version tag: a proof signature can never be
    /// replayed as an internal receipt or vice versa.
    pub fn sign_customer_proof(
        &self,
        fields: &CustomerProofFields<'_>,
    ) -> Result<SignedRoutingReceipt, ReceiptPayloadError> {
        let payload = canonical_customer_proof(fields)?;
        Ok(self.sign_payload(&payload))
    }
}

/// `hex(sha256(public_key))[..16]`.
pub fn key_id_for(public_key: &[u8; RECEIPT_KEY_BYTES]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..8])
}

/// Why a presented (payload, signature) pair was rejected. Reported to
/// callers as a verdict, never as a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerifyError {
    /// The signature was not base64/hex of exactly 64 bytes.
    MalformedSignature,
    /// The public key was not 32 bytes in either accepted encoding.
    MalformedPublicKey,
    /// The signature does not verify over the payload under this key.
    SignatureMismatch,
}

impl std::fmt::Display for ReceiptVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedSignature => {
                write!(f, "signature is not 64 bytes of base64/hex Ed25519")
            }
            Self::MalformedPublicKey => {
                write!(f, "public key is not 32 bytes of base64/hex Ed25519")
            }
            Self::SignatureMismatch => write!(
                f,
                "Ed25519 signature does not verify over the payload under this public key"
            ),
        }
    }
}

impl std::error::Error for ReceiptVerifyError {}

/// Decode a signature presented as base64 (standard/URL-safe, padded or not)
/// or 128 hex characters.
pub fn parse_signature(raw: &str) -> Result<[u8; RECEIPT_SIGNATURE_BYTES], ReceiptVerifyError> {
    let trimmed = raw.trim();
    let decoded: Vec<u8> = if trimmed.len() == RECEIPT_SIGNATURE_BYTES * 2
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex::decode(trimmed).map_err(|_| ReceiptVerifyError::MalformedSignature)?
    } else {
        decode_base64_candidates(trimmed).ok_or(ReceiptVerifyError::MalformedSignature)?
    };
    if decoded.len() != RECEIPT_SIGNATURE_BYTES {
        return Err(ReceiptVerifyError::MalformedSignature);
    }
    let mut signature = [0u8; RECEIPT_SIGNATURE_BYTES];
    signature.copy_from_slice(&decoded);
    Ok(signature)
}

/// Decode a public key presented as base64 or 64 hex characters.
pub fn parse_public_key(raw: &str) -> Result<[u8; RECEIPT_KEY_BYTES], ReceiptVerifyError> {
    let trimmed = raw.trim();
    let decoded: Vec<u8> = if trimmed.len() == RECEIPT_KEY_BYTES * 2
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex::decode(trimmed).map_err(|_| ReceiptVerifyError::MalformedPublicKey)?
    } else {
        decode_base64_candidates(trimmed).ok_or(ReceiptVerifyError::MalformedPublicKey)?
    };
    if decoded.len() != RECEIPT_KEY_BYTES {
        return Err(ReceiptVerifyError::MalformedPublicKey);
    }
    let mut public_key = [0u8; RECEIPT_KEY_BYTES];
    public_key.copy_from_slice(&decoded);
    Ok(public_key)
}

/// Verify a presented (payload, signature) pair under a public key.
///
/// This is the exact function the public verify endpoint runs; it needs no
/// secret material, so an external party can reproduce it with any Ed25519
/// implementation over the canonical payload bytes.
pub fn verify_payload(
    payload: &str,
    signature: &str,
    public_key: &[u8; RECEIPT_KEY_BYTES],
) -> Result<(), ReceiptVerifyError> {
    let signature = parse_signature(signature)?;
    UnparsedPublicKey::new(&ED25519, public_key.as_slice())
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| ReceiptVerifyError::SignatureMismatch)
}

/// Whether this process must refuse to run without `RECEIPT_SIGNING_KEY`.
///
/// Follows the repo-wide production detection (`NODE_ENV` / `ENVIRONMENT` /
/// `APP_ENV` = production|prod, the same set `apexmail-lib`'s
/// `secret_at_rest` uses). In production an unsigned acceptance path is a
/// contradiction of the "no claim without evidence" invariant, so the
/// services that write receipts refuse to boot without a key; in dev the
/// absence is tolerated at BOOT but every receipt write still refuses to
/// record an unsigned row.
pub fn receipt_signer_required_in_production() -> bool {
    ["NODE_ENV", "ENVIRONMENT", "APP_ENV"]
        .into_iter()
        .any(|var| {
            let value = std::env::var(var).unwrap_or_default();
            value.eq_ignore_ascii_case("production") || value.eq_ignore_ascii_case("prod")
        })
}

/// Resolve the public key used to publish/verify receipts from the process
/// environment.
///
/// * `RECEIPT_PUBLIC_KEY` set and valid → `Ok(Some(public_key))`.
/// * unset, `RECEIPT_SIGNING_KEY` set and valid → its derived public half.
/// * both unset → `Ok(None)`, the caller must answer 503, never fabricate a
///   key (fail closed).
/// * either set but malformed → `Err` (always fatal for the endpoint).
pub fn verification_key_from_env() -> Result<Option<[u8; RECEIPT_KEY_BYTES]>, ReceiptVerifyError> {
    match std::env::var(RECEIPT_PUBLIC_KEY_ENV) {
        Ok(raw) if !raw.trim().is_empty() => return parse_public_key(&raw).map(Some),
        _ => {}
    }
    match std::env::var(RECEIPT_SIGNING_KEY_ENV) {
        Ok(raw) if !raw.trim().is_empty() => {
            let seed =
                parse_signing_seed(&raw).map_err(|_| ReceiptVerifyError::MalformedPublicKey)?;
            Ok(Some(public_key_from_seed(&seed)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn fields<'a>(ip: Option<&'a str>) -> RoutingReceiptFields<'a> {
        RoutingReceiptFields {
            message_id: "msg_01HZX",
            tenant_id: "tenant-a",
            transport: "dedicated",
            accepted_at: "2026-10-15T09:30:00.123+00:00",
            actual_source_ip: ip,
        }
    }

    #[test]
    fn customer_proof_is_minimal_signed_and_never_carries_internals() {
        let signer = RoutingReceiptSigner::from_seed(&seed(11)).unwrap();
        let receipt_id = customer_proof_receipt_id("msg_01HZX", "tenant-a");
        let proof = signer
            .sign_customer_proof(&CustomerProofFields {
                receipt_id: &receipt_id,
                routing_policy: "eu_only",
                policy_satisfied: true,
                residency_class: "EEA",
                accepted_at: "2026-10-15T09:30:00.123+00:00",
            })
            .unwrap();
        // Verifies under the published key alone.
        verify_payload(&proof.payload, &proof.signature, &signer.public_key()).unwrap();
        // And carries NONE of the internal receipt's routing internals.
        for absent in [
            "tenant-a",
            "msg_01HZX",
            "transport=",
            "actual_source_ip",
            "ses",
            "dedicated",
        ] {
            assert!(
                !proof.payload.contains(absent),
                "proof must not carry `{absent}`"
            );
        }
        assert!(proof.payload.starts_with("apexmail-routing-proof/v2\n"));
        // The opaque id is deterministic and does not leak its inputs.
        assert_eq!(
            receipt_id,
            customer_proof_receipt_id("msg_01HZX", "tenant-a")
        );
        assert_ne!(
            receipt_id,
            customer_proof_receipt_id("msg_01HZY", "tenant-a")
        );
        assert!(!receipt_id.contains("msg"));
        // A proof signature cannot be replayed as an internal receipt shape.
        assert!(!proof.payload.starts_with(RECEIPT_PAYLOAD_VERSION));
    }

    #[test]
    fn customer_proof_refuses_newlines() {
        let err = canonical_customer_proof(&CustomerProofFields {
            receipt_id: "ok",
            routing_policy: "eu\n_only",
            policy_satisfied: true,
            residency_class: "EEA",
            accepted_at: "t",
        })
        .expect_err("newline refused");
        assert_eq!(err.field, "routing_policy");
    }

    #[test]
    fn canonical_payload_is_deterministic_and_omits_a_missing_source_ip() {
        let with_ip = canonical_payload(&fields(Some("203.0.113.9"))).expect("payload");
        let without_ip = canonical_payload(&fields(None)).expect("payload");
        assert_eq!(
            with_ip,
            canonical_payload(&fields(Some("203.0.113.9"))).unwrap()
        );
        assert!(with_ip.ends_with("actual_source_ip=203.0.113.9"));
        assert!(!without_ip.contains("actual_source_ip"));
        assert!(without_ip.starts_with(RECEIPT_PAYLOAD_VERSION));
    }

    #[test]
    fn canonical_payload_refuses_newlines_instead_of_escaping() {
        let err = canonical_payload(&RoutingReceiptFields {
            message_id: "msg\ninjected=1",
            ..fields(None)
        })
        .expect_err("newline must be refused");
        assert_eq!(err.field, "message_id");
    }

    #[test]
    fn seed_parses_from_hex_and_every_base64_flavour() {
        let raw = seed(7);
        assert_eq!(parse_signing_seed(&hex::encode(raw)).unwrap(), raw);
        assert_eq!(parse_signing_seed(&B64_STANDARD.encode(raw)).unwrap(), raw);
        assert_eq!(
            parse_signing_seed(&base64::engine::general_purpose::URL_SAFE.encode(raw)).unwrap(),
            raw
        );
        assert_eq!(
            parse_signing_seed(&STANDARD_NO_PAD.encode(raw)).unwrap(),
            raw
        );
    }

    #[test]
    fn seed_parser_rejects_empty_and_wrong_length_keys() {
        for bad in ["", "abcd", &"aa".repeat(31), &"aa".repeat(33)] {
            assert!(matches!(
                parse_signing_seed(bad),
                Err(ReceiptKeyError::InvalidEncoding { .. })
            ));
        }
    }

    #[test]
    fn signature_round_trips_and_recomputes_from_the_published_public_key() {
        let signer = RoutingReceiptSigner::from_seed(&seed(3)).expect("signer");
        let signed = signer.sign_fields(&fields(Some("198.51.100.7"))).unwrap();

        assert_eq!(signed.scheme, "ed25519");
        assert_eq!(signed.key_id, signer.key_id());

        // An INDEPENDENT verifier: only the published public key + payload.
        let published = parse_public_key(&signer.public_key_base64()).expect("published key");
        assert_eq!(published, public_key_from_seed(&seed(3)));
        verify_payload(&signed.payload, &signed.signature, &published).expect("must verify");
        // Accepted in hex form too.
        verify_payload(
            &signed.payload,
            &hex::encode(parse_signature(&signed.signature).unwrap()),
            &parse_public_key(&signer.public_key_hex()).unwrap(),
        )
        .expect("hex forms verify");
    }

    #[test]
    fn tampered_payload_or_signature_fails_verification() {
        let signer = RoutingReceiptSigner::from_seed(&seed(4)).expect("signer");
        let signed = signer.sign_fields(&fields(Some("198.51.100.7"))).unwrap();
        let public = signer.public_key();

        let tampered_payload = signed.payload.replace("tenant-a", "tenant-b");
        assert_eq!(
            verify_payload(&tampered_payload, &signed.signature, &public),
            Err(ReceiptVerifyError::SignatureMismatch)
        );

        let mut raw = parse_signature(&signed.signature).unwrap();
        raw[0] ^= 0x01;
        let flipped = STANDARD_NO_PAD.encode(raw);
        assert_eq!(
            verify_payload(&signed.payload, &flipped, &public),
            Err(ReceiptVerifyError::SignatureMismatch)
        );

        // A different key must not verify the same payload/signature.
        let other = RoutingReceiptSigner::from_seed(&seed(5)).expect("signer");
        assert_eq!(
            verify_payload(&signed.payload, &signed.signature, &other.public_key()),
            Err(ReceiptVerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn malformed_signature_and_public_key_are_verdicts_not_panics() {
        let signer = RoutingReceiptSigner::from_seed(&seed(6)).unwrap();
        let signed = signer.sign_fields(&fields(None)).unwrap();
        assert_eq!(
            verify_payload(&signed.payload, "not-a-signature", &signer.public_key()),
            Err(ReceiptVerifyError::MalformedSignature)
        );
        assert_eq!(
            parse_public_key("short"),
            Err(ReceiptVerifyError::MalformedPublicKey)
        );
    }

    /// A generated signer publishes exactly the key a verifier decodes from
    /// the served forms, and a receipt it signs verifies under that
    /// published key alone (no secret material on the verifier side).
    #[test]
    fn a_generated_signer_verifies_under_its_published_key_alone() {
        let signer = RoutingReceiptSigner::generate();
        let published = parse_public_key(&signer.public_key_base64()).expect("published key");
        assert_eq!(published, signer.public_key());
        assert_eq!(
            parse_public_key(&signer.public_key_hex()).expect("hex form"),
            published
        );
        let signed = signer.sign_fields(&fields(None)).unwrap();
        verify_payload(&signed.payload, &signed.signature, &published).expect("must verify");
    }

    #[test]
    fn key_id_is_the_documented_fingerprint() {
        let public = seed(9);
        assert_eq!(
            key_id_for(&public),
            hex::encode(&Sha256::digest(public)[..8])
        );
        assert_eq!(key_id_for(&public).len(), 16);
    }
}
