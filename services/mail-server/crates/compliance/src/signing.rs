//! Statutory-document authenticity: RFC 3161 trusted timestamps and
//! ASiC-E / BDOC (ETSI EN 319 162) signature-container verification.
//!
//! # Why this module exists
//!
//! Statutory filings (annual reports, tax returns, KMD/TSD/VD submissions)
//! need an authenticity anchor that a third party can re-verify later. A bare
//! "authenticated-actor attestation" is not independently verifiable: it says
//! only that *some* credential was presented to *this* service. This module
//! produces and verifies two standard, externally checkable artefacts:
//!
//! * **RFC 3161 timestamps** — a TSA signs a message imprint (a SHA-2 digest
//!   of the document) together with a nonce and a `genTime`. The token is a
//!   CMS `SignedData` (RFC 5652) carrying a `TSTInfo` (RFC 3161).
//! * **ASiC-E / BDOC containers** — a ZIP whose members are the signed
//!   documents plus `META-INF/signatures*.xml` holding XML-DSig / XAdES
//!   signatures over those members.
//!
//! # What is PROVEN (timestamp)
//!
//! * The TSA returned `PKIStatusInfo.status = granted(0)` for this request.
//! * The token's `TSTInfo.messageImprint` digest equals the digest this module
//!   computed over the exact document bytes it submitted.
//! * The token's nonce equals the 64-bit nonce this module generated and sent,
//!   so the token is a response to *this* exchange (not a replay of another).
//! * `TSTInfo.genTime` parses and lies within the configured tolerance of the
//!   caller-supplied verification clock.
//! * The first certificate in `SignedData.certificates` parses as X.509.
//! * The CMS `digestAlgorithms` set and the signer's `digestAlgorithm` are
//!   accepted SHA-2 algorithms.
//! * When the signature algorithm is in the supported set (RSA PKCS#1 v1.5
//!   SHA-1/256/384/512, ECDSA P-256/P-384 SHA-256/384, Ed25519 — the set the
//!   `ring` backend of `x509-parser` implements), the CMS signature over the
//!   signed attributes is checked against the public key of that certificate,
//!   and the signed `messageDigest` attribute is checked against the hash of
//!   the `TSTInfo` eContent. The signature verdict is reported separately
//!   (`token_signature_valid`), and when it cannot be performed the check is
//!   reported as `not_performed` with the exact reason — never as a pass.
//!
//! # What is NOT PROVEN (timestamp)
//!
//! * **That the TSA is authoritative or qualified.** Trust is modelled as
//!   "the operator configured this TSA URL" ([`timestamp::TsaConfig`]). No
//!   check against the EU trusted list, no accreditation check, no
//!   qualified-certificate check. Therefore an evidence record from this
//!   module is *not* by itself a "qualified electronic timestamp" in the sense
//!   of eIDAS Article 42.
//! * **Certificate chain / path validation.** No trust store is configured,
//!   so the signer certificate is not chained to a root, key usage is not
//!   enforced by a path validator, and no revocation (CRL/OCSP) is checked.
//! * **Certificate validity window.** `notBefore`/`notAfter` are recorded but
//!   not enforced; a token signed by an expired certificate is not rejected
//!   here.
//!
//! # What is PROVEN (ASiC-E container)
//!
//! * `mimetype` is exactly `application/vnd.etsi.asic-e+zip`.
//! * `META-INF/signatures*.xml` parses as XML.
//! * Every file `Reference` URI resolves to a member and the member's bytes
//!   hash to the stated `DigestValue` (per-reference verdicts, so a caller can
//!   see exactly which document failed).
//! * Every member outside `mimetype` / `META-INF/` is covered by at least one
//!   reference.
//! * The signing certificate is present and parses as X.509.
//! * When the signature algorithm is in the supported set, the
//!   `SignatureValue` is verified against the certificate's public key over
//!   the *raw octets of the `SignedInfo` element as they appear in the
//!   container*.
//!
//! # What is NOT PROVEN (ASiC-E container)
//!
//! * **XML canonicalization.** The module does not implement exclusive C14N
//!   (or any other canonicalization). The signature check hashes the raw
//!   `SignedInfo` octets, which equal the canonical form only when the
//!   producer serialized the element canonically (the normal case for
//!   conforming ASiC-E tooling, but not guaranteed). Same-document
//!   (`URI="#id"`) reference digests are likewise computed over raw octets,
//!   so a mismatch there is reported as *inconclusive without C14N*, not as
//!   definite tampering.
//! * **ZIP-level structure.** The caller supplies the unpacked members, so
//!   the ASiC-E rules "`mimetype` is the first entry and is stored
//!   uncompressed" cannot be verified here.
//! * **Signer identity / authorization.** The certificate is only checked to
//!   parse; no chain, no qualification, no revocation, no name binding to an
//!   organization.
//!
//! # Fail-closed configuration contract (timestamp transport)
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `APEXMAIL_TSA_URL` | *(unset)* | RFC 3161 TSA endpoint. Unset/empty means no timestamping: [`timestamp::TimeStampError::NotConfigured`]. |
//! | `APEXMAIL_TSA_AUTH_HEADER` | *(unset)* | Optional full header, e.g. `Authorization: Bearer <token>`. Never logged or serialised into evidence. |
//! | `APEXMAIL_TSA_TOLERANCE_SECS` | `300` | Maximum accepted absolute difference between `genTime` and the verification clock. |
//! | `APEXMAIL_TSA_TIMEOUT_SECS` | `30` | Bounded total timeout for the POST. |
//! | `APEXMAIL_TSA_MAX_RESPONSE_BYTES` | `1048576` | Hard cap on the response body; larger replies are rejected before parsing. |
//!
//! A real qualified timestamp additionally requires the operator to contract
//! a qualified trust service provider, point `APEXMAIL_TSA_URL` at its
//! RFC 3161 endpoint, and (outside this module) validate the token against
//! that provider's trust anchor. This module never fabricates a token when no
//! TSA is configured.
//!
//! # Hostile input posture
//!
//! [`der`] is a purpose-built DER reader/writer, not a general ASN.1 library.
//! It refuses indefinite lengths, over-long (non-minimal) lengths, truncated
//! input, trailing garbage, high-tag-number forms, oversized elements, deep
//! nesting and excessive element counts with typed errors. It never panics on
//! malformed input and performs no unbounded recursion.
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Schema version stamped into every evidence record produced here.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Outcome of one named verification check.
///
/// A boolean would hide the difference between "checked and passed",
/// "checked and failed", and "could not be checked". Auditors need the third
/// case stated explicitly, so it is a first-class outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// The check ran and passed.
    Pass,
    /// The check ran and failed; `detail` carries the observed values.
    Fail {
        /// Observed values / reason for failure.
        detail: String,
    },
    /// The check could not run. `reason` states exactly what is missing or
    /// unsupported. This is never treated as a pass by [`all_passed`].
    NotPerformed {
        /// What is missing or unsupported.
        reason: String,
    },
}

impl CheckOutcome {
    /// True only for [`CheckOutcome::Pass`].
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckOutcome::Pass)
    }

    /// True for [`CheckOutcome::Fail`].
    pub fn is_fail(&self) -> bool {
        matches!(self, CheckOutcome::Fail { .. })
    }

    /// True for [`CheckOutcome::NotPerformed`].
    pub fn is_not_performed(&self) -> bool {
        matches!(self, CheckOutcome::NotPerformed { .. })
    }
}

/// One named, independently reported verification check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckVerdict {
    /// Stable machine-readable check id (e.g. `imprint_matches_document`).
    pub check: String,
    /// Whether [`all_passed`] requires this check to be `Pass`.
    pub required: bool,
    /// The outcome.
    pub outcome: CheckOutcome,
    /// Optional extra context, including for passing checks (e.g. a scope
    /// limitation that the operator should read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl CheckVerdict {
    /// A passing check.
    pub fn pass(check: impl Into<String>, required: bool) -> Self {
        Self {
            check: check.into(),
            required,
            outcome: CheckOutcome::Pass,
            note: None,
        }
    }

    /// A failing check; `detail` should carry the observed values.
    pub fn fail(check: impl Into<String>, required: bool, detail: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            required,
            outcome: CheckOutcome::Fail {
                detail: detail.into(),
            },
            note: None,
        }
    }

    /// A check that could not be performed.
    pub fn not_performed(
        check: impl Into<String>,
        required: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            required,
            outcome: CheckOutcome::NotPerformed {
                reason: reason.into(),
            },
            note: None,
        }
    }

    /// Attach a note to any outcome.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// True only for a performed, passing check.
    pub fn is_pass(&self) -> bool {
        self.outcome.is_pass()
    }
}

/// True when every required check passed. Optional checks that failed or were
/// not performed do not block; inspect them via the returned evidence.
pub fn all_passed(checks: &[CheckVerdict]) -> bool {
    checks.iter().all(|check| !check.required || check.outcome.is_pass())
}

/// True when every check (required or not) is a `Pass` — the strongest claim
/// this module can make. A `not_performed` check (e.g. an unsupported
/// signature algorithm) makes this false.
pub fn strictly_passed(checks: &[CheckVerdict]) -> bool {
    checks.iter().all(|check| check.outcome.is_pass())
}

/// True when any check failed, required or not.
pub fn has_failures(checks: &[CheckVerdict]) -> bool {
    checks.iter().any(|check| check.outcome.is_fail())
}

/// Human-readable summary of the non-passing checks, for error messages.
pub fn describe_failures(checks: &[CheckVerdict]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for check in checks {
        match &check.outcome {
            CheckOutcome::Pass => {}
            CheckOutcome::Fail { detail } => {
                parts.push(format!("{} failed ({})", check.check, detail));
            }
            CheckOutcome::NotPerformed { reason } => {
                parts.push(format!("{} not performed ({})", check.check, reason));
            }
        }
    }
    if parts.is_empty() {
        "no failures".to_string()
    } else {
        parts.join("; ")
    }
}

/// Summary of an X.509 certificate embedded in a token or container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateSummary {
    /// Distinguished name of the subject.
    pub subject: String,
    /// Distinguished name of the issuer.
    pub issuer: String,
    /// Serial number as lowercase hex (no separators).
    pub serial_hex: String,
    /// `notBefore` rendering from the certificate (ASN.1 time string).
    pub not_before: String,
    /// `notAfter` rendering from the certificate (ASN.1 time string).
    pub not_after: String,
    /// Public-key algorithm OID as a dotted string.
    pub public_key_algorithm_oid: String,
    /// SHA-256 of the full certificate DER.
    pub sha256_fingerprint_hex: String,
}

// ---------------------------------------------------------------------------
// Purpose-built DER reader/writer
// ---------------------------------------------------------------------------

/// Minimal DER (X.690) reader and writer, hardened for hostile input.
///
/// This is deliberately *not* a general-purpose ASN.1 library: it supports
/// only the subset RFC 3161 / RFC 5652 need, and every refusal is a typed
/// error. See the module docs for the exact hardening guarantees.
pub mod der {
    use thiserror::Error;

    /// Universal, primitive BOOLEAN.
    pub const TAG_BOOLEAN: u8 = 0x01;
    /// Universal, primitive INTEGER.
    pub const TAG_INTEGER: u8 = 0x02;
    /// Universal, primitive BIT STRING.
    pub const TAG_BIT_STRING: u8 = 0x03;
    /// Universal, primitive OCTET STRING.
    pub const TAG_OCTET_STRING: u8 = 0x04;
    /// Universal, primitive NULL.
    pub const TAG_NULL: u8 = 0x05;
    /// Universal, primitive OBJECT IDENTIFIER.
    pub const TAG_OID: u8 = 0x06;
    /// Universal, primitive UTF8String.
    pub const TAG_UTF8_STRING: u8 = 0x0C;
    /// Universal, primitive UTCTime.
    pub const TAG_UTC_TIME: u8 = 0x17;
    /// Universal, primitive GeneralizedTime.
    pub const TAG_GENERALIZED_TIME: u8 = 0x18;
    /// Universal, constructed SEQUENCE.
    pub const TAG_SEQUENCE: u8 = 0x30;
    /// Universal, constructed SET.
    pub const TAG_SET: u8 = 0x31;
    /// Context-specific, constructed `[0]`.
    pub const TAG_CTX_0: u8 = 0xA0;
    /// Context-specific, constructed `[1]`.
    pub const TAG_CTX_1: u8 = 0xA1;

    /// Typed DER failures.
    #[derive(Debug, Clone, PartialEq, Eq, Error)]
    pub enum DerError {
        /// Input ended where a tag or length byte was required.
        #[error("unexpected end of DER input")]
        UnexpectedEof,
        /// An element claims more bytes than remain.
        #[error("truncated DER element: needs {needed} bytes, {available} available")]
        Truncated {
            /// Bytes the element claims.
            needed: usize,
            /// Bytes actually available.
            available: usize,
        },
        /// Indefinite-length encoding (`0x80`) is not valid DER.
        #[error("indefinite-length DER encodings are refused")]
        IndefiniteLength,
        /// A length was encoded in more bytes than necessary (not DER).
        #[error("non-minimal (over-long) DER length encoding")]
        NonMinimalLength,
        /// The length field itself is longer than 8 bytes.
        #[error("DER length field uses more than 8 bytes")]
        LengthFieldTooLong,
        /// An element exceeds the configured per-element byte cap.
        #[error("DER element of {length} bytes exceeds the configured maximum of {max}")]
        ElementTooLarge {
            /// Declared element length.
            length: usize,
            /// Configured maximum.
            max: usize,
        },
        /// High-tag-number form (tag number 31) is not needed here.
        #[error("unsupported DER tag form (first byte {tag:#04x})")]
        UnsupportedTag {
            /// The offending first byte.
            tag: u8,
        },
        /// A tag did not match the expected one.
        #[error("expected DER tag {expected:#04x} but found {actual:#04x}")]
        UnexpectedTag {
            /// Expected tag byte.
            expected: u8,
            /// Actual tag byte.
            actual: u8,
        },
        /// Nesting deeper than the configured maximum.
        #[error("DER nesting depth exceeds the configured maximum of {max}")]
        DepthExceeded {
            /// Configured maximum depth.
            max: usize,
        },
        /// More elements than the configured maximum.
        #[error("DER element count exceeds the configured maximum of {max}")]
        ElementLimitExceeded {
            /// Configured maximum element count.
            max: usize,
        },
        /// INTEGER bytes were empty, negative, or otherwise malformed.
        #[error("invalid DER INTEGER encoding")]
        InvalidInteger,
        /// The integer does not fit in `u64`.
        #[error("DER INTEGER does not fit in u64")]
        IntegerOverflow,
        /// OBJECT IDENTIFIER bytes were malformed or too long.
        #[error("invalid DER OBJECT IDENTIFIER encoding")]
        InvalidOid,
        /// A string field was not valid UTF-8.
        #[error("invalid UTF-8 in DER string")]
        InvalidUtf8,
        /// BOOLEAN was neither `0x00` nor `0xFF`.
        #[error("invalid DER BOOLEAN encoding")]
        InvalidBoolean,
        /// BIT STRING was empty or had an impossible unused-bit count.
        #[error("invalid DER BIT STRING encoding")]
        InvalidBitString,
        /// GeneralizedTime could not be parsed.
        #[error("invalid GeneralizedTime: {0}")]
        InvalidTime(String),
        /// Bytes follow the top-level element.
        #[error("trailing garbage after the top-level DER element ({remaining} bytes)")]
        TrailingGarbage {
            /// Number of unconsumed bytes.
            remaining: usize,
        },
    }

    /// Resource limits applied to every parse.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Limits {
        /// Maximum constructed nesting depth.
        pub max_depth: usize,
        /// Maximum number of TLVs read with one budget.
        pub max_elements: usize,
        /// Maximum length of a single element's contents.
        pub max_element_bytes: usize,
    }

    impl Default for Limits {
        fn default() -> Self {
            Self {
                max_depth: 24,
                max_elements: 4096,
                max_element_bytes: 16 * 1024 * 1024,
            }
        }
    }

    /// Shared parse budget: depth and element count.
    ///
    /// Pass the *same* budget into nested parsers (`descend` keeps the
    /// invariants) so a deeply nested or very large structure cannot bypass
    /// the limits.
    #[derive(Debug, Clone, Copy)]
    pub struct Budget {
        limits: Limits,
        depth: usize,
        elements: usize,
    }

    impl Budget {
        /// A budget with the given limits.
        pub fn new(limits: Limits) -> Self {
            Self {
                limits,
                depth: 0,
                elements: 0,
            }
        }

        /// The limits in force.
        pub fn limits(&self) -> Limits {
            self.limits
        }

        /// Number of elements read so far.
        pub fn elements_read(&self) -> usize {
            self.elements
        }

        fn note_element(&mut self) -> Result<(), DerError> {
            self.elements = self.elements.saturating_add(1);
            if self.elements > self.limits.max_elements {
                return Err(DerError::ElementLimitExceeded {
                    max: self.limits.max_elements,
                });
            }
            Ok(())
        }

        /// Run `f` one level deeper, refusing if the depth cap is reached.
        pub fn descend<R>(
            &mut self,
            f: impl FnOnce(&mut Budget) -> Result<R, DerError>,
        ) -> Result<R, DerError> {
            if self.depth + 1 > self.limits.max_depth {
                return Err(DerError::DepthExceeded {
                    max: self.limits.max_depth,
                });
            }
            self.depth += 1;
            let result = f(self);
            self.depth -= 1;
            result
        }
    }

    impl Default for Budget {
        fn default() -> Self {
            Self::new(Limits::default())
        }
    }

    /// One decoded tag-length-value element.
    #[derive(Debug, Clone, Copy)]
    pub struct Tlv<'a> {
        /// The first (identifier) byte.
        pub tag: u8,
        /// Whether the constructed bit is set.
        pub constructed: bool,
        /// The element's contents (without tag and length).
        pub content: &'a [u8],
        /// The complete element (tag, length, contents).
        pub encoded: &'a [u8],
    }

    impl<'a> Tlv<'a> {
        /// A cursor over this element's contents.
        pub fn reader(&self) -> Reader<'a> {
            Reader::new(self.content)
        }

        /// Whether this element has the given tag byte.
        pub fn is_tag(&self, tag: u8) -> bool {
            self.tag == tag
        }
    }

    /// A cursor over a DER byte slice.
    #[derive(Debug, Clone)]
    pub struct Reader<'a> {
        input: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        /// A cursor positioned at the start of `input`.
        pub fn new(input: &'a [u8]) -> Self {
            Self { input, pos: 0 }
        }

        /// Current byte offset.
        pub fn position(&self) -> usize {
            self.pos
        }

        /// Bytes not yet consumed.
        pub fn remaining(&self) -> &'a [u8] {
            self.input.get(self.pos..).unwrap_or(&[])
        }

        /// Whether everything has been consumed.
        pub fn is_empty(&self) -> bool {
            self.pos >= self.input.len()
        }

        /// The tag byte at the cursor, if any.
        pub fn peek_tag(&self) -> Option<u8> {
            self.input.get(self.pos).copied()
        }

        /// Read the next element.
        pub fn read(&mut self, budget: &mut Budget) -> Result<Tlv<'a>, DerError> {
            let input = self.input;
            let start = self.pos;
            let first = *input.get(start).ok_or(DerError::UnexpectedEof)?;
            if first & 0x1F == 0x1F {
                return Err(DerError::UnsupportedTag { tag: first });
            }
            let constructed = first & 0x20 != 0;
            let len_byte = *input.get(start + 1).ok_or(DerError::Truncated {
                needed: 2,
                available: input.len().saturating_sub(start),
            })?;

            let (len, header) = if len_byte == 0x80 {
                return Err(DerError::IndefiniteLength);
            } else if len_byte & 0x80 == 0 {
                (len_byte as usize, 2usize)
            } else {
                let n = (len_byte & 0x7F) as usize;
                if n > 8 {
                    return Err(DerError::LengthFieldTooLong);
                }
                let available = input.len().saturating_sub(start + 2);
                if available < n {
                    return Err(DerError::Truncated {
                        needed: n,
                        available,
                    });
                }
                if n > 1 && input[start + 2] == 0 {
                    return Err(DerError::NonMinimalLength);
                }
                let mut value: u64 = 0;
                for index in 0..n {
                    value = (value << 8) | input[start + 2 + index] as u64;
                }
                if value < 0x80 {
                    return Err(DerError::NonMinimalLength);
                }
                let value = usize::try_from(value).map_err(|_| DerError::ElementTooLarge {
                    length: usize::MAX,
                    max: budget.limits.max_element_bytes,
                })?;
                if value > budget.limits.max_element_bytes {
                    return Err(DerError::ElementTooLarge {
                        length: value,
                        max: budget.limits.max_element_bytes,
                    });
                }
                (value, 2 + n)
            };

            let content_start = start + header;
            let end = content_start
                .checked_add(len)
                .ok_or(DerError::ElementTooLarge {
                    length: len,
                    max: budget.limits.max_element_bytes,
                })?;
            if end > input.len() {
                return Err(DerError::Truncated {
                    needed: len,
                    available: input.len().saturating_sub(content_start),
                });
            }
            self.pos = end;
            budget.note_element()?;
            Ok(Tlv {
                tag: first,
                constructed,
                content: input.get(content_start..end).unwrap_or(&[]),
                encoded: input.get(start..end).unwrap_or(&[]),
            })
        }

        /// Read the next element, requiring a specific tag.
        pub fn read_tagged(&mut self, budget: &mut Budget, tag: u8) -> Result<Tlv<'a>, DerError> {
            let tlv = self.read(budget)?;
            if tlv.tag != tag {
                return Err(DerError::UnexpectedTag {
                    expected: tag,
                    actual: tlv.tag,
                });
            }
            Ok(tlv)
        }

        /// Read the next element only if it has the given tag.
        pub fn read_if_tagged(
            &mut self,
            budget: &mut Budget,
            tag: u8,
        ) -> Result<Option<Tlv<'a>>, DerError> {
            if self.peek_tag() == Some(tag) {
                Ok(Some(self.read(budget)?))
            } else {
                Ok(None)
            }
        }

        /// Refuse any unconsumed bytes (trailing garbage).
        pub fn finish(&self) -> Result<(), DerError> {
            if self.pos < self.input.len() {
                Err(DerError::TrailingGarbage {
                    remaining: self.input.len() - self.pos,
                })
            } else {
                Ok(())
            }
        }
    }

    /// Decode a non-negative INTEGER that fits in `u64`.
    pub fn decode_u64(tlv: &Tlv<'_>) -> Result<u64, DerError> {
        if tlv.tag != TAG_INTEGER {
            return Err(DerError::UnexpectedTag {
                expected: TAG_INTEGER,
                actual: tlv.tag,
            });
        }
        let content = tlv.content;
        if content.is_empty() {
            return Err(DerError::InvalidInteger);
        }
        if content[0] & 0x80 != 0 {
            // Negative integers are not used by the structures parsed here.
            return Err(DerError::InvalidInteger);
        }
        let mut first_nonzero = 0usize;
        while first_nonzero < content.len() && content[first_nonzero] == 0 {
            first_nonzero += 1;
        }
        let significant = &content[first_nonzero..];
        if significant.len() > 8 {
            return Err(DerError::IntegerOverflow);
        }
        let mut value: u64 = 0;
        for byte in significant {
            value = (value << 8) | *byte as u64;
        }
        Ok(value)
    }

    /// Decode a BOOLEAN (`0x00` / `0xFF` only).
    pub fn decode_bool(tlv: &Tlv<'_>) -> Result<bool, DerError> {
        if tlv.tag != TAG_BOOLEAN {
            return Err(DerError::UnexpectedTag {
                expected: TAG_BOOLEAN,
                actual: tlv.tag,
            });
        }
        match tlv.content {
            [0x00] => Ok(false),
            [0xFF] => Ok(true),
            _ => Err(DerError::InvalidBoolean),
        }
    }

    /// Decode an OBJECT IDENTIFIER to dotted-decimal form.
    pub fn decode_oid(tlv: &Tlv<'_>) -> Result<String, DerError> {
        if tlv.tag != TAG_OID {
            return Err(DerError::UnexpectedTag {
                expected: TAG_OID,
                actual: tlv.tag,
            });
        }
        decode_oid_bytes(tlv.content)
    }

    /// Decode OBJECT IDENTIFIER *contents* (without tag/length).
    pub fn decode_oid_bytes(content: &[u8]) -> Result<String, DerError> {
        if content.is_empty() {
            return Err(DerError::InvalidOid);
        }
        const MAX_ARCS: usize = 128;
        let mut arcs: Vec<u64> = Vec::new();
        let first = content[0] as u64;
        if first < 40 {
            arcs.push(0);
            arcs.push(first);
        } else if first < 80 {
            arcs.push(1);
            arcs.push(first - 40);
        } else {
            arcs.push(2);
            arcs.push(first - 80);
        }
        let mut value: u64 = 0;
        let mut in_arc = false;
        for byte in &content[1..] {
            if value > (u64::MAX >> 7) {
                return Err(DerError::InvalidOid);
            }
            value = (value << 7) | (byte & 0x7F) as u64;
            in_arc = true;
            if byte & 0x80 == 0 {
                arcs.push(value);
                if arcs.len() > MAX_ARCS {
                    return Err(DerError::InvalidOid);
                }
                value = 0;
                in_arc = false;
            }
        }
        if in_arc {
            return Err(DerError::InvalidOid);
        }
        Ok(arcs
            .iter()
            .map(|arc| arc.to_string())
            .collect::<Vec<_>>()
            .join("."))
    }

    /// Decode a GeneralizedTime to UTC.
    ///
    /// Accepts `YYYYMMDDHHMMSS[.fraction](Z|+hhmm|-hhmm)`; RFC 3161 requires
    /// the `Z` form and this parser is deliberately strict about shape (fixed
    /// 14 leading digits, bounded length, ASCII digits only).
    pub fn decode_generalized_time(
        tlv: &Tlv<'_>,
    ) -> Result<chrono::DateTime<chrono::Utc>, DerError> {
        if tlv.tag != TAG_GENERALIZED_TIME {
            return Err(DerError::UnexpectedTag {
                expected: TAG_GENERALIZED_TIME,
                actual: tlv.tag,
            });
        }
        let text = std::str::from_utf8(tlv.content).map_err(|_| DerError::InvalidUtf8)?;
        if !text.is_ascii() || text.len() < 15 || text.len() > 32 {
            return Err(DerError::InvalidTime(format!(
                "unexpected GeneralizedTime shape ({} bytes)",
                text.len()
            )));
        }
        let digits = &text[..14];
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DerError::InvalidTime(
                "GeneralizedTime date/time portion is not 14 digits".to_string(),
            ));
        }
        let number = |slice: &str| -> Result<u32, DerError> {
            slice
                .parse::<u32>()
                .map_err(|_| DerError::InvalidTime(format!("bad number {slice:?}")))
        };
        let year = number(&digits[0..4])?;
        let month = number(&digits[4..6])?;
        let day = number(&digits[6..8])?;
        let hour = number(&digits[8..10])?;
        let minute = number(&digits[10..12])?;
        let second = number(&digits[12..14])?;

        let mut rest = &text[14..];
        let mut nanos: u32 = 0;
        let fraction = rest
            .strip_prefix('.')
            .or_else(|| rest.strip_prefix(','));
        if let Some(fraction) = fraction {
            let digit_count = fraction
                .bytes()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digit_count == 0 {
                return Err(DerError::InvalidTime(
                    "empty fractional seconds".to_string(),
                ));
            }
            let significant = &fraction[..digit_count.min(9)];
            let mut parsed: u32 = 0;
            let mut scale: u32 = 0;
            for byte in significant.bytes() {
                parsed = parsed * 10 + (byte - b'0') as u32;
                scale += 1;
            }
            while scale < 9 {
                parsed = parsed.saturating_mul(10);
                scale += 1;
            }
            nanos = parsed;
            rest = &fraction[digit_count..];
        }

        let offset_seconds: i32 = if rest == "Z" || rest == "z" {
            0
        } else if rest.len() == 5 && (rest.starts_with('+') || rest.starts_with('-')) {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let hours = number(&rest[1..3])?;
            let minutes = number(&rest[3..5])?;
            if hours > 23 || minutes > 59 {
                return Err(DerError::InvalidTime(format!("bad UTC offset {rest:?}")));
            }
            sign * (hours as i32 * 3600 + minutes as i32 * 60)
        } else {
            return Err(DerError::InvalidTime(format!(
                "missing or malformed timezone designator in {text:?}"
            )));
        };

        use chrono::{FixedOffset, NaiveDate, TimeZone, Utc};
        let naive = NaiveDate::from_ymd_opt(year as i32, month, day)
            .and_then(|date| date.and_hms_nano_opt(hour, minute, second, nanos))
            .ok_or_else(|| DerError::InvalidTime(format!("out-of-range date/time in {text:?}")))?;
        let zone = FixedOffset::east_opt(offset_seconds)
            .ok_or_else(|| DerError::InvalidTime("bad UTC offset".to_string()))?;
        let offset_aware = zone
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(|| DerError::InvalidTime("ambiguous local time".to_string()))?;
        Ok(offset_aware.with_timezone(&Utc))
    }

    /// Decode an OCTET STRING.
    pub fn decode_octet_string<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], DerError> {
        if tlv.tag != TAG_OCTET_STRING {
            return Err(DerError::UnexpectedTag {
                expected: TAG_OCTET_STRING,
                actual: tlv.tag,
            });
        }
        Ok(tlv.content)
    }

    /// Check the unused-bit count of a BIT STRING and return its data bytes.
    pub fn decode_bit_string<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], DerError> {
        if tlv.tag != TAG_BIT_STRING {
            return Err(DerError::UnexpectedTag {
                expected: TAG_BIT_STRING,
                actual: tlv.tag,
            });
        }
        let (unused, data) = tlv.content.split_first().ok_or(DerError::InvalidBitString)?;
        if *unused > 7 || (*unused > 0 && data.is_empty()) {
            return Err(DerError::InvalidBitString);
        }
        Ok(data)
    }

    // -- Writer ---------------------------------------------------------------

    /// Encode a TLV element with a definite, minimal length.
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(content.len() + 6);
        out.push(tag);
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut length_bytes = Vec::new();
            let mut remaining = len;
            while remaining > 0 {
                length_bytes.push((remaining & 0xFF) as u8);
                remaining >>= 8;
            }
            length_bytes.reverse();
            out.push(0x80 | length_bytes.len() as u8);
            out.extend_from_slice(&length_bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// Concatenate already-encoded parts.
    pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = parts.iter().map(|part| part.len()).sum();
        let mut out = Vec::with_capacity(total);
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    /// Encode a SEQUENCE from already-encoded parts.
    pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &concat(parts))
    }

    /// Encode a SET from already-encoded parts.
    pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_SET, &concat(parts))
    }

    /// Encode a BOOLEAN.
    pub fn boolean(value: bool) -> Vec<u8> {
        tlv(TAG_BOOLEAN, &[if value { 0xFF } else { 0x00 }])
    }

    /// Encode a NULL.
    pub fn null() -> Vec<u8> {
        tlv(TAG_NULL, &[])
    }

    /// Encode a non-negative INTEGER from a `u64` (minimal, with a leading
    /// zero only when the high bit requires it).
    pub fn unsigned_integer(value: u64) -> Vec<u8> {
        unsigned_integer_bytes(&value.to_be_bytes())
    }

    /// Encode a non-negative INTEGER from big-endian magnitude bytes.
    pub fn unsigned_integer_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut first_nonzero = 0usize;
        while first_nonzero < bytes.len() && bytes[first_nonzero] == 0 {
            first_nonzero += 1;
        }
        let significant = &bytes[first_nonzero..];
        if significant.is_empty() {
            return tlv(TAG_INTEGER, &[0x00]);
        }
        if significant[0] & 0x80 != 0 {
            let mut content = Vec::with_capacity(significant.len() + 1);
            content.push(0x00);
            content.extend_from_slice(significant);
            tlv(TAG_INTEGER, &content)
        } else {
            tlv(TAG_INTEGER, significant)
        }
    }

    /// Encode an OCTET STRING.
    pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
        tlv(TAG_OCTET_STRING, bytes)
    }

    /// Encode an OBJECT IDENTIFIER from dotted-decimal form.
    pub fn oid(dotted: &str) -> Result<Vec<u8>, DerError> {
        let mut arcs: Vec<u64> = Vec::new();
        for part in dotted.split('.') {
            let arc = part.parse::<u64>().map_err(|_| DerError::InvalidOid)?;
            arcs.push(arc);
            if arcs.len() > 128 {
                return Err(DerError::InvalidOid);
            }
        }
        if arcs.len() < 2 || arcs[0] > 2 {
            return Err(DerError::InvalidOid);
        }
        if arcs[0] < 2 && arcs[1] > 39 {
            return Err(DerError::InvalidOid);
        }
        let mut content = Vec::new();
        push_base128(&mut content, arcs[0] * 40 + arcs[1]);
        for arc in &arcs[2..] {
            push_base128(&mut content, *arc);
        }
        Ok(tlv(TAG_OID, &content))
    }

    fn push_base128(out: &mut Vec<u8>, value: u64) {
        let mut buffer = [0u8; 10];
        let mut index = buffer.len() - 1;
        buffer[index] = (value & 0x7F) as u8;
        let mut remaining = value >> 7;
        while remaining > 0 {
            index -= 1;
            buffer[index] = ((remaining & 0x7F) as u8) | 0x80;
            remaining >>= 7;
        }
        out.extend_from_slice(&buffer[index..]);
    }

    /// Encode an `AlgorithmIdentifier` with `NULL` parameters (RSA-style).
    pub fn algorithm_identifier(dotted: &str) -> Result<Vec<u8>, DerError> {
        Ok(sequence(&[oid(dotted)?, null()]))
    }

    /// Encode an `AlgorithmIdentifier` with absent parameters (EC/Ed25519).
    pub fn algorithm_identifier_without_parameters(dotted: &str) -> Result<Vec<u8>, DerError> {
        Ok(sequence(&[oid(dotted)?]))
    }
}

// ---------------------------------------------------------------------------
// RFC 3161 timestamps
// ---------------------------------------------------------------------------

/// RFC 3161 / RFC 5652 timestamps: request building, transport, token parsing
/// and named verification checks. See the module docs for proven / not-proven
/// properties and the configuration contract.
pub mod timestamp {
    use super::der::{self, Budget, DerError, Reader, Tlv};
    use super::{
        all_passed, describe_failures, CheckVerdict, CertificateSummary, EVIDENCE_SCHEMA_VERSION,
    };
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256, Sha512};
    use thiserror::Error;
    use x509_parser::prelude::FromDer;

    /// Environment variable holding the TSA endpoint. Unset means no
    /// timestamping (fail closed).
    pub const ENV_TSA_URL: &str = "APEXMAIL_TSA_URL";
    /// Environment variable holding an optional HTTP auth header
    /// (full `Name: Value` form).
    pub const ENV_TSA_AUTH_HEADER: &str = "APEXMAIL_TSA_AUTH_HEADER";
    /// Environment variable for the genTime tolerance in seconds.
    pub const ENV_TSA_TOLERANCE_SECS: &str = "APEXMAIL_TSA_TOLERANCE_SECS";
    /// Environment variable for the HTTP timeout in seconds.
    pub const ENV_TSA_TIMEOUT_SECS: &str = "APEXMAIL_TSA_TIMEOUT_SECS";
    /// Environment variable for the response size cap in bytes.
    pub const ENV_TSA_MAX_RESPONSE_BYTES: &str = "APEXMAIL_TSA_MAX_RESPONSE_BYTES";

    /// Default genTime tolerance (seconds).
    pub const DEFAULT_TOLERANCE_SECS: i64 = 300;
    /// Default HTTP timeout (seconds).
    pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
    /// Default response body cap (bytes).
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

    /// OID of SHA-256 (`id-sha256`, RFC 8017).
    pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
    /// OID of SHA-384.
    pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
    /// OID of SHA-512.
    pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
    /// OID of PKCS#7 `signedData`.
    pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    /// OID of `id-ct-TSTInfo`.
    pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
    /// OID of the CMS `contentType` signed attribute.
    pub const OID_CONTENT_TYPE_ATTR: &str = "1.2.840.113549.1.9.3";
    /// OID of the CMS `messageDigest` signed attribute.
    pub const OID_MESSAGE_DIGEST_ATTR: &str = "1.2.840.113549.1.9.4";
    /// OID of the ESS `signingCertificateV2` signed attribute (RFC 5035).
    pub const OID_SIGNING_CERT_V2_ATTR: &str = "1.2.840.113549.1.9.16.2.47";
    /// OID of `rsaEncryption` as used for CMS `signatureAlgorithm`.
    pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    /// OID of RSASSA-PSS.
    pub const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";

    /// Map a CMS digest algorithm onto the combined PKCS#1 v1.5 signature OID.
    fn rsa_pkcs1_oid_for_digest(digest_oid: &str) -> Option<&'static str> {
        match digest_oid {
            OID_SHA256 => Some("1.2.840.113549.1.1.11"),
            OID_SHA384 => Some("1.2.840.113549.1.1.12"),
            OID_SHA512 => Some("1.2.840.113549.1.1.13"),
            _ => None,
        }
    }

    /// SHA-2 digests this module will request and accept.
    pub const ACCEPTED_DIGESTS: &[&str] = &[OID_SHA256, OID_SHA384, OID_SHA512];

    const HTTP_CONTENT_TYPE: &str = "application/timestamp-query";
    const HTTP_ACCEPT: &str = "application/timestamp-reply";
    const HTTP_CONTENT_TYPE_REPLY: &str = "application/timestamp-reply";

    /// Digest algorithm that can be requested from a TSA.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum HashAlgorithm {
        /// SHA-256 (`2.16.840.1.101.3.4.2.1`).
        Sha256,
        /// SHA-512 (`2.16.840.1.101.3.4.2.3`).
        Sha512,
    }

    impl HashAlgorithm {
        /// The digest algorithm OID.
        pub const fn oid(self) -> &'static str {
            match self {
                HashAlgorithm::Sha256 => OID_SHA256,
                HashAlgorithm::Sha512 => OID_SHA512,
            }
        }

        /// A friendly name (`sha256` / `sha512`).
        pub const fn name(self) -> &'static str {
            match self {
                HashAlgorithm::Sha256 => "sha256",
                HashAlgorithm::Sha512 => "sha512",
            }
        }

        /// Digest the given bytes.
        pub fn digest(self, data: &[u8]) -> Vec<u8> {
            match self {
                HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
                HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
            }
        }
    }

    /// Map an accepted digest OID to an algorithm.
    pub fn hash_algorithm_from_oid(oid: &str) -> Option<HashAlgorithm> {
        match oid {
            OID_SHA256 => Some(HashAlgorithm::Sha256),
            OID_SHA512 => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }

    /// Digest bytes with an accepted OID (SHA-384 included for token-internal
    /// hashes even though it is not requestable from here).
    fn digest_for_oid(oid: &str, data: &[u8]) -> Option<Vec<u8>> {
        match oid {
            OID_SHA256 => Some(Sha256::digest(data).to_vec()),
            OID_SHA384 => {
                use sha2::Sha384;
                Some(Sha384::digest(data).to_vec())
            }
            OID_SHA512 => Some(Sha512::digest(data).to_vec()),
            _ => None,
        }
    }

    /// Optional HTTP auth header for the TSA request.
    ///
    /// Deliberately not `Serialize`: credentials must never end up in a
    /// persisted evidence record or a log line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TsaAuthHeader {
        /// Header name, e.g. `Authorization`.
        pub name: String,
        /// Header value, e.g. `Bearer <token>`.
        pub value: String,
    }

    /// TSA client configuration. Construct with [`TsaConfig::new`] or read
    /// the environment with [`TsaConfig::from_env`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TsaConfig {
        /// RFC 3161 endpoint URL (http or https).
        pub url: String,
        /// Optional auth header.
        pub auth_header: Option<TsaAuthHeader>,
        /// Accepted absolute difference between `genTime` and the
        /// verification clock, in seconds.
        pub tolerance_secs: i64,
        /// Total HTTP timeout in seconds.
        pub timeout_secs: u64,
        /// Hard cap on the response body size.
        pub max_response_bytes: usize,
    }

    impl TsaConfig {
        /// A configuration with defaults, validating the URL.
        pub fn new(url: impl Into<String>) -> Result<Self, TimeStampError> {
            let url = url.into();
            let trimmed = url.trim();
            if trimmed.is_empty() {
                return Err(TimeStampError::InvalidConfig(
                    "TSA URL is empty".to_string(),
                ));
            }
            let parsed = url::Url::parse(trimmed).map_err(|error| {
                TimeStampError::InvalidConfig(format!("TSA URL is not a URL: {error}"))
            })?;
            match parsed.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(TimeStampError::InvalidConfig(format!(
                        "TSA URL scheme {other:?} is not http/https"
                    )));
                }
            }
            match parsed.host_str() {
                Some(host) if !host.is_empty() => {}
                _ => {
                    return Err(TimeStampError::InvalidConfig(
                        "TSA URL has no host".to_string(),
                    ));
                }
            }
            Ok(Self {
                url: trimmed.to_string(),
                auth_header: None,
                tolerance_secs: DEFAULT_TOLERANCE_SECS,
                timeout_secs: DEFAULT_TIMEOUT_SECS,
                max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            })
        }

        /// Override the genTime tolerance.
        pub fn with_tolerance_secs(mut self, tolerance_secs: i64) -> Self {
            self.tolerance_secs = tolerance_secs;
            self
        }

        /// Override the HTTP timeout.
        pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
            self.timeout_secs = timeout_secs;
            self
        }

        /// Override the response size cap.
        pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
            self.max_response_bytes = max_response_bytes;
            self
        }

        /// Attach an auth header.
        pub fn with_auth_header(
            mut self,
            name: impl Into<String>,
            value: impl Into<String>,
        ) -> Self {
            self.auth_header = Some(TsaAuthHeader {
                name: name.into(),
                value: value.into(),
            });
            self
        }

        /// Read configuration from the environment.
        ///
        /// `Ok(None)` means no TSA is configured — the caller must not
        /// timestamp anything. See the module docs for the variable names.
        pub fn from_env() -> Result<Option<Self>, TimeStampError> {
            let url = std::env::var(ENV_TSA_URL)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let Some(url) = url else {
                return Ok(None);
            };
            let mut config = Self::new(url)?;
            if let Some(raw_header) = std::env::var(ENV_TSA_AUTH_HEADER)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            {
                let (name, value) = raw_header.split_once(':').ok_or_else(|| {
                    TimeStampError::InvalidConfig(format!(
                        "{ENV_TSA_AUTH_HEADER} must be in 'Name: Value' form"
                    ))
                })?;
                let name = name.trim();
                let value = value.trim();
                if name.is_empty() || value.is_empty() {
                    return Err(TimeStampError::InvalidConfig(format!(
                        "{ENV_TSA_AUTH_HEADER} has an empty name or value"
                    )));
                }
                config.auth_header = Some(TsaAuthHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            if let Some(seconds) = std::env::var(ENV_TSA_TOLERANCE_SECS)
                .ok()
                .and_then(|value| value.trim().parse::<i64>().ok())
            {
                if seconds <= 0 {
                    return Err(TimeStampError::InvalidConfig(format!(
                        "{ENV_TSA_TOLERANCE_SECS} must be a positive number of seconds"
                    )));
                }
                config.tolerance_secs = seconds;
            }
            if let Some(seconds) = std::env::var(ENV_TSA_TIMEOUT_SECS)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
            {
                if seconds == 0 {
                    return Err(TimeStampError::InvalidConfig(format!(
                        "{ENV_TSA_TIMEOUT_SECS} must be greater than zero"
                    )));
                }
                config.timeout_secs = seconds;
            }
            if let Some(bytes) = std::env::var(ENV_TSA_MAX_RESPONSE_BYTES)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
            {
                if bytes == 0 {
                    return Err(TimeStampError::InvalidConfig(format!(
                        "{ENV_TSA_MAX_RESPONSE_BYTES} must be greater than zero"
                    )));
                }
                config.max_response_bytes = bytes;
            }
            Ok(Some(config))
        }

        /// Human-readable description for logs (never the credential).
        pub fn describe(&self) -> String {
            format!(
                "TSA {} (timeout {}s, tolerance {}s, max response {} bytes, auth {})",
                self.url,
                self.timeout_secs,
                self.tolerance_secs,
                self.max_response_bytes,
                if self.auth_header.is_some() {
                    "configured"
                } else {
                    "none"
                }
            )
        }

        /// Build a verification request that inherits this configuration's
        /// tolerance and URL.
        pub fn verification_request<'a>(
            &'a self,
            document: &'a [u8],
            nonce: u64,
            algorithm: HashAlgorithm,
            now: DateTime<Utc>,
        ) -> TimestampVerificationRequest<'a> {
            TimestampVerificationRequest {
                document,
                nonce,
                algorithm,
                tolerance_secs: self.tolerance_secs,
                now,
                tsa_url: Some(self.url.as_str()),
            }
        }
    }

    /// Errors from the timestamp path.
    #[derive(Debug, Error)]
    pub enum TimeStampError {
        /// No TSA is configured. Fail closed: no timestamp is produced.
        #[error("no timestamp authority is configured ({ENV_TSA_URL} is unset); refusing to fabricate a timestamp")]
        NotConfigured,
        /// Configuration was present but invalid.
        #[error("invalid TSA configuration: {0}")]
        InvalidConfig(String),
        /// The HTTP request itself failed (DNS, connect, TLS, timeout, ...).
        #[error("TSA request failed: {0}")]
        Transport(String),
        /// The TSA answered with a non-success HTTP status.
        #[error("TSA returned HTTP status {status}")]
        HttpStatus {
            /// The HTTP status code.
            status: u16,
        },
        /// The response content type was not `application/timestamp-reply`.
        #[error("TSA response has content type {content_type:?}, expected application/timestamp-reply")]
        WrongContentType {
            /// Observed content type, if any.
            content_type: Option<String>,
        },
        /// The response body exceeded the configured cap.
        #[error("TSA response exceeds the configured maximum of {limit} bytes")]
        ResponseTooLarge {
            /// Configured cap.
            limit: usize,
        },
        /// The response did not parse as DER.
        #[error("malformed DER in TSA response: {0}")]
        MalformedDer(#[from] DerError),
        /// The DER parsed but the structure was not a valid `TimeStampResp`.
        #[error("malformed TSA response: {0}")]
        MalformedResponse(String),
        /// The TSA refused to issue a timestamp.
        #[error("TSA rejected the request: status {status} ({status_name}){}{}", format_status_strings(.status_string), format_fail_info(.fail_info))]
        Rejected {
            /// Numeric `PKIStatus`.
            status: u64,
            /// Name of the `PKIStatus`.
            status_name: &'static str,
            /// Any `statusString` values returned.
            status_string: Vec<String>,
            /// Decoded `failInfo` bit names.
            fail_info: Vec<String>,
        },
        /// The response parsed but one or more required checks failed.
        #[error("timestamp verification failed: {}", describe_failures(.failures))]
        VerificationFailed {
            /// The failing (or unperformed) required checks.
            failures: Vec<CheckVerdict>,
            /// The full evidence record, for auditing what was observed.
            evidence: Box<TimeStampEvidence>,
        },
    }

    fn format_status_strings(values: &[String]) -> String {
        if values.is_empty() {
            String::new()
        } else {
            format!(" — {}", values.join("; "))
        }
    }

    fn format_fail_info(values: &[String]) -> String {
        if values.is_empty() {
            String::new()
        } else {
            format!(" [{}]", values.join(", "))
        }
    }

    /// The parsed `TimeStampReq` (exposed so callers and tests can audit what
    /// was actually sent).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TimeStampRequest {
        /// Structure version (must be 1).
        pub version: u64,
        /// Requested message-imprint digest OID.
        pub imprint_algorithm_oid: String,
        /// Requested message imprint digest.
        pub imprint: Vec<u8>,
        /// Nonce, if present.
        pub nonce: Option<u64>,
        /// Whether a certificate was requested.
        pub cert_req: bool,
    }

    /// Inputs to [`verify_response`], kept explicit so an auditor can see
    /// exactly what the verification was run against.
    #[derive(Debug, Clone)]
    pub struct TimestampVerificationRequest<'a> {
        /// The exact document bytes that were (or would be) submitted.
        pub document: &'a [u8],
        /// The nonce that was sent with the request.
        pub nonce: u64,
        /// The digest algorithm that was requested.
        pub algorithm: HashAlgorithm,
        /// Accepted absolute difference between `genTime` and `now`.
        pub tolerance_secs: i64,
        /// The verification clock reading.
        pub now: DateTime<Utc>,
        /// The TSA URL this token came from, recorded in the evidence.
        pub tsa_url: Option<&'a str>,
    }

    /// A persisted, serde-serialisable audit record for one timestamp.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TimeStampEvidence {
        /// Evidence schema version ([`EVIDENCE_SCHEMA_VERSION`]).
        pub schema_version: u32,
        /// The nonce that was requested and matched.
        pub request_nonce: u64,
        /// The nonce in hex (`0x…`).
        pub request_nonce_hex: String,
        /// TSA URL, when known.
        pub tsa_url: Option<String>,
        /// Imprint algorithm name (`sha256` / `sha512`).
        pub imprint_algorithm: String,
        /// Imprint algorithm OID.
        pub imprint_algorithm_oid: String,
        /// Imprint digest from the token, hex.
        pub imprint_hex: String,
        /// Digest this module computed over the submitted document, hex.
        pub document_digest_hex: String,
        /// Raw `genTime` string from the token.
        pub gen_time_raw: String,
        /// `genTime` as RFC 3339 (UTC), when it parsed.
        pub gen_time_rfc3339: Option<String>,
        /// `genTime` as a Unix timestamp, when it parsed.
        pub gen_time_unix: Option<i64>,
        /// TSA policy OID.
        pub policy_oid: String,
        /// Token serial number, hex.
        pub serial_number_hex: String,
        /// `TSTInfo.version`.
        pub tst_info_version: u64,
        /// `TSTInfo.ordering`.
        pub ordering: bool,
        /// `TSTInfo.accuracy` seconds, when present.
        pub accuracy_seconds: Option<u64>,
        /// The signer certificate, when one was returned and parsed.
        pub signer_certificate: Option<CertificateSummary>,
        /// Every named check with its independent outcome.
        pub checks: Vec<CheckVerdict>,
        /// Plain-language list of properties this evidence proves.
        pub proven_properties: Vec<String>,
        /// Plain-language list of properties this evidence does NOT prove.
        pub not_proven_properties: Vec<String>,
    }

    impl TimeStampEvidence {
        /// True when every required check passed. Optional failures are
        /// reported in `checks` but do not block.
        pub fn all_passed(&self) -> bool {
            all_passed(&self.checks)
        }

        /// True when every check passed and none was skipped.
        pub fn strictly_passed(&self) -> bool {
            super::strictly_passed(&self.checks)
        }

        /// True when any check failed.
        pub fn has_failures(&self) -> bool {
            super::has_failures(&self.checks)
        }

        /// The checks that did not pass.
        pub fn failing_checks(&self) -> Vec<&CheckVerdict> {
            self.checks
                .iter()
                .filter(|check| !check.outcome.is_pass())
                .collect()
        }
    }

    /// Properties proven by a passing [`TimeStampEvidence`] record. Written
    /// for a non-cryptographer auditor.
    pub const PROVEN_PROPERTIES: &[&str] = &[
        "The timestamp authority returned the status \"granted\" for this request.",
        "The digest inside the token equals the digest computed from the exact document bytes submitted with the request.",
        "The nonce inside the token equals the nonce generated and sent with this request, so the token answers this exchange and is not a replay of a different one.",
        "The token's genTime is within the configured tolerance of the clock reading supplied at verification time.",
        "The signer certificate carried in the token parses as an X.509 certificate, and its subject, serial, validity window and SHA-256 fingerprint are recorded.",
        "The token's digest algorithms are accepted SHA-2 algorithms.",
        "The value of the CMS signature over the signed attributes was checked against the public key in the token's certificate (when the signature algorithm is supported), and the signed messageDigest attribute equals the hash of the timestamped content.",
    ];

    /// Properties NOT proven by a [`TimeStampEvidence`] record. Kept as a
    /// constant so an auditor can compare a record against this list.
    pub const NOT_PROVEN_PROPERTIES: &[&str] = &[
        "That the timestamp authority is authoritative, qualified or accredited. Trust is modelled as \"the operator configured this TSA URL\"; no EU trusted-list, accreditation or qualified-certificate check is performed.",
        "That the signer certificate chains to any trusted root: no certificate-path validation is performed and no trust store is configured.",
        "That the signer certificate was valid at genTime: notBefore/notAfter are recorded but not enforced.",
        "That the certificate has not been revoked: no CRL or OCSP check is performed.",
        "That the timestamp is a qualified electronic timestamp within the meaning of eIDAS Article 42; that requires a qualified trust service provider and validation against its trust anchor, neither of which this repository integrates.",
    ];

    /// Generate a 64-bit nonce.
    ///
    /// The high bit is always set so the DER INTEGER encoding is a fixed
    /// 9-byte value (with a leading `0x00`); this keeps the request byte
    /// layout deterministic for tests and audits. A zero nonce has negligible
    /// probability.
    pub fn random_nonce() -> u64 {
        let uuid = uuid::Uuid::new_v4();
        let bytes = uuid.as_bytes();
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[..8]);
        u64::from_be_bytes(raw) | (1u64 << 63)
    }

    /// Build a DER-encoded `TimeStampReq`.
    ///
    /// Shape: `SEQUENCE { INTEGER 1, SEQUENCE { AlgorithmIdentifier, OCTET
    /// STRING }, INTEGER nonce, BOOLEAN certReq }`.
    pub fn build_request(
        document: &[u8],
        algorithm: HashAlgorithm,
        nonce: u64,
        cert_req: bool,
    ) -> Result<Vec<u8>, TimeStampError> {
        let imprint_algorithm = der::algorithm_identifier(algorithm.oid())?;
        let message_imprint = der::sequence(&[
            imprint_algorithm,
            der::octet_string(&algorithm.digest(document)),
        ]);
        let mut parts = vec![
            der::unsigned_integer(1),
            message_imprint,
            der::unsigned_integer(nonce),
        ];
        if cert_req {
            parts.push(der::boolean(true));
        }
        Ok(der::sequence(&parts))
    }

    /// Parse a DER-encoded `TimeStampReq` (used for auditing and by tests).
    pub fn parse_request(input: &[u8]) -> Result<TimeStampRequest, TimeStampError> {
        let mut budget = Budget::default();
        let mut reader = Reader::new(input);
        let top = reader.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        reader.finish()?;
        let mut inner = top.reader();
        let version = der::decode_u64(&inner.read_tagged(&mut budget, der::TAG_INTEGER)?)?;
        let imprint = inner.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        let mut imprint_reader = imprint.reader();
        let algorithm_tlv = imprint_reader.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        let mut algorithm_reader = algorithm_tlv.reader();
        let algorithm_oid =
            der::decode_oid(&algorithm_reader.read_tagged(&mut budget, der::TAG_OID)?)?;
        let digest = der::decode_octet_string(
            &imprint_reader.read_tagged(&mut budget, der::TAG_OCTET_STRING)?,
        )?
        .to_vec();
        imprint_reader.finish()?;
        let nonce = inner
            .read_if_tagged(&mut budget, der::TAG_INTEGER)?
            .map(|tlv| der::decode_u64(&tlv))
            .transpose()?;
        let cert_req = inner
            .read_if_tagged(&mut budget, der::TAG_BOOLEAN)?
            .map(|tlv| der::decode_bool(&tlv))
            .transpose()?
            .unwrap_or(false);
        Ok(TimeStampRequest {
            version,
            imprint_algorithm_oid: algorithm_oid,
            imprint: digest,
            nonce,
            cert_req,
        })
    }

    // -- Response parsing -----------------------------------------------------

    #[derive(Debug, Clone)]
    struct StatusInfo {
        status: u64,
        status_name: &'static str,
        status_string: Vec<String>,
        fail_info: Vec<String>,
    }

    #[derive(Debug, Clone)]
    struct ParsedTstInfo {
        version: u64,
        policy: String,
        imprint_algorithm: String,
        imprint: Vec<u8>,
        serial: Vec<u8>,
        gen_time_raw: String,
        gen_time: Option<DateTime<Utc>>,
        nonce: Option<u64>,
        ordering: bool,
        accuracy_seconds: Option<u64>,
    }

    #[derive(Debug, Clone)]
    struct SignedAttribute {
        oid: String,
        value_tag: u8,
        value_content: Vec<u8>,
        value_encoded: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    enum SignerId {
        IssuerAndSerial { issuer: Vec<u8>, serial: Vec<u8> },
        SubjectKeyIdentifier(Vec<u8>),
    }

    #[derive(Debug, Clone)]
    struct ParsedSignerInfo {
        digest_algorithm: String,
        signed_attributes: Option<Vec<SignedAttribute>>,
        signed_attributes_set_der: Option<Vec<u8>>,
        signature_algorithm_raw: Vec<u8>,
        signature: Vec<u8>,
        signer_id: Option<SignerId>,
    }

    impl ParsedSignerInfo {
        fn attribute(&self, oid: &str) -> Option<&SignedAttribute> {
            self.signed_attributes
                .as_ref()
                .and_then(|attributes| attributes.iter().find(|attribute| attribute.oid == oid))
        }
    }

    #[derive(Debug, Clone)]
    struct ParsedToken {
        digest_algorithms: Vec<String>,
        econtent: Vec<u8>,
        certificates: Vec<Vec<u8>>,
        signer_infos: Vec<ParsedSignerInfo>,
        tst: ParsedTstInfo,
    }

    fn status_name(status: u64) -> &'static str {
        match status {
            0 => "granted",
            1 => "grantedWithMods",
            2 => "rejection",
            3 => "waiting",
            4 => "revocationWarning",
            5 => "revocationNotification",
            _ => "unknown",
        }
    }

    const FAIL_INFO_BITS: &[(usize, &str)] = &[
        (0, "badAlg"),
        (2, "badRequest"),
        (5, "badDataFormat"),
        (14, "timeNotAvailable"),
        (15, "unacceptedPolicy"),
        (16, "unacceptedExtension"),
        (17, "addInfoNotAvailable"),
        (25, "systemFailure"),
    ];

    fn decode_fail_info(tlv: &Tlv<'_>) -> Result<Vec<String>, DerError> {
        let bits = der::decode_bit_string(tlv)?;
        let total_bits = bits.len() * 8;
        let mut names = Vec::new();
        for (bit, name) in FAIL_INFO_BITS {
            if *bit >= total_bits {
                continue;
            }
            let byte = bits[bit / 8];
            let mask = 0x80u8 >> (bit % 8);
            if byte & mask != 0 {
                names.push((*name).to_string());
            }
        }
        Ok(names)
    }

    fn parse_status_info(content: &[u8], budget: &mut Budget) -> Result<StatusInfo, DerError> {
        budget.descend(|budget| {
            let mut reader = Reader::new(content);
            let status = der::decode_u64(&reader.read_tagged(budget, der::TAG_INTEGER)?)?;
            let mut status_string = Vec::new();
            if reader.peek_tag() == Some(der::TAG_SEQUENCE) {
                let free_text = reader.read(budget)?;
                let mut text_reader = free_text.reader();
                while !text_reader.is_empty() {
                    let value = text_reader.read(budget)?;
                    if value.tag == der::TAG_UTF8_STRING {
                        status_string.push(
                            std::str::from_utf8(value.content)
                                .map_err(|_| DerError::InvalidUtf8)?
                                .to_string(),
                        );
                    }
                }
            }
            let mut fail_info = Vec::new();
            if reader.peek_tag() == Some(der::TAG_BIT_STRING) {
                let bits = reader.read(budget)?;
                fail_info = decode_fail_info(&bits)?;
            }
            reader.finish()?;
            Ok(StatusInfo {
                status,
                status_name: status_name(status),
                status_string,
                fail_info,
            })
        })
    }

    /// Split a `TimeStampResp` into its status and (optionally) the raw
    /// `timeStampToken` bytes.
    fn parse_response(input: &[u8]) -> Result<(StatusInfo, Option<&[u8]>), TimeStampError> {
        let mut budget = Budget::default();
        let mut reader = Reader::new(input);
        let top = reader.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        reader.finish()?;
        let mut inner = top.reader();
        let status_tlv = inner.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        let status = parse_status_info(status_tlv.content, &mut budget)?;
        let token = inner.read_if_tagged(&mut budget, der::TAG_SEQUENCE)?;
        Ok((status, token.map(|tlv| tlv.encoded)))
    }

    fn parse_tst_info(content: &[u8], budget: &mut Budget) -> Result<ParsedTstInfo, DerError> {
        let mut outer = Reader::new(content);
        let tst_info = outer.read_tagged(budget, der::TAG_SEQUENCE)?;
        outer.finish()?;
        budget.descend(|budget| {
            let mut reader = tst_info.reader();
            let version = der::decode_u64(&reader.read_tagged(budget, der::TAG_INTEGER)?)?;
            let policy = der::decode_oid(&reader.read_tagged(budget, der::TAG_OID)?)?;
            let imprint_tlv = reader.read_tagged(budget, der::TAG_SEQUENCE)?;
            let mut imprint_reader = imprint_tlv.reader();
            let algorithm_tlv = imprint_reader.read_tagged(budget, der::TAG_SEQUENCE)?;
            let mut algorithm_reader = algorithm_tlv.reader();
            let imprint_algorithm =
                der::decode_oid(&algorithm_reader.read_tagged(budget, der::TAG_OID)?)?;
            let imprint = der::decode_octet_string(
                &imprint_reader.read_tagged(budget, der::TAG_OCTET_STRING)?,
            )?
            .to_vec();
            imprint_reader.finish()?;
            let serial = reader.read_tagged(budget, der::TAG_INTEGER)?.content.to_vec();
            let gen_time_tlv = reader.read_tagged(budget, der::TAG_GENERALIZED_TIME)?;
            let gen_time_raw = std::str::from_utf8(gen_time_tlv.content)
                .map_err(|_| DerError::InvalidUtf8)?
                .to_string();
            let gen_time = der::decode_generalized_time(&gen_time_tlv).ok();

            // Optional fields, in RFC 3161 order.
            let mut accuracy_seconds = None;
            if reader.peek_tag() == Some(der::TAG_SEQUENCE) {
                let accuracy = reader.read(budget)?;
                accuracy_seconds = parse_accuracy_seconds(&accuracy, budget).ok().flatten();
            }
            let mut ordering = false;
            if reader.peek_tag() == Some(der::TAG_BOOLEAN) {
                let boolean = reader.read(budget)?;
                ordering = der::decode_bool(&boolean)?;
            }
            let mut nonce = None;
            if reader.peek_tag() == Some(der::TAG_INTEGER) {
                let nonce_tlv = reader.read(budget)?;
                nonce = Some(der::decode_u64(&nonce_tlv)?);
            }
            // Remaining optional fields ([0] tsa, [1] extensions) carry no
            // data this module verifies; they are intentionally not required
            // so tokens containing them still parse.
            Ok(ParsedTstInfo {
                version,
                policy,
                imprint_algorithm,
                imprint,
                serial,
                gen_time_raw,
                gen_time,
                nonce,
                ordering,
                accuracy_seconds,
            })
        })
    }

    fn parse_accuracy_seconds(tlv: &Tlv<'_>, budget: &mut Budget) -> Result<Option<u64>, DerError> {
        if tlv.tag != der::TAG_SEQUENCE {
            return Ok(None);
        }
        budget.descend(|budget| {
            let mut reader = tlv.reader();
            if reader.peek_tag() == Some(der::TAG_INTEGER) {
                let seconds = reader.read(budget)?;
                return Ok(Some(der::decode_u64(&seconds)?));
            }
            Ok(None)
        })
    }

    fn parse_signed_attributes(
        content: &[u8],
        budget: &mut Budget,
    ) -> Result<Vec<SignedAttribute>, DerError> {
        budget.descend(|budget| {
            let mut reader = Reader::new(content);
            let mut attributes = Vec::new();
            while !reader.is_empty() {
                let attribute = reader.read_tagged(budget, der::TAG_SEQUENCE)?;
                let mut attribute_reader = attribute.reader();
                let oid = der::decode_oid(&attribute_reader.read_tagged(budget, der::TAG_OID)?)?;
                let values = attribute_reader.read_tagged(budget, der::TAG_SET)?;
                let mut values_reader = values.reader();
                let first_value = values_reader.read(budget)?;
                attributes.push(SignedAttribute {
                    oid,
                    value_tag: first_value.tag,
                    value_content: first_value.content.to_vec(),
                    value_encoded: first_value.encoded.to_vec(),
                });
            }
            Ok(attributes)
        })
    }

    fn parse_signer_info(
        content: &[u8],
        budget: &mut Budget,
    ) -> Result<ParsedSignerInfo, DerError> {
        budget.descend(|budget| {
            let mut reader = Reader::new(content);
            let _version = der::decode_u64(&reader.read_tagged(budget, der::TAG_INTEGER)?)?;
            let signer_id_tlv = reader.read(budget)?;
            let signer_id = match signer_id_tlv.tag {
                der::TAG_SEQUENCE => {
                    let mut sid_reader = signer_id_tlv.reader();
                    let issuer = sid_reader.read(budget)?.encoded.to_vec();
                    let serial = sid_reader
                        .read_tagged(budget, der::TAG_INTEGER)?
                        .content
                        .to_vec();
                    Some(SignerId::IssuerAndSerial { issuer, serial })
                }
                der::TAG_CTX_0 => {
                    Some(SignerId::SubjectKeyIdentifier(signer_id_tlv.content.to_vec()))
                }
                _ => None,
            };
            let digest_algorithm_tlv = reader.read_tagged(budget, der::TAG_SEQUENCE)?;
            let mut digest_reader = digest_algorithm_tlv.reader();
            let digest_oid = der::decode_oid(&digest_reader.read_tagged(budget, der::TAG_OID)?)?;
            let signed_attributes_tlv = reader.read_if_tagged(budget, der::TAG_CTX_0)?;
            let (signed_attributes, signed_attributes_set_der) = match &signed_attributes_tlv {
                Some(tlv) => (
                    Some(parse_signed_attributes(tlv.content, budget)?),
                    Some(der::tlv(der::TAG_SET, tlv.content)),
                ),
                None => (None, None),
            };
            let signature_algorithm_tlv = reader.read_tagged(budget, der::TAG_SEQUENCE)?;
            let signature = der::decode_octet_string(
                &reader.read_tagged(budget, der::TAG_OCTET_STRING)?,
            )?
            .to_vec();
            Ok(ParsedSignerInfo {
                digest_algorithm: digest_oid,
                signed_attributes,
                signed_attributes_set_der,
                signature_algorithm_raw: signature_algorithm_tlv.encoded.to_vec(),
                signature,
                signer_id,
            })
        })
    }

    fn parse_token(input: &[u8]) -> Result<ParsedToken, TimeStampError> {
        let mut budget = Budget::default();
        let mut reader = Reader::new(input);
        let content_info = reader.read_tagged(&mut budget, der::TAG_SEQUENCE)?;
        reader.finish()?;
        let mut content_info_reader = content_info.reader();
        let content_type =
            der::decode_oid(&content_info_reader.read_tagged(&mut budget, der::TAG_OID)?)?;
        if content_type != OID_SIGNED_DATA {
            return Err(TimeStampError::MalformedResponse(format!(
                "timeStampToken contentType is {content_type}, expected signedData ({OID_SIGNED_DATA})"
            )));
        }
        let explicit = content_info_reader.read_tagged(&mut budget, der::TAG_CTX_0)?;
        let signed_data = {
            let mut content_reader = explicit.reader();
            content_reader.read_tagged(&mut budget, der::TAG_SEQUENCE)?
        };

        let (digest_algorithms, econtent, certificates, signer_infos) =
            budget.descend(|budget| {
                let mut reader = signed_data.reader();
                let _version = der::decode_u64(&reader.read_tagged(budget, der::TAG_INTEGER)?)?;
                let digest_algorithms_tlv = reader.read_tagged(budget, der::TAG_SET)?;
                let mut digest_algorithms = Vec::new();
                {
                    let mut set_reader = digest_algorithms_tlv.reader();
                    while !set_reader.is_empty() {
                        let algorithm = set_reader.read_tagged(budget, der::TAG_SEQUENCE)?;
                        let mut algorithm_reader = algorithm.reader();
                        let oid =
                            der::decode_oid(&algorithm_reader.read_tagged(budget, der::TAG_OID)?)?;
                        digest_algorithms.push(oid);
                    }
                }
                let encap = reader.read_tagged(budget, der::TAG_SEQUENCE)?;
                let mut encap_reader = encap.reader();
                let econtent_type =
                    der::decode_oid(&encap_reader.read_tagged(budget, der::TAG_OID)?)?;
                if econtent_type != OID_TST_INFO {
                    return Err(DerError::UnexpectedTag {
                        expected: der::TAG_OID,
                        actual: der::TAG_OID,
                    });
                }
                let explicit = encap_reader.read_tagged(budget, der::TAG_CTX_0)?;
                let econtent = {
                    let mut inner = explicit.reader();
                    der::decode_octet_string(&inner.read_tagged(budget, der::TAG_OCTET_STRING)?)?
                        .to_vec()
                };
                let mut certificates = Vec::new();
                if reader.peek_tag() == Some(der::TAG_CTX_0) {
                    let certificate_set = reader.read_tagged(budget, der::TAG_CTX_0)?;
                    let mut set_reader = certificate_set.reader();
                    while !set_reader.is_empty() {
                        let certificate = set_reader.read_tagged(budget, der::TAG_SEQUENCE)?;
                        certificates.push(certificate.encoded.to_vec());
                    }
                }
                if reader.peek_tag() == Some(der::TAG_CTX_1) {
                    // CRLs are not used for verification; skip without parsing.
                    let _ = reader.read_tagged(budget, der::TAG_CTX_1)?;
                }
                let signer_infos_tlv = reader.read_tagged(budget, der::TAG_SET)?;
                let mut signer_infos = Vec::new();
                {
                    let mut set_reader = signer_infos_tlv.reader();
                    while !set_reader.is_empty() {
                        let signer_info = set_reader.read_tagged(budget, der::TAG_SEQUENCE)?;
                        signer_infos.push(parse_signer_info(signer_info.content, budget)?);
                    }
                }
                Ok((digest_algorithms, econtent, certificates, signer_infos))
            })?;

        let tst = parse_tst_info(&econtent, &mut budget)?;
        Ok(ParsedToken {
            digest_algorithms,
            econtent,
            certificates,
            signer_infos,
            tst,
        })
    }

    // -- Verification ---------------------------------------------------------

    /// Verify a DER `TimeStampResp` against the request parameters.
    ///
    /// Returns `Err` only when no evidence record can exist: malformed DER, a
    /// missing token, a rejected status, or an unrecognisable response. When
    /// the response parses, the returned evidence carries every named check
    /// with an independent outcome; the caller gates on
    /// [`TimeStampEvidence::all_passed`].
    pub fn verify_response(
        response_der: &[u8],
        request: &TimestampVerificationRequest<'_>,
    ) -> Result<TimeStampEvidence, TimeStampError> {
        let (status, token_der) = parse_response(response_der)?;
        if status.status != 0 {
            return Err(TimeStampError::Rejected {
                status: status.status,
                status_name: status.status_name,
                status_string: status.status_string,
                fail_info: status.fail_info,
            });
        }
        let token_der = token_der.ok_or_else(|| {
            TimeStampError::MalformedResponse(
                "granted TimeStampResp carries no timeStampToken".to_string(),
            )
        })?;
        let token = parse_token(token_der)?;

        let mut checks: Vec<CheckVerdict> = Vec::new();
        checks.push(CheckVerdict::pass("status_granted", true));

        let tst = &token.tst;

        // 1. Imprint algorithm matches the requested one.
        if tst.imprint_algorithm == request.algorithm.oid() {
            checks.push(CheckVerdict::pass("imprint_algorithm_expected", true));
        } else {
            checks.push(CheckVerdict::fail(
                "imprint_algorithm_expected",
                true,
                format!(
                    "token imprint algorithm is {} but {} was requested",
                    tst.imprint_algorithm,
                    request.algorithm.oid()
                ),
            ));
        }

        // 2. Returned imprint equals the digest of the submitted document.
        let document_digest = digest_for_oid(&tst.imprint_algorithm, request.document)
            .unwrap_or_else(|| request.algorithm.digest(request.document));
        if document_digest == tst.imprint {
            checks.push(CheckVerdict::pass("imprint_matches_document", true));
        } else {
            checks.push(CheckVerdict::fail(
                "imprint_matches_document",
                true,
                format!(
                    "token imprint {} does not equal the {} digest {} of the submitted document",
                    hex::encode(&tst.imprint),
                    tst.imprint_algorithm,
                    hex::encode(&document_digest)
                ),
            ));
        }

        // 3. Nonce equality.
        match tst.nonce {
            Some(nonce) if nonce == request.nonce => {
                checks.push(CheckVerdict::pass("nonce_matches_request", true));
            }
            Some(nonce) => {
                checks.push(CheckVerdict::fail(
                    "nonce_matches_request",
                    true,
                    format!(
                        "token nonce 0x{nonce:016X} does not equal the requested nonce 0x{:016X}",
                        request.nonce
                    ),
                ));
            }
            None => {
                checks.push(CheckVerdict::fail(
                    "nonce_matches_request",
                    true,
                    "token carries no nonce".to_string(),
                ));
            }
        }

        // 4. genTime parsing and tolerance.
        match tst.gen_time {
            Some(gen_time) => {
                checks.push(CheckVerdict::pass("gen_time_parses", true));
                let delta = (request.now - gen_time).num_seconds();
                if delta.abs() <= request.tolerance_secs {
                    checks.push(CheckVerdict::pass("gen_time_within_tolerance", true));
                } else {
                    checks.push(CheckVerdict::fail(
                        "gen_time_within_tolerance",
                        true,
                        format!(
                            "genTime {} is {delta} seconds from the verification clock {} (tolerance {}s)",
                            gen_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            request.now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            request.tolerance_secs
                        ),
                    ));
                }
            }
            None => {
                checks.push(CheckVerdict::fail(
                    "gen_time_parses",
                    true,
                    format!("genTime {:?} did not parse", tst.gen_time_raw),
                ));
                checks.push(CheckVerdict::not_performed(
                    "gen_time_within_tolerance",
                    true,
                    "genTime did not parse".to_string(),
                ));
            }
        }

        // 5. Signer certificate (first in certificates) parses.
        let certificate_der = token.certificates.first();
        let certificate = certificate_der.and_then(|der| {
            x509_parser::prelude::X509Certificate::from_der(der)
                .ok()
                .map(|(_, certificate)| certificate)
        });
        match certificate {
            Some(_) => checks.push(CheckVerdict::pass("signer_certificate_parses", true)),
            None => checks.push(CheckVerdict::fail(
                "signer_certificate_parses",
                true,
                if certificate_der.is_some() {
                    "the first certificate in SignedData.certificates is not a parseable X.509 certificate"
                        .to_string()
                } else {
                    "SignedData carries no certificates".to_string()
                },
            )),
        }

        // 6. Digest algorithms accepted.
        let signer = token.signer_infos.first();
        let digests_accepted = token
            .digest_algorithms
            .iter()
            .all(|oid| ACCEPTED_DIGESTS.contains(&oid.as_str()))
            && signer
                .map(|signer| ACCEPTED_DIGESTS.contains(&signer.digest_algorithm.as_str()))
                .unwrap_or(false);
        if digests_accepted {
            checks.push(CheckVerdict::pass("digest_algorithm_accepted", true));
        } else {
            checks.push(CheckVerdict::fail(
                "digest_algorithm_accepted",
                true,
                format!(
                    "SignedData digestAlgorithms {:?}, signer digestAlgorithm {:?} (accepted: {:?})",
                    token.digest_algorithms,
                    signer.map(|signer| signer.digest_algorithm.clone()),
                    ACCEPTED_DIGESTS
                ),
            ));
        }

        let Some(signer) = signer else {
            checks.push(CheckVerdict::fail(
                "signed_attrs_content_type",
                true,
                "SignedData has no SignerInfo".to_string(),
            ));
            checks.push(CheckVerdict::not_performed(
                "signed_attrs_message_digest_matches_econtent",
                true,
                "no SignerInfo".to_string(),
            ));
            checks.push(CheckVerdict::not_performed(
                "ess_signing_certificate_hash_matches_certificate",
                true,
                "no SignerInfo".to_string(),
            ));
            checks.push(CheckVerdict::not_performed(
                "signer_id_matches_certificate",
                false,
                "no SignerInfo".to_string(),
            ));
            checks.push(CheckVerdict::not_performed(
                "token_signature_valid",
                true,
                "no SignerInfo".to_string(),
            ));
            return Ok(build_evidence(request, tst, certificate_der, certificate, checks));
        };

        // 7. Signed attributes: contentType must be id-ct-TSTInfo.
        match signer.attribute(OID_CONTENT_TYPE_ATTR) {
            Some(attribute) if attribute.value_tag == der::TAG_OID => {
                match der::decode_oid_bytes(&attribute.value_content) {
                    Ok(oid) if oid == OID_TST_INFO => {
                        checks.push(CheckVerdict::pass("signed_attrs_content_type", true));
                    }
                    Ok(oid) => checks.push(CheckVerdict::fail(
                        "signed_attrs_content_type",
                        true,
                        format!("signed contentType is {oid}, expected {OID_TST_INFO}"),
                    )),
                    Err(error) => checks.push(CheckVerdict::fail(
                        "signed_attrs_content_type",
                        true,
                        format!("signed contentType does not decode: {error}"),
                    )),
                }
            }
            Some(_) => checks.push(CheckVerdict::fail(
                "signed_attrs_content_type",
                true,
                "signed contentType attribute has an unexpected value type".to_string(),
            )),
            None => checks.push(CheckVerdict::fail(
                "signed_attrs_content_type",
                true,
                "signedAttrs carry no contentType attribute".to_string(),
            )),
        }

        // 8. Signed messageDigest equals the hash of the eContent.
        match signer.attribute(OID_MESSAGE_DIGEST_ATTR) {
            Some(attribute) if attribute.value_tag == der::TAG_OCTET_STRING => {
                match digest_for_oid(&signer.digest_algorithm, &token.econtent) {
                    Some(expected) if expected == attribute.value_content => {
                        checks.push(CheckVerdict::pass(
                            "signed_attrs_message_digest_matches_econtent",
                            true,
                        ));
                    }
                    Some(expected) => checks.push(CheckVerdict::fail(
                        "signed_attrs_message_digest_matches_econtent",
                        true,
                        format!(
                            "signed messageDigest {} does not equal the {} digest {} of the TSTInfo eContent",
                            hex::encode(&attribute.value_content),
                            signer.digest_algorithm,
                            hex::encode(&expected)
                        ),
                    )),
                    None => checks.push(CheckVerdict::not_performed(
                        "signed_attrs_message_digest_matches_econtent",
                        true,
                        format!(
                            "signer digest algorithm {} is not supported for hashing",
                            signer.digest_algorithm
                        ),
                    )),
                }
            }
            Some(_) => checks.push(CheckVerdict::fail(
                "signed_attrs_message_digest_matches_econtent",
                true,
                "signed messageDigest attribute has an unexpected value type".to_string(),
            )),
            None => checks.push(CheckVerdict::not_performed(
                "signed_attrs_message_digest_matches_econtent",
                true,
                "signedAttrs carry no messageDigest attribute (RFC 5652 requires it when signed attributes are present; RFC 3161 tokens must have signed attributes)".to_string(),
            )),
        }

        // 9. ESS signing-certificate hash binds the certificate.
        match signer.attribute(OID_SIGNING_CERT_V2_ATTR) {
            Some(_) if certificate.is_none() => checks.push(CheckVerdict::not_performed(
                "ess_signing_certificate_hash_matches_certificate",
                true,
                "the signer certificate did not parse, so the ESS certificate hash cannot be bound"
                    .to_string(),
            )),
            Some(attribute) => match certificate_der {
                Some(der) => match parse_ess_cert_hash(attribute) {
                    Ok((hash_algorithm_oid, expected_hash)) => {
                        match digest_for_oid(&hash_algorithm_oid, der) {
                            Some(actual) if actual == expected_hash => checks.push(CheckVerdict::pass(
                                "ess_signing_certificate_hash_matches_certificate",
                                true,
                            )),
                            Some(actual) => checks.push(CheckVerdict::fail(
                                "ess_signing_certificate_hash_matches_certificate",
                                true,
                                format!(
                                    "ESS certificate hash {} does not equal the {} hash {} of the token certificate",
                                    hex::encode(&expected_hash),
                                    hash_algorithm_oid,
                                    hex::encode(&actual)
                                ),
                            )),
                            None => checks.push(CheckVerdict::not_performed(
                                "ess_signing_certificate_hash_matches_certificate",
                                true,
                                format!(
                                    "ESS hash algorithm {hash_algorithm_oid} is not supported for hashing"
                                ),
                            )),
                        }
                    }
                    Err(reason) => checks.push(CheckVerdict::fail(
                        "ess_signing_certificate_hash_matches_certificate",
                        true,
                        reason,
                    )),
                },
                None => checks.push(CheckVerdict::not_performed(
                    "ess_signing_certificate_hash_matches_certificate",
                    true,
                    "no certificate to compare against".to_string(),
                )),
            },
            None => checks.push(CheckVerdict::not_performed(
                "ess_signing_certificate_hash_matches_certificate",
                true,
                "token has no signingCertificateV2 signed attribute (RFC 3161 requires it)"
                    .to_string(),
            )),
        }

        // 10. Signer identifier matches the certificate (optional; not
        // performed for subjectKeyIdentifier-style signer ids).
        match (&signer.signer_id, certificate.as_ref()) {
            (Some(SignerId::IssuerAndSerial { issuer, serial }), Some(cert)) => {
                let serial_matches = cert.raw_serial() == serial.as_slice();
                let issuer_matches = issuer_name_matches(issuer, cert);
                match (serial_matches, issuer_matches) {
                    (true, Some(true)) => {
                        checks.push(CheckVerdict::pass("signer_id_matches_certificate", false))
                    }
                    (true, None) => checks.push(CheckVerdict::not_performed(
                        "signer_id_matches_certificate",
                        false,
                        "SignerInfo issuer name could not be re-parsed for comparison".to_string(),
                    )),
                    (serial_matches, issuer_matches) => checks.push(CheckVerdict::fail(
                        "signer_id_matches_certificate",
                        false,
                        format!(
                            "SignerInfo issuerAndSerialNumber does not match the certificate (serial match: {serial_matches}, issuer match: {issuer_matches:?})"
                        ),
                    )),
                }
            }
            (Some(SignerId::SubjectKeyIdentifier(key_id)), _) => {
                checks.push(CheckVerdict::not_performed(
                    "signer_id_matches_certificate",
                    false,
                    format!(
                        "SignerInfo identifies the signer by subjectKeyIdentifier {}; key-id matching is not implemented",
                        hex::encode(key_id)
                    ),
                ))
            }
            (Some(SignerId::IssuerAndSerial { .. }), None) => {
                checks.push(CheckVerdict::not_performed(
                    "signer_id_matches_certificate",
                    false,
                    "no parseable certificate to compare the SignerInfo identifier against"
                        .to_string(),
                ))
            }
            (None, _) => checks.push(CheckVerdict::not_performed(
                "signer_id_matches_certificate",
                false,
                "unrecognised SignerInfo signer identifier".to_string(),
            )),
        }

        // 11. Token signature. The only check that can turn the certificate
        // into an authentication statement, and reported with its exact
        // scope: signature over the signed attributes, public key from the
        // token's own certificate, no path validation.
        match certificate.as_ref() {
            Some(cert) => match verify_token_signature(signer, cert, &token.econtent) {
                Ok(()) => checks.push(CheckVerdict::pass("token_signature_valid", true)),
                Err(SignatureFailure::Unsupported(reason)) => {
                    checks.push(CheckVerdict::not_performed(
                        "token_signature_valid",
                        true,
                        reason,
                    ))
                }
                Err(SignatureFailure::Invalid(reason)) => {
                    checks.push(CheckVerdict::fail("token_signature_valid", true, reason))
                }
            },
            None => checks.push(CheckVerdict::not_performed(
                "token_signature_valid",
                true,
                "the token's signer certificate did not parse, so no public key is available"
                    .to_string(),
            )),
        }

        Ok(build_evidence(request, tst, certificate_der, certificate, checks))
    }

    fn issuer_name_matches(
        issuer_der: &[u8],
        certificate: &x509_parser::prelude::X509Certificate<'_>,
    ) -> Option<bool> {
        let parsed = x509_parser::prelude::X509Name::from_der(issuer_der).ok()?;
        if !parsed.0.is_empty() {
            return None;
        }
        Some(parsed.1.to_string() == certificate.issuer().to_string())
    }

    fn parse_ess_cert_hash(attribute: &SignedAttribute) -> Result<(String, Vec<u8>), String> {
        // The attribute value is `SigningCertificateV2 ::= SEQUENCE { certs
        // SEQUENCE OF ESSCertIDv2, ... }`; parse it from the full DER so the
        // ESSCertIDv2 level is reached.
        let mut budget = Budget::default();
        let mut reader = Reader::new(&attribute.value_encoded);
        let top = reader
            .read_tagged(&mut budget, der::TAG_SEQUENCE)
            .map_err(|error| format!("ESS signingCertificateV2 value is malformed: {error}"))?;
        let mut top_reader = top.reader();
        let certs = top_reader
            .read_tagged(&mut budget, der::TAG_SEQUENCE)
            .map_err(|error| format!("ESS signingCertificateV2 has no certs sequence: {error}"))?;
        let mut certs_reader = certs.reader();
        let ess_cert_id = certs_reader
            .read_tagged(&mut budget, der::TAG_SEQUENCE)
            .map_err(|error| format!("ESS signingCertificateV2 has no ESSCertIDv2: {error}"))?;
        let mut ess_reader = ess_cert_id.reader();
        let first = ess_reader
            .read(&mut budget)
            .map_err(|error| format!("ESSCertIDv2 is malformed: {error}"))?;
        let (hash_algorithm_oid, hash_tlv) = if first.tag == der::TAG_SEQUENCE {
            let mut algorithm_reader = first.reader();
            let oid = der::decode_oid(
                &algorithm_reader
                    .read_tagged(&mut budget, der::TAG_OID)
                    .map_err(|error| format!("ESSCertIDv2 hashAlgorithm is malformed: {error}"))?,
            )
            .map_err(|error| format!("ESSCertIDv2 hashAlgorithm OID is malformed: {error}"))?;
            let hash = ess_reader
                .read_tagged(&mut budget, der::TAG_OCTET_STRING)
                .map_err(|error| format!("ESSCertIDv2 certHash is missing: {error}"))?;
            (oid, hash)
        } else {
            (OID_SHA256.to_string(), first)
        };
        if hash_tlv.tag != der::TAG_OCTET_STRING {
            return Err("ESSCertIDv2 certHash is not an OCTET STRING".to_string());
        }
        Ok((hash_algorithm_oid, hash_tlv.content.to_vec()))
    }

    enum SignatureFailure {
        Unsupported(String),
        Invalid(String),
    }

    fn verify_token_signature(
        signer: &ParsedSignerInfo,
        certificate: &x509_parser::prelude::X509Certificate<'_>,
        econtent: &[u8],
    ) -> Result<(), SignatureFailure> {
        use x509_parser::prelude::AlgorithmIdentifier;
        let data: Vec<u8> = match &signer.signed_attributes_set_der {
            Some(set) => set.clone(),
            None => econtent.to_vec(),
        };
        let (remaining, algorithm) =
            AlgorithmIdentifier::from_der(&signer.signature_algorithm_raw).map_err(|error| {
                SignatureFailure::Unsupported(format!(
                    "signature AlgorithmIdentifier did not parse: {error}"
                ))
            })?;
        if !remaining.is_empty() {
            return Err(SignatureFailure::Unsupported(
                "signature AlgorithmIdentifier has trailing bytes".to_string(),
            ));
        }
        // CMS carries the digest separately: a very common SignerInfo uses
        // `rsaEncryption` as signatureAlgorithm, with the digest named by
        // digestAlgorithm. Map that pair onto the combined PKCS#1 OID the
        // verification backend understands. RSASSA-PSS is a distinct scheme
        // and is reported as unsupported rather than guessed at.
        let mapped_der: Option<Vec<u8>> =
            if algorithm.algorithm.to_string() == OID_RSA_ENCRYPTION {
                match rsa_pkcs1_oid_for_digest(&signer.digest_algorithm) {
                    Some(oid) => Some(der::algorithm_identifier(oid).map_err(|error| {
                        SignatureFailure::Unsupported(format!(
                            "could not encode the RSA signature algorithm: {error}"
                        ))
                    })?),
                    None => {
                        return Err(SignatureFailure::Unsupported(format!(
                            "signatureAlgorithm is rsaEncryption but digestAlgorithm {} has no supported PKCS#1 v1.5 mapping",
                            signer.digest_algorithm
                        )));
                    }
                }
            } else if algorithm.algorithm.to_string() == OID_RSASSA_PSS {
                return Err(SignatureFailure::Unsupported(
                    "signatureAlgorithm is RSASSA-PSS (1.2.840.113549.1.1.10); the available verification backend supports PKCS#1 v1.5, ECDSA and Ed25519 only"
                        .to_string(),
                ));
            } else {
                None
            };
        let mapped_algorithm = match &mapped_der {
            Some(bytes) => {
                let (remaining, mapped) = AlgorithmIdentifier::from_der(bytes).map_err(
                    |error| {
                        SignatureFailure::Unsupported(format!(
                            "could not parse the mapped RSA signature algorithm: {error}"
                        ))
                    },
                )?;
                if !remaining.is_empty() {
                    return Err(SignatureFailure::Unsupported(
                        "mapped RSA signature algorithm has trailing bytes".to_string(),
                    ));
                }
                Some(mapped)
            }
            None => None,
        };
        let algorithm = mapped_algorithm.as_ref().unwrap_or(&algorithm);
        let signature = x509_parser::der_parser::asn1_rs::BitString::new(0, &signer.signature);
        match x509_parser::verify::verify_signature(
            certificate.public_key(),
            algorithm,
            &signature,
            &data,
        ) {
            Ok(()) => Ok(()),
            Err(x509_parser::prelude::X509Error::SignatureUnsupportedAlgorithm) => {
                Err(SignatureFailure::Unsupported(format!(
                    "signature algorithm {} is outside the supported set (RSA PKCS#1 v1.5 SHA-1/256/384/512, ECDSA P-256/P-384 SHA-256/384, Ed25519)",
                    algorithm.algorithm
                )))
            }
            Err(error) => Err(SignatureFailure::Invalid(format!(
                "CMS signature over the signed attributes did not verify: {error}"
            ))),
        }
    }

    fn build_evidence(
        request: &TimestampVerificationRequest<'_>,
        tst: &ParsedTstInfo,
        certificate_der: Option<&Vec<u8>>,
        certificate: Option<x509_parser::prelude::X509Certificate<'_>>,
        checks: Vec<CheckVerdict>,
    ) -> TimeStampEvidence {
        let signer_certificate = certificate
            .as_ref()
            .and_then(|certificate| certificate_der.map(|der| summarise_certificate(certificate, der)));
        let document_digest = digest_for_oid(&tst.imprint_algorithm, request.document)
            .unwrap_or_else(|| request.algorithm.digest(request.document));
        TimeStampEvidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            request_nonce: request.nonce,
            request_nonce_hex: format!("0x{:016X}", request.nonce),
            tsa_url: request.tsa_url.map(str::to_string),
            imprint_algorithm: hash_algorithm_from_oid(&tst.imprint_algorithm)
                .map(|algorithm| algorithm.name().to_string())
                .unwrap_or_else(|| tst.imprint_algorithm.clone()),
            imprint_algorithm_oid: tst.imprint_algorithm.clone(),
            imprint_hex: hex::encode(&tst.imprint),
            document_digest_hex: hex::encode(&document_digest),
            gen_time_raw: tst.gen_time_raw.clone(),
            gen_time_rfc3339: tst
                .gen_time
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            gen_time_unix: tst.gen_time.map(|time| time.timestamp()),
            policy_oid: tst.policy.clone(),
            serial_number_hex: hex::encode(&tst.serial),
            tst_info_version: tst.version,
            ordering: tst.ordering,
            accuracy_seconds: tst.accuracy_seconds,
            signer_certificate,
            checks,
            proven_properties: PROVEN_PROPERTIES
                .iter()
                .map(|value| value.to_string())
                .collect(),
            not_proven_properties: NOT_PROVEN_PROPERTIES
                .iter()
                .map(|value| value.to_string())
                .collect(),
        }
    }

    /// Summarise a parsed certificate and its DER.
    pub fn summarise_certificate(
        certificate: &x509_parser::prelude::X509Certificate<'_>,
        certificate_der: &[u8],
    ) -> CertificateSummary {
        CertificateSummary {
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            serial_hex: hex::encode(certificate.raw_serial()),
            not_before: certificate.validity().not_before.to_string(),
            not_after: certificate.validity().not_after.to_string(),
            public_key_algorithm_oid: certificate.public_key().algorithm.algorithm.to_string(),
            sha256_fingerprint_hex: hex::encode(Sha256::digest(certificate_der)),
        }
    }

    // -- Transport ------------------------------------------------------------

    /// RFC 3161 HTTP client. [`TimeStampClient::from_env`] returns `Ok(None)`
    /// when no TSA URL is configured, which callers must treat as "no
    /// timestamp".
    pub struct TimeStampClient {
        config: TsaConfig,
        http: reqwest::Client,
    }

    impl TimeStampClient {
        /// Build a client for the given configuration.
        pub fn new(config: TsaConfig) -> Result<Self, TimeStampError> {
            let timeout = std::time::Duration::from_secs(config.timeout_secs.max(1));
            let http = reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(timeout)
                .build()
                .map_err(|error| {
                    TimeStampError::Transport(format!("HTTP client build failed: {error}"))
                })?;
            Ok(Self { config, http })
        }

        /// Read the environment; `Ok(None)` means no TSA is configured.
        pub fn from_env() -> Result<Option<Self>, TimeStampError> {
            match TsaConfig::from_env()? {
                Some(config) => Ok(Some(Self::new(config)?)),
                None => Ok(None),
            }
        }

        /// The configuration in use.
        pub fn config(&self) -> &TsaConfig {
            &self.config
        }

        /// Request a timestamp for `document`, verifying against the wall
        /// clock. Fails closed: any required check that does not pass becomes
        /// a [`TimeStampError::VerificationFailed`] carrying the evidence.
        pub async fn timestamp(
            &self,
            document: &[u8],
            algorithm: HashAlgorithm,
        ) -> Result<TimeStampEvidence, TimeStampError> {
            self.timestamp_at(document, algorithm, Utc::now()).await
        }

        /// Deterministic variant of [`TimeStampClient::timestamp`] with an
        /// explicit verification clock (tests, replay audits).
        pub async fn timestamp_at(
            &self,
            document: &[u8],
            algorithm: HashAlgorithm,
            now: DateTime<Utc>,
        ) -> Result<TimeStampEvidence, TimeStampError> {
            let nonce = random_nonce();
            let request_der = build_request(document, algorithm, nonce, true)?;
            let response_der = self.post(&request_der).await?;
            let request = self
                .config
                .verification_request(document, nonce, algorithm, now);
            let evidence = verify_response(&response_der, &request)?;
            if evidence.all_passed() {
                Ok(evidence)
            } else {
                let failures = evidence
                    .checks
                    .iter()
                    .filter(|check| check.required && !check.outcome.is_pass())
                    .cloned()
                    .collect();
                Err(TimeStampError::VerificationFailed {
                    failures,
                    evidence: Box::new(evidence),
                })
            }
        }

        async fn post(&self, request_der: &[u8]) -> Result<Vec<u8>, TimeStampError> {
            let mut builder = self
                .http
                .post(&self.config.url)
                .header(reqwest::header::CONTENT_TYPE, HTTP_CONTENT_TYPE)
                .header(reqwest::header::ACCEPT, HTTP_ACCEPT)
                .body(request_der.to_vec());
            if let Some(auth) = &self.config.auth_header {
                builder = builder.header(auth.name.as_str(), auth.value.as_str());
            }
            let response = builder
                .send()
                .await
                .map_err(|error| TimeStampError::Transport(error.to_string()))?;
            let status = response.status();
            if !status.is_success() {
                return Err(TimeStampError::HttpStatus {
                    status: status.as_u16(),
                });
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());
            let content_type_ok = content_type
                .as_deref()
                .map(|value| {
                    value
                        .split(';')
                        .next()
                        .map(|media_type| {
                            media_type.trim().eq_ignore_ascii_case(HTTP_CONTENT_TYPE_REPLY)
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !content_type_ok {
                return Err(TimeStampError::WrongContentType { content_type });
            }
            if let Some(length) = response.content_length() {
                if length > self.config.max_response_bytes as u64 {
                    return Err(TimeStampError::ResponseTooLarge {
                        limit: self.config.max_response_bytes,
                    });
                }
            }
            let mut body: Vec<u8> = Vec::new();
            let mut response = response;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| TimeStampError::Transport(error.to_string()))?
            {
                if body.len() + chunk.len() > self.config.max_response_bytes {
                    return Err(TimeStampError::ResponseTooLarge {
                        limit: self.config.max_response_bytes,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        }
    }

    /// Fail-closed entry point: with `config == None` this returns
    /// [`TimeStampError::NotConfigured`] without performing any network call,
    /// and never fabricates a timestamp.
    pub async fn timestamp_document(
        config: Option<&TsaConfig>,
        document: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<TimeStampEvidence, TimeStampError> {
        let Some(config) = config else {
            return Err(TimeStampError::NotConfigured);
        };
        let client = TimeStampClient::new(config.clone())?;
        client.timestamp(document, algorithm).await
    }
}

// ---------------------------------------------------------------------------
// ASiC-E / BDOC containers
// ---------------------------------------------------------------------------

/// ASiC-E / BDOC (ETSI EN 319 162) container verification over unpacked
/// members. See the module docs for proven / not-proven properties.
pub mod container {
    use super::der;
    use super::{
        all_passed, has_failures, strictly_passed, CheckVerdict, CertificateSummary,
        EVIDENCE_SCHEMA_VERSION,
    };
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    use base64::Engine as _;
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    use quick_xml::reader::NsReader;
    use quick_xml::XmlVersion;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_parser::prelude::FromDer;

    /// The exact `mimetype` member content required by ETSI EN 319 162-1.
    pub const ASIC_E_MIMETYPE: &str = "application/vnd.etsi.asic-e+zip";
    /// XML DSig namespace.
    pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
    /// XAdES v1.3.2 namespace.
    pub const XADES_NS_V13: &str = "http://uri.etsi.org/01903/v1.3.2#";
    /// XAdES v1.4.2 namespace.
    pub const XADES_NS_V142: &str = "http://uri.etsi.org/01903/v1.4.2#";
    /// The `mimetype` member path.
    pub const MIMETYPE_MEMBER: &str = "mimetype";
    /// The canonical signature file path.
    pub const SIGNATURES_XML: &str = "META-INF/signatures.xml";
    /// Cap on `signatures*.xml` size.
    pub const MAX_SIGNATURES_XML_BYTES: usize = 4 * 1024 * 1024;
    /// Cap on the number of signature files processed.
    pub const MAX_SIGNATURE_FILES: usize = 8;

    // Digest algorithm URIs (XML DSig / XML Enc).
    const URI_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    const URI_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    const URI_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
    const URI_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

    // Signature method URIs.
    const URI_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const URI_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    const URI_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    const URI_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const URI_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    const URI_ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    const URI_ED25519: &str = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";

    const MAX_XML_DEPTH: usize = 64;
    const MAX_XML_EVENTS: usize = 200_000;
    const MAX_XML_ATTRIBUTES: usize = 256;
    const MAX_XML_TEXT_TOTAL: usize = 2 * 1024 * 1024;
    const MAX_SIGNATURES: usize = 32;

    /// One unpacked container member.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ContainerMember {
        /// Member path, as it would appear inside the ZIP (forward slashes,
        /// no leading slash).
        pub path: String,
        /// Member bytes.
        pub content: Vec<u8>,
    }

    impl ContainerMember {
        /// Construct a member.
        pub fn new(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
            Self {
                path: path.into(),
                content: content.into(),
            }
        }
    }

    /// A member's path and size, recorded for audit.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MemberInfo {
        /// Member path.
        pub path: String,
        /// Member size in bytes.
        pub size_bytes: usize,
    }

    /// Per-reference digest verdict.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReferenceVerdict {
        /// The `Reference@URI`.
        pub uri: String,
        /// The `Reference@Type`, when present.
        pub reference_type: Option<String>,
        /// Whether the URI points inside the signature document (`#id`)
        /// rather than at a container member.
        pub is_same_document: bool,
        /// Declared digest algorithm URI.
        pub digest_algorithm: String,
        /// Friendly digest algorithm name when recognised.
        pub digest_algorithm_name: Option<String>,
        /// Stated digest, hex.
        pub expected_digest_hex: String,
        /// Computed digest, hex (absent when it could not be computed).
        pub actual_digest_hex: Option<String>,
        /// Whether the digest matched.
        pub ok: bool,
        /// Whether a mismatch here should fail the container gate.
        pub required: bool,
        /// Human-readable detail, including any canonicalization caveat.
        pub detail: String,
    }

    /// One XML signature inside one signature file.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignatureEvidence {
        /// `Signature@Id`, when present.
        pub signature_id: Option<String>,
        /// `SignatureMethod@Algorithm`.
        pub signature_method: Option<String>,
        /// `CanonicalizationMethod@Algorithm`.
        pub canonicalization_method: Option<String>,
        /// Signature-level checks.
        pub checks: Vec<CheckVerdict>,
        /// Per-reference verdicts.
        pub references: Vec<ReferenceVerdict>,
        /// The signing certificate, when one was found and parsed.
        pub signer_certificate: Option<CertificateSummary>,
    }

    /// The complete, serde-serialisable container evidence record.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AsicEvidence {
        /// Evidence schema version ([`EVIDENCE_SCHEMA_VERSION`]).
        pub schema_version: u32,
        /// The `mimetype` member content, when present.
        pub mimetype: Option<String>,
        /// The container's members.
        pub members: Vec<MemberInfo>,
        /// Container-level checks.
        pub container_checks: Vec<CheckVerdict>,
        /// One entry per XML signature found.
        pub signatures: Vec<SignatureEvidence>,
        /// Plain-language list of properties this evidence proves.
        pub proven_properties: Vec<String>,
        /// Plain-language list of properties this evidence does NOT prove.
        pub not_proven_properties: Vec<String>,
    }

    impl AsicEvidence {
        /// True when every required check (container, signature and reference)
        /// passed.
        pub fn all_passed(&self) -> bool {
            all_passed(&self.container_checks)
                && self
                    .signatures
                    .iter()
                    .all(|signature| all_passed(&signature.checks))
                && self.all_required_references_ok()
        }

        /// True when every check everywhere is a `Pass`.
        pub fn strictly_passed(&self) -> bool {
            strictly_passed(&self.container_checks)
                && self
                    .signatures
                    .iter()
                    .all(|signature| strictly_passed(&signature.checks))
                && self
                    .signatures
                    .iter()
                    .flat_map(|signature| signature.references.iter())
                    .all(|reference| reference.ok)
        }

        /// True when any check failed.
        pub fn has_failures(&self) -> bool {
            has_failures(&self.container_checks)
                || self
                    .signatures
                    .iter()
                    .any(|signature| has_failures(&signature.checks))
        }

        /// Every check that did not pass, with a path prefix.
        pub fn failing_checks(&self) -> Vec<String> {
            let mut out = Vec::new();
            for check in &self.container_checks {
                if !check.outcome.is_pass() {
                    out.push(format!("container:{}: {:?}", check.check, check.outcome));
                }
            }
            for (index, signature) in self.signatures.iter().enumerate() {
                for check in &signature.checks {
                    if !check.outcome.is_pass() {
                        out.push(format!(
                            "signature[{index}]:{}: {:?}",
                            check.check, check.outcome
                        ));
                    }
                }
            }
            for (index, signature) in self.signatures.iter().enumerate() {
                for reference in &signature.references {
                    if !reference.ok {
                        out.push(format!(
                            "signature[{index}]:reference[{}]: {}",
                            reference.uri, reference.detail
                        ));
                    }
                }
            }
            out
        }

        fn all_required_references_ok(&self) -> bool {
            self.signatures
                .iter()
                .flat_map(|signature| signature.references.iter())
                .filter(|reference| reference.required)
                .all(|reference| reference.ok)
        }
    }

    /// Properties proven by a passing [`AsicEvidence`] record.
    pub const PROVEN_PROPERTIES: &[&str] = &[
        "The container declares the ASiC-E media type exactly: mimetype = application/vnd.etsi.asic-e+zip.",
        "Every signed file reference resolves to a container member and the member's bytes hash to the digest stated in signatures.xml.",
        "Every container member outside mimetype and META-INF/ is covered by at least one signature reference.",
        "The signing certificate is present in the signature and parses as an X.509 certificate.",
        "When the signature algorithm is supported, the SignatureValue verifies against the signing certificate's public key over the SignedInfo octets as serialized in the container.",
    ];

    /// Properties NOT proven by an [`AsicEvidence`] record.
    pub const NOT_PROVEN_PROPERTIES: &[&str] = &[
        "XML canonicalization was not performed. The signature and same-document reference checks use raw octets; they equal the canonical form only when the producer serialized canonically. A same-document digest mismatch is reported as inconclusive, not as tampering.",
        "ZIP-level ASiC-E rules (mimetype is the first entry and is stored uncompressed) cannot be checked from unpacked members; the caller supplies the members.",
        "The signer's identity, authorization or qualification is not established: no certificate-chain validation, no trust store, no revocation check, no name binding.",
    ];

    /// Verify an unpacked ASiC-E / BDOC container.
    ///
    /// Never returns an error for bad content: every problem becomes a named
    /// check so the caller can persist and inspect exactly what was found.
    /// Gate on [`AsicEvidence::all_passed`].
    pub fn verify_asic_e(members: &[ContainerMember]) -> AsicEvidence {
        let mut container_checks: Vec<CheckVerdict> = Vec::new();
        let member_infos: Vec<MemberInfo> = members
            .iter()
            .map(|member| MemberInfo {
                path: member.path.clone(),
                size_bytes: member.content.len(),
            })
            .collect();

        // mimetype.
        let mimetypes: Vec<&ContainerMember> = members
            .iter()
            .filter(|member| member.path == MIMETYPE_MEMBER)
            .collect();
        if mimetypes.is_empty() {
            container_checks.push(CheckVerdict::fail(
                "mimetype_member_present",
                true,
                "container has no 'mimetype' member".to_string(),
            ));
        } else if mimetypes.len() > 1 {
            container_checks.push(CheckVerdict::fail(
                "mimetype_member_present",
                true,
                format!("container has {} 'mimetype' members", mimetypes.len()),
            ));
        } else {
            container_checks.push(CheckVerdict::pass("mimetype_member_present", true));
        }
        let mimetype_text = mimetypes
            .first()
            .map(|member| String::from_utf8_lossy(&member.content).into_owned());
        match mimetypes.first() {
            Some(member) if member.content == ASIC_E_MIMETYPE.as_bytes() => {
                container_checks.push(CheckVerdict::pass("mimetype_exact", true));
            }
            Some(member) => container_checks.push(CheckVerdict::fail(
                "mimetype_exact",
                true,
                format!(
                    "mimetype is {:?}, expected exactly {:?}",
                    String::from_utf8_lossy(&member.content),
                    ASIC_E_MIMETYPE
                ),
            )),
            None => container_checks.push(CheckVerdict::not_performed(
                "mimetype_exact",
                true,
                "no mimetype member".to_string(),
            )),
        }

        // Signature files.
        let signature_files: Vec<&ContainerMember> = members
            .iter()
            .filter(|member| is_signature_file(&member.path))
            .collect();
        if signature_files.is_empty() {
            container_checks.push(CheckVerdict::fail(
                "signature_file_present",
                true,
                "container has no META-INF/signatures.xml (or signaturesN.xml)".to_string(),
            ));
        } else if signature_files.len() > MAX_SIGNATURE_FILES {
            container_checks.push(CheckVerdict::fail(
                "signature_file_present",
                true,
                format!(
                    "container has {} signature files, more than the supported {}",
                    signature_files.len(),
                    MAX_SIGNATURE_FILES
                ),
            ));
        } else {
            container_checks.push(CheckVerdict::pass("signature_file_present", true));
        }

        let mut signatures: Vec<SignatureEvidence> = Vec::new();
        let mut referenced_members: Vec<String> = Vec::new();
        for file in &signature_files {
            let size_check = format!("signatures_xml_size_within_limit[{}]", file.path);
            if file.content.len() > MAX_SIGNATURES_XML_BYTES {
                container_checks.push(CheckVerdict::fail(
                    size_check,
                    true,
                    format!(
                        "{} bytes exceeds the {} byte limit",
                        file.content.len(),
                        MAX_SIGNATURES_XML_BYTES
                    ),
                ));
                continue;
            }
            container_checks.push(CheckVerdict::pass(size_check, true));
            let parse_check = format!("signatures_xml_parses[{}]", file.path);
            let text = match std::str::from_utf8(&file.content) {
                Ok(text) => text,
                Err(error) => {
                    container_checks.push(CheckVerdict::fail(
                        parse_check,
                        true,
                        format!("signature file is not UTF-8: {error}"),
                    ));
                    continue;
                }
            };
            let tree = match parse_xml_tree(text) {
                Ok(tree) => {
                    container_checks.push(CheckVerdict::pass(parse_check, true));
                    tree
                }
                Err(error) => {
                    container_checks.push(CheckVerdict::fail(parse_check, true, error));
                    continue;
                }
            };
            let mut signature_nodes = Vec::new();
            collect_signature_nodes(&tree, &mut signature_nodes);
            if signature_nodes.is_empty() {
                container_checks.push(CheckVerdict::fail(
                    format!("signature_present[{}]", file.path),
                    true,
                    "file contains no ds:Signature element in the XML DSig namespace"
                        .to_string(),
                ));
                continue;
            }
            container_checks.push(CheckVerdict::pass(
                format!("signature_present[{}]", file.path),
                true,
            ));
            let mut id_spans: Vec<(String, usize, usize)> = Vec::new();
            collect_id_spans(&tree, &mut id_spans);
            for node in signature_nodes.iter() {
                if signatures.len() >= MAX_SIGNATURES {
                    container_checks.push(CheckVerdict::fail(
                        "signature_count_within_limit",
                        true,
                        format!("more than {MAX_SIGNATURES} signatures found"),
                    ));
                    break;
                }
                let (evidence, resolved_members) =
                    verify_signature_element(node, text, members, &id_spans);
                referenced_members.extend(resolved_members);
                signatures.push(evidence);
            }
        }

        // Unsigned member coverage.
        let mut unsigned: Vec<String> = Vec::new();
        for member in members {
            if member.path == MIMETYPE_MEMBER || member.path.starts_with("META-INF/") {
                continue;
            }
            if !referenced_members.iter().any(|path| path == &member.path) {
                unsigned.push(member.path.clone());
            }
        }
        if unsigned.is_empty() {
            container_checks.push(CheckVerdict::pass("all_container_files_signed", true));
        } else {
            container_checks.push(CheckVerdict::fail(
                "all_container_files_signed",
                true,
                format!(
                    "{} container member(s) are not covered by any signature reference: {}",
                    unsigned.len(),
                    unsigned.join(", ")
                ),
            ));
        }

        AsicEvidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            mimetype: mimetype_text,
            members: member_infos,
            container_checks,
            signatures,
            proven_properties: PROVEN_PROPERTIES
                .iter()
                .map(|value| value.to_string())
                .collect(),
            not_proven_properties: NOT_PROVEN_PROPERTIES
                .iter()
                .map(|value| value.to_string())
                .collect(),
        }
    }

    fn is_signature_file(path: &str) -> bool {
        let Some(name) = path.strip_prefix("META-INF/") else {
            return false;
        };
        let Some(stem) = name.strip_prefix("signatures") else {
            return false;
        };
        match stem.strip_suffix(".xml") {
            Some("") => true,
            Some(digits) => digits.bytes().all(|byte| byte.is_ascii_digit()),
            None => false,
        }
    }

    fn verify_signature_element(
        signature: &XmlNode,
        xml: &str,
        members: &[ContainerMember],
        id_spans: &[(String, usize, usize)],
    ) -> (SignatureEvidence, Vec<String>) {
        let mut checks: Vec<CheckVerdict> = Vec::new();
        let mut references: Vec<ReferenceVerdict> = Vec::new();
        let mut resolved_members: Vec<String> = Vec::new();
        let signature_id = signature.attr("Id").map(str::to_string);

        let signed_info = signature.first_descendant("SignedInfo", Some(DSIG_NS));
        let canonicalization_method = signature
            .first_descendant("CanonicalizationMethod", Some(DSIG_NS))
            .and_then(|node| node.attr("Algorithm"))
            .map(str::to_string);
        let signature_method = signature
            .first_descendant("SignatureMethod", Some(DSIG_NS))
            .and_then(|node| node.attr("Algorithm"))
            .map(str::to_string);

        let Some(signed_info) = signed_info else {
            checks.push(CheckVerdict::fail(
                "signed_info_present",
                true,
                "Signature has no ds:SignedInfo child".to_string(),
            ));
            return (
                SignatureEvidence {
                    signature_id,
                    signature_method,
                    canonicalization_method,
                    checks,
                    references,
                    signer_certificate: None,
                },
                resolved_members,
            );
        };
        checks.push(CheckVerdict::pass("signed_info_present", true));
        match &canonicalization_method {
            Some(method) => checks.push(
                CheckVerdict::pass("canonicalization_method_declared", true).with_note(format!(
                    "declared {method}; this module does not apply canonicalization (it hashes raw octets)"
                )),
            ),
            None => checks.push(CheckVerdict::fail(
                "canonicalization_method_declared",
                true,
                "SignedInfo has no CanonicalizationMethod".to_string(),
            )),
        }

        // Reference digests.
        for reference in signed_info.descendants("Reference", Some(DSIG_NS)) {
            let uri = reference.attr("URI").unwrap_or("").to_string();
            let reference_type = reference.attr("Type").map(str::to_string);
            let is_same_document = uri.starts_with('#');
            let digest_algorithm = reference
                .first_descendant("DigestMethod", Some(DSIG_NS))
                .and_then(|node| node.attr("Algorithm"))
                .unwrap_or("")
                .to_string();
            let digest_value_text = reference
                .first_descendant("DigestValue", Some(DSIG_NS))
                .map(|node| node.text.trim().to_string())
                .unwrap_or_default();
            let transforms: Vec<String> = reference
                .first_descendant("Transforms", Some(DSIG_NS))
                .map(|node| {
                    node.descendants("Transform", Some(DSIG_NS))
                        .into_iter()
                        .filter_map(|transform| transform.attr("Algorithm").map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let required = !is_same_document;
            let digest_algorithm_name =
                digest_algorithm_name(&digest_algorithm).map(str::to_string);
            let expected_digest = decode_base64_text(&digest_value_text);
            let mut detail = String::new();
            if !transforms.is_empty() {
                detail.push_str(&format!("transforms declared: {}; ", transforms.join(", ")));
            }
            let resolved_member = if is_same_document {
                None
            } else {
                resolve_member_uri(members, &uri)
            };
            if let Some(member) = resolved_member {
                resolved_members.push(member.path.clone());
            }
            let (actual_digest, ok) = match (&digest_algorithm_name, expected_digest.as_ref()) {
                (None, _) => {
                    detail.push_str("digest algorithm is not supported (only SHA-256/384/512 are accepted); ");
                    (None, false)
                }
                (Some(_), Err(error)) => {
                    detail.push_str(&format!("DigestValue is not decodable base64 ({error}); "));
                    (None, false)
                }
                (Some(_), Ok(expected)) => {
                    let input: Option<Vec<u8>> = if is_same_document {
                        let fragment = &uri[1..];
                        id_spans
                            .iter()
                            .find(|(id, _, _)| id == fragment)
                            .map(|(_, start, end)| xml.as_bytes()[*start..*end].to_vec())
                    } else {
                        resolved_member.map(|member| member.content.clone())
                    };
                    match input {
                        Some(input) => match digest_bytes(&digest_algorithm, &input) {
                            Some(actual) => {
                                let ok = actual.as_slice() == expected.as_slice();
                                if !ok {
                                    if is_same_document {
                                        detail.push_str(
                                            "raw-octet digest mismatch: the module does not canonicalize, so this is inconclusive without C14N rather than proof of tampering; ",
                                        );
                                    } else {
                                        detail.push_str("digest mismatch; ");
                                    }
                                }
                                (Some(actual), ok)
                            }
                            None => {
                                detail.push_str("digest algorithm unsupported; ");
                                (None, false)
                            }
                        },
                        None => {
                            if is_same_document {
                                detail.push_str(&format!(
                                    "no element with Id={:?} found in the signature document; ",
                                    &uri[1..]
                                ));
                            } else {
                                detail.push_str(
                                    "no container member matches the reference URI (after percent-decoding); ",
                                );
                            }
                            (None, false)
                        }
                    }
                }
            };
            if detail.is_empty() {
                detail.push_str("digest matches");
            }
            references.push(ReferenceVerdict {
                uri,
                reference_type,
                is_same_document,
                digest_algorithm,
                digest_algorithm_name,
                expected_digest_hex: expected_digest.as_ref().map(hex::encode).unwrap_or_default(),
                actual_digest_hex: actual_digest.map(hex::encode),
                ok,
                required,
                detail,
            });
        }
        let required_references_ok = references
            .iter()
            .filter(|reference| reference.required)
            .all(|reference| reference.ok);
        if references.is_empty() {
            checks.push(CheckVerdict::fail(
                "references_verified",
                true,
                "SignedInfo has no Reference elements".to_string(),
            ));
        } else if required_references_ok {
            checks.push(CheckVerdict::pass("references_verified", true));
        } else {
            let failed: Vec<String> = references
                .iter()
                .filter(|reference| reference.required && !reference.ok)
                .map(|reference| reference.uri.clone())
                .collect();
            checks.push(CheckVerdict::fail(
                "references_verified",
                true,
                format!("digest verification failed for: {}", failed.join(", ")),
            ));
        }

        // Certificates from KeyInfo.
        let certificates: Vec<Vec<u8>> = signature
            .descendants("X509Certificate", Some(DSIG_NS))
            .into_iter()
            .filter_map(|node| decode_base64_text(&node.text).ok())
            .collect();
        let parsed_first = certificates.first().and_then(|der| {
            x509_parser::prelude::X509Certificate::from_der(der)
                .ok()
                .map(|(_, certificate)| (der.clone(), certificate))
        });
        if certificates.is_empty() {
            checks.push(CheckVerdict::fail(
                "signer_certificate_present",
                true,
                "KeyInfo contains no ds:X509Certificate".to_string(),
            ));
        } else {
            checks.push(CheckVerdict::pass("signer_certificate_present", true));
        }
        match &parsed_first {
            Some(_) => checks.push(CheckVerdict::pass("signer_certificate_parses", true)),
            None if certificates.is_empty() => checks.push(CheckVerdict::not_performed(
                "signer_certificate_parses",
                true,
                "no certificate to parse".to_string(),
            )),
            None => checks.push(CheckVerdict::fail(
                "signer_certificate_parses",
                true,
                "the first X509Certificate value is not a parseable X.509 certificate".to_string(),
            )),
        }
        let signer_certificate = parsed_first
            .as_ref()
            .map(|(der, certificate)| super::timestamp::summarise_certificate(certificate, der));

        // SignatureValue over the raw SignedInfo octets.
        let signature_value = signature
            .first_descendant("SignatureValue", Some(DSIG_NS))
            .map(|node| node.text.trim().to_string())
            .unwrap_or_default();
        let signature_value_bytes = decode_base64_text(&signature_value);
        match &signature_value_bytes {
            Ok(bytes) if !bytes.is_empty() => {
                checks.push(CheckVerdict::pass("signature_value_decodes", true));
            }
            Ok(_) => checks.push(CheckVerdict::fail(
                "signature_value_decodes",
                true,
                "SignatureValue is empty".to_string(),
            )),
            Err(error) => checks.push(CheckVerdict::fail(
                "signature_value_decodes",
                true,
                format!("SignatureValue is not decodable base64: {error}"),
            )),
        }
        match (
            signature_value_bytes.as_ref(),
            &parsed_first,
            &signature_method,
        ) {
            (Ok(bytes), Some((_, certificate)), Some(method)) => {
                let raw_signed_info = &xml.as_bytes()[signed_info.start..signed_info.end];
                match verify_xmldsig_signature(method, raw_signed_info, bytes, certificate) {
                    Ok(()) => checks.push(CheckVerdict::pass(
                        "signature_value_over_raw_signed_info",
                        true,
                    )),
                    Err(SignatureFailure::Unsupported(reason)) => {
                        checks.push(CheckVerdict::not_performed(
                            "signature_value_over_raw_signed_info",
                            true,
                            reason,
                        ))
                    }
                    Err(SignatureFailure::Invalid(reason)) => checks.push(CheckVerdict::fail(
                        "signature_value_over_raw_signed_info",
                        true,
                        format!(
                            "{reason} (checked over the raw SignedInfo octets; a conforming signer that canonicalized differently would also fail this raw-octet check)"
                        ),
                    )),
                }
            }
            (Err(_), _, _) => checks.push(CheckVerdict::not_performed(
                "signature_value_over_raw_signed_info",
                true,
                "SignatureValue did not decode".to_string(),
            )),
            (_, None, _) => checks.push(CheckVerdict::not_performed(
                "signature_value_over_raw_signed_info",
                true,
                "no parseable signing certificate, so no public key is available".to_string(),
            )),
            (_, _, None) => checks.push(CheckVerdict::fail(
                "signature_value_over_raw_signed_info",
                true,
                "SignedInfo has no SignatureMethod".to_string(),
            )),
        }

        // XAdES signing-certificate digest, when present.
        match find_xades_cert_digest(signature) {
            Some((algorithm, expected)) => match (&parsed_first, decode_base64_text(&expected)) {
                (Some((der, _)), Ok(expected_bytes)) => match digest_bytes(&algorithm, der) {
                    Some(actual) if actual == expected_bytes => checks.push(CheckVerdict::pass(
                        "signing_certificate_digest_matches_signer_certificate",
                        false,
                    )),
                    Some(actual) => checks.push(CheckVerdict::fail(
                        "signing_certificate_digest_matches_signer_certificate",
                        false,
                        format!(
                            "XAdES CertDigest {} does not equal the {algorithm} digest {} of the signing certificate",
                            hex::encode(&expected_bytes),
                            hex::encode(&actual)
                        ),
                    )),
                    None => checks.push(CheckVerdict::not_performed(
                        "signing_certificate_digest_matches_signer_certificate",
                        false,
                        format!("digest algorithm {algorithm} is not supported"),
                    )),
                },
                (None, _) => checks.push(CheckVerdict::not_performed(
                    "signing_certificate_digest_matches_signer_certificate",
                    false,
                    "no parseable signing certificate".to_string(),
                )),
                (_, Err(error)) => checks.push(CheckVerdict::fail(
                    "signing_certificate_digest_matches_signer_certificate",
                    false,
                    format!("XAdES CertDigest value is not decodable base64: {error}"),
                )),
            },
            None => checks.push(CheckVerdict::not_performed(
                "signing_certificate_digest_matches_signer_certificate",
                false,
                "signature has no XAdES SigningCertificateV2/CertDigest".to_string(),
            )),
        }

        (
            SignatureEvidence {
                signature_id,
                signature_method,
                canonicalization_method,
                checks,
                references,
                signer_certificate,
            },
            resolved_members,
        )
    }

    enum SignatureFailure {
        Unsupported(String),
        Invalid(String),
    }

    fn xmldsig_algorithm_oid(uri: &str) -> Option<(&'static str, bool)> {
        // (OID, parameters-present)
        match uri {
            URI_RSA_SHA256 => Some(("1.2.840.113549.1.1.11", true)),
            URI_RSA_SHA384 => Some(("1.2.840.113549.1.1.12", true)),
            URI_RSA_SHA512 => Some(("1.2.840.113549.1.1.13", true)),
            URI_RSA_SHA1 => Some(("1.2.840.113549.1.1.5", true)),
            URI_ECDSA_SHA256 => Some(("1.2.840.10045.4.3.2", false)),
            URI_ECDSA_SHA384 => Some(("1.2.840.10045.4.3.3", false)),
            URI_ED25519 => Some(("1.3.101.112", false)),
            _ => None,
        }
    }

    fn verify_xmldsig_signature(
        method_uri: &str,
        signed_info_raw: &[u8],
        signature_value: &[u8],
        certificate: &x509_parser::prelude::X509Certificate<'_>,
    ) -> Result<(), SignatureFailure> {
        use x509_parser::prelude::{AlgorithmIdentifier, FromDer};
        let (oid, with_parameters) = xmldsig_algorithm_oid(method_uri).ok_or_else(|| {
            SignatureFailure::Unsupported(format!("signature method {method_uri} is not supported"))
        })?;
        let algorithm_der = if with_parameters {
            der::algorithm_identifier(oid)
        } else {
            der::algorithm_identifier_without_parameters(oid)
        }
        .map_err(|error| SignatureFailure::Invalid(format!("could not encode algorithm: {error}")))?;
        let (remaining, algorithm) = AlgorithmIdentifier::from_der(&algorithm_der)
            .map_err(|error| SignatureFailure::Invalid(format!("algorithm identifier: {error}")))?;
        if !remaining.is_empty() {
            return Err(SignatureFailure::Invalid(
                "algorithm identifier has trailing bytes".to_string(),
            ));
        }
        let signature = x509_parser::der_parser::asn1_rs::BitString::new(0, signature_value);
        match x509_parser::verify::verify_signature(
            certificate.public_key(),
            &algorithm,
            &signature,
            signed_info_raw,
        ) {
            Ok(()) => Ok(()),
            Err(x509_parser::prelude::X509Error::SignatureUnsupportedAlgorithm) => {
                Err(SignatureFailure::Unsupported(format!(
                    "signature method {method_uri} maps to {oid}, which the available verification backend does not support"
                )))
            }
            Err(error) => Err(SignatureFailure::Invalid(format!(
                "SignatureValue did not verify: {error}"
            ))),
        }
    }

    fn find_xades_cert_digest(signature: &XmlNode) -> Option<(String, String)> {
        let cert_digest = signature.first_descendant("CertDigest", None)?;
        let algorithm = cert_digest
            .first_descendant("DigestMethod", Some(DSIG_NS))
            .and_then(|node| node.attr("Algorithm"))
            .map(str::to_string)?;
        let value = cert_digest
            .first_descendant("DigestValue", Some(DSIG_NS))
            .map(|node| node.text.trim().to_string())?;
        Some((algorithm, value))
    }

    fn digest_algorithm_name(uri: &str) -> Option<&'static str> {
        match uri {
            URI_SHA256 => Some("sha256"),
            URI_SHA384 => Some("sha384"),
            URI_SHA512 => Some("sha512"),
            URI_SHA1 => Some("sha1"),
            _ => None,
        }
    }

    fn digest_bytes(uri: &str, data: &[u8]) -> Option<Vec<u8>> {
        match uri {
            URI_SHA256 => Some(Sha256::digest(data).to_vec()),
            URI_SHA384 => Some(Sha384::digest(data).to_vec()),
            URI_SHA512 => Some(Sha512::digest(data).to_vec()),
            URI_SHA1 => None, // SHA-1 is recognised but refused.
            _ => None,
        }
    }

    fn decode_base64_text(text: &str) -> Result<Vec<u8>, String> {
        let cleaned: String = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if cleaned.is_empty() {
            return Err("empty value".to_string());
        }
        STANDARD
            .decode(cleaned.as_bytes())
            .or_else(|_| STANDARD_NO_PAD.decode(cleaned.as_bytes()))
            .map_err(|error| error.to_string())
    }

    /// Resolve a reference URI to a member: no fragments, no absolute URLs,
    /// no path traversal; percent-decoding is applied.
    pub fn resolve_member_uri<'a>(
        members: &'a [ContainerMember],
        uri: &str,
    ) -> Option<&'a ContainerMember> {
        if uri.starts_with('#') {
            return None;
        }
        let lower = uri.to_ascii_lowercase();
        if lower.starts_with("http:")
            || lower.starts_with("https:")
            || lower.starts_with("file:")
            || lower.starts_with("ftp:")
            || uri.starts_with('/')
        {
            return None;
        }
        let decoded = percent_decode(uri).ok()?;
        let normalized = decoded.strip_prefix("./").unwrap_or(&decoded);
        if normalized
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
            || normalized.contains('\\')
            || normalized.contains('\0')
        {
            return None;
        }
        members.iter().find(|member| member.path == normalized)
    }

    fn percent_decode(input: &str) -> Result<String, ()> {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    let high = *bytes.get(index + 1).ok_or(())?;
                    let low = *bytes.get(index + 2).ok_or(())?;
                    out.push((hex_digit(high)? << 4) | hex_digit(low)?);
                    index += 3;
                }
                byte => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| ())
    }

    fn hex_digit(byte: u8) -> Result<u8, ()> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(()),
        }
    }

    // -- Minimal, bounded XML tree -------------------------------------------

    #[derive(Debug, Clone)]
    struct XmlNode {
        local: String,
        namespace: Option<String>,
        attributes: Vec<(String, String)>,
        text: String,
        children: Vec<XmlNode>,
        start: usize,
        end: usize,
    }

    impl XmlNode {
        fn attr(&self, name: &str) -> Option<&str> {
            self.attributes
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }

        fn matches(&self, local: &str, namespace: Option<&str>) -> bool {
            self.local == local
                && match namespace {
                    Some(namespace) => self.namespace.as_deref() == Some(namespace),
                    None => true,
                }
        }

        fn first_descendant(&self, local: &str, namespace: Option<&str>) -> Option<&XmlNode> {
            self.descendants(local, namespace).into_iter().next()
        }

        fn descendants(&self, local: &str, namespace: Option<&str>) -> Vec<&XmlNode> {
            let mut out = Vec::new();
            for child in &self.children {
                if child.matches(local, namespace) {
                    out.push(child);
                    continue;
                }
                if child.local == "Signature" && child.namespace.as_deref() == Some(DSIG_NS) {
                    continue;
                }
                out.extend(child.descendants(local, namespace));
            }
            out
        }
    }

    fn collect_signature_nodes<'a>(node: &'a XmlNode, out: &mut Vec<&'a XmlNode>) {
        if node.local == "Signature" && node.namespace.as_deref() == Some(DSIG_NS) {
            out.push(node);
            return;
        }
        for child in &node.children {
            collect_signature_nodes(child, out);
        }
    }

    fn collect_id_spans(node: &XmlNode, out: &mut Vec<(String, usize, usize)>) {
        if let Some(id) = node.attr("Id") {
            out.push((id.to_string(), node.start, node.end));
        }
        for child in &node.children {
            collect_id_spans(child, out);
        }
    }

    fn parse_xml_tree(input: &str) -> Result<XmlNode, String> {
        let mut reader = NsReader::from_str(input);
        let mut root = XmlNode {
            local: "#document".to_string(),
            namespace: None,
            attributes: Vec::new(),
            text: String::new(),
            children: Vec::new(),
            start: 0,
            end: input.len(),
        };
        let mut events = 0usize;
        let mut text_total = 0usize;
        parse_children(&mut reader, &mut root, 0, &mut events, &mut text_total)?;
        Ok(root)
    }

    fn parse_children(
        reader: &mut NsReader<&[u8]>,
        parent: &mut XmlNode,
        depth: usize,
        events: &mut usize,
        text_total: &mut usize,
    ) -> Result<bool, String> {
        loop {
            let start = reader.buffer_position() as usize;
            let (resolution, event) = reader
                .read_resolved_event()
                .map_err(|error| format!("malformed XML: {error}"))?;
            *events += 1;
            if *events > MAX_XML_EVENTS {
                return Err("XML event limit exceeded".to_string());
            }
            let namespace: Option<String> = match resolution {
                ResolveResult::Bound(namespace) => {
                    Some(String::from_utf8_lossy(namespace.as_ref()).into_owned())
                }
                _ => None,
            };
            match event {
                Event::Start(element) => {
                    if depth + 1 > MAX_XML_DEPTH {
                        return Err("XML nesting depth limit exceeded".to_string());
                    }
                    let mut node = XmlNode {
                        local: String::from_utf8_lossy(element.local_name().as_ref()).into_owned(),
                        namespace,
                        attributes: element_attributes(&element)?,
                        text: String::new(),
                        children: Vec::new(),
                        start,
                        end: start,
                    };
                    let hit_end_of_document =
                        parse_children(reader, &mut node, depth + 1, events, text_total)?;
                    if hit_end_of_document {
                        return Err("unexpected end of XML document".to_string());
                    }
                    node.end = reader.buffer_position() as usize;
                    parent.children.push(node);
                }
                Event::Empty(element) => {
                    if depth + 1 > MAX_XML_DEPTH {
                        return Err("XML nesting depth limit exceeded".to_string());
                    }
                    let node = XmlNode {
                        local: String::from_utf8_lossy(element.local_name().as_ref()).into_owned(),
                        namespace,
                        attributes: element_attributes(&element)?,
                        text: String::new(),
                        children: Vec::new(),
                        start,
                        end: reader.buffer_position() as usize,
                    };
                    parent.children.push(node);
                }
                Event::End(_) => return Ok(false),
                Event::Text(text) => {
                    let decoded = text
                        .xml10_content()
                        .map_err(|error| format!("malformed XML text: {error}"))?;
                    *text_total += decoded.len();
                    if *text_total > MAX_XML_TEXT_TOTAL {
                        return Err("XML text limit exceeded".to_string());
                    }
                    parent.text.push_str(&decoded);
                }
                Event::CData(data) => {
                    let value = String::from_utf8_lossy(&data.into_inner()).into_owned();
                    *text_total += value.len();
                    if *text_total > MAX_XML_TEXT_TOTAL {
                        return Err("XML text limit exceeded".to_string());
                    }
                    parent.text.push_str(&value);
                }
                Event::Eof => return Ok(true),
                _ => {}
            }
        }
    }

    fn element_attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<Vec<(String, String)>, String> {
        let mut attributes = Vec::new();
        for attribute in element.attributes() {
            let attribute =
                attribute.map_err(|error| format!("malformed XML attribute: {error}"))?;
            if attributes.len() >= MAX_XML_ATTRIBUTES {
                return Err("XML attribute limit exceeded".to_string());
            }
            let key = String::from_utf8_lossy(attribute.key.local_name().as_ref()).into_owned();
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| format!("malformed XML attribute value: {error}"))?
                .into_owned();
            attributes.push((key, value));
        }
        Ok(attributes)
    }
}
