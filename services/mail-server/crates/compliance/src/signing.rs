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
    checks
        .iter()
        .all(|check| !check.required || check.outcome.is_pass())
}

/// True when every check (required or not) is a `Pass` — the strongest claim
/// this module can make. A `not_performed` check (e.g. an unsupported
/// signature algorithm) makes this false, and so does an EMPTY check list:
/// "every check passed" is vacuously true over zero checks and must not back
/// the strongest claim this module can make.
pub fn strictly_passed(checks: &[CheckVerdict]) -> bool {
    !checks.is_empty() && checks.iter().all(|check| check.outcome.is_pass())
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
                // The bound is checked in u64 space (total for every input)
                // before the conversion, so the cast below is lossless on
                // every target whose usize is at least 32 bits.
                if value > budget.limits.max_element_bytes as u64 {
                    return Err(DerError::ElementTooLarge {
                        length: value as usize,
                        max: budget.limits.max_element_bytes,
                    });
                }
                (value as usize, 2 + n)
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
        let fraction = rest.strip_prefix('.').or_else(|| rest.strip_prefix(','));
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
        let (unused, data) = tlv
            .content
            .split_first()
            .ok_or(DerError::InvalidBitString)?;
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

/// Build a verification `AlgorithmIdentifier` from OID arcs.
///
/// `x509_parser::verify::verify_signature` reads only the algorithm OID (the
/// NULL parameters of the RSA encodings are never inspected), so the
/// identifier is constructed directly instead of round-tripping through DER.
/// `Oid::from` fails only for structurally impossible arcs; the reason string
/// is surfaced as `Unsupported` by both verification modules.
fn verification_algorithm_from_arcs(
    arcs: &[u64],
) -> Result<x509_parser::prelude::AlgorithmIdentifier<'static>, String> {
    let oid = x509_parser::der_parser::asn1_rs::Oid::from(arcs).map_err(|error| {
        format!("could not encode the signature algorithm OID {arcs:?}: {error:?}")
    })?;
    Ok(x509_parser::prelude::AlgorithmIdentifier::new(oid, None))
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
        all_passed, describe_failures, CertificateSummary, CheckVerdict, EVIDENCE_SCHEMA_VERSION,
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

    /// Map a CMS digest algorithm onto the combined PKCS#1 v1.5 signature
    /// algorithm ARCs.
    fn rsa_pkcs1_arcs_for_digest(digest_oid: &str) -> Option<&'static [u64]> {
        match digest_oid {
            OID_SHA256 => Some(&[1, 2, 840, 113549, 1, 1, 11]),
            OID_SHA384 => Some(&[1, 2, 840, 113549, 1, 1, 12]),
            OID_SHA512 => Some(&[1, 2, 840, 113549, 1, 1, 13]),
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
            // The url crate refuses special schemes (http/https) without a
            // non-empty host at parse time, so a successfully parsed URL of
            // those schemes always carries one. Keep the invariant asserted
            // so a future url-crate regression cannot slip through silently.
            debug_assert!(
                parsed.host_str().is_some_and(|host| !host.is_empty()),
                "url crate invariant broken: special scheme parsed without a host"
            );
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
        #[error(
            "TSA response has content type {content_type:?}, expected application/timestamp-reply"
        )]
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
            let serial = reader
                .read_tagged(budget, der::TAG_INTEGER)?
                .content
                .to_vec();
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

    /// Parse the `seconds` INTEGER of an `Accuracy` SEQUENCE the caller has
    /// already tag-checked ([`der::TAG_SEQUENCE`]).
    fn parse_accuracy_seconds(tlv: &Tlv<'_>, budget: &mut Budget) -> Result<Option<u64>, DerError> {
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
                der::TAG_CTX_0 => Some(SignerId::SubjectKeyIdentifier(
                    signer_id_tlv.content.to_vec(),
                )),
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
            let signature =
                der::decode_octet_string(&reader.read_tagged(budget, der::TAG_OCTET_STRING)?)?
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
            return Ok(build_evidence(
                request,
                tst,
                certificate_der,
                certificate,
                checks,
            ));
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
            // `certificate` is Some only when derived from `certificate_der`,
            // so a parseable certificate implies the DER bytes are present.
            Some(attribute) => {
                let der = certificate_der.expect("certificate implies certificate_der");
                match parse_ess_cert_hash(attribute) {
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
                }
            }
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
                Err(SignatureFailure::Unsupported(reason)) => checks.push(
                    CheckVerdict::not_performed("token_signature_valid", true, reason),
                ),
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

        Ok(build_evidence(
            request,
            tst,
            certificate_der,
            certificate,
            checks,
        ))
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
        let (remaining, algorithm) = AlgorithmIdentifier::from_der(&signer.signature_algorithm_raw)
            .map_err(|error| {
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
        // digestAlgorithm. Map that pair onto the combined PKCS#1 identifier
        // the verification backend understands. RSASSA-PSS is a distinct
        // scheme and is reported as unsupported rather than guessed at.
        let mapped_algorithm = if algorithm.algorithm.to_string() == OID_RSA_ENCRYPTION {
            match rsa_pkcs1_arcs_for_digest(&signer.digest_algorithm) {
                Some(arcs) => Some(
                    super::verification_algorithm_from_arcs(arcs)
                        .map_err(SignatureFailure::Unsupported)?,
                ),
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
        let signer_certificate = certificate.as_ref().and_then(|certificate| {
            certificate_der.map(|der| summarise_certificate(certificate, der))
        });
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
        ///
        /// Only `timeout`/`connect_timeout` are configured on the HTTP
        /// builder; constructing such a client cannot fail unless the TLS
        /// backend itself is unusable (in which case every client in the
        /// process is, and there is no degraded mode worth continuing in).
        pub fn new(config: TsaConfig) -> Result<Self, TimeStampError> {
            let timeout = std::time::Duration::from_secs(config.timeout_secs.max(1));
            let http = reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(timeout)
                .build()
                .expect(
                    "reqwest client construction failed: only timeout/connect_timeout are set, \
                     so this means the TLS backend is unusable — refusing to run with a \
                     degraded HTTP stack",
                );
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
            self.timestamp_at_with_nonce(document, algorithm, now, random_nonce())
                .await
        }

        /// [`TimeStampClient::timestamp_at`] with an explicit nonce, for
        /// deterministic replay audits: a stored token can be re-requested
        /// and re-verified against the exact exchange that produced it.
        pub async fn timestamp_at_with_nonce(
            &self,
            document: &[u8],
            algorithm: HashAlgorithm,
            now: DateTime<Utc>,
            nonce: u64,
        ) -> Result<TimeStampEvidence, TimeStampError> {
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
                            media_type
                                .trim()
                                .eq_ignore_ascii_case(HTTP_CONTENT_TYPE_REPLY)
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

    /// Adversarial unit tests for the module-private parsing and
    /// verification arms. Synthetic CMS tokens are assembled with the DER
    /// writer so every refusal path is reachable without a live TSA.
    #[cfg(test)]
    mod timestamp_tests {
        use super::super::der;
        use super::super::CheckOutcome;
        use super::*;

        // The same certificate the OpenSSL fixture carries (DER, hex) — the
        // unit tests cannot reach the integration fixtures.
        const CERT_HEX: &str = "3082038930820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e29301e170d3236303931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399dd8a1afa71521c6d91b63775378ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd73252218420ef3b6fcd27ee010864862edacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a2bb604ebfce7bd1bd24e30efb99949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9f2369fb513db37a20955e62384892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d482a300d06092a864886f70d01010b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3b497022b04630a1e1e58d8fddea0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee683c0e3ce96ecb5334f04398b6488bbead7c74771ec913e6d927e54261ebb67dc036762683a573b2596436e0f6370f81e0e87070a556ba33e5157388a8a5853840c834a4d53a2d0d40816c99a4b1ca06b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e8de49c4bd43a8585a5af92dd7e4b3730fb785f";

        const DOCUMENT: &[u8] = b"unit-test statutory document bytes";

        fn cert_der() -> Vec<u8> {
            hex::decode(CERT_HEX).expect("certificate hex")
        }

        fn now() -> DateTime<Utc> {
            DateTime::parse_from_rfc3339("2026-09-12T21:19:44Z")
                .expect("clock")
                .with_timezone(&Utc)
        }

        fn request<'a>(document: &'a [u8]) -> TimestampVerificationRequest<'a> {
            TimestampVerificationRequest {
                document,
                nonce: 7,
                algorithm: HashAlgorithm::Sha256,
                tolerance_secs: 300,
                now: now(),
                tsa_url: Some("https://tsa.unit.test/"),
            }
        }

        fn sha256_algorithm() -> Vec<u8> {
            der::algorithm_identifier(OID_SHA256).expect("sha256 algorithm")
        }

        /// Build a `TSTInfo` DER with configurable genTime bytes, accuracy,
        /// ordering flag and nonce.
        fn tst_info(gen_time: &[u8], accuracy: bool, ordering: bool, nonce: bool) -> Vec<u8> {
            let imprint = der::sequence(&[
                sha256_algorithm(),
                der::octet_string(&HashAlgorithm::Sha256.digest(DOCUMENT)),
            ]);
            let mut parts = vec![
                der::unsigned_integer(1),
                der::oid("1.3.6.1.4.1.57264.1.1").expect("policy"),
                imprint,
                der::unsigned_integer_bytes(&[0x02]),
                der::tlv(der::TAG_GENERALIZED_TIME, gen_time),
            ];
            if accuracy {
                parts.push(der::sequence(&[der::unsigned_integer(1)]));
            }
            if ordering {
                parts.push(der::boolean(true));
            }
            if nonce {
                parts.push(der::unsigned_integer(7));
            }
            der::sequence(&parts)
        }

        struct SignerSpec {
            sid: Vec<u8>,
            digest_algorithm: Vec<u8>,
            signed_attributes: Vec<Vec<u8>>,
            signature_algorithm: Vec<u8>,
            signature: Vec<u8>,
        }

        fn attribute(oid: &str, value: Vec<u8>) -> Vec<u8> {
            der::sequence(&[der::oid(oid).expect("attr oid"), der::set(&[value])])
        }

        fn default_signer() -> SignerSpec {
            SignerSpec {
                sid: der::sequence(&[
                    der::sequence(&[der::tlv(0x31, &der::sequence(&[]))]), // Name (garbage shape)
                    der::unsigned_integer_bytes(&[0x02]),
                ]),
                digest_algorithm: sha256_algorithm(),
                signed_attributes: vec![
                    attribute(
                        OID_CONTENT_TYPE_ATTR,
                        der::oid(OID_TST_INFO).expect("contentType"),
                    ),
                    attribute(
                        OID_MESSAGE_DIGEST_ATTR,
                        der::octet_string(&Sha256::digest(tst_info(
                            b"20260912211944Z",
                            false,
                            false,
                            true,
                        ))),
                    ),
                    attribute(
                        OID_SIGNING_CERT_V2_ATTR,
                        ess_signing_certificate(None, Sha256::digest(cert_der()).to_vec()),
                    ),
                ],
                signature_algorithm: der::algorithm_identifier("1.2.840.113549.1.1.11")
                    .expect("sha256WithRSA"),
                signature: der::octet_string(&[0xAA; 32]),
            }
        }

        /// `SigningCertificateV2` attribute value; `hash_algorithm` None uses
        /// the SHA-256 default (no algorithm element).
        fn ess_signing_certificate(hash_algorithm: Option<Vec<u8>>, cert_hash: Vec<u8>) -> Vec<u8> {
            let mut cert_id = Vec::new();
            if let Some(algorithm) = hash_algorithm {
                cert_id.extend_from_slice(&algorithm);
            }
            cert_id.extend_from_slice(&der::octet_string(&cert_hash));
            der::sequence(&[der::sequence(&[der::sequence(&[cert_id])])])
        }

        fn signer_info(spec: &SignerSpec) -> Vec<u8> {
            let mut parts = vec![
                der::unsigned_integer(1),
                spec.sid.clone(),
                spec.digest_algorithm.clone(),
            ];
            if !spec.signed_attributes.is_empty() {
                let mut content = Vec::new();
                for attr in &spec.signed_attributes {
                    content.extend_from_slice(attr);
                }
                parts.push(der::tlv(der::TAG_CTX_0, &content));
            }
            parts.push(spec.signature_algorithm.clone());
            parts.push(spec.signature.clone());
            der::sequence(&parts)
        }

        /// Assemble a full `TimeStampResp` (status granted) around the given
        /// TSTInfo and signer specs.
        fn response(tst: &[u8], signers: &[SignerSpec], certs: bool, crls: bool) -> Vec<u8> {
            let encap = der::sequence(&[
                der::oid(OID_TST_INFO).expect("tstInfo oid"),
                der::tlv(der::TAG_CTX_0, &der::octet_string(tst)),
            ]);
            let mut parts = vec![
                der::unsigned_integer(1),
                der::set(&[sha256_algorithm()]),
                encap,
            ];
            if certs {
                parts.push(der::tlv(der::TAG_CTX_0, &cert_der()));
            }
            if crls {
                parts.push(der::tlv(der::TAG_CTX_1, &[]));
            }
            parts.push(der::set(
                &signers.iter().map(signer_info).collect::<Vec<_>>(),
            ));
            let signed_data = der::sequence(&parts);
            let token = der::sequence(&[
                der::oid(OID_SIGNED_DATA).expect("signedData oid"),
                der::tlv(der::TAG_CTX_0, &signed_data),
            ]);
            der::sequence(&[der::sequence(&[der::unsigned_integer(0)]), token])
        }

        fn verify(bytes: &[u8]) -> Result<TimeStampEvidence, TimeStampError> {
            verify_response(bytes, &request(DOCUMENT))
        }

        fn outcome<'a>(evidence: &'a TimeStampEvidence, check: &str) -> &'a CheckOutcome {
            &evidence
                .checks
                .iter()
                .find(|verdict| verdict.check == check)
                .unwrap_or_else(|| panic!("missing check {check}"))
                .outcome
        }

        #[test]
        fn zz_debug_synthetic_response_parses() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let signer = default_signer();
            let bytes = response(&tst, &[signer], true, false);
            let (status, token) = parse_response(&bytes).expect("parse_response");
            assert_eq!(status.status, 0);
            let token = token.expect("token present");
            let parsed = parse_token(token).expect("parse_token");
            assert_eq!(parsed.tst.nonce, Some(7));
            assert_eq!(parsed.certificates.len(), 1);
            assert_eq!(parsed.signer_infos.len(), 1);
        }

        // ── status classification and rendering ──────────────────────────

        #[test]
        fn rejection_status_names_and_renders_every_status() {
            // Status 0 (granted) with no token is MalformedResponse by
            // contract (verify_response rejects non-granted statuses FIRST);
            // the loop covers every rejection/waiting status.
            for (status, expected) in [
                (1u64, "grantedWithMods"),
                (2, "rejection"),
                (3, "waiting"),
                (4, "revocationWarning"),
                (5, "revocationNotification"),
                (6, "unknown"),
                (99, "unknown"),
            ] {
                let body = der::sequence(&[der::sequence(&[der::unsigned_integer(status)])]);
                let error = verify(&body).expect_err("non-granted must be rejected");
                match error {
                    TimeStampError::Rejected {
                        status: observed,
                        status_name,
                        ..
                    } => {
                        assert_eq!(observed, status);
                        assert_eq!(status_name, expected);
                    }
                    other => panic!("expected Rejected, got {other:?}"),
                }
            }

            // A rejection with status strings AND fail info renders both into
            // the message; one with neither renders bare.
            let with_strings = der::sequence(&[der::sequence(&[
                der::unsigned_integer(2),
                der::sequence(&[der::tlv(der::TAG_UTF8_STRING, b"busy")]),
                der::tlv(der::TAG_BIT_STRING, &[0x00, 0b0010_0000]),
            ])]);
            let message = verify(&with_strings).expect_err("rejection").to_string();
            assert!(message.contains("busy"), "{message}");
            assert!(message.contains("badRequest"), "{message}");
            let bare = der::sequence(&[der::sequence(&[der::unsigned_integer(2)])]);
            let message = verify(&bare).expect_err("rejection").to_string();
            assert!(
                message.contains("status 2 (rejection)") && !message.contains('\u{2014}'),
                "{message}"
            );
        }

        #[test]
        fn granted_response_without_a_token_is_malformed() {
            let body = der::sequence(&[der::sequence(&[der::unsigned_integer(0)])]);
            let error = verify(&body).expect_err("granted status must carry a token");
            match error {
                TimeStampError::MalformedResponse(message) => {
                    assert!(message.contains("no timeStampToken"), "{message}")
                }
                other => panic!("expected MalformedResponse, got {other:?}"),
            }
        }

        // ── TSTInfo optional fields ──────────────────────────────────────

        #[test]
        fn tst_info_ordering_accuracy_and_nonce_all_parse() {
            let tst = tst_info(b"20260912211944Z", true, true, true);
            let signer = SignerSpec {
                signed_attributes: vec![
                    attribute(
                        OID_CONTENT_TYPE_ATTR,
                        der::oid(OID_TST_INFO).expect("contentType"),
                    ),
                    attribute(
                        OID_MESSAGE_DIGEST_ATTR,
                        der::octet_string(&Sha256::digest(&tst)),
                    ),
                ],
                ..default_signer()
            };
            let evidence =
                verify(&response(&tst, &[signer], true, false)).expect("optional fields parse");
            assert!(evidence.ordering, "ordering BOOLEAN observed");
            assert_eq!(evidence.accuracy_seconds, Some(1));
            // The nonce field was present and matched the request.
            assert_eq!(
                outcome(&evidence, "nonce_matches_request"),
                &CheckOutcome::Pass
            );
        }

        #[test]
        fn unparsable_gen_time_fails_only_the_time_checks() {
            let tst = tst_info(b"99999999999999Z", false, false, true);
            let signer = default_signer();
            let evidence = verify(&response(&tst, &[signer], true, false))
                .expect("token parses; genTime failure is a named check");
            assert!(outcome(&evidence, "gen_time_parses").is_fail());
            assert!(outcome(&evidence, "gen_time_within_tolerance").is_not_performed());
            assert_eq!(evidence.gen_time_rfc3339, None);
            assert_eq!(evidence.gen_time_unix, None);
            assert_eq!(evidence.gen_time_raw, "99999999999999Z");
            assert_eq!(
                outcome(&evidence, "imprint_matches_document"),
                &CheckOutcome::Pass
            );
        }

        // ── certificate and signer structure ────────────────────────────

        #[test]
        fn token_without_certificates_fails_the_certificate_check() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let signer = default_signer();
            let evidence = verify(&response(&tst, &[signer], false, false))
                .expect("token without a certificate set parses");
            let failed = outcome(&evidence, "signer_certificate_parses");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("carries no certificates"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            assert!(evidence.signer_certificate.is_none());
            assert!(outcome(&evidence, "token_signature_valid").is_not_performed());
            assert!(outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate"
            )
            .is_not_performed());
        }

        #[test]
        fn token_with_crls_parses_and_a_missing_signer_fails_closed() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            // CRL set present, empty SignerInfo set.
            let evidence = verify(&response(&tst, &[], true, true))
                .expect("token without SignerInfos still produces evidence");
            assert!(outcome(&evidence, "signed_attrs_content_type").is_fail());
            assert!(
                outcome(&evidence, "signed_attrs_message_digest_matches_econtent")
                    .is_not_performed()
            );
            assert!(outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate"
            )
            .is_not_performed());
            assert!(outcome(&evidence, "signer_id_matches_certificate").is_not_performed());
            assert!(outcome(&evidence, "token_signature_valid").is_not_performed());
            assert!(!evidence.all_passed());
        }

        // ── signed attributes ────────────────────────────────────────────

        #[test]
        fn content_type_attribute_is_checked_for_value_and_identity() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            // Wrong OID: signed contentType names something else.
            let mut signer = default_signer();
            signer.signed_attributes[0] = attribute(
                OID_CONTENT_TYPE_ATTR,
                der::oid("1.2.840.113549.1.9.16.1.99").expect("other oid"),
            );
            let evidence = verify(&response(&tst, &[signer], true, false))
                .expect("parses; wrong contentType is a named check");
            let failed = outcome(&evidence, "signed_attrs_content_type");
            match failed {
                CheckOutcome::Fail { detail } => assert!(detail.contains("expected"), "{detail}"),
                other => panic!("expected Fail, got {other:?}"),
            }

            // Wrong value type: an INTEGER where an OID must be.
            let mut signer = default_signer();
            signer.signed_attributes[0] =
                attribute(OID_CONTENT_TYPE_ATTR, der::unsigned_integer(1));
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(&evidence, "signed_attrs_content_type");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("unexpected value type"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Undecodable OID bytes.
            let mut signer = default_signer();
            signer.signed_attributes[0] = attribute(
                OID_CONTENT_TYPE_ATTR,
                der::tlv(der::TAG_OID, &[0x2A, 0x88]), // trailing continuation
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            assert!(outcome(&evidence, "signed_attrs_content_type").is_fail());

            // Missing entirely.
            let mut signer = default_signer();
            signer.signed_attributes.remove(0);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(&evidence, "signed_attrs_content_type");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no contentType"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn message_digest_attribute_type_and_presence_are_checked() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let mut signer = default_signer();
            signer.signed_attributes[1] =
                attribute(OID_MESSAGE_DIGEST_ATTR, der::unsigned_integer(1));
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(&evidence, "signed_attrs_message_digest_matches_econtent");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("unexpected value type"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            let mut signer = default_signer();
            signer.signed_attributes.remove(1);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            assert!(
                outcome(&evidence, "signed_attrs_message_digest_matches_econtent")
                    .is_not_performed()
            );
        }

        #[test]
        fn message_digest_mismatch_names_the_two_digests() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let mut signer = default_signer();
            signer.signed_attributes[1] = attribute(
                OID_MESSAGE_DIGEST_ATTR,
                der::octet_string(&Sha256::digest(b"other content")),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(&evidence, "signed_attrs_message_digest_matches_econtent");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("does not equal"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        // ── ESS signing certificate ──────────────────────────────────────

        #[test]
        fn ess_hash_algorithm_element_is_honoured_when_present() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            // SHA-512 algorithm element with the matching digest: passes.
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                ess_signing_certificate(
                    Some(sha512_algorithm_identifier()),
                    Sha512::digest(cert_der()).to_vec(),
                ),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            assert_eq!(
                outcome(
                    &evidence,
                    "ess_signing_certificate_hash_matches_certificate"
                ),
                &CheckOutcome::Pass,
                "{:?}",
                evidence.failing_checks()
            );

            // Same algorithm, wrong hash: fails naming both values.
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                ess_signing_certificate(
                    Some(sha512_algorithm_identifier()),
                    Sha512::digest(b"other").to_vec(),
                ),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("does not equal"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // SHA-384 is an accepted digest for ESS hashing.
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                ess_signing_certificate(
                    Some(der::algorithm_identifier(OID_SHA384).expect("sha384")),
                    sha384_of(&cert_der()),
                ),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            assert_eq!(
                outcome(
                    &evidence,
                    "ess_signing_certificate_hash_matches_certificate"
                ),
                &CheckOutcome::Pass
            );
        }

        fn sha512_algorithm_identifier() -> Vec<u8> {
            der::algorithm_identifier(OID_SHA512).expect("sha512 algorithm")
        }

        fn sha384_of(data: &[u8]) -> Vec<u8> {
            use sha2::Digest;
            sha2::Sha384::digest(data).to_vec()
        }

        #[test]
        fn ess_unsupported_hash_and_malformed_values_are_reported() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            // SHA-1 hash algorithm: recognised name, refused for hashing.
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                ess_signing_certificate(
                    Some(der::algorithm_identifier("1.3.14.3.2.26").expect("sha1")),
                    vec![0x00; 20],
                ),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate",
            );
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("not supported for hashing"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }

            // Malformed ESS value (no certs sequence inside).
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                der::sequence(&[der::unsigned_integer(1)]),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no certs sequence"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // certHash element is not an OCTET STRING (algorithm absent).
            let mut signer = default_signer();
            signer.signed_attributes[2] = attribute(
                OID_SIGNING_CERT_V2_ATTR,
                der::sequence(&[der::sequence(&[der::sequence(&[der::unsigned_integer(1)])])]),
            );
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("not an OCTET STRING"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // No ESS attribute at all.
            let mut signer = default_signer();
            signer.signed_attributes.truncate(2);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            assert!(outcome(
                &evidence,
                "ess_signing_certificate_hash_matches_certificate"
            )
            .is_not_performed());
        }

        // ── signer identifier ────────────────────────────────────────────

        #[test]
        fn subject_key_identifier_and_unknown_signer_ids_are_not_performed() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let mut signer = default_signer();
            signer.sid = der::tlv(der::TAG_CTX_0, &[0x04, 0x01, 0x02]);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "signer_id_matches_certificate");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("subjectKeyIdentifier"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }

            let mut signer = default_signer();
            signer.sid = der::unsigned_integer(1);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "signer_id_matches_certificate");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("unrecognised"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }
        }

        #[test]
        fn signer_id_mismatch_and_unparsable_issuer_are_reported() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            // IssuerAndSerial with a serial that does NOT match the cert.
            let mut signer = default_signer();
            signer.sid = der::sequence(&[
                der::sequence(&[]), // empty Name: parses, no remaining
                der::unsigned_integer_bytes(&[0x99]),
            ]);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let failed = outcome(&evidence, "signer_id_matches_certificate");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("serial match: false"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Issuer Name that does not re-parse: comparison not performed.
            let mut signer = default_signer();
            // An OCTET STRING where the issuer Name belongs: x509's Name
            // parser refuses it outright (a SEQUENCE-shaped sid still parses
            // as an RDN sequence and merely compares unequal).
            signer.sid = der::sequence(&[
                der::octet_string(b"not a name"),
                der::unsigned_integer_bytes(&cert_serial()),
            ]);
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "signer_id_matches_certificate");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("could not be re-parsed"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }
        }

        fn cert_serial() -> Vec<u8> {
            x509_parser::prelude::X509Certificate::from_der(&cert_der())
                .expect("cert")
                .1
                .raw_serial()
                .to_vec()
        }

        // ── signature algorithm classification ───────────────────────────

        #[test]
        fn pss_and_unmappable_rsa_digests_are_reported_unsupported() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let mut signer = default_signer();
            signer.signature_algorithm =
                der::algorithm_identifier(OID_RSASSA_PSS).expect("PSS algorithm");
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "token_signature_valid");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("RSASSA-PSS"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }

            // rsaEncryption with a SHA-1 digest has no PKCS#1 mapping here.
            let mut signer = default_signer();
            signer.signature_algorithm =
                der::algorithm_identifier(OID_RSA_ENCRYPTION).expect("rsaEncryption");
            signer.digest_algorithm = der::algorithm_identifier("1.3.14.3.2.26").expect("sha1");
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "token_signature_valid");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(
                        reason.contains("no supported PKCS#1 v1.5 mapping"),
                        "{reason}"
                    )
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }
        }

        #[test]
        fn algorithm_identifier_with_inner_trailing_bytes_is_refused() {
            // SEQUENCE { OID sha256WithRSA, NULL, NULL } — the third element
            // is left unconsumed by AlgorithmIdentifier::from_der.
            let raw = der::sequence(&[
                der::oid("1.2.840.113549.1.1.11").expect("oid"),
                der::null(),
                der::null(),
            ]);
            let (remaining, _algorithm) = x509_parser::prelude::AlgorithmIdentifier::from_der(&raw)
                .expect("parses the first two elements");
            if remaining.is_empty() {
                // x509-parser consumes trailing elements; the guard in
                // verify_token_signature then has nothing to fire on and the
                // check is dead — this test pins that knowledge.
                return;
            }
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let mut signer = default_signer();
            signer.signature_algorithm = raw;
            let evidence = verify(&response(&tst, &[signer], true, false)).expect("parses");
            let skipped = outcome(&evidence, "token_signature_valid");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("trailing bytes"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }
        }

        #[test]
        fn verification_algorithm_builder_rejects_impossible_arcs() {
            let error = super::super::verification_algorithm_from_arcs(&[7, 1])
                .expect_err("first arc >= 7");
            assert!(error.contains("could not encode"), "{error}");
            let error = super::super::verification_algorithm_from_arcs(&[1, 40])
                .expect_err("second arc >= 40 under 1.x");
            assert!(error.contains("could not encode"), "{error}");
            let ok = super::super::verification_algorithm_from_arcs(&[1, 2, 840, 113549, 1, 1, 11])
                .expect("sha256WithRSA arcs are valid");
            assert_eq!(
                ok.algorithm.to_string(),
                "1.2.840.113549.1.1.11",
                "the constructed identifier names the mapped algorithm"
            );
        }

        // ── request / status parsing edges ───────────────────────────────

        #[test]
        fn parse_request_refuses_hostile_imprints_and_trailing_elements() {
            // Imprint OCTET STRING replaced by a BOOLEAN.
            let hostile = der::sequence(&[
                der::unsigned_integer(1),
                der::sequence(&[sha256_algorithm(), der::boolean(true)]),
                der::unsigned_integer(7),
            ]);
            assert!(parse_request(&hostile).is_err());

            // Trailing element inside the MessageImprint sequence.
            let hostile = der::sequence(&[
                der::unsigned_integer(1),
                der::sequence(&[
                    sha256_algorithm(),
                    der::octet_string(&[0u8; 32]),
                    der::null(),
                ]),
                der::unsigned_integer(7),
            ]);
            assert!(parse_request(&hostile).is_err());

            // Same shape inside a TSTInfo imprint.
            let hostile = der::sequence(&[
                der::oid("1.3.6.1.4.1.57264.1.1").expect("policy"),
                der::sequence(&[
                    sha256_algorithm(),
                    der::octet_string(&[0u8; 32]),
                    der::null(),
                ]),
                der::unsigned_integer_bytes(&[0x02]),
                der::tlv(der::TAG_GENERALIZED_TIME, b"20260912211944Z"),
            ]);
            let wrapped = der::tlv(der::TAG_CTX_0, &der::octet_string(&hostile));
            let encap = der::sequence(&[der::oid(OID_TST_INFO).expect("tstInfo"), wrapped]);
            let signed_data = der::sequence(&[
                der::unsigned_integer(1),
                der::set(&[sha256_algorithm()]),
                encap,
                der::tlv(der::TAG_CTX_0, &cert_der()),
                der::set(&[signer_info(&default_signer())]),
            ]);
            let token = der::sequence(&[
                der::oid(OID_SIGNED_DATA).expect("signedData"),
                der::tlv(der::TAG_CTX_0, &signed_data),
            ]);
            let body = der::sequence(&[der::sequence(&[der::unsigned_integer(0)]), token]);
            assert!(
                matches!(verify(&body), Err(TimeStampError::MalformedDer(_))),
                "trailing imprint element must be a DER refusal"
            );
        }

        #[test]
        fn status_strings_skip_non_utf8_elements_and_foreign_content_type_is_refused() {
            // statusString carrying a non-UTF8String element is skipped
            // without failing the response.
            let with_printable = der::sequence(&[der::sequence(&[
                der::unsigned_integer(2),
                der::sequence(&[
                    der::tlv(der::TAG_UTF8_STRING, b"hello"),
                    der::tlv(0x13, b"printable"), // PrintableString element
                ]),
                der::tlv(der::TAG_BIT_STRING, &[0x00, 0x80]),
            ])]);
            let error = verify(&with_printable).expect_err("rejection");
            match error {
                TimeStampError::Rejected {
                    status_string,
                    fail_info,
                    ..
                } => {
                    assert_eq!(status_string, vec!["hello".to_string()]);
                    assert_eq!(fail_info, vec!["badAlg".to_string()]);
                }
                other => panic!("expected Rejected, got {other:?}"),
            }

            // A token whose ContentInfo names something other than
            // signedData is refused as malformed.
            let wrong_content = der::sequence(&[
                der::oid("1.2.840.113549.1.7.1").expect("data oid"),
                der::tlv(der::TAG_CTX_0, &der::octet_string(&[])),
            ]);
            let body = der::sequence(&[der::sequence(&[der::unsigned_integer(0)]), wrong_content]);
            let error = verify(&body).expect_err("foreign contentType");
            match error {
                TimeStampError::MalformedResponse(message) => {
                    assert!(message.contains("expected signedData"), "{message}")
                }
                other => panic!("expected MalformedResponse, got {other:?}"),
            }
        }

        #[test]
        fn hash_algorithm_names_and_digests_are_complete() {
            assert_eq!(HashAlgorithm::Sha256.name(), "sha256");
            assert_eq!(HashAlgorithm::Sha512.name(), "sha512");
            assert_eq!(HashAlgorithm::Sha256.oid(), OID_SHA256);
            assert_eq!(HashAlgorithm::Sha512.oid(), OID_SHA512);
            assert_eq!(
                hash_algorithm_from_oid(OID_SHA384),
                None,
                "SHA-384 is token-internal only and not requestable"
            );
            assert_eq!(hash_algorithm_from_oid("1.1.1.1"), None);
            assert_eq!(HashAlgorithm::Sha512.digest(DOCUMENT).len(), 64);
        }

        #[test]
        fn evidence_fields_expose_what_was_parsed() {
            let tst = tst_info(b"20260912211944Z", false, false, true);
            let evidence =
                verify(&response(&tst, &[default_signer()], true, false)).expect("parses");
            assert_eq!(evidence.tst_info_version, 1);
            assert_eq!(evidence.serial_number_hex, "02");
            assert_eq!(evidence.policy_oid, "1.3.6.1.4.1.57264.1.1");
            let certificate = evidence.signer_certificate.as_ref().expect("cert");
            assert!(certificate.not_before.contains("2026"));
            // The signature value is synthetic: it must NOT verify.
            let failed = outcome(&evidence, "token_signature_valid");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("did not verify"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        // ── configuration builders ───────────────────────────────────────

        #[test]
        fn config_builders_override_every_field_and_describe_themselves() {
            let config = TsaConfig::new("https://tsa.example.test/rfc3161")
                .expect("valid")
                .with_tolerance_secs(60)
                .with_timeout_secs(9)
                .with_max_response_bytes(4096)
                .with_auth_header("Authorization", "Bearer secret");
            assert_eq!(config.tolerance_secs, 60);
            assert_eq!(config.timeout_secs, 9);
            assert_eq!(config.max_response_bytes, 4096);
            let auth = config.auth_header.as_ref().expect("auth");
            assert_eq!(auth.name, "Authorization");
            assert_eq!(auth.value, "Bearer secret");
            let described = config.describe();
            assert!(described.contains("tolerance 60s"), "{described}");
            assert!(described.contains("auth configured"), "{described}");
            assert!(!described.contains("secret"), "{described}");
            // The verification request inherits tolerance and URL.
            let request = config.verification_request(DOCUMENT, 5, HashAlgorithm::Sha256, now());
            assert_eq!(request.tolerance_secs, 60);
            assert_eq!(request.tsa_url, Some("https://tsa.example.test/rfc3161"));
        }

        // ── environment matrix (serialized: env is process-global) ───────

        /// Serializes env-mutating tests in this module.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        fn with_env<T>(
            vars: &[(&str, Option<&str>)],
            run: impl FnOnce() -> Result<Option<T>, TimeStampError>,
        ) -> Result<Option<T>, TimeStampError> {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let saved: Vec<(String, Option<String>)> = vars
                .iter()
                .map(|(name, _)| ((*name).to_string(), std::env::var(name).ok()))
                .collect();
            for (name, value) in vars {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            let result = run();
            for (name, value) in &saved {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            result
        }

        #[test]
        fn from_env_reads_every_variable_and_its_failure_modes() {
            // Unset URL: unconfigured.
            let config =
                with_env(&[(ENV_TSA_URL, None)], TsaConfig::from_env).expect("unconfigured");
            assert!(config.is_none());

            // Well-formed everything.
            let config = with_env(
                &[
                    (ENV_TSA_URL, Some("https://tsa.example.test/rfc3161")),
                    (ENV_TSA_AUTH_HEADER, Some("Authorization: Bearer x")),
                    (ENV_TSA_TOLERANCE_SECS, Some("90")),
                    (ENV_TSA_TIMEOUT_SECS, Some("8")),
                    (ENV_TSA_MAX_RESPONSE_BYTES, Some("2048")),
                ],
                TsaConfig::from_env,
            )
            .expect("valid environment")
            .expect("configured");
            assert_eq!(config.tolerance_secs, 90);
            assert_eq!(config.timeout_secs, 8);
            assert_eq!(config.max_response_bytes, 2048);
            let auth = config.auth_header.expect("auth");
            assert_eq!(auth.name, "Authorization");
            assert_eq!(auth.value, "Bearer x");

            // Auth header without a colon.
            let error = with_env(
                &[
                    (ENV_TSA_URL, Some("https://tsa.example.test/")),
                    (ENV_TSA_AUTH_HEADER, Some("no-colon-here")),
                ],
                TsaConfig::from_env,
            )
            .expect_err("malformed auth header");
            match error {
                TimeStampError::InvalidConfig(message) => {
                    assert!(message.contains("'Name: Value'"), "{message}")
                }
                other => panic!("expected InvalidConfig, got {other:?}"),
            }

            // Empty name or value side.
            let error = with_env(
                &[
                    (ENV_TSA_URL, Some("https://tsa.example.test/")),
                    (ENV_TSA_AUTH_HEADER, Some("   : value")),
                ],
                TsaConfig::from_env,
            )
            .expect_err("empty auth name");
            assert!(matches!(error, TimeStampError::InvalidConfig(_)));

            // Non-positive tolerance / timeout / size.
            for (name, value) in [
                (ENV_TSA_TOLERANCE_SECS, "0"),
                (ENV_TSA_TOLERANCE_SECS, "-5"),
                (ENV_TSA_TIMEOUT_SECS, "0"),
                (ENV_TSA_MAX_RESPONSE_BYTES, "0"),
            ] {
                let error = with_env(
                    &[
                        (ENV_TSA_URL, Some("https://tsa.example.test/")),
                        (name, Some(value)),
                    ],
                    TsaConfig::from_env,
                )
                .expect_err("bad numeric override");
                match error {
                    TimeStampError::InvalidConfig(message) => {
                        assert!(message.contains(name), "{name}={value}: {message}")
                    }
                    other => panic!("{name}={value}: expected InvalidConfig, got {other:?}"),
                }
            }

            // Unparseable numbers fall back to the defaults (no error).
            let config = with_env(
                &[
                    (ENV_TSA_URL, Some("https://tsa.example.test/")),
                    (ENV_TSA_TOLERANCE_SECS, Some("soon")),
                ],
                TsaConfig::from_env,
            )
            .expect("garbage numbers are ignored")
            .expect("configured");
            assert_eq!(config.tolerance_secs, DEFAULT_TOLERANCE_SECS);
        }

        #[test]
        fn client_from_env_builds_or_reports_unconfigured() {
            let client = with_env(
                &[
                    (ENV_TSA_URL, Some("https://tsa.example.test/rfc3161")),
                    (ENV_TSA_TIMEOUT_SECS, Some("5")),
                ],
                TimeStampClient::from_env,
            )
            .expect("valid env")
            .expect("client");
            assert_eq!(client.config().url, "https://tsa.example.test/rfc3161");
            assert_eq!(client.config().timeout_secs, 5);

            let none = with_env(&[(ENV_TSA_URL, None)], TimeStampClient::from_env)
                .expect("unconfigured is not an error");
            assert!(none.is_none());

            let outcome = with_env(
                &[(ENV_TSA_URL, Some("ftp://tsa.example.test/"))],
                TimeStampClient::from_env,
            );
            match outcome {
                Err(TimeStampError::InvalidConfig(_)) => {}
                Err(other) => panic!("expected InvalidConfig, got {other:?}"),
                Ok(_) => panic!("ftp scheme must not build a client"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ASiC-E / BDOC containers
// ---------------------------------------------------------------------------

/// ASiC-E / BDOC (ETSI EN 319 162) container verification over unpacked
/// members. See the module docs for proven / not-proven properties.
pub mod container {
    use super::{
        all_passed, has_failures, strictly_passed, CertificateSummary, CheckVerdict,
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
                    "file contains no ds:Signature element in the XML DSig namespace".to_string(),
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
                    detail.push_str(
                        "digest algorithm is not supported (only SHA-256/384/512 are accepted); ",
                    );
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
                expected_digest_hex: expected_digest
                    .as_ref()
                    .map(hex::encode)
                    .unwrap_or_default(),
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
        // `decode_base64_text` never returns an empty Ok (an empty value is
        // an Err), so a decoded SignatureValue always carries bytes.
        match &signature_value_bytes {
            Ok(_) => {
                checks.push(CheckVerdict::pass("signature_value_decodes", true));
            }
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
            // A structurally-missing SignatureMethod is judged BEFORE the
            // certificate gate: the malformation of the signature element is
            // the more informative verdict, and masking it behind
            // NotPerformed would let a malformed signature read as "merely
            // unverifiable".
            (_, _, None) => checks.push(CheckVerdict::fail(
                "signature_value_over_raw_signed_info",
                true,
                "SignedInfo has no SignatureMethod".to_string(),
            )),
            (_, None, _) => checks.push(CheckVerdict::not_performed(
                "signature_value_over_raw_signed_info",
                true,
                "no parseable signing certificate, so no public key is available".to_string(),
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

    fn xmldsig_algorithm_arcs(uri: &str) -> Option<&'static [u64]> {
        match uri {
            URI_RSA_SHA256 => Some(&[1, 2, 840, 113549, 1, 1, 11]),
            URI_RSA_SHA384 => Some(&[1, 2, 840, 113549, 1, 1, 12]),
            URI_RSA_SHA512 => Some(&[1, 2, 840, 113549, 1, 1, 13]),
            URI_RSA_SHA1 => Some(&[1, 2, 840, 113549, 1, 1, 5]),
            URI_ECDSA_SHA256 => Some(&[1, 2, 840, 10045, 4, 3, 2]),
            URI_ECDSA_SHA384 => Some(&[1, 2, 840, 10045, 4, 3, 3]),
            URI_ED25519 => Some(&[1, 3, 101, 112]),
            _ => None,
        }
    }

    fn verify_xmldsig_signature(
        method_uri: &str,
        signed_info_raw: &[u8],
        signature_value: &[u8],
        certificate: &x509_parser::prelude::X509Certificate<'_>,
    ) -> Result<(), SignatureFailure> {
        let arcs = xmldsig_algorithm_arcs(method_uri).ok_or_else(|| {
            SignatureFailure::Unsupported(format!("signature method {method_uri} is not supported"))
        })?;
        // verify_signature reads only the algorithm OID, so the identifier is
        // built directly from the ARCs (see verification_algorithm_from_arcs).
        let algorithm =
            super::verification_algorithm_from_arcs(arcs).map_err(SignatureFailure::Unsupported)?;
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
                    "signature method {method_uri} maps to an algorithm the available verification backend does not support"
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

    fn element_attributes(
        element: &quick_xml::events::BytesStart<'_>,
    ) -> Result<Vec<(String, String)>, String> {
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

    /// Adversarial unit tests for the module-private container arms. The
    /// valid-container round trip lives in tests/signing_tests.rs; here every
    /// refusal and degradation path is driven directly.
    #[cfg(test)]
    mod container_tests {
        use super::super::CheckOutcome;
        use super::*;

        const DOC: &[u8] = b"container unit document";

        fn members(signatures_xml: &str) -> Vec<ContainerMember> {
            vec![
                ContainerMember::new("mimetype", ASIC_E_MIMETYPE.as_bytes().to_vec()),
                ContainerMember::new(
                    "META-INF/signatures.xml",
                    signatures_xml.as_bytes().to_vec(),
                ),
                ContainerMember::new("document.txt", DOC.to_vec()),
            ]
        }

        fn container_check<'a>(evidence: &'a AsicEvidence, id: &str) -> &'a CheckOutcome {
            &evidence
                .container_checks
                .iter()
                .find(|check| check.check == id)
                .unwrap_or_else(|| panic!("missing container check {id}"))
                .outcome
        }

        fn signature_check<'a>(evidence: &'a AsicEvidence, id: &str) -> &'a CheckOutcome {
            &evidence.signatures[0]
                .checks
                .iter()
                .find(|check| check.check == id)
                .unwrap_or_else(|| panic!("missing signature check {id}"))
                .outcome
        }

        fn doc_digest_b64() -> String {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(DOC))
        }

        /// A minimal, valid-shaped signature XML over document.txt.
        fn signature_xml(reference_uri: &str, digest_b64: &str) -> String {
            format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig-1">
  <ds:SignedInfo Id="si-1">
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="{reference_uri}">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>{digest_b64}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AAAA</ds:SignatureValue>
</ds:Signature>"#
            )
        }

        #[test]
        fn duplicate_mimetype_members_fail_the_presence_check() {
            let mut extra = members(&signature_xml("document.txt", &doc_digest_b64()));
            extra.push(ContainerMember::new(
                "mimetype",
                ASIC_E_MIMETYPE.as_bytes().to_vec(),
            ));
            let evidence = verify_asic_e(&extra);
            let failed = container_check(&evidence, "mimetype_member_present");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("2 'mimetype' members"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn too_many_signature_files_fail_the_presence_check() {
            let mut many = vec![
                ContainerMember::new("mimetype", ASIC_E_MIMETYPE.as_bytes().to_vec()),
                ContainerMember::new("document.txt", DOC.to_vec()),
            ];
            for index in 0..=MAX_SIGNATURE_FILES {
                many.push(ContainerMember::new(
                    format!("META-INF/signatures{index}.xml"),
                    signature_xml("document.txt", &doc_digest_b64()).into_bytes(),
                ));
            }
            let evidence = verify_asic_e(&many);
            let failed = container_check(&evidence, "signature_file_present");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("more than the supported"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn oversized_and_non_utf8_signature_files_fail_their_own_checks() {
            let mut oversized = members("");
            oversized[1] = ContainerMember::new(
                "META-INF/signatures.xml",
                vec![b'x'; MAX_SIGNATURES_XML_BYTES + 1],
            );
            let evidence = verify_asic_e(&oversized);
            let failed = container_check(
                &evidence,
                "signatures_xml_size_within_limit[META-INF/signatures.xml]",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("exceeds the"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            let mut binary = members("");
            binary[1] = ContainerMember::new("META-INF/signatures.xml", vec![0xFF, 0xFE, 0x00]);
            let evidence = verify_asic_e(&binary);
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("not UTF-8"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn signature_file_naming_accepts_numbered_and_rejects_other_suffixes() {
            // signatures1.xml is a signature file; the covered member must be
            // counted; a different suffix is not.
            let xml = signature_xml("document.txt", &doc_digest_b64());
            let mut container = vec![
                ContainerMember::new("mimetype", ASIC_E_MIMETYPE.as_bytes().to_vec()),
                ContainerMember::new("META-INF/signatures1.xml", xml.clone().into_bytes()),
                ContainerMember::new("META-INF/signatures.json", xml.into_bytes()),
                ContainerMember::new("document.txt", DOC.to_vec()),
            ];
            let evidence = verify_asic_e(&container);
            assert!(container_check(&evidence, "signature_file_present").is_pass());
            assert_eq!(evidence.signatures.len(), 1, "only signatures1.xml counts");
            assert!(evidence.signatures[0]
                .references
                .iter()
                .any(|reference| reference.uri == "document.txt"));
            container.retain(|member| member.path != "META-INF/signatures1.xml");
            let evidence = verify_asic_e(&container);
            assert!(container_check(&evidence, "signature_file_present").is_fail());
        }

        #[test]
        fn more_than_thirty_two_signatures_hit_the_count_limit() {
            let mut one_signature = String::new();
            for index in 0..(MAX_SIGNATURES + 1) {
                one_signature.push_str(&format!(
                    r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="x"/><ds:SignatureMethod Algorithm="x"/><ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#,
                    doc_digest_b64()
                ));
                let _ = index;
            }
            let evidence = verify_asic_e(&members(&one_signature));
            assert_eq!(evidence.signatures.len(), MAX_SIGNATURES);
            let failed = container_check(&evidence, "signature_count_within_limit");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(
                        detail.contains(&format!("more than {MAX_SIGNATURES} signatures")),
                        "{detail}"
                    )
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn missing_signed_info_fails_only_that_signature() {
            let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
            let evidence = verify_asic_e(&members(xml));
            let failed = signature_check(&evidence, "signed_info_present");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no ds:SignedInfo"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            // The early return leaves no further signature checks.
            assert!(evidence.signatures[0]
                .checks
                .iter()
                .all(|check| check.check != "references_verified"));
        }

        #[test]
        fn missing_canonicalization_method_fails_its_check() {
            let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
            let evidence = verify_asic_e(&members(xml));
            let failed = signature_check(&evidence, "canonicalization_method_declared");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no CanonicalizationMethod"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn references_without_elements_transforms_digests_and_same_document_cases() {
            // No Reference elements at all.
            let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="c14n"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
            let evidence = verify_asic_e(&members(xml));
            let failed = signature_check(&evidence, "references_verified");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no Reference elements"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Transforms declared: recorded in the detail, digest still
            // verified over the member bytes.
            let xml = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="c14n"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="document.txt"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#,
                doc_digest_b64()
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(reference.ok, "{:?}", reference.detail);
            assert!(
                reference.detail.contains("transforms declared"),
                "{:?}",
                reference.detail
            );

            // Unsupported digest algorithm.
            let xml = signature_xml_ref(
                "document.txt",
                doc_digest_b64(),
                "http://www.w3.org/2001/04/xmlenc#md5",
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(!reference.ok);
            assert!(
                reference
                    .detail
                    .contains("digest algorithm is not supported"),
                "{:?}",
                reference.detail
            );

            // SHA-1 is recognised but refused for hashing.
            let xml = signature_xml_ref(
                "document.txt",
                "AAAA",
                "http://www.w3.org/2000/09/xmldsig#sha1",
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(!reference.ok);
            assert!(
                reference.detail.contains("digest algorithm unsupported"),
                "{:?}",
                reference.detail
            );

            // SHA-384 / SHA-512 digests verify.
            use base64::Engine as _;
            for (uri, digest) in [
                (
                    "http://www.w3.org/2001/04/xmldsig-more#sha384",
                    Sha384::digest(DOC).to_vec(),
                ),
                (
                    "http://www.w3.org/2001/04/xmlenc#sha512",
                    Sha512::digest(DOC).to_vec(),
                ),
            ] {
                let xml = signature_xml_ref(
                    "document.txt",
                    base64::engine::general_purpose::STANDARD.encode(digest),
                    uri,
                );
                let evidence = verify_asic_e(&members(&xml));
                let reference = &evidence.signatures[0].references[0];
                assert!(reference.ok, "{uri}: {:?}", reference.detail);
            }

            // Undecodable base64 DigestValue.
            let xml = signature_xml_ref(
                "document.txt",
                "!!!not-base64!!!",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(!reference.ok);
            assert!(
                reference.detail.contains("not decodable base64"),
                "{:?}",
                reference.detail
            );

            // Same-document reference whose Id does not exist.
            let xml = signature_xml_ref(
                "#no-such-id",
                doc_digest_b64(),
                "http://www.w3.org/2001/04/xmlenc#sha256",
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(!reference.ok);
            assert!(
                reference.detail.contains("no element with Id="),
                "{:?}",
                reference.detail
            );

            // Same-document digest mismatch is reported as inconclusive.
            let xml = signature_xml_ref(
                "#si-1",
                doc_digest_b64(), // wrong digest for the SignedInfo octets
                "http://www.w3.org/2001/04/xmlenc#sha256",
            );
            let evidence = verify_asic_e(&members(&xml));
            let reference = &evidence.signatures[0].references[0];
            assert!(!reference.ok);
            assert!(
                reference.detail.contains("inconclusive without C14N"),
                "{:?}",
                reference.detail
            );
        }

        fn signature_xml_ref(uri: &str, digest_b64: impl AsRef<str>, digest_uri: &str) -> String {
            let digest_b64 = digest_b64.as_ref();
            format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig-1"><ds:SignedInfo Id="si-1"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="{digest_uri}"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#
            )
        }

        #[test]
        fn certificate_and_signature_value_degradation_paths() {
            let good = signature_xml("document.txt", &doc_digest_b64());

            // No KeyInfo at all.
            let no_cert = good.replace(
                "<ds:SignatureValue>AAAA</ds:SignatureValue>",
                "<ds:SignatureValue>AAAA</ds:SignatureValue><ds:Object/>",
            );
            let evidence = verify_asic_e(&members(&no_cert));
            let failed = signature_check(&evidence, "signer_certificate_present");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no ds:X509Certificate"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            assert!(signature_check(&evidence, "signer_certificate_parses").is_not_performed());
            assert!(
                signature_check(&evidence, "signature_value_over_raw_signed_info")
                    .is_not_performed()
            );

            // Certificate bytes that are not X.509.
            let bad_cert = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo Id="si"><ds:CanonicalizationMethod Algorithm="c"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
                doc_digest_b64()
            );
            let evidence = verify_asic_e(&members(&bad_cert));
            let failed = signature_check(&evidence, "signer_certificate_parses");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("not a parseable X.509"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            assert!(
                signature_check(&evidence, "signature_value_over_raw_signed_info")
                    .is_not_performed()
            );

            // Empty SignatureValue (missing element).
            let missing_value = good.replace("<ds:SignatureValue>AAAA</ds:SignatureValue>", "");
            let evidence = verify_asic_e(&members(&missing_value));
            let failed = signature_check(&evidence, "signature_value_decodes");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("not decodable base64"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
            assert!(
                signature_check(&evidence, "signature_value_over_raw_signed_info")
                    .is_not_performed()
            );

            // No SignatureMethod: a hard failure, not a skip.
            let no_method = good.replace(
                r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#,
                "",
            );
            let evidence = verify_asic_e(&members(&no_method));
            let failed = signature_check(&evidence, "signature_value_over_raw_signed_info");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("no SignatureMethod"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Unsupported signature method URI (HMAC): not performed — but
            // only judged once a parseable certificate exists, so the
            // variant carries KeyInfo (the bare template has none, and the
            // certificate gate would otherwise mask the method verdict).
            let cert_b64 = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(fixture_cert_der())
            };
            let with_cert = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
                doc_digest_b64()
            );
            let hmac = with_cert.replace(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
            );
            let evidence = verify_asic_e(&members(&hmac));
            let skipped = signature_check(&evidence, "signature_value_over_raw_signed_info");
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("not supported"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }
        }

        #[test]
        fn xades_certificate_digest_paths() {
            let cert_b64 = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(fixture_cert_der())
            };
            let good_digest = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(fixture_cert_der()))
            };
            let template = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="c14n"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:SignedProperties><xades:SignedSignatureProperties><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{{digest_uri}}"/><ds:DigestValue>{{digest_b64}}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>"#,
                doc_digest_b64()
            );

            // Matching digest passes.
            let xml = template
                .replace("{digest_uri}", "http://www.w3.org/2001/04/xmlenc#sha256")
                .replace("{digest_b64}", &good_digest);
            let evidence = verify_asic_e(&members(&xml));
            assert_eq!(
                signature_check(
                    &evidence,
                    "signing_certificate_digest_matches_signer_certificate"
                ),
                &CheckOutcome::Pass
            );

            // Mismatching digest fails naming both values.
            let xml = template
                .replace("{digest_uri}", "http://www.w3.org/2001/04/xmlenc#sha256")
                .replace("{digest_b64}", &{
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"other"))
                });
            let evidence = verify_asic_e(&members(&xml));
            let failed = signature_check(
                &evidence,
                "signing_certificate_digest_matches_signer_certificate",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("does not equal"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Unsupported digest algorithm: not performed.
            let xml = template
                .replace("{digest_uri}", "http://www.w3.org/2000/09/xmldsig#sha1")
                .replace("{digest_b64}", "AAAA");
            let evidence = verify_asic_e(&members(&xml));
            let skipped = signature_check(
                &evidence,
                "signing_certificate_digest_matches_signer_certificate",
            );
            match skipped {
                CheckOutcome::NotPerformed { reason } => {
                    assert!(reason.contains("not supported"), "{reason}")
                }
                other => panic!("expected NotPerformed, got {other:?}"),
            }

            // Undecodable CertDigest base64.
            let xml = template
                .replace("{digest_uri}", "http://www.w3.org/2001/04/xmlenc#sha256")
                .replace("{digest_b64}", "!!!not-base64!!!");
            let evidence = verify_asic_e(&members(&xml));
            let failed = signature_check(
                &evidence,
                "signing_certificate_digest_matches_signer_certificate",
            );
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("not decodable base64"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // No XAdES block at all: not performed.
            let xml = template.split("<ds:Object>").next().unwrap().to_string() + "</ds:Signature>";
            let evidence = verify_asic_e(&members(&xml));
            assert!(signature_check(
                &evidence,
                "signing_certificate_digest_matches_signer_certificate"
            )
            .is_not_performed());
        }

        /// The genuine fixture TSA certificate (same DER the integration
        /// fixture carries), decoded from hex.
        fn fixture_cert_der() -> Vec<u8> {
            static CERT_HEX: &str = "3082038930820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e29301e170d3236303931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399dd8a1afa71521c6d91b63775378ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd73252218420ef3b6fcd27ee010864862edacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a2bb604ebfce7bd1bd24e30efb99949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9f2369fb513db37a20955e62384892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d482a300d06092a864886f70d01010b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3b497022b04630a1e1e58d8fddea0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee683c0e3ce96ecb5334f04398b6488bbead7c74771ec913e6d927e54261ebb67dc036762683a573b2596436e0f6370f81e0e87070a556ba33e5157388a8a5853840c834a4d53a2d0d40816c99a4b1ca06b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e8de49c4bd43a8585a5af92dd7e4b3730fb785f";
            hex::decode(CERT_HEX).expect("fixture certificate hex")
        }

        #[test]
        fn failing_checks_and_evidence_helpers_report_every_problem() {
            let evidence = verify_asic_e(&[ContainerMember::new("document.txt", DOC.to_vec())]);
            assert!(evidence.has_failures());
            let lines = evidence.failing_checks();
            assert!(
                lines
                    .iter()
                    .any(|line| line.starts_with("container:mimetype_member_present")),
                "{lines:?}"
            );
            // A container with a bad reference reports through the reference
            // branch too.
            let xml = signature_xml("document.txt", "AAAA");
            let evidence = verify_asic_e(&members(&xml));
            assert!(evidence.has_failures());
            assert!(!evidence.all_passed());
            assert!(!evidence.strictly_passed());
            let lines = evidence.failing_checks();
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("signature[0]:reference[document.txt]")),
                "{lines:?}"
            );
            let signature_line = lines
                .iter()
                .find(|line| line.starts_with("signature[0]:"))
                .expect("signature check line");
            assert!(signature_line.contains(':'), "{lines:?}");
        }

        #[test]
        fn member_uri_resolution_refuses_fragments_traversal_and_bad_escapes() {
            let pool = vec![ContainerMember::new("a/b.txt", DOC.to_vec())];
            assert!(resolve_member_uri(&pool, "#fragment").is_none());
            assert!(resolve_member_uri(&pool, "a/b.txt").is_some());
            assert!(resolve_member_uri(&pool, "./a/b.txt").is_some());
            assert!(
                resolve_member_uri(&pool, "a%2Fb.txt").is_some(),
                "decoded path"
            );
            assert!(
                resolve_member_uri(&pool, "a%2Gb.txt").is_none(),
                "bad escape"
            );
            assert!(
                resolve_member_uri(&pool, "a%2").is_none(),
                "truncated escape"
            );
            assert!(resolve_member_uri(&pool, "a%2E%2E/b").is_none());
            assert!(
                resolve_member_uri(&pool, "FTP://host/x").is_none(),
                "scheme case-insensitive"
            );
            assert!(
                resolve_member_uri(&pool, "a\\b").is_none(),
                "backslash refused"
            );
            assert!(resolve_member_uri(&pool, "a\x00b").is_none(), "NUL refused");
            assert!(
                resolve_member_uri(&pool, "a//b.txt").is_none(),
                "empty segment"
            );
        }

        #[test]
        fn nested_signatures_are_not_descended_into_for_outer_references() {
            // The outer Signature's SignedInfo search must not return the
            // NESTED Signature's SignedInfo.
            let xml = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="c14n"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="document.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue><ds:Object><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="inner-c14n"/><ds:SignatureMethod Algorithm="inner-method"/><ds:Reference URI="nested.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BBBB</ds:SignatureValue></ds:Signature></ds:Object></ds:Signature>"#,
                doc_digest_b64()
            );
            let evidence = verify_asic_e(&members(&xml));
            // collect_signature_nodes finds only the outer signature...
            assert_eq!(evidence.signatures.len(), 1);
            // ...and its method is the OUTER one, proving the nested
            // SignedInfo was skipped during descent.
            assert_eq!(
                evidence.signatures[0].signature_method.as_deref(),
                Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            );
            // The outer reference resolved (nested.txt was never resolved).
            let uris: Vec<&str> = evidence.signatures[0]
                .references
                .iter()
                .map(|reference| reference.uri.as_str())
                .collect();
            assert_eq!(uris, vec!["document.txt"]);
        }

        #[test]
        fn xml_parser_enforces_its_resource_limits() {
            // Depth: 65 levels of nesting.
            let mut deep = String::from("<r>");
            for _ in 0..(MAX_XML_DEPTH + 2) {
                deep.push_str("<e>");
            }
            for _ in 0..(MAX_XML_DEPTH + 2) {
                deep.push_str("</e>");
            }
            deep.push_str("</r>");
            let evidence = verify_asic_e(&members(&deep));
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("depth limit"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Unclosed element at EOF.
            let unclosed = "<r><e></r>".to_string();
            let evidence = verify_asic_e(&members(&unclosed));
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            assert!(failed.is_fail(), "{failed:?}");

            // Event flood: more than MAX_XML_EVENTS events.
            // A self-closing element is ONE event: the flood must exceed
            // MAX_XML_EVENTS elements, not half of it.
            let mut flood = String::with_capacity(MAX_XML_EVENTS * 5 + 32);
            flood.push_str("<r>");
            for _ in 0..(MAX_XML_EVENTS + 8) {
                flood.push_str("<e/>");
            }
            flood.push_str("</r>");
            let evidence = verify_asic_e(&members(&flood));
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("event limit"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // Attribute flood: more than MAX_XML_ATTRIBUTES on one element.
            let mut many_attrs = String::from("<r");
            for index in 0..(MAX_XML_ATTRIBUTES + 2) {
                many_attrs.push_str(&format!(" a{index}=\"v\""));
            }
            many_attrs.push_str("/>");
            let evidence = verify_asic_e(&members(&many_attrs));
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("attribute limit"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }

        #[test]
        fn xml_text_and_cdata_limits_apply() {
            // Text content beyond MAX_XML_TEXT_TOTAL.
            let mut big_text = String::with_capacity(MAX_XML_TEXT_TOTAL + 64);
            big_text.push_str("<r>");
            for _ in 0..(MAX_XML_TEXT_TOTAL / 64 + 4) {
                for _ in 0..64 {
                    big_text.push('x');
                }
            }
            big_text.push_str("</r>");
            let evidence = verify_asic_e(&members(&big_text));
            let failed =
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]");
            match failed {
                CheckOutcome::Fail { detail } => {
                    assert!(detail.contains("text limit"), "{detail}")
                }
                other => panic!("expected Fail, got {other:?}"),
            }

            // CDATA sections count toward the same budget and are accepted
            // when within it.
            let cdata = "<r><![CDATA[hello cdata]]></r>".to_string();
            let evidence = verify_asic_e(&members(&cdata));
            assert!(
                container_check(&evidence, "signatures_xml_parses[META-INF/signatures.xml]")
                    .is_pass()
            );
            // Signature XML with no signature element fails signature_present.
            assert!(
                container_check(&evidence, "signature_present[META-INF/signatures.xml]").is_fail()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Adversarial unit tests (module-private arms that integration tests cannot
// reach; the transport/HTTP arms live in tests/signing_tests.rs)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod signing_unit_tests {
    use super::der::{self, Budget, DerError, Limits, Reader};
    use super::{all_passed, describe_failures, has_failures, strictly_passed, CheckVerdict};

    fn parse_one(bytes: Vec<u8>) -> der::Tlv<'static> {
        // Test-only: the element is leaked so every call site can pass a
        // freshly built buffer without a binding.
        let bytes = Box::leak(bytes.into_boxed_slice());
        let mut budget = Budget::default();
        let mut reader = Reader::new(bytes);
        let tlv = reader.read(&mut budget).expect("one TLV");
        assert!(reader.is_empty(), "expected exactly one TLV");
        tlv
    }

    // ── check-summary helpers ───────────────────────────────────────────

    #[test]
    fn describe_failures_names_every_non_passing_check() {
        let pass = CheckVerdict::pass("ok", true);
        let fail = CheckVerdict::fail("boom", true, "exploded");
        let skipped = CheckVerdict::not_performed("later", false, "unsupported");
        assert_eq!(
            describe_failures(std::slice::from_ref(&pass)),
            "no failures",
            "an all-pass list has nothing to report"
        );
        assert_eq!(
            describe_failures(&[pass, fail, skipped]),
            "boom failed (exploded); later not performed (unsupported)"
        );
        // The aggregate gates stay consistent with the outcomes.
        assert!(all_passed(&[CheckVerdict::pass("x", true)]));
        assert!(!has_failures(&[CheckVerdict::not_performed(
            "y", true, "why"
        )]));
        assert!(has_failures(&[CheckVerdict::fail("z", false, "d")]));
        assert!(!strictly_passed(&[]));
    }

    // ── DER budget / cursor / TLV surface ───────────────────────────────

    #[test]
    fn budget_and_cursor_report_their_state() {
        let limits = Limits {
            max_depth: 3,
            max_elements: 5,
            max_element_bytes: 64,
        };
        let mut budget = Budget::new(limits);
        assert_eq!(budget.limits(), limits);
        assert_eq!(budget.elements_read(), 0);
        let blob = der::sequence(&[der::null()]);
        let mut reader = Reader::new(&blob);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), blob.as_slice());
        assert_eq!(reader.peek_tag(), Some(der::TAG_SEQUENCE));
        let top = reader.read(&mut budget).expect("read");
        assert_eq!(budget.elements_read(), 1);
        assert!(top.is_tag(der::TAG_SEQUENCE));
        assert!(!top.is_tag(der::TAG_NULL));
        assert!(reader.is_empty());
        assert_eq!(reader.remaining(), b"".as_slice());
        assert_eq!(reader.position(), blob.len());
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn decode_u64_rejects_wrong_tag_empty_and_oversized() {
        let wrong_tag = parse_one(der::tlv(der::TAG_NULL, &[]));
        assert_eq!(
            der::decode_u64(&wrong_tag),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_INTEGER,
                actual: der::TAG_NULL,
            })
        );
        let empty = parse_one(der::tlv(der::TAG_INTEGER, &[]));
        assert_eq!(der::decode_u64(&empty), Err(DerError::InvalidInteger));
        // More than 8 significant bytes does not fit in u64.
        let huge = parse_one(der::tlv(der::TAG_INTEGER, &[0x01; 9]));
        assert_eq!(der::decode_u64(&huge), Err(DerError::IntegerOverflow));
        // Leading zeros are not significant: a 9-byte encoding whose eight
        // leading zeros leave exactly one significant byte still decodes...
        let padded = parse_one(vec![0x02, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        assert_eq!(der::decode_u64(&padded), Ok(1));
        // ...and the mis-ordered variant really is 2^56 (the significant
        // byte's position is what matters, not the zero count alone).
        let shifted = parse_one(vec![0x02, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(der::decode_u64(&shifted), Ok(1_u64 << 56));
    }

    #[test]
    fn decode_bool_is_strict() {
        let wrong_tag = parse_one(der::tlv(der::TAG_NULL, &[]));
        assert_eq!(
            der::decode_bool(&wrong_tag),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_BOOLEAN,
                actual: der::TAG_NULL,
            })
        );
        let neither = parse_one(der::tlv(der::TAG_BOOLEAN, &[0x01]));
        assert_eq!(der::decode_bool(&neither), Err(DerError::InvalidBoolean));
        assert_eq!(der::decode_bool(&parse_one(der::boolean(false))), Ok(false));
        assert_eq!(der::decode_bool(&parse_one(der::boolean(true))), Ok(true));
    }

    #[test]
    fn decode_oid_rejects_hostile_content() {
        let wrong_tag = parse_one(der::tlv(der::TAG_NULL, &[]));
        assert_eq!(
            der::decode_oid(&wrong_tag),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_OID,
                actual: der::TAG_NULL,
            })
        );
        assert_eq!(
            der::decode_oid(&parse_one(der::tlv(der::TAG_OID, &[]))),
            Err(DerError::InvalidOid)
        );
        // First arc 0 keeps small second arcs in arc 0.
        assert_eq!(
            der::decode_oid(&parse_one(der::tlv(der::TAG_OID, &[0x01]))),
            Ok("0.1".to_string())
        );
        // 129 arcs exceed the cap.
        let mut many = vec![0x2A_u8]; // 1.2
        for arc in 0..130u64 {
            let mut encoded = Vec::new();
            let mut value = arc;
            loop {
                let byte = (value & 0x7F) as u8;
                value >>= 7;
                if value == 0 {
                    encoded.insert(0, byte);
                    break;
                }
                encoded.insert(0, byte | 0x80);
            }
            many.extend_from_slice(&encoded);
        }
        assert_eq!(
            der::decode_oid(&parse_one(der::tlv(der::TAG_OID, &many))),
            Err(DerError::InvalidOid)
        );
        // A trailing continuation byte never terminates the final arc.
        assert_eq!(
            der::decode_oid(&parse_one(der::tlv(der::TAG_OID, &[0x2A, 0x88]))),
            Err(DerError::InvalidOid)
        );
        // A single arc byte overflowing u64 is refused before it wraps.
        let overflow = [0x80_u8; 10];
        assert_eq!(
            der::decode_oid(&parse_one(der::tlv(der::TAG_OID, &overflow))),
            Err(DerError::InvalidOid)
        );
    }

    #[test]
    fn oid_encoding_rejects_nonsense_arcs() {
        let mut dotted = "1.2".to_string();
        for arc in 0..130 {
            dotted.push_str(&format!(".{arc}"));
        }
        assert_eq!(der::oid(&dotted), Err(DerError::InvalidOid));
        assert_eq!(
            der::oid("2.99999999999999999999"),
            Err(DerError::InvalidOid)
        );
    }

    #[test]
    fn generalized_time_rejects_wrong_tag_bad_offsets_and_empty_fractions() {
        let wrong_tag = parse_one(der::tlv(der::TAG_UTC_TIME, b"260912211944Z"));
        assert_eq!(
            der::decode_generalized_time(&wrong_tag),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_GENERALIZED_TIME,
                actual: der::TAG_UTC_TIME,
            })
        );
        for bad in [
            &b"20260912211944.Z"[..],
            &b"20260912211944+9900"[..],
            &b"20260912211944-0060"[..],
        ] {
            let tlv = parse_one(der::tlv(der::TAG_GENERALIZED_TIME, bad));
            assert!(
                matches!(
                    der::decode_generalized_time(&tlv),
                    Err(DerError::InvalidTime(_))
                ),
                "accepted {bad:?}"
            );
        }
        // A negative offset with sane numbers parses and converts.
        let offset = parse_one(der::tlv(der::TAG_GENERALIZED_TIME, b"20260912211944-0130"));
        let parsed = der::decode_generalized_time(&offset).expect("offset form");
        assert_eq!(parsed.to_rfc3339(), "2026-09-12T22:49:44+00:00");
    }

    #[test]
    fn octet_and_bit_string_decoding_is_tag_strict() {
        assert_eq!(
            der::decode_octet_string(&parse_one(der::null())),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_OCTET_STRING,
                actual: der::TAG_NULL,
            })
        );
        assert_eq!(
            der::decode_bit_string(&parse_one(der::null())),
            Err(DerError::UnexpectedTag {
                expected: der::TAG_BIT_STRING,
                actual: der::TAG_NULL,
            })
        );
        for hostile in [
            vec![der::TAG_BIT_STRING, 0x00],       // no unused-bits byte
            vec![der::TAG_BIT_STRING, 0x01, 0x08], // impossible unused count
            vec![der::TAG_BIT_STRING, 0x01, 0x01], // unused bits, no data
        ] {
            let tlv = parse_one(hostile);
            assert_eq!(
                der::decode_bit_string(&tlv),
                Err(DerError::InvalidBitString)
            );
        }
        let good_bytes = der::tlv(der::TAG_BIT_STRING, &[0x00, 0xFF]);
        let good = parse_one(good_bytes);
        assert_eq!(der::decode_bit_string(&good), Ok(&[0xFF_u8][..]));
    }

    #[test]
    fn writers_round_trip_set_zero_and_parameterless_algorithms() {
        // SET writer + concat.
        let set = der::set(&[der::unsigned_integer(1), der::unsigned_integer(2)]);
        let tlv = parse_one(set);
        assert!(tlv.is_tag(der::TAG_SET));
        let mut inner = tlv.reader();
        let mut budget = Budget::default();
        assert_eq!(
            der::decode_u64(&inner.read(&mut budget).expect("first")),
            Ok(1)
        );
        assert_eq!(
            der::decode_u64(&inner.read(&mut budget).expect("second")),
            Ok(2)
        );

        // All-zero magnitude encodes as INTEGER 0.
        assert_eq!(
            der::unsigned_integer_bytes(&[0x00, 0x00]),
            vec![0x02, 0x01, 0x00]
        );
        assert_eq!(der::unsigned_integer(0), vec![0x02, 0x01, 0x00]);
        // A high-bit magnitude gains the padding zero.
        assert_eq!(
            der::unsigned_integer_bytes(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );

        // EC/Ed25519-style AlgorithmIdentifier carries no parameters.
        let encoded = der::algorithm_identifier_without_parameters("1.3.101.112").expect("encode");
        let tlv = parse_one(encoded);
        let mut inner = tlv.reader();
        let mut budget = Budget::default();
        let oid = der::decode_oid(&inner.read_tagged(&mut budget, der::TAG_OID).expect("oid"))
            .expect("decode");
        assert_eq!(oid, "1.3.101.112");
        assert!(inner.is_empty(), "no parameters element");

        // RSA-style carries an explicit NULL.
        let rsa = der::algorithm_identifier("1.2.840.113549.1.1.11").expect("encode");
        assert!(rsa.windows(2).any(|window| window == [0x05, 0x00]));
    }
}
