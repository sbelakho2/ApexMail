//! Taxonomy-driven XBRL 2.1: a loader for a configured taxonomy package, the
//! fact/context/unit model, and validation of instances against the loaded
//! taxonomy.
//!
//! # Why this module exists
//!
//! XBRL is not self-describing: the meaning of every fact lives in a taxonomy
//! (an entry-point schema plus its presentation/label/calculation linkbases).
//! This repository vendors no Estonian e-aruande taxonomy (the registrar's
//! package is not reachable from the build environment), so correctness must
//! come from a CONFIGURED taxonomy and never from element names invented in
//! code:
//!
//! * [`load_taxonomy`] loads an entry point from a configured source
//!   (filesystem path or URI) and follows `xs:import` / `xs:include` /
//!   `link:linkbaseRef` references relative to the referring document, so a
//!   multi-file package loads as a whole;
//! * [`instance::validate_instance`] refuses facts whose concept the taxonomy
//!   does not declare, whose context does not match the concept's period type,
//!   whose unit/decimals rules are violated, and reports calculation-linkbase
//!   inconsistencies with the concepts and amounts involved;
//! * the ApexMail extension namespace stays reserved for facts the configured
//!   taxonomy has no concept for; those facts are declared in an extension
//!   schema the emitter writes alongside the instance, so every extension
//!   element is visibly an extension and the instance is self-describing.
//!
//! Bounds ([`TaxonomyLimits`]) cap the number of documents, the import depth
//! and the bytes read, so a hostile or enormous taxonomy is refused quickly
//! with a typed error instead of hanging the process. Cycles and missing
//! imports are typed errors ([`TaxonomyError::ImportCycle`],
//! [`TaxonomyError::MissingImport`]), never panics.
//!
//! # What is deliberately NOT done here
//!
//! * No network fetching: the default resolver reads the filesystem and
//!   refuses remote locations with a typed error. A caller that wants URL
//!   entry points injects its own [`TaxonomyResolver`] (see
//!   [`load_taxonomy_with`]) — the loader and the reference resolution are the
//!   same either way.
//! * No guess about the official Estonian package: the entry point, the
//!   concept binding and the extension namespace are all configuration input.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod instance;

pub use instance::{
    declared_concept, numeric_kind_of, parse_instance, validate_instance, Context, ContextPeriod,
    Decimals, ExtensionSchema, Fact, FactValue, InstanceDocument, InstanceError, Unit,
    ValidationFailure, XbrlReadiness, FAIL_ABSTRACT_CONCEPT, FAIL_BINDING_INVALID,
    FAIL_BINDING_MISSING, FAIL_CALCULATION_MISMATCH, FAIL_CALCULATION_OVERFLOW,
    FAIL_CONCEPT_NOT_ITEM, FAIL_CONCEPT_UNDECLARED, FAIL_CONTEXT_PERIOD_INVALID,
    FAIL_DUPLICATE_CONTEXT, FAIL_DUPLICATE_FACT, FAIL_DUPLICATE_UNIT, FAIL_EMPTY_CONTEXT_ID,
    FAIL_MISSING_CONTEXT_PERIOD, FAIL_MISSING_DECIMALS, FAIL_MISSING_ENTITY_IDENTIFIER,
    FAIL_MISSING_ENTITY_SCHEME, FAIL_MISSING_PERIOD_TYPE, FAIL_MISSING_UNIT,
    FAIL_MISSING_UNIT_MEASURE, FAIL_NON_NUMERIC_VALUE, FAIL_PERIOD_TYPE_MISMATCH,
    FAIL_UNEXPECTED_DECIMALS, FAIL_UNEXPECTED_UNIT, FAIL_UNKNOWN_CONTEXT, FAIL_UNKNOWN_UNIT,
};

// ---------------------------------------------------------------------------
// Standard namespaces, arc roles and roles
// ---------------------------------------------------------------------------

/// XML Schema namespace.
pub const XSD_NAMESPACE: &str = "http://www.w3.org/2001/XMLSchema";
/// XBRL 2.1 instance namespace.
pub const XBRL_INSTANCE_NAMESPACE: &str = "http://www.xbrl.org/2003/instance";
/// XBRL 2.1 linkbase namespace.
pub const XBRL_LINKBASE_NAMESPACE: &str = "http://www.xbrl.org/2003/linkbase";
/// XLink namespace.
pub const XBRL_XLINK_NAMESPACE: &str = "http://www.w3.org/1999/xlink";
/// ISO 4217 namespace used by XBRL unit measures.
pub const ISO4217_NAMESPACE: &str = "http://www.xbrl.org/2003/iso4217";
/// The standard label role (`link:label` resources without an explicit role).
pub const STANDARD_LABEL_ROLE: &str = "http://www.xbrl.org/2003/role/label";
/// Presentation linkbase arc role (parent -> child).
pub const PARENT_CHILD_ARCROLE: &str = "http://www.xbrl.org/2003/arcrole/parent-child";
/// Calculation linkbase arc role (parent = weighted sum of children).
pub const SUMMATION_ITEM_ARCROLE: &str = "http://www.xbrl.org/2003/arcrole/summation-item";
/// Label linkbase arc role (concept -> label resource).
pub const CONCEPT_LABEL_ARCROLE: &str = "http://www.xbrl.org/2003/arcrole/concept-label";

// ---------------------------------------------------------------------------
// QName
// ---------------------------------------------------------------------------

/// An expanded XML name: namespace URI plus local name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QName {
    pub namespace: String,
    pub name: String,
}

impl QName {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Clark notation, `{namespace}name`, unambiguous in messages and data.
    pub fn clark(&self) -> String {
        format!("{{{}}}{}", self.namespace, self.name)
    }
}

impl fmt::Display for QName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.clark())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed taxonomy failure. Every malformed, missing or hostile input surfaces
/// as one of these; the loader never panics on package content.
#[derive(Debug, Error)]
pub enum TaxonomyError {
    #[error("no taxonomy entry point is configured")]
    NotConfigured,
    #[error("invalid taxonomy source {value:?}: {reason}")]
    InvalidSource { value: String, reason: String },
    #[error("cannot read taxonomy document {location}: {detail}")]
    Io { location: String, detail: String },
    #[error(
        "taxonomy location {location} is unsupported by this resolver: {detail}"
    )]
    UnsupportedLocation { location: String, detail: String },
    #[error("taxonomy reference {reference:?} from {from} cannot be resolved: {detail}")]
    UnresolvableReference {
        from: String,
        reference: String,
        detail: String,
    },
    #[error("taxonomy document {location} exceeds the {limit}-byte document bound")]
    DocumentTooLarge { location: String, limit: usize },
    #[error("taxonomy exceeds the {limit}-byte total bound")]
    TotalBytesExceeded { limit: usize },
    #[error("taxonomy exceeds the maximum of {limit} documents")]
    TooManyDocuments { limit: usize },
    #[error("taxonomy import depth exceeds the maximum of {limit} at {location}")]
    MaxDepthExceeded { location: String, limit: usize },
    #[error("taxonomy import cycle: {chain}")]
    ImportCycle { chain: String },
    #[error("missing import referenced from {from}: {reference} (resolved to {location})")]
    MissingImport {
        from: String,
        reference: String,
        location: String,
    },
    #[error("taxonomy document {location} is not well-formed XML: {detail}")]
    MalformedXml { location: String, detail: String },
    #[error("taxonomy document {location} is not an XML Schema or linkbase: {detail}")]
    UnsupportedDocument { location: String, detail: String },
    #[error("taxonomy schema {location} does not declare a targetNamespace")]
    MissingTargetNamespace { location: String },
    #[error("malformed taxonomy content in {location}: {detail}")]
    Malformed { location: String, detail: String },
    #[error("duplicate element declaration id {id:?} in taxonomy document {location}")]
    DuplicateElementId { id: String, location: String },
    #[error("concept {concept} is declared more than once (second declaration in {location})")]
    DuplicateConcept { concept: String, location: String },
    #[error("linkbase locator in {location} cannot be resolved ({href:?}): {detail}")]
    UnresolvedLocator {
        location: String,
        href: String,
        detail: String,
    },
    #[error("calculation arc weight {value:?} in {location} is not a decimal number")]
    InvalidWeight { value: String, location: String },
    #[error("concept {concept} is not declared in taxonomy namespace {target_namespace}")]
    UnknownConcept {
        concept: String,
        target_namespace: String,
    },
    #[error("concept {concept} is abstract; abstract concepts cannot carry facts")]
    AbstractConcept { concept: String },
    #[error("concept {concept} is not an XBRL item (substitution group xbrli:item)")]
    NotAnItemConcept { concept: String },
    #[error("QName reference {value:?} is malformed: {detail}")]
    BadQName { value: String, detail: String },
    #[error("QName reference {value:?} uses prefix {prefix:?} which the taxonomy never binds")]
    UnknownPrefix { value: String, prefix: String },
}

impl TaxonomyError {
    /// Stable machine code for API/readiness reporting.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::InvalidSource { .. } => "invalid_source",
            Self::Io { .. } => "io",
            Self::UnsupportedLocation { .. } => "unsupported_location",
            Self::UnresolvableReference { .. } => "unresolvable_reference",
            Self::DocumentTooLarge { .. } => "document_too_large",
            Self::TotalBytesExceeded { .. } => "total_bytes_exceeded",
            Self::TooManyDocuments { .. } => "too_many_documents",
            Self::MaxDepthExceeded { .. } => "max_depth_exceeded",
            Self::ImportCycle { .. } => "import_cycle",
            Self::MissingImport { .. } => "missing_import",
            Self::MalformedXml { .. } => "malformed_xml",
            Self::UnsupportedDocument { .. } => "unsupported_document",
            Self::MissingTargetNamespace { .. } => "missing_target_namespace",
            Self::Malformed { .. } => "malformed",
            Self::DuplicateElementId { .. } => "duplicate_element_id",
            Self::DuplicateConcept { .. } => "duplicate_concept",
            Self::UnresolvedLocator { .. } => "unresolved_locator",
            Self::InvalidWeight { .. } => "invalid_weight",
            Self::UnknownConcept { .. } => "concept_undeclared",
            Self::AbstractConcept { .. } => "concept_abstract",
            Self::NotAnItemConcept { .. } => "concept_not_item",
            Self::BadQName { .. } => "bad_qname",
            Self::UnknownPrefix { .. } => "unknown_prefix",
        }
    }
}

// ---------------------------------------------------------------------------
// Decimal amounts (exact, never floating point)
// ---------------------------------------------------------------------------

/// An exact decimal number: `unscaled * 10^-scale`.
///
/// Used for fact values, calculation weights and calculation sums. All
/// arithmetic is checked and returns `None` on overflow, so hostile amounts
/// degrade into validation failures rather than panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DecimalAmount {
    pub unscaled: i128,
    pub scale: u32,
}

impl DecimalAmount {
    pub fn zero() -> Self {
        Self {
            unscaled: 0,
            scale: 0,
        }
    }

    /// A monetary amount in euro cents (`12345` -> `123.45`).
    pub fn from_cents(cents: i64) -> Self {
        Self {
            unscaled: i128::from(cents),
            scale: 2,
        }
    }

    /// Parse an XML Schema `decimal` lexical form (no exponent, no currency).
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() || text.len() > 40 {
            return None;
        }
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        let (integer_part, fraction_part) = match digits.split_once('.') {
            Some((integer, fraction)) => (integer, fraction),
            None => (digits, ""),
        };
        if integer_part.is_empty() && fraction_part.is_empty() {
            return None;
        }
        if !integer_part.bytes().all(|b| b.is_ascii_digit())
            || !fraction_part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let scale = u32::try_from(fraction_part.len()).ok()?;
        if scale > 18 {
            return None;
        }
        let combined = format!("{integer_part}{fraction_part}");
        let magnitude: i128 = combined.parse().ok()?;
        Some(Self {
            unscaled: if negative { -magnitude } else { magnitude },
            scale,
        })
    }

    /// Exact decimal string (`scale` decimal places, no exponent).
    pub fn to_display(self) -> String {
        let negative = self.unscaled < 0;
        let magnitude = self.unscaled.unsigned_abs().to_string();
        let scale = self.scale as usize;
        let body = if scale == 0 {
            magnitude
        } else if magnitude.len() > scale {
            let split = magnitude.len() - scale;
            format!("{}.{}", &magnitude[..split], &magnitude[split..])
        } else {
            format!("0.{}{}", "0".repeat(scale - magnitude.len()), magnitude)
        };
        if negative {
            format!("-{body}")
        } else {
            body
        }
    }

    fn rescaled_to(self, scale: u32) -> Option<i128> {
        if scale < self.scale {
            return None;
        }
        let factor = 10i128.checked_pow(scale - self.scale)?;
        self.unscaled.checked_mul(factor)
    }

    /// Checked addition; `None` on overflow.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let scale = self.scale.max(other.scale);
        let left = self.rescaled_to(scale)?;
        let right = other.rescaled_to(scale)?;
        Some(Self {
            unscaled: left.checked_add(right)?,
            scale,
        })
    }

    /// Checked multiplication; `None` on overflow or an excessive scale.
    pub fn checked_mul(self, other: Self) -> Option<Self> {
        let scale = self.scale.checked_add(other.scale)?;
        if scale > 18 {
            return None;
        }
        Some(Self {
            unscaled: self.unscaled.checked_mul(other.unscaled)?,
            scale,
        })
    }

    pub fn is_zero(self) -> bool {
        self.unscaled == 0
    }
}

// ---------------------------------------------------------------------------
// Concepts, arcs, taxonomy
// ---------------------------------------------------------------------------

/// XBRL period type declared by a concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeriodType {
    Instant,
    Duration,
}

impl PeriodType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Duration => "duration",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "instant" => Some(Self::Instant),
            "duration" => Some(Self::Duration),
            _ => None,
        }
    }
}

/// XBRL balance declared by a concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Balance {
    Debit,
    Credit,
}

impl Balance {
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "debit" => Some(Self::Debit),
            "credit" => Some(Self::Credit),
            _ => None,
        }
    }
}

/// How a concept's declared type relates to XBRL's numeric item types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericKind {
    /// Derived (possibly through custom types) from `xbrli:monetaryItemType`.
    Monetary,
    /// Derived from another XBRL numeric item type (decimal, shares, ...).
    Numeric,
}

/// One global element declaration from a schema document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Concept {
    pub qname: QName,
    pub type_qname: Option<QName>,
    pub period_type: Option<PeriodType>,
    pub balance: Option<Balance>,
    pub is_abstract: bool,
    pub substitution_group: Option<QName>,
    pub id: Option<String>,
    /// Document the declaration was read from, for audit messages.
    pub source: String,
}

impl Concept {
    /// An XBRL item: substitution group `xbrli:item`, or an element that
    /// declares a periodType without belonging to another substitution group.
    pub fn is_item(&self) -> bool {
        match &self.substitution_group {
            Some(group) => {
                group.namespace == XBRL_INSTANCE_NAMESPACE && group.name == "item"
            }
            None => self.period_type.is_some(),
        }
    }

    /// An XBRL tuple: substitution group `xbrli:tuple`.
    pub fn is_tuple(&self) -> bool {
        self.substitution_group
            .as_ref()
            .is_some_and(|group| {
                group.namespace == XBRL_INSTANCE_NAMESPACE && group.name == "tuple"
            })
    }
}

/// A concept as seen by the validator (taxonomy concepts and extension
/// declarations share this shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredConcept {
    pub qname: QName,
    pub period_type: Option<PeriodType>,
    pub balance: Option<Balance>,
    pub is_abstract: bool,
    pub is_item: bool,
    pub numeric: Option<NumericKind>,
    pub source: String,
}

/// One presentation-linkbase arc (parent -> child).
#[derive(Debug, Clone, PartialEq)]
pub struct PresentationArc {
    pub role: String,
    pub parent: QName,
    pub child: QName,
    pub order: Option<f64>,
}

/// One calculation-linkbase arc: `parent = weight * child` in a sum.
#[derive(Debug, Clone, PartialEq)]
pub struct CalculationArc {
    pub role: String,
    pub parent: QName,
    pub child: QName,
    pub weight: DecimalAmount,
    pub order: Option<f64>,
}

/// One loaded taxonomy document and its content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedDocument {
    pub location: String,
    pub sha256: String,
    pub bytes: usize,
}

/// Auditable identity of the taxonomy a report was validated against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxonomyIdentity {
    pub entry_point: String,
    pub target_namespace: String,
    /// SHA-256 over the sorted (location, document digest) pairs.
    pub digest: String,
    pub document_count: usize,
    pub concept_count: usize,
}

/// A fully loaded taxonomy package.
#[derive(Debug, Clone)]
pub struct XbrlTaxonomy {
    pub entry_point: String,
    pub target_namespace: String,
    /// Every global element declaration keyed by expanded name.
    pub concepts: BTreeMap<QName, Concept>,
    /// Named type -> base type, for monetary/numeric derivation.
    pub type_bases: BTreeMap<QName, QName>,
    pub presentation_arcs: Vec<PresentationArc>,
    pub calculation_arcs: Vec<CalculationArc>,
    /// Concept -> label role -> text.
    pub labels: BTreeMap<QName, BTreeMap<String, String>>,
    /// Prefix -> namespace, as declared across the package (entry point first).
    pub prefixes: BTreeMap<String, String>,
    pub documents: Vec<LoadedDocument>,
    /// Digest over the loaded documents (see [`TaxonomyIdentity::digest`]).
    pub digest: String,
}

impl XbrlTaxonomy {
    pub fn concept(&self, qname: &QName) -> Option<&Concept> {
        self.concepts.get(qname)
    }

    /// Label text for a concept in a given role, when a label linkbase
    /// declared it.
    pub fn label(&self, qname: &QName, role: &str) -> Option<&str> {
        self.labels
            .get(qname)
            .and_then(|by_role| by_role.get(role))
            .map(String::as_str)
    }

    /// The standard (`http://www.xbrl.org/2003/role/label`) label.
    pub fn standard_label(&self, qname: &QName) -> Option<&str> {
        self.label(qname, STANDARD_LABEL_ROLE)
    }

    /// A stable prefix bound to a namespace, preferring `ee` then the first
    /// non-empty prefix.
    pub fn prefix_for_namespace(&self, namespace: &str) -> Option<&str> {
        let mut fallback: Option<&str> = None;
        for (prefix, bound) in &self.prefixes {
            if bound == namespace && !prefix.is_empty() {
                if prefix == "ee" {
                    return Some(prefix);
                }
                if fallback.is_none() {
                    fallback = Some(prefix);
                }
            }
        }
        fallback
    }

    /// Human-readable concept name for messages: `ee:Assets` when a prefix is
    /// bound to the namespace, Clark notation otherwise.
    pub fn display_name(&self, qname: &QName) -> String {
        match self.prefix_for_namespace(&qname.namespace) {
            Some(prefix) => format!("{prefix}:{}", qname.name),
            None => qname.clark(),
        }
    }

    pub fn identity(&self) -> TaxonomyIdentity {
        TaxonomyIdentity {
            entry_point: self.entry_point.clone(),
            target_namespace: self.target_namespace.clone(),
            digest: self.digest.clone(),
            document_count: self.documents.len(),
            concept_count: self.concepts.len(),
        }
    }

    /// Resolve a configured concept reference to an expanded name:
    /// `prefix:name`, `{namespace}name`, or a bare local name in the
    /// taxonomy's target namespace.
    pub fn resolve_qname(&self, reference: &str) -> Result<QName, TaxonomyError> {
        let value = reference.trim();
        if value.is_empty() {
            return Err(TaxonomyError::BadQName {
                value: value.to_string(),
                detail: "empty concept reference".to_string(),
            });
        }
        if let Some(rest) = value.strip_prefix('{') {
            if let Some((namespace, name)) = rest.split_once('}') {
                if !namespace.is_empty() && !name.is_empty() {
                    return Ok(QName::new(namespace, name));
                }
            }
            return Err(TaxonomyError::BadQName {
                value: value.to_string(),
                detail: "Clark notation must be {namespace}localname".to_string(),
            });
        }
        if let Some((prefix, name)) = value.split_once(':') {
            if prefix.is_empty() || name.is_empty() {
                return Err(TaxonomyError::BadQName {
                    value: value.to_string(),
                    detail: "prefix and local name must both be non-empty".to_string(),
                });
            }
            let namespace =
                self.prefixes
                    .get(prefix)
                    .ok_or_else(|| TaxonomyError::UnknownPrefix {
                        value: value.to_string(),
                        prefix: prefix.to_string(),
                    })?;
            return Ok(QName::new(namespace.clone(), name));
        }
        Ok(QName::new(
            self.target_namespace.clone(),
            value.to_string(),
        ))
    }

    /// Numeric category of a concept's declared type, walking custom type
    /// derivation up to the XBRL built-ins. `None` means "not numeric, or the
    /// type chain leaves the loaded package" (the validator then does not
    /// enforce numeric unit rules it cannot justify).
    pub fn numeric_kind(&self, qname: &QName) -> Option<NumericKind> {
        let concept = self.concepts.get(qname)?;
        let mut current = concept.type_qname.clone()?;
        let mut visited = BTreeSet::new();
        for _ in 0..32 {
            if !visited.insert(current.clone()) {
                return None;
            }
            if current.namespace == XBRL_INSTANCE_NAMESPACE {
                return match current.name.as_str() {
                    "monetaryItemType" => Some(NumericKind::Monetary),
                    "decimalItemType"
                    | "integerItemType"
                    | "nonPositiveIntegerItemType"
                    | "negativeIntegerItemType"
                    | "nonNegativeIntegerItemType"
                    | "positiveIntegerItemType"
                    | "floatItemType"
                    | "doubleItemType"
                    | "sharesItemType"
                    | "pureItemType" => Some(NumericKind::Numeric),
                    _ => None,
                };
            }
            current = self.type_bases.get(&current)?.clone();
        }
        None
    }

    /// The validator's view of a declared taxonomy concept.
    pub fn declare(&self, qname: &QName) -> Option<DeclaredConcept> {
        let concept = self.concepts.get(qname)?;
        Some(DeclaredConcept {
            qname: concept.qname.clone(),
            period_type: concept.period_type,
            balance: concept.balance,
            is_abstract: concept.is_abstract,
            is_item: concept.is_item(),
            numeric: self.numeric_kind(qname),
            source: concept.source.clone(),
        })
    }

    pub fn presentation_children(&self, parent: &QName) -> Vec<&QName> {
        self.presentation_arcs
            .iter()
            .filter(|arc| &arc.parent == parent)
            .map(|arc| &arc.child)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Source, locations and resolvers
// ---------------------------------------------------------------------------

/// Where a taxonomy entry point is configured: a filesystem path or a URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaxonomySource {
    File(PathBuf),
    Uri(String),
}

impl TaxonomySource {
    /// Parse a configured source string. Values containing a URI scheme
    /// (`https://`, `memory://`, ...) are URIs; everything else is a path.
    pub fn parse(value: &str) -> Result<Self, TaxonomyError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(TaxonomyError::NotConfigured);
        }
        if value.contains("://") {
            Ok(Self::Uri(value.to_string()))
        } else {
            Ok(Self::File(PathBuf::from(value)))
        }
    }

    pub fn location(&self) -> TaxonomyLocation {
        match self {
            Self::File(path) => TaxonomyLocation::File(path.clone()),
            Self::Uri(uri) => TaxonomyLocation::Uri(uri.clone()),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Uri(uri) => uri.clone(),
        }
    }
}

/// A resolved document location inside a taxonomy package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaxonomyLocation {
    File(PathBuf),
    Uri(String),
}

impl TaxonomyLocation {
    pub fn as_string(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Uri(uri) => uri.clone(),
        }
    }
}

impl fmt::Display for TaxonomyLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_string())
    }
}

/// How the loader reads documents and resolves references between them.
///
/// Implement this to fetch a URL-based package (the loader itself is
/// transport-agnostic); the default implementation is
/// [`FileSystemResolver`].
pub trait TaxonomyResolver {
    /// Read the bytes of a document.
    fn load(&self, location: &TaxonomyLocation) -> Result<Vec<u8>, TaxonomyError>;
    /// Resolve a reference found inside `base` (already-resolved location) to
    /// the location of the referenced document.
    fn resolve(
        &self,
        base: &TaxonomyLocation,
        reference: &str,
    ) -> Result<TaxonomyLocation, TaxonomyError>;
}

/// The default resolver: filesystem only, references resolved relative to the
/// referring document (with lexical `..`/`.` normalization).
///
/// Remote locations are refused with a typed
/// [`TaxonomyError::UnsupportedLocation`]; inject a different resolver for
/// URL-based packages.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileSystemResolver;

impl TaxonomyResolver for FileSystemResolver {
    fn load(&self, location: &TaxonomyLocation) -> Result<Vec<u8>, TaxonomyError> {
        match location {
            TaxonomyLocation::File(path) => {
                std::fs::read(path).map_err(|error| TaxonomyError::Io {
                    location: path.display().to_string(),
                    detail: error.to_string(),
                })
            }
            TaxonomyLocation::Uri(uri) => Err(TaxonomyError::UnsupportedLocation {
                location: uri.clone(),
                detail: "the filesystem resolver cannot fetch remote documents; vendor the \
                         package locally or inject a TaxonomyResolver that can"
                    .to_string(),
            }),
        }
    }

    fn resolve(
        &self,
        base: &TaxonomyLocation,
        reference: &str,
    ) -> Result<TaxonomyLocation, TaxonomyError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(TaxonomyError::UnresolvableReference {
                from: base.as_string(),
                reference: reference.to_string(),
                detail: "empty reference".to_string(),
            });
        }
        if reference.contains("://") {
            return Ok(TaxonomyLocation::Uri(reference.to_string()));
        }
        match base {
            TaxonomyLocation::File(base_path) => {
                let path = Path::new(reference);
                let joined = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    base_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(path)
                };
                Ok(TaxonomyLocation::File(normalize_path(&joined)))
            }
            TaxonomyLocation::Uri(uri) => Err(TaxonomyError::UnsupportedLocation {
                location: uri.clone(),
                detail: format!(
                    "reference {reference:?} cannot be resolved by the filesystem resolver"
                ),
            }),
        }
    }
}

/// An in-memory resolver for tests and offline fixtures: documents are keyed
/// by URI (`memory://taxonomy/entry.xsd`), relative references are joined onto
/// the referring URI.
#[derive(Debug, Clone, Default)]
pub struct MemoryResolver {
    documents: BTreeMap<String, Vec<u8>>,
}

impl MemoryResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, location: &str, content: impl Into<String>) {
        self.documents
            .insert(location.to_string(), content.into().into_bytes());
    }

    pub fn contains(&self, location: &str) -> bool {
        self.documents.contains_key(location)
    }
}

impl TaxonomyResolver for MemoryResolver {
    fn load(&self, location: &TaxonomyLocation) -> Result<Vec<u8>, TaxonomyError> {
        let key = match location {
            TaxonomyLocation::Uri(uri) => uri.clone(),
            TaxonomyLocation::File(path) => path.display().to_string(),
        };
        self.documents.get(&key).cloned().ok_or(TaxonomyError::Io {
            location: key,
            detail: "not present in the in-memory fixture set".to_string(),
        })
    }

    fn resolve(
        &self,
        base: &TaxonomyLocation,
        reference: &str,
    ) -> Result<TaxonomyLocation, TaxonomyError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(TaxonomyError::UnresolvableReference {
                from: base.as_string(),
                reference: reference.to_string(),
                detail: "empty reference".to_string(),
            });
        }
        if reference.contains("://") {
            return Ok(TaxonomyLocation::Uri(reference.to_string()));
        }
        let base_uri = match base {
            TaxonomyLocation::Uri(uri) => uri,
            TaxonomyLocation::File(path) => {
                return Err(TaxonomyError::UnsupportedLocation {
                    location: path.display().to_string(),
                    detail: "the in-memory resolver addresses documents by URI".to_string(),
                });
            }
        };
        let base_url = url::Url::parse(base_uri).map_err(|error| {
            TaxonomyError::UnresolvableReference {
                from: base.as_string(),
                reference: reference.to_string(),
                detail: error.to_string(),
            }
        })?;
        let joined =
            base_url
                .join(reference)
                .map_err(|error| TaxonomyError::UnresolvableReference {
                    from: base.as_string(),
                    reference: reference.to_string(),
                    detail: error.to_string(),
                })?;
        Ok(TaxonomyLocation::Uri(joined.to_string()))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    let mut prefix: Option<std::ffi::OsString> = None;
    let mut absolute = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = Some(prefix_component.as_os_str().to_os_string());
            }
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => match parts.last() {
                Some(last) if last != ".." => {
                    parts.pop();
                }
                _ if absolute => {}
                _ => parts.push(std::ffi::OsString::from("..")),
            },
            Component::Normal(part) => parts.push(part.to_os_string()),
        }
    }
    let mut out = PathBuf::new();
    if let Some(prefix) = prefix {
        out.push(prefix);
    }
    if absolute {
        out.push(Component::RootDir.as_os_str());
    }
    for part in parts {
        out.push(part);
    }
    out
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Work bounds for loading a taxonomy package. A hostile or enormous package
/// is refused as soon as a bound is crossed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyLimits {
    pub max_documents: usize,
    pub max_depth: usize,
    pub max_document_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for TaxonomyLimits {
    fn default() -> Self {
        Self {
            max_documents: 256,
            max_depth: 16,
            max_document_bytes: 8 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load a taxonomy package from a configured entry point using the default
/// filesystem resolver and the default bounds.
pub fn load_taxonomy(
    source: &TaxonomySource,
    limits: &TaxonomyLimits,
) -> Result<XbrlTaxonomy, TaxonomyError> {
    load_taxonomy_with(source, &FileSystemResolver, limits)
}

/// Load a taxonomy package with an explicit resolver (URL fetching, in-memory
/// fixtures, ...). See [`TaxonomyResolver`].
pub fn load_taxonomy_with<R: TaxonomyResolver>(
    source: &TaxonomySource,
    resolver: &R,
    limits: &TaxonomyLimits,
) -> Result<XbrlTaxonomy, TaxonomyError> {
    let entry = source.location();
    let mut accumulator = TaxonomyAccumulator::default();
    let mut state = LoadState::default();
    load_document(
        &entry,
        0,
        resolver,
        limits,
        &mut accumulator,
        &mut state,
        true,
    )?;
    accumulator.finish(source)
}

#[derive(Debug, Default)]
struct LoadState {
    loaded: BTreeMap<TaxonomyLocation, usize>,
    stack: Vec<TaxonomyLocation>,
}

fn load_document<R: TaxonomyResolver>(
    location: &TaxonomyLocation,
    depth: usize,
    resolver: &R,
    limits: &TaxonomyLimits,
    accumulator: &mut TaxonomyAccumulator,
    state: &mut LoadState,
    is_entry: bool,
) -> Result<(), TaxonomyError> {
    if state.stack.iter().any(|on_stack| on_stack == location) {
        let mut chain: Vec<String> = state.stack.iter().map(TaxonomyLocation::as_string).collect();
        chain.push(location.as_string());
        return Err(TaxonomyError::ImportCycle {
            chain: chain.join(" -> "),
        });
    }
    if state.loaded.contains_key(location) {
        return Ok(());
    }
    if state.loaded.len() >= limits.max_documents {
        return Err(TaxonomyError::TooManyDocuments {
            limit: limits.max_documents,
        });
    }
    if depth > limits.max_depth {
        return Err(TaxonomyError::MaxDepthExceeded {
            location: location.as_string(),
            limit: limits.max_depth,
        });
    }
    let bytes = resolver.load(location)?;
    if bytes.len() > limits.max_document_bytes {
        return Err(TaxonomyError::DocumentTooLarge {
            location: location.as_string(),
            limit: limits.max_document_bytes,
        });
    }
    if accumulator.total_bytes.saturating_add(bytes.len()) > limits.max_total_bytes {
        return Err(TaxonomyError::TotalBytesExceeded {
            limit: limits.max_total_bytes,
        });
    }
    let raw = parse_document(location, &bytes)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    accumulator.total_bytes += bytes.len();
    accumulator.documents.push(LoadedDocument {
        location: location.as_string(),
        sha256: digest,
        bytes: bytes.len(),
    });
    state.loaded.insert(location.clone(), accumulator.documents.len() - 1);
    let first_reference = accumulator.references.len();
    accumulator.merge(raw, location, is_entry)?;
    let references: Vec<(TaxonomyLocation, RawReference)> =
        accumulator.references[first_reference..].to_vec();

    state.stack.push(location.clone());
    for (from, reference) in references {
        let Some(child) = resolve_reference(resolver, &from, &reference)? else {
            continue;
        };
        load_document(
            &child,
            depth + 1,
            resolver,
            limits,
            accumulator,
            state,
            false,
        )
        .map_err(|error| match error {
            TaxonomyError::Io { .. } => TaxonomyError::MissingImport {
                from: from.as_string(),
                reference: reference.describe(),
                location: child.as_string(),
            },
            other => other,
        })?;
    }
    state.stack.pop();
    Ok(())
}

/// Resolve one reference to a document location. `Ok(None)` means the
/// reference is a namespace-only import of a namespace the consumer already
/// knows (xbrli, linkbase, xlink, xsd, iso4217), which carries nothing to
/// load.
fn resolve_reference<R: TaxonomyResolver>(
    resolver: &R,
    from: &TaxonomyLocation,
    reference: &RawReference,
) -> Result<Option<TaxonomyLocation>, TaxonomyError> {
    let Some(reference_text) = reference.location() else {
        match reference {
            RawReference::Import { namespace, .. }
                if namespace.as_deref().is_some_and(is_known_namespace) =>
            {
                return Ok(None);
            }
            _ => {
                return Err(TaxonomyError::MissingImport {
                    from: from.as_string(),
                    reference: reference.describe(),
                    location: "unresolvable reference without a location".to_string(),
                });
            }
        }
    };
    resolver
        .resolve(from, reference_text)
        .map(Some)
        .map_err(|error| match error {
            TaxonomyError::UnsupportedLocation { detail, .. } => {
                TaxonomyError::UnresolvableReference {
                    from: from.as_string(),
                    reference: reference_text.to_string(),
                    detail,
                }
            }
            other => other,
        })
}

/// Namespaces the loader never has to fetch: the XBRL 2.1 instance/linkbase
/// machinery and XML Schema itself.
fn is_known_namespace(namespace: &str) -> bool {
    matches!(
        namespace,
        XSD_NAMESPACE
            | XBRL_INSTANCE_NAMESPACE
            | XBRL_LINKBASE_NAMESPACE
            | XBRL_XLINK_NAMESPACE
            | ISO4217_NAMESPACE
    )
}

// ---------------------------------------------------------------------------
// Document parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArcKind {
    Presentation,
    Calculation,
    Label,
    Other,
}

#[derive(Debug, Clone)]
struct RawExtendedLink {
    serial: usize,
    role: String,
}

#[derive(Debug, Clone)]
struct RawLocator {
    link: usize,
    label: String,
    href: String,
    location: String,
}

#[derive(Debug, Clone)]
struct RawLabelResource {
    link: usize,
    label: String,
    role: String,
    text: String,
}

#[derive(Debug, Clone)]
struct RawArc {
    link: usize,
    kind: ArcKind,
    arcrole: String,
    from: String,
    to: String,
    weight: Option<String>,
    order: Option<String>,
    location: String,
}

#[derive(Debug, Clone)]
enum RawReference {
    Import {
        namespace: Option<String>,
        location: Option<String>,
    },
    Include {
        location: String,
    },
    Linkbase {
        location: String,
    },
}

impl RawReference {
    fn location(&self) -> Option<&str> {
        match self {
            Self::Import { location, .. } => location.as_deref(),
            Self::Include { location } | Self::Linkbase { location } => Some(location),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Import {
                namespace,
                location,
            } => format!(
                "xs:import namespace {:?} schemaLocation {:?}",
                namespace.as_deref().unwrap_or("<missing>"),
                location.as_deref().unwrap_or("<missing>")
            ),
            Self::Include { location } => format!("xs:include schemaLocation {location:?}"),
            Self::Linkbase { location } => format!("link:linkbaseRef href {location:?}"),
        }
    }
}

#[derive(Debug, Default)]
struct RawDocument {
    target_namespace: Option<String>,
    prefixes: BTreeMap<String, String>,
    concepts: Vec<Concept>,
    type_bases: Vec<(QName, QName)>,
    references: Vec<RawReference>,
    extended_links: Vec<RawExtendedLink>,
    locators: Vec<RawLocator>,
    labels: Vec<RawLabelResource>,
    arcs: Vec<RawArc>,
    ids: Vec<(String, QName)>,
}

/// Parse one schema or linkbase document into raw declarations. Errors are
/// typed; no input panics.
fn parse_document(location: &TaxonomyLocation, bytes: &[u8]) -> Result<RawDocument, TaxonomyError> {
    let text = String::from_utf8_lossy(bytes);
    let mut reader = quick_xml::NsReader::from_str(&text);
    let mut parser = DocumentParser {
        location,
        document: RawDocument::default(),
        scope: NamespaceScope::default(),
        frames: Vec::new(),
        next_link: 0,
        label_buffer: None,
    };
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| TaxonomyError::MalformedXml {
                location: location.as_string(),
                detail: error.to_string(),
            })?;
        let element_namespace: Option<String> = match &resolved {
            quick_xml::name::ResolveResult::Bound(namespace) => {
                Some(String::from_utf8_lossy(namespace.as_ref()).into_owned())
            }
            quick_xml::name::ResolveResult::Unbound => None,
            quick_xml::name::ResolveResult::Unknown(prefix) => {
                return Err(TaxonomyError::MalformedXml {
                    location: location.as_string(),
                    detail: format!(
                        "element uses prefix {:?} which is not bound in scope",
                        String::from_utf8_lossy(prefix)
                    ),
                });
            }
        };
        match event {
            quick_xml::events::Event::Start(start) => {
                parser.on_start(&start, element_namespace.as_deref())?;
            }
            quick_xml::events::Event::Empty(start) => {
                parser.on_start(&start, element_namespace.as_deref())?;
                parser.on_end()?;
            }
            quick_xml::events::Event::End(_) => {
                parser.on_end()?;
            }
            quick_xml::events::Event::Text(text) => {
                parser.on_text(&text)?;
            }
            quick_xml::events::Event::CData(text) => {
                parser.on_cdata(&text)?;
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }
    if !parser.frames.is_empty() {
        return Err(TaxonomyError::MalformedXml {
            location: location.as_string(),
            detail: "document ended with unclosed elements".to_string(),
        });
    }
    Ok(parser.document)
}

struct DocumentParser<'a> {
    location: &'a TaxonomyLocation,
    document: RawDocument,
    scope: NamespaceScope,
    frames: Vec<ElementFrame>,
    next_link: usize,
    label_buffer: Option<String>,
}

struct ElementFrame {
    qname: QName,
    namespace_frame: bool,
    named_type: Option<QName>,
    extended_link: Option<usize>,
    label_resource: Option<(usize, String, String)>,
}

impl DocumentParser<'_> {
    fn malformed(&self, detail: impl Into<String>) -> TaxonomyError {
        TaxonomyError::Malformed {
            location: self.location.as_string(),
            detail: detail.into(),
        }
    }

    fn resolve_qname_value(&self, value: &str) -> Result<QName, TaxonomyError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(self.malformed("empty QName attribute value"));
        }
        if let Some(rest) = value.strip_prefix('{') {
            if let Some((namespace, name)) = rest.split_once('}') {
                if !namespace.is_empty() && !name.is_empty() {
                    return Ok(QName::new(namespace, name));
                }
            }
            return Err(TaxonomyError::BadQName {
                value: value.to_string(),
                detail: "Clark notation must be {namespace}localname".to_string(),
            });
        }
        if let Some((prefix, name)) = value.split_once(':') {
            if name.is_empty() {
                return Err(TaxonomyError::BadQName {
                    value: value.to_string(),
                    detail: "local name is empty".to_string(),
                });
            }
            let namespace = match self.scope.resolve(prefix) {
                Some(namespace) => namespace.to_string(),
                None => {
                    return Err(TaxonomyError::UnknownPrefix {
                        value: value.to_string(),
                        prefix: prefix.to_string(),
                    });
                }
            };
            return Ok(QName::new(namespace, name));
        }
        let default_namespace = self.scope.resolve("").unwrap_or("");
        Ok(QName::new(default_namespace, value))
    }

    fn on_start(
        &mut self,
        start: &quick_xml::events::BytesStart<'_>,
        namespace: Option<&str>,
    ) -> Result<(), TaxonomyError> {
        let attributes = collect_attributes(start, &self.scope)
            .map_err(|detail| self.malformed(detail))?;
        let pushed = self.scope.push(attributes.namespace_declarations.clone());
        for (prefix, namespace) in &attributes.namespace_declarations {
            if !namespace.is_empty() {
                self.document
                    .prefixes
                    .entry(prefix.clone())
                    .or_insert_with(|| namespace.clone());
            }
        }
        let local = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
        let qname = QName::new(namespace.unwrap_or(""), local);
        let is_root = self.frames.is_empty();
        if is_root {
            let is_schema = qname.namespace == XSD_NAMESPACE && qname.name == "schema";
            let is_linkbase =
                qname.namespace == XBRL_LINKBASE_NAMESPACE && qname.name == "linkbase";
            if !is_schema && !is_linkbase {
                return Err(TaxonomyError::UnsupportedDocument {
                    location: self.location.as_string(),
                    detail: format!("root element is {qname}"),
                });
            }
            if is_schema {
                if let Some(target) = attributes.get("targetNamespace") {
                    self.document.target_namespace = Some(target.to_string());
                }
            }
        }
        let parent_qname = self.frames.last().map(|frame| frame.qname.clone());
        let parent_is_schema_root = matches!(
            parent_qname.as_ref(),
            Some(parent) if parent.namespace == XSD_NAMESPACE && parent.name == "schema"
        );
        let mut frame = ElementFrame {
            qname: qname.clone(),
            namespace_frame: pushed,
            named_type: None,
            extended_link: None,
            label_resource: None,
        };

        if qname.namespace == XSD_NAMESPACE {
            match qname.name.as_str() {
                "element" if parent_is_schema_root => {
                    if let Some(concept) = self.global_element(&attributes)? {
                        self.document.concepts.push(concept);
                    }
                }
                "simpleType" | "complexType" => {
                    if let Some(name) = attributes.get("name") {
                        let target = self.document.target_namespace.clone().ok_or_else(|| {
                            self.malformed("named type declared before targetNamespace")
                        })?;
                        frame.named_type = Some(QName::new(target, name));
                    }
                }
                "restriction" | "extension" => {
                    if let Some(base) = attributes.get("base") {
                        if let Some(owner) = self
                            .frames
                            .iter()
                            .rev()
                            .find_map(|frame| frame.named_type.clone())
                        {
                            let base = self.resolve_qname_value(base)?;
                            self.document.type_bases.push((owner, base));
                        }
                    }
                }
                "import" if parent_is_schema_root => {
                    self.document.references.push(RawReference::Import {
                        namespace: attributes.get("namespace").map(str::to_string),
                        location: attributes.get("schemaLocation").map(str::to_string),
                    });
                }
                "include" if parent_is_schema_root => {
                    match attributes.get("schemaLocation") {
                        Some(reference) => self.document.references.push(RawReference::Include {
                            location: reference.to_string(),
                        }),
                        None => {
                            return Err(self.malformed("xs:include without schemaLocation"));
                        }
                    }
                }
                _ => {}
            }
        } else if qname.namespace == XBRL_LINKBASE_NAMESPACE {
            match qname.name.as_str() {
                "linkbaseRef" => {
                    if let Some(href) = attributes.get_ns(XBRL_XLINK_NAMESPACE, "href") {
                        self.document.references.push(RawReference::Linkbase {
                            location: href.to_string(),
                        });
                    } else {
                        return Err(self.malformed("link:linkbaseRef without xlink:href"));
                    }
                }
                "presentationLink" | "calculationLink" | "labelLink" | "definitionLink"
                | "referenceLink" | "footnoteLink" => {
                    self.next_link += 1;
                    self.document.extended_links.push(RawExtendedLink {
                        serial: self.next_link,
                        role: attributes
                            .get_ns(XBRL_XLINK_NAMESPACE, "role")
                            .unwrap_or("")
                            .to_string(),
                    });
                    frame.extended_link = Some(self.next_link);
                }
                "loc" => {
                    let link = self.current_extended_link()?;
                    let label = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "label")
                        .ok_or_else(|| self.malformed("link:loc without xlink:label"))?;
                    let href = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "href")
                        .ok_or_else(|| self.malformed("link:loc without xlink:href"))?;
                    self.document.locators.push(RawLocator {
                        link,
                        label: label.to_string(),
                        href: href.to_string(),
                        location: self.location.as_string(),
                    });
                }
                "label" => {
                    let link = self.current_extended_link()?;
                    let label = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "label")
                        .ok_or_else(|| self.malformed("link:label without xlink:label"))?;
                    let role = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "role")
                        .unwrap_or(STANDARD_LABEL_ROLE)
                        .to_string();
                    frame.label_resource = Some((link, label.to_string(), role));
                }
                "presentationArc" | "calculationArc" | "labelArc" | "definitionArc"
                | "referenceArc" | "footnoteArc" => {
                    let link = self.current_extended_link()?;
                    let kind = match qname.name.as_str() {
                        "presentationArc" => ArcKind::Presentation,
                        "calculationArc" => ArcKind::Calculation,
                        "labelArc" => ArcKind::Label,
                        _ => ArcKind::Other,
                    };
                    let from = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "from")
                        .ok_or_else(|| self.malformed(format!("{} without xlink:from", qname.name)))?;
                    let to = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "to")
                        .ok_or_else(|| self.malformed(format!("{} without xlink:to", qname.name)))?;
                    let arcrole = attributes
                        .get_ns(XBRL_XLINK_NAMESPACE, "arcrole")
                        .unwrap_or("")
                        .to_string();
                    self.document.arcs.push(RawArc {
                        link,
                        kind,
                        arcrole,
                        from: from.to_string(),
                        to: to.to_string(),
                        weight: attributes.get("weight").map(str::to_string),
                        order: attributes.get("order").map(str::to_string),
                        location: self.location.as_string(),
                    });
                }
                _ => {}
            }
        }
        self.frames.push(frame);
        Ok(())
    }

    fn global_element(
        &mut self,
        attributes: &AttributeSet,
    ) -> Result<Option<Concept>, TaxonomyError> {
        let Some(name) = attributes.get("name") else {
            // A global xs:element without a name is not an XBRL concept.
            return Ok(None);
        };
        let target = self
            .document
            .target_namespace
            .clone()
            .ok_or_else(|| self.malformed("xs:element declared before targetNamespace"))?;
        let qname = QName::new(target, name);
        let type_qname = match attributes.get("type") {
            Some(value) => Some(self.resolve_qname_value(value)?),
            None => None,
        };
        let period_type = match attributes
            .get_ns(XBRL_INSTANCE_NAMESPACE, "periodType")
            .or_else(|| attributes.get("periodType"))
        {
            Some(value) => Some(PeriodType::parse(value).ok_or_else(|| {
                self.malformed(format!(
                    "concept {name} declares unknown xbrli:periodType {value:?} (expected \
                     instant or duration)"
                ))
            })?),
            None => None,
        };
        let balance = match attributes
            .get_ns(XBRL_INSTANCE_NAMESPACE, "balance")
            .or_else(|| attributes.get("balance"))
        {
            Some(value) => Some(Balance::parse(value).ok_or_else(|| {
                self.malformed(format!(
                    "concept {name} declares unknown xbrli:balance {value:?} (expected debit or \
                     credit)"
                ))
            })?),
            None => None,
        };
        let substitution_group = match attributes.get("substitutionGroup") {
            Some(value) => Some(self.resolve_qname_value(value)?),
            None => None,
        };
        let is_abstract = attributes.bool_attr("abstract");
        let id = attributes.get("id").map(str::to_string);
        if let Some(id) = &id {
            self.document.ids.push((id.clone(), qname.clone()));
        }
        let concept = Concept {
            qname,
            type_qname,
            period_type,
            balance,
            is_abstract,
            substitution_group,
            id,
            source: self.location.as_string(),
        };
        if !concept.is_abstract && concept.is_item() && concept.period_type.is_none() {
            return Err(self.malformed(format!(
                "concept {} is a non-abstract item without an xbrli:periodType; the period \
                 type cannot be validated",
                concept.qname
            )));
        }
        Ok(Some(concept))
    }

    fn current_extended_link(&self) -> Result<usize, TaxonomyError> {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| frame.extended_link)
            .ok_or_else(|| self.malformed("link element outside an extended link"))
    }

    fn on_text(&mut self, text: &quick_xml::events::BytesText<'_>) -> Result<(), TaxonomyError> {
        if self
            .frames
            .last()
            .and_then(|frame| frame.label_resource.as_ref())
            .is_some()
        {
            let decoded = decode_text(text).map_err(|detail| self.malformed(detail))?;
            self.label_buffer
                .get_or_insert_with(String::new)
                .push_str(&decoded);
        }
        Ok(())
    }

    fn on_cdata(&mut self, text: &quick_xml::events::BytesCData<'_>) -> Result<(), TaxonomyError> {
        if self
            .frames
            .last()
            .and_then(|frame| frame.label_resource.as_ref())
            .is_some()
        {
            let decoded = String::from_utf8_lossy(text.as_ref()).into_owned();
            self.label_buffer
                .get_or_insert_with(String::new)
                .push_str(&decoded);
        }
        Ok(())
    }

    fn on_end(&mut self) -> Result<(), TaxonomyError> {
        let Some(frame) = self.frames.pop() else {
            return Err(self.malformed("unbalanced closing element"));
        };
        if let Some((link, label, role)) = frame.label_resource {
            let text = self.label_buffer.take().unwrap_or_default();
            self.document.labels.push(RawLabelResource {
                link,
                label,
                role,
                text: text.trim().to_string(),
            });
        }
        self.scope.pop(frame.namespace_frame);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accumulation and finishing
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TaxonomyAccumulator {
    documents: Vec<LoadedDocument>,
    entry_target_namespace: Option<String>,
    concepts: BTreeMap<QName, Concept>,
    type_bases: BTreeMap<QName, QName>,
    prefixes: BTreeMap<String, String>,
    ids: BTreeMap<String, QName>,
    extended_links: BTreeMap<usize, RawExtendedLink>,
    locators: Vec<RawLocator>,
    labels: Vec<RawLabelResource>,
    arcs: Vec<RawArc>,
    references: Vec<(TaxonomyLocation, RawReference)>,
    total_bytes: usize,
    next_link_serial: usize,
}

impl TaxonomyAccumulator {
    fn merge(
        &mut self,
        mut raw: RawDocument,
        location: &TaxonomyLocation,
        is_entry: bool,
    ) -> Result<(), TaxonomyError> {
        if is_entry {
            self.entry_target_namespace = raw.target_namespace.clone();
        }
        for (prefix, namespace) in std::mem::take(&mut raw.prefixes) {
            self.prefixes.entry(prefix).or_insert(namespace);
        }
        for (id, qname) in raw.ids {
            if self.ids.insert(id.clone(), qname).is_some() {
                return Err(TaxonomyError::DuplicateElementId {
                    id,
                    location: location.as_string(),
                });
            }
        }
        for concept in raw.concepts {
            let qname = concept.qname.clone();
            if self.concepts.insert(qname.clone(), concept).is_some() {
                return Err(TaxonomyError::DuplicateConcept {
                    concept: qname.clark(),
                    location: location.as_string(),
                });
            }
        }
        for (owner, base) in raw.type_bases {
            self.type_bases.insert(owner, base);
        }
        let link_count = raw.extended_links.len();
        let offset = self.next_link_serial;
        for mut link in raw.extended_links {
            link.serial += offset;
            self.extended_links.insert(link.serial, link);
        }
        for mut locator in raw.locators {
            locator.link += offset;
            self.locators.push(locator);
        }
        for mut label in raw.labels {
            label.link += offset;
            self.labels.push(label);
        }
        for mut arc in raw.arcs {
            arc.link += offset;
            self.arcs.push(arc);
        }
        self.next_link_serial += link_count;
        for reference in raw.references {
            self.references.push((location.clone(), reference));
        }
        Ok(())
    }

    fn finish(self, source: &TaxonomySource) -> Result<XbrlTaxonomy, TaxonomyError> {
        let entry_location = source.location();
        let target_namespace =
            self.entry_target_namespace
                .clone()
                .ok_or_else(|| TaxonomyError::MissingTargetNamespace {
                    location: entry_location.as_string(),
                })?;

        // Resolve linkbase locators (document#id) to the declared concepts.
        let mut locator_concepts: BTreeMap<(usize, String), QName> = BTreeMap::new();
        for locator in &self.locators {
            let id = locator
                .href
                .rsplit_once('#')
                .map(|(_, id)| id)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| TaxonomyError::UnresolvedLocator {
                    location: locator.location.clone(),
                    href: locator.href.clone(),
                    detail: "the locator href has no fragment identifier".to_string(),
                })?;
            let concept = self
                .ids
                .get(id)
                .ok_or_else(|| TaxonomyError::UnresolvedLocator {
                    location: locator.location.clone(),
                    href: locator.href.clone(),
                    detail: format!(
                        "no global element declaration with id {id:?} was loaded from the package"
                    ),
                })?;
            locator_concepts.insert((locator.link, locator.label.clone()), concept.clone());
        }
        let lookup = |link: usize, key: &str, href_hint: &str| -> Result<QName, TaxonomyError> {
            locator_concepts
                .get(&(link, key.to_string()))
                .cloned()
                .ok_or_else(|| TaxonomyError::UnresolvedLocator {
                    location: href_hint.to_string(),
                    href: key.to_string(),
                    detail: format!("no link:loc with xlink:label {key:?} in the extended link"),
                })
        };

        let link_role = |serial: usize| -> String {
            self.extended_links
                .get(&serial)
                .map(|link| link.role.clone())
                .unwrap_or_default()
        };

        let mut presentation_arcs = Vec::new();
        let mut calculation_arcs = Vec::new();
        for arc in &self.arcs {
            match arc.kind {
                ArcKind::Presentation if arc.arcrole == PARENT_CHILD_ARCROLE => {
                    presentation_arcs.push(PresentationArc {
                        role: link_role(arc.link),
                        parent: lookup(arc.link, &arc.from, &arc.location)?,
                        child: lookup(arc.link, &arc.to, &arc.location)?,
                        order: parse_order(arc.order.as_deref()),
                    });
                }
                ArcKind::Calculation if arc.arcrole == SUMMATION_ITEM_ARCROLE => {
                    let weight_text = arc.weight.as_deref().ok_or_else(|| {
                        TaxonomyError::Malformed {
                            location: arc.location.clone(),
                            detail: "calculationArc with arcrole summation-item has no weight"
                                .to_string(),
                        }
                    })?;
                    let weight = DecimalAmount::parse(weight_text).ok_or_else(|| {
                        TaxonomyError::InvalidWeight {
                            value: weight_text.to_string(),
                            location: arc.location.clone(),
                        }
                    })?;
                    calculation_arcs.push(CalculationArc {
                        role: link_role(arc.link),
                        parent: lookup(arc.link, &arc.from, &arc.location)?,
                        child: lookup(arc.link, &arc.to, &arc.location)?,
                        weight,
                        order: parse_order(arc.order.as_deref()),
                    });
                }
                _ => {}
            }
        }
        presentation_arcs.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then_with(|| left.parent.cmp(&right.parent))
                .then_with(|| left.child.cmp(&right.child))
                .then_with(|| {
                    left.order
                        .unwrap_or(f64::INFINITY)
                        .total_cmp(&right.order.unwrap_or(f64::INFINITY))
                })
        });
        calculation_arcs.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then_with(|| left.parent.cmp(&right.parent))
                .then_with(|| left.child.cmp(&right.child))
                .then_with(|| left.weight.cmp(&right.weight))
        });

        // Labels: labelArc from a locator to a label resource.
        let mut label_resources: BTreeMap<(usize, String), (String, String)> = BTreeMap::new();
        for label in &self.labels {
            label_resources.insert(
                (label.link, label.label.clone()),
                (label.role.clone(), label.text.clone()),
            );
        }
        let mut labels: BTreeMap<QName, BTreeMap<String, String>> = BTreeMap::new();
        for arc in &self.arcs {
            if arc.kind == ArcKind::Label && arc.arcrole == CONCEPT_LABEL_ARCROLE {
                let concept = lookup(arc.link, &arc.from, &arc.location)?;
                let Some((role, text)) = label_resources.get(&(arc.link, arc.to.clone())) else {
                    continue;
                };
                labels
                    .entry(concept)
                    .or_default()
                    .entry(role.clone())
                    .or_insert_with(|| text.clone());
            }
        }

        let mut hasher = Sha256::new();
        let mut digests: Vec<(&String, &String)> = self
            .documents
            .iter()
            .map(|document| (&document.location, &document.sha256))
            .collect();
        digests.sort();
        for (location, digest) in digests {
            hasher.update(location.as_bytes());
            hasher.update(b"\0");
            hasher.update(digest.as_bytes());
            hasher.update(b"\n");
        }
        let digest = hex::encode(hasher.finalize());

        Ok(XbrlTaxonomy {
            entry_point: source.as_str(),
            target_namespace,
            concepts: self.concepts,
            type_bases: self.type_bases,
            presentation_arcs,
            calculation_arcs,
            labels,
            prefixes: self.prefixes,
            documents: self.documents,
            digest,
        })
    }
}

fn parse_order(order: Option<&str>) -> Option<f64> {
    order.and_then(|value| value.trim().parse::<f64>().ok())
}

// ---------------------------------------------------------------------------
// Minimal XML scope/attribute helpers (shared with the instance parser)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct NamespaceScope {
    frames: Vec<BTreeMap<String, String>>,
}

impl NamespaceScope {
    fn resolve(&self, prefix: &str) -> Option<&str> {
        self.frames
            .iter()
            .rev()
            .find_map(|frame| frame.get(prefix))
            .map(String::as_str)
            .filter(|namespace| !namespace.is_empty())
    }

    fn push(&mut self, declarations: BTreeMap<String, String>) -> bool {
        if declarations.is_empty() {
            false
        } else {
            self.frames.push(declarations);
            true
        }
    }

    fn pop(&mut self, pushed: bool) {
        if pushed {
            self.frames.pop();
        }
    }
}

#[derive(Debug, Default, Clone)]
struct AttributeSet {
    unprefixed: BTreeMap<String, String>,
    namespaced: Vec<(String, String, String)>,
    namespace_declarations: BTreeMap<String, String>,
}

impl AttributeSet {
    fn get(&self, local: &str) -> Option<&str> {
        self.unprefixed.get(local).map(String::as_str)
    }

    fn get_ns(&self, namespace: &str, local: &str) -> Option<&str> {
        self.namespaced
            .iter()
            .find(|(bound, name, _)| bound == namespace && name == local)
            .map(|(_, _, value)| value.as_str())
    }

    fn bool_attr(&self, local: &str) -> bool {
        matches!(self.get(local).map(str::trim), Some("true") | Some("1"))
    }
}

fn collect_attributes(
    start: &quick_xml::events::BytesStart<'_>,
    scope: &NamespaceScope,
) -> Result<AttributeSet, String> {
    let mut attributes = AttributeSet::default();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| format!("malformed attribute: {error}"))?;
        let key = attribute.key;
        let key_name = String::from_utf8_lossy(key.as_ref()).into_owned();
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|error| format!("malformed attribute value: {error}"))?
            .into_owned();
        if key_name == "xmlns" {
            attributes
                .namespace_declarations
                .insert(String::new(), value);
            continue;
        }
        if let Some(prefix) = key_name.strip_prefix("xmlns:") {
            attributes
                .namespace_declarations
                .insert(prefix.to_string(), value);
            continue;
        }
        match key.prefix() {
            Some(prefix) => {
                let prefix = String::from_utf8_lossy(prefix.as_ref()).into_owned();
                let namespace = scope
                    .resolve(&prefix)
                    .ok_or_else(|| format!("attribute {key_name} uses unbound prefix {prefix:?}"))?;
                let local = String::from_utf8_lossy(key.local_name().as_ref()).into_owned();
                attributes
                    .namespaced
                    .push((namespace.to_string(), local, value));
            }
            None => {
                attributes.unprefixed.insert(key_name, value);
            }
        }
    }
    Ok(attributes)
}

fn decode_text(text: &quick_xml::events::BytesText<'_>) -> Result<String, String> {
    let decoded = text
        .decode()
        .map_err(|error| format!("malformed text content: {error}"))?;
    quick_xml::escape::unescape(&decoded)
        .map(|cow| cow.into_owned())
        .map_err(|error| format!("malformed entity reference: {error}"))
}
