//! XBRL 2.1 instance documents: the context/unit/fact model, a parser, and
//! validation against a loaded taxonomy plus the ApexMail extension schema.
//!
//! Facts are only meaningful relative to a taxonomy: a fact is
//! `(concept QName, context, unit, value, decimals)`. The validator refuses
//! any fact whose concept is not declared, whose context does not match the
//! concept's `periodType`, whose unit/decimals shape does not fit the concept
//! type, and reports calculation-linkbase inconsistencies naming the concepts
//! and the amounts involved. It never silently fixes a value.
//!
//! Structural requirements (an entity identifier and scheme for every
//! context, a period per context, resolvable context/unit references, unique
//! ids, non-empty unit measures) are checked here too.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    collect_attributes, decode_text, AttributeSet, CalculationArc, DecimalAmount, DeclaredConcept,
    NamespaceScope, NumericKind, PeriodType, QName, XbrlTaxonomy, XBRL_INSTANCE_NAMESPACE,
    XBRL_LINKBASE_NAMESPACE, XBRL_XLINK_NAMESPACE,
};

// ---------------------------------------------------------------------------
// Stable validation-failure codes
// ---------------------------------------------------------------------------

pub const FAIL_CONCEPT_UNDECLARED: &str = "concept_undeclared";
pub const FAIL_ABSTRACT_CONCEPT: &str = "concept_abstract";
pub const FAIL_CONCEPT_NOT_ITEM: &str = "concept_not_item";
pub const FAIL_MISSING_PERIOD_TYPE: &str = "missing_period_type";
pub const FAIL_PERIOD_TYPE_MISMATCH: &str = "period_type_mismatch";
pub const FAIL_UNKNOWN_CONTEXT: &str = "unknown_context";
pub const FAIL_MISSING_ENTITY_IDENTIFIER: &str = "missing_entity_identifier";
pub const FAIL_MISSING_ENTITY_SCHEME: &str = "missing_entity_scheme";
pub const FAIL_EMPTY_CONTEXT_ID: &str = "empty_context_id";
pub const FAIL_DUPLICATE_CONTEXT: &str = "duplicate_context";
pub const FAIL_MISSING_CONTEXT_PERIOD: &str = "missing_context_period";
pub const FAIL_CONTEXT_PERIOD_INVALID: &str = "context_period_invalid";
pub const FAIL_MISSING_UNIT: &str = "missing_unit";
pub const FAIL_UNKNOWN_UNIT: &str = "unknown_unit";
pub const FAIL_MISSING_UNIT_MEASURE: &str = "missing_unit_measure";
pub const FAIL_DUPLICATE_UNIT: &str = "duplicate_unit";
pub const FAIL_MISSING_DECIMALS: &str = "missing_decimals";
pub const FAIL_UNEXPECTED_UNIT: &str = "unexpected_unit";
pub const FAIL_UNEXPECTED_DECIMALS: &str = "unexpected_decimals";
pub const FAIL_NON_NUMERIC_VALUE: &str = "non_numeric_value";
pub const FAIL_DUPLICATE_FACT: &str = "duplicate_fact";
pub const FAIL_CALCULATION_MISMATCH: &str = "calculation_mismatch";
pub const FAIL_CALCULATION_OVERFLOW: &str = "calculation_overflow";
pub const FAIL_BINDING_MISSING: &str = "binding_missing";
pub const FAIL_BINDING_INVALID: &str = "binding_invalid";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed instance-parsing failure; hostile XML never panics.
#[derive(Debug, Error)]
pub enum InstanceError {
    #[error("instance is not well-formed XML: {detail}")]
    MalformedXml { detail: String },
    #[error("root element {found} is not an XBRL instance ({XBRL_INSTANCE_NAMESPACE}xbrl)")]
    NotAnInstance { found: String },
    #[error("instance context {id:?} is malformed: {detail}")]
    MalformedContext { id: String, detail: String },
    #[error("instance fact {fact} is malformed: {detail}")]
    MalformedFact { fact: String, detail: String },
    #[error("instance document ended with unclosed elements")]
    Unbalanced,
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// The period of an XBRL context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPeriod {
    Instant {
        date: NaiveDate,
    },
    Duration {
        start: NaiveDate,
        end: NaiveDate,
    },
}

impl ContextPeriod {
    pub fn period_type(self) -> PeriodType {
        match self {
            Self::Instant { .. } => PeriodType::Instant,
            Self::Duration { .. } => PeriodType::Duration,
        }
    }

    /// Human-readable description used in validation messages.
    pub fn describe(self) -> String {
        match self {
            Self::Instant { date } => format!("instant {date}"),
            Self::Duration { start, end } => format!("duration {start}..{end}"),
        }
    }
}

/// One `xbrli:context`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub id: String,
    pub entity_identifier: Option<String>,
    pub entity_scheme: Option<String>,
    pub period: Option<ContextPeriod>,
}

/// One `xbrli:unit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    pub id: String,
    pub measures: Vec<String>,
}

/// The `decimals` attribute of a numeric fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decimals {
    Finite(i32),
    Infinite,
}

impl Decimals {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("INF") {
            return Some(Self::Infinite);
        }
        value.parse::<i32>().ok().map(Self::Finite)
    }
}

/// A fact value: an exact decimal or text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactValue {
    Numeric(DecimalAmount),
    Text(String),
}

impl FactValue {
    pub fn as_numeric(&self) -> Option<DecimalAmount> {
        match self {
            Self::Numeric(value) => Some(*value),
            Self::Text(_) => None,
        }
    }
}

/// One fact in an instance document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub concept: QName,
    pub context_ref: String,
    pub unit_ref: Option<String>,
    pub value: FactValue,
    pub decimals: Option<Decimals>,
    pub id: Option<String>,
}

/// A parsed (or emitter-built) instance document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceDocument {
    pub contexts: Vec<Context>,
    pub units: Vec<Unit>,
    pub facts: Vec<Fact>,
    pub schema_refs: Vec<String>,
    /// Prefix -> namespace declarations on the instance root.
    pub namespaces: BTreeMap<String, String>,
}

impl InstanceDocument {
    pub fn empty() -> Self {
        Self {
            contexts: Vec::new(),
            units: Vec::new(),
            facts: Vec::new(),
            schema_refs: Vec::new(),
            namespaces: BTreeMap::new(),
        }
    }
}

/// Concepts declared by the ApexMail extension schema that accompanies an
/// emitted instance. Extension facts are validated against these declarations
/// exactly like taxonomy facts are validated against the taxonomy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionSchema {
    pub target_namespace: String,
    pub concepts: BTreeMap<QName, DeclaredConcept>,
}

impl ExtensionSchema {
    pub fn declare(&self, qname: &QName) -> Option<&DeclaredConcept> {
        self.concepts.get(qname)
    }

    pub fn insert(&mut self, concept: DeclaredConcept) {
        self.concepts.insert(concept.qname.clone(), concept);
    }

    pub fn len(&self) -> usize {
        self.concepts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.concepts.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an XBRL 2.1 instance document. Typed errors only; malformed input
/// never panics.
pub fn parse_instance(xml: &str) -> Result<InstanceDocument, InstanceError> {
    let mut reader = quick_xml::NsReader::from_str(xml);
    let mut parser = InstanceParser {
        document: InstanceDocument::empty(),
        scope: NamespaceScope::default(),
        frames: Vec::new(),
        pending_context: None,
        pending_unit: None,
        pending_fact: None,
        text_slot: None,
        text_buffer: String::new(),
    };
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| InstanceError::MalformedXml {
                detail: error.to_string(),
            })?;
        let element_namespace: Option<String> = match &resolved {
            quick_xml::name::ResolveResult::Bound(namespace) => {
                Some(String::from_utf8_lossy(namespace.as_ref()).into_owned())
            }
            quick_xml::name::ResolveResult::Unbound => None,
            quick_xml::name::ResolveResult::Unknown(prefix) => {
                return Err(InstanceError::MalformedXml {
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
                if parser.text_slot.is_some() {
                    parser
                        .text_buffer
                        .push_str(&String::from_utf8_lossy(text.as_ref()));
                }
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }
    if !parser.frames.is_empty() {
        return Err(InstanceError::Unbalanced);
    }
    Ok(parser.document)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextSlot {
    Identifier,
    Instant,
    StartDate,
    EndDate,
    Measure,
    FactValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameRole {
    Root,
    Context,
    Entity,
    Identifier,
    Period,
    Instant,
    StartDate,
    EndDate,
    Unit,
    Measure,
    SchemaRef,
    Fact,
    Tuple,
    Other,
}

struct InstanceFrame {
    namespace_frame: bool,
    role: FrameRole,
}

#[derive(Debug, Default)]
struct PartialContext {
    id: String,
    identifier: Option<String>,
    scheme: Option<String>,
    instant: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

#[derive(Debug, Default)]
struct PartialUnit {
    id: String,
    measures: Vec<String>,
}

#[derive(Debug)]
struct PartialFact {
    concept: QName,
    context_ref: String,
    unit_ref: Option<String>,
    decimals: Option<Decimals>,
    id: Option<String>,
}

struct InstanceParser {
    document: InstanceDocument,
    scope: NamespaceScope,
    frames: Vec<InstanceFrame>,
    pending_context: Option<PartialContext>,
    pending_unit: Option<PartialUnit>,
    pending_fact: Option<PartialFact>,
    text_slot: Option<TextSlot>,
    text_buffer: String,
}

impl InstanceParser {
    fn on_start(
        &mut self,
        start: &quick_xml::events::BytesStart<'_>,
        namespace: Option<&str>,
    ) -> Result<(), InstanceError> {
        let attributes =
            collect_attributes(start, &self.scope).map_err(|detail| InstanceError::MalformedXml {
                detail,
            })?;
        let pushed = self.scope.push(attributes.namespace_declarations.clone());
        let local = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
        let qname = QName::new(namespace.unwrap_or(""), local);
        let is_root = self.frames.is_empty();
        if is_root {
            if qname.namespace != XBRL_INSTANCE_NAMESPACE || qname.name != "xbrl" {
                return Err(InstanceError::NotAnInstance {
                    found: qname.clark(),
                });
            }
            for (prefix, namespace) in &attributes.namespace_declarations {
                if !namespace.is_empty() {
                    self.document
                        .namespaces
                        .entry(prefix.clone())
                        .or_insert_with(|| namespace.clone());
                }
            }
        }
        let parent_role = self
            .frames
            .last()
            .map(|frame| frame.role)
            .unwrap_or(FrameRole::Other);
        let role = if is_root {
            FrameRole::Root
        } else {
            self.begin_child(parent_role, &qname, &attributes)?
        };
        self.frames.push(InstanceFrame {
            namespace_frame: pushed,
            role,
        });
        Ok(())
    }

    fn begin_child(
        &mut self,
        parent_role: FrameRole,
        qname: &QName,
        attributes: &AttributeSet,
    ) -> Result<FrameRole, InstanceError> {
        let in_instance_namespace = qname.namespace == XBRL_INSTANCE_NAMESPACE;
        let in_standard_namespace = matches!(
            qname.namespace.as_str(),
            XBRL_INSTANCE_NAMESPACE | XBRL_LINKBASE_NAMESPACE | XBRL_XLINK_NAMESPACE
        );
        match parent_role {
            FrameRole::Root => {
                if in_instance_namespace && qname.name == "context" {
                    let id = attributes.get("id").unwrap_or("").to_string();
                    self.pending_context = Some(PartialContext {
                        id,
                        ..PartialContext::default()
                    });
                    Ok(FrameRole::Context)
                } else if in_instance_namespace && qname.name == "unit" {
                    let id = attributes.get("id").unwrap_or("").to_string();
                    self.pending_unit = Some(PartialUnit {
                        id,
                        measures: Vec::new(),
                    });
                    Ok(FrameRole::Unit)
                } else if qname.namespace == XBRL_LINKBASE_NAMESPACE && qname.name == "schemaRef" {
                    if let Some(href) = attributes.get_ns(XBRL_XLINK_NAMESPACE, "href") {
                        self.document.schema_refs.push(href.to_string());
                    }
                    Ok(FrameRole::SchemaRef)
                } else if in_standard_namespace {
                    Ok(FrameRole::Other)
                } else {
                    self.pending_fact = Some(PartialFact {
                        concept: qname.clone(),
                        context_ref: attributes
                            .get("contextRef")
                            .unwrap_or("")
                            .to_string(),
                        unit_ref: attributes.get("unitRef").map(str::to_string),
                        decimals: attributes.get("decimals").and_then(Decimals::parse),
                        id: attributes.get("id").map(str::to_string),
                    });
                    self.text_slot = Some(TextSlot::FactValue);
                    self.text_buffer.clear();
                    Ok(FrameRole::Fact)
                }
            }
            FrameRole::Context => {
                if in_instance_namespace && qname.name == "entity" {
                    Ok(FrameRole::Entity)
                } else if in_instance_namespace && qname.name == "identifier" {
                    if let Some(context) = self.pending_context.as_mut() {
                        context.scheme = attributes.get("scheme").map(str::to_string);
                    }
                    self.text_slot = Some(TextSlot::Identifier);
                    self.text_buffer.clear();
                    Ok(FrameRole::Identifier)
                } else if in_instance_namespace && qname.name == "period" {
                    Ok(FrameRole::Period)
                } else {
                    Ok(FrameRole::Other)
                }
            }
            FrameRole::Entity => {
                if in_instance_namespace && qname.name == "identifier" {
                    if let Some(context) = self.pending_context.as_mut() {
                        context.scheme = attributes.get("scheme").map(str::to_string);
                    }
                    self.text_slot = Some(TextSlot::Identifier);
                    self.text_buffer.clear();
                    Ok(FrameRole::Identifier)
                } else {
                    Ok(FrameRole::Other)
                }
            }
            FrameRole::Period => {
                if in_instance_namespace && qname.name == "instant" {
                    self.text_slot = Some(TextSlot::Instant);
                    self.text_buffer.clear();
                    Ok(FrameRole::Instant)
                } else if in_instance_namespace && qname.name == "startDate" {
                    self.text_slot = Some(TextSlot::StartDate);
                    self.text_buffer.clear();
                    Ok(FrameRole::StartDate)
                } else if in_instance_namespace && qname.name == "endDate" {
                    self.text_slot = Some(TextSlot::EndDate);
                    self.text_buffer.clear();
                    Ok(FrameRole::EndDate)
                } else {
                    Ok(FrameRole::Other)
                }
            }
            FrameRole::Unit => {
                if in_instance_namespace && qname.name == "measure" {
                    self.text_slot = Some(TextSlot::Measure);
                    self.text_buffer.clear();
                    Ok(FrameRole::Measure)
                } else {
                    Ok(FrameRole::Other)
                }
            }
            FrameRole::Fact => {
                // An element inside a fact means the parent is a tuple, not a
                // simple fact: drop the fact and ignore the subtree.
                if let Some(frame) = self.frames.last_mut() {
                    frame.role = FrameRole::Tuple;
                }
                self.pending_fact = None;
                self.text_slot = None;
                self.text_buffer.clear();
                Ok(FrameRole::Tuple)
            }
            _ => Ok(FrameRole::Other),
        }
    }

    fn on_text(&mut self, text: &quick_xml::events::BytesText<'_>) -> Result<(), InstanceError> {
        if self.text_slot.is_some() {
            let decoded =
                decode_text(text).map_err(|detail| InstanceError::MalformedXml { detail })?;
            self.text_buffer.push_str(&decoded);
        }
        Ok(())
    }

    fn take_text(&mut self) -> String {
        self.text_slot = None;
        std::mem::take(&mut self.text_buffer)
    }

    fn on_end(&mut self) -> Result<(), InstanceError> {
        let Some(frame) = self.frames.pop() else {
            return Err(InstanceError::Unbalanced);
        };
        match frame.role {
            FrameRole::Identifier => {
                let text = self.take_text();
                if let Some(context) = self.pending_context.as_mut() {
                    context.identifier = Some(text.trim().to_string());
                }
            }
            FrameRole::Instant => {
                let text = self.take_text();
                if let Some(context) = self.pending_context.as_mut() {
                    context.instant = Some(text.trim().to_string());
                }
            }
            FrameRole::StartDate => {
                let text = self.take_text();
                if let Some(context) = self.pending_context.as_mut() {
                    context.start = Some(text.trim().to_string());
                }
            }
            FrameRole::EndDate => {
                let text = self.take_text();
                if let Some(context) = self.pending_context.as_mut() {
                    context.end = Some(text.trim().to_string());
                }
            }
            FrameRole::Measure => {
                let text = self.take_text();
                if let Some(unit) = self.pending_unit.as_mut() {
                    unit.measures.push(text.trim().to_string());
                }
            }
            FrameRole::Fact => {
                let text = self.take_text();
                if let Some(pending) = self.pending_fact.take() {
                    let text = text.trim().to_string();
                    let value = match DecimalAmount::parse(&text) {
                        Some(amount) => FactValue::Numeric(amount),
                        None => FactValue::Text(text),
                    };
                    self.document.facts.push(Fact {
                        concept: pending.concept,
                        context_ref: pending.context_ref,
                        unit_ref: pending.unit_ref,
                        value,
                        decimals: pending.decimals,
                        id: pending.id,
                    });
                }
            }
            FrameRole::Context => {
                let Some(pending) = self.pending_context.take() else {
                    self.scope.pop(frame.namespace_frame);
                    return Ok(());
                };
                let period = match (&pending.instant, &pending.start, &pending.end) {
                    (Some(instant), _, _) => Some(ContextPeriod::Instant {
                        date: parse_date(instant, &pending.id)?,
                    }),
                    (None, Some(start), Some(end)) => Some(ContextPeriod::Duration {
                        start: parse_date(start, &pending.id)?,
                        end: parse_date(end, &pending.id)?,
                    }),
                    _ => None,
                };
                self.document.contexts.push(Context {
                    id: pending.id,
                    entity_identifier: pending.identifier,
                    entity_scheme: pending.scheme,
                    period,
                });
            }
            FrameRole::Unit => {
                if let Some(unit) = self.pending_unit.take() {
                    self.document.units.push(Unit {
                        id: unit.id,
                        measures: unit.measures,
                    });
                }
            }
            _ => {
                if self.text_slot.is_some() {
                    self.take_text();
                }
            }
        }
        self.scope.pop(frame.namespace_frame);
        Ok(())
    }
}

fn parse_date(value: &str, context_id: &str) -> Result<NaiveDate, InstanceError> {
    NaiveDate::parse_from_str(value.trim(), "%Y-%m-%d").map_err(|error| {
        InstanceError::MalformedContext {
            id: context_id.to_string(),
            detail: format!("date {value:?} is not an XML Schema date: {error}"),
        }
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// One validation failure. `code` is a stable machine identifier, `message`
/// names the concepts/contexts and amounts involved, and the concept/amount
/// vectors carry the raw values for machine consumers.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct ValidationFailure {
    pub code: String,
    pub message: String,
    pub concepts: Vec<String>,
    pub amounts: Vec<String>,
}

impl ValidationFailure {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            concepts: Vec::new(),
            amounts: Vec::new(),
        }
    }

    pub fn with_concepts(mut self, concepts: Vec<String>) -> Self {
        self.concepts = concepts;
        self
    }

    pub fn with_amounts(mut self, amounts: Vec<String>) -> Self {
        self.amounts = amounts;
        self
    }
}

/// Honest readiness statement derived from the taxonomy and the validation
/// result. `submission_ready` is true only when a taxonomy is loaded, the
/// concept binding resolved, and every fact validated against that taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XbrlReadiness {
    pub submission_ready: bool,
    pub taxonomy: Option<super::TaxonomyIdentity>,
    pub missing: Vec<String>,
    pub validation_failures: Vec<ValidationFailure>,
}

impl XbrlReadiness {
    pub fn not_ready(missing: Vec<String>) -> Self {
        Self {
            submission_ready: false,
            taxonomy: None,
            missing,
            validation_failures: Vec::new(),
        }
    }

    /// A one-line explanation for documents/instance comments.
    pub fn summary(&self) -> String {
        if self.submission_ready {
            return "submission-ready for the configured taxonomy".to_string();
        }
        if let Some(missing) = self.missing.first() {
            return format!("not submission-ready: {missing}");
        }
        if let Some(failure) = self.validation_failures.first() {
            return format!(
                "not submission-ready: {} validation failure(s), first: {} ({})",
                self.validation_failures.len(),
                failure.message,
                failure.code
            );
        }
        "not submission-ready: no taxonomy was configured".to_string()
    }
}

/// Validate every fact, context, unit and calculation relationship of an
/// instance against the loaded taxonomy and the extension schema that
/// accompanies the instance. The returned failures are deterministic and
/// sorted; the validator never mutates the instance.
pub fn validate_instance(
    taxonomy: &XbrlTaxonomy,
    extensions: &ExtensionSchema,
    instance: &InstanceDocument,
) -> Vec<ValidationFailure> {
    let mut failures: Vec<ValidationFailure> = Vec::new();
    let display = |qname: &QName| -> String {
        if qname.namespace == extensions.target_namespace {
            format!("apex:{}", qname.name)
        } else {
            taxonomy.display_name(qname)
        }
    };

    // -- Contexts: unique ids, entity identifier + scheme, period presence.
    let mut context_ids: BTreeSet<&str> = BTreeSet::new();
    for context in &instance.contexts {
        if context.id.trim().is_empty() {
            failures.push(ValidationFailure::new(
                FAIL_EMPTY_CONTEXT_ID,
                "an xbrli:context has an empty id",
            ));
        } else if !context_ids.insert(context.id.as_str()) {
            failures.push(ValidationFailure::new(
                FAIL_DUPLICATE_CONTEXT,
                format!("context id {:?} is declared more than once", context.id),
            ));
        }
        if context
            .entity_identifier
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            failures.push(ValidationFailure::new(
                FAIL_MISSING_ENTITY_IDENTIFIER,
                format!(
                    "context {:?} carries no xbrli:entity/xbrli:identifier; every context must \
                     identify the reporting entity",
                    context.id
                ),
            ));
        }
        if context
            .entity_scheme
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            failures.push(ValidationFailure::new(
                FAIL_MISSING_ENTITY_SCHEME,
                format!(
                    "context {:?} carries no identifier scheme; XBRL requires the scheme that \
                     issued the entity identifier",
                    context.id
                ),
            ));
        }
        match context.period {
            None => failures.push(ValidationFailure::new(
                FAIL_MISSING_CONTEXT_PERIOD,
                format!("context {:?} declares no period", context.id),
            )),
            Some(ContextPeriod::Duration { start, end }) if end < start => {
                failures.push(ValidationFailure::new(
                    FAIL_CONTEXT_PERIOD_INVALID,
                    format!(
                        "context {:?} has a reversed duration {start}..{end}",
                        context.id
                    ),
                ));
            }
            Some(_) => {}
        }
    }

    // -- Units: unique ids and a measure.
    let mut unit_ids: BTreeSet<&str> = BTreeSet::new();
    for unit in &instance.units {
        if !unit_ids.insert(unit.id.as_str()) {
            failures.push(ValidationFailure::new(
                FAIL_DUPLICATE_UNIT,
                format!("unit id {:?} is declared more than once", unit.id),
            ));
        }
        if unit.measures.is_empty() {
            failures.push(ValidationFailure::new(
                FAIL_MISSING_UNIT_MEASURE,
                format!("unit {:?} declares no xbrli:measure", unit.id),
            ));
        }
    }

    let contexts: BTreeMap<&str, &Context> = instance
        .contexts
        .iter()
        .map(|context| (context.id.as_str(), context))
        .collect();
    let units: BTreeMap<&str, &Unit> = instance
        .units
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect();

    // -- Facts.
    let mut seen_facts: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut numeric_values: BTreeMap<(&str, &str), BTreeMap<&QName, DecimalAmount>> =
        BTreeMap::new();
    for fact in &instance.facts {
        let declaration = taxonomy
            .declare(&fact.concept)
            .or_else(|| extensions.declare(&fact.concept).cloned());
        let fact_name = display(&fact.concept);
        let duplicate_key = (
            fact.concept.clark(),
            fact.context_ref.clone(),
            fact.unit_ref.clone().unwrap_or_default(),
        );
        if !seen_facts.insert(duplicate_key) {
            failures.push(
                ValidationFailure::new(
                    FAIL_DUPLICATE_FACT,
                    format!(
                        "fact {fact_name} is reported more than once for context {:?} and unit \
                         {:?}; duplicate facts are ambiguous",
                        fact.context_ref,
                        fact.unit_ref.as_deref().unwrap_or("<none>")
                    ),
                )
                .with_concepts(vec![fact_name.clone()]),
            );
        }

        let context = contexts.get(fact.context_ref.as_str()).copied();
        if context.is_none() {
            failures.push(
                ValidationFailure::new(
                    FAIL_UNKNOWN_CONTEXT,
                    format!(
                        "fact {fact_name} references context {:?}, which the instance does not \
                         declare",
                        fact.context_ref
                    ),
                )
                .with_concepts(vec![fact_name.clone()]),
            );
        }

        match &declaration {
            None => {
                failures.push(
                    ValidationFailure::new(
                        FAIL_CONCEPT_UNDECLARED,
                        format!(
                            "fact concept {fact_name} is not declared by the loaded taxonomy \
                             (target namespace {}) nor by the ApexMail extension schema; \
                             undeclared element names are refused, never guessed",
                            taxonomy.target_namespace
                        ),
                    )
                    .with_concepts(vec![fact_name.clone(), fact.concept.clark()]),
                );
                continue;
            }
            Some(declared) => {
                if declared.is_abstract {
                    failures.push(
                        ValidationFailure::new(
                            FAIL_ABSTRACT_CONCEPT,
                            format!(
                                "fact {fact_name} uses an abstract concept; abstract concepts \
                                 cannot carry facts"
                            ),
                        )
                        .with_concepts(vec![fact_name.clone()]),
                    );
                    continue;
                }
                if !declared.is_item {
                    failures.push(
                        ValidationFailure::new(
                            FAIL_CONCEPT_NOT_ITEM,
                            format!(
                                "fact {fact_name} uses a concept that is not an XBRL item \
                                 (substitution group xbrli:item)"
                            ),
                        )
                        .with_concepts(vec![fact_name.clone()]),
                    );
                    continue;
                }
                if declared.period_type.is_none() {
                    failures.push(
                        ValidationFailure::new(
                            FAIL_MISSING_PERIOD_TYPE,
                            format!(
                                "concept {fact_name} declares no xbrli:periodType; the fact \
                                 context cannot be validated"
                            ),
                        )
                        .with_concepts(vec![fact_name.clone()]),
                    );
                }
                // Period type must match the context.
                if let (Some(declared_period), Some(context)) =
                    (declared.period_type, context)
                {
                    if let Some(actual_period) = context.period {
                        let actual_type = actual_period.period_type();
                        if declared_period != actual_type {
                            failures.push(
                                ValidationFailure::new(
                                    FAIL_PERIOD_TYPE_MISMATCH,
                                    format!(
                                        "concept {fact_name} is {} but context {:?} reports a \
                                         {}; an {} concept cannot be reported with a {} context",
                                        declared_period.as_str(),
                                        fact.context_ref,
                                        actual_period.describe(),
                                        declared_period.as_str(),
                                        actual_type.as_str()
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            );
                        }
                    }
                }
                // Unit/decimals rules follow the declared type.
                match declared.numeric {
                    Some(_) => {
                        match fact.unit_ref.as_deref() {
                            None => failures.push(
                                ValidationFailure::new(
                                    FAIL_MISSING_UNIT,
                                    format!(
                                        "numeric fact {fact_name} has no unitRef; a numeric fact \
                                         must report the unit it is measured in"
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            ),
                            Some(unit_ref) => {
                                if !units.contains_key(unit_ref) {
                                    failures.push(
                                        ValidationFailure::new(
                                            FAIL_UNKNOWN_UNIT,
                                            format!(
                                                "fact {fact_name} references unit {unit_ref:?}, \
                                                 which the instance does not declare"
                                            ),
                                        )
                                        .with_concepts(vec![fact_name.clone()]),
                                    );
                                } else if let Some(value) = fact.value.as_numeric() {
                                    numeric_values
                                        .entry((
                                            fact.context_ref.as_str(),
                                            fact.unit_ref.as_deref().unwrap_or(""),
                                        ))
                                        .or_default()
                                        .insert(&fact.concept, value);
                                }
                            }
                        }
                        if fact.decimals.is_none() {
                            failures.push(
                                ValidationFailure::new(
                                    FAIL_MISSING_DECIMALS,
                                    format!(
                                        "numeric fact {fact_name} carries no decimals attribute; \
                                         the accuracy of the reported amount is undefined"
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            );
                        }
                        if fact.value.as_numeric().is_none() {
                            failures.push(
                                ValidationFailure::new(
                                    FAIL_NON_NUMERIC_VALUE,
                                    format!(
                                        "fact {fact_name} is numeric but its value is not a \
                                         decimal number"
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            );
                        }
                    }
                    None => {
                        if let Some(unit_ref) = fact.unit_ref.as_deref() {
                            failures.push(
                                ValidationFailure::new(
                                    FAIL_UNEXPECTED_UNIT,
                                    format!(
                                        "non-numeric fact {fact_name} carries unitRef \
                                         {unit_ref:?}; non-monetary concepts carry no unit"
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            );
                        }
                        if fact.decimals.is_some() {
                            failures.push(
                                ValidationFailure::new(
                                    FAIL_UNEXPECTED_DECIMALS,
                                    format!(
                                        "non-numeric fact {fact_name} carries a decimals \
                                         attribute; decimals apply to numeric facts only"
                                    ),
                                )
                                .with_concepts(vec![fact_name.clone()]),
                            );
                        }
                    }
                }
            }
        }
    }

    // -- Calculation linkbase: parent = sum of weighted children.
    let mut arcs_by_parent: BTreeMap<&QName, Vec<&CalculationArc>> = BTreeMap::new();
    for arc in &taxonomy.calculation_arcs {
        arcs_by_parent.entry(&arc.parent).or_default().push(arc);
    }
    for ((context_id, unit_id), values) in &numeric_values {
        for (parent, arcs) in &arcs_by_parent {
            let Some(parent_value) = values.get(*parent).copied() else {
                continue;
            };
            let mut sum = DecimalAmount::zero();
            let mut terms: Vec<String> = Vec::new();
            let mut concepts: Vec<String> = vec![display(parent)];
            let mut overflow = false;
            for arc in arcs {
                let child_value = values
                    .get(&arc.child)
                    .copied()
                    .unwrap_or_else(DecimalAmount::zero);
                let signed = match child_value.checked_mul(arc.weight) {
                    Some(value) => value,
                    None => {
                        overflow = true;
                        break;
                    }
                };
                sum = match sum.checked_add(signed) {
                    Some(value) => value,
                    None => {
                        overflow = true;
                        break;
                    }
                };
                terms.push(format!(
                    "{} * {} = {}",
                    display(&arc.child),
                    arc.weight.to_display(),
                    signed.to_display()
                ));
                concepts.push(display(&arc.child));
            }
            if overflow {
                failures.push(
                    ValidationFailure::new(
                        FAIL_CALCULATION_OVERFLOW,
                        format!(
                            "calculation for {} in context {context_id:?} overflows the exact \
                             decimal range; the amounts cannot be verified",
                            display(parent)
                        ),
                    )
                    .with_concepts(concepts),
                );
                continue;
            }
            if sum != parent_value {
                failures.push(
                    ValidationFailure::new(
                        FAIL_CALCULATION_MISMATCH,
                        format!(
                            "calculation mismatch for {} in context {context_id:?} (unit \
                             {unit_id:?}): the fact reports {} but the calculation linkbase sums \
                             {} to {}; the reported value is not silently adjusted",
                            display(parent),
                            parent_value.to_display(),
                            terms.join(" + "),
                            sum.to_display()
                        ),
                    )
                    .with_concepts(concepts)
                    .with_amounts(vec![
                        parent_value.to_display(),
                        sum.to_display(),
                    ]),
                );
            }
        }
    }

    failures.sort();
    failures.dedup();
    failures
}

/// Numeric kind of a concept as used by validation messages/tests.
pub fn numeric_kind_of(taxonomy: &XbrlTaxonomy, qname: &QName) -> Option<NumericKind> {
    taxonomy.numeric_kind(qname)
}

/// Read a fact's declared concept from the taxonomy (helper for tests).
pub fn declared_concept(taxonomy: &XbrlTaxonomy, qname: &QName) -> Option<DeclaredConcept> {
    taxonomy.declare(qname)
}
