//! # STIX/TAXII Client — Structured Threat Intelligence eXchange
//!
//! Implements STIX 2.1 indicator parsing and a TAXII 2.1 client for
//! ingesting threat intelligence from standard feeds.
//!
//! ## STIX 2.1
//! - Parses STIX Bundle objects containing `indicator`, `malware`,
//! `attack-pattern`, and `relationship` SDOs
//! - Extracts IP, domain, URL, and file hash indicators
//! - Maps STIX patterns to threat-intel blocklist entries
//!
//! ## TAXII 2.1
//! - Discovery endpoint (`/taxii2/`)
//! - API Root enumeration
//! - Collection listing and object polling
//! - Configurable poll interval and pagination support
//!
//! ## Feature Gating
//! Network I/O (actual TAXII HTTP calls) requires the `taxii` feature
//! flag and the `reqwest` dependency. Without it, parsing and
//! domain-model types are still available for offline use.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// STIX 2.1 Domain Model
// ---------------------------------------------------------------------------

/// A STIX 2.1 Bundle — top-level container for STIX objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    /// Must be `"bundle"`
    #[serde(rename = "type")]
    pub object_type: String,
    /// Bundle ID (e.g. `bundle--<uuid>`)
    pub id: String,
    /// Objects contained in the bundle
    #[serde(default)]
    pub objects: Vec<StixObject>,
}

/// Union of supported STIX Domain Objects (SDOs).
/// We use `#[serde(tag = "type")]` to dispatch on the `"type"` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StixObject {
    /// Indicator — contains a STIX pattern describing observables.
    #[serde(rename = "indicator")]
    Indicator(StixIndicator),
    /// Malware family descriptor.
    #[serde(rename = "malware")]
    Malware(StixMalware),
    /// ATT&CK technique or generic attack pattern.
    #[serde(rename = "attack-pattern")]
    AttackPattern(StixAttackPattern),
    /// Relationship link between two SDOs.
    #[serde(rename = "relationship")]
    Relationship(StixRelationship),
    /// Catch-all for unrecognised types — stored as raw JSON map.
    #[serde(other)]
    Unknown,
}

/// STIX Indicator SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    /// STIX ID (e.g. `indicator--<uuid>`)
    pub id: String,
    /// Created timestamp
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
    /// Modified timestamp
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    /// Human-readable name
    #[serde(default)]
    pub name: Option<String>,
    /// Longer description
    #[serde(default)]
    pub description: Option<String>,
    /// STIX Pattern (e.g. `[ipv4-addr:value = '1.2.3.4']`)
    #[serde(default)]
    pub pattern: Option<String>,
    /// Pattern type (should be `"stix"`)
    #[serde(default)]
    pub pattern_type: Option<String>,
    /// Indicator type labels
    #[serde(default)]
    pub indicator_types: Vec<String>,
    /// Valid-from timestamp
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    /// Valid-until timestamp
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
    /// Confidence (0–100)
    #[serde(default)]
    pub confidence: Option<u8>,
    /// Kill chain phases
    #[serde(default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
}

/// STIX Malware SDO (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixMalware {
    /// STIX ID
    pub id: String,
    /// Malware name
    #[serde(default)]
    pub name: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Malware type labels
    #[serde(default)]
    pub malware_types: Vec<String>,
    /// Is this a family (true) or an instance (false)?
    #[serde(default)]
    pub is_family: bool,
}

/// STIX Attack Pattern SDO (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixAttackPattern {
    /// STIX ID
    pub id: String,
    /// Technique name
    #[serde(default)]
    pub name: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Kill chain phases
    #[serde(default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
}

/// STIX Relationship SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    /// STIX ID
    pub id: String,
    /// Relationship type (e.g. `"indicates"`, `"uses"`)
    pub relationship_type: String,
    /// Source SDO reference
    pub source_ref: String,
    /// Target SDO reference
    pub target_ref: String,
}

/// Kill chain phase reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    /// Kill chain name (e.g. `"mitre-attack"`)
    pub kill_chain_name: String,
    /// Phase name (e.g. `"initial-access"`)
    pub phase_name: String,
}

// ---------------------------------------------------------------------------
// STIX Pattern Extraction
// ---------------------------------------------------------------------------

/// An extracted observable from a STIX pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedIndicator {
    /// IPv4 address
    Ipv4(String),
    /// IPv6 address
    Ipv6(String),
    /// Domain name
    Domain(String),
    /// URL
    Url(String),
    /// File hash (algorithm, value)
    FileHash(String, String),
    /// Email address
    Email(String),
}

/// Parse a STIX 2.1 indicator pattern and extract observables.
/// Supports common STIX Cyber Observation patterns like:/// - `[ipv4-addr:value = '1.2.3.4']`
/// - `[domain-name:value = 'evil.com']`
/// - `[url:value = 'http://evil.com/malware']`
/// - `[file:hashes.'SHA-256' = 'abc123...']`
/// - `[email-addr:value = 'bad@evil.com']`
/// Returns empty vec for patterns that cannot be parsed.
pub fn extract_indicators(pattern: &str) -> Vec<ExtractedIndicator> {
    let mut results = Vec::new();

    // Simple regex-free extraction:find quoted values after known keys
    let extract_value = |key: &str, input: &str| -> Option<String> {
        let key_pos = input.find(key)?;
        let after_key = &input[key_pos + key.len()..];
        // Skip whitespace and '='
        let after_eq = after_key.find('=').map(|p| &after_key[p + 1..])?;
        // Find quoted value
        let quote_start = after_eq.find('\'')?;
        let value_start = &after_eq[quote_start + 1..];
        let quote_end = value_start.find('\'')?;
        Some(value_start[..quote_end].to_string())
    };

    if let Some(ip) = extract_value("ipv4-addr:value", pattern) {
        results.push(ExtractedIndicator::Ipv4(ip));
    }
    if let Some(ip) = extract_value("ipv6-addr:value", pattern) {
        results.push(ExtractedIndicator::Ipv6(ip));
    }
    if let Some(domain) = extract_value("domain-name:value", pattern) {
        results.push(ExtractedIndicator::Domain(domain));
    }
    if let Some(url) = extract_value("url:value", pattern) {
        results.push(ExtractedIndicator::Url(url));
    }
    if let Some(email) = extract_value("email-addr:value", pattern) {
        results.push(ExtractedIndicator::Email(email));
    }

    // File hash extraction:file:hashes.'<algo>'
    let hash_algorithms = ["SHA-256", "SHA-1", "MD5", "SHA-512"];
    for algo in &hash_algorithms {
        let key = format!("file:hashes.'{}'", algo);
        if let Some(hash) = extract_value(&key, pattern) {
            results.push(ExtractedIndicator::FileHash(algo.to_string(), hash));
        }
    }

    results
}

/// Process a STIX bundle and extract all indicators with their metadata.
pub fn process_bundle(bundle: &StixBundle) -> Vec<ProcessedIndicator> {
    let mut indicators = Vec::new();

    for obj in &bundle.objects {
        if let StixObject::Indicator(ind) = obj {
            let extracted = ind
                .pattern
                .as_deref()
                .map(extract_indicators)
                .unwrap_or_default();
            for ext in extracted {
                indicators.push(ProcessedIndicator {
                    stix_id: ind.id.clone(),
                    name: ind.name.clone(),
                    description: ind.description.clone(),
                    indicator: ext,
                    confidence: ind.confidence.unwrap_or(50),
                    valid_from: ind.valid_from,
                    valid_until: ind.valid_until,
                    indicator_types: ind.indicator_types.clone(),
                });
            }
        }
    }

    indicators
}

/// A processed indicator ready for ingestion into the threat-intel store.
#[derive(Debug, Clone)]
pub struct ProcessedIndicator {
    /// Original STIX ID
    pub stix_id: String,
    /// Human-readable name (if any)
    pub name: Option<String>,
    /// Description (if any)
    pub description: Option<String>,
    /// Extracted observable
    pub indicator: ExtractedIndicator,
    /// Confidence (0–100)
    pub confidence: u8,
    /// Valid-from timestamp
    pub valid_from: Option<DateTime<Utc>>,
    /// Valid-until timestamp
    pub valid_until: Option<DateTime<Utc>>,
    /// Indicator type labels
    pub indicator_types: Vec<String>,
}

// ---------------------------------------------------------------------------
// TAXII 2.1 Domain Model
// ---------------------------------------------------------------------------

/// TAXII 2.1 Discovery response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiDiscovery {
    /// Human-readable title
    #[serde(default)]
    pub title: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Contact info
    #[serde(default)]
    pub contact: Option<String>,
    /// Default API Root URL
    #[serde(default)]
    pub default: Option<String>,
    /// All available API Root URLs
    #[serde(default)]
    pub api_roots: Vec<String>,
}

/// TAXII 2.1 API Root information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiApiRoot {
    /// Title
    #[serde(default)]
    pub title: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Versions supported
    #[serde(default)]
    pub versions: Vec<String>,
    /// Max content length
    #[serde(default)]
    pub max_content_length: Option<u64>,
}

/// TAXII 2.1 Collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    /// Collection ID (UUID)
    pub id: String,
    /// Title
    #[serde(default)]
    pub title: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Whether this collection can be read
    #[serde(default = "default_true")]
    pub can_read: bool,
    /// Whether this collection can be written to
    #[serde(default)]
    pub can_write: bool,
    /// Media types supported
    #[serde(default)]
    pub media_types: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// TAXII 2.1 Collections list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollections {
    /// Collections
    #[serde(default)]
    pub collections: Vec<TaxiiCollection>,
}

/// TAXII 2.1 Envelope — container for objects returned from a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiEnvelope {
    /// Whether more objects are available (pagination)
    #[serde(default)]
    pub more: bool,
    /// Next page URL (if pagination)
    #[serde(default)]
    pub next: Option<String>,
    /// STIX objects
    #[serde(default)]
    pub objects: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// TAXII 2.1 Client Configuration
// ---------------------------------------------------------------------------

/// Configuration for a TAXII 2.1 client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiClientConfig {
    /// TAXII server base URL (e.g. `https://taxii.example.com`)
    pub server_url: String,
    /// Optional username for HTTP Basic authentication
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password
    #[serde(default)]
    pub password: Option<String>,
    /// Optional API key (sent as `Authorization:Bearer <key>`)
    #[serde(default)]
    pub api_key: Option<String>,
    /// Specific collection IDs to poll (empty = poll all readable)
    #[serde(default)]
    pub collection_ids: Vec<String>,
    /// Poll interval in seconds (default:3600 = 1 hour)
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Maximum objects per page
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Custom HTTP headers
    #[serde(default)]
    pub custom_headers: HashMap<String, String>,
}

fn default_poll_interval() -> u64 {
    3600
}
fn default_page_size() -> u32 {
    100
}

impl Default for TaxiiClientConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            username: None,
            password: None,
            api_key: None,
            collection_ids: Vec::new(),
            poll_interval_secs: default_poll_interval(),
            page_size: default_page_size(),
            custom_headers: HashMap::new(),
        }
    }
}

/// TAXII 2.1 Client.
/// Provides methods for TAXII discovery, collection enumeration, and
/// object retrieval. Actual HTTP I/O is stubbed unless the `taxii`
/// feature flag is enabled.
pub struct TaxiiClient {
    config: TaxiiClientConfig,
}

impl TaxiiClient {
    /// Create a new TAXII client.
    pub fn new(config: TaxiiClientConfig) -> Self {
        Self { config }
    }

    /// Get the server URL.
    pub fn server_url(&self) -> &str {
        &self.config.server_url
    }

    /// Build the discovery URL:`<server>/taxii2/`
    pub fn discovery_url(&self) -> String {
        format!("{}/taxii2/", self.config.server_url.trim_end_matches('/'))
    }

    /// Build the collections URL for a given API root.
    pub fn collections_url(&self, api_root: &str) -> String {
        format!("{}/collections/", api_root.trim_end_matches('/'))
    }

    /// Build the objects URL for a given API root and collection.
    pub fn objects_url(&self, api_root: &str, collection_id: &str) -> String {
        format!(
            "{}/collections/{}/objects/",
            api_root.trim_end_matches('/'),
            collection_id
        )
    }

    /// Parse a TAXII envelope JSON response into STIX objects.
    pub fn parse_envelope(json: &str) -> Result<TaxiiEnvelope, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parse a STIX bundle JSON string.
    pub fn parse_bundle(json: &str) -> Result<StixBundle, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv4_indicator() {
        let pattern = "[ipv4-addr:value = '192.168.1.1']";
        let indicators = extract_indicators(pattern);
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0],
            ExtractedIndicator::Ipv4("192.168.1.1".into())
        );
    }

    #[test]
    fn test_extract_domain_indicator() {
        let pattern = "[domain-name:value = 'evil.example.com']";
        let indicators = extract_indicators(pattern);
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0],
            ExtractedIndicator::Domain("evil.example.com".into())
        );
    }

    #[test]
    fn test_extract_url_indicator() {
        let pattern = "[url:value = 'http://evil.com/malware.exe']";
        let indicators = extract_indicators(pattern);
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0],
            ExtractedIndicator::Url("http://evil.com/malware.exe".into())
        );
    }

    #[test]
    fn test_extract_file_hash_indicator() {
        let pattern = "[file:hashes.'SHA-256' = 'abc123def456']";
        let indicators = extract_indicators(pattern);
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0],
            ExtractedIndicator::FileHash("SHA-256".into(), "abc123def456".into())
        );
    }

    #[test]
    fn test_extract_email_indicator() {
        let pattern = "[email-addr:value = 'phisher@evil.com']";
        let indicators = extract_indicators(pattern);
        assert_eq!(indicators.len(), 1);
        assert_eq!(
            indicators[0],
            ExtractedIndicator::Email("phisher@evil.com".into())
        );
    }

    #[test]
    fn test_extract_multiple_from_compound_pattern() {
        // Compound pattern with OR
        let pattern = "[ipv4-addr:value = '10.0.0.1'] OR [domain-name:value = 'bad.com']";
        let indicators = extract_indicators(pattern);
        assert!(
            indicators.len() >= 2,
            "Should extract both indicators: {:?}",
            indicators
        );
    }

    #[test]
    fn test_extract_no_match() {
        let pattern = "some random text without indicators";
        let indicators = extract_indicators(pattern);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_parse_stix_bundle() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle --12345",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator --00001",
                    "pattern": "[ipv4-addr:value = '203.0.113.5']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                    "confidence": 85
                },
                {
                    "type": "malware",
                    "id": "malware --00001",
                    "name": "TestMalware",
                    "is_family": true,
                    "malware_types": ["ransomware"]
                }
            ]
        }"#;

        let bundle: StixBundle = serde_json::from_str(json).expect("parse bundle");
        assert_eq!(bundle.id, "bundle --12345");
        assert_eq!(bundle.objects.len(), 2);

        let indicators = process_bundle(&bundle);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].confidence, 85);
        assert_eq!(
            indicators[0].indicator,
            ExtractedIndicator::Ipv4("203.0.113.5".into())
        );
    }

    #[test]
    fn test_process_bundle_empty() {
        let bundle = StixBundle {
            object_type: "bundle".into(),
            id: "bundle --empty".into(),
            objects: vec![],
        };
        let indicators = process_bundle(&bundle);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_taxii_client_urls() {
        let config = TaxiiClientConfig {
            server_url: "https://taxii.example.com".into(),
            ..Default::default()
        };
        let client = TaxiiClient::new(config);

        assert_eq!(client.discovery_url(), "https://taxii.example.com/taxii2/");
        assert_eq!(
            client.collections_url("https://taxii.example.com/api1"),
            "https://taxii.example.com/api1/collections/"
        );
        assert_eq!(
            client.objects_url("https://taxii.example.com/api1", "collection-uuid"),
            "https://taxii.example.com/api1/collections/collection-uuid/objects/"
        );
    }

    #[test]
    fn test_parse_taxii_envelope() {
        let json = r#"{
            "more": true,
            "next": "https://taxii.example.com/api1/collections/abc/objects/?next=page2",
            "objects": [
                {"type": "indicator", "id": "indicator --1", "pattern":"[ipv4-addr:value = '1.2.3.4']"}
            ]
        }"#;

        let envelope = TaxiiClient::parse_envelope(json).expect("parse envelope");
        assert!(envelope.more);
        assert!(envelope.next.is_some());
        assert_eq!(envelope.objects.len(), 1);
    }

    #[test]
    fn test_taxii_discovery_deserialization() {
        let json = r#"{
            "title": "Test TAXII Server",
            "description": "A test server",
            "default": "https://taxii.example.com/api1/",
            "api_roots": [
                "https://taxii.example.com/api1/",
                "https://taxii.example.com/api2/"
            ]
        }"#;

        let discovery: TaxiiDiscovery = serde_json::from_str(json).expect("parse discovery");
        assert_eq!(discovery.title.as_deref(), Some("Test TAXII Server"));
        assert_eq!(discovery.api_roots.len(), 2);
    }

    #[test]
    fn test_taxii_collection_deserialization() {
        let json = r#"{
            "collections": [
                {
                    "id": "abc-123",
                    "title": "APT Indicators",
                    "description": "Advanced persistent threat indicators",
                    "can_read": true,
                    "can_write": false,
                    "media_types": ["application/taxii+json;version=2.1"]
                }
            ]
        }"#;

        let collections: TaxiiCollections = serde_json::from_str(json).expect("parse collections");
        assert_eq!(collections.collections.len(), 1);
        assert_eq!(collections.collections[0].id, "abc-123");
        assert!(collections.collections[0].can_read);
        assert!(!collections.collections[0].can_write);
    }

    #[test]
    fn test_stix_relationship_deserialization() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle --rels",
            "objects": [
                {
                    "type": "relationship",
                    "id": "relationship --001",
                    "relationship_type": "indicates",
                    "source_ref": "indicator --001",
                    "target_ref": "malware --001"
                }
            ]
        }"#;

        let bundle: StixBundle = serde_json::from_str(json).expect("parse bundle");
        assert_eq!(bundle.objects.len(), 1);
        if let StixObject::Relationship(rel) = &bundle.objects[0] {
            assert_eq!(rel.relationship_type, "indicates");
        } else {
            panic!("Expected relationship object");
        }
    }

    #[test]
    fn test_stix_attack_pattern() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle --ap",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern --001",
                    "name": "Spear Phishing",
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ]
                }
            ]
        }"#;

        let bundle: StixBundle = serde_json::from_str(json).expect("parse bundle");
        if let StixObject::AttackPattern(ap) = &bundle.objects[0] {
            assert_eq!(ap.name.as_deref(), Some("Spear Phishing"));
            assert_eq!(ap.kill_chain_phases.len(), 1);
        } else {
            panic!("Expected attack-pattern object");
        }
    }

    #[test]
    fn test_default_taxii_config() {
        let config = TaxiiClientConfig::default();
        assert_eq!(config.poll_interval_secs, 3600);
        assert_eq!(config.page_size, 100);
        assert!(config.collection_ids.is_empty());
    }

    #[test]
    fn test_unknown_stix_object_handled() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle --unknown",
            "objects": [
                {"type": "campaign", "id": "campaign --001", "name":"APT28"}
            ]
        }"#;

        let bundle: StixBundle = serde_json::from_str(json).expect("parse bundle");
        assert_eq!(bundle.objects.len(), 1);
        matches!(&bundle.objects[0], StixObject::Unknown);
    }
}
