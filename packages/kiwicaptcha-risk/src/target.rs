//! Target-identifier resolution, normalization and pseudonym derivation
//! (risk-v1 target dimension), byte-identical with the PHP mirror.
//!
//! - [`TargetIdentifierResolver`]: maps an assessment scope to the raw
//!   submitted target identifier ([`FormFieldTargetResolver`] reads a
//!   per-scope form field name; an unconfigured scope carries no target
//!   dimension).
//! - [`normalize_target`]: the versioned pipeline — `nfkc` compatibility
//!   normalization, Unicode case folding, a trim of the ASCII whitespace
//!   edges, then the free static per-provider email canonicalization
//!   table ([`TargetEmailCanonicalization`]).
//! - [`target_hmac`]: the full 32-byte HMAC-SHA256 over the normalized
//!   identifier, keyed by the master-derived target key, with the
//!   pipeline version stamped into the derivation context. Only that
//!   digest is ever passed onward.
//!
//! The live path of the derived pseudonym (not a side channel): the
//! engine's `resolve_target_id` feeds the typed outcomes facade
//! (`OutcomeHandle::target`), whose authentication-failure reports
//! register the failure in the target-dimension state
//! (`protocol/risk-v1/target_failure.lua` / `assess_v2.lua` KEYS[14..16])
//! that the marks stage reads back as the attacked-target record. The
//! pseudonym is the sole key; the raw and normalized identifier never
//! leave this boundary.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::keys::RiskKeys;

type HmacSha256 = Hmac<Sha256>;

/// The pipeline version stamped into the target derivation context.
/// Bump on every change to any pipeline stage or to the provider table;
/// the bump re-derives every target pseudonym, so two pipeline versions
/// can never collide on one target state.
pub const TARGET_PIPELINE_VERSION: u64 = 1;

/// The ASCII whitespace the trim stage removes from both edges, the
/// exact set PHP's `trim()` default covers. The Unicode trim of the
/// standard library is wider and would diverge from the PHP mirror.
const TRIM_EDGES: &[char] = &[' ', '\t', '\n', '\r', '\0', '\u{0b}'];

/// Resolves the raw target identifier of one assessment.
///
/// The resolver reads the request's submitted form fields and returns the
/// raw value bound to the scope's target dimension, or `None` when the
/// scope carries no target dimension. It never normalizes and never
/// derives a pseudonym: the raw value crosses exactly one boundary (into
/// [`normalize_target`]) and the normalized value exactly one more (into
/// [`target_hmac`]), so no other stage ever holds the raw identifier.
pub trait TargetIdentifierResolver: Send + Sync {
    /// The raw target identifier, or `None` when the scope has no
    /// configured target field, the field is absent from `fields`, or
    /// its value is empty (no target dimension for this assessment).
    fn resolve(&self, scope: u32, fields: &[(&str, &str)]) -> Option<String>;
}

/// Default target resolver: one configured form field name per scope.
///
/// The map is the deployment's per-scope choice of the form field that
/// carries the target identifier, e.g. `{1: "username", 2: "email"}` for
/// a login scope and a signup scope. A scope without a configured field
/// resolves `None`: that assessment simply carries no target dimension.
#[derive(Debug, Clone)]
pub struct FormFieldTargetResolver {
    field_names: HashMap<u32, String>,
}

impl FormFieldTargetResolver {
    /// Builds the resolver from the per-scope field-name map.
    ///
    /// # Panics
    ///
    /// Panics when a configured field name is empty: the empty string
    /// would match every absent field and silently split one target's
    /// pseudonyms.
    pub fn new(field_names: HashMap<u32, String>) -> FormFieldTargetResolver {
        for (scope, field) in &field_names {
            assert!(
                !field.is_empty(),
                "the target field name for scope {scope} must be a non-empty string"
            );
        }
        FormFieldTargetResolver { field_names }
    }
}

impl TargetIdentifierResolver for FormFieldTargetResolver {
    fn resolve(&self, scope: u32, fields: &[(&str, &str)]) -> Option<String> {
        let field = self.field_names.get(&scope)?;
        let value = fields.iter().find(|(name, _)| name == field)?;
        if value.1.is_empty() {
            return None;
        }
        Some(value.1.to_string())
    }
}

/// The free static per-provider email canonicalization table.
///
/// A pure table, no service and no network: the curated provider rules
/// shipped with the crate. The input is the already-trimmed, folded and
/// `nfkc`-normalized identifier; the output collapses the
/// provider-specific aliasing that lets one mailbox appear under many
/// spellings.
///
/// Rules: googlemail.com rewrites to gmail.com; gmail.com strips the
/// local part at the first plus tag and removes every dot; outlook.com,
/// live.com, hotmail.com and icloud.com strip the local part at the first
/// plus tag but keep dots; yahoo.com strips the local part at the first
/// hyphen tag. Every other provider keeps the local part untouched except
/// for the trim and case folding the pipeline already applied, and the
/// domain matches exactly (a bare or subdomained host is never rewritten).
///
/// The table has its own version const: any change to a rule bumps
/// [`TargetEmailCanonicalization::TABLE_VERSION`] together with
/// [`TARGET_PIPELINE_VERSION`], so derived target pseudonyms can never
/// collide across table revisions.
pub struct TargetEmailCanonicalization;

impl TargetEmailCanonicalization {
    /// Version of the curated provider table (bump with the pipeline
    /// version).
    pub const TABLE_VERSION: u64 = 1;

    fn rule(domain: &str) -> Option<LocalRule> {
        match domain {
            "gmail.com" => Some(LocalRule::StripPlusAndDots),
            "outlook.com" | "live.com" | "hotmail.com" | "icloud.com" => Some(LocalRule::StripPlus),
            "yahoo.com" => Some(LocalRule::StripHyphen),
            _ => None,
        }
    }

    /// The domain rewrite applied before the rule lookup.
    fn alias(domain: &str) -> &str {
        match domain {
            "googlemail.com" => "gmail.com",
            other => other,
        }
    }
}

#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum LocalRule {
    StripPlusAndDots,
    StripPlus,
    StripHyphen,
}

impl LocalRule {
    fn apply(self, local: &str) -> String {
        let stripped = match self {
            Self::StripPlusAndDots | Self::StripPlus => match local.find('+') {
                Some(at) => &local[..at],
                None => local,
            },
            Self::StripHyphen => match local.find('-') {
                Some(at) => &local[..at],
                None => local,
            },
        };
        match self {
            Self::StripPlusAndDots => stripped.chars().filter(|c| *c != '.').collect(),
            _ => stripped.to_string(),
        }
    }
}

impl TargetEmailCanonicalization {
    /// Canonicalizes an email-shaped identifier per the provider table.
    /// A value without an at sign is returned unchanged (a plain username
    /// has no provider rule). The local part splits at the last at sign,
    /// so a quoted local part carrying an at sign stays one local part.
    pub fn canonicalize(identifier: &str) -> String {
        let Some(at) = identifier.rfind('@') else {
            return identifier.to_string();
        };
        let local = &identifier[..at];
        let domain = &identifier[at + 1..];
        let domain = Self::alias(domain);
        match Self::rule(domain) {
            None => identifier.to_string(),
            Some(rule) => format!("{}@{}", rule.apply(local), domain),
        }
    }
}

/// The versioned target-identifier normalization pipeline.
///
/// Stages, in order: `nfkc` compatibility normalization, Unicode case
/// folding (`str::to_lowercase`), a trim of the ASCII whitespace edges,
/// then the free static per-provider email canonicalization table.
///
/// Case-folding boundary, stated honestly: `to_lowercase` applies the
/// locale-independent Unicode lowercasing, which covers the practical
/// fold space for identifiers (fullwidth and compatibility forms arrive
/// already folded by `nfkc`; the Turkish dotless i and the capital I fold
/// identically in both cores). It is not full Unicode case folding: the
/// German sharp s stays sharp s (never folds to "ss"). The shared vector
/// corpus (protocol/risk-v1/target-vectors.json) pins the exact behavior
/// in both languages. PHP parity: the mirror's `mb_strtolower` tracks the
/// platform's Unicode data, and the corpus is the cross-language fence.
///
/// The pipeline version is stamped into the derivation context
/// ([`target_hmac`]), so a pipeline change derives fresh pseudonyms.
pub fn normalize_target(raw: &str) -> String {
    let nfkc: String = raw.nfkc().collect();
    let folded = nfkc.to_lowercase();
    let trimmed = folded.trim_matches(TRIM_EDGES);
    TargetEmailCanonicalization::canonicalize(trimmed)
}

/// The full 32-byte HMAC-SHA256 over a normalized target identifier.
///
/// The message mirrors the shared pseudonym framing with the context
/// `b"tgt"` and the pipeline version in the epoch slot: the MAC covers
/// `"kiwi-risk-id-v1\0tgt\0"`, the big-endian version and the normalized
/// value, in that order. Unlike the 16-byte identity pseudonyms this
/// digest is kept whole: the target dimension is keyed by the full
/// digest, and the version stamp means a pipeline change can never
/// collide with pseudonyms derived under an earlier pipeline.
pub fn target_hmac(key: &[u8; 32], normalized: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"kiwi-risk-id-v1\0");
    mac.update(b"tgt");
    mac.update(b"\0");
    mac.update(&TARGET_PIPELINE_VERSION.to_be_bytes());
    mac.update(normalized.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The target pseudonym (64 lowercase hex chars) derived by the identity
/// factory's target key: the hex of [`target_hmac`] under
/// `RiskKeys::target`. The caller passes only the output of
/// [`normalize_target`] forward; the normalized value itself never leaves
/// this boundary.
pub fn target_id(keys: &RiskKeys, normalized: &str) -> String {
    hex::encode(target_hmac(&keys.target, normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fullwidth_and_compatibility_forms_fold_to_their_ascii_bases() {
        assert_eq!(normalize_target("ｅｘａｍｐｌｅ"), "example");
        assert_eq!(normalize_target("\u{fb01}le42"), "file42");
        assert_eq!(normalize_target("\u{216b}"), "xii");
        assert_eq!(
            normalize_target("Ｕｓｅｒ＠Ｅｘａｍｐｌｅ．ｃｏｍ"),
            "user@example.com"
        );
    }

    #[test]
    fn case_folding_keeps_the_documented_boundary() {
        assert_eq!(normalize_target("Straße"), "straße");
        assert_ne!(normalize_target("Straße"), normalize_target("STRASSE"));
        assert_eq!(normalize_target("İstanbul"), "i\u{307}stanbul");
        assert_ne!(normalize_target("İstanbul"), normalize_target("Istanbul"));
        assert_eq!(normalize_target("ııii"), "ııii");
    }

    #[test]
    fn trim_removes_exactly_the_php_edge_set() {
        assert_eq!(normalize_target("  padded\t"), "padded");
        assert_eq!(normalize_target("\u{a0}nbsp\u{a0}"), "nbsp");
        assert_eq!(normalize_target("a b"), "a b");
        // A control byte outside the trim set survives the edges.
        assert_eq!(normalize_target("\u{85}x"), "\u{85}x");
    }

    #[test]
    fn provider_table_collapses_only_its_own_providers() {
        let gmail = normalize_target("ab@gmail.com");
        assert_eq!(normalize_target("A..B@gmail.com"), gmail);
        assert_eq!(normalize_target("a.b+x@gmail.com"), gmail);
        assert_eq!(
            normalize_target("a.b.x@GoogleMail.com"),
            normalize_target("abx@gmail.com")
        );
        assert_eq!(normalize_target("AB@GMAIL.COM"), gmail);

        assert_eq!(
            normalize_target("First.Last+Etsy@Outlook.com"),
            "first.last@outlook.com"
        );
        assert_ne!(
            normalize_target("a.b@outlook.com"),
            normalize_target("ab@outlook.com")
        );
        assert_eq!(normalize_target("a.b.c+news@live.com"), "a.b.c@live.com");
        assert_eq!(normalize_target("x.y+z@hotmail.com"), "x.y@hotmail.com");
        assert_eq!(normalize_target("name+tag@icloud.com"), "name@icloud.com");

        let yahoo = normalize_target("ab@yahoo.com");
        assert_eq!(normalize_target("ab-news@yahoo.com"), yahoo);
        assert_ne!(
            normalize_target("a.b@yahoo.com"),
            normalize_target("ab@yahoo.com")
        );

        // Providers outside the table never fold.
        assert_eq!(normalize_target("a+b@proton.me"), "a+b@proton.me");
        assert_ne!(
            normalize_target("a+b@proton.me"),
            normalize_target("ab@proton.me")
        );
        assert_eq!(normalize_target("a.b+x@example.com"), "a.b+x@example.com");
        assert_eq!(normalize_target("user@gmail"), "user@gmail");
    }

    #[test]
    fn homoglyphs_and_accents_never_over_normalize() {
        assert_ne!(normalize_target("\u{430}lice"), normalize_target("alice"));
        assert_ne!(
            normalize_target("andré@gmail.com"),
            normalize_target("andre@gmail.com")
        );
    }

    #[test]
    fn target_hmac_matches_the_contract_shape_and_version_stamp() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        let mut mac = HmacSha256::new_from_slice(&keys.target).unwrap();
        mac.update(b"kiwi-risk-id-v1\0tgt\0");
        mac.update(&1u64.to_be_bytes());
        mac.update(b"material");
        let digest = mac.finalize().into_bytes();
        assert_eq!(target_hmac(&keys.target, "material"), digest[..]);
        assert_eq!(target_id(&keys, "material"), hex::encode(digest));
        // A version bump derives a different pseudonym: the stamp works.
        let mut other = HmacSha256::new_from_slice(&keys.target).unwrap();
        other.update(b"kiwi-risk-id-v1\0tgt\0");
        other.update(&2u64.to_be_bytes());
        other.update(b"material");
        let other_digest = other.finalize().into_bytes();
        assert_ne!(target_hmac(&keys.target, "material"), other_digest[..]);
    }

    #[test]
    fn form_field_resolver_reads_the_per_scope_field() {
        let mut map = HashMap::new();
        map.insert(1u32, "username".to_string());
        map.insert(2u32, "email".to_string());
        let resolver = FormFieldTargetResolver::new(map);
        let fields = [("username", "alice"), ("email", "a.b@gmail.com")];
        assert_eq!(resolver.resolve(1, &fields), Some("alice".to_string()));
        assert_eq!(
            resolver.resolve(2, &fields),
            Some("a.b@gmail.com".to_string())
        );
        // An unconfigured scope carries no target dimension.
        assert_eq!(resolver.resolve(3, &fields), None);
        // An absent or empty field resolves None.
        assert_eq!(resolver.resolve(1, &[]), None);
        assert_eq!(resolver.resolve(1, &[("username", "")]), None);
    }

    #[test]
    #[should_panic(expected = "must be a non-empty string")]
    fn form_field_resolver_refuses_an_empty_field_name() {
        let mut map = HashMap::new();
        map.insert(1u32, String::new());
        let _ = FormFieldTargetResolver::new(map);
    }

    #[test]
    fn table_version_stays_pinned_to_the_pipeline() {
        // The provider table and the pipeline version move together: the
        // corpus generator stamps one version, so a table edit that does
        // not bump the pipeline version breaks this anchor on purpose.
        assert_eq!(TargetEmailCanonicalization::TABLE_VERSION, 1);
        assert_eq!(TARGET_PIPELINE_VERSION, 1);
    }
}
