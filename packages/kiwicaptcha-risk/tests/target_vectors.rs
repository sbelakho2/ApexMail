//! Shared target-identifier vectors (protocol/risk-v1/
//! target-vectors.json): every input runs the versioned normalization
//! pipeline and the target HMAC under the recorded master; the PHP
//! mirror (`tests/TargetVectorsTest.php`) derives the identical bytes.
//! The corpus pins the collapse families (gmail dot/plus variants,
//! googlemail, provider plus/hyphen tags), the non-folding families
//! (proton plus tags, outlook dots, homoglyphs, accents) and the
//! case-folding boundary (sharp s, dotted capital i). Pure — no Redis.

use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::target::{
    normalize_target, FormFieldTargetResolver, TargetEmailCanonicalization,
    TargetIdentifierResolver, TARGET_PIPELINE_VERSION,
};
use std::collections::HashMap;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/risk-v1/target-vectors.json"
);

struct Corpus {
    master_key: String,
    rows: Vec<(String, serde_json::Value)>,
}

fn corpus() -> Corpus {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("cannot read {VECTORS_PATH}: {e}"));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(
        doc["pipeline_version"].as_u64().expect("pipeline_version"),
        TARGET_PIPELINE_VERSION,
        "the corpus was generated under a different pipeline version"
    );
    Corpus {
        master_key: doc["master_key"].as_str().expect("master_key").to_string(),
        rows: doc["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .map(|v| (v["note"].as_str().expect("note").to_string(), v.clone()))
            .collect(),
    }
}

#[test]
fn shared_target_vectors_match_php() {
    let corpus = corpus();
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(corpus.master_key.as_bytes()));
    let id_of = |note: &str| -> String {
        let row = corpus
            .rows
            .iter()
            .find(|(n, _)| n == note)
            .unwrap_or_else(|| panic!("no vector row named {note:?}"))
            .1
            .clone();
        let normalized = normalize_target(row["input"].as_str().expect("input"));
        assert_eq!(
            normalized,
            row["expected_normalized"]
                .as_str()
                .expect("expected_normalized"),
            "vector {note:?} must normalize exactly"
        );
        factory.target_id(&normalized)
    };

    assert!(
        corpus.rows.len() >= 30,
        "the vector families must stay comprehensive"
    );
    for (note, row) in &corpus.rows {
        let input = row["input"].as_str().expect("input");
        let normalized = normalize_target(input);
        assert_eq!(
            normalized,
            row["expected_normalized"]
                .as_str()
                .expect("expected_normalized"),
            "vector {note:?} must normalize exactly"
        );
        let expected = row["expected_id"].as_str().expect("expected_id");
        assert_eq!(factory.target_id(&normalized), expected, "vector {note:?}");
        assert!(
            expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
            "the pseudonym must be 64 lowercase hex chars"
        );
    }

    // Collapse families: one mailbox, one target pseudonym.
    let gmail = id_of("gmail plain anchor");
    assert_eq!(gmail, id_of("gmail dots collapse"));
    assert_eq!(gmail, id_of("gmail plus and dots collapse"));
    assert_eq!(gmail, id_of("gmail domain case folds"));
    assert_eq!(
        id_of("googlemail rewrites to gmail"),
        factory.target_id("abx@gmail.com")
    );
    assert_eq!(
        id_of("outlook plus tag stripped"),
        factory.target_id("first.last@outlook.com")
    );
    assert_eq!(
        id_of("live plus tag stripped"),
        factory.target_id("a.b.c@live.com")
    );
    assert_eq!(
        id_of("hotmail plus tag stripped"),
        factory.target_id("x.y@hotmail.com")
    );
    assert_eq!(
        id_of("icloud plus tag stripped"),
        factory.target_id("name@icloud.com")
    );
    assert_eq!(
        id_of("yahoo minus tag stripped"),
        id_of("yahoo plain anchor")
    );
    assert_eq!(
        id_of("nfkc fullwidth letters"),
        factory.target_id("example")
    );

    // Non-folding families: distinct targets, pinned so the pipeline is
    // never over-normalizing (proton plus tags, outlook dots, homoglyphs,
    // accents, embedded whitespace, the case-folding boundary).
    assert_ne!(
        id_of("proton plus tag stays"),
        id_of("proton plain distinct pair")
    );
    assert_ne!(
        id_of("outlook dots stay"),
        id_of("outlook dots distinct pair")
    );
    assert_ne!(id_of("yahoo dots stay"), id_of("yahoo plain anchor"));
    assert_ne!(
        id_of("cyrillic a homoglyph stays"),
        id_of("latin a anchor distinct")
    );
    assert_ne!(
        id_of("accent stays"),
        id_of("accent stripped distinct pair")
    );
    assert_ne!(
        id_of("embedded space stays"),
        id_of("embedded distinct pair")
    );
    assert_ne!(
        id_of("fold sharp s stays"),
        id_of("fold sharp s boundary distinct")
    );
    assert_ne!(
        id_of("fold turkish capital dotted i"),
        id_of("fold turkish plain i distinct")
    );
}

#[test]
fn form_field_resolver_reads_the_per_scope_field_and_skips_unconfigured_scopes() {
    let mut map = HashMap::new();
    map.insert(1u32, "username".to_string());
    map.insert(2u32, "email".to_string());
    let resolver = FormFieldTargetResolver::new(map);
    let fields = [
        ("username", "Alice"),
        ("email", "a.b@gmail.com"),
        ("password", "hunter2"),
    ];

    assert_eq!(resolver.resolve(1, &fields), Some("Alice".to_string()));
    assert_eq!(
        resolver.resolve(2, &fields),
        Some("a.b@gmail.com".to_string())
    );
    // A scope without a configured field carries no target dimension.
    assert_eq!(resolver.resolve(3, &fields), None);
    assert_eq!(resolver.resolve(1, &[]), None);
    assert_eq!(resolver.resolve(1, &[("username", "")]), None);
}

#[test]
fn provider_table_version_is_pinned() {
    // The table moves together with the pipeline version; the corpus
    // stamps one version, so this anchor breaks on a table edit that
    // forgets the bump.
    assert_eq!(TargetEmailCanonicalization::TABLE_VERSION, 1);
    assert_eq!(TARGET_PIPELINE_VERSION, 1);
}
