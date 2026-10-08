//! Drift guard between the code's canonical AI vocabularies and the
//! machine-checked corpora in `docs/eval/`.
//!
//! `tools/check_eval_corpora.py` proves the corpora are canonically truthful
//! and complete; this test proves the *code* still agrees with the files the
//! live sweep feeds it. It fails when a taxonomy variant is added/renamed
//! without the corpus following (or vice versa), and when a canonical plan
//! fact is not required by at least one chat case.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ai_service::{knowledge, reply_classify};

fn eval_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../docs/eval")
        .canonicalize()
        .expect("docs/eval must exist next to the workspace")
}

fn corpus(name: &str) -> serde_json::Value {
    let path = eval_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn string_set(value: &serde_json::Value, pointer: &str) -> BTreeSet<String> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing array at {pointer}"))
        .iter()
        .filter_map(|entry| entry.as_str().map(str::to_string))
        .collect()
}

/// Every disposition the classification corpus asserts is canonical, and the
/// corpus covers every canonical disposition — byte-for-byte with `TAXONOMY`.
#[test]
fn reply_corpus_covers_the_canonical_taxonomy() {
    let corpus = corpus("reply-classification-goldens.json");
    let canonical: BTreeSet<String> = reply_classify::TAXONOMY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let mut asserted: BTreeSet<String> = BTreeSet::new();
    for case in corpus["cases"].as_array().expect("cases array") {
        for disposition in case["expect"]["disposition"]
            .as_array()
            .expect("disposition array")
        {
            let disposition = disposition.as_str().expect("disposition string");
            assert!(
                canonical.contains(disposition),
                "corpus asserts non-canonical disposition {disposition:?}; \
                 canonical: {:?}",
                reply_classify::TAXONOMY
            );
            asserted.insert(disposition.to_string());
        }
        if let Some(class) = case["expect"]["objection_class"].as_str() {
            assert!(
                reply_classify::OBJECTION_CLASSES.contains(&class),
                "corpus asserts non-canonical objection class {class:?}"
            );
        }
    }
    let missing: Vec<&String> = canonical.difference(&asserted).collect();
    assert!(
        missing.is_empty(),
        "corpus has no case for dispositions {missing:?} — coverage is incomplete"
    );
    assert_eq!(canonical.len(), 11, "the taxonomy is the canonical eleven");
}

/// Every canonical objection class has a dedicated classification case AND a
/// dedicated rebuttal golden; the reply pipeline's six-value taxonomy cannot
/// drift from the files the sweep scores.
#[test]
fn objection_corpus_covers_every_class() {
    let classification = corpus("reply-classification-goldens.json");
    let rebuttal = corpus("objection-rebuttal-goldens.json");
    let mut in_classification: BTreeSet<String> = BTreeSet::new();
    for case in classification["cases"].as_array().expect("cases array") {
        let classes = &case["expect"]["objection_class"];
        if let Some(class) = classes.as_str() {
            in_classification.insert(class.to_string());
        } else if let Some(list) = classes.as_array() {
            for class in list.iter().filter_map(serde_json::Value::as_str) {
                in_classification.insert(class.to_string());
            }
        }
    }
    let mut in_rebuttal: BTreeSet<String> = BTreeSet::new();
    for case in rebuttal["cases"].as_array().expect("cases array") {
        assert!(
            !case["forbidden_claims"]
                .as_array()
                .expect("forbidden_claims array")
                .is_empty(),
            "a rebuttal golden has an empty deny-list"
        );
        if let Some(class) = case["objection_class"].as_str() {
            in_rebuttal.insert(class.to_string());
        }
    }
    for class in reply_classify::OBJECTION_CLASSES {
        assert!(
            in_classification.contains(class),
            "no classification case asserts objection class {class:?}"
        );
        assert!(
            in_rebuttal.contains(class),
            "no rebuttal golden covers objection class {class:?}"
        );
    }
    assert_eq!(reply_classify::OBJECTION_CLASSES.len(), 6);
}

/// Every canonical plan price and email limit is required by at least one
/// chat case, and no chat case requires a numeric token the canonical
/// catalog does not carry. This pins the RUNNING catalog (knowledge::PLANS,
/// derived from platform-catalog) to the corpus.
#[test]
fn chat_corpus_covers_the_canonical_plan_facts() {
    let corpus = corpus("chat-qa-goldens.json");
    let mut required: BTreeSet<String> = BTreeSet::new();
    for case in corpus["cases"].as_array().expect("cases array") {
        for entry in case["must_contain"].as_array().expect("must_contain array") {
            let entry = entry.as_str().expect("string entry");
            // Numeric tokens only; textual entries are the Python gate's job.
            let mut token = String::new();
            for ch in entry.chars().chain(std::iter::once(' ')) {
                if ch.is_ascii_digit() || ch == ',' {
                    token.push(ch);
                } else {
                    if !token.is_empty() {
                        required.insert(token.trim_matches(',').to_string());
                        token.clear();
                    }
                }
            }
        }
    }
    for plan in knowledge::PLANS.iter() {
        for value in [
            plan.price_eur.to_string(),
            plan.email_limit.to_string(),
            plan.api_call_limit.to_string(),
        ] {
            if value == "-1" {
                continue; // unlimited: no numeric fact to require
            }
            assert!(
                required.contains(&value) || required.contains(&format_number(&value)),
                "no chat case requires the canonical value {value} for plan {}",
                plan.name
            );
        }
    }
    assert!(
        knowledge::PLANS.len() >= 6,
        "the canonical catalog carries at least the six subscription rows"
    );
}

/// `1,750`-style rendering of an integer for corpus comparison.
fn format_number(value: &str) -> String {
    let (sign, digits) = value
        .strip_prefix('-')
        .map_or(("", value), |rest| ("-", rest));
    let mut out = String::new();
    let chars: Vec<char> = digits.chars().collect();
    for (index, ch) in chars.iter().enumerate() {
        if index > 0 && (chars.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch);
    }
    format!("{sign}{out}")
}
