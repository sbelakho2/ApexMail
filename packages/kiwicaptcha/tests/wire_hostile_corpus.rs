//! The shared hostile wire corpus against the Rust decoder.
//!
//! The fixture is expanded by
//! `packages/kiwicaptcha-php/tests/Fixtures/generate-wire-hostile-corpus.php`
//! and read byte-for-byte by every hosted SDK suite. The expected
//! verdicts are the reference decoder's, so a host that drifts fails
//! here rather than silently accepting a token its peers reject.

use std::fs;

use kiwicaptcha::token::{DecodeError, SolutionToken};
use serde_json::Value;

fn corpus() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wire-hostile-corpus.json"
    );
    let text = fs::read_to_string(path).expect("the wire corpus fixture must exist");
    serde_json::from_str(&text).expect("the wire corpus must be valid JSON")
}

fn class_of(error: DecodeError) -> &'static str {
    match error {
        DecodeError::InvalidBase64 => "base64",
        DecodeError::InvalidUtf8 => "utf8",
        DecodeError::TooLarge => "size",
        DecodeError::InvalidCounter => "counter",
        DecodeError::InvalidDuration => "duration",
        DecodeError::Malformed => "malformed",
    }
}

#[test]
fn every_corpus_row_has_the_reference_verdict() {
    let document = corpus();
    let rows = document["vectors"].as_array().expect("vectors array");
    assert!(rows.len() >= 100, "the corpus must stay broad");
    for row in rows {
        let id = row["id"].as_str().expect("id");
        let raw = row["raw"].as_str().expect("raw");
        let expected = &row["expect"];
        match expected["verdict"].as_str().expect("verdict") {
            "accept" => {
                let token = SolutionToken::decode(raw)
                    .unwrap_or_else(|e| panic!("{id}: rejected by the Rust decoder ({e:?})"));
                assert_eq!(
                    token.counter as i64,
                    expected["counter"].as_i64().unwrap(),
                    "{id}"
                );
                assert_eq!(
                    token.duration_ms as i64,
                    expected["duration_ms"].as_i64().unwrap(),
                    "{id}"
                );
                assert_eq!(
                    token.execution_digest.as_deref(),
                    expected["execution_digest"].as_str(),
                    "{id}"
                );
                assert_eq!(
                    token.execution_trace.as_deref(),
                    expected["execution_trace"].as_str(),
                    "{id}"
                );
                assert_eq!(
                    token.rsw_proof.as_deref(),
                    expected["rsw_proof"].as_str(),
                    "{id}"
                );
                if let Some(telemetry) = expected.get("telemetry") {
                    assert_eq!(&token.telemetry, telemetry, "{id}: telemetry value");
                }
                if let Some(score) = expected.get("telemetry_score") {
                    assert_eq!(
                        kiwicaptcha::verify::score_telemetry(&token.telemetry, token.duration_ms),
                        score.as_bool().expect("telemetry_score"),
                        "{id}: telemetry score"
                    );
                }
            }
            "reject" => {
                let error = SolutionToken::decode(raw)
                    .err()
                    .unwrap_or_else(|| panic!("{id}: the Rust decoder accepted a hostile row"));
                let wanted = expected["class"].as_str().expect("class");
                if wanted != "any" {
                    assert_eq!(class_of(error), wanted, "{id}");
                }
            }
            other => panic!("{id}: unknown verdict {other}"),
        }
    }
}
