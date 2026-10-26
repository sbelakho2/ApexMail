//! Static disclosure scan over the AI surfaces the third external audit
//! flagged: every prompt file the email-answering agent can load by
//! default, and the dormant AI training-corpus pipeline.
//!
//! The runtime prompt is operator-overridable via AI_EMAIL_AGENT_PROMPT /
//! AI_EMAIL_AGENT_PROMPT_FILE, but the repository-resident default is
//! `crates/ai-service/config/email_agent_prompt.txt`; every file shipped in
//! that directory is scanned, so a second default prompt cannot ship with a
//! leak. No python forbidden-terms scanner with provider-disclosure roots
//! exists in tools/ (docs-lint.sh is a prose linter; bots_disclosure_suite.py
//! is a live-HTTP suite), so the corpus gate is folded in here.
//!
//! The training corpus legitimately carries canonical pricing and
//! customer-side dialog, so it gets ONLY the provider/facility term list;
//! the price-pattern and team-language checks apply to prompt files alone.
//! A checker line that lists a term inside a `must_not_contain` deny-list
//! is a defensive control, not a disclosure, and is exempted.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../")
        .canonicalize()
        .expect("repository root must exist next to the workspace")
}

/// Every file under the crate's prompt/config directory: the set of default
/// prompt files the service can load (AI_EMAIL_AGENT_PROMPT_FILE defaults to
/// config/email_agent_prompt.txt relative to the working directory).
fn prompt_files() -> Vec<PathBuf> {
    let dir = repo_root()
        .join("services/mail-server/crates/ai-service/config")
        .canonicalize()
        .expect("ai-service config directory must exist");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    assert!(
        files
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == "email_agent_prompt.txt")),
        "the default email-agent prompt file must exist in the scanned root"
    );
    files
}

/// The corpus pipeline tree: generators, checkers, and generated JSONL.
/// Model artifacts (merged_*/output_* checkpoints, tokenizers, caches) are
/// binary model state, not authored corpus content, and are skipped.
fn corpus_files() -> Vec<PathBuf> {
    let root = repo_root().join("apps/ai/training");
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name.starts_with("merged_")
                    || name.starts_with("output_")
                    || name == "__pycache__"
                    || name == ".git"
                {
                    continue;
                }
                collect(&path, out);
            } else {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "py" | "jsonl" | "md") && name != "tokenizer.json" {
                    out.push(path);
                }
            }
        }
    }
    let mut out = Vec::new();
    collect(&root, &mut out);
    out.sort();
    assert!(
        !out.is_empty(),
        "the apps/ai/training corpus root must exist and carry files"
    );
    out
}

/// Provider, transport-architecture, facility, and org-language terms no
/// prompt file may carry (audit 3; owner directive).
const PROMPT_FORBIDDEN_TERMS: &[&str] = &[
    "Hetzner",
    "SES+self-hosted",
    "hybrid SES",
    "engineering team",
    "legal team",
    "single host",
    "no standby",
];

/// Provider and facility terms no corpus file may carry. Country-level
/// residency ("EU/EEA", "Finland (EU)") is allowed by the directive, so
/// bare country names are not listed; cities and providers are.
const CORPUS_FORBIDDEN_TERMS: &[&str] = &[
    "Hetzner",
    "SES+self-hosted",
    "hybrid SES",
    "Nuremberg",
    "Helsinki",
    "Frankfurt",
    "Germany standby",
];

fn price_patterns() -> Vec<(String, Regex)> {
    vec![
        (
            "euro amount".to_string(),
            Regex::new("€\\d").expect("regex"),
        ),
        (
            "EUR amount".to_string(),
            Regex::new("\\d+ EUR").expect("regex"),
        ),
        (
            "decimal price".to_string(),
            Regex::new("\\d+\\.\\d{2}").expect("regex"),
        ),
    ]
}

#[test]
fn prompt_files_carry_no_provider_team_or_pricing_disclosure() {
    let prices = price_patterns();
    for path in prompt_files() {
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for term in PROMPT_FORBIDDEN_TERMS {
            assert!(
                !text.contains(term),
                "{}: prompt file must not contain {term:?} (provider/team/topology disclosure)",
                path.display()
            );
        }
        for (label, pattern) in &prices {
            assert!(
                !pattern.is_match(&text),
                "{}: prompt file must not carry a hardcoded price ({label}); \
                 pricing reaches the model only as runtime catalog facts",
                path.display()
            );
        }
    }
}

#[test]
fn training_corpus_pipeline_carries_no_provider_disclosure() {
    for path in corpus_files() {
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (index, line) in text.lines().enumerate() {
            // A deny-list entry (`must_not_contain`) asserts the model must
            // NOT say the term; that line is a control, not a disclosure.
            if line.contains("must_not_contain") {
                continue;
            }
            for term in CORPUS_FORBIDDEN_TERMS {
                assert!(
                    !line.contains(term),
                    "{}:{}: corpus pipeline must not carry {term:?} \
                     (provider/facility disclosure)",
                    path.display(),
                    index + 1
                );
            }
        }
    }
}
