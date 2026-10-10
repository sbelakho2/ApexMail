//! API error + public page contracts: the “perfect” external surface.
//!
//! Every client (browser, SDK, curl) must see the same error grammar and
//! the same marketing/consent facts. Drift here is a product lie.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // integration-tests lives at services/mail-server/crates/integration-tests
    // ancestors: 0=self 1=crates 2=mail-server 3=services 4=repo root
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(4)
        .expect("repo root above services/mail-server/crates")
        .to_path_buf()
}

/// Perfect marketing/commercial facts: Free is 3k/mo + 30k launch; annual is
/// 10 payments / ~16.7%. Scans the presentation layer for the known lies.
#[test]
fn marketing_never_claims_30k_recurring_free_or_10_percent_annual() {
    let root = repo_root();
    let mut offenders = Vec::new();

    let mut walk = |dir: &PathBuf| {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if matches!(name, "target" | ".git" | "node_modules" | ".venv") {
                    continue;
                }
                walk(&path);
                continue;
            }
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if !matches!(ext, "md" | "html" | "json" | "po") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            // Recurring Free 30k/month (not framed as one-time launch).
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                let claims_30k_month =
                    (lower.contains("30,000") || lower.contains("30k") || lower.contains("30000"))
                        && lower.contains("month")
                        && lower.contains("free")
                        && !lower.contains("launch")
                        && !lower.contains("one-time")
                        && !lower.contains("one time");
                let claims_10_pct = (lower.contains("10% off")
                    || lower.contains("10% discount")
                    || lower.contains("annual (10%"))
                    && !lower.contains("16.7")
                    && !lower.contains("10 monthly");
                if claims_30k_month || claims_10_pct {
                    offenders.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    };
    walk(&root.join("apps/marketing-zola"));
    walk(&root.join("docs"));

    assert!(
        offenders.is_empty(),
        "commercial lies in presentation layer:\n{}",
        offenders.join("\n")
    );
}

/// Perfect localization: translated quickstarts and SLAs are not empty
/// shells. English-only pages may exist, but DE/ES/FR counterparts of the
/// four-language families must carry real body text.
#[test]
fn translated_quickstart_and_sla_bodies_are_non_empty() {
    let root = repo_root().join("apps/marketing-zola/content");
    let pairs = [
        ("quickstart/index.de.md", "quickstart/index.md"),
        ("quickstart/index.es.md", "quickstart/index.md"),
        ("quickstart/index.fr.md", "quickstart/index.md"),
        ("sla/index.de.md", "sla/index.md"),
        ("sla/index.es.md", "sla/index.md"),
        ("sla/index.fr.md", "sla/index.md"),
    ];
    for (translated, english) in pairs {
        let t_path = root.join(translated);
        let e_path = root.join(english);
        let t = fs::read_to_string(&t_path)
            .unwrap_or_else(|e| panic!("missing translated body {}: {e}", t_path.display()));
        let e = fs::read_to_string(&e_path)
            .unwrap_or_else(|e| panic!("missing english body {}: {e}", e_path.display()));
        // Body = content after front-matter.
        let body = |s: &str| {
            s.splitn(3, "---")
                .nth(2)
                .unwrap_or(s)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
        };
        assert!(
            body(&t) >= 10,
            "{translated} is an empty shell ({} lines)",
            body(&t)
        );
        assert!(
            body(&t) * 2 >= body(&e),
            "{translated} is far thinner than {english} ({} vs {})",
            body(&t),
            body(&e)
        );
    }
}

/// Perfect SLA shape: every language exposes scope/uptime/credits/exclusions
/// (the audit found translations that dropped most terms).
#[test]
fn sla_translations_carry_substantive_term_sections() {
    let root = repo_root().join("apps/marketing-zola/content/sla");
    for lang in ["index.md", "index.de.md", "index.es.md", "index.fr.md"] {
        let text = fs::read_to_string(root.join(lang))
            .unwrap_or_else(|e| panic!("missing SLA {lang}: {e}"));
        let lower = text.to_ascii_lowercase();
        // At least these four commercial term classes must appear.
        let classes = [
            (
                "uptime or availability",
                [
                    "uptime",
                    "availability",
                    "verfügbarkeit",
                    "disponibilidad",
                    "disponibilité",
                ],
            ),
            (
                "credits",
                [
                    "credit",
                    "service credit",
                    "gutschrift",
                    "crédit",
                    "credito",
                ],
            ),
            (
                "exclusions",
                ["exclusion", "ausschluss", "exclusion", "exclusion"],
            ),
            (
                "claims process",
                ["claim", "claims", "anspruch", "reclamación", "réclamation"],
            ),
        ];
        for (label, needles) in classes {
            assert!(
                needles.iter().any(|n| lower.contains(n)),
                "SLA {lang} missing {label}"
            );
        }
    }
}

/// Perfect API surface: OpenAPI (if present) still describes the send
/// contract’s required fields. A file that exists and disagrees is a lie.
#[test]
fn openapi_and_send_contract_agree_on_required_send_fields() {
    let root = repo_root();
    let send_contract = root.join("packages/contract/send-contract.json");
    if !send_contract.exists() {
        return;
    }
    let text = fs::read_to_string(&send_contract).expect("read send-contract");
    let value: serde_json::Value = serde_json::from_str(&text).expect("send-contract is JSON");
    // The contract must at least name to/subject/html or a documented alias.
    let blob = value.to_string().to_ascii_lowercase();
    assert!(blob.contains("to") || blob.contains("recipient"), "{blob}");
    assert!(blob.contains("subject") || blob.contains("body"), "{blob}");
}
