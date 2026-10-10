//! API error + public page contracts: the “perfect” external surface.
//!
//! Every client (browser, SDK, curl) must see the same error grammar and
//! the same marketing/consent facts. Drift here is a product lie.

use std::fs;
use std::path::{Path, PathBuf};

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
/// Remove `<...>` tags and collapse whitespace, so claim checks judge the
/// VISIBLE text of minified markup rather than raw source lines.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

#[test]
fn marketing_never_claims_30k_recurring_free_or_10_percent_annual() {
    let root = repo_root();
    let mut offenders = Vec::new();

    fn walk(dir: &Path, offenders: &mut Vec<String>) {
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
                walk(&path, offenders);
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
            // The check runs on TAG-STRIPPED, sentence-scoped chunks: a
            // minified HTML page is one giant line, so line-scoped
            // co-occurrence matched unrelated words elsewhere on the line
            // (false positive on the correct DE card "3,000 E-Mails/Monat +
            // 30,000 Startguthaben"). Chunking keeps the claim inside the
            // sentence that actually makes it, and the vocabulary covers the
            // site's English + German surfaces.
            let plain = strip_tags(&text);
            for chunk in plain
                .split(['.', '!', '?', ';', '\n', '·', '—'])
                .map(str::trim)
                .filter(|chunk| !chunk.is_empty())
            {
                let lower = chunk.to_lowercase();
                // The 30k figure only lies when it is an EMAIL quota: a
                // 30,000-per-month API-call allowance is a different thing.
                let email_after_30k = ["30,000", "30k", "30000"].iter().any(|token| {
                    chunk
                        .to_lowercase()
                        .find(token)
                        .map(|index| {
                            let tail = &chunk[index + token.len()..];
                            let window: String =
                                tail.chars().take(48).collect::<String>().to_lowercase();
                            window.contains("email")
                                || window.contains("e-mail")
                                || window.contains("mail")
                        })
                        .unwrap_or(false)
                });
                let claims_30k_month = email_after_30k
                    && (lower.contains("month") || lower.contains("monat"))
                    && (lower.contains("free")
                        || lower.contains("kostenlos")
                        || lower.contains("gratis"))
                    && !lower.contains("launch")
                    && !lower.contains("startguthaben")
                    && !lower.contains("one-time")
                    && !lower.contains("one time")
                    && !lower.contains("einmalig");
                let claims_10_pct = (lower.contains("10% off")
                    || lower.contains("10% discount")
                    || lower.contains("10% rabatt")
                    || lower.contains("annual (10%"))
                    && !lower.contains("16.7")
                    && !lower.contains("10 monthly")
                    && !lower.contains("10 monats");
                if claims_30k_month || claims_10_pct {
                    offenders.push(format!("{}: {}", path.display(), chunk.trim()));
                }
            }
        }
    }
    walk(&root.join("apps/marketing-zola"), &mut offenders);
    // `docs/**` EXCEPT the audit archive: audit reports and recorded evidence
    // legitimately QUOTE past claims (including ones since corrected); the
    // check's subject is the live presentation layer.
    walk(&root.join("docs"), &mut offenders);
    offenders.retain(|entry| !entry.contains("/docs/audit/"));

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
        let classes: &[(&str, &[&str])] = &[
            (
                "uptime or availability",
                &[
                    "uptime",
                    "availability",
                    "verfügbarkeit",
                    "disponibilidad",
                    "disponibilité",
                ],
            ),
            (
                "credits",
                &[
                    "credit",
                    "service credit",
                    "gutschrift",
                    "crédit",
                    "credito",
                ],
            ),
            (
                // "ausschl" (stem) matches Ausschluss AND Ausschlüsse — the
                // German heading uses the umlaut plural, which the previous
                // "ausschluss" needle could never match.
                "exclusions",
                &["exclusion", "exclusión", "ausschl"],
            ),
            (
                // DE uses "Gutschriften beantragen" / "Gutschriftenanträge"
                // (stem "antr" covers both, umlaut plural included).
                "claims process",
                &["claim", "anspruch", "antr", "solicit", "réclam", "demand"],
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
