use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::BTreeMap;

pub const BASELINE_JSON: &str =
    include_str!("../../../../../docs/development/ui-design-token-baseline.json");

static BASELINE: Lazy<Value> = Lazy::new(|| {
    serde_json::from_str(BASELINE_JSON).expect("ui design token baseline json should parse")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntry {
    pub source: String,
    pub name: String,
    pub value: String,
}

pub fn token_categories(surface: &str) -> Vec<String> {
    BASELINE["surfaces"][surface]
        .as_object()
        .map(|categories| {
            categories
                .keys()
                .filter(|key| *key != "sources")
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn token_entries(surface: &str, category: &str) -> Vec<TokenEntry> {
    flatten_entries(&BASELINE["surfaces"][surface][category])
}

pub fn token_value(surface: &str, category: &str, name: &str) -> Option<String> {
    let normalized_name = name.trim();

    token_entries(surface, category)
        .into_iter()
        .find(|entry| entry.name.trim() == normalized_name)
        .map(|entry| entry.value)
}

pub fn total_token_count(surface: &str) -> usize {
    token_categories(surface)
        .into_iter()
        .map(|category| token_entries(surface, &category).len())
        .sum()
}

fn flatten_entries(value: &Value) -> Vec<TokenEntry> {
    match value {
        Value::Array(entries) => entries
            .iter()
            .filter_map(entry_from_value)
            .collect::<Vec<_>>(),
        Value::Object(map) => map.values().flat_map(flatten_entries).collect::<Vec<_>>(),
        _ => Vec::new(),
    }
}

fn entry_from_value(entry: &Value) -> Option<TokenEntry> {
    Some(TokenEntry {
        source: entry
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("generated")
            .to_string(),
        name: entry.get("name")?.as_str()?.to_string(),
        value: entry.get("value")?.as_str()?.to_string(),
    })
}

// ── Live authorities ─────────────────────────────────────────────────────
//
// Review §5.1 tokens.rs: "Validate current theme authorities instead of
// historical snapshots. Make source-versus-artifact drift visible."
//
// `ui-design-token-baseline.json` is a SNAPSHOT (it is kept in sync by the
// tests below, but it is not the authority). The authority is the authored
// `assets/globals.input.css`, and the served sheet is the compiled
// `assets/globals.css` — both embedded in the crate, so the drift check is
// hermetic (no filesystem, no build step).

/// Token name → value pairs for one named block of a stylesheet. The block
/// is addressed by the tail of its selector line (`:root`, `.dark`,
/// `:root:not(.light)`, …) and the body is scanned with brace-depth
/// matching, so nested `@media` around a block does not truncate it.
pub fn block_tokens(sheet: &str, block: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(rel) = sheet.find(&format!("{block} {{")) else {
        return out;
    };
    let Some(open) = sheet[rel..].find('{').map(|offset| rel + offset) else {
        return out;
    };
    let mut depth = 1usize;
    let mut end = open + 1;
    let bytes = sheet.as_bytes();
    while end < bytes.len() && depth > 0 {
        match bytes[end] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        end += 1;
    }
    if depth != 0 {
        return out;
    }
    let body = &sheet[open + 1..end - 1];
    for line in body.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("--") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(':') else {
            continue;
        };
        // Values may carry a trailing comment: `--x: 1 2 3; /* note */`.
        let value = value.split("/*").next().unwrap_or(value);
        let value = value.trim().trim_end_matches(';').trim();
        if !value.is_empty() {
            out.insert(format!("--{name}"), value.to_string());
        }
    }
    out
}

/// Token name → value pairs from the light-theme `:root` block of a
/// stylesheet (the theme authority the `.dark` / `:root:not(.light)` blocks
/// override a subset of).
pub fn live_tokens(sheet: &str) -> BTreeMap<String, String> {
    block_tokens(sheet, ":root")
}

/// The authored source's live tokens (`assets/ark.css`, the design
/// authority that globals.input.css and the marketing build both inline).
pub fn source_tokens() -> BTreeMap<String, String> {
    live_tokens(crate::ARK_CSS)
}

/// The served artifact's live tokens (`assets/globals.css`).
pub fn artifact_tokens() -> BTreeMap<String, String> {
    live_tokens(crate::GLOBALS_CSS)
}

/// `(name, source_value, artifact_value)` for every token whose value
/// differs between the authored source and the compiled artifact. Empty
/// means the artifact is a faithful product of its input; any entry is the
/// "rebuilding can discard fixes" hazard the review describes (P1-9).
pub fn source_artifact_drift() -> Vec<(String, String, String)> {
    let source = source_tokens();
    let artifact = artifact_tokens();
    source
        .iter()
        .filter_map(|(name, value)| {
            let artifact_value = artifact.get(name)?;
            (artifact_value != value).then(|| (name.clone(), value.clone(), artifact_value.clone()))
        })
        .collect()
}

/// `(name, baseline_value, live_value)` for every baseline color token that
/// disagrees with the live authored authority. The snapshot must follow the
/// authority, never the other way around.
pub fn baseline_color_drift() -> Vec<(String, String, String)> {
    let live = source_tokens();
    token_entries("web", "colors")
        .into_iter()
        .filter_map(|entry| {
            let name = entry.name.trim().to_string();
            let live_value = live.get(&name)?;
            (live_value.trim() != entry.value.trim()).then(|| {
                (
                    name,
                    entry.value.trim().to_string(),
                    live_value.trim().to_string(),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_web_token_categories() {
        let categories = token_categories("web");
        assert!(categories.contains(&"colors".to_string()));
        assert!(categories.contains(&"spacing".to_string()));
        assert!(categories.contains(&"typography".to_string()));
        assert!(categories.contains(&"icons".to_string()));
        assert!(categories.contains(&"motion".to_string()));
    }

    #[test]
    fn resolves_known_web_tokens() {
        assert_eq!(
            token_value("web", "spacing", " --space-4").as_deref(),
            Some("16px")
        );
        assert_eq!(
            token_value("web", "motion", " --motion-duration").as_deref(),
            Some("130ms")
        );
        assert_eq!(
            token_value("web", "radius", " --radius-lg").as_deref(),
            Some("0px")
        );
    }

    /// The values the MFA/console surfaces actually render come from the
    /// CURRENT authority (the authored input sheet), not the snapshot JSON.
    #[test]
    fn live_tokens_come_from_the_current_authority() {
        let tokens = source_tokens();
        // ARK: paper canvas, ink foreground, interaction blue, destruction
        // red — and interaction is NEVER destruction.
        assert_eq!(
            tokens.get("--background").map(String::as_str),
            Some("255 255 255")
        );
        assert_eq!(
            tokens.get("--foreground").map(String::as_str),
            Some("14 20 27")
        );
        assert_eq!(
            tokens.get("--border").map(String::as_str),
            Some("196 205 213")
        );
        assert_eq!(tokens.get("--input").map(String::as_str), Some("14 20 27"));
        assert_eq!(
            tokens.get("--primary").map(String::as_str),
            Some("29 79 124")
        );
        assert_eq!(
            tokens.get("--destructive").map(String::as_str),
            Some("142 42 32")
        );
        assert_ne!(
            tokens.get("--primary"),
            tokens.get("--destructive"),
            "the brand and the destruction colour must never coincide"
        );
        assert_eq!(
            tokens.get("--muted-foreground").map(String::as_str),
            Some("61 75 89")
        );
        assert_eq!(
            tokens.get("--accent-text").map(String::as_str),
            Some("20 58 92")
        );
        // The wordmark is the fixed logo artefact: red B91C1C + Mail 09090B.
        assert_eq!(
            tokens.get("--wordmark-apex").map(String::as_str),
            Some("185 28 28")
        );
        assert_eq!(
            tokens.get("--wordmark-mail").map(String::as_str),
            Some("9 9 11")
        );
        // Radius 0 everywhere — the arch tokens are gone.
        assert_eq!(tokens.get("--radius").map(String::as_str), Some("0px"));
        assert_eq!(tokens.get("--radius-lg").map(String::as_str), Some("0px"));
        assert!(tokens.get("--radius-arch").is_none());
        // Success is blue: no green exists.
        assert_eq!(
            tokens.get("--success").map(String::as_str),
            Some("29 79 124")
        );
    }

    /// Review P1-9/§5.1 tokens.rs: the compiled artifact must not drift from
    /// the authored source — rebuilding may not discard token fixes.
    #[test]
    fn source_and_artifact_tokens_do_not_drift() {
        let drift = source_artifact_drift();
        assert!(
            drift.is_empty(),
            "globals.css token values drifted from globals.input.css: {drift:?}"
        );
    }

    /// The baseline snapshot is kept in sync with the live authority by this
    /// test; a drift here means someone edited the JSON (or the tokens)
    /// without the other side following.
    #[test]
    fn baseline_snapshot_follows_the_live_authority() {
        let drift = baseline_color_drift();
        assert!(
            drift.is_empty(),
            "ui-design-token-baseline.json (name, baseline, live) drift: {drift:?}"
        );
    }

    #[test]
    fn counts_web_tokens() {
        assert!(total_token_count("web") > 50);
    }
}
