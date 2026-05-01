use once_cell::sync::Lazy;
use serde_json::Value;

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
            token_value("web", "colors", " --background").as_deref(),
            Some("248 246 243")
        );
        assert_eq!(
            token_value("web", "spacing", " --space-4").as_deref(),
            Some("16px")
        );
        assert_eq!(
            token_value("web", "motion", " --motion-duration-180").as_deref(),
            Some("180ms")
        );
        assert_eq!(
            token_value("web", "radius", " --radius-lg").as_deref(),
            Some("18px")
        );
    }

    #[test]
    fn counts_web_tokens() {
        assert!(total_token_count("web") > 50);
    }
}
