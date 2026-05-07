//! CSV value sanitisation to prevent injection attacks.
//!
//! # Source files replaced
//!
//! | Original location | What was replaced |
//! |---|---|
//! | [`billing-service/src/routes.rs`](services/mail-server/crates/billing-service/src/routes.rs:1608) | `sanitize_csv_value()` |
//! | [`api-server/src/routes/billing.rs`](services/mail-server/crates/api-server/src/routes/billing.rs:1127) | duplicate of the above |
//! | [`billing-service/src/accounting_export.rs`](services/mail-server/crates/billing-service/src/accounting_export.rs:223) | duplicate field quoting/escaping |

use serde_json::Value;

/// Characters that, when appearing at the start of a CSV cell, can trigger
/// formula execution in spreadsheet applications (Excel, LibreOffice, etc.).
const FORMULA_START_CHARS: &[char] = &['=', '+', '-', '@', '\t', '\r', '\n'];

/// Sanitize a [`serde_json::Value`] for safe inclusion in a CSV cell.
///
/// Prefixes the value with a single quote (`'`) when the first character
/// could trigger formula execution. Non-string values are converted to their
/// JSON text representation first.
pub fn sanitize_csv_value(value: &Value) -> String {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };

    sanitize_csv_text(&text)
}

/// Sanitize raw text for safe inclusion in a CSV cell.
pub fn sanitize_csv_text(text: &str) -> String {
    if text.starts_with(FORMULA_START_CHARS) {
        format!("'{text}")
    } else {
        text.to_string()
    }
}

/// Return a fully quoted RFC 4180 CSV field after formula sanitisation.
pub fn quote_csv_field(value: &str) -> String {
    let sanitized = sanitize_csv_text(value);
    let escaped = sanitized.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_csv_value_prefixes_equals() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("=SUM(A1:A2)")),
            "'=SUM(A1:A2)"
        );
    }

    #[test]
    fn sanitize_csv_value_prefixes_plus() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("+SUM(A1:A2)")),
            "'+SUM(A1:A2)"
        );
    }

    #[test]
    fn sanitize_csv_value_prefixes_minus() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("-SUM(A1:A2)")),
            "'-SUM(A1:A2)"
        );
    }

    #[test]
    fn sanitize_csv_value_prefixes_at() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("@SUM(A1:A2)")),
            "'@SUM(A1:A2)"
        );
    }

    #[test]
    fn sanitize_csv_value_prefixes_tab() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("\t=SUM(A1)")),
            "'\t=SUM(A1)"
        );
    }

    #[test]
    fn sanitize_csv_value_prefixes_carriage_return() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("\r=SUM(A1)")),
            "'\r=SUM(A1)"
        );
    }

    #[test]
    fn sanitize_csv_value_preserves_plain_text() {
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("plain text")),
            "plain text"
        );
    }

    #[test]
    fn sanitize_csv_value_preserves_numbers() {
        assert_eq!(sanitize_csv_value(&serde_json::json!(42)), "42");
        assert_eq!(sanitize_csv_value(&serde_json::json!(3.14)), "3.14");
    }

    #[test]
    fn sanitize_csv_value_handles_null() {
        assert_eq!(sanitize_csv_value(&serde_json::Value::Null), "");
    }

    #[test]
    fn sanitize_csv_value_handles_empty_string() {
        assert_eq!(sanitize_csv_value(&serde_json::json!("")), "");
    }

    #[test]
    fn sanitize_csv_text_prefixes_formula_like_text() {
        assert_eq!(sanitize_csv_text("=SUM(A1:A2)"), "'=SUM(A1:A2)");
    }

    #[test]
    fn quote_csv_field_escapes_quotes() {
        assert_eq!(quote_csv_field(r#"he"llo"#), r#""he""llo""#);
    }

    #[test]
    fn quote_csv_field_prefixes_formula_like_text() {
        assert_eq!(quote_csv_field("=SUM(A1:A2)"), "\"'=SUM(A1:A2)\"");
    }
}
