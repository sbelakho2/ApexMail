//! Server-provided page data for the SSR render pipeline.
//!
//! The console is a zero-JavaScript SSR surface: every list page renders
//! its rows from data the server loads *before* rendering. This module is
//! the plain-data contract between the api-server's query layer (which
//! owns sqlx) and the view functions (which own HTML). The api-server
//! builds a [`ListPageData`] per route; [`crate::leptos_views::data_list_page`]
//! renders it with the same primitives the hand-written pages use.
//!
//! Honesty rule: when the backing table has no rows (or no writer yet),
//! the loader passes an empty `rows` vector and the renderer shows a real
//! empty state — demo data is never fabricated on the data path.

use crate::shell::html_escape;

/// One KPI card at the top of a list/overview page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpiCardData {
    pub label: String,
    pub value: String,
    /// Secondary line under the value (e.g. "vs. previous 30 days").
    pub hint: Option<String>,
}

impl KpiCardData {
    pub fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.to_string(),
            value: value.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }
}

/// A single table cell. `Raw` cells are trusted, pre-escaped HTML built by
/// the renderer itself (status pills, action links); every other variant
/// is escaped at render time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCell {
    /// Plain text (HTML-escaped).
    Text(String),
    /// Monospaced text for ids / codes (HTML-escaped).
    Mono(String),
    /// Link to a same-origin path.
    Link { href: String, text: String },
    /// Status pill (draft/sent/active/… — rendered as an indicator).
    Status(String),
}

impl DataCell {
    pub fn text(value: impl Into<String>) -> Self {
        DataCell::Text(value.into())
    }

    pub fn mono(value: impl Into<String>) -> Self {
        DataCell::Mono(value.into())
    }

    pub fn status(value: &str) -> Self {
        DataCell::Status(value.to_string())
    }
}

/// One row: `id` backs the bulk-action checkbox, delete confirm links and
/// the detail link; `cells` line up with [`TableData::columns`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRowData {
    pub id: String,
    pub cells: Vec<DataCell>,
}

/// Table shape: column labels plus the data rows that fill them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableData {
    pub columns: Vec<String>,
    pub rows: Vec<DataRowData>,
}

/// A `<select>` filter inside the GET search form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSelectData {
    /// Form field name (serialized into the query string on submit).
    pub name: String,
    pub label: String,
    /// (value, label, selected) triples.
    pub options: Vec<(String, String, bool)>,
}

impl FilterSelectData {
    pub fn new(name: &str, label: &str, options: Vec<(String, String, bool)>) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            options,
        }
    }
}

/// Bulk action bar configuration (delete-selected over checked rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkActionData {
    /// POST target for the wrapped form.
    pub action: String,
    pub button_label: String,
}

/// Everything `data_list_page` needs to render a full list/overview page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListPageData {
    pub title: String,
    pub description: String,
    /// KPI cards rendered above the table (empty ⇒ none).
    pub kpis: Vec<KpiCardData>,
    /// Table (columns + rows). `None` for pure overview pages.
    pub table: Option<TableData>,
    /// GET search form label + placeholder. Empty label ⇒ no search form.
    pub search_label: String,
    pub search_placeholder: String,
    /// Current search value (preserved in the input).
    pub current_query: String,
    /// GET filter selects inside the search form.
    pub filters: Vec<FilterSelectData>,
    /// Canonical path for pagination/filter links (e.g. "/campaigns").
    pub base_path: String,
    /// Preserved filter query (without `page=`) for pagination links.
    pub filter_query: String,
    /// 1-based current page.
    pub page: usize,
    pub total_pages: usize,
    /// Total matching rows (rendered as "Showing X of N").
    pub total_count: i64,
    pub per_page: usize,
    /// Bulk action bar (checkbox column appears when set).
    pub bulk_action: Option<BulkActionData>,
    /// Primary action link (e.g. "New Campaign" → /campaigns/new).
    pub primary_action: Option<(String, String)>,
    /// Per-row action links: detail page prefix (`/campaigns/`) and the
    /// signed-confirm delete intent (`delete-campaign`).
    pub detail_path_prefix: Option<String>,
    pub delete_intent: Option<String>,
    /// Detail link label (defaults to "View").
    pub detail_label: String,
    /// Edit link suffix appended to `{detail_path_prefix}{id}` when set.
    pub edit_path_suffix: Option<String>,
    /// Honest empty state copy.
    pub empty_title: String,
    pub empty_description: String,
}

impl ListPageData {
    /// Human summary line: "Showing 1–10 of 42 campaigns." or an honest
    /// zero-row phrasing.
    pub fn summary(&self, noun: &str) -> String {
        let plural = format!("{noun}s");
        if self.total_count == 0 {
            return format!("No {plural} yet.");
        }
        let start = (self.page.saturating_sub(1)) * self.per_page.max(1) + 1;
        let end = ((start + self.rows_len().saturating_sub(1)) as i64).min(self.total_count);
        format!("Showing {start}–{end} of {total} {plural}.", total = self.total_count)
    }

    fn rows_len(&self) -> usize {
        self.table.as_ref().map(|t| t.rows.len()).unwrap_or(0)
    }
}

/// Prefilled campaign editor state for `/campaigns/{id}/edit` (loaded
/// server-side from the campaigns row).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CampaignEditData {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub html_body: String,
    /// `datetime-local` value string (may be empty for drafts).
    pub scheduled_at: String,
}

/// Pending TOTP setup, carried from `POST /web/auth/mfa/setup` to the
/// security page through a short-lived signed cookie (never the URL).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MfaSetupData {
    pub secret: String,
    pub otpauth: String,
}

/// Render a `<td>` for a [`DataCell`] (mirrors `Table` cell classes).
pub fn render_data_cell(cell: &DataCell) -> String {
    match cell {
        DataCell::Text(value) => html_escape(value),
        DataCell::Mono(value) => format!(
            "<code class=\"font-mono text-xs bg-muted/40 rounded px-1.5 py-0.5\">{}</code>",
            html_escape(value)
        ),
        DataCell::Link { href, text } => format!(
            "<a href=\"{}\" class=\"font-bold text-foreground hover:text-primary\">{}</a>",
            attribute_escape(href),
            html_escape(text)
        ),
        DataCell::Status(status) => {
            crate::primitives::StatusIndicator { status }.render_html()
        }
    }
}

/// Escape a value for use inside a double-quoted attribute.
fn attribute_escape(value: &str) -> String {
    html_escape(value).replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_are_honest() {
        let mut data = ListPageData {
            page: 2,
            per_page: 10,
            total_count: 42,
            ..Default::default()
        };
        data.table = Some(TableData {
            columns: vec!["Name".into()],
            rows: (0..10)
                .map(|i| DataRowData {
                    id: format!("r{i}"),
                    cells: vec![DataCell::text(format!("row {i}"))],
                })
                .collect(),
        });
        assert_eq!(data.summary("campaign"), "Showing 11–20 of 42 campaigns.");
        assert_eq!(
            ListPageData::default().summary("tenant"),
            "No tenants yet."
        );
    }

    #[test]
    fn cells_escape_text_but_render_semantic_html() {
        assert_eq!(
            render_data_cell(&DataCell::text("<script>alert(1)</script>")),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        let link = render_data_cell(&DataCell::Link {
            href: "/campaigns/c_1".to_string(),
            text: "Spring \"Winback\"".to_string(),
        });
        assert!(link.contains("href=\"/campaigns/c_1\""));
        assert!(link.contains("Spring &quot;Winback&quot;"));
        let status = render_data_cell(&DataCell::status("sent"));
        assert!(status.to_ascii_lowercase().contains("sent"));
    }

    #[test]
    fn attribute_values_are_quoted_safe() {
        assert_eq!(
            attribute_escape("/a?x=\"1\"&y=2"),
            "/a?x=&quot;1&quot;&amp;y=2"
        );
    }
}
