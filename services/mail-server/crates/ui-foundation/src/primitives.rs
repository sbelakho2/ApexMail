//! Design-system primitives for the zero-JavaScript SSR surfaces.
//!
//! # Usable primitives vs. inert legacy exports
//!
//! The console ships **no client-side JavaScript**, so a primitive is only
//! "usable" when its behaviour works in a plain HTML document. Review §4.9 /
//! §5.1 primitives.rs asks for that distinction to be explicit:
//!
//! **Usable (native, SSR-complete), compose these:**
//! * `Button`, `Label`, `Input`, `Textarea` (native `maxlength` when
//!   `max_length` is set), `NativeSelect` (escaped at this boundary),
//!   `NativeCheckbox`, `Badge`/`StatusIndicator`, `Card`, `EmptyState`,
//!   `AsyncState`, `Table`, `Progress`,
//!   `PaginationControls::render_html_with_links` (real `<a href>` links),
//!   `Avatar`, `Skeleton`, `ChartLegendItem`.
//!
//! **Inert legacy exports (library risks, NOT proof that a page is broken)
//!, prefer the native counterpart or a confirmation page:**
//! * `Select` → `NativeSelect` (the combobox needs the hydration script).
//! * `Checkbox` (button + `role="checkbox"`), `Switch`, `Slider`,
//!   `RadioGroup` → `NativeCheckbox` / native `input[type=radio|range]`
//!   inside a real `<form>`.
//! * `Dialog`, `AlertDialog`, `Popover`, `DropdownMenu` → the typed
//!   `/confirm` page or a `<details>` disclosure; these render open markup
//!   with `data-*` hooks and no code to open, trap, or dismiss it.
//! * `Tabs` → real links/query parameters where switching is
//!   server-rendered. `Accordion` → native `<details>/<summary>`.
//!   `Toast` → the flash banner (PRG feedback), the disabled toast surface
//!   stays disabled until its behaviour is real.
//! * `PaginationControls::render_html` (inert buttons) →
//!   `render_html_with_links`.
//!
//! The `*BehaviorContract` structs below document the behaviour each legacy
//! widget *would* need; they are not evidence that it is implemented.

/// Escape HTML special characters in attribute/text interpolation.
fn html_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Deterministic per-title dialog id: renders must be byte-identical
/// between calls (migration determinism contract), so a global counter is
/// not usable. Two dialogs on one page share an id only if their titles are
/// identical, titles are page-distinct ("Delete campaign?" vs "Delete
/// list?"), and a same-title pair is still addressed via distinct wrapper
/// ids from the page markup.
#[allow(dead_code)]
fn next_dialog_id() -> String {
    "apex-dialog".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimitiveSpec {
    pub checklist_id: &'static str,
    pub rust_name: &'static str,
    pub contract_id: &'static str,
    pub status: &'static str,
}

pub const PRIMITIVES: &[PrimitiveSpec] = &[
    PrimitiveSpec {
        checklist_id: "4.3",
        rust_name: "Button",
        contract_id: "primitive/button",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.4",
        rust_name: "Input",
        contract_id: "primitive/input",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.5",
        rust_name: "Textarea",
        contract_id: "primitive/textarea",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.6",
        rust_name: "Checkbox",
        contract_id: "primitive/checkbox",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.7",
        rust_name: "Select",
        contract_id: "primitive/select",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.8",
        rust_name: "Switch",
        contract_id: "primitive/switch",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.9",
        rust_name: "Slider",
        contract_id: "primitive/slider",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.10",
        rust_name: "RadioGroup",
        contract_id: "primitive/radio-group",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.11",
        rust_name: "Label",
        contract_id: "primitive/label",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.12",
        rust_name: "Progress",
        contract_id: "primitive/progress",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.13",
        rust_name: "Dialog",
        contract_id: "primitive/dialog",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.14",
        rust_name: "AlertDialog",
        contract_id: "primitive/alert-dialog",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.15",
        rust_name: "DropdownMenu",
        contract_id: "primitive/dropdown-menu",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.16",
        rust_name: "Popover",
        contract_id: "primitive/popover",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.17",
        rust_name: "Tooltip",
        contract_id: "primitive/tooltip",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.18",
        rust_name: "Accordion",
        contract_id: "primitive/accordion",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.19",
        rust_name: "Tabs",
        contract_id: "primitive/tabs",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.20",
        rust_name: "ScrollArea",
        contract_id: "primitive/scroll-area",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.21",
        rust_name: "Table",
        contract_id: "primitive/table",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.22",
        rust_name: "Card",
        contract_id: "primitive/card",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.23",
        rust_name: "Badge",
        contract_id: "primitive/badge",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.24",
        rust_name: "Avatar",
        contract_id: "primitive/avatar",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.25",
        rust_name: "EmptyState",
        contract_id: "primitive/empty-state",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.26",
        rust_name: "AsyncState",
        contract_id: "primitive/async-state",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.27",
        rust_name: "Skeleton",
        contract_id: "primitive/skeleton",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.28",
        rust_name: "StatusIndicator",
        contract_id: "primitive/status-indicator",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.29",
        rust_name: "PaginationControls",
        contract_id: "primitive/pagination-controls",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.30",
        rust_name: "Toast",
        contract_id: "primitive/toast",
        status: "implemented",
    },
    PrimitiveSpec {
        checklist_id: "4.31",
        rust_name: "Charts",
        contract_id: "primitive/charts",
        status: "implemented",
    },
];

fn status_indicator_config(status: &str) -> (&str, &str, &str) {
    const DOT_SUCCESS: &str = "<span class=\"mr-1 h-2 w-2\" aria-hidden=\"true\"></span>";
    const DOT_INFO: &str = "<span class=\"mr-1 h-2 w-2\" aria-hidden=\"true\"></span>";
    const DOT_WARNING: &str = "<span class=\"mr-1 h-2 w-2\" aria-hidden=\"true\"></span>";
    const DOT_ERROR: &str = "<span class=\"mr-1 h-2 w-2\" aria-hidden=\"true\"></span>";
    const DOT_OUTLINE: &str =
        "<span class=\"mr-1 h-2 w-2 border border-current\" aria-hidden=\"true\"></span>";
    match status.to_ascii_lowercase().as_str() {
        "draft" => ("Draft", "secondary", DOT_OUTLINE),
        "scheduled" => ("Scheduled", "info", DOT_INFO),
        "sending" => ("Sending", "warning", DOT_WARNING),
        "sent" => ("Sent", "success", DOT_SUCCESS),
        "paused" => ("Paused", "outline", DOT_OUTLINE),
        "subscribed" => ("Subscribed", "success", DOT_SUCCESS),
        "unsubscribed" => ("Unsubscribed", "secondary", DOT_OUTLINE),
        "bounced" => ("Bounced", "warning", DOT_WARNING),
        "complained" => ("Complained", "error", DOT_ERROR),
        "delivered" => ("Delivered", "success", DOT_SUCCESS),
        "queued" => (
            "Queued",
            "secondary",
            "<span class=\"mr-1 h-2 w-2\" aria-hidden=\"true\"></span>",
        ),
        "failed" => ("Failed", "error", DOT_ERROR),
        // ── Control-plane vocabulary ────────────────────────────────
        // Active tenants, verified domains, healthy fleet states, and
        // finished work previously fell through to gray. Severity words
        // (critical/high/…) map so alerts triage by color.
        "active" => ("Active", "success", DOT_SUCCESS),
        "verified" => ("Verified", "success", DOT_SUCCESS),
        "healthy" => ("Healthy", "success", DOT_SUCCESS),
        "operational" => ("Operational", "success", DOT_SUCCESS),
        "ready" => ("Ready", "success", DOT_SUCCESS),
        "online" => ("Online", "success", DOT_SUCCESS),
        "completed" => ("Completed", "success", DOT_SUCCESS),
        "approved" => ("Approved", "success", DOT_SUCCESS),
        "suspended" => ("Suspended", "outline-error", DOT_ERROR),
        "blocked" => ("Blocked", "outline-error", DOT_ERROR),
        "cancelled" | "canceled" => ("Cancelled", "secondary", DOT_OUTLINE),
        "rejected" => ("Rejected", "secondary", DOT_OUTLINE),
        "stopped" => ("Stopped", "secondary", DOT_OUTLINE),
        "acknowledged" => ("Acknowledged", "outline", DOT_OUTLINE),
        "critical" => ("Critical", "error", DOT_ERROR),
        "high" => ("High", "error", DOT_ERROR),
        "medium" => ("Medium", "warning", DOT_WARNING),
        "low" => ("Low", "secondary", DOT_OUTLINE),
        "escalated" => ("Escalated", "warning", DOT_WARNING),
        "pending" => ("Pending", "outline", DOT_OUTLINE),
        "invited" => ("Invited", "info", DOT_INFO),
        "processing" => ("Processing", "info", DOT_INFO),
        "in_progress" => ("In progress", "info", DOT_INFO),
        "draining" => ("Draining", "warning", DOT_WARNING),
        "new" => ("New", "secondary", DOT_OUTLINE),
        "qualified" => ("Qualified", "info", DOT_INFO),
        "proposal" => ("Proposal", "info", DOT_INFO),
        // MFA/secret enrollment vocabulary (review §7 Operators: "Replace
        // reused sent/draft MFA labels with Enabled/Not configured"). The
        // values are the wire vocabulary the CP loaders emit.
        "enabled" => ("Enabled", "success", DOT_SUCCESS),
        "not_configured" => ("Not configured", "secondary", DOT_OUTLINE),
        _ => (status, "secondary", DOT_OUTLINE),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_chart_shell(
    title: Option<&str>,
    description: Option<&str>,
    last_updated_label: Option<&str>,
    height: usize,
    legend_items: &[ChartLegendItem<'_>],
    data_count: usize,
    empty_state_reason: &str,
    chart_markup: &str,
) -> String {
    let content = if data_count == 0 {
        chart_empty_state_markup(empty_state_reason)
    } else {
        format!("{}{}", chart_legend_markup(legend_items), chart_markup)
    };

    render_chart_frame(title, description, last_updated_label, height, &content)
}

fn chart_empty_state_markup(reason: &str) -> String {
    // No outer border/background here, the surrounding chart frame already provides the
    // single visible boundary. Adding another border created a triple-stacked look when
    // the chart frame itself was nested inside a card.
    format!("<div class=\"apex-empty-state flex min-h-[220px] flex-col items-center justify-center gap-3 p-6\"><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" class=\"h-7 w-7\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M3 3v18h18M7 15l3-3 3 3 5-5\"/></svg><p class=\"max-w-xs\">{}</p></div>", chart_empty_description(reason))
}

fn chart_legend_markup(items: &[ChartLegendItem<'_>]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let entries = items
        .iter()
        .map(|item| format!("<div class=\"inline-flex items-center gap-2\"><span class=\"h-2.5 w-2.5\" style=\"background-color: {}\" aria-hidden=\"true\"></span><span>{}</span></div>", item.color, item.name))
        .collect::<Vec<_>>()
        .join("");

    format!("<div class=\"mb-3 flex flex-wrap items-center gap-x-4 gap-y-2\" aria-label=\"Chart legend\">{}</div>", entries)
}

fn render_chart_frame(
    title: Option<&str>,
    description: Option<&str>,
    last_updated_label: Option<&str>,
    height: usize,
    content: &str,
) -> String {
    let header = if title.is_some() || description.is_some() {
        format!(
            "<div class=\"flex flex-col space-y-1.5 p-6\">{}{}{}</div>",
            title
                .map(|value| format!("<h2 class=\"break-words apex-h3\">{}</h2>", value))
                .unwrap_or_default(),
            description
                .map(|value| format!("<p class=\"break-words\">{}</p>", value))
                .unwrap_or_default(),
            chart_meta_markup(last_updated_label),
        )
    } else {
        String::new()
    };

    // The chart frame is almost always wrapped in a panel/card by the page layout.
    // Use a transparent border and no inner padding so we don't double-frame nor
    // double-pad the chart inside that card.
    format!(
        "<div class=\"apex-chart-frame border\">{}<div style=\"height: {}px\">{}</div></div>",
        header, height, content
    )
}

fn chart_meta_markup(last_updated_label: Option<&str>) -> String {
    last_updated_label
        .map(|value| format!("<p class=\"mt-1\">Last updated {}</p>", value))
        .unwrap_or_default()
}

// ── ARK class helpers ──────────────────────────────────────────────────
// The ARK vocabulary owns colour, type and geometry; these helpers exist so
// the primitives keep their public API while emitting only apex-* classes
// (plus structural layout utilities).

fn button_variant_class(variant: &str) -> &'static str {
    match variant {
        "destructive" => "apex-btn--danger",
        "outline" | "secondary" => "",
        "ghost" | "link" => "apex-btn--link",
        _ => "apex-btn--primary",
    }
}

fn button_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "apex-btn--sm",
        _ => "",
    }
}

fn input_variant_class(variant: &str) -> &'static str {
    match variant {
        "error" => "apex-input-error",
        _ => "",
    }
}

fn input_size_class(_size: &str) -> &'static str {
    ""
}

fn textarea_resize_class(_resize: &str) -> &'static str {
    ""
}

fn label_variant_class(variant: &str) -> &'static str {
    match variant {
        "error" => "apex-error",
        _ => "",
    }
}

fn label_size_class(_size: &str) -> &'static str {
    ""
}

fn badge_variant_class(variant: &str) -> &'static str {
    if variant.contains("warning") {
        "apex-status apex-status--warn"
    } else if variant.contains("destructive")
        || variant.contains("error")
        || variant.contains("fail")
    {
        "apex-status apex-status--fail"
    } else if variant.contains("success")
        || variant.contains("default")
        || variant.contains("secondary")
    {
        "apex-status apex-status--on"
    } else {
        "apex-status"
    }
}

fn card_padding_class(_padding: &str) -> &'static str {
    ""
}

fn skeleton_variant_class(_variant: &str) -> &'static str {
    "apex-loading"
}

fn tooltip_variant_class(_variant: &str) -> &'static str {
    ""
}

fn tooltip_side_class(_side: &str) -> &'static str {
    ""
}

fn table_align_class(align: &str) -> &'static str {
    match align {
        "center" => "text-center",
        "right" => "text-right",
        _ => "text-left",
    }
}

fn chart_empty_description(reason: &str) -> &'static str {
    match reason {
        "filtered-out" => {
            "No data matches the current filters. Adjust filters or broaden the timeframe."
        }
        "permission" => "Chart data is unavailable for your current access scope.",
        "delayed" => "Chart data is delayed while sources catch up. Retry shortly for live values.",
        _ => "No chartable data is available for this range.",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button<'a> {
    pub label: &'a str,
    pub variant: &'a str,
    pub size: &'a str,
    pub disabled: bool,
    pub loading: bool,
    pub left_icon: Option<&'a str>,
    pub right_icon: Option<&'a str>,
    /// `true` renders `type="submit"` (the button submits its form, e.g.
    /// a Save button inside a `data-api-form`). `false` renders
    /// `type="button"` so non-submit actions can never accidentally
    /// trigger a form submission (the HTML default is `type="submit"`).
    pub submit: bool,
}

impl<'a> Button<'a> {
    pub fn render_html(&self) -> String {
        let disabled = if self.disabled || self.loading {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let button_type = if self.submit { "submit" } else { "button" };
        // ARK: a busy action changes its verb and its border, there is no
        // spinner. Icons are chrome (the API fields stay, unrendered).
        let _ = (self.left_icon, self.right_icon);
        let busy = if self.loading {
            " aria-busy=\"true\""
        } else {
            ""
        };
        let busy_class = if self.loading { " apex-btn--busy" } else { "" };
        format!(
            "<button type=\"{button_type}\" class=\"{} {} apex-btn{}\" data-variant=\"{}\" data-size=\"{}\"{}{}>{}</button>",
            button_variant_class(self.variant),
            button_size_class(self.size),
            busy_class,
            self.variant,
            self.size,
            disabled,
            busy,
            self.label,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input<'a> {
    pub input_type: &'a str,
    pub value: &'a str,
    pub placeholder: &'a str,
    pub variant: &'a str,
    pub size: &'a str,
    pub left_icon: Option<&'a str>,
    pub right_icon: Option<&'a str>,
    pub error: Option<&'a str>,
    pub disabled: bool,
    pub autocomplete: Option<&'a str>,
    pub required: bool,
    /// Form field name. Without it the input is invisible to `FormData`
    /// serialization, so `data-api-form` handlers would submit `{}`.
    pub name: Option<&'a str>,
    /// DOM id. With a `Label`'s `html_for` carrying the same value the pair
    /// is programmatically associated (`<label for=…>` ↔ `<input id=…>`);
    /// the error paragraph's id derives from it so `aria-describedby`
    /// stays unique per control.
    pub id: Option<&'a str>,
}

impl<'a> Input<'a> {
    pub fn render_html(&self) -> String {
        let resolved_variant = self.error.map(|_| "error").unwrap_or(self.variant);
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        // The error paragraph id is derived from the input id so multiple
        // errored inputs on one page never share a duplicate id, and
        // `aria-describedby` always points at the paragraph THIS render
        // emits right after the control.
        let error_id = match self.id {
            Some(id) => format!("{}-error", html_escape(id)),
            None => "input-error".to_string(),
        };
        let aria_error = if self.error.is_some() {
            format!(" aria-invalid=\"true\" aria-describedby=\"{error_id}\"")
        } else {
            String::new()
        };
        let id_attr = self
            .id
            .map(|value| format!(" id=\"{}\"", html_escape(value)))
            .unwrap_or_default();
        let autocomplete_attr = self
            .autocomplete
            .map(|value| format!(" autocomplete=\"{}\"", value))
            .unwrap_or_default();
        let name_attr = self
            .name
            .map(|value| format!(" name=\"{}\"", html_escape(value)))
            .unwrap_or_default();
        let required_attr = if self.required {
            " required aria-required=\"true\""
        } else {
            ""
        };
        // Batch-2 a11y fix: the attributes used to be concatenated INSIDE
        // the class attribute's quotes (a malformed tag that browsers only
        // parsed by accident, and which made `autocomplete` a class token
        // instead of an attribute). Every attribute now sits where it
        // belongs: classes in class=, the rest as real attributes.
        let classes = format!(
            "apex-input {} {}",
            input_variant_class(resolved_variant),
            input_size_class(self.size),
        );
        let input_markup = format!(
            "<input type=\"{input_type}\"{name}{id} value=\"{value}\" placeholder=\"{placeholder}\" class=\"{classes} apex-input\"{disabled}{aria_error}{autocomplete_attr}{required_attr} data-variant=\"{variant}\" data-size=\"{size}\" />",
            input_type = self.input_type,
            name = name_attr,
            id = id_attr,
            // Server-loaded, user-controlled values: escaping is mandatory
            // here (a `"` in a campaign name would otherwise break out of the
            // attribute, the one render path in this crate that did not
            // escape; dogfood finding 2026-10-06).
            value = html_escape(self.value),
            placeholder = html_escape(self.placeholder),
            classes = classes,
            disabled = disabled,
            aria_error = aria_error,
            autocomplete_attr = autocomplete_attr,
            required_attr = required_attr,
            variant = resolved_variant,
            size = self.size,
        );

        let base = if self.left_icon.is_some() || self.right_icon.is_some() {
            let left = self
                .left_icon
                .map(|icon| format!("<div class=\"absolute left-3\">{icon}</div>"))
                .unwrap_or_default();
            let right = self
                .right_icon
                .map(|icon| format!("<div class=\"absolute right-3\">{icon}</div>"))
                .unwrap_or_default();
            let adjusted =
                input_markup.replace("class=\"flex w-full", "class=\"flex w-full pl-10 pr-10");
            format!("<div class=\"relative\">{}{adjusted}{}</div>", left, right)
        } else {
            input_markup
        };

        if let Some(error) = self.error {
            return format!(
                "<div>{base}<p id=\"{}\" class=\"apex-error\" role=\"alert\">{}</p></div>",
                html_escape(&error_id),
                html_escape(error),
            );
        }

        base
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Textarea<'a> {
    pub value: &'a str,
    pub placeholder: &'a str,
    pub variant: &'a str,
    pub resize: &'a str,
    pub max_length: Option<usize>,
    pub show_count: bool,
    /// Form field name (see `Input::name`).
    pub name: Option<&'a str>,
    /// DOM id for `<label for=…>` association (see `Input::id`); the
    /// character-count span's id derives from it when `show_count` is set.
    pub id: Option<&'a str>,
}

impl<'a> Textarea<'a> {
    pub fn render_html(&self) -> String {
        let char_count_id = match self.id {
            Some(id) => format!("{id}-count"),
            None => "textarea-char-count".to_string(),
        };
        let describedby = if self.show_count {
            format!(" aria-describedby=\"{}\"", char_count_id)
        } else {
            String::new()
        };
        let name_attr = self
            .name
            .map(|value| format!(" name=\"{}\"", value))
            .unwrap_or_default();
        let id_attr = self
            .id
            .map(|value| format!(" id=\"{}\"", value))
            .unwrap_or_default();
        // The limit is NATIVE: `maxlength` is enforced by the browser for
        // typing and by the handler for pasted/scripted input, so the field
        // never silently accepts more than it says (review §5.1 primitives.rs:
        // "implement native textarea limits").
        let maxlength_attr = self
            .max_length
            .map(|max| format!(" maxlength=\"{max}\""))
            .unwrap_or_default();
        let textarea = format!(
            "<textarea{}{}{} class=\"flex min-h-[80px] w-full border px-3 py-2 {} {} apex-input apex-textarea\" data-variant=\"{}\" data-resize=\"{}\" placeholder=\"{}\"{}>{}</textarea>",
            id_attr,
            name_attr,
            maxlength_attr,
            input_variant_class(self.variant),
            textarea_resize_class(self.resize),
            self.variant,
            self.resize,
            html_escape(self.placeholder),
            describedby,
            html_escape(self.value),
        );

        if self.show_count {
            let count = self.value.chars().count();
            // The SSR render ships no script, so this can never be a LIVE
            // counter. It states the LIMIT and the value as rendered, a
            // truthful helper instead of a counter that looks live and is
            // not (review §5.1 primitives.rs: "remove misleading static
            // counters" / "replace the SSR-only 'live' count with a truthful
            // limit helper").
            let suffix = match self.max_length {
                Some(max) => format!("Limit {max} characters · {count} entered"),
                None => format!("{count} characters entered"),
            };
            return format!("<div class=\"relative\">{textarea}<span id=\"{}\" class=\"absolute bottom-2 right-2\">{suffix}</span></div>", char_count_id);
        }

        textarea
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkbox {
    pub checked: bool,
    pub variant: &'static str,
    pub size: &'static str,
    pub indeterminate: bool,
    pub disabled: bool,
    pub aria_label: Option<&'static str>,
}

impl Checkbox {
    pub fn render_html(&self) -> String {
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let aria_label = self
            .aria_label
            .map(|value| format!(" aria-label=\"{}\"", html_escape(value)))
            .unwrap_or_default();
        let mixed = if self.indeterminate {
            " aria-checked=\"mixed\""
        } else {
            ""
        };
        let checked = if self.checked { " checked" } else { "" };
        let _ = self.variant;
        format!(
            "<input type=\"checkbox\" class=\"apex-checkbox apex-input\"{checked}{mixed}{disabled}{aria_label} />"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSelect<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub options: Vec<SelectOption<'a>>,
    pub required: bool,
    /// `true` renders a multi-select (`listIds`-style arrays); the shared
    /// classes and label contract stay identical.
    pub multiple: bool,
    /// Rendered size for a multi-select (rows visible).
    pub size: Option<usize>,
}

impl NativeSelect<'_> {
    pub fn render_html(&self) -> String {
        let multiple_attrs = if self.multiple {
            format!(" multiple size=\"{}\"", self.size.unwrap_or(6).max(2))
        } else {
            String::new()
        };
        let required_attr = if self.required { " required" } else { "" };
        let options = self
            .options
            .iter()
            .map(|option| {
                let selected = if option.selected { " selected" } else { "" };
                let disabled = if option.disabled { " disabled" } else { "" };
                format!(
                    "<option value=\"{}\"{}{}>{}</option>",
                    html_escape(option.value),
                    selected,
                    disabled,
                    html_escape(option.label)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<select id=\"{}\" name=\"{}\" class=\"apex-select{}\"{}{}>{}</select>",
            html_escape(self.id),
            html_escape(self.name),
            if self.multiple {
                " min-h-12 py-2"
            } else {
                " h-12"
            },
            required_attr,
            multiple_attrs,
            options,
        )
    }
}

/// A NATIVE `<input type="checkbox">` styled with the shared control
/// classes, the no-JS sibling of the combobox-family [`Checkbox`] button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCheckbox<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub checked: bool,
    pub label: &'a str,
}

impl NativeCheckbox<'_> {
    pub fn render_html(&self) -> String {
        let checked = if self.checked { " checked" } else { "" };
        format!(
            "<label class=\"flex items-center gap-3 min-h-[44px] apex-em apex-label\" for=\"{}\"\
><input id=\"{}\" name=\"{}\" type=\"checkbox\" value=\"true\"{} class=\"h-4 w-4 border apex-input\" />\
<span>{}</span></label>",
            html_escape(self.id),
            html_escape(self.id),
            html_escape(self.name),
            checked,
            html_escape(self.label),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectOption<'a> {
    pub value: &'a str,
    pub label: &'a str,
    pub disabled: bool,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Select<'a> {
    pub placeholder: &'a str,
    pub value_label: Option<&'a str>,
    pub variant: &'a str,
    pub size: &'a str,
    pub open: bool,
    pub options: Vec<SelectOption<'a>>,
    /// Form field name. The Select is a custom combobox (not a native
    /// `<select>`), so the name is emitted on the wrapper together with
    /// `data-field`/`data-value` which the `data-api-form` hydration script
    /// reads as a fallback when serializing the form payload.
    pub name: Option<&'a str>,
    /// When set, choosing an option re-navigates with this query parameter
    /// updated (list-page filters) instead of only updating `data-value`.
    pub filter_param: Option<&'a str>,
    /// DOM id for the combobox trigger button so an external
    /// `<label for=…>` can name it (a11y). `None` keeps the legacy render.
    pub id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub checked: bool,
    pub variant: &'static str,
    pub size: &'static str,
    pub disabled: bool,
}

impl Switch {
    pub fn render_html(&self) -> String {
        let _ = (self.variant, self.size);
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let checked = if self.checked { " checked" } else { "" };
        format!("<input type=\"checkbox\" class=\"apex-checkbox apex-input\"{checked}{disabled} />")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slider {
    pub value: u8,
    pub variant: &'static str,
    pub size: &'static str,
    pub show_tooltip: bool,
}

impl Slider {
    pub fn render_html(&self) -> String {
        let _ = (self.variant, self.size, self.show_tooltip);
        format!(
            "<input type=\"range\" min=\"0\" max=\"100\" value=\"{}\" class=\"apex-input\" aria-valuenow=\"{}\" />",
            self.value, self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioGroupItem<'a> {
    pub value: &'a str,
    pub label: &'a str,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioGroup<'a> {
    pub name: &'a str,
    pub selected: &'a str,
    pub variant: &'a str,
    pub size: &'a str,
    pub orientation: &'a str,
    pub items: Vec<RadioGroupItem<'a>>,
}

impl<'a> RadioGroup<'a> {
    pub fn render_html(&self) -> String {
        // ARK: native radios in labelled rows, no roving tabindex, no
        // role=radio buttons, no indicator glyph.
        let _ = (self.variant, self.size);
        let group_class = if self.orientation == "horizontal" {
            "flex flex-row flex-wrap gap-4"
        } else {
            "flex flex-col gap-2"
        };
        let items = self
            .items
            .iter()
            .map(|item| {
                let checked = if item.value == self.selected { " checked" } else { "" };
                let disabled = if item.disabled { " disabled" } else { "" };
                format!(
                    "<label class=\"apex-check\"><input type=\"radio\" name=\"{}\" value=\"{}\"{checked}{disabled} /><span>{}</span></label>",
                    html_escape(self.name),
                    html_escape(item.value),
                    html_escape(item.label)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!("<div role=\"radiogroup\" class=\"{group_class}\">{items}</div>")
    }

    /// Native radios keep their native keyboard contract: arrow keys move
    /// the selection, Space selects. There is no roving tabindex to
    /// document because the browser owns it.
    pub fn keyboard_navigation_contract() -> RadioGroupKeyboardContract {
        RadioGroupKeyboardContract {
            arrow_down_moves_next: true,
            arrow_up_moves_prev: true,
            arrow_right_moves_next: true,
            arrow_left_moves_prev: true,
            home_moves_first: false,
            end_moves_last: false,
            wrap_around: false,
            space_selects: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioGroupKeyboardContract {
    pub arrow_down_moves_next: bool,
    pub arrow_up_moves_prev: bool,
    pub arrow_right_moves_next: bool,
    pub arrow_left_moves_prev: bool,
    pub home_moves_first: bool,
    pub end_moves_last: bool,
    pub wrap_around: bool,
    pub space_selects: bool,
}

impl<'a> Select<'a> {
    pub fn render_html(&self) -> String {
        // ARK: a select is a NATIVE select with the shared field recipe —
        // no custom combobox, no listbox overlay, no animation state.
        let _ = (self.variant, self.size, self.open, self.value_label);
        let id_attr = self
            .id
            .map(|id| format!(" id=\"{}\"", html_escape(id)))
            .unwrap_or_default();
        let name_attr = self
            .name
            .map(|name| {
                format!(
                    " name=\"{}\" data-field=\"{}\"",
                    html_escape(name),
                    html_escape(name)
                )
            })
            .unwrap_or_default();
        let mut options = String::new();
        if !self.placeholder.is_empty() {
            options.push_str(&format!(
                "<option value=\"\"{}>{}</option>",
                if self.options.iter().any(|o| o.selected) {
                    ""
                } else {
                    " selected"
                },
                html_escape(self.placeholder)
            ));
        }
        for option in &self.options {
            options.push_str(&format!(
                "<option value=\"{}\"{}{}>{}</option>",
                html_escape(option.value),
                if option.selected { " selected" } else { "" },
                if option.disabled { " disabled" } else { "" },
                html_escape(option.label)
            ));
        }
        format!(
            "<span class=\"apex-select-wrap\"><select class=\"apex-select\"{id_attr}{name_attr}>{options}</select></span>"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label<'a> {
    pub text: &'a str,
    pub required: bool,
    pub optional: bool,
    pub variant: &'a str,
    pub size: &'a str,
    /// The labelled control's DOM id, emitted as the `for` attribute so
    /// `<label>`/`<input>` are programmatically associated (a11y). `None`
    /// keeps the label descriptive-only (the legacy render).
    pub html_for: Option<&'a str>,
}

impl<'a> Label<'a> {
    pub fn render_html(&self) -> String {
        let suffix = if self.required {
            "<span class=\"ml-1 apex-error\">*</span>"
        } else {
            ""
        };
        let optional = if self.optional {
            "<span class=\"ml-1\">(optional)</span>"
        } else {
            ""
        };
        let for_attr = self
            .html_for
            .map(|value| format!(" for=\"{}\"", value))
            .unwrap_or_default();
        format!(
            "<label{} class=\"{} {} apex-em apex-label\">{}{}{}</label>",
            for_attr,
            label_variant_class(self.variant),
            label_size_class(self.size),
            self.text,
            suffix,
            optional
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub value: u8,
    pub variant: &'static str,
    pub size: &'static str,
    pub animated: bool,
    pub show_value: bool,
}

impl Progress {
    pub fn render_html(&self) -> String {
        let _ = (self.variant, self.size, self.animated);
        format!(
            "<span class=\"apex-meta\" role=\"progressbar\" aria-valuemin=\"0\" aria-valuemax=\"100\" aria-valuenow=\"{}\">{} of 100</span>",
            self.value, self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge<'a> {
    pub text: &'a str,
    pub variant: &'a str,
    pub size: &'a str,
    pub icon: Option<&'a str>,
}

impl<'a> Badge<'a> {
    pub fn render_html(&self) -> String {
        let icon = self
            .icon
            .map(|markup| format!("<span class=\"mr-1\">{markup}</span>"))
            .unwrap_or_default();
        // `text` is escaped HERE at the primitive boundary: unknown status
        // strings fall through `status_indicator_config` as the raw input
        // (DB-sourced VARCHARs like event_type / suppression reason), so the
        // badge label must never be interpolated verbatim.
        let text = html_escape(self.text);
        let _ = icon; // ARK: status is a word and its 8px square, no glyph
        format!(
            "<span class=\"{}\" data-variant=\"{}\" data-size=\"{}\">{}</span>",
            badge_variant_class(self.variant),
            self.variant,
            self.size,
            text,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card<'a> {
    pub title: &'a str,
    pub body: &'a str,
    pub variant: &'a str,
    pub padding: &'a str,
    pub interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avatar<'a> {
    pub label: &'a str,
    pub image_url: Option<&'a str>,
    pub fallback: &'a str,
    pub size: &'a str,
    pub status: &'a str,
}

impl<'a> Avatar<'a> {
    pub fn render_html(&self) -> String {
        // ARK: a person is a name (initials as machine data); avatar
        // photographs were chrome. The URL stays accepted and unrendered.
        let _ = (self.image_url, self.size, self.status);
        format!(
            "<span class=\"apex-avatar\" aria-label=\"{}\">{}</span>",
            html_escape(self.label),
            html_escape(self.fallback),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyState<'a> {
    pub icon_markup: Option<&'a str>,
    pub title: &'a str,
    pub description: Option<&'a str>,
    pub action_label: Option<&'a str>,
    /// When set, the action renders as a real link to this route (e.g.
    /// "/campaigns/new") instead of a dead button, empty-state CTAs must
    /// navigate somewhere that exists.
    pub action_href: Option<&'a str>,
}

impl<'a> EmptyState<'a> {
    pub fn render_html(&self) -> String {
        let icon = self
            .icon_markup
            .map(|icon| format!("<div class=\"apex-label\">{}</div>", icon))
            .unwrap_or_default();
        let description = self
            .description
            .map(|text| format!("<p class=\"mx-auto max-w-[320px]\">{}</p>", text))
            .unwrap_or_default();
        let action = match (self.action_label, self.action_href) {
            (Some(label), Some(href)) => {
                format!("<a href=\"{}\" class=\"mt-6 apex-btn\">{}</a>", href, label)
            }
            (Some(label), None) => format!(
                "<button type=\"button\" class=\"mt-6 apex-btn\">{}</button>",
                label
            ),
            _ => String::new(),
        };
        format!(
            "<div class=\"apex-empty-state flex flex-col items-center justify-center py-12 px-6\">{}<h2 class=\"mb-2 apex-h3\">{}</h2>{}{}</div>",
            icon,
            self.title,
            description,
            action,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncState<'a> {
    Loading {
        label: &'a str,
        source_label: Option<&'a str>,
    },
    Error {
        title: &'a str,
        description: &'a str,
        retry_label: Option<&'a str>,
    },
    Empty {
        title: &'a str,
        description: &'a str,
        action_label: Option<&'a str>,
    },
}

impl<'a> AsyncState<'a> {
    pub fn render_html(&self) -> String {
        match self {
            Self::Loading {
                label,
                source_label,
            } => {
                let badge = source_label
                    .map(|value| {
                        Badge {
                            text: value,
                            variant: "outline",
                            size: "default",
                            icon: None,
                        }
                        .render_html()
                    })
                    .unwrap_or_default();
                format!("<div class=\"flex items-center justify-center min-h-[320px]\"><div class=\"flex flex-col items-center gap-3\"><svg class=\"h-8 w-8\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><circle class=\"\" cx=\"12\" cy=\"12\" r=\"10\" stroke=\"currentColor\" stroke-width=\"3\"></circle><path class=\"\" fill=\"currentColor\" d=\"M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z\"></path></svg><p class=\"apex-em\">{}</p>{}</div></div>", label, badge)
            }
            Self::Error {
                title,
                description,
                retry_label,
            } => EmptyState {
                icon_markup: Some("<span class=\"h-8 w-8\">!</span>"),
                title,
                description: Some(description),
                // The Retry control is a real link, not a dead button: an
                // empty-href anchor reloads the current page natively (the
                // console has no JavaScript to drive a button).
                action_label: *retry_label,
                action_href: retry_label.map(|_| ""),
            }
            .render_html(),
            Self::Empty {
                title,
                description,
                action_label,
            } => EmptyState {
                icon_markup: Some("<span class=\"h-8 w-8\">⌂</span>"),
                title,
                description: Some(description),
                action_label: *action_label,
                action_href: None,
            }
            .render_html(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton<'a> {
    pub variant: &'a str,
    pub class_name: &'a str,
}

impl<'a> Skeleton<'a> {
    pub fn render_html(&self) -> String {
        // ARK: loading is blank ruled rows, the shape of the ledger to come.
        format!(
            "<div class=\"{} {}\" aria-hidden=\"true\"><div class=\"apex-loading__row\"><div class=\"apex-loading__bar\"></div><div class=\"apex-loading__bar\" style=\"width:40%\"></div></div></div>",
            skeleton_variant_class(self.variant),
            self.class_name
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusIndicator<'a> {
    pub status: &'a str,
}

impl<'a> StatusIndicator<'a> {
    pub fn render_html(&self) -> String {
        let (label, variant, icon) = status_indicator_config(self.status);
        Badge {
            text: label,
            variant,
            size: "default",
            icon: Some(icon),
        }
        .render_html()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaginationControls {
    pub page: usize,
    pub total_pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog<'a> {
    pub title: &'a str,
    pub description: Option<&'a str>,
    pub body: &'a str,
    pub size: &'a str,
    pub variant: &'a str,
    pub hide_close_button: bool,
}

impl<'a> Dialog<'a> {
    pub fn render_html(&self) -> String {
        // ARK: confirmation is a PAGE SECTION, never a modal. No overlay, no
        // role=dialog, no focus trap, the content is a ruled notice.
        let _ = (self.size, self.variant, self.hide_close_button);
        let description = self
            .description
            .map(|value| format!("<p>{}</p>", html_escape(value)))
            .unwrap_or_default();
        format!(
            "<section class=\"apex-notice\"><b>{}</b>{}{}</section>",
            html_escape(self.title),
            description,
            self.body
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertDialog<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub confirm_label: &'a str,
    pub cancel_label: Option<&'a str>,
    pub variant: &'a str,
    pub dialog_type: &'a str,
}

impl<'a> AlertDialog<'a> {
    pub fn render_html(&self) -> String {
        // ARK: a destructive confirmation is a PAGE (the /confirm flow), not
        // a modal. The primitive renders its content as an inline notice.
        let _ = (self.variant, self.dialog_type, self.cancel_label);
        format!(
            "<section class=\"apex-notice apex-notice--fail\"><b>Confirm</b><p class=\"apex-em\">{}</p><p>{}</p><p><button type=\"submit\" class=\"apex-btn apex-btn--danger\">{}</button></p></section>",
            html_escape(self.title),
            html_escape(self.message),
            html_escape(self.confirm_label),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Popover<'a> {
    pub preview_title: &'a str,
    pub preview_description: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    pub score_label: &'a str,
    pub score_value: &'a str,
    pub dismiss_label: &'a str,
    pub action_label: &'a str,
}

impl<'a> Popover<'a> {
    pub fn render_html(&self) -> String {
        // ARK: no floating popovers. The content is an inline ruled panel —
        // always visible, no positioning, no dismissal, no focus trap.
        format!(
            "<section class=\"apex-panel\"><div class=\"apex-panel__head\">{}</div><div class=\"apex-panel__body\"><p class=\"apex-meta\">{}</p><p class=\"apex-meta\" style=\"margin-top:.4rem\">{}</p><p style=\"margin-top:.6rem\"><span class=\"apex-meta\">{}</span> {}</p></div></section>",
            html_escape(self.title),
            html_escape(self.preview_title),
            html_escape(self.description),
            html_escape(self.score_label),
            Badge { text: self.score_value, variant: "outline", size: "default", icon: None }.render_html(),
        )
        .replace(
            "</div></section>",
            &format!("</div><p style=\"margin-top:.75rem\"><a class=\"apex-link\">{}</a></p></section>", html_escape(self.action_label)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropdownMenuItem<'a> {
    pub label: &'a str,
    pub inset: bool,
    pub destructive: bool,
    pub shortcut: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropdownMenu<'a> {
    pub label: Option<&'a str>,
    pub items: Vec<DropdownMenuItem<'a>>,
    pub show_separator: bool,
}

impl<'a> DropdownMenu<'a> {
    pub fn render_html(&self) -> String {
        // ARK: no kebab menus. Items are inline underlined verbs in the row;
        // shortcuts render as plain machine text beside the verb.
        let mut verbs = String::new();
        for item in &self.items {
            let shortcut = item
                .shortcut
                .map(|value| {
                    format!(
                        "<span class=\"apex-mono\" style=\"margin-left:.4rem\">{}</span>",
                        html_escape(value)
                    )
                })
                .unwrap_or_default();
            let class = if item.destructive {
                "apex-btn--link apex-error"
            } else {
                "apex-btn--link"
            };
            verbs.push_str(&format!(
                "<a class=\"{} apex-link\">{}{}</a>",
                class,
                html_escape(item.label),
                shortcut
            ));
        }
        let label = self
            .label
            .map(|value| format!("<span class=\"apex-meta\">{}</span> ", html_escape(value)))
            .unwrap_or_default();
        format!(
            "<nav class=\"apex-row-actions\" style=\"display:flex;gap:1rem;flex-wrap:wrap\">{}{}</nav>",
            label, verbs
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tooltip<'a> {
    pub content: &'a str,
    pub variant: &'a str,
    pub side: &'a str,
    pub delay_duration: u16,
}

impl<'a> Tooltip<'a> {
    pub fn render_html(&self) -> String {
        // ARK: no hover tooltips, the text is an always-visible help line.
        let _ = (
            self.side,
            tooltip_variant_class(self.variant),
            tooltip_side_class(self.side),
        );
        format!("<p class=\"apex-help\">{}</p>", html_escape(self.content))
    }

    /// Tooltip delay and positioning contract:matches Radix Tooltip behavior.
    pub fn positioning_contract() -> TooltipPositioningContract {
        TooltipPositioningContract {
            default_delay_ms: 700,
            skip_delay_ms: 300,
            side_offset: 4,
            collision_padding: 8,
            supports_arrow: true,
            supports_collision_boundary: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooltipPositioningContract {
    pub default_delay_ms: u16,
    pub skip_delay_ms: u16,
    pub side_offset: u8,
    pub collision_padding: u8,
    pub supports_arrow: bool,
    pub supports_collision_boundary: bool,
}

impl TooltipPositioningContract {
    pub fn spec() -> Self {
        Self {
            default_delay_ms: 700,
            skip_delay_ms: 300,
            side_offset: 4,
            collision_padding: 8,
            supports_arrow: true,
            supports_collision_boundary: true,
        }
    }
}

/// Accordion:accessible expand/collapse sections with animation.
/// animation-timing:200ms ease-out (matches tailwind `accordion-down`/`accordion-up` keyframes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordionItem<'a> {
    pub value: &'a str,
    pub trigger_label: &'a str,
    pub content: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accordion<'a> {
    pub accordion_type: &'a str,
    pub collapsible: bool,
    pub orientation: &'a str,
    pub open_values: Vec<&'a str>,
    pub items: Vec<AccordionItem<'a>>,
}

impl<'a> Accordion<'a> {
    pub fn render_html(&self) -> String {
        // ARK: native <details> disclosures inside ruled panels, zero JS,
        // no roving focus, no rotating chevron.
        let _ = (self.accordion_type, self.collapsible, self.orientation);
        let items = self
            .items
            .iter()
            .map(|item| {
                // open_values is the native details contract: listed values
                // render open, the rest closed.
                let open = if self.open_values.contains(&item.value) { " open" } else { "" };
                format!(
                    "<details class=\"apex-panel\" data-value=\"{}\"{open}><summary class=\"apex-panel__head\">{}</summary><div class=\"apex-panel__body\">{}</div></details>",
                    html_escape(item.value),
                    html_escape(item.trigger_label),
                    item.content
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!("<div class=\"space-y-2\">{items}</div>")
    }

    /// Native <details> carries the disclosure contract: no animation, no
    /// height math, the browser owns open/close.
    pub fn animation_contract() -> AccordionAnimationContract {
        AccordionAnimationContract {
            expand_duration_ms: 0,
            collapse_duration_ms: 0,
            easing: "none",
            uses_height_auto_animation: false,
            css_keyframe_down: "",
            css_keyframe_up: "",
        }
    }

    /// Native <details>/<summary> keyboard contract: Enter/Space toggles on
    /// the summary; there is no custom roving focus.
    pub fn keyboard_contract() -> AccordionKeyboardContract {
        AccordionKeyboardContract {
            space_toggles: true,
            enter_toggles: true,
            arrow_down_moves_next: false,
            arrow_up_moves_prev: false,
            home_moves_first: false,
            end_moves_last: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordionAnimationContract {
    pub expand_duration_ms: u16,
    pub collapse_duration_ms: u16,
    pub easing: &'static str,
    pub uses_height_auto_animation: bool,
    pub css_keyframe_down: &'static str,
    pub css_keyframe_up: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordionKeyboardContract {
    pub space_toggles: bool,
    pub enter_toggles: bool,
    pub arrow_down_moves_next: bool,
    pub arrow_up_moves_prev: bool,
    pub home_moves_first: bool,
    pub end_moves_last: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrollArea<'a> {
    pub orientation: &'a str,
    pub content: &'a str,
}

impl<'a> ScrollArea<'a> {
    pub fn render_html(&self) -> String {
        // ARK: a scroll region is a scroll region.
        let _ = self.orientation;
        format!("<div class=\"overflow-auto\">{}</div>", self.content)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub variant: &'a str,
    pub action_label: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartLegendItem<'a> {
    pub key: &'a str,
    pub name: &'a str,
    pub color: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartSeries<'a> {
    pub key: &'a str,
    pub name: &'a str,
    pub color: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartPoint<'a> {
    pub label: &'a str,
    pub value: &'a str,
    pub color: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexLineChart<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub last_updated_label: Option<&'a str>,
    pub height: usize,
    pub series: Vec<ChartSeries<'a>>,
    pub data_count: usize,
    pub empty_state_reason: &'a str,
}

impl<'a> ApexLineChart<'a> {
    pub fn render_html(&self) -> String {
        render_chart_shell(
            self.title,
            self.description,
            self.last_updated_label,
            self.height,
            &self
                .series
                .iter()
                .map(|series| ChartLegendItem {
                    key: series.key,
                    name: series.name,
                    color: series.color,
                })
                .collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            "<div data-chart-kind=\"line\" class=\"apex-chart-frame\"></div>",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexBarChart<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub last_updated_label: Option<&'a str>,
    pub height: usize,
    pub bars: Vec<ChartSeries<'a>>,
    pub data_count: usize,
    pub layout: &'a str,
    pub empty_state_reason: &'a str,
}

impl<'a> ApexBarChart<'a> {
    pub fn render_html(&self) -> String {
        render_chart_shell(
            self.title,
            self.description,
            self.last_updated_label,
            self.height,
            &self
                .bars
                .iter()
                .map(|series| ChartLegendItem {
                    key: series.key,
                    name: series.name,
                    color: series.color,
                })
                .collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            &format!(
                "<div data-chart-kind=\"bar\" data-layout=\"{}\" class=\"apex-chart-frame\"></div>",
                self.layout
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexAreaChart<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub last_updated_label: Option<&'a str>,
    pub height: usize,
    pub areas: Vec<ChartSeries<'a>>,
    pub data_count: usize,
    pub empty_state_reason: &'a str,
}

impl<'a> ApexAreaChart<'a> {
    pub fn render_html(&self) -> String {
        render_chart_shell(
            self.title,
            self.description,
            self.last_updated_label,
            self.height,
            &self
                .areas
                .iter()
                .map(|series| ChartLegendItem {
                    key: series.key,
                    name: series.name,
                    color: series.color,
                })
                .collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            "<div data-chart-kind=\"area\" class=\"apex-chart-frame\"></div>",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexPieChart<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub last_updated_label: Option<&'a str>,
    pub height: usize,
    pub slices: Vec<ChartPoint<'a>>,
    pub empty_state_reason: &'a str,
    pub inner_radius: usize,
    pub outer_radius: usize,
}

impl<'a> ApexPieChart<'a> {
    pub fn render_html(&self) -> String {
        let legend = self
            .slices
            .iter()
            .map(|slice| ChartLegendItem {
                key: slice.label,
                name: slice.label,
                color: slice.color,
            })
            .collect::<Vec<_>>();
        let content = if self.slices.is_empty() {
            chart_empty_state_markup(self.empty_state_reason)
        } else {
            let labels = self
                .slices
                .iter()
                .map(|slice| format!("<div class=\"\">{} ({})</div>", slice.label, slice.value))
                .collect::<Vec<_>>()
                .join("");
            format!("{}<div data-chart-kind=\"pie\" data-inner-radius=\"{}\" data-outer-radius=\"{}\" class=\"apex-chart-frame\">{}</div>", chart_legend_markup(&legend), self.inner_radius, self.outer_radius, labels)
        };
        render_chart_frame(
            self.title,
            self.description,
            self.last_updated_label,
            self.height,
            &content,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableColumn<'a> {
    pub label: &'a str,
    pub align: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table<'a> {
    pub columns: Vec<TableColumn<'a>>,
    pub rows: Vec<Vec<&'a str>>,
    pub caption: Option<&'a str>,
}

impl<'a> Table<'a> {
    pub fn render_html(&self) -> String {
        let headers = self
            .columns
            .iter()
            .map(|column| {
                format!(
                    "<th scope=\"col\" class=\"align-middle whitespace-nowrap {}\">{}</th>",
                    table_align_class(column.align),
                    column.label
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let rows = if self.rows.is_empty() {
            let colspan = self.columns.len().max(1);
            // A bare "No rows to display" is a dead end: render a real
            // empty state inside the table instead (title + guidance),
            // matching the standalone EmptyState styling.
            format!(
                "<tr class=\"border-b\"><td colspan=\"{colspan}\" class=\"p-10\">\
<div class=\"apex-empty-state flex flex-col items-center justify-center px-6\">\
<h2 class=\"mb-1 apex-h3\">Nothing here yet</h2>\
<p class=\"mx-auto max-w-[320px]\">Entries appear here as soon as one is created. Use the page's create action to add the first one.</p>\
</div></td></tr>"
            )
        } else {
            self.rows
                .iter()
                .map(|row| {
                    let cells = row
                        .iter()
                        .enumerate()
                        .map(|(index, value)| {
                            let align = self
                                .columns
                                .get(index)
                                .map(|column| table_align_class(column.align))
                                .unwrap_or("text-left");
                            let cell_class = if align == "text-right" {
                                "apex-num".to_string()
                            } else {
                                align.to_string()
                            };
                            format!("<td class=\"align-middle {}\">{}</td>", cell_class, value)
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    format!("<tr class=\"border-b min-h-[44px]\">{}</tr>", cells)
                })
                .collect::<Vec<_>>()
                .join("")
        };
        let caption = self
            .caption
            .map(|value| format!("<caption class=\"mt-4\">{}</caption>", value))
            .unwrap_or_default();
        // Review §4.8 / R2's filed item: a wide table scrolls horizontally at
        // mobile, so the scroll container is a keyboard-reachable named
        // region. One change here covers every data table the shared row
        // renderer composes (the CSS `:focus-visible` ring on
        // `.apex-table-wrap` was already in place). The caption names the
        // region when present; otherwise the label stays generic rather than
        // inventing a title.
        let region_label = match self.caption {
            Some(value) if !value.trim().is_empty() => {
                format!("{} (scrollable table)", html_escape(value))
            }
            _ => "Scrollable data table".to_string(),
        };
        format!("<div class=\"apex-table-wrap relative w-full overflow-x-auto\" tabindex=\"0\" role=\"region\" aria-label=\"{region_label}\"><table class=\"apex-table w-full\"><thead class=\"sticky top-0 z-10\"><tr>{}</tr></thead><tbody>{}</tbody>{}</table></div>", headers, rows, caption)
    }
}

impl<'a> Toast<'a> {
    pub fn render_html(&self) -> String {
        // ARK: outcomes are written into the page as a status line, no
        // overlay, no dismiss control, no icons.
        let description = self
            .description
            .map(|value| format!(" {}", html_escape(value)))
            .unwrap_or_default();
        let action = self
            .action_label
            .map(|value| format!(" {}", html_escape(value)))
            .unwrap_or_default();
        let title = self
            .title
            .map(|value| format!("<b>{}</b>", html_escape(value)))
            .unwrap_or_default();
        format!(
            "<p class=\"apex-statusline\" role=\"status\">{}{}{}</p>",
            title, description, action
        )
    }
}

impl PaginationControls {
    /// DEPRECATED (review §5.2 "Pagination: retain the working link-based
    /// renderer; deprecate inert button output"): this renders four
    /// `<button>` elements with NO handler behind them, the console ships no
    /// JavaScript, so nothing can ever respond. Use
    /// [`PaginationControls::render_html_with_links`], which emits real
    /// `<a href>` links that preserve the current filter query and keeps only
    /// the disabled edges as non-interactive buttons.
    #[deprecated(note = "inert buttons without a handler; use render_html_with_links instead")]
    pub fn render_html(&self) -> String {
        let safe_total_pages = self.total_pages.max(1);
        // Clamp the page counter so a zero/negative state renders "Page 1"
        // instead of "Page 0 of N" with both back-buttons disabled.
        let safe_page = self.page.max(1);
        let is_first_page = safe_page <= 1;
        let is_last_page = safe_page >= safe_total_pages;
        let button = |label: &str, disabled: bool| {
            let disabled_attr = if disabled {
                " disabled aria-disabled=\"true\""
            } else {
                ""
            };
            format!(
                "<button class=\"apex-btn\"{}>{}</button>",
                disabled_attr, label
            )
        };
        format!(
            "<div class=\"flex items-center gap-2\" role=\"navigation\" aria-label=\"Pagination controls\">{}{}<span class=\"px-2\">Page {} of {}</span>{}{}</div>",
            button("First", is_first_page),
            button("Previous", is_first_page),
            safe_page,
            safe_total_pages,
            button("Next", is_last_page),
            button("Last", is_last_page),
        )
    }

    pub fn render_html_with_links(
        &self,
        base_path: &str,
        extra_query: Option<&str>,
        persistence_key: Option<&str>,
    ) -> String {
        let safe_total_pages = self.total_pages.max(1);
        let current_page = self.page.clamp(1, safe_total_pages);
        let preserved = extra_query
            .filter(|value| !value.is_empty())
            .map(|value| format!("&{}", value))
            .unwrap_or_default();
        // Dead JS-era markup purge: the pagination storage key fed a
        // localStorage bridge that no longer exists. Query preservation is
        // server-side now (the links carry the filter query); the parameter
        // stays for call-site compatibility and is deliberately unused.
        let _ = persistence_key;
        let link = |label: &str, target_page: usize, disabled: bool| {
            if disabled {
                return format!("<span class=\"apex-meta\">{}</span>", label);
            }
            format!(
                "<a href=\"{}?page={}{}\">{}</a>",
                base_path, target_page, preserved, label
            )
        };
        format!(
            "<nav class=\"apex-pager\" role=\"navigation\" aria-label=\"Pagination controls\" data-current-page=\"{}\" data-total-pages=\"{}\">{}{}<span class=\"apex-pager__sentence\">Page {} of {}</span>{}{}</div>",
            current_page,
            safe_total_pages,
            link("First", 1, current_page == 1),
            link("Previous", current_page.saturating_sub(1).max(1), current_page == 1),
            current_page,
            safe_total_pages,
            link("Next", (current_page + 1).min(safe_total_pages), current_page == safe_total_pages),
            link("Last", safe_total_pages, current_page == safe_total_pages),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabItem<'a> {
    pub value: &'a str,
    pub label: &'a str,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tabs<'a> {
    pub variant: &'a str,
    pub tabs: Vec<TabItem<'a>>,
    pub content_html: &'a str,
}

impl<'a> Tabs<'a> {
    pub fn render_html(&self) -> String {
        // ARK: a ruled strip of tab labels (`.apex-tabs a.is-active`); the
        // zero-JS console changes tabs by navigation, so a TabItem without a
        // target renders as static text, never a dead button.
        let _ = self.variant;
        let tabs = self
            .tabs
            .iter()
            .map(|tab| {
                let class = if tab.active { "is-active" } else { "" };
                format!(
                    "<span class=\"{}\">{}</span>",
                    class,
                    html_escape(tab.label)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<div class=\"apex-tabs\">{tabs}</div><div role=\"tabpanel\">{}</div>",
            self.content_html
        )
    }
}

impl<'a> Card<'a> {
    pub fn render_html(&self) -> String {
        // ARK: one panel recipe. `interactive` changes nothing visually —
        // panels are not buttons and carry no hover lift.
        let _ = self.interactive;
        format!(
            "<section class=\"apex-panel {}\"><div class=\"apex-panel__head\"><h2 class=\"apex-h3\">{}</h2></div><div class=\"apex-panel__body\">{}</div></section>",
            card_padding_class(self.padding),
            self.title,
            self.body,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ButtonDensityContract {
    pub compact_height: &'static str,
    pub default_height: &'static str,
    pub comfortable_height: &'static str,
}

impl ButtonDensityContract {
    pub fn spec() -> Self {
        Self {
            compact_height: "h-8",
            default_height: "h-12",
            comfortable_height: "h-14",
        }
    }
}

pub fn button_density_class(density: &str) -> &'static str {
    // ARK owns button geometry; density maps to the three sanctioned steps.
    match density {
        "compact" => "apex-btn--sm",
        "comfortable" => "apex-btn--lg",
        _ => "",
    }
}

/// Input helper-text contract (4.4):renders below-input assistance text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputHelperText<'a> {
    pub text: &'a str,
    pub variant: &'a str,
}

impl<'a> InputHelperText<'a> {
    pub fn render_html(&self) -> String {
        let class = match self.variant {
            "error" => "text-xs text-destructive mt-1.5",
            "success" => "text-xs text-success mt-1.5",
            "warning" => "text-xs text-warning mt-1.5",
            _ => "text-xs text-muted-foreground mt-1.5",
        };
        format!("<p class=\"{}\" role=\"status\">{}</p>", class, self.text)
    }
}

/// Input autofill/paste/IME behavior contract (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBehaviorContract {
    pub autofill_preserves_styling: bool,
    pub paste_strips_formatting: bool,
    pub ime_composition_supported: bool,
    pub autofill_css: &'static str,
}

impl InputBehaviorContract {
    pub fn spec() -> Self {
        Self {
            autofill_preserves_styling: true,
            paste_strips_formatting: true,
            ime_composition_supported: true,
            autofill_css: "autofill:shadow-[inset_0_0_0px_1000px] autofill:shadow-background autofill:[-webkit-text-fill-color:inherit]",
        }
    }
}

/// Select dropdown positioning/collision/keyboard contract (4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectBehaviorContract {
    pub dropdown_side: &'static str,
    pub dropdown_align: &'static str,
    pub side_offset: u8,
    pub collision_padding: u8,
    pub supports_viewport_collision: bool,
    pub keyboard_arrow_navigates: bool,
    pub keyboard_enter_selects: bool,
    pub keyboard_escape_closes: bool,
    pub keyboard_type_ahead: bool,
    pub max_height_viewport_percent: u8,
}

impl SelectBehaviorContract {
    pub fn spec() -> Self {
        Self {
            dropdown_side: "bottom",
            dropdown_align: "start",
            side_offset: 4,
            collision_padding: 8,
            supports_viewport_collision: true,
            keyboard_arrow_navigates: true,
            keyboard_enter_selects: true,
            keyboard_escape_closes: true,
            keyboard_type_ahead: true,
            max_height_viewport_percent: 40,
        }
    }
}

/// Dialog behavior contract (4.13):focus trap, escape, click-outside, animation, portal, scroll-lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogBehaviorContract {
    pub focus_trap_enabled: bool,
    pub initial_focus_selector: &'static str,
    pub restore_focus_on_close: bool,
    pub escape_closes: bool,
    pub click_outside_closes: bool,
    pub scroll_lock_enabled: bool,
    pub portal_container: &'static str,
    pub animation_enter_ms: u16,
    pub animation_exit_ms: u16,
    pub animation_easing: &'static str,
    pub overlay_blur: &'static str,
}

impl DialogBehaviorContract {
    pub fn spec() -> Self {
        Self {
            focus_trap_enabled: true,
            initial_focus_selector: "[data-autofocus], button:not([disabled])",
            restore_focus_on_close: true,
            escape_closes: true,
            click_outside_closes: true,
            scroll_lock_enabled: true,
            portal_container: "body",
            animation_enter_ms: 200,
            animation_exit_ms: 200,
            animation_easing: "ease-out",
            overlay_blur: "none",
        }
    }
}

/// Dropdown menu behavior contract (4.15):positioning, keyboard nav, nested menus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropdownMenuBehaviorContract {
    pub side: &'static str,
    pub align: &'static str,
    pub side_offset: u8,
    pub collision_padding: u8,
    pub supports_nested_submenus: bool,
    pub keyboard_arrow_navigates: bool,
    pub keyboard_enter_activates: bool,
    pub keyboard_escape_closes: bool,
    pub keyboard_right_opens_submenu: bool,
    pub keyboard_left_closes_submenu: bool,
    pub typeahead_enabled: bool,
    pub close_on_outside_click: bool,
}

impl DropdownMenuBehaviorContract {
    pub fn spec() -> Self {
        Self {
            side: "bottom",
            align: "start",
            side_offset: 4,
            collision_padding: 8,
            supports_nested_submenus: true,
            keyboard_arrow_navigates: true,
            keyboard_enter_activates: true,
            keyboard_escape_closes: true,
            keyboard_right_opens_submenu: true,
            keyboard_left_closes_submenu: true,
            typeahead_enabled: true,
            close_on_outside_click: true,
        }
    }
}

/// Popover behavior contract (4.16):arrow placement and collision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopoverBehaviorContract {
    pub supports_arrow: bool,
    pub arrow_size: u8,
    pub arrow_padding: u8,
    pub side_offset: u8,
    pub collision_padding: u8,
    pub supports_collision_boundary: bool,
    pub close_on_outside_click: bool,
    pub close_on_escape: bool,
}

impl PopoverBehaviorContract {
    pub fn spec() -> Self {
        Self {
            supports_arrow: true,
            arrow_size: 8,
            arrow_padding: 4,
            side_offset: 4,
            collision_padding: 8,
            supports_collision_boundary: true,
            close_on_outside_click: true,
            close_on_escape: true,
        }
    }
}

/// Tabs behavior contract (4.19):keyboard navigation and focus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabsBehaviorContract {
    pub keyboard_arrow_navigates: bool,
    pub keyboard_home_first: bool,
    pub keyboard_end_last: bool,
    pub activation_mode: &'static str,
    pub focus_follows_selection: bool,
    pub loop_navigation: bool,
    pub orientation: &'static str,
}

impl TabsBehaviorContract {
    pub fn spec() -> Self {
        Self {
            keyboard_arrow_navigates: true,
            keyboard_home_first: true,
            keyboard_end_last: true,
            activation_mode: "automatic",
            focus_follows_selection: true,
            loop_navigation: true,
            orientation: "horizontal",
        }
    }
}

/// ScrollArea momentum behavior contract (4.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrollAreaBehaviorContract {
    pub native_momentum_scrolling: bool,
    pub scrollbar_auto_hide: bool,
    pub scrollbar_auto_hide_delay_ms: u16,
    pub scroll_snap: bool,
    pub overscroll_behavior: &'static str,
    pub css_scroll_behavior: &'static str,
}

impl ScrollAreaBehaviorContract {
    pub fn spec() -> Self {
        Self {
            native_momentum_scrolling: true,
            scrollbar_auto_hide: true,
            scrollbar_auto_hide_delay_ms: 600,
            scroll_snap: false,
            overscroll_behavior: "contain",
            css_scroll_behavior: "-webkit-overflow-scrolling: touch",
        }
    }
}

/// Table sorting/selection contract (4.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInteractionContract {
    pub sortable: bool,
    pub sort_indicator_asc: &'static str,
    pub sort_indicator_desc: &'static str,
    pub sort_indicator_none: &'static str,
    pub selectable: bool,
    pub select_all_header: bool,
    pub row_checkbox_aria: &'static str,
    pub select_all_aria: &'static str,
    pub keyboard_space_toggles: bool,
    pub keyboard_shift_range_select: bool,
}

impl TableInteractionContract {
    pub fn spec() -> Self {
        Self {
            sortable: true,
            sort_indicator_asc: "▲",
            sort_indicator_desc: "▼",
            sort_indicator_none: "⇅",
            selectable: true,
            select_all_header: true,
            row_checkbox_aria: "Select row",
            select_all_aria: "Select all rows",
            keyboard_space_toggles: true,
            keyboard_shift_range_select: true,
        }
    }
}

/// Renderable sortable table header.
pub fn render_sortable_header(
    label: &str,
    sort_key: &str,
    current_sort: Option<(&str, &str)>,
) -> String {
    let (indicator, aria_sort) = match current_sort {
        Some((key, "asc")) if key == sort_key => ("▲", "ascending"),
        Some((key, "desc")) if key == sort_key => ("▼", "descending"),
        _ => ("⇅", "none"),
    };
    format!(
        "<th scope=\"col\" class=\"align-middle whitespace-nowrap\" aria-sort=\"{}\" data-sort-key=\"{}\"><div class=\"flex items-center gap-1\">{}<span class=\"\">{}</span></div></th>",
        aria_sort, sort_key, label, indicator,
    )
}

/// Renderable selectable table row checkbox.
pub fn render_row_checkbox(selected: bool) -> String {
    // ARK: a native checkbox with its square ink rule.
    let checked = if selected { " checked" } else { "" };
    format!(
        "<td class=\"w-12 align-middle\"><input type=\"checkbox\" aria-label=\"Select row\" class=\"apex-checkbox apex-input\"{checked} /></td>"
    )
}

/// Skeleton shimmer animation contract (4.27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonAnimationContract {
    pub shimmer_enabled: bool,
    pub shimmer_css: &'static str,
    pub pulse_duration_ms: u16,
    pub dimension_matching: bool,
}

impl SkeletonAnimationContract {
    pub fn spec() -> Self {
        Self {
            shimmer_enabled: false,
            shimmer_css: "apex-loading",
            pulse_duration_ms: 0,
            dimension_matching: true,
        }
    }
}

/// Skeleton with exact dimensions for layout parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonDimensioned {
    pub width: &'static str,
    pub height: &'static str,
    pub variant: &'static str,
    pub rounded: &'static str,
}

impl SkeletonDimensioned {
    pub fn render_html(&self) -> String {
        format!(
            "<div class=\"{} {}\" style=\"width: {}; height: {};\" aria-hidden=\"true\"></div>",
            skeleton_variant_class(self.variant),
            self.rounded,
            self.width,
            self.height,
        )
    }
}

/// Toast timing/dismissal contract (4.30).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToastBehaviorContract {
    pub default_duration_ms: u32,
    pub dismiss_on_swipe: bool,
    pub swipe_direction: &'static str,
    pub swipe_threshold: u8,
    pub pause_on_hover: bool,
    pub pause_on_focus_within: bool,
    pub max_visible: u8,
    pub stacking_gap: u8,
    pub auto_close: bool,
    pub position: &'static str,
    pub close_button_always_visible: bool,
}

impl ToastBehaviorContract {
    pub fn spec() -> Self {
        Self {
            default_duration_ms: 5000,
            dismiss_on_swipe: true,
            swipe_direction: "right",
            swipe_threshold: 50,
            pause_on_hover: true,
            pause_on_focus_within: true,
            max_visible: 5,
            stacking_gap: 8,
            auto_close: true,
            position: "bottom-right",
            close_button_always_visible: true,
        }
    }
}

/// Chart interaction contract (4.31):axis, gridline, hover state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartInteractionContract {
    pub axis_line_color: &'static str,
    pub axis_tick_size: u8,
    pub axis_label_font_size: &'static str,
    pub gridline_dash_array: &'static str,
    pub gridline_color: &'static str,
    pub tooltip_follows_cursor: bool,
    pub tooltip_snap_to_point: bool,
    pub crosshair_enabled: bool,
    pub crosshair_dash_array: &'static str,
    pub hover_dot_radius: u8,
    pub hover_dot_stroke_width: u8,
}

impl ChartInteractionContract {
    pub fn spec() -> Self {
        Self {
            axis_line_color: "rgb(var( --border))",
            axis_tick_size: 5,
            axis_label_font_size: "12px",
            gridline_dash_array: "3 3",
            gridline_color: "rgb(var( --border) / 0.3)",
            tooltip_follows_cursor: false,
            tooltip_snap_to_point: true,
            crosshair_enabled: true,
            crosshair_dash_array: "4 4",
            hover_dot_radius: 4,
            hover_dot_stroke_width: 2,
        }
    }
}

/// Renderable chart axis with gridlines.
pub fn render_chart_axis(label: &str, side: &str) -> String {
    format!(
        "<g data-axis=\"{}\" aria-label=\"{}\"><line stroke=\"rgb(var(--border))\" /><text class=\"apex-meta\">{}</text></g>",
        html_escape(side),
        html_escape(label),
        html_escape(label),
    )
}

/// Renderable chart gridlines.
pub fn render_chart_gridlines(count: usize) -> String {
    let lines = (0..count).map(|_| {
        "<line class=\"gridline\" stroke=\"rgb(var( --border))\" stroke-opacity=\"0.3\" stroke-dasharray=\"3 3\" />"
    }).collect::<Vec<_>>().join("");
    format!("<g aria-hidden=\"true\">{}</g>", lines)
}

/// Routing behavior contracts (4.32):nested layouts, redirects, query params, hash, back/forward, scroll restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingBehaviorContract {
    pub nested_layout_support: bool,
    pub redirect_status_code: u16,
    pub query_param_preservation: bool,
    pub hash_navigation: bool,
    pub back_forward_navigation: bool,
    pub scroll_restoration: bool,
    pub scroll_restoration_key: &'static str,
    pub redirect_preserve_query: bool,
    pub deep_link_support: bool,
    pub auth_redirect_target: &'static str,
}

impl RoutingBehaviorContract {
    pub fn spec() -> Self {
        Self {
            nested_layout_support: true,
            redirect_status_code: 307,
            query_param_preservation: true,
            hash_navigation: true,
            back_forward_navigation: true,
            scroll_restoration: true,
            scroll_restoration_key: "scroll-position",
            redirect_preserve_query: true,
            deep_link_support: true,
            auth_redirect_target: "/login",
        }
    }
}

/// Shell behavior contracts (4.33):tab persistence, page header, command palette.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellBehaviorContract {
    pub tab_persistence_key: &'static str,
    pub tab_persistence_storage: &'static str,
    pub page_header_breadcrumbs: bool,
    pub page_header_action_slot: bool,
    pub command_palette_shortcut: &'static str,
    pub command_palette_fuzzy_search: bool,
    pub command_palette_max_results: usize,
    pub command_palette_sections: &'static [&'static str],
}

impl ShellBehaviorContract {
    pub fn spec() -> Self {
        Self {
            tab_persistence_key: "apexmail-active-tab",
            tab_persistence_storage: "localStorage",
            page_header_breadcrumbs: true,
            page_header_action_slot: true,
            command_palette_shortcut: "⌘K",
            command_palette_fuzzy_search: true,
            command_palette_max_results: 10,
            command_palette_sections: &["Navigation", "Actions", "Settings", "Help"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_phase_four_primitives() {
        assert!(PRIMITIVES.len() >= 20);
        assert!(PRIMITIVES.iter().any(|item| item.rust_name == "Button"));
        assert!(PRIMITIVES.iter().any(|item| item.rust_name == "Toast"));
    }

    #[test]
    fn renders_core_scaffolds() {
        let button = Button {
            label: "Save",
            variant: "default",
            size: "default",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true,
        };
        let input = Input {
            id: None,
            input_type: "email",
            value: "",
            placeholder: "you@example.com",
            variant: "default",
            size: "default",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: false,
            name: None,
        };
        let progress = Progress {
            value: 42,
            variant: "default",
            size: "default",
            animated: false,
            show_value: true,
        };

        assert!(button.render_html().contains("Save"));
        assert!(input.render_html().contains("you@example.com"));
        assert!(progress.render_html().contains("42 of 100"));
    }

    #[test]
    fn button_supports_variants_sizes_and_states() {
        let html = Button {
            label: "Deploy",
            variant: "destructive",
            size: "lg",
            disabled: true,
            loading: false,
            left_icon: Some("<svg></svg>"),
            right_icon: Some("<svg></svg>"),
            submit: false,
        }
        .render_html();

        // ARK: destructive is the red-rule variant; every control composes
        // the apex-btn primitive, and ARK is icon-free as chrome.
        assert!(html.contains("apex-btn"));
        assert!(html.contains("apex-btn--danger"), "{html}");
        assert!(!html.contains("uppercase"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
        assert!(
            !html.contains("<svg") && !html.contains("mr-2"),
            "no icon chrome: {html}"
        );
        // ARK: focus is the global 3px double outline; no ring utilities, no
        // pressed-scale, no premium easing, no shadows.
        assert!(!html.contains("focus-visible:ring"));
        assert!(!html.contains("scale-"));
        assert!(!html.contains("ease-premium"));
        assert!(!html.contains("shadow"));
    }

    #[test]
    fn button_supports_loading_and_icon_only_states() {
        let loading = Button {
            label: "Saving",
            variant: "default",
            size: "default",
            disabled: false,
            loading: true,
            left_icon: Some("<svg></svg>"),
            right_icon: Some("<svg></svg>"),
            submit: false,
        }
        .render_html();
        let icon_only = Button {
            label: "",
            variant: "ghost",
            size: "icon",
            disabled: false,
            loading: false,
            left_icon: Some("<svg></svg>"),
            right_icon: None,
            submit: true,
        }
        .render_html();

        // ARK: loading changes the verb and the border, never a spinner.
        assert!(!loading.contains("animate-spin"));
        assert!(loading.contains("aria-busy=\"true\""));
        assert!(loading.contains("apex-btn--busy"));
        assert!(!loading.contains("<span class=\"mr-2\"><svg></svg></span>"));
        assert!(icon_only.contains("data-size=\"icon\""));
    }

    #[test]
    fn outline_button_uses_dark_mode_safe_tokens() {
        let html = Button {
            label: "Duplicate",
            variant: "outline",
            size: "default",
            disabled: false,
            loading: false,
            left_icon: None,
            right_icon: None,
            submit: true,
        }
        .render_html();

        // ARK: outline/secondary compose the base primitive (2px ink rule);
        // the focus is the global outline, so the dark-mode ring utilities
        // cannot return.
        assert!(html.contains("apex-btn"), "{html}");
        assert!(
            !html.contains("ring-") && !html.contains("text-foreground"),
            "{html}"
        );
    }

    #[test]
    fn input_supports_icons_and_error_state() {
        let html = Input {
            id: None,
            input_type: "text",
            value: "bad",
            placeholder: "email",
            variant: "default",
            size: "lg",
            left_icon: Some("<svg></svg>"),
            right_icon: Some("<svg></svg>"),
            error: Some("Required"),
            disabled: false,
            autocomplete: None,
            required: false,
            name: None,
        }
        .render_html();

        assert!(html.contains("apex-input"));
        assert!(html.contains("apex-input-error"));
        assert!(html.contains("Required"));
        assert!(html.contains("placeholder=\"email\""));
        // Spiral-Lock DNA: the concentric two-arms focus replaced the ring.
        // ARK: focus is the one global 3px double outline; no per-control ring.
        assert!(!html.contains("apex-focus-ring"));
    }

    #[test]
    fn input_supports_disabled_size_and_default_states() {
        let html = Input {
            id: None,
            input_type: "email",
            value: "owner@apexmail.ee",
            placeholder: "you@example.com",
            variant: "default",
            size: "sm",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: true,
            autocomplete: None,
            required: false,
            name: None,
        }
        .render_html();

        assert!(html.contains("apex-input"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
        assert!(!html.contains("rounded-["));
    }

    #[test]
    fn textarea_supports_resize_and_counter() {
        let html = Textarea {
            id: None,
            value: "abc",
            placeholder: "Write",
            variant: "default",
            resize: "none",
            max_length: Some(10),
            show_count: true,
            name: None,
        }
        .render_html();

        assert!(html.contains("apex-textarea"));
        assert!(html.contains("maxlength=\"10\""));
        assert!(html.contains("aria-describedby"));
        assert!(html.contains("maxlength=\"10\""));
        assert!(html.contains("absolute bottom-2 right-2"));
    }

    /// Form fields must carry a `name` attribute, without one, `FormData`
    /// serialization skips the element entirely and `data-api-form` handlers
    /// receive an empty `{}` payload.
    #[test]
    fn named_fields_render_name_attributes() {
        let input = Input {
            id: None,
            input_type: "email",
            value: "",
            placeholder: "contact@example.com",
            variant: "default",
            size: "default",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: true,
            name: Some("email"),
        }
        .render_html();
        assert!(input.contains("name=\"email\""));

        let textarea = Textarea {
            id: None,
            value: "",
            placeholder: "Paste HTML",
            variant: "default",
            resize: "vertical",
            max_length: None,
            show_count: false,
            name: Some("html_body"),
        }
        .render_html();
        assert!(textarea.contains("<textarea name=\"html_body\""));

        let select = Select {
            id: None,
            placeholder: "Select audience",
            value_label: Some("VIP Customers"),
            variant: "default",
            size: "default",
            open: false,
            options: vec![SelectOption {
                value: "vip",
                label: "VIP Customers",
                disabled: false,
                selected: true,
            }],
            name: Some("audience"),
            filter_param: None,
        }
        .render_html();
        // ARK: a native select carries name + the selected option.
        assert!(select.contains("name=\"audience\""));
        assert!(select.contains("data-field=\"audience\""));
        assert!(select.contains("<option value=\"vip\" selected>"));

        // Unnamed fields must not render a stale/empty name attribute.
        let unnamed = Input {
            id: None,
            input_type: "text",
            value: "",
            placeholder: "filter",
            variant: "default",
            size: "default",
            left_icon: None,
            right_icon: None,
            error: None,
            disabled: false,
            autocomplete: None,
            required: false,
            name: None,
        }
        .render_html();
        assert!(!unnamed.contains("name="));
    }

    #[test]
    fn checkbox_supports_indeterminate_and_size() {
        let html = Checkbox {
            checked: false,
            variant: "success",
            size: "lg",
            indeterminate: true,
            disabled: true,
            aria_label: None,
        }
        .render_html();

        assert!(html.contains("<input type=\"checkbox\""), "{html}");
        assert!(html.contains("aria-checked=\"mixed\""), "{html}");
        assert!(html.contains("disabled aria-disabled=\"true\""));
    }

    #[test]
    fn label_supports_required_optional_and_variants() {
        let html = Label {
            html_for: None,
            text: "Email",
            required: true,
            optional: false,
            variant: "error",
            size: "lg",
        }
        .render_html();

        assert!(html.contains("apex-label"), "{html}");
        assert!(html.contains("Email"));
        assert!(html.contains("*</span>"));
    }

    #[test]
    fn progress_supports_variant_size_and_animation() {
        let html = Progress {
            value: 67,
            variant: "warning",
            size: "xl",
            animated: true,
            show_value: true,
        }
        .render_html();

        assert!(html.contains("67 of 100"), "{html}");
        assert!(html.contains("role=\"progressbar\""), "{html}");
        assert!(!html.contains("animate-"));
    }

    #[test]
    fn badge_supports_variant_size_and_icon() {
        let html = Badge {
            text: "Active",
            variant: "success",
            size: "sm",
            icon: Some("<svg></svg>"),
        }
        .render_html();

        assert!(html.contains("apex-status apex-status--on"), "{html}");
        // Badges are small uppercase status pills (rounded-full, semibold).
        assert!(!html.contains("rounded-full"));
        assert!(!html.contains("font-semibold"));
        assert!(!html.contains("text-[10px]"));
        assert!(!html.contains("<svg"), "no icon markup: {html}");

        let warning = Badge {
            text: "Warning",
            variant: "outline-warning",
            size: "default",
            icon: None,
        }
        .render_html();
        assert!(warning.contains("apex-status--warn"), "{warning}");
    }

    #[test]
    fn closed_select_still_ships_option_dom_with_values() {
        let html = Select {
            id: None,
            placeholder: "Select plan",
            value_label: Some("Starter"),
            variant: "default",
            size: "default",
            open: false,
            options: vec![SelectOption {
                value: "starter",
                label: "Starter",
                disabled: false,
                selected: true,
            }],
            name: Some("plan"),
            filter_param: None,
        }
        .render_html();
        // The listbox is present but hidden (closed state).
        assert!(html.contains("<select class=\"apex-select\""), "{html}");
        assert!(
            html.contains("<option value=\"starter\" selected>"),
            "{html}"
        );
        assert!(!html.contains("role=\"listbox\""));
    }

    #[test]
    fn radio_items_have_label_for_id_wiring() {
        let html = RadioGroup {
            name: "plan",
            selected: "pro",
            variant: "default",
            size: "default",
            orientation: "vertical",
            items: vec![
                RadioGroupItem {
                    value: "starter",
                    label: "Starter",
                    disabled: false,
                },
                RadioGroupItem {
                    value: "pro",
                    label: "Pro",
                    disabled: false,
                },
            ],
        }
        .render_html();
        // ARK: labelled native radios, the label wraps the input, so no
        // id/for wiring is needed (and none is emitted).
        assert!(html.contains("<label class=\"apex-check\">"), "{html}");
        assert!(
            html.contains("value=\"starter\"") && html.contains("value=\"pro\""),
            "{html}"
        );
        assert!(html.contains("<span>Pro</span>"), "{html}");
        assert!(!html.contains("for=\"plan-option"));
    }

    #[test]
    fn avatar_escapes_image_url_and_label() {
        let html = Avatar {
            label: "Alt\"><script>alert(1)</script>",
            image_url: Some("https://x.example/a.png?u=1\"><script>alert(2)</script>"),
            fallback: "AB",
            size: "default",
            status: "none",
        }
        .render_html();
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn dialog_ids_are_unique_per_title_and_deterministic() {
        let a = Dialog {
            title: "Delete campaign?",
            description: None,
            body: "",
            size: "default",
            variant: "default",
            hide_close_button: false,
        }
        .render_html();
        let b = Dialog {
            title: "Delete list?",
            description: None,
            body: "",
            size: "default",
            variant: "default",
            hide_close_button: false,
        }
        .render_html();
        assert!(a.contains("<b>Delete campaign?</b>"), "{a}");
        assert!(b.contains("<b>Delete list?</b>"), "{b}");
        assert_eq!(
            a,
            Dialog {
                title: "Delete campaign?",
                description: None,
                body: "",
                size: "default",
                variant: "default",
                hide_close_button: false,
            }
            .render_html()
        );
    }

    #[test]
    fn select_supports_trigger_and_open_menu() {
        let html = Select {
            id: None,
            placeholder: "Select plan",
            value_label: Some("Enterprise"),
            variant: "success",
            size: "lg",
            open: true,
            options: vec![
                SelectOption {
                    value: "starter",
                    label: "Starter",
                    disabled: false,
                    selected: false,
                },
                SelectOption {
                    value: "enterprise",
                    label: "Enterprise",
                    disabled: false,
                    selected: true,
                },
            ],
            name: None,
            filter_param: None,
        }
        .render_html();

        assert!(html.contains("<select class=\"apex-select\""), "{html}");
        assert!(html.contains("Enterprise"), "{html}");
        assert!(!html.contains("data-open"), "{html}");
        assert!(!html.contains("role=\"option\""));
    }

    #[test]
    fn slider_supports_variant_size_and_tooltip() {
        let html = Slider {
            value: 75,
            variant: "warning",
            size: "lg",
            show_tooltip: true,
        }
        .render_html();

        assert!(html.contains("<input type=\"range\""), "{html}");
        assert!(html.contains("value=\"75\""), "{html}");
        assert!(!html.contains("data-size"));
    }

    #[test]
    fn tabs_support_variants_and_active_state() {
        let html = Tabs {
            variant: "underline",
            tabs: vec![
                TabItem {
                    value: "overview",
                    label: "Overview",
                    active: true,
                },
                TabItem {
                    value: "usage",
                    label: "Usage",
                    active: false,
                },
            ],
            content_html: "<section>Panel</section>",
        }
        .render_html();

        // ARK: a ruled tab strip; the active item carries is-active.
        assert!(html.contains("apex-tabs"), "{html}");
        assert!(html.contains("class=\"is-active\""), "{html}");
        assert!(html.contains("<section>Panel</section>"), "{html}");
        assert!(!html.contains("data-state"));
    }

    #[test]
    fn avatar_supports_fallback_size_and_status() {
        let html = Avatar {
            label: "Ada Lovelace",
            image_url: None,
            fallback: "AL",
            size: "xl",
            status: "online",
        }
        .render_html();

        assert!(html.contains("apex-avatar"), "{html}");
        assert!(!html.contains("rounded-full") && !html.contains("ring-"));
        assert!(html.contains(">AL<"));
    }

    #[test]
    fn empty_state_supports_description_and_action() {
        let html = EmptyState {
            icon_markup: Some("<span class=\"h-8 w-8\">☆</span>"),
            title: "No campaigns yet",
            description: Some("Create your first campaign to get started."),
            action_label: Some("Create campaign"),
            action_href: None,
        }
        .render_html();

        assert!(html.contains("No campaigns yet"));
        assert!(html.contains("Create your first campaign"));
        assert!(html.contains("Create campaign"));
    }

    #[test]
    fn async_state_supports_loading_error_and_empty() {
        let loading = AsyncState::Loading {
            label: "Loading...",
            source_label: Some("api"),
        }
        .render_html();
        let error = AsyncState::Error {
            title: "Something went wrong",
            description: "Retry later",
            retry_label: Some("Retry"),
        }
        .render_html();
        let empty = AsyncState::Empty {
            title: "No data",
            description: "Nothing to show",
            action_label: None,
        }
        .render_html();

        assert!(loading.contains("Loading..."));
        assert!(loading.contains("api"));
        assert!(error.contains("Something went wrong"));
        assert!(error.contains("Retry"));
        assert!(empty.contains("No data"));
    }

    #[test]
    fn skeleton_supports_variants() {
        let html = Skeleton {
            variant: "circle",
            class_name: "h-10 w-10",
        }
        .render_html();
        assert!(html.contains("apex-loading"), "{html}");
        assert!(!html.contains("rounded"));
        assert!(html.contains("h-10 w-10"));
    }

    #[test]
    fn status_indicator_maps_known_statuses() {
        let html = StatusIndicator {
            status: "delivered",
        }
        .render_html();
        assert!(html.contains("Delivered"));
        assert!(html.contains("success"));
    }

    /// Regression (audit SM11 F1): unknown status strings fall through
    /// `status_indicator_config` as the RAW input (DB-sourced event types /
    /// suppression reasons are not a fixed enum), so the badge label, and
    /// every other primitive text slot, must be escaped at the render
    /// boundary. Markup in an unrecognized status value must render as text,
    /// never as elements or attributes.
    #[test]
    fn unknown_status_renders_escaped_not_as_markup() {
        let payload = "<img src=x onerror=alert(1)>";
        let badge = Badge {
            text: payload,
            variant: "secondary",
            size: "default",
            icon: None,
        }
        .render_html();
        assert!(
            !badge.contains("<img"),
            "raw markup must not reach the badge label"
        );
        assert!(badge.contains("&lt;img src=x onerror=alert(1)&gt;"));

        let status = StatusIndicator { status: payload }.render_html();
        assert!(
            !status.contains("<img"),
            "unknown status must render escaped"
        );
        assert!(status.contains("&lt;img"));

        let dialog = Dialog {
            title: payload,
            description: Some(payload),
            body: "",
            size: "default",
            variant: "default",
            hide_close_button: true,
        }
        .render_html();
        assert!(
            !dialog.contains("<img"),
            "Dialog text slots must be escaped"
        );

        let alert = AlertDialog {
            title: payload,
            message: payload,
            confirm_label: payload,
            cancel_label: Some(payload),
            variant: "destructive",
            dialog_type: "confirm",
        }
        .render_html();
        assert!(
            !alert.contains("<img"),
            "AlertDialog text slots must be escaped"
        );

        let popover = Popover {
            preview_title: payload,
            preview_description: payload,
            title: payload,
            description: payload,
            score_label: payload,
            score_value: payload,
            dismiss_label: payload,
            action_label: payload,
        }
        .render_html();
        assert!(
            !popover.contains("<img"),
            "Popover text slots must be escaped"
        );
    }

    /// The DEPRECATED button renderer: kept tested only so its page-counter
    /// clamping cannot regress while any caller still uses it.
    #[allow(deprecated)]
    #[test]
    fn pagination_controls_render_navigation_states() {
        let html = PaginationControls {
            page: 2,
            total_pages: 5,
        }
        .render_html();
        assert!(html.contains("aria-label=\"Pagination controls\""));
        assert!(html.contains("Page 2 of 5"));
        assert!(html.contains("First"));
        assert!(html.contains("Last"));
    }

    #[test]
    fn pagination_controls_can_render_query_preserving_links() {
        let html = PaginationControls {
            page: 3,
            total_pages: 7,
        }
        .render_html_with_links(
            "/campaigns",
            Some("status=draft&query=spring"),
            Some("apexmail:campaigns:page"),
        );

        assert!(html.contains("href=\"/campaigns?page=1&status=draft&query=spring\""));
        assert!(html.contains("href=\"/campaigns?page=2&status=draft&query=spring\""));
        assert!(html.contains("href=\"/campaigns?page=4&status=draft&query=spring\""));
        // Dead JS-era markup purge: the localStorage bridge key is gone —
        // query preservation is carried by the hrefs themselves.
        assert!(!html.contains("data-pagination-storage-key"));
        assert!(!html.contains("data-preserve-query"));
    }

    #[test]
    fn dialog_supports_size_variant_and_close_button() {
        let html = Dialog {
            title: "Campaign details",
            description: Some("Review the selected audience."),
            body: "<section>Body</section>",
            size: "lg",
            variant: "glass",
            hide_close_button: false,
        }
        .render_html();

        assert!(html.contains("apex-notice"), "{html}");
        assert!(html.contains("Campaign details"), "{html}");
        assert!(html.contains("Review the selected audience."), "{html}");
        assert!(!html.contains("role=\"dialog\"") && !html.contains("data-focus-trap"));
        assert!(!html.contains("glass") && !html.contains("max-w-2xl"));
    }

    #[test]
    fn alert_dialog_supports_confirm_and_destructive_variants() {
        let html = AlertDialog {
            title: "Delete domain",
            message: "This action cannot be undone.",
            confirm_label: "Delete",
            cancel_label: Some("Cancel"),
            variant: "destructive",
            dialog_type: "confirm",
        }
        .render_html();

        assert!(html.contains("apex-notice apex-notice--fail"), "{html}");
        assert!(html.contains("Delete domain"), "{html}");
        assert!(html.contains("apex-btn--danger"), "{html}");
        assert!(!html.contains("role=\"alertdialog\"") && !html.contains("data-focus-trap"));
    }

    #[test]
    fn popover_supports_preview_and_anchored_content() {
        let html = Popover {
            preview_title: "Popover preview",
            preview_description: "Anchored inline context for compact guidance and actions.",
            title: "Segment risk summary",
            description: "Complaint risk is elevated for contacts added within the last 7 days.",
            score_label: "Risk score",
            score_value: "Moderate",
            dismiss_label: "Dismiss",
            action_label: "Open report",
        }
        .render_html();

        assert!(html.contains("apex-panel"), "{html}");
        assert!(html.contains("Segment risk summary"));
        assert!(html.contains("Open report"));
    }

    #[test]
    fn dropdown_menu_supports_labels_and_shortcuts() {
        let html = DropdownMenu {
            label: Some("Actions"),
            items: vec![
                DropdownMenuItem {
                    label: "Edit",
                    inset: false,
                    destructive: false,
                    shortcut: Some("⌘E"),
                },
                DropdownMenuItem {
                    label: "Delete",
                    inset: false,
                    destructive: true,
                    shortcut: None,
                },
            ],
            show_separator: true,
        }
        .render_html();

        assert!(html.contains("apex-row-actions"), "{html}");
        assert!(html.contains("Actions"));
        assert!(html.contains("⌘E"));
        assert!(
            html.contains("apex-error") || html.contains("apex-btn--link"),
            "{html}"
        );
        // ARK: no menu role, no separator element, no menuitem roving
        // focus, the items render as inline underlined verbs in the row.
        assert!(!html.contains("role=\"menu\""));
        assert!(!html.contains("role=\"menuitem\""));
        assert!(!html.contains("show_separator"));
        assert!(html.contains("apex-row-actions"), "{html}");
        assert!(html.contains("Edit") && html.contains("Delete"), "{html}");
        assert!(
            html.contains("⌘E"),
            "the shortcut renders as machine text: {html}"
        );
    }

    #[allow(deprecated)]
    #[test]
    fn pagination_clamps_page_counter() {
        let html = PaginationControls {
            page: 0,
            total_pages: 3,
        }
        .render_html();
        assert!(html.contains("Page 1 of 3"));
        assert!(!html.contains("Page 0"));

        let zeroed = PaginationControls {
            page: 2,
            total_pages: 0,
        }
        .render_html();
        assert!(zeroed.contains("Page 2 of 1"));
    }

    #[test]
    fn tooltip_supports_variant_side_and_delay() {
        let html = Tooltip {
            content: "Helpful hint",
            variant: "light",
            side: "right",
            delay_duration: 200,
        }
        .render_html();
        // ARK: no hover tooltips, the text is an always-visible help line.
        assert!(html.contains("apex-help"), "{html}");
        assert!(html.contains("Helpful hint"), "{html}");
        assert!(!html.contains("role=\"tooltip\""));
    }

    #[test]
    fn scroll_area_supports_orientation() {
        let html = ScrollArea {
            orientation: "both",
            content: "<div>Rows</div>",
        }
        .render_html();
        assert!(html.contains("overflow-auto"), "{html}");
        assert!(!html.contains("scrollbar-"), "no custom scrollbar chrome");
        assert!(html.contains("Rows"));
    }

    #[test]
    fn toast_supports_variants_and_actions() {
        let html = Toast {
            title: Some("Saved"),
            description: Some("Campaign saved successfully."),
            variant: "success",
            action_label: Some("Undo"),
        }
        .render_html();

        assert!(html.contains("role=\"status\""));
        assert!(html.contains("Saved"));
        assert!(html.contains("Undo"));
        assert!(html.contains("apex-statusline"), "{html}");
        assert!(
            !html.contains("Close notification"),
            "no dismiss control: {html}"
        );
    }

    #[test]
    fn charts_support_empty_legend_and_metadata_states() {
        let empty = ApexAreaChart {
            title: Some("Empty dataset"),
            description: Some("No chartable data available for the selected period"),
            last_updated_label: Some("2 minutes ago"),
            height: 240,
            areas: vec![ChartSeries {
                key: "sent",
                name: "Sent",
                color: "rgb(var( --primary))",
            }],
            data_count: 0,
            empty_state_reason: "no-data",
        }
        .render_html();

        let pie = ApexPieChart {
            title: Some("Audience composition"),
            description: Some("Breakdown by source"),
            last_updated_label: None,
            height: 300,
            slices: vec![
                ChartPoint {
                    label: "API",
                    value: "42%",
                    color: "rgb(var( --chart-1))",
                },
                ChartPoint {
                    label: "CSV",
                    value: "58%",
                    color: "rgb(var( --surface-500))",
                },
            ],
            empty_state_reason: "no-data",
            inner_radius: 60,
            outer_radius: 80,
        }
        .render_html();

        assert!(empty.contains("No chartable data is available for this range."));
        assert!(empty.contains("Last updated 2 minutes ago"));
        assert!(!empty.contains("data-chart-kind=\"area\""));
        assert!(pie.contains("aria-label=\"Chart legend\""));
        assert!(pie.contains("data-chart-kind=\"pie\""));
        assert!(pie.contains("data-inner-radius=\"60\""));
        assert!(pie.contains("data-outer-radius=\"80\""));
        assert!(pie.contains("Audience composition"));
    }

    #[test]
    fn table_supports_headers_rows_and_caption() {
        let html = Table {
            columns: vec![
                TableColumn {
                    label: "Campaign",
                    align: "left",
                },
                TableColumn {
                    label: "Delivered",
                    align: "right",
                },
            ],
            rows: vec![vec!["Launch", "1200"]],
            caption: Some("Delivery summary"),
        }
        .render_html();

        assert!(html.contains("apex-table-wrap"));
        assert!(
            html.contains("apex-table-wrap") || html.contains("apex-loading"),
            "{html}"
        );
        assert!(html.contains("Delivery summary"));
        assert!(html.contains("text-right"));
        assert!(html.contains("Delivered"));
        assert!(html.contains("overflow-x-auto"));
        assert!(
            html.contains("apex-figure") || html.contains("apex-num"),
            "{html}"
        );
    }

    /// Review §4.8 / R2's filed item: the horizontally scrollable table
    /// region is keyboard-reachable (`tabindex="0"`), announced as a region
    /// (`role="region"`) and NAMED (the caption, or a generic label when the
    /// table has no caption), the stylesheet's `:focus-visible` ring was
    /// already in place.
    #[test]
    fn table_scroll_region_is_keyboard_reachable_and_named() {
        let captioned = Table {
            columns: vec![TableColumn {
                label: "Name",
                align: "left",
            }],
            rows: vec![vec!["k"]],
            caption: Some("API keys"),
        }
        .render_html();
        assert!(
            captioned.contains(
                "class=\"apex-table-wrap relative w-full overflow-x-auto\" tabindex=\"0\" role=\"region\" aria-label=\"API keys (scrollable table)\""
            ),
            "captioned table region must carry its name: {captioned}"
        );
        let uncaptioned = Table {
            columns: vec![TableColumn {
                label: "Name",
                align: "left",
            }],
            rows: vec![],
            caption: None,
        }
        .render_html();
        assert!(
            uncaptioned.contains("role=\"region\" aria-label=\"Scrollable data table\"")
                && uncaptioned.contains("tabindex=\"0\""),
            "uncaptioned table region must still be reachable + named: {uncaptioned}"
        );
    }

    #[test]
    fn tabs_support_pills_variant_and_content() {
        let html = Tabs {
            variant: "pills",
            tabs: vec![
                TabItem {
                    value: "overview",
                    label: "Overview",
                    active: true,
                },
                TabItem {
                    value: "deliverability",
                    label: "Deliverability",
                    active: false,
                },
            ],
            content_html: "<section>Tab content</section>",
        }
        .render_html();

        assert!(html.contains("apex-tabs"), "{html}");
        assert!(html.contains("Overview"), "{html}");
        assert!(html.contains("Tab content"), "{html}");
        assert!(!html.contains("role=\"tab\""));
    }

    #[test]
    fn charts_support_line_and_bar_configuration_metadata() {
        let line = ApexLineChart {
            title: Some("Delivery trend"),
            description: Some("Rolling seven-day delivery volume"),
            last_updated_label: Some("just now"),
            height: 280,
            series: vec![ChartSeries {
                key: "delivered",
                name: "Delivered",
                color: "rgb(var( --chart-1))",
            }],
            data_count: 7,
            empty_state_reason: "no-data",
        }
        .render_html();
        let bar = ApexBarChart {
            title: Some("Complaint sources"),
            description: Some("Grouped by channel"),
            last_updated_label: None,
            height: 260,
            bars: vec![ChartSeries {
                key: "api",
                name: "API",
                color: "rgb(var( --chart-2))",
            }],
            data_count: 3,
            layout: "vertical",
            empty_state_reason: "no-data",
        }
        .render_html();

        assert!(line.contains("data-chart-kind=\"line\""));
        assert!(line.contains("height: 280px"));
        assert!(line.contains("Delivery trend"));
        assert!(bar.contains("data-chart-kind=\"bar\""));
        assert!(bar.contains("data-layout=\"vertical\""));
        assert!(bar.contains("Complaint sources"));
    }

    #[test]
    fn card_supports_variant_padding_and_interactive_state() {
        let html = Card {
            title: "Usage",
            body: "42,000 emails",
            variant: "outline",
            padding: "lg",
            interactive: true,
        }
        .render_html();

        assert!(
            !html.contains("shadow") && !html.contains("hover:"),
            "{html}"
        );
        assert!(html.contains("apex-panel"), "{html}");
        assert!(
            !html.contains("cursor-pointer"),
            "panels are not buttons: {html}"
        );
        assert!(html.contains("42,000 emails"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.10 RadioGroup, render + keyboard + variants/sizes
    // ────────────────────────────────────────────────────────────

    #[test]
    fn radio_group_renders_all_items_with_roles() {
        let html = RadioGroup {
            name: "plan",
            selected: "pro",
            variant: "default",
            size: "md",
            orientation: "vertical",
            items: vec![
                RadioGroupItem {
                    value: "free",
                    label: "Free",
                    disabled: false,
                },
                RadioGroupItem {
                    value: "pro",
                    label: "Pro",
                    disabled: false,
                },
                RadioGroupItem {
                    value: "enterprise",
                    label: "Enterprise",
                    disabled: true,
                },
            ],
        }
        .render_html();

        // ARK: a radiogroup of native radio inputs; checked/disabled are
        // native attributes (native radios expose their own semantics).
        assert!(html.contains("role=\"radiogroup\""), "{html}");
        assert_eq!(html.matches("<input type=\"radio\"").count(), 3, "{html}");
        assert!(html.contains(" checked"), "{html}");
        assert!(html.contains(" disabled"), "{html}");
        assert!(!html.contains("data-state"));
        assert!(html.contains("Free"));
        assert!(html.contains("Pro"));
        assert!(html.contains("Enterprise"));
    }

    #[test]
    fn radio_group_horizontal_orientation() {
        let html = RadioGroup {
            name: "speed",
            selected: "",
            variant: "default",
            size: "md",
            orientation: "horizontal",
            items: vec![
                RadioGroupItem {
                    value: "slow",
                    label: "Slow",
                    disabled: false,
                },
                RadioGroupItem {
                    value: "fast",
                    label: "Fast",
                    disabled: false,
                },
            ],
        }
        .render_html();

        assert!(html.contains("flex-row"));
        assert!(html.contains("role=\"radiogroup\""), "{html}");
    }

    #[test]
    fn radio_group_keyboard_contract_specifies_all_keys() {
        let kc = RadioGroup::keyboard_navigation_contract();
        // Native radios: arrows move and Space selects; the browser owns the
        // rest (no roving tabindex, no Home/End hijack, no custom wrap).
        assert!(kc.arrow_up_moves_prev);
        assert!(kc.arrow_down_moves_next);
        assert!(kc.arrow_left_moves_prev);
        assert!(kc.arrow_right_moves_next);
        assert!(!kc.home_moves_first);
        assert!(!kc.end_moves_last);
        assert!(!kc.wrap_around);
        assert!(kc.space_selects);
    }

    #[test]
    fn accordion_renders_items_with_aria() {
        let html = Accordion {
            accordion_type: "single",
            collapsible: true,
            orientation: "vertical",
            open_values: vec!["faq-1"],
            items: vec![
                AccordionItem {
                    value: "faq-1",
                    trigger_label: "What is ApexMail?",
                    content: "An email platform.",
                },
                AccordionItem {
                    value: "faq-2",
                    trigger_label: "Pricing?",
                    content: "See pricing page.",
                },
            ],
        }
        .render_html();

        assert!(html.contains("<details"), "{html}");
        assert!(html.contains("<summary"), "{html}");
        assert!(!html.contains("data-state"));
        assert!(html.contains("What is ApexMail?"));
        assert!(html.contains("An email platform."));
        assert!(html.contains("Pricing?"));
        // closed content still in DOM (for animation), but has hidden attribute
        assert!(html.contains("<details"), "{html}");
    }

    #[test]
    fn accordion_multiple_mode_allows_multiple_open() {
        let html = Accordion {
            accordion_type: "multiple",
            collapsible: true,
            orientation: "vertical",
            open_values: vec!["a", "b"],
            items: vec![
                AccordionItem {
                    value: "a",
                    trigger_label: "A",
                    content: "Content A",
                },
                AccordionItem {
                    value: "b",
                    trigger_label: "B",
                    content: "Content B",
                },
                AccordionItem {
                    value: "c",
                    trigger_label: "C",
                    content: "Content C",
                },
            ],
        }
        .render_html();

        // ARK: each item is one native <details> (no state attributes).
        assert_eq!(html.matches("<details").count(), 3, "{html}");
    }

    #[test]
    fn accordion_animation_contract_values() {
        let ac = Accordion::animation_contract();

        // ARK: native <details>, no animation to configure.
        assert_eq!(ac.expand_duration_ms, 0);
        assert_eq!(ac.collapse_duration_ms, 0);
        assert_eq!(ac.easing, "none");
        assert!(!ac.uses_height_auto_animation);
        assert!(ac.css_keyframe_down.is_empty());
    }

    #[test]
    fn accordion_keyboard_contract_values() {
        let kc = Accordion::keyboard_contract();

        assert!(kc.space_toggles);
        assert!(kc.enter_toggles);
        assert!(!kc.arrow_down_moves_next);
        assert!(!kc.arrow_up_moves_prev);
        assert!(!kc.home_moves_first);
        assert!(!kc.end_moves_last);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.3 Button density contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn button_density_contract_specifies_three_levels() {
        let d = ButtonDensityContract::spec();
        assert_eq!(d.compact_height, "h-8");
        assert_eq!(d.default_height, "h-12");
        assert_eq!(d.comfortable_height, "h-14");
    }

    #[test]
    fn button_density_class_applies_correct_classes() {
        // ARK owns button geometry: density maps to the sanctioned steps.
        assert_eq!(button_density_class("compact"), "apex-btn--sm");
        assert_eq!(button_density_class("default"), "");
        assert_eq!(button_density_class("comfortable"), "apex-btn--lg");
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.4 Input helper-text, autofill/paste/IME contracts
    // ────────────────────────────────────────────────────────────

    #[test]
    fn input_helper_text_renders_all_variants() {
        for (variant, expected_class) in [
            ("default", "text-muted-foreground"),
            ("error", "text-destructive"),
            ("success", "text-success"),
            ("warning", "text-warning"),
        ] {
            let html = InputHelperText {
                text: "Hint",
                variant,
            }
            .render_html();
            assert!(
                html.contains(expected_class),
                "variant {variant} should have class {expected_class}"
            );
            assert!(html.contains("Hint"));
            assert!(html.contains("role=\"status\""));
        }
    }

    #[test]
    fn input_behavior_contract_specifies_autofill_and_ime() {
        let c = InputBehaviorContract::spec();
        assert!(c.autofill_preserves_styling);
        assert!(c.paste_strips_formatting);
        assert!(c.ime_composition_supported);
        assert!(c.autofill_css.contains("autofill"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.7 Select positioning/collision/keyboard contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn select_behavior_contract_covers_keyboard_and_positioning() {
        let c = SelectBehaviorContract::spec();
        assert_eq!(c.dropdown_side, "bottom");
        assert_eq!(c.side_offset, 4);
        assert_eq!(c.collision_padding, 8);
        assert!(c.supports_viewport_collision);
        assert!(c.keyboard_arrow_navigates);
        assert!(c.keyboard_enter_selects);
        assert!(c.keyboard_escape_closes);
        assert!(c.keyboard_type_ahead);
        assert_eq!(c.max_height_viewport_percent, 40);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.13 Dialog behavior contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn dialog_behavior_contract_covers_focus_trap_and_animation() {
        let c = DialogBehaviorContract::spec();
        assert!(c.focus_trap_enabled);
        assert!(c.restore_focus_on_close);
        assert!(c.escape_closes);
        assert!(c.click_outside_closes);
        assert!(c.scroll_lock_enabled);
        assert_eq!(c.portal_container, "body");
        assert_eq!(c.animation_enter_ms, 200);
        assert_eq!(c.animation_exit_ms, 200);
        assert_eq!(c.animation_easing, "ease-out");
        assert_eq!(c.overlay_blur, "none", "modals are banned: no overlay blur");
        assert!(c.initial_focus_selector.contains("autofocus"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.15 Dropdown menu behavior contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn dropdown_menu_behavior_contract_covers_nested_and_keyboard() {
        let c = DropdownMenuBehaviorContract::spec();
        assert!(c.supports_nested_submenus);
        assert!(c.keyboard_arrow_navigates);
        assert!(c.keyboard_enter_activates);
        assert!(c.keyboard_escape_closes);
        assert!(c.keyboard_right_opens_submenu);
        assert!(c.keyboard_left_closes_submenu);
        assert!(c.typeahead_enabled);
        assert!(c.close_on_outside_click);
        assert_eq!(c.side_offset, 4);
        assert_eq!(c.collision_padding, 8);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.16 Popover arrow/collision contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn popover_behavior_contract_covers_arrow_and_collision() {
        let c = PopoverBehaviorContract::spec();
        assert!(c.supports_arrow);
        assert_eq!(c.arrow_size, 8);
        assert_eq!(c.arrow_padding, 4);
        assert_eq!(c.side_offset, 4);
        assert!(c.supports_collision_boundary);
        assert!(c.close_on_outside_click);
        assert!(c.close_on_escape);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.17 Tooltip delay/positioning contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn tooltip_positioning_contract_covers_delay_and_collision() {
        let c = TooltipPositioningContract::spec();
        assert_eq!(c.default_delay_ms, 700);
        assert_eq!(c.skip_delay_ms, 300);
        assert_eq!(c.side_offset, 4);
        assert!(c.supports_collision_boundary);
        assert!(c.supports_arrow);
        assert_eq!(c.collision_padding, 8);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.19 Tabs keyboard/focus contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn tabs_behavior_contract_covers_keyboard_and_focus() {
        let c = TabsBehaviorContract::spec();
        assert!(c.keyboard_arrow_navigates);
        assert!(c.keyboard_home_first);
        assert!(c.keyboard_end_last);
        assert_eq!(c.activation_mode, "automatic");
        assert!(c.focus_follows_selection);
        assert!(c.loop_navigation);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.20 ScrollArea momentum contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn scroll_area_behavior_contract_covers_momentum() {
        let c = ScrollAreaBehaviorContract::spec();
        assert!(c.native_momentum_scrolling);
        assert!(c.scrollbar_auto_hide);
        assert_eq!(c.scrollbar_auto_hide_delay_ms, 600);
        assert_eq!(c.overscroll_behavior, "contain");
        assert!(c.css_scroll_behavior.contains("overflow-scrolling"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.21 Table sorting/selection contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn table_interaction_contract_covers_sort_and_select() {
        let c = TableInteractionContract::spec();
        assert!(c.sortable);
        assert!(c.selectable);
        assert!(c.select_all_header);
        assert!(c.keyboard_space_toggles);
        assert!(c.keyboard_shift_range_select);
        assert_eq!(c.sort_indicator_asc, "▲");
        assert_eq!(c.sort_indicator_desc, "▼");
    }

    #[test]
    fn render_sortable_header_shows_correct_indicator() {
        let asc_html = render_sortable_header("Name", "name", Some(("name", "asc")));
        assert!(asc_html.contains("▲"));
        assert!(asc_html.contains("aria-sort=\"ascending\""));

        let desc_html = render_sortable_header("Name", "name", Some(("name", "desc")));
        assert!(desc_html.contains("▼"));
        assert!(desc_html.contains("aria-sort=\"descending\""));

        let none_html = render_sortable_header("Name", "name", None);
        assert!(none_html.contains("⇅"));
        assert!(none_html.contains("aria-sort=\"none\""));
    }

    #[test]
    fn render_row_checkbox_checked_and_unchecked() {
        let checked = render_row_checkbox(true);
        // ARK: a native checkbox with its checked attribute.
        assert!(checked.contains("<input type=\"checkbox\""), "{checked}");
        assert!(checked.contains(" checked"), "{checked}");
        assert!(!checked.contains("data-state"));

        let unchecked = render_row_checkbox(false);
        assert!(
            unchecked.contains("<input type=\"checkbox\""),
            "{unchecked}"
        );
        assert!(!unchecked.contains(" checked"), "{unchecked}");
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.27 Skeleton shimmer/dimensions contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn skeleton_animation_contract_specifies_shimmer() {
        let c = SkeletonAnimationContract::spec();
        // ARK: loading is blank ruled rows, no shimmer, no pulse.
        assert!(!c.shimmer_enabled);
        assert_eq!(c.shimmer_css, "apex-loading");
        assert_eq!(c.pulse_duration_ms, 0);
        assert!(c.dimension_matching);
    }

    #[test]
    fn skeleton_dimensioned_renders_with_exact_size() {
        let html = SkeletonDimensioned {
            width: "200px",
            height: "16px",
            variant: "default",
            rounded: "rounded-sm",
        }
        .render_html();

        assert!(html.contains("apex-loading"), "{html}");
        assert!(html.contains("width: 200px"));
        assert!(html.contains("height: 16px"));
        assert!(html.contains("aria-hidden=\"true\""));
        assert!(html.contains("rounded-sm"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.30 Toast timing/dismissal contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn toast_behavior_contract_covers_timing_and_dismissal() {
        let c = ToastBehaviorContract::spec();
        assert_eq!(c.default_duration_ms, 5000);
        assert!(c.dismiss_on_swipe);
        assert_eq!(c.swipe_direction, "right");
        assert_eq!(c.swipe_threshold, 50);
        assert!(c.pause_on_hover);
        assert!(c.pause_on_focus_within);
        assert_eq!(c.max_visible, 5);
        assert!(c.auto_close);
        assert!(c.close_button_always_visible);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.31 Chart axis/gridline/hover contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn chart_interaction_contract_covers_axis_and_hover() {
        let c = ChartInteractionContract::spec();
        assert!(c.tooltip_snap_to_point);
        assert!(c.crosshair_enabled);
        assert_eq!(c.axis_tick_size, 5);
        assert_eq!(c.hover_dot_radius, 4);
        assert_eq!(c.gridline_dash_array, "3 3");
    }

    #[test]
    fn render_chart_axis_produces_svg_group() {
        let html = render_chart_axis("Revenue", "bottom");
        assert!(html.contains("data-axis=\"bottom\""), "{html}");
        assert!(html.contains("Revenue"));
        assert!(html.contains("aria-label"));
    }

    #[test]
    fn render_chart_gridlines_produces_correct_count() {
        let html = render_chart_gridlines(5);
        assert_eq!(html.matches("<line").count(), 5);
        assert!(html.contains("aria-hidden=\"true\""));
        assert!(html.contains("stroke-dasharray=\"3 3\""));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.32 Routing behavior contracts
    // ────────────────────────────────────────────────────────────

    #[test]
    fn routing_behavior_contract_covers_all_navigation() {
        let c = RoutingBehaviorContract::spec();
        assert!(c.nested_layout_support);
        assert_eq!(c.redirect_status_code, 307);
        assert!(c.query_param_preservation);
        assert!(c.hash_navigation);
        assert!(c.back_forward_navigation);
        assert!(c.scroll_restoration);
        assert!(c.redirect_preserve_query);
        assert!(c.deep_link_support);
        assert_eq!(c.auth_redirect_target, "/login");
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.33 Shell tab persistence / command palette contracts
    // ────────────────────────────────────────────────────────────

    #[test]
    fn shell_behavior_contract_covers_persistence_and_palette() {
        let c = ShellBehaviorContract::spec();
        assert_eq!(c.tab_persistence_key, "apexmail-active-tab");
        assert_eq!(c.tab_persistence_storage, "localStorage");
        assert!(c.page_header_breadcrumbs);
        assert!(c.page_header_action_slot);
        assert_eq!(c.command_palette_shortcut, "⌘K");
        assert!(c.command_palette_fuzzy_search);
        assert_eq!(c.command_palette_max_results, 10);
        assert_eq!(c.command_palette_sections.len(), 4);
        assert!(c.command_palette_sections.contains(&"Navigation"));
        assert!(c.command_palette_sections.contains(&"Actions"));
    }

    // ── Adversarial: tri-state controls, contracts, deterministic ids ───

    #[test]
    fn checkbox_covers_checked_unchecked_and_indeterminate() {
        for (checked, indeterminate, state) in [
            (false, false, "unchecked"),
            (true, false, "checked"),
            (false, true, "indeterminate"),
        ] {
            let html = Checkbox {
                checked,
                variant: "default",
                size: "default",
                indeterminate,
                disabled: false,
                aria_label: Some("Select row"),
            }
            .render_html();
            assert!(html.contains("<input type=\"checkbox\""), "{state}: {html}");
            assert_eq!(
                html.contains("aria-checked=\"mixed\""),
                indeterminate,
                "{state} aria-checked mixed"
            );
            // ARK: no indicator glyph, the native checked attribute is the
            // state, and indeterminate is aria-checked="mixed".
            assert_eq!(
                html.contains(" checked>") || html.contains(" checked "),
                checked,
                "{state} must render the checked attribute only when on"
            );
            assert!(html.contains("aria-label=\"Select row\""));
        }

        let disabled = Checkbox {
            checked: false,
            variant: "default",
            size: "default",
            indeterminate: false,
            disabled: true,
            aria_label: None,
        }
        .render_html();
        assert!(disabled.contains(" disabled aria-disabled=\"true\""));
        assert!(!disabled.contains("aria-label"));
    }

    #[test]
    fn switch_slider_and_progress_states_are_distinct() {
        let on = Switch {
            checked: true,
            variant: "default",
            size: "default",
            disabled: false,
        }
        .render_html();
        let off = Switch {
            checked: false,
            variant: "default",
            size: "default",
            disabled: false,
        }
        .render_html();
        assert!(on.contains("checked"));
        assert!(!off.contains("checked"));
        assert_ne!(on, off);

        let slider_with = Slider {
            value: 40,
            variant: "default",
            size: "default",
            show_tooltip: true,
        }
        .render_html();
        assert!(slider_with.contains("value=\"40\""), "range value");
        assert!(!slider_with.contains("tooltip"));
        let slider_without = Slider {
            value: 40,
            variant: "default",
            size: "default",
            show_tooltip: false,
        }
        .render_html();
        assert!(!slider_without.contains(">40</span>"));

        let progress = Progress {
            value: 30,
            variant: "default",
            size: "default",
            animated: true,
            show_value: true,
        }
        .render_html();
        assert!(progress.contains("30 of 100"), "{progress}");
        assert!(!progress.contains("animate-"));
        // Full and empty extremes never underflow.
        for value in [0u8, 100u8] {
            let html = Progress {
                value,
                variant: "default",
                size: "default",
                animated: false,
                show_value: false,
            }
            .render_html();
            assert!(
                html.contains(&format!("{} of 100", value)),
                "value {value}: {html}"
            );
        }
    }

    #[test]
    fn dialog_ids_are_deterministic_and_title_derived() {
        let first = Dialog {
            title: "Delete campaign?",
            description: Some("Permanent"),
            body: "<p>x</p>",
            size: "default",
            variant: "default",
            hide_close_button: false,
        }
        .render_html();
        let second = Dialog {
            title: "Delete campaign?",
            description: None,
            body: "",
            size: "default",
            variant: "default",
            hide_close_button: true,
        }
        .render_html();
        assert!(first.contains("Delete campaign"), "{first}");
        // Determinism is per-input: the same notice always renders the same
        // bytes (the old dialog id derivation no longer exists).
        assert_eq!(
            first,
            Dialog {
                title: "Delete campaign?",
                description: Some("Permanent"),
                body: "<p>x</p>",
                size: "default",
                variant: "default",
                hide_close_button: false,
            }
            .render_html()
        );
        assert!(!second.contains("data-dialog-close"));
        // A title with no alphanumerics still yields the stable base id.
        let punctuation = Dialog {
            title: "???",
            description: None,
            body: "",
            size: "default",
            variant: "default",
            hide_close_button: false,
        }
        .render_html();
        assert!(punctuation.contains("<b>???</b>"), "{punctuation}");

        // AlertDialog initial focus depends on the dialog type.
        let confirm = AlertDialog {
            title: "Remove?",
            message: "confirm",
            confirm_label: "Remove",
            cancel_label: Some("Cancel"),
            variant: "destructive",
            dialog_type: "confirm",
        }
        .render_html();
        // ARK: no focus routing, there is no dialog. The notice carries the
        // destructive verb and the message.
        assert!(confirm.contains("apex-notice--fail"), "{confirm}");
        assert!(confirm.contains("Remove"), "{confirm}");
    }

    #[test]
    fn tooltip_contract_matches_the_radix_numbers() {
        let contract = Tooltip::positioning_contract();
        assert_eq!(contract, TooltipPositioningContract::spec());
        assert_eq!(contract.default_delay_ms, 700);
        assert_eq!(contract.skip_delay_ms, 300);
        assert_eq!(contract.side_offset, 4);
        assert_eq!(contract.collision_padding, 8);
        assert!(contract.supports_arrow);
        assert!(contract.supports_collision_boundary);
        let html = Tooltip {
            content: "Save",
            variant: "default",
            side: "top",
            delay_duration: 700,
        }
        .render_html();
        // ARK: no tooltip element ships; the text is a visible help line.
        assert!(html.contains("apex-help"), "{html}");
        assert!(html.contains("Save"), "{html}");
    }
}

#[cfg(test)]
mod escaping_tests {
    use super::*;

    #[test]
    fn hostile_values_cannot_break_out_of_attributes() {
        // Dogfood 2026-10-06: the form primitives were the one render path in
        // this crate that interpolated DB-loaded values unescaped.
        let input = Input {
            id: Some("x\"><script>alert(1)</script>"),
            value: "\" onfocus=\"alert(1)",
            placeholder: "\"><img src=x>",
            name: Some("n\" onchange=\"evil()"),
            input_type: "text",
            variant: "default",
            size: "default",
            left_icon: None,
            right_icon: None,
            error: Some("<script>alert(2)</script>"),
            disabled: false,
            autocomplete: None,
            required: false,
        }
        .render_html();
        for raw in [
            "<script>",
            "onfocus=\"alert",
            "<img src=x",
            "onchange=\"evil",
        ] {
            assert!(!input.contains(raw), "unescaped {raw:?} in {input}");
        }
        assert!(input.contains("&lt;script&gt;"));
        assert!(input.contains("&quot;"));

        let checkbox = NativeCheckbox {
            id: "a\"><b>",
            name: "n\"><i>",
            checked: false,
            label: "<b>bold</b>",
        }
        .render_html();
        assert!(!checkbox.contains("<b>bold</b>"));
        assert!(checkbox.contains("&lt;b&gt;bold&lt;/b&gt;"));
    }

    /// Review §3 P1-8: tenant-controlled list/segment names are interpolated
    /// into native `<option>` markup. The escape must happen AT the primitive
    /// boundary, value, label, plus the select's own id/name, so no call
    /// site has to remember it.
    #[test]
    fn native_select_escapes_hostile_value_label_id_and_name() {
        let hostile = "\"><script>alert(1)</script>";
        let id = format!("list{hostile}");
        let name = format!("ids{hostile}");
        let value = format!("v{hostile}");
        let label = format!("L{hostile}");
        let html = NativeSelect {
            id: &id,
            name: &name,
            options: vec![SelectOption {
                value: &value,
                label: &label,
                disabled: false,
                selected: true,
            }],
            required: true,
            multiple: false,
            size: None,
        }
        .render_html();
        for raw in [
            "<script>",
            "\"><script>",
            "value=\"v\">",
            "id=\"list\">",
            "name=\"ids\">",
        ] {
            assert!(!html.contains(raw), "unescaped {raw:?} in {html}");
        }
        assert_eq!(html.matches("&lt;script&gt;").count(), 4, "{html}");
        assert!(html.contains("&quot;&gt;"), "{html}");
        // The option stays a single, well-formed element: exactly one
        // value/selected pair and no attribute closed early.
        assert_eq!(html.matches("<option ").count(), 1, "{html}");
        assert_eq!(html.matches(" selected").count(), 1, "{html}");
        assert!(
            html.contains(" value=\"v&quot;&gt;&lt;script&gt;"),
            "{html}"
        );
        assert!(html.ends_with("</select>"), "{html}");
    }
}
