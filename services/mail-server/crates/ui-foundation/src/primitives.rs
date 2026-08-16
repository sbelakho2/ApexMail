use crate::icons::{render_icon, IconRenderOptions};

fn primitive_icon(name: &str, class_name: &str) -> String {
    render_icon(
        name,
        IconRenderOptions {
            size: 18,
            stroke_width: 2.0,
            class_name: Some(class_name),
        },
    )
    .unwrap_or_default()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button<'a> {
    pub label: &'a str,
    pub variant: &'a str,
    pub size: &'a str,
    pub disabled: bool,
    pub loading: bool,
    pub left_icon: Option<&'a str>,
    pub right_icon: Option<&'a str>,
}

impl<'a> Button<'a> {
    pub fn render_html(&self) -> String {
        let disabled = if self.disabled || self.loading {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let loading = if self.loading {
            "<svg class=\"mr-2 h-4 w-4 animate-spin\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><circle class=\"opacity-25\" cx=\"12\" cy=\"12\" r=\"10\" stroke=\"currentColor\" stroke-width=\"3\"></circle><path class=\"opacity-75\" fill=\"currentColor\" d=\"M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z\"></path></svg>"
        } else {
            ""
        };
        let left_icon = if !self.loading {
            self.left_icon
                .map(|icon| format!("<span class=\"mr-2\">{icon}</span>"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let right_icon = if !self.loading {
            self.right_icon
                .map(|icon| format!("<span class=\"ml-2\">{icon}</span>"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        format!(
            "<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] ring-offset-background transition-colors duration-150 ease-out !shadow-none hover:!shadow-none active:!shadow-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 {} {}\" data-variant=\"{}\" data-size=\"{}\"{}>{}{}{}{}</button>",
            button_variant_class(self.variant),
            button_size_class(self.size),
            self.variant,
            self.size,
            disabled,
            loading,
            left_icon,
            self.label,
            right_icon,
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
}

impl<'a> Input<'a> {
    pub fn render_html(&self) -> String {
        let resolved_variant = self.error.map(|_| "error").unwrap_or(self.variant);
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let _error_id = "input-error";
        let aria_error = if self.error.is_some() {
            " aria-invalid=\"true\" aria-describedby=\"input-error\""
        } else {
            ""
        };
        let autocomplete_attr = self
            .autocomplete
            .map(|value| format!(" autocomplete=\"{}\"", value))
            .unwrap_or_default();
        let name_attr = self
            .name
            .map(|value| format!(" name=\"{}\"", value))
            .unwrap_or_default();
        let required_attr = if self.required {
            " required aria-required=\"true\""
        } else {
            ""
        };
        let input_markup = format!(
            "<input type=\"{}\"{} value=\"{}\" placeholder=\"{}\" class=\"flex w-full rounded-md border bg-background text-[14px] ring-offset-background transition-all duration-300 file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:border-primary disabled:cursor-not-allowed disabled:opacity-50 hover:border-border/80 {} {}{}{}{}\"{} data-variant=\"{}\" data-size=\"{}\" />",
            self.input_type,
            name_attr,
            self.value,
            self.placeholder,
            input_variant_class(resolved_variant),
            input_size_class(self.size),
            disabled,
            aria_error,
            autocomplete_attr,
            required_attr,
            resolved_variant,
            self.size,
        );

        let base = if self.left_icon.is_some() || self.right_icon.is_some() {
            let left = self.left_icon.map(|icon| format!("<div class=\"absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{icon}</div>")).unwrap_or_default();
            let right = self.right_icon.map(|icon| format!("<div class=\"absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground\">{icon}</div>")).unwrap_or_default();
            let adjusted =
                input_markup.replace("class=\"flex w-full", "class=\"flex w-full pl-10 pr-10");
            format!("<div class=\"relative\">{}{adjusted}{}</div>", left, right)
        } else {
            input_markup
        };

        if let Some(error) = self.error {
            return format!(
                "<div>{base}<p id=\"input-error\" class=\"text-xs text-destructive\" role=\"alert\">{error}</p></div>"
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
}

impl<'a> Textarea<'a> {
    pub fn render_html(&self) -> String {
        let char_count_id = "textarea-char-count";
        let describedby = if self.show_count {
            format!(" aria-describedby=\"{}\"", char_count_id)
        } else {
            String::new()
        };
        let name_attr = self
            .name
            .map(|value| format!(" name=\"{}\"", value))
            .unwrap_or_default();
        let textarea = format!(
            "<textarea{} class=\"flex min-h-[80px] w-full rounded-md border bg-background px-3 py-2 text-[14px] ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:border-primary disabled:cursor-not-allowed disabled:opacity-50 hover:border-border/80 transition-all duration-200 {} {}\" data-variant=\"{}\" data-resize=\"{}\" placeholder=\"{}\"{}>{}</textarea>",
            name_attr,
            input_variant_class(self.variant),
            textarea_resize_class(self.resize),
            self.variant,
            self.resize,
            self.placeholder,
            describedby,
            self.value,
        );

        if self.show_count {
            let count = self.value.chars().count();
            let suffix = self
                .max_length
                .map(|max| format!("{count}/{max}"))
                .unwrap_or_else(|| count.to_string());
            return format!("<div class=\"relative\">{textarea}<span id=\"{}\" class=\"absolute bottom-2 right-2 text-xs text-muted-foreground\">{suffix}</span></div>", char_count_id);
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
        let state = if self.indeterminate {
            "indeterminate"
        } else if self.checked {
            "checked"
        } else {
            "unchecked"
        };
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let aria_label = self
            .aria_label
            .map(|label| format!(" aria-label=\"{}\"", label))
            .unwrap_or_default();
        let indicator = if self.indeterminate {
            primitive_icon("minus", "h-3 w-3")
        } else if self.checked {
            primitive_icon("check", "h-3 w-3")
        } else {
            String::new()
        };
        format!(
            "<button type=\"button\" role=\"checkbox\" aria-checked=\"{}\" class=\"peer shrink-0 border ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-all duration-200 relative after:absolute after:left-1/2 after:top-1/2 after:h-[44px] after:w-[44px] after:-translate-x-1/2 after:-translate-y-1/2 after:content-[\"\"] {} {}\" data-state=\"{}\"{}{}>{}</button>",
            self.checked || self.indeterminate,
            checkbox_variant_class(self.variant),
            checkbox_size_class(self.size),
            state,
            disabled,
            aria_label,
            indicator,
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
}

impl<'a> Select<'a> {
    pub fn render_html(&self) -> String {
        let value = self.value_label.unwrap_or(self.placeholder);
        let selected_value = self
            .options
            .iter()
            .find(|option| option.selected)
            .map(|option| option.value)
            .unwrap_or("");
        let name_attrs = self
            .name
            .map(|name| {
                format!(
                    " name=\"{name}\" data-field=\"{name}\" data-value=\"{selected_value}\""
                )
            })
            .unwrap_or_default();
        let listbox_id = "select-listbox";
        let active_id = if self.open {
            self.options
                .iter()
                .position(|o| o.selected)
                .map(|i| format!("select-option-{}", i))
                .unwrap_or_else(|| "select-option-0".to_string())
        } else {
            String::new()
        };
        let expanded = if self.open { "true" } else { "false" };
        let activedescendant = if self.open {
            format!(" aria-activedescendant=\"{}\"", active_id)
        } else {
            String::new()
        };
        let menu = if self.open {
            let items = self
                .options
                .iter()
                .enumerate()
                .map(|(i, option)| {
                    let selected = if option.selected {
                        format!("<span class=\"absolute left-2 flex h-3.5 w-3.5 items-center justify-center\">{}</span>", primitive_icon("check", "h-3.5 w-3.5"))
                    } else {
                        String::new()
                    };
                    let disabled = if option.disabled { " data-disabled=\"true\"" } else { "" };
                    format!(
                        "<div id=\"select-option-{}\" class=\"relative flex w-full cursor-default select-none items-center rounded-md py-3 pl-8 pr-2 text-sm outline-none hover:bg-surface-50 focus:bg-surface-100 focus:text-surface-900 data-[disabled]:pointer-events-none data-[disabled]:opacity-50 min-h-[44px]\" role=\"option\" aria-selected=\"{}\"{}>{}<span>{}</span></div>",
                        i, option.selected,
                        disabled,
                        selected,
                        option.label,
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<div id=\"{}\" class=\"relative z-50 max-h-106 min-w-[8rem] overflow-hidden rounded-lg border bg-popover text-popover-foreground border-border/60 data-[state=open]:animate-in\" role=\"listbox\"><div class=\"p-1\">{}</div></div>",
                listbox_id, items,
            )
        } else {
            String::new()
        };

        let trigger_keyboard_attrs = if self.open {
            " data-keyboard-contract=\"select\" data-keyboard-arrow-navigates=\"true\" data-keyboard-enter-selects=\"true\" data-keyboard-escape-closes=\"true\""
        } else {
            ""
        };

        format!(
            "<div data-open=\"{}\"{}><button type=\"button\" role=\"combobox\" aria-expanded=\"{}\" aria-controls=\"{}\" aria-haspopup=\"listbox\"{}{} class=\"flex w-full items-center justify-between rounded-md border border-surface-200 bg-background px-3 py-2 text-[14px] ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1 transition-all duration-200 {} {}\" data-variant=\"{}\" data-size=\"{}\"><span>{}</span><span class=\"h-4 w-4 opacity-50\">⌄</span></button>{}</div>",
            self.open,
            name_attrs,
            expanded, listbox_id,
            activedescendant,
            trigger_keyboard_attrs,
            select_variant_class(self.variant),
            select_size_class(self.size),
            self.variant,
            self.size,
            value,
            menu,
        )
    }
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
        let disabled = if self.disabled {
            " disabled aria-disabled=\"true\""
        } else {
            ""
        };
        let state = if self.checked { "checked" } else { "unchecked" };
        format!(
            "<button type=\"button\" role=\"switch\" aria-checked=\"{}\" class=\"peer inline-flex shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 hover:opacity-90 active:scale-95 duration-200 relative after:absolute after:left-1/2 after:top-1/2 after:h-[44px] after:w-[44px] after:-translate-x-1/2 after:-translate-y-1/2 after:content-[\"\"] {} {}\" data-state=\"{}\"{}><span class=\"pointer-events-none block rounded-full bg-background ring-0 transition-transform {} {}\"></span></button>",
            self.checked,
            switch_variant_class(self.variant),
            switch_size_class(self.size),
            state,
            disabled,
            switch_thumb_size_class(self.size),
            switch_thumb_state_class(self.size, self.checked),
        )
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
        let tooltip = if self.show_tooltip {
            format!("<span class=\"absolute -top-8 left-1/2 -translate-x-1/2 rounded bg-primary px-3 py-1 text-xs text-white\">{}</span>", self.value)
        } else {
            String::new()
        };
        format!(
            "<div class=\"relative flex w-full touch-none select-none items-center\" data-size=\"{}\"><div class=\"relative w-full grow overflow-hidden rounded-sm bg-secondary {}\"><div class=\"absolute h-full {}\" style=\"width:{}%\"></div></div><span class=\"block rounded-sm border-2 border-primary bg-background ring-offset-background transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:scale-110 hover: relative {}\">{}</span></div>",
            self.size,
            slider_track_size_class(self.size),
            progress_indicator_class(self.variant),
            self.value,
            slider_thumb_size_class(self.size),
            tooltip,
        )
    }
}

/// RadioGroup:accessible radio-group with arrow-key navigation and focus management.
/// Matches the role="radiogroup" contract used in report filters.
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
        let items_html = self.items.iter().enumerate().map(|(i, item)| {
            let checked = item.value == self.selected;
            let disabled = if item.disabled { " disabled aria-disabled=\"true\"" } else { "" };
            let tabindex = if checked || (self.selected.is_empty() && i == 0) { "0" } else { "-1" };
            let indicator = if checked {
                "<span class=\"h-2.5 w-2.5 rounded-full bg-current\"></span>"
            } else {
                ""
            };
            let state = if checked { "checked" } else { "unchecked" };
            format!(
                "<div class=\"flex items-center space-x-2\"><button type=\"button\" role=\"radio\" aria-checked=\"{}\" tabindex=\"{}\" data-value=\"{}\" data-state=\"{}\" class=\"aspect-square rounded-full border ring-offset-background focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 {} {}\"{}>{}</button><label class=\"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70\">{}</label></div>",
                checked, tabindex, item.value, state,
                radio_variant_class(self.variant),
                radio_size_class(self.size),
                disabled, indicator, item.label,
            )
        }).collect::<Vec<_>>().join("");

        let orientation_class = match self.orientation {
            "horizontal" => "flex-row gap-4",
            _ => "flex-col gap-2",
        };

        let radio_keyboard_attrs = " data-keyboard-contract=\"radiogroup\" data-keyboard-arrow-next=\"true\" data-keyboard-arrow-prev=\"true\" data-keyboard-home-first=\"true\" data-keyboard-end-last=\"true\" data-keyboard-wrap-around=\"true\"";

        format!(
            "<div role=\"radiogroup\" aria-label=\"{}\" data-orientation=\"{}\" class=\"flex {}\"{}>{}</div>",
            self.name, self.orientation, orientation_class, radio_keyboard_attrs, items_html,
        )
    }

    /// Keyboard navigation contract:ArrowDown/ArrowRight moves to next,
    /// ArrowUp/ArrowLeft moves to previous, Home/End jump to first/last,
    /// wrapping enabled by default.
    pub fn keyboard_navigation_contract() -> RadioGroupKeyboardContract {
        RadioGroupKeyboardContract {
            arrow_down_moves_next: true,
            arrow_up_moves_prev: true,
            arrow_right_moves_next: true,
            arrow_left_moves_prev: true,
            home_moves_first: true,
            end_moves_last: true,
            wrap_around: true,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label<'a> {
    pub text: &'a str,
    pub required: bool,
    pub optional: bool,
    pub variant: &'a str,
    pub size: &'a str,
}

impl<'a> Label<'a> {
    pub fn render_html(&self) -> String {
        let suffix = if self.required {
            "<span class=\"ml-1 text-destructive\">*</span>"
        } else {
            ""
        };
        let optional = if self.optional {
            "<span class=\"ml-1 text-muted-foreground\">(optional)</span>"
        } else {
            ""
        };
        format!(
            "<label class=\"text-sm font-medium leading-none {} {}\">{}{}{}</label>",
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
        let animated = if self.animated {
            " animate-progress"
        } else {
            ""
        };
        let value = if self.show_value {
            format!(
                "<span class=\"text-sm text-muted-foreground apex-metric-number\">{}%</span>",
                self.value
            )
        } else {
            String::new()
        };
        format!(
            "<div class=\"flex items-center gap-2\"><div class=\"relative w-full overflow-hidden rounded-sm {} {}\"><div class=\"h-full w-full flex-1 transition-all duration-300 ease-in-out {}{}\" style=\"transform: translateX(-{}%);\"></div></div>{}</div>",
            progress_track_class(self.variant),
            progress_size_class(self.size),
            progress_indicator_class(self.variant),
            animated,
            100_u8.saturating_sub(self.value),
            value,
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
        format!(
            "<div class=\"inline-flex items-center rounded-full border font-semibold uppercase tracking-wide transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 max-w-full min-w-0 truncate {} {}\" data-variant=\"{}\" data-size=\"{}\">{}{}</div>",
            badge_variant_class(self.variant),
            badge_size_class(self.size),
            self.variant,
            self.size,
            icon,
            self.text,
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
        let image = self.image_url.map(|src| format!("<img src=\"{}\" alt=\"{}\" class=\"aspect-square h-full w-full object-cover\" />", src, self.label)).unwrap_or_default();
        let fallback = if self.image_url.is_none() {
            format!("<span class=\"flex h-full w-full items-center justify-center bg-surface-100 text-surface-600 font-semibold text-xs uppercase tracking-wide\">{}</span>", self.fallback)
        } else {
            String::new()
        };
        format!(
            "<div class=\"relative flex shrink-0 overflow-hidden rounded-full border border-surface-200 {} {}\" aria-label=\"{}\">{}{}</div>",
            avatar_size_class(self.size),
            avatar_status_class(self.status),
            self.label,
            image,
            fallback,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyState<'a> {
    pub icon_markup: Option<&'a str>,
    pub title: &'a str,
    pub description: Option<&'a str>,
    pub action_label: Option<&'a str>,
}

impl<'a> EmptyState<'a> {
    pub fn render_html(&self) -> String {
        let icon = self.icon_markup.map(|icon| format!("<div class=\"mb-4 flex h-16 w-16 items-center justify-center rounded-lg bg-muted/50 border border-border/50\">{}</div>", icon)).unwrap_or_default();
        let description = self.description.map(|text| format!("<p class=\"mx-auto max-w-[320px] text-sm text-muted-foreground leading-relaxed\">{}</p>", text)).unwrap_or_default();
        let action = self.action_label.map(|label| format!("<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] border border-surface-200 bg-background text-foreground hover:border-surface-300 h-10 px-3 text-sm min-h-[44px] mt-6\">{}</button>", label)).unwrap_or_default();
        format!(
            "<div class=\"apex-empty-state flex flex-col items-center justify-center py-12 px-6 text-center animate-in fade-in zoom-in-95 duration-500\">{}<h3 class=\"text-[17px] font-bold text-foreground mb-2\">{}</h3>{}{}</div>",
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
                format!("<div class=\"flex items-center justify-center min-h-[320px]\"><div class=\"flex flex-col items-center gap-3\"><svg class=\"animate-spin h-8 w-8 text-muted-foreground\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\"><circle class=\"opacity-25\" cx=\"12\" cy=\"12\" r=\"10\" stroke=\"currentColor\" stroke-width=\"3\"></circle><path class=\"opacity-75\" fill=\"currentColor\" d=\"M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z\"></path></svg><p class=\"text-sm text-muted-foreground font-medium\">{}</p>{}</div></div>", label, badge)
            }
            Self::Error {
                title,
                description,
                retry_label,
            } => EmptyState {
                icon_markup: Some("<span class=\"h-8 w-8 text-muted-foreground/60\">!</span>"),
                title,
                description: Some(description),
                action_label: *retry_label,
            }
            .render_html(),
            Self::Empty {
                title,
                description,
                action_label,
            } => EmptyState {
                icon_markup: Some("<span class=\"h-8 w-8 text-muted-foreground/60\">⌂</span>"),
                title,
                description: Some(description),
                action_label: *action_label,
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
        format!(
            "<div class=\"animate-pulse rounded-sm {} {}\"></div>",
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
        let description = self
            .description
            .map(|value| format!("<p class=\"text-sm text-muted-foreground\">{}</p>", value))
            .unwrap_or_default();
        let close = if self.hide_close_button {
            String::new()
        } else {
            format!("<button data-dialog-close data-focus-initial=\"true\" class=\"absolute right-4 top-4 rounded-md opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2\" aria-label=\"Close\">{}<span class=\"sr-only\">Close</span></button>", primitive_icon("x", "h-4 w-4"))
        };
        format!(
            "<div class=\"fixed inset-0 z-50 bg-black/40 backdrop-blur-sm data-[state=open]:animate-in\"></div><div role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"dialog-title-id\" tabindex=\"-1\" data-focus-trap=\"true\" data-escape-dismiss=\"true\" data-initial-focus=\"[data-focus-initial]\" class=\"fixed left-[50%] top-[50%] z-50 grid w-full translate-x-[-50%] translate-y-[-50%] gap-4 border bg-background p-6 duration-200 sm:rounded-lg {} {}\"><div class=\"flex flex-col space-y-1.5 text-center sm:text-left\"><h2 id=\"dialog-title-id\" class=\"text-lg font-bold leading-none tracking-tight\">{}</h2>{}</div><div>{}</div>{}</div>",
            dialog_size_class(self.size),
            dialog_variant_class(self.variant),
            self.title,
            description,
            self.body,
            close,
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
        let initial_focus = if self.dialog_type == "confirm" {
            "[data-alert-dialog-cancel]"
        } else {
            "[data-alert-dialog-confirm]"
        };
        let cancel = if self.dialog_type == "confirm" {
            format!(
                "<button data-alert-dialog-cancel class=\"px-4 py-2 rounded-md text-sm font-medium bg-muted text-foreground hover:bg-muted/80 transition-colors\">{}</button>",
                self.cancel_label.unwrap_or("Cancel")
            )
        } else {
            String::new()
        };
        format!(
            "<div class=\"fixed inset-0 z-[200] flex items-center justify-center bg-black/50 backdrop-blur-sm\"><div class=\"bg-card border border-border rounded-lg p-6 max-w-md w-full mx-4 animate-in fade-in zoom-in-95 duration-200\" role=\"alertdialog\" aria-modal=\"true\" aria-labelledby=\"dialog-title\" aria-describedby=\"dialog-message\" tabindex=\"-1\" data-focus-trap=\"true\" data-escape-dismiss=\"true\" data-initial-focus=\"{}\"><h2 id=\"dialog-title\" class=\"text-lg font-bold text-foreground mb-2\">{}</h2><p id=\"dialog-message\" class=\"text-sm text-muted-foreground mb-6\">{}</p><div class=\"flex justify-end gap-3\">{}<button data-alert-dialog-confirm class=\"px-4 py-2 rounded-md text-sm font-medium transition-colors {}\">{}</button></div></div></div>",
            initial_focus,
            self.title,
            self.message,
            cancel,
            alert_dialog_confirm_class(self.variant),
            self.confirm_label,
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
        format!(
            "<div class=\"relative min-h-[180px] rounded-lg border border-border bg-muted/10 p-4\"><div class=\"flex items-start justify-between gap-4\"><div><p class=\"text-sm font-semibold text-foreground\">{}</p><p class=\"text-xs text-muted-foreground\">{}</p></div><button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] ring-offset-background transition-colors duration-150 ease-out !shadow-none hover:!shadow-none active:!shadow-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 border border-surface-200 bg-background text-foreground hover:border-surface-300 h-12 px-4 py-2\">Review segment health</button></div><div class=\"absolute right-4 top-16 z-10 w-[280px] rounded-lg border border-border bg-popover p-4 text-popover-foreground\"><p class=\"text-sm font-semibold\">{}</p><p class=\"mt-1 text-xs text-muted-foreground\">{}</p><div class=\"mt-3 flex items-center justify-between rounded-md border border-border bg-background px-3 py-2 text-xs\"><span>{}</span>{}</div><div class=\"mt-3 flex justify-end gap-2\"><button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] ring-offset-background transition-colors duration-150 ease-out !shadow-none hover:!shadow-none active:!shadow-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 text-foreground hover:bg-surface-50 h-10 px-3 text-sm min-h-[44px]\">{}</button><button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] ring-offset-background transition-colors duration-150 ease-out !shadow-none hover:!shadow-none active:!shadow-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-white hover:bg-primary/90 h-10 px-3 text-sm min-h-[44px]\">{}</button></div></div></div>",
            self.preview_title,
            self.preview_description,
            self.title,
            self.description,
            self.score_label,
            Badge { text: self.score_value, variant: "outline", size: "default", icon: None }.render_html(),
            self.dismiss_label,
            self.action_label,
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
        let label = self.label.map(|value| format!("<div class=\"px-3 py-1.5 text-[11px] font-semibold uppercase tracking-widest text-surface-600\">{}</div>", value)).unwrap_or_default();
        let separator = if self.show_separator {
            "<div class=\"-mx-1 my-1 h-px bg-surface-200/50\"></div>"
        } else {
            ""
        };
        let items = self.items.iter().enumerate().map(|(i, item)| {
            let destructive = if item.destructive { " text-destructive focus:bg-destructive/10 focus:text-destructive" } else { "" };
            let inset = if item.inset { " pl-8" } else { "" };
            let shortcut = item.shortcut.map(|value| format!("<span class=\"ml-auto text-xs opacity-60\">{}</span>", value)).unwrap_or_default();
            let tabindex = if i == 0 { "0" } else { "-1" };
            format!("<div role=\"menuitem\" tabindex=\"{}\" class=\"relative flex cursor-default select-none items-center rounded-md px-3 py-3 text-[14px] font-medium outline-none transition-colors hover:bg-surface-50 focus:bg-surface-100 focus:text-surface-900 cursor-pointer min-h-[44px]{}{}\">{}{}</div>", tabindex, inset, destructive, item.label, shortcut)
        }).collect::<Vec<_>>().join("");
        let keyboard_attrs = " data-keyboard-contract=\"dropdown-menu\" data-keyboard-arrow-navigates=\"true\" data-keyboard-enter-activates=\"true\" data-keyboard-escape-closes=\"true\"";
        // The separator belongs INSIDE the menu container (between the label
        // and the items) — rendering it after the closing </div> left it
        // stranded outside the menu, where keyboard/role semantics ignore it.
        format!("<div class=\"z-50 min-w-[8rem] overflow-hidden rounded-lg border border-surface-200/60 bg-card/90 backdrop-blur-xl p-1.5 text-surface-900 data-[state=open]:animate-in\" role=\"menu\"{}>{}{}{}</div>", keyboard_attrs, label, separator, items)
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
        format!("<div role=\"tooltip\" data-side=\"{}\" data-delay=\"{}\" class=\"z-50 overflow-hidden rounded-md border px-3 py-1.5 text-xs animate-in fade-in-0 zoom-in-95 {} {}\">{}</div>", self.side, self.delay_duration, tooltip_variant_class(self.variant), tooltip_side_class(self.side), self.content)
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
        let items_html = self.items.iter().enumerate().map(|(i, item)| {
            let is_open = self.open_values.contains(&item.value);
            let state = if is_open { "open" } else { "closed" };
            let content_class = if is_open {
                "overflow-hidden transition-all duration-200 ease-out"
            } else {
                "overflow-hidden h-0 transition-all duration-200 ease-out"
            };
            let icon_rotation = if is_open { " rotate-180" } else { "" };

            format!(
                "<div class=\"border-b border-surface-100 last:border-0\" data-state=\"{}\" data-value=\"{}\"><h3 class=\"flex\"><button type=\"button\" aria-expanded=\"{}\" aria-controls=\"accordion-panel-{}\" id=\"accordion-trigger-{}\" class=\"flex flex-1 items-center justify-between py-4 font-medium transition-all hover:underline [&[data-state=open]>svg]:rotate-180\" data-state=\"{}\"><span>{}</span><svg class=\"h-4 w-4 shrink-0 transition-transform duration-200{}\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"m6 9 6 6 6-6\"/></svg></button></h3><div id=\"accordion-panel-{}\" role=\"region\" aria-labelledby=\"accordion-trigger-{}\" class=\"{}\" data-state=\"{}\"><div class=\"pb-4 pt-0\">{}</div></div></div>",
                state, item.value, is_open, i, i, state, item.trigger_label,
                icon_rotation, i, i, content_class, state, item.content,
            )
        }).collect::<Vec<_>>().join("");

        format!(
            "<div data-accordion-type=\"{}\" data-collapsible=\"{}\" data-orientation=\"{}\" class=\"w-full\">{}</div>",
            self.accordion_type, self.collapsible, self.orientation, items_html,
        )
    }

    /// Animation contract:matches the tailwind `accordion-down`/`accordion-up` keyframes.
    pub fn animation_contract() -> AccordionAnimationContract {
        AccordionAnimationContract {
            expand_duration_ms: 200,
            collapse_duration_ms: 200,
            easing: "ease-out",
            uses_height_auto_animation: true,
            css_keyframe_down: "accordion-down 0.2s ease-out",
            css_keyframe_up: "accordion-up 0.2s ease-out",
        }
    }

    /// Keyboard navigation contract.
    pub fn keyboard_contract() -> AccordionKeyboardContract {
        AccordionKeyboardContract {
            space_toggles: true,
            enter_toggles: true,
            arrow_down_moves_next: true,
            arrow_up_moves_prev: true,
            home_moves_first: true,
            end_moves_last: true,
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
        format!("<div class=\"relative {} scrollbar-thin scrollbar-track-transparent scrollbar-thumb-border hover:scrollbar-thumb-muted-foreground/50\">{}</div>", scroll_area_orientation_class(self.orientation), self.content)
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
            &self.series.iter().map(|series| ChartLegendItem { key: series.key, name: series.name, color: series.color }).collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            "<div data-chart-kind=\"line\" class=\"rounded-sm border border-border/50 bg-background/40\"></div>",
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
            &self.bars.iter().map(|series| ChartLegendItem { key: series.key, name: series.name, color: series.color }).collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            &format!("<div data-chart-kind=\"bar\" data-layout=\"{}\" class=\"rounded-sm border border-border/50 bg-background/40\"></div>", self.layout),
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
            &self.areas.iter().map(|series| ChartLegendItem { key: series.key, name: series.name, color: series.color }).collect::<Vec<_>>(),
            self.data_count,
            self.empty_state_reason,
            "<div data-chart-kind=\"area\" class=\"rounded-sm border border-border/50 bg-background/40\"></div>",
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
                .map(|slice| {
                    format!(
                        "<div class=\"text-xs text-muted-foreground\">{} ({})</div>",
                        slice.label, slice.value
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!("{}<div data-chart-kind=\"pie\" data-inner-radius=\"{}\" data-outer-radius=\"{}\" class=\"rounded-sm border border-border/50 bg-background/40\">{}</div>", chart_legend_markup(&legend), self.inner_radius, self.outer_radius, labels)
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
        let headers = self.columns.iter().map(|column| {
            format!("<th scope=\"col\" class=\"h-12 px-4 align-middle font-semibold text-muted-foreground text-[11px] uppercase tracking-wide bg-muted/20 whitespace-nowrap {}\">{}</th>", table_align_class(column.align), column.label)
        }).collect::<Vec<_>>().join("");
        let rows = if self.rows.is_empty() {
            let colspan = self.columns.len().max(1);
            format!("<tr class=\"border-b\"><td colspan=\"{}\" class=\"p-6 text-center text-sm text-muted-foreground\">No rows to display</td></tr>", colspan)
        } else {
            self.rows.iter().map(|row| {
                let cells = row.iter().enumerate().map(|(index, value)| {
                    let align = self.columns.get(index).map(|column| table_align_class(column.align)).unwrap_or("text-left");
                    format!("<td class=\"p-4 align-middle apex-metric-number whitespace-nowrap {}\">{}</td>", align, value)
                }).collect::<Vec<_>>().join("");
                format!("<tr class=\"border-b transition-colors hover:bg-muted/50 min-h-[44px]\">{}</tr>", cells)
            }).collect::<Vec<_>>().join("")
        };
        let caption = self
            .caption
            .map(|value| {
                format!(
                    "<caption class=\"mt-4 text-sm text-muted-foreground\">{}</caption>",
                    value
                )
            })
            .unwrap_or_default();
        format!("<div class=\"apex-table-wrap relative w-full overflow-x-auto\"><table class=\"apex-table w-full min-w-[640px] caption-bottom text-sm\"><thead class=\"[&_tr]:border-b sticky top-0 z-10 bg-background\"><tr>{}</tr></thead><tbody class=\"[&_tr:last-child]:border-0\">{}</tbody>{}</table></div>", headers, rows, caption)
    }
}

impl<'a> Toast<'a> {
    pub fn render_html(&self) -> String {
        let title = self
            .title
            .map(|value| format!("<div class=\"text-sm font-semibold\">{}</div>", value))
            .unwrap_or_default();
        let description = self
            .description
            .map(|value| format!("<div class=\"text-sm opacity-90\">{}</div>", value))
            .unwrap_or_default();
        let action = self.action_label.map(|value| format!("<button class=\"inline-flex h-8 shrink-0 items-center justify-center rounded-md border bg-transparent px-3 text-sm font-medium ring-offset-background transition-colors hover:bg-secondary\">{}</button>", value)).unwrap_or_default();
        format!("<div class=\"group pointer-events-auto relative flex w-full items-center justify-between space-x-4 overflow-hidden rounded-lg border p-4 pr-8 transition-all {}\" role=\"status\"><div class=\"flex items-start gap-3\">{}<div class=\"grid gap-1\">{}{}</div></div>{}<button class=\"absolute right-2 top-2 rounded-md p-1 text-foreground/50\" aria-label=\"Close notification\">{}</button></div>", toast_variant_class(self.variant), toast_icon_markup(self.variant), title, description, action, primitive_icon("x", "h-4 w-4"))
    }
}

impl PaginationControls {
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
            format!("<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] border border-surface-200 bg-background text-foreground hover:border-surface-300 h-10 px-3 text-sm min-h-[44px]\"{}>{}</button>", disabled_attr, label)
        };
        format!(
            "<div class=\"flex items-center gap-2\" role=\"navigation\" aria-label=\"Pagination controls\">{}{}<span class=\"px-2 text-sm text-muted-foreground\">Page {} of {}</span>{}{}</div>",
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
        let persistence_attr = persistence_key
            .map(|value| {
                format!(
                    " data-pagination-storage-key=\"{}\" data-preserve-query=\"true\"",
                    value
                )
            })
            .unwrap_or_default();
        let link = |label: &str, target_page: usize, disabled: bool| {
            if disabled {
                return format!(
                    "<button class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] border border-surface-200 bg-background text-foreground hover:border-surface-300 h-10 px-3 text-sm min-h-[44px]\" disabled aria-disabled=\"true\">{}</button>",
                    label,
                );
            }

            format!(
                "<a href=\"{}?page={}{}\" class=\"inline-flex items-center justify-center whitespace-nowrap rounded-md text-[14px] font-sans font-semibold tracking-[0.01em] border border-surface-200 bg-background text-foreground hover:border-surface-300 h-10 px-3 text-sm min-h-[44px]\">{}</a>",
                base_path,
                target_page,
                preserved,
                label,
            )
        };
        format!(
            "<div class=\"flex flex-wrap items-center gap-2\" role=\"navigation\" aria-label=\"Pagination controls\" data-current-page=\"{}\" data-total-pages=\"{}\"{}>{}{}<span class=\"px-2 text-sm text-muted-foreground\">Page {} of {}</span>{}{}</div>",
            current_page,
            safe_total_pages,
            persistence_attr,
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
        let triggers = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let state = if tab.active { "active" } else { "inactive" };
                let aria_selected = if tab.active { "true" } else { "false" };
                let tabindex = if tab.active { "0" } else { "-1" };
                let tabpanel_id = format!("tabpanel-{}", i);
                format!(
                    "<button type=\"button\" role=\"tab\" aria-selected=\"{}\" aria-controls=\"{}\" tabindex=\"{}\" data-state=\"{}\" class=\"inline-flex items-center justify-center whitespace-nowrap px-3 py-3 text-[14px] font-medium ring-offset-background transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 min-h-[44px] {}\">{}</button>",
                    aria_selected, tabpanel_id, tabindex, state,
                    tabs_trigger_variant_class(self.variant),
                    tab.label,
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<div><div role=\"tablist\" class=\"inline-flex items-center justify-center transition-all duration-300 {}\">{}</div><div role=\"tabpanel\" id=\"tabpanel-0\" aria-labelledby=\"tab-0\" class=\"mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2\">{}</div></div>",
            tabs_list_variant_class(self.variant),
            triggers,
            self.content_html,
        )
    }
}

impl<'a> Card<'a> {
    pub fn render_html(&self) -> String {
        let interactive = if self.interactive {
            " cursor-pointer hover:border-surface-950 hover:bg-surface-50 active:scale-[0.99]"
        } else {
            ""
        };
        format!(
            "<div class=\"apex-card rounded-lg border border-surface-200 bg-card text-surface-950 transition-premium {} {}{}\"><div class=\"flex flex-col space-y-2 min-w-0 mb-4\"><h3 class=\"text-sm font-bold tracking-tight leading-tight break-words text-surface-400\">{}</h3></div><div class=\"min-w-0\">{}</div></div>",
            card_variant_class(self.variant),
            card_padding_class(self.padding),
            interactive,
            self.title,
            self.body,
        )
    }
}

fn button_variant_class(variant: &str) -> &'static str {
    match variant {
        "destructive" => "bg-primary text-white hover:bg-brand-700",
        "outline" => "border border-surface-200 bg-background text-foreground hover:border-surface-300",
        "secondary" => "border border-surface-200 bg-background text-foreground hover:border-surface-300",
        "ghost" => "text-foreground hover:bg-surface-50",
        "link" => "text-primary font-semibold underline decoration-brand-200 underline-offset-4 hover:decoration-primary",
        _ => "bg-primary text-white border border-brand-700 hover:bg-brand-700",
    }
}

fn button_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "px-5 py-2.5 text-[11px] tracking-tight",
        "lg" => "px-8 py-4 text-[15px] tracking-tight",
        "xl" => "px-10 py-5 text-[17px] tracking-tight",
        "icon" => "h-10 w-10",
        _ => "px-6 py-3 text-[13px] tracking-tight",
    }
}

fn input_variant_class(variant: &str) -> &'static str {
    match variant {
        "error" => "border-primary focus-visible:ring-primary/20 focus-visible:border-primary",
        "success" => "border-success focus-visible:ring-success/20 focus-visible:border-success",
        "ghost" => "border-transparent bg-transparent hover:bg-surface-50",
        _ => "border-surface-200",
    }
}

fn input_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-10 px-3 text-[13px] rounded-md",
        "lg" => "h-14 px-6 text-[16px] rounded-md",
        _ => "h-12 px-4 text-[14px] rounded-md",
    }
}

fn textarea_resize_class(resize: &str) -> &'static str {
    match resize {
        "none" => "resize-none",
        "horizontal" => "resize-x",
        "both" => "resize",
        _ => "resize-y",
    }
}

fn checkbox_variant_class(variant: &str) -> &'static str {
    match variant {
        "success" => "border-success data-[state=checked]:bg-success data-[state=checked]:text-white",
        "destructive" => "border-destructive data-[state=checked]:bg-destructive data-[state=checked]:text-destructive-foreground",
        _ => "border-input data-[state=checked]:bg-primary data-[state=checked]:text-white data-[state=checked]:border-primary",
    }
}

fn checkbox_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-3 w-3 rounded-sm",
        "lg" => "h-6 w-6 rounded-sm",
        _ => "h-4 w-4 rounded-sm",
    }
}

fn select_variant_class(variant: &str) -> &'static str {
    match variant {
        "error" => "border-primary focus:ring-primary/20 focus:border-primary",
        "success" => "border-success focus:ring-success/20 focus:border-success",
        "ghost" => "border-transparent bg-transparent hover:bg-surface-50",
        _ => "border-surface-200 hover:border-surface-950",
    }
}

fn select_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-10 px-3 text-[12px] tracking-tight rounded-md",
        "lg" => "h-14 px-6 text-[15px] tracking-tight rounded-md",
        _ => "h-12 px-4 text-[14px] tracking-tight rounded-md",
    }
}

fn switch_variant_class(variant: &str) -> &'static str {
    match variant {
        "success" => "data-[state=checked]:bg-success data-[state=unchecked]:bg-muted shadow-inner",
        "destructive" => {
            "data-[state=checked]:bg-destructive data-[state=unchecked]:bg-muted shadow-inner"
        }
        _ => "data-[state=checked]:bg-primary data-[state=unchecked]:bg-muted shadow-inner",
    }
}

fn switch_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-4 w-7",
        "lg" => "h-7 w-14",
        _ => "h-6 w-11",
    }
}

fn switch_thumb_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-3 w-3",
        "lg" => "h-6 w-6",
        _ => "h-5 w-5",
    }
}

fn switch_thumb_state_class(size: &str, checked: bool) -> &'static str {
    match (size, checked) {
        ("sm", true) => "translate-x-3",
        ("lg", true) => "translate-x-7",
        ("default", true) => "translate-x-5",
        _ => "translate-x-0",
    }
}

fn slider_track_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-1",
        "lg" => "h-3",
        _ => "h-2",
    }
}

fn slider_thumb_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-3 w-3",
        "lg" => "h-6 w-6",
        _ => "h-5 w-5",
    }
}

fn label_variant_class(variant: &str) -> &'static str {
    match variant {
        "muted" => "text-muted-foreground",
        "error" => "text-destructive",
        "success" => "text-success",
        _ => "text-foreground",
    }
}

fn label_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "text-xs",
        "lg" => "text-base",
        _ => "text-sm",
    }
}

fn progress_track_class(variant: &str) -> &'static str {
    match variant {
        "success" => "bg-success/20",
        "warning" => "bg-warning/20",
        "error" => "bg-destructive/20",
        _ => "bg-surface-100",
    }
}

fn progress_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-1",
        "lg" => "h-3",
        "xl" => "h-4",
        _ => "h-2",
    }
}

fn progress_indicator_class(variant: &str) -> &'static str {
    match variant {
        "success" => "bg-success",
        "warning" => "bg-warning",
        "error" => "bg-destructive",
        _ => "bg-primary",
    }
}

fn badge_variant_class(variant: &str) -> &'static str {
    match variant {
        "secondary" => {
            "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80"
        }
        "destructive" => {
            "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90"
        }
        "outline" => "text-foreground hover:bg-accent hover:text-accent-foreground",
        "success" => "border border-success/30 bg-success/15 text-foreground hover:bg-success/20 ",
        "warning" => "border border-warning/35 bg-warning/20 text-foreground hover:bg-warning/25 ",
        "error" => {
            "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/90 "
        }
        "info" => "border-transparent bg-info text-info-foreground hover:bg-info/90 ",
        "ghost" => "border-transparent bg-muted text-muted-foreground hover:bg-muted/80",
        "outline-success" => "text-foreground border-success/35 bg-success/15",
        "outline-warning" => "text-foreground border-warning/35 bg-warning/20",
        "outline-error" => "text-destructive border-destructive/30 bg-destructive/5",
        _ => "border-transparent bg-primary text-white hover:bg-primary/90 ",
    }
}

fn badge_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "px-2 py-0.5 text-[10px]",
        "lg" => "px-3 py-1 text-xs",
        _ => "px-2.5 py-0.5 text-[11px]",
    }
}

fn card_variant_class(variant: &str) -> &'static str {
    match variant {
        "ghost" => "border-transparent shadow-none",
        "outline" => "border-border bg-transparent",
        "elevated" => "shadow-premium-hover hover:border-primary/30",
        "inset" => "border-border bg-muted/30 shadow-inner",
        _ => "shadow-premium hover:border-primary/30 hover:bg-muted/40 hover:shadow-premium-hover",
    }
}

fn card_padding_class(padding: &str) -> &'static str {
    match padding {
        "none" => "",
        "xs" => "p-2",
        "sm" => "p-4",
        "lg" => "p-8",
        "xl" => "p-10",
        _ => "p-6 md:p-8",
    }
}

fn avatar_size_class(size: &str) -> &'static str {
    match size {
        "xs" => "h-6 w-6 rounded-full",
        "sm" => "h-8 w-8 rounded-full",
        "lg" => "h-12 w-12 rounded-full",
        "xl" => "h-16 w-16 rounded-full",
        "2xl" => "h-20 w-20 rounded-full",
        _ => "h-10 w-10 rounded-full",
    }
}

fn avatar_status_class(status: &str) -> &'static str {
    match status {
        "online" => "ring-2 ring-success ring-offset-2 ring-offset-background",
        "offline" => "ring-2 ring-muted ring-offset-2 ring-offset-background",
        "busy" => "ring-2 ring-error ring-offset-2 ring-offset-background",
        "away" => "ring-2 ring-warning ring-offset-2 ring-offset-background",
        _ => "",
    }
}

fn skeleton_variant_class(variant: &str) -> &'static str {
    match variant {
        "card" => "bg-surface-200/50 rounded-sm",
        "text" => "bg-surface-100 h-4 w-full rounded-sm",
        "circle" => "bg-surface-100 rounded-full",
        _ => "bg-surface-100",
    }
}

fn status_indicator_config(status: &str) -> (&str, &str, &str) {
    match status.to_ascii_lowercase().as_str() {
        "draft" => (
            "Draft",
            "secondary",
            "<span class=\"mr-1 h-2 w-2 rounded-full border border-current\" aria-hidden=\"true\"></span>",
        ),
        "scheduled" => ("Scheduled", "info", "<span class=\"mr-1 h-2 w-2 rounded-full bg-info-500\" aria-hidden=\"true\"></span>"),
        "sending" => (
            "Sending",
            "warning",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-warning-500\" aria-hidden=\"true\"></span>",
        ),
        "sent" => ("Sent", "success", "<span class=\"mr-1 h-2 w-2 rounded-full bg-success-500\" aria-hidden=\"true\"></span>"),
        "paused" => ("Paused", "outline", "<span class=\"mr-1 h-2 w-2 rounded-full border border-current\" aria-hidden=\"true\"></span>"),
        "subscribed" => (
            "Subscribed",
            "success",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-success-500\" aria-hidden=\"true\"></span>",
        ),
        "unsubscribed" => (
            "Unsubscribed",
            "secondary",
            "<span class=\"mr-1 h-2 w-2 rounded-full border border-current\" aria-hidden=\"true\"></span>",
        ),
        "bounced" => (
            "Bounced",
            "warning",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-warning-500\" aria-hidden=\"true\"></span>",
        ),
        "complained" => (
            "Complained",
            "error",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-destructive\" aria-hidden=\"true\"></span>",
        ),
        "delivered" => (
            "Delivered",
            "success",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-success-500\" aria-hidden=\"true\"></span>",
        ),
        "queued" => (
            "Queued",
            "secondary",
            "<span class=\"mr-1 h-2 w-2 rounded-full bg-muted-foreground\" aria-hidden=\"true\"></span>",
        ),
        "failed" => ("Failed", "error", "<span class=\"mr-1 h-2 w-2 rounded-full bg-destructive\" aria-hidden=\"true\"></span>"),
        _ => (status, "secondary", "<span class=\"mr-1 h-2 w-2 rounded-full border border-current\" aria-hidden=\"true\"></span>"),
    }
}

fn dialog_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "max-w-sm",
        "lg" => "max-w-2xl",
        "xl" => "max-w-4xl",
        "full" => "max-w-[calc(100%-2rem)] h-[calc(100%-2rem)]",
        _ => "max-w-lg",
    }
}

fn dialog_variant_class(variant: &str) -> &'static str {
    match variant {
        "glass" => "glass border-white/10 backdrop-blur-xl bg-background/80",
        "premium" => "premium-card border-border",
        _ => "border-border",
    }
}

fn alert_dialog_confirm_class(variant: &str) -> &'static str {
    match variant {
        "destructive" => "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        _ => "bg-primary text-white hover:bg-primary/90",
    }
}

fn tooltip_variant_class(variant: &str) -> &'static str {
    match variant {
        // The "light" variant renders an explicitly white popover (bg-white)
        // rather than the theme-dependent card token, so a light tooltip stays
        // legible regardless of dark/light mode.
        "light" => "bg-white text-surface-900 border-surface-200",
        "glass" => "backdrop-blur-md bg-white/10 border-white/20 text-white ",
        _ => "bg-surface-900 text-white border-surface-800 ",
    }
}

fn tooltip_side_class(side: &str) -> &'static str {
    match side {
        "bottom" => "data-[side=bottom]:slide-in-from-top-2",
        "left" => "data-[side=left]:slide-in-from-right-2",
        "right" => "data-[side=right]:slide-in-from-left-2",
        _ => "data-[side=top]:slide-in-from-bottom-2",
    }
}

fn scroll_area_orientation_class(orientation: &str) -> &'static str {
    match orientation {
        "horizontal" => "overflow-x-auto overflow-y-hidden",
        "both" => "overflow-auto",
        _ => "overflow-y-auto overflow-x-hidden",
    }
}

fn toast_variant_class(variant: &str) -> &'static str {
    match variant {
        "success" => "border-success/30 bg-success/10 backdrop-blur-xl text-success-700",
        "destructive" => "destructive group border-destructive/30 bg-destructive/10 backdrop-blur-xl text-destructive",
        "warning" => "border-warning/30 bg-warning/10 backdrop-blur-xl text-warning-700",
        "info" => "border-primary/30 bg-primary/10 backdrop-blur-xl text-primary-700",
        _ => "border-surface-200 bg-card/90 backdrop-blur-xl text-surface-900",
    }
}

fn toast_icon_markup(variant: &str) -> String {
    match variant {
        "success" => primitive_icon("check-circle", "h-5 w-5 text-success"),
        "destructive" => primitive_icon("alert-circle", "h-5 w-5 text-destructive-foreground"),
        "warning" => primitive_icon("alert-triangle", "h-5 w-5 text-warning"),
        "info" => primitive_icon("info", "h-5 w-5 text-primary"),
        _ => String::new(),
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

fn chart_empty_state_markup(reason: &str) -> String {
    // No outer border/background here — the surrounding chart frame already provides the
    // single visible boundary. Adding another border created a triple-stacked look when
    // the chart frame itself was nested inside a card.
    format!("<div class=\"apex-chart-empty flex min-h-[220px] flex-col items-center justify-center gap-3 p-6 text-center text-sm text-muted-foreground\"><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" class=\"h-7 w-7 opacity-40\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M3 3v18h18M7 15l3-3 3 3 5-5\"/></svg><p class=\"max-w-xs leading-5\">{}</p></div>", chart_empty_description(reason))
}

fn chart_meta_markup(last_updated_label: Option<&str>) -> String {
    last_updated_label
        .map(|value| {
            format!(
                "<p class=\"mt-1 text-xs text-muted-foreground\">Last updated {}</p>",
                value
            )
        })
        .unwrap_or_default()
}

fn chart_legend_markup(items: &[ChartLegendItem<'_>]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let entries = items
        .iter()
        .map(|item| format!("<div class=\"inline-flex items-center gap-2 text-xs text-muted-foreground\"><span class=\"h-2.5 w-2.5 rounded-sm\" style=\"background-color: {}\" aria-hidden=\"true\"></span><span>{}</span></div>", item.color, item.name))
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
            title.map(|value| format!("<h3 class=\"font-display font-bold leading-tight tracking-tight break-words\">{}</h3>", value)).unwrap_or_default(),
            description.map(|value| format!("<p class=\"font-display text-sm text-muted-foreground break-words\">{}</p>", value)).unwrap_or_default(),
            chart_meta_markup(last_updated_label),
        )
    } else {
        String::new()
    };

    // The chart frame is almost always wrapped in a panel/card by the page layout.
    // Use a transparent border and no inner padding so we don't double-frame nor
    // double-pad the chart inside that card.
    format!("<div class=\"apex-chart-frame rounded-sm border border-transparent bg-transparent text-card-foreground\">{}<div style=\"height: {}px\">{}</div></div>", header, height, content)
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

fn table_align_class(align: &str) -> &'static str {
    match align {
        "center" => "text-center",
        "right" => "text-right",
        _ => "text-left",
    }
}

fn tabs_list_variant_class(variant: &str) -> &'static str {
    match variant {
        "underline" => {
            "border-b border-border bg-transparent w-full justify-start gap-8 px-0 rounded-none"
        }
        "pills" => "gap-1 bg-transparent",
        _ => "rounded-lg bg-muted/50 p-1 text-muted-foreground border border-border/50",
    }
}

fn tabs_trigger_variant_class(variant: &str) -> &'static str {
    match variant {
        "underline" => "relative border-b-2 border-transparent pb-3 pt-2 px-1 text-surface-500 rounded-none data-[state=active]:border-primary data-[state=active]:text-primary hover:text-surface-950",
        "pills" => "rounded-md px-4 bg-transparent text-surface-500 hover:bg-surface-50 data-[state=active]:bg-brand-50 data-[state=active]:text-primary",
        _ => "rounded-md text-surface-500 hover:text-surface-950 data-[state=active]:bg-background data-[state=active]:text-foreground",
    }
}

fn radio_variant_class(variant: &str) -> &'static str {
    match variant {
        "success" => "border-success text-success data-[state=checked]:border-success",
        "destructive" => {
            "border-destructive text-destructive data-[state=checked]:border-destructive"
        }
        _ => "border-primary text-primary data-[state=checked]:border-primary",
    }
}

fn radio_size_class(size: &str) -> &'static str {
    match size {
        "sm" => "h-3.5 w-3.5",
        "lg" => "h-5 w-5",
        _ => "h-4 w-4",
    }
}

// ────────────────────────────────────────────────────────────
// Interactive behavior contracts for unchecked Phase 4 items
// ────────────────────────────────────────────────────────────

/// Button density contract (4.3):density variants control vertical padding.
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
    match density {
        "compact" => "h-8 px-3 py-1 text-xs",
        "comfortable" => "h-14 px-6 py-4 text-base",
        _ => "h-12 px-4 py-2",
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
            overlay_blur: "backdrop-blur-sm",
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
        "<th scope=\"col\" class=\"h-12 px-4 align-middle font-semibold text-muted-foreground text-[11px] uppercase tracking-wide bg-muted/20 whitespace-nowrap cursor-pointer select-none hover:bg-muted/40 transition-colors\" aria-sort=\"{}\" data-sort-key=\"{}\"><div class=\"flex items-center gap-1\">{}<span class=\"text-muted-foreground/60\">{}</span></div></th>",
        aria_sort, sort_key, label, indicator,
    )
}

/// Renderable selectable table row checkbox.
pub fn render_row_checkbox(selected: bool) -> String {
    let indicator = if selected {
        primitive_icon("check", "h-3 w-3")
    } else {
        String::new()
    };
    format!(
        "<td class=\"w-12 p-4 align-middle\"><button type=\"button\" role=\"checkbox\" aria-checked=\"{}\" aria-label=\"Select row\" class=\"peer shrink-0 border border-input ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 h-4 w-4 rounded-sm data-[state=checked]:bg-primary data-[state=checked]:text-white data-[state=checked]:border-primary\" data-state=\"{}\">{}</button></td>",
        selected,
        if selected { "checked" } else { "unchecked" },
        indicator,
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
            shimmer_enabled: true,
            shimmer_css: "animate-pulse",
            pulse_duration_ms: 2000,
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
            "<div class=\"animate-pulse {} {}\" style=\"width: {}; height: {};\" aria-hidden=\"true\"></div>",
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
        "<g class=\"chart-axis chart-axis-{}\" aria-label=\"{}\"><line class=\"axis-line\" stroke=\"rgb(var( --border))\" /><text class=\"axis-label text-xs fill-muted-foreground\">{}</text></g>",
        side, label, label,
    )
}

/// Renderable chart gridlines.
pub fn render_chart_gridlines(count: usize) -> String {
    let lines = (0..count).map(|_| {
        "<line class=\"gridline\" stroke=\"rgb(var( --border))\" stroke-opacity=\"0.3\" stroke-dasharray=\"3 3\" />"
    }).collect::<Vec<_>>().join("");
    format!(
        "<g class=\"chart-gridlines\" aria-hidden=\"true\">{}</g>",
        lines
    )
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
        };
        let input = Input {
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
        assert!(progress.render_html().contains("42%"));
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
        }
        .render_html();

        assert!(html.contains("bg-primary"));
        assert!(html.contains("text-white"));
        assert!(html.contains("px-8 py-4 text-[15px] tracking-tight"));
        assert!(!html.contains("uppercase"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
        assert!(html.contains("<span class=\"mr-2\"><svg></svg></span>"));
        assert!(html.contains("<span class=\"ml-2\"><svg></svg></span>"));
        assert!(html
            .contains("focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"));
        assert!(html.contains("hover:!shadow-none"));
        assert!(html.contains("active:!shadow-none"));
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
        }
        .render_html();

        assert!(loading.contains("animate-spin"));
        assert!(!loading.contains("<span class=\"mr-2\"><svg></svg></span>"));
        assert!(icon_only.contains("data-size=\"icon\""));
        assert!(icon_only.contains("h-10 w-10"));
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
        }
        .render_html();

        assert!(html.contains("bg-background"));
        assert!(html.contains("text-foreground"));
        assert!(!html.contains("bg-white text-surface-950"));
    }

    #[test]
    fn input_supports_icons_and_error_state() {
        let html = Input {
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

        assert!(html.contains("relative"));
        assert!(html.contains("pl-10 pr-10"));
        assert!(html.contains("border-primary"));
        assert!(html.contains("Required"));
        assert!(html.contains("placeholder=\"email\""));
        assert!(html.contains("focus-visible:ring-2"));
    }

    #[test]
    fn input_supports_disabled_size_and_default_states() {
        let html = Input {
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

        assert!(html.contains("h-10 px-3 text-[13px] rounded-md"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
        assert!(html.contains("border-surface-200"));
    }

    #[test]
    fn textarea_supports_resize_and_counter() {
        let html = Textarea {
            value: "abc",
            placeholder: "Write",
            variant: "default",
            resize: "none",
            max_length: Some(10),
            show_count: true,
        name: None,
    }
        .render_html();

        assert!(html.contains("resize-none"));
        assert!(html.contains("3/10"));
        assert!(html.contains("absolute bottom-2 right-2"));
    }

    /// Form fields must carry a `name` attribute — without one, `FormData`
    /// serialization skips the element entirely and `data-api-form` handlers
    /// receive an empty `{}` payload.
    #[test]
    fn named_fields_render_name_attributes() {
        let input = Input {
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
        }
        .render_html();
        // The custom combobox is not a native <select>; the name is exposed
        // via data-field/data-value for the api-form serialization fallback.
        assert!(select.contains("name=\"audience\""));
        assert!(select.contains("data-field=\"audience\""));
        assert!(select.contains("data-value=\"vip\""));

        // Unnamed fields must not render a stale/empty name attribute.
        let unnamed = Input {
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

        assert!(html.contains("data-state=\"indeterminate\""));
        assert!(html.contains("h-6 w-6 rounded-sm"));
        assert!(html.contains("border-success"));
        assert!(html.contains("disabled aria-disabled=\"true\""));
    }

    #[test]
    fn label_supports_required_optional_and_variants() {
        let html = Label {
            text: "Email",
            required: true,
            optional: false,
            variant: "error",
            size: "lg",
        }
        .render_html();

        assert!(html.contains("text-destructive"));
        assert!(html.contains("text-base"));
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

        assert!(html.contains("bg-warning/20"));
        assert!(html.contains("h-4"));
        assert!(html.contains("bg-warning animate-progress"));
        assert!(html.contains("67%"));
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

        assert!(html.contains("bg-success/15"));
        // Badges are small uppercase status pills (rounded-full, semibold).
        assert!(html.contains("rounded-full"));
        assert!(html.contains("font-semibold"));
        assert!(html.contains("px-2 py-0.5 text-[10px]"));
        assert!(html.contains("<span class=\"mr-1\"><svg></svg></span>"));

        let warning = Badge {
            text: "Warning",
            variant: "outline-warning",
            size: "default",
            icon: None,
        }
        .render_html();
        assert!(warning.contains("border-warning/35 bg-warning/20"));
    }

    #[test]
    fn select_supports_trigger_and_open_menu() {
        let html = Select {
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
    }
        .render_html();

        assert!(html.contains("data-open=\"true\""));
        assert!(html.contains("border-success"));
        assert!(html.contains("h-14 px-6 text-[15px] tracking-tight rounded-md"));
        assert!(html.contains("Enterprise"));
        assert!(html.contains("role=\"option\""));
    }

    #[test]
    fn switch_supports_variants_sizes_and_checked_state() {
        let html = Switch {
            checked: true,
            variant: "success",
            size: "lg",
            disabled: false,
        }
        .render_html();

        assert!(html.contains("role=\"switch\""));
        assert!(html.contains("data-[state=checked]:bg-success"));
        assert!(html.contains("h-7 w-14"));
        assert!(html.contains("translate-x-7"));
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

        assert!(html.contains("data-size=\"lg\""));
        assert!(html.contains("bg-warning"));
        assert!(html.contains("h-3"));
        assert!(html.contains(">75<"));
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

        assert!(html.contains("role=\"tablist\""));
        assert!(html.contains("data-[state=active]:border-primary"));
        assert!(html.contains("data-state=\"active\""));
        assert!(html.contains("<section>Panel</section>"));
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

        assert!(html.contains("h-16 w-16 rounded-full"));
        assert!(html.contains("ring-success"));
        assert!(html.contains(">AL<"));
    }

    #[test]
    fn empty_state_supports_description_and_action() {
        let html = EmptyState {
            icon_markup: Some("<span class=\"h-8 w-8\">☆</span>"),
            title: "No campaigns yet",
            description: Some("Create your first campaign to get started."),
            action_label: Some("Create campaign"),
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
        assert!(html.contains("animate-pulse"));
        assert!(html.contains("rounded-sm"));
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
        assert!(html.contains("data-pagination-storage-key=\"apexmail:campaigns:page\""));
        assert!(html.contains("data-preserve-query=\"true\""));
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

        assert!(html.contains("role=\"dialog\""));
        assert!(html.contains("data-focus-trap=\"true\""));
        assert!(html.contains("data-dialog-close"));
        assert!(html.contains("max-w-2xl"));
        assert!(html.contains("glass border-white/10"));
        assert!(html.contains("Close"));
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

        assert!(html.contains("role=\"alertdialog\""));
        assert!(html.contains("data-focus-trap=\"true\""));
        assert!(html.contains("data-alert-dialog-cancel"));
        assert!(html.contains("data-alert-dialog-confirm"));
        assert!(html.contains("Delete domain"));
        assert!(html.contains("Cancel"));
        assert!(html.contains("bg-destructive text-destructive-foreground"));
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

        assert!(
            html.contains("rounded-lg border border-border bg-popover p-4 text-popover-foreground")
        );
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

        assert!(html.contains("role=\"menu\""));
        assert!(html.contains("Actions"));
        assert!(html.contains("⌘E"));
        assert!(html.contains("text-destructive"));
        // The separator must live INSIDE the menu container, before the
        // items — not stranded after the closing </div>.
        let menu_pos = html.find("role=\"menu\"").expect("menu role");
        let separator_pos = html
            .find("bg-surface-200/50")
            .expect("separator rendered");
        let item_pos = html.find("role=\"menuitem\"").expect("menu items");
        assert!(
            menu_pos < separator_pos && separator_pos < item_pos,
            "separator must sit inside the menu container, before the items"
        );
    }

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
        assert!(html.contains("role=\"tooltip\""));
        assert!(html.contains("data-delay=\"200\""));
        assert!(html.contains("bg-white text-surface-900"));
    }

    #[test]
    fn scroll_area_supports_orientation() {
        let html = ScrollArea {
            orientation: "both",
            content: "<div>Rows</div>",
        }
        .render_html();
        assert!(html.contains("overflow-auto"));
        assert!(html.contains("scrollbar-thin"));
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
        assert!(html.contains("border-success/30"));
        assert!(html.contains("Close notification"));
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

        assert!(html.contains("min-w-[640px]"));
        assert!(html.contains("sticky top-0 z-10 bg-background"));
        assert!(html.contains("Delivery summary"));
        assert!(html.contains("text-right"));
        assert!(html.contains("Delivered"));
        assert!(html.contains("overflow-x-auto"));
        assert!(html.contains("apex-metric-number"));
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

        assert!(html.contains("role=\"tablist\""));
        assert!(html.contains("role=\"tab\""));
        assert!(html.contains("data-state=\"active\""));
        assert!(html.contains("Overview"));
        assert!(html.contains("Tab content"));
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

        assert!(html.contains("border-border bg-transparent"));
        assert!(html.contains("p-8"));
        assert!(html.contains("cursor-pointer"));
        assert!(html.contains("42,000 emails"));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.10 RadioGroup — render + keyboard + variants/sizes
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

        assert!(html.contains("role=\"radiogroup\""));
        assert!(html.contains("role=\"radio\""));
        assert!(html.contains("aria-checked=\"true\""));
        assert!(html.contains("aria-checked=\"false\""));
        assert!(html.contains("aria-disabled=\"true\""));
        assert!(html.contains("data-state=\"checked\""));
        assert!(html.contains("data-state=\"unchecked\""));
        assert!(html.contains("Free"));
        assert!(html.contains("Pro"));
        assert!(html.contains("Enterprise"));
    }

    #[test]
    fn radio_group_variant_classes_map_correctly() {
        assert!(radio_variant_class("default").contains("border-primary"));
        assert!(radio_variant_class("success").contains("border-success"));
        assert!(radio_variant_class("destructive").contains("border-destructive"));
    }

    #[test]
    fn radio_group_size_classes_map_correctly() {
        assert!(radio_size_class("sm").contains("h-3.5"));
        assert!(radio_size_class("md").contains("h-4"));
        assert!(radio_size_class("lg").contains("h-5"));
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
        assert!(html.contains("data-orientation=\"horizontal\""));
    }

    #[test]
    fn radio_group_keyboard_contract_specifies_all_keys() {
        let kc = RadioGroup::keyboard_navigation_contract();
        assert!(kc.arrow_up_moves_prev);
        assert!(kc.arrow_down_moves_next);
        assert!(kc.arrow_left_moves_prev);
        assert!(kc.arrow_right_moves_next);
        assert!(kc.home_moves_first);
        assert!(kc.end_moves_last);
        assert!(kc.wrap_around);
        assert!(kc.space_selects);
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.18 Accordion — render + animation + keyboard
    // ────────────────────────────────────────────────────────────

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

        assert!(html.contains("data-state=\"open\""));
        assert!(html.contains("data-state=\"closed\""));
        assert!(html.contains("aria-expanded=\"true\""));
        assert!(html.contains("aria-expanded=\"false\""));
        assert!(html.contains("What is ApexMail?"));
        assert!(html.contains("An email platform."));
        assert!(html.contains("Pricing?"));
        // closed content still in DOM (for animation), but has hidden attribute
        assert!(html.contains("hidden"));
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

        // Two open items × 3 data-state attrs each (wrapper, trigger, panel) = 6
        // One closed item × 3 = 3
        assert_eq!(html.matches("data-state=\"open\"").count(), 6);
        assert_eq!(html.matches("data-state=\"closed\"").count(), 3);
    }

    #[test]
    fn accordion_animation_contract_values() {
        let ac = Accordion::animation_contract();

        assert_eq!(ac.expand_duration_ms, 200);
        assert_eq!(ac.collapse_duration_ms, 200);
        assert_eq!(ac.easing, "ease-out");
        assert!(ac.css_keyframe_down.contains("accordion-down"));
        assert!(ac.css_keyframe_up.contains("accordion-up"));
    }

    #[test]
    fn accordion_keyboard_contract_values() {
        let kc = Accordion::keyboard_contract();

        assert!(kc.space_toggles);
        assert!(kc.enter_toggles);
        assert!(kc.arrow_down_moves_next);
        assert!(kc.arrow_up_moves_prev);
        assert!(kc.home_moves_first);
        assert!(kc.end_moves_last);
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
        assert!(button_density_class("compact").contains("h-8"));
        assert!(button_density_class("default").contains("h-12"));
        assert!(button_density_class("comfortable").contains("h-14"));
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
        assert!(c.overlay_blur.contains("blur"));
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
        assert!(checked.contains("aria-checked=\"true\""));
        assert!(checked.contains("data-state=\"checked\""));
        assert!(checked.contains("<svg"));

        let unchecked = render_row_checkbox(false);
        assert!(unchecked.contains("aria-checked=\"false\""));
        assert!(unchecked.contains("data-state=\"unchecked\""));
    }

    // ────────────────────────────────────────────────────────────
    // Phase 4.27 Skeleton shimmer/dimensions contract
    // ────────────────────────────────────────────────────────────

    #[test]
    fn skeleton_animation_contract_specifies_shimmer() {
        let c = SkeletonAnimationContract::spec();
        assert!(c.shimmer_enabled);
        assert_eq!(c.shimmer_css, "animate-pulse");
        assert_eq!(c.pulse_duration_ms, 2000);
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

        assert!(html.contains("animate-pulse"));
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
        assert!(html.contains("chart-axis-bottom"));
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
}
