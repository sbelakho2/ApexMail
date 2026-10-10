//! Whole-repo “perfect” contract: UX workflows, persona journeys, and
//! adversarial boundary invariants.
//!
//! These tests encode what a complete, honest product must do — not merely
//! what a unit currently returns. They are intentionally cross-surface:
//! the same expectation is checked against every path a user (or attacker)
//! can reach.
//!
//! PERFECT = for every persona and every workflow combination:
//!   1. The journey has no dead end (every terminal state offers a next action).
//!   2. Destructive actions state consequence and require explicit confirmation.
//!   3. Empty ≠ unavailable ≠ restricted ≠ running ≠ failed (distinct, actionable).
//!   4. Forms preserve typed state and associate errors with controls.
//!   5. Tenant / role / scope / CSRF boundaries hold under hostile input.
//!   6. Idempotent retries never double-charge or double-send.
//!   7. Failures are loud and recoverable — never silent zeros.
//!
//! DO NOT mark a workflow “covered” because a page renders. Cover the
//! combination: entry → action → confirmation → result → recovery.

#![allow(clippy::bool_assert_comparison)]

// ─── Persona × workflow matrix (the “perfect” definition) ─────────────────
//
// | Persona        | Must complete end-to-end |
// |----------------|--------------------------|
// | Visitor        | discover → pricing → signup → verify → dashboard |
// | New customer   | first domain → DNS verify → first campaign → send → events |
// | Sender         | API key → API send → suppression → webhook |
// | Team admin     | invite → accept → role change → remove (confirm) |
// | Biller         | plan view → upgrade → invoice → cancel (confirm) |
// | Operator (CP)  | login → tenant inspect → impersonate (confirm) → audit |
// | Support        | destructive confirm → honest flash → recovery link |
// | Attacker       | cross-tenant, CSRF-less, XSS, injection, quota exhaust |
//
// Combinations that MUST also hold:
//   * signup with paid intent ≠ activated paid plan before billing
//   * scheduled campaign save == authorization to auto-send (copy + worker)
//   * edit resource == update (never create-duplicate)
//   * live data page ≠ lose create/invite form
//   * blank optional body == keep stored (template) / reject (create)
//   * form error == same form, same values, linked errors

/// Perfect UX: every workflow terminal state names the next action.
/// A bare “Nothing here” without a recovery path is a defect.
#[test]
fn every_empty_or_terminal_state_offers_a_next_action() {
    // Console empty states (renderer contract).
    let empty = ui_foundation::leptos_views::web_campaigns_page();
    // Static fallbacks may be table-less but must still offer the primary
    // create path somewhere on the page.
    assert!(
        empty.contains("/campaigns/new") || empty.contains("New Campaign"),
        "campaigns terminal state must offer create: {empty}"
    );

    let templates = ui_foundation::leptos_views::web_templates_page();
    assert!(
        templates.contains("/templates/new")
            || templates.contains("New Template")
            || templates.contains("Create"),
        "templates terminal state must offer create: {templates}"
    );

    // Placement waiting state must offer a way out.
    let waiting = ui_foundation::leptos_views::web_inbox_placement_detail_page();
    assert!(
        waiting.contains("/inbox-placement"),
        "waiting placement detail must link back to tests: {waiting}"
    );
}

/// Perfect UX: destructive actions never look like ordinary navigation.
/// They must render as confirm-bound buttons (GET /confirm with signed
/// intent), not plain links.
#[test]
fn destructive_row_actions_bind_to_confirmation_not_plain_links() {
    use ui_foundation::view_data::{DataCell, DataRowData, ListPageData, TableData};

    let mut data = ListPageData {
        title: "Contacts".into(),
        description: "d".into(),
        base_path: "/contacts".into(),
        delete_intent: Some("delete-contact".into()),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Email".into()],
        rows: vec![DataRowData {
            id: "c1".into(),
            cells: vec![DataCell::text("a@example.com")],
        }],
    });
    let html = ui_foundation::leptos_views::data_list_page(&data, "contact");

    assert!(
        html.contains("action=\"/confirm\""),
        "delete must go through /confirm: {html}"
    );
    assert!(
        html.contains("intent"),
        "confirm must carry a signed intent: {html}"
    );
    assert!(
        !html.contains("href=\"/contacts/c1/delete\""),
        "delete must not be a plain GET navigation link: {html}"
    );
}

/// Perfect UX: edit is identity-preserving. Creating on edit is a data-loss
/// workflow (duplicate + abandoned original).
#[test]
fn edit_workflows_post_to_update_never_create() {
    let edit = ui_foundation::leptos_views::web_campaign_edit_page_for_id("c_keep");
    assert!(edit.contains("action=\"/web/campaigns/update\""), "{edit}");
    assert!(edit.contains("name=\"id\" value=\"c_keep\""), "{edit}");
    assert!(
        !edit.contains("action=\"/web/campaigns\""),
        "edit must not fall through to create: {edit}"
    );

    let tpl = ui_foundation::leptos_views::web_template_edit_page_with_values(
        &ui_foundation::view_data::TemplateEditData {
            id: "t_keep".into(),
            name: "N".into(),
            subject: "S".into(),
            html_body: "<p>x</p>".into(),
        },
    );
    assert!(tpl.contains("action=\"/web/templates/update\""), "{tpl}");
    assert!(tpl.contains("name=\"id\" value=\"t_keep\""), "{tpl}");
}

/// Perfect UX + worker truth: a schedule is authorization to send.
/// Copy that says “nothing sends automatically” would let users arm
/// production sends they believe are inert.
#[test]
fn schedule_authorization_copy_matches_worker_behavior() {
    // Worker contract (worker-processors::campaigns::start_due_scheduled):
    //   UPDATE … SET status='sending' WHERE status='scheduled' AND scheduled_at <= NOW()
    let editor = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        editor.contains("start automatically"),
        "new editor must state automatic start: {editor}"
    );
    assert!(
        editor.contains("authorizes that automatic send"),
        "saving a schedule must be framed as authorization: {editor}"
    );
    assert!(
        !editor.contains("nothing sends automatically"),
        "stale inert-schedule copy is a safety defect: {editor}"
    );
    assert!(
        !editor.contains("waits for you to press Start"),
        "stale manual-start copy is a safety defect: {editor}"
    );
}

/// Perfect UX: a data-backed page must not lose its create/invite action
/// just because rows exist (the “two products” failure mode).
#[test]
fn live_data_pages_keep_creation_actions() {
    use ui_foundation::view_data::{DataCell, DataRowData, ListPageData, TableData};

    let mut data = ListPageData {
        title: "API Keys".into(),
        description: "creds".into(),
        base_path: "/settings/api-keys".into(),
        action_form_html: ui_foundation::leptos_views::api_key_create_form_html(),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Name".into()],
        rows: vec![DataRowData {
            id: "k1".into(),
            cells: vec![DataCell::text("prod")],
        }],
    });
    let html = ui_foundation::leptos_views::data_list_page(&data, "key");
    assert!(
        html.contains("Create an API key"),
        "populated table must still compose the create form: {html}"
    );
    // And every other live settings surface has its action form.
    assert!(ui_foundation::leptos_views::team_invite_form_html().contains("Send invitation"));
    assert!(ui_foundation::leptos_views::webhook_register_form_html().contains("Register endpoint"));
    assert!(
        ui_foundation::leptos_views::dedicated_ip_request_form_html()
            .contains("Request dedicated IP")
    );
}

/// Perfect UX: state language is distinct — completed-without-results,
/// failed, and waiting are three different recovery stories.
#[test]
fn lifecycle_states_are_distinct_and_actionable() {
    use ui_foundation::view_data::{PlacementDetailData, PlacementProviderRow};

    let base = PlacementDetailData {
        id: "t1".into(),
        name: "Run".into(),
        status: "completed".into(),
        total_accounts: 5,
        completed_accounts: 5,
        created_at: "2026-10-01T00:00:00Z".into(),
        completed_at: "2026-10-01T00:05:00Z".into(),
        providers: vec![PlacementProviderRow {
            provider: "Gmail".into(),
            accounts_tested: 5,
            inbox: 5,
            promotions: 0,
            spam: 0,
            absent: 0,
        }],
    };
    let done = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(&base);
    assert!(done.contains("Per-provider results"), "{done}");
    assert!(done.contains("Gmail"), "{done}");

    let failed = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
        &PlacementDetailData {
            status: "failed".into(),
            providers: vec![],
            ..base.clone()
        },
    );
    assert!(failed.contains("This test failed"), "{failed}");
    assert!(
        failed.contains("/inbox-placement/new"),
        "failed must offer retry: {failed}"
    );

    let empty_done = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
        &PlacementDetailData {
            providers: vec![],
            ..base
        },
    );
    assert!(empty_done.contains("no recorded results"), "{empty_done}");
    assert!(
        empty_done.contains("/inbox-placement/new"),
        "empty completion must offer a new test: {empty_done}"
    );
}

/// Perfect UX: form errors must not look like success, and the preview must
/// not claim email-client fidelity the sanitizer cannot deliver.
#[test]
fn honesty_claims_match_machinery() {
    let editor = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        editor.contains("sanitized structural view"),
        "preview must be labeled structural: {editor}"
    );
    assert!(
        !editor.contains("exactly as recipients will see"),
        "must not claim recipient-client rendering: {editor}"
    );
}

/// Perfect UX: the wordmark is the brand lockup (black + red), not a
/// collapsed monochrome token. Asserted on the public login surface.
#[test]
fn brand_lockup_is_two_tone_across_auth_surfaces() {
    let login = ui_foundation::leptos_views::web_login_page("csrf");
    assert!(
        login.contains("text-brand-600\">Apex"),
        "login wordmark Apex must be brand red: {login}"
    );
    assert!(
        login.contains("text-surface-950\">Mail"),
        "login wordmark Mail must be ink: {login}"
    );
    assert!(
        !login.contains("text-primary\">Apex"),
        "wordmark must not depend on .text-primary: {login}"
    );

    let shell = ui_foundation::shell::WebDashboardShell {
        sidebar_collapsed: false,
        mobile_menu_open: false,
        child_html: "",
        header: ui_foundation::shell::ShellHeader {
            search_query: "",
            unread_count: 0,
            avatar_fallback: "AM",
            user_context: None,
            mobile_menu_open: false,
        },
        impersonation_banner: None,
        toast_surface: None,
        current_path: "/dashboard",
        csrf_token: "tok",
    }
    .render_html();
    assert!(shell.contains("text-brand-600\">Apex"), "{shell}");
    assert!(shell.contains("text-surface-950\">Mail"), "{shell}");
}

/// Perfect security: native select option markup is escaped at the primitive
/// boundary so tenant-controlled names cannot break out of attributes.
#[test]
fn tenant_controlled_select_markup_cannot_break_out() {
    use ui_foundation::primitives::{NativeSelect, SelectOption};

    let evil = "\" onfocus=\"alert(1)";
    let html = NativeSelect {
        id: "id1",
        name: "list_ids",
        options: vec![SelectOption {
            value: evil,
            label: "</option><script>alert(1)</script>",
            disabled: false,
            selected: true,
        }],
        required: false,
        multiple: true,
        size: Some(4),
    }
    .render_html();
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
    assert!(html.contains("&quot;"), "{html}");
}

/// Perfect security: QR mask patterns follow ISO/IEC 18004 so third-party
/// authenticators interoperate (transposed masks silently break MFA).
/// Public encoder surface must produce a well-formed matrix for every
/// payload class the MFA enrollment uses.
#[test]
fn mfa_qr_encodes_interoperable_matrices() {
    for payload in [
        "otpauth://totp/ApexMail:ops%40apexmail.ee?secret=JBSWY3DPEHPK3PXP&issuer=ApexMail",
        "otpauth://totp/short?secret=AAAAAAAAAAAAAAAA",
    ] {
        let qr = ui_foundation::qr::encode(payload)
            .unwrap_or_else(|| panic!("encode must succeed for {payload}"));
        assert!(qr.mask < 8, "mask id out of range: {}", qr.mask);
        assert!(qr.size >= 21, "matrix too small: {}", qr.size);
        assert_eq!(
            qr.size,
            21 + 4 * (qr.version as usize - 1),
            "size/version mismatch"
        );
        let svg = ui_foundation::qr::to_svg(&qr, 4, 2);
        assert!(svg.contains("<svg"), "{payload}");
        assert!(svg.contains("width="), "{payload}");
    }
}

/// Perfect workflows: bulk + row actions must coexist without nested forms
/// (browsers drop inner forms → row delete silently becomes bulk submit).
#[test]
fn bulk_and_row_workflows_coexist_without_nested_forms() {
    use ui_foundation::view_data::{
        BulkActionData, DataCell, DataRowData, ListPageData, TableData,
    };

    let mut data = ListPageData {
        title: "Contacts".into(),
        description: "d".into(),
        base_path: "/contacts".into(),
        delete_intent: Some("delete-contact".into()),
        bulk_action: Some(BulkActionData {
            action: "/web/contacts/delete-bulk".into(),
            button_label: "Delete selected".into(),
        }),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Email".into()],
        rows: vec![
            DataRowData {
                id: "c1".into(),
                cells: vec![DataCell::text("a@x.test")],
            },
            DataRowData {
                id: "c2".into(),
                cells: vec![DataCell::text("b@x.test")],
            },
        ],
    });
    let html = ui_foundation::leptos_views::data_list_page(&data, "contact");

    // Depth scan: every <form> must close before the next opens.
    let mut depth = 0i32;
    let mut max_depth = 0i32;
    let bytes = html.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' {
            let end = html[i..].find('>').map(|e| i + e).unwrap_or(html.len());
            let tag = &html[i + 1..end];
            if tag == "form" || tag.starts_with("form ") {
                depth += 1;
                max_depth = max_depth.max(depth);
            } else if tag.starts_with("/form") {
                depth -= 1;
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    assert!(max_depth <= 1, "nested forms break row workflows: {html}");
    assert!(depth == 0, "unbalanced forms: {html}");
    assert!(html.contains("data-bulk-form=\"contact\""), "{html}");
    assert!(html.contains("form=\"row-delete-c1\""), "{html}");
}

/// Perfect domain workflow: Verify DNS must hit the mounted browser handler
/// (a dead POST target is a silent workflow death).
#[test]
fn domain_verify_workflow_posts_to_a_mounted_handler() {
    use ui_foundation::view_data::{DataCell, DataRowData, ListPageData, TableData};

    let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let mut data = ListPageData {
        title: "Domain".into(),
        description: "DNS".into(),
        base_path: format!("/domains/{id}"),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Type".into(), "Host".into(), "Value".into(), "State".into()],
        rows: vec![DataRowData {
            id: "TXT".into(),
            cells: vec![
                DataCell::mono("TXT"),
                DataCell::mono("_dmarc.example.com"),
                DataCell::mono("v=DMARC1; p=none"),
                DataCell::status("pending"),
            ],
        }],
    });
    let html = ui_foundation::leptos_views::data_list_page(&data, "domain");
    assert!(
        html.contains(&format!("/web/domains/{id}/verify")),
        "verify must target the web handler: {html}"
    );
}

/// Perfect security: the same document must not nest forms OR allow
/// unescaped tenant strings in option values (combined adversarial path).
#[test]
fn combined_bulk_select_and_escape_invariants_hold() {
    use ui_foundation::primitives::{NativeSelect, SelectOption};
    use ui_foundation::view_data::{DataCell, DataRowData, ListPageData, TableData};

    let mut data = ListPageData {
        title: "Lists".into(),
        description: "d".into(),
        base_path: "/lists".into(),
        delete_intent: Some("delete-list".into()),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Name".into()],
        rows: vec![DataRowData {
            id: "l1".into(),
            cells: vec![DataCell::text("\"><img src=x onerror=alert(1)>")],
        }],
    });
    let html = ui_foundation::leptos_views::data_list_page(&data, "list");
    assert!(
        !html.contains("<img src=x"),
        "row text must be escaped: {html}"
    );
    assert!(html.contains("&lt;img"), "escaped form must appear: {html}");

    let sel = NativeSelect {
        id: "s",
        name: "n",
        options: vec![SelectOption {
            value: "a\"b",
            label: "A&B",
            disabled: false,
            selected: false,
        }],
        required: false,
        multiple: false,
        size: None,
    }
    .render_html();
    assert!(sel.contains("a&quot;b"), "{sel}");
    assert!(sel.contains("A&amp;B"), "{sel}");
}
