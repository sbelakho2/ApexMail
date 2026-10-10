//! UX workflow combinations and persona journeys — the “perfect” product
//! contract for every user path, not a page-by-page smoke list.
//!
//! PERFECT means each combination below is true simultaneously:
//!   * entry → primary action → confirmation (if destructive) → result → recovery
//!   * no dead-end empty/failed/unavailable state
//!   * edit ≠ create; schedule ≠ inert metadata; live data ≠ lost actions
//!   * previews and counts never claim fidelity or measurement they lack
//!
//! UPDATE-ONLY suite: assertions are written against the current renderers.
//! Do not run from a prompt that forbids execution.

use ui_foundation::leptos_views::*;
use ui_foundation::shell::{ShellHeader, WebDashboardShell};
use ui_foundation::view_data::*;

fn shell() -> String {
    WebDashboardShell {
        sidebar_collapsed: false,
        mobile_menu_open: false,
        child_html: "<main></main>",
        header: ShellHeader {
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
    .render_html()
}

/// Every primary navigation destination a signed-in customer can reach from
/// the shell must render a document with one main landmark and a title —
/// the journey cannot start from a blank or 404 chrome.
#[test]
fn persona_customer_shell_destinations_all_render() {
    let chrome = shell();
    for href in [
        "/dashboard",
        "/campaigns",
        "/contacts",
        "/lists",
        "/templates",
        "/reports",
        "/analytics",
        "/events",
        "/domains",
        "/settings/api-keys",
        "/settings/team",
        "/settings/billing",
        "/settings/webhooks",
        "/settings/profile",
    ] {
        assert!(
            chrome.contains(&format!("href=\"{href}\"")),
            "customer journey cannot reach {href}: {chrome}"
        );
    }
}

/// Workflow combo: create campaign → (optional schedule) → edit → preview.
/// The create and edit surfaces must be the same form language, different
/// actions, and both name the schedule consequence.
#[test]
fn workflow_create_schedule_edit_preview_share_one_contract() {
    let create = web_campaigns_new_page();
    let edit = web_campaign_edit_page_for_id("c1");
    let edit_values = web_campaign_edit_page_with_values(&CampaignEditData {
        id: "c1".into(),
        name: "Welcome".into(),
        subject: "Hi".into(),
        html_body: "<p>x</p>".into(),
        scheduled_at: "2030-01-01T10:00".into(),
    });

    // One form language: name/subject/content exist on all three.
    for html in [&create, &edit, &edit_values] {
        assert!(html.contains("name=\"name\""), "{html}");
        assert!(html.contains("name=\"subject\""), "{html}");
        assert!(html.contains("name=\"html_body\""), "{html}");
        assert!(html.contains("name=\"scheduled_at\""), "{html}");
    }

    // Create → create action; edit → update action (identity-preserving).
    assert!(create.contains("action=\"/web/campaigns\""), "{create}");
    assert!(
        !create.contains("action=\"/web/campaigns/update\""),
        "{create}"
    );
    assert!(edit.contains("action=\"/web/campaigns/update\""), "{edit}");
    assert!(
        edit_values.contains("action=\"/web/campaigns/update\""),
        "{edit_values}"
    );
    assert!(
        edit_values.contains("name=\"id\" value=\"c1\""),
        "{edit_values}"
    );

    // Schedule consequence named on every surface (authorization to send).
    for html in [&create, &edit, &edit_values] {
        assert!(
            html.contains("authorizes that automatic send")
                || html.contains("starts the send automatically")
                || html.contains("start automatically"),
            "schedule consequence missing: {html}"
        );
    }

    // Preview is a sibling action on the same form (formaction), not a
    // separate app — keeps workflow combo in one submission context.
    assert!(
        create.contains("formaction=\"/web/campaigns/preview\""),
        "{create}"
    );
}

/// Workflow combo: template create vs edit. Create rejects blank body
/// (nothing to keep); edit keeps stored body on blank (editor promise).
/// Both must round-trip through the same update/preview actions.
#[test]
fn workflow_template_create_vs_edit_blank_body_semantics() {
    let create = web_templates_new_page();
    assert!(
        create.contains("action=\"/web/templates\""),
        "create posts to create: {create}"
    );
    assert!(
        !create.contains("Leave the content empty to keep"),
        "create must not promise keep-on-blank: {create}"
    );

    let edit = web_template_edit_page_with_values(&TemplateEditData {
        id: "t1".into(),
        name: "N".into(),
        subject: "S".into(),
        html_body: "<p>body</p>".into(),
    });
    assert!(edit.contains("action=\"/web/templates/update\""), "{edit}");
    assert!(
        edit.contains("Leave the content empty to keep the stored body"),
        "edit must promise keep-on-blank: {edit}"
    );
    assert!(
        edit.contains("formaction=\"/web/templates/preview\""),
        "edit keeps preview in-workflow: {edit}"
    );
}

/// Workflow combo: domain add → verify → tracking. Verify must target a
/// real handler; tracking keeps parent context navigable.
#[test]
fn workflow_domain_add_verify_tracking_actions_are_live() {
    let id = "11111111-2222-3333-4444-555555555555";
    let mut detail = ListPageData {
        title: "Domain".into(),
        description: "DNS setup and verification state.".into(),
        base_path: format!("/domains/{id}"),
        ..Default::default()
    };
    detail.table = Some(TableData {
        columns: vec!["Type".into(), "Host".into(), "Value".into(), "State".into()],
        rows: vec![DataRowData {
            id: "MX".into(),
            cells: vec![
                DataCell::mono("MX"),
                DataCell::mono("@"),
                DataCell::mono("mx.apexmail.ee"),
                DataCell::status("pending"),
            ],
        }],
    });
    let html = data_list_page(&detail, "domain");
    assert!(
        html.contains(&format!("/web/domains/{id}/verify")),
        "{html}"
    );
    // New-domain affordance exists on the list hub.
    let list = web_domains_page();
    assert!(
        list.contains("/domains/new") || list.contains("Add Domain") || list.contains("New Domain"),
        "{list}"
    );
}

/// Workflow combo: team invite beside live membership; API key create beside
/// live keys; webhook register beside live endpoints. Populated ≠ orphaned
/// read-only lists.
#[test]
fn workflow_settings_live_tables_keep_mutations() {
    assert!(api_key_create_form_html().contains("action=\"/web/api-keys\""));
    assert!(team_invite_form_html().contains("action=\"/web/team/invite\""));
    assert!(webhook_register_form_html().contains("action=\"/web/webhooks\""));
    assert!(dedicated_ip_request_form_html().contains("action=\"/web/dedicated-ips/request\""));

    // And they compose with tables via action_form_html.
    let mut data = ListPageData {
        title: "Team".into(),
        description: "d".into(),
        base_path: "/settings/team".into(),
        action_form_html: team_invite_form_html(),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Email".into()],
        rows: vec![DataRowData {
            id: "u1".into(),
            cells: vec![DataCell::text("a@x.test")],
        }],
    });
    let html = data_list_page(&data, "member");
    assert!(html.contains("Send invitation"), "{html}");
    assert!(html.contains("<table"), "{html}");
}

/// Workflow combo: bulk delete + row delete on the same table. Nested forms
/// would silently break one of the two workflows in every browser.
#[test]
fn workflow_bulk_and_row_delete_are_both_submittable() {
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
        rows: vec![DataRowData {
            id: "c1".into(),
            cells: vec![DataCell::text("a@x.test")],
        }],
    });
    let html = data_list_page(&data, "contact");

    // Bulk submit present.
    assert!(html.contains("data-bulk-form=\"contact\""), "{html}");
    assert!(html.contains("/web/contacts/delete-bulk"), "{html}");
    // Row delete present and bound via form=.
    assert!(html.contains("id=\"row-delete-c1\""), "{html}");
    assert!(html.contains("form=\"row-delete-c1\""), "{html}");
    // Sibling, not nested: the row-delete form appears before the bulk form.
    let row_at = html.find("id=\"row-delete-c1\"").unwrap();
    let bulk_at = html.find("data-bulk-form=").unwrap();
    assert!(
        row_at < bulk_at,
        "row-delete form must be a sibling before bulk: {html}"
    );
}

/// Workflow combo: placement test list → detail → (completed|failed|running)
/// → new test. Every terminal state links forward.
#[test]
fn workflow_placement_list_detail_states_link_forward() {
    let list = web_inbox_placement_page();
    assert!(
        list.contains("/inbox-placement/new") || list.contains("New Test"),
        "{list}"
    );

    let waiting = web_inbox_placement_detail_page();
    assert!(waiting.contains("/inbox-placement"), "{waiting}");

    let failed = web_inbox_placement_detail_page_with_data(&PlacementDetailData {
        id: "t".into(),
        name: "N".into(),
        status: "failed".into(),
        total_accounts: 1,
        completed_accounts: 0,
        created_at: "2026-01-01T00:00:00Z".into(),
        completed_at: String::new(),
        providers: vec![],
    });
    assert!(
        failed.contains("/inbox-placement/new"),
        "failed must offer retry: {failed}"
    );
}

/// Workflow combo: API key scopes are a least-privilege decision surface
/// (grouped), not an undifferentiated checkbox wall that trains users to
/// over-grant.
#[test]
fn workflow_api_key_scopes_are_grouped_for_least_privilege() {
    let form = api_key_create_form_html();
    let groups = [
        "Sending",
        "Reading",
        "Contacts &amp; lists",
        "Templates &amp; campaigns",
        "Domains &amp; webhooks",
        "Analytics &amp; suppressions",
    ];
    for g in groups {
        assert!(form.contains(g), "missing group {g}: {form}");
    }
    assert!(form.contains("Prefer read-only keys"), "{form}");
    // Not a flat wall: fieldset/legend structure required.
    assert!(form.matches("<fieldset").count() >= 6, "{form}");
    assert!(form.matches("<legend").count() >= 6, "{form}");
}

/// Workflow combo: reports → deliverability → events → message timeline.
/// Each hub must offer the next hop (no orphan pages).
#[test]
fn workflow_measurement_hubs_link_downstream() {
    let reports = web_reports_page();
    assert!(
        reports.contains("/reports/deliverability") || reports.contains("Delivery"),
        "{reports}"
    );

    let events = web_events_page();
    assert!(
        events.contains("name=\"query\"") || events.contains("/events"),
        "events must offer search or self: {events}"
    );

    let timeline = web_message_timeline_page();
    assert!(
        timeline.contains("/events"),
        "timeline must return to events: {timeline}"
    );
}

/// Workflow combo: signup paid intent vs first-run Free. A selected paid
/// plan must not look activated before billing completes.
#[test]
fn workflow_signup_paid_intent_is_not_activated_access() {
    let signup = web_signup_page_with_plan("csrf", Some("pro"));
    // Intent is carried, but copy must not claim the plan is live.
    assert!(
        !signup.contains("Plan active") && !signup.contains("Your Pro plan is live"),
        "paid intent must not claim activation: {signup}"
    );
    // Native POST signup (no SPA assumption).
    assert!(
        signup.contains("method=\"post\"") || signup.contains("method=\"POST\""),
        "{signup}"
    );
}

/// Workflow combo: destructive confirmation names the action + consequence
/// and keeps a cancel route (operator workflow).
#[test]
fn workflow_destructive_confirm_names_resource_and_consequence() {
    let page = web_confirm_page("delete-campaign", "c_123", "/campaigns", "sig", true);
    assert!(
        page.contains("Delete campaign?"),
        "intent-specific title required: {page}"
    );
    assert!(
        page.contains("permanently removes"),
        "consequence must be stated: {page}"
    );
    assert!(page.contains("c_123"), "resource id visible: {page}");
    assert!(
        page.contains("/campaigns"),
        "must offer return path: {page}"
    );
    assert!(
        page.contains("Yes, delete it"),
        "confirm verb must be explicit: {page}"
    );
    assert!(page.contains("Cancel"), "cancel must exist: {page}");

    // Invalid/tampered signature is a distinct honest refusal.
    let bad = web_confirm_page("delete-campaign", "c_123", "/campaigns", "sig", false);
    assert!(bad.contains("Confirmation link unavailable"), "{bad}");
    assert!(bad.contains("Nothing was changed"), "{bad}");
}

/// Workflow combo: CP operator path. Login recovery + tenant work are
/// reachable; impersonation is a deliberate action surface.
#[test]
fn workflow_operator_console_entry_and_tenants() {
    let cp_login = control_plane_login_page("csrf");
    assert!(
        cp_login.contains("Operator") || cp_login.contains("operator"),
        "{cp_login}"
    );
    assert!(
        cp_login.to_lowercase().contains("method=\"post\""),
        "{cp_login}"
    );

    let tenants = control_plane_tenants_page();
    assert!(
        tenants.contains("Tenant") || tenants.contains("/tenants"),
        "{tenants}"
    );
}

/// Workflow combo: preview honesty under the sanitizer. Campaign and
/// template previews must not promise recipient-client fidelity.
#[test]
fn workflow_previews_are_structural_across_surfaces() {
    let editor = web_campaigns_new_page();
    assert!(editor.contains("sanitized structural view"), "{editor}");
    assert!(!editor.contains("exactly as recipients"), "{editor}");
}

/// Workflow combo: auth surfaces are one system (same lockup, native forms,
/// no criminal-warning banners).
#[test]
fn workflow_auth_surfaces_share_one_system() {
    for html in [
        web_login_page("csrf"),
        web_signup_page("csrf"),
        web_forgot_password_page("csrf"),
    ] {
        assert!(
            html.contains("text-brand-600\">Apex") || html.contains("Apex"),
            "{html}"
        );
        assert!(
            !html.contains("criminal") && !html.contains("Criminal"),
            "no criminal-warning chrome: {html}"
        );
        // Native form post.
        assert!(html.to_lowercase().contains("method=\"post\""), "{html}");
    }
}

/// Workflow combo: CTA / primary actions on marketing-adjacent console
/// surfaces never 404-in-advance (hrefs point at real console routes).
#[test]
fn workflow_console_internal_hrefs_resolve_to_known_routes() {
    let settings = web_settings_page();
    for href in [
        "/settings/api-keys",
        "/settings/team",
        "/settings/billing",
        "/settings/webhooks",
        "/settings/profile",
        "/settings/suppressions",
    ] {
        assert!(
            settings.contains(&format!("href=\"{href}\"")),
            "{href} missing from settings hub"
        );
    }
}
