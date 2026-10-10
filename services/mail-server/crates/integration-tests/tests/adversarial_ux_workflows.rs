//! Adversarial UX workflow-combination contracts (T6).
//!
//! `perfect_contract_tests.rs` pins the happy-path "perfect" matrix. THIS
//! suite is the hostile re-derivation: it re-walks the same persona journeys
//! looking for the failure modes that only appear when workflows are
//! combined — dead-end empty states, create/edit action bleed, schedule copy
//! that lies about auto-send, lifecycle states that collapse into one
//! another, destructive actions reachable by plain GET, bulk forms swallowing
//! row forms, and marketing claims that contradict the billing authority.
//!
//! Every assertion is either rendered from the public `ui_foundation` /
//! `api-server` APIs or read from FILES ON DISK — nothing is a tautological
//! string match against a constant defined in this file. A drift in the
//! product surfaces must turn these red.
//!
//! DO NOT mark a workflow "covered" because a page renders. Cover the
//! combination: entry → action → confirmation → result → recovery.

use std::path::{Path, PathBuf};

// ─── Shared helpers ───────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("CARGO_MANIFEST_DIR is services/mail-server/crates/integration-tests")
        .to_path_buf()
}

/// Depth scan for `<form>` nesting. Browsers drop inner forms, so a nested
/// pair silently rebinds row actions to the outer bulk submit.
fn max_form_depth(html: &str) -> (i32, i32) {
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
    (max_depth, depth)
}

/// Extract every `class="…apex-empty-state…"` block body (the EmptyState
/// primitive's wrapper) so a dead CTA button cannot hide in page chrome.
fn empty_state_blocks(html: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let marker = "apex-empty-state";
    let mut rest = html;
    while let Some(start) = rest.find(marker) {
        // Walk back to the opening `<div` that owns this class.
        let before = &rest[..start];
        let Some(open) = before.rfind("<div") else {
            break;
        };
        let after = &rest[open..];
        let Some(open_end) = after.find('>') else {
            break;
        };
        // Forward-scan to the matching close is overkill: take a bounded
        // window (EmptyState markup is small) up to the next section break.
        let window = &after[open_end + 1..];
        let end = window
            .find("</section>")
            .or_else(|| window.find("</form>"))
            .unwrap_or(window.len().min(2_500));
        blocks.push(window[..end].to_string());
        rest = &window[end..];
    }
    blocks
}

/// A navigable next action: a real href into a route, or a form that POSTs
/// somewhere. A bare `<button type="button">` is a dead end.
fn has_next_action(html: &str) -> bool {
    html.contains("href=\"/")
        || html.contains("href=\"")
            && (html.contains("method=\"post\"") || html.contains("method=\"get\""))
        || (html.contains("<form") && html.contains("action=\"/"))
}

/// Recursively collect marketing source files (content + data + templates),
/// skipping build output and compiled CSS.
fn collect_marketing_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "public" || name == "static" || name == "__pycache__" {
            continue;
        }
        if path.is_dir() {
            collect_marketing_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("md") | Some("json") | Some("html") | Some("toml")
        ) {
            out.push(path);
        }
    }
}

fn marketing_root() -> PathBuf {
    repo_root().join("apps/marketing-zola")
}

fn read_required(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "required marketing/docs file missing or unreadable: {} ({e})",
            path.display()
        )
    })
}

/// `## ` headings from a markdown body (front matter excluded by only
/// counting ATX headings with a space after the hashes).
fn section_headings(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            trimmed.strip_prefix("## ").map(|s| s.trim().to_string())
        })
        .collect()
}

// ─── 1. Workflow matrix: every terminal empty state offers a next action ──

/// GATE: for EACH terminal empty state the journey can land on, the rendered
/// surface must expose a real next-action (href or POST form) — never a dead
/// button and never a bare "nothing here".
#[test]
fn workflow_matrix_every_terminal_empty_state_offers_a_next_action() {
    use ui_foundation::view_data::{
        BulkActionData, DataCell, DataRowData, ListPageData, PlacementDetailData,
        PlacementProviderRow, TableData,
    };

    // (journey step, rendered HTML, required next-action needle)
    let mut matrix: Vec<(&str, String, &str)> = Vec::new();

    // Customer: domains → no domain yet.
    matrix.push((
        "customer/domains-empty",
        ui_foundation::leptos_views::web_domains_page(),
        "/domains/new",
    ));

    // Customer: placement list empty.
    matrix.push((
        "customer/placement-list-empty",
        ui_foundation::leptos_views::web_inbox_placement_page(),
        "/inbox-placement/new",
    ));

    // Customer: placement detail waiting (static fallback).
    matrix.push((
        "customer/placement-detail-waiting",
        ui_foundation::leptos_views::web_inbox_placement_detail_page(),
        "/inbox-placement",
    ));

    // Customer: placement completed-without-results.
    let placement_base = PlacementDetailData {
        id: "t_matrix".into(),
        name: "Matrix run".into(),
        status: "completed".into(),
        total_accounts: 3,
        completed_accounts: 3,
        created_at: "2026-10-01T00:00:00Z".into(),
        completed_at: "2026-10-01T00:05:00Z".into(),
        providers: vec![],
    };
    matrix.push((
        "customer/placement-completed-empty",
        ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(&placement_base),
        "/inbox-placement/new",
    ));

    // Customer: placement failed.
    matrix.push((
        "customer/placement-failed",
        ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
            &PlacementDetailData {
                status: "failed".into(),
                providers: vec![PlacementProviderRow {
                    provider: "Gmail".into(),
                    accounts_tested: 0,
                    inbox: 0,
                    promotions: 0,
                    spam: 0,
                    absent: 0,
                }],
                ..placement_base.clone()
            },
        ),
        "/inbox-placement/new",
    ));

    // Customer: placement running.
    matrix.push((
        "customer/placement-running",
        ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
            &PlacementDetailData {
                status: "running".into(),
                ..placement_base.clone()
            },
        ),
        "/inbox-placement",
    ));

    // Sender: dedicated IPs empty — the CTA may live in the header form
    // rather than inside the EmptyState block, so the PAGE must act.
    matrix.push((
        "sender/dedicated-ips-empty",
        ui_foundation::leptos_views::web_dedicated_ips_page(),
        "/web/dedicated-ips",
    ));

    // Customer: campaigns empty via the data-driven list (primary action).
    let mut campaigns = ListPageData {
        title: "Campaigns".into(),
        description: "d".into(),
        base_path: "/campaigns".into(),
        primary_action: Some(("New Campaign".into(), "/campaigns/new".into())),
        empty_title: "No campaigns yet".into(),
        empty_description: "Create your first campaign.".into(),
        ..Default::default()
    };
    campaigns.table = Some(TableData {
        columns: vec!["Name".into()],
        rows: vec![],
    });
    matrix.push((
        "customer/campaigns-empty",
        ui_foundation::leptos_views::data_list_page(&campaigns, "campaign"),
        "/campaigns/new",
    ));

    // Operator: CP tenants empty (empty-state CTA is the collection action).
    matrix.push((
        "operator/cp-tenants-empty",
        ui_foundation::leptos_views::control_plane_tenants_page(),
        "/tenants/new",
    ));

    // Team: contacts empty with bulk scope still offering import/create
    // through the action form / primary action.
    let mut contacts = ListPageData {
        title: "Contacts".into(),
        description: "d".into(),
        base_path: "/contacts".into(),
        primary_action: Some(("Add Contact".into(), "/contacts/new".into())),
        delete_intent: Some("delete-contact".into()),
        bulk_action: Some(BulkActionData {
            action: "/web/contacts/delete-bulk".into(),
            button_label: "Delete selected".into(),
        }),
        empty_title: "No contacts yet".into(),
        empty_description: "Import or add a contact.".into(),
        ..Default::default()
    };
    contacts.table = Some(TableData {
        columns: vec!["Email".into()],
        rows: vec![DataRowData {
            id: "c1".into(),
            cells: vec![DataCell::text("a@x.test")],
        }],
    });
    let contacts_html = ui_foundation::leptos_views::data_list_page(&contacts, "contact");
    // Live-data page (rows present) must still carry the create affordance.
    assert!(
        contacts_html.contains("/contacts/new") || contacts_html.contains("Add Contact"),
        "live contacts page must keep its create action: {contacts_html}"
    );

    for (step, html, needle) in &matrix {
        assert!(
            html.contains(needle),
            "workflow matrix [{step}]: terminal state must offer next action containing {needle:?}, got: {html}"
        );
        assert!(
            has_next_action(html),
            "workflow matrix [{step}]: page has no navigable next action at all: {html}"
        );
    }

    // Dead-CTA detection: an EmptyState that renders an action button MUST
    // pair it with an href. A lone <button type="button"> is a dead end.
    for (step, html, _) in &matrix {
        for block in empty_state_blocks(html) {
            if block.contains("action_label") || block.contains("mt-6") {
                let has_anchor = block.contains("<a href=\"");
                let has_button = block.contains("<button type=\"button\"");
                assert!(
                    !(has_button && !has_anchor),
                    "workflow matrix [{step}]: empty-state CTA is a dead button (no href): {block}"
                );
            }
        }
    }
}

// ─── 2. Edit-vs-create action matrix (campaign, template) ─────────────

/// GATE: edit is identity-preserving and create is insert-only. The two
/// action endpoints must never be interchangeable across the matrix.
#[test]
fn edit_vs_create_action_matrix_campaign_and_template() {
    use ui_foundation::view_data::{CampaignEditData, TemplateEditData};

    // ── Campaign ──────────────────────────────────────────────────────
    let create = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        create.contains("action=\"/web/campaigns\""),
        "campaign CREATE must POST to the create endpoint: {create}"
    );
    assert!(
        !create.contains("action=\"/web/campaigns/update\""),
        "campaign CREATE must not POST to update: {create}"
    );
    assert!(
        !create.contains("name=\"id\""),
        "campaign CREATE must not carry a hidden row id: {create}"
    );

    let edit = ui_foundation::leptos_views::web_campaign_edit_page_for_id("c_matrix");
    assert!(
        edit.contains("action=\"/web/campaigns/update\""),
        "campaign EDIT must POST to the update endpoint: {edit}"
    );
    assert!(
        edit.contains("name=\"id\" value=\"c_matrix\""),
        "campaign EDIT must carry the bound id: {edit}"
    );
    assert!(
        !edit.contains("action=\"/web/campaigns\""),
        "campaign EDIT must not fall through to create: {edit}"
    );

    let edit_values =
        ui_foundation::leptos_views::web_campaign_edit_page_with_values(&CampaignEditData {
            id: "c_vals".into(),
            name: "Keep me".into(),
            subject: "Sub".into(),
            html_body: "<p>body</p>".into(),
            scheduled_at: "2026-12-01T10:00".into(),
        });
    assert!(
        edit_values.contains("action=\"/web/campaigns/update\""),
        "{edit_values}"
    );
    assert!(
        edit_values.contains("value=\"c_vals\""),
        "value-prefilled edit must keep the id: {edit_values}"
    );
    assert!(
        edit_values.contains("value=\"Keep me\""),
        "failed-replay style prefills must keep typed values: {edit_values}"
    );

    // ── Template ──────────────────────────────────────────────────────
    let tpl_create = ui_foundation::leptos_views::web_templates_new_page();
    assert!(
        tpl_create.contains("action=\"/web/templates\""),
        "template CREATE must POST to the create endpoint: {tpl_create}"
    );
    assert!(
        !tpl_create.contains("action=\"/web/templates/update\""),
        "template CREATE must not POST to update: {tpl_create}"
    );
    assert!(
        !tpl_create.contains("name=\"id\""),
        "template CREATE must not carry a hidden row id: {tpl_create}"
    );

    let tpl_edit =
        ui_foundation::leptos_views::web_template_edit_page_with_values(&TemplateEditData {
            id: "t_matrix".into(),
            name: "Welcome".into(),
            subject: "Hi".into(),
            html_body: "<p>x</p>".into(),
        });
    assert!(
        tpl_edit.contains("action=\"/web/templates/update\""),
        "template EDIT must POST to the update endpoint: {tpl_edit}"
    );
    assert!(
        tpl_edit.contains("name=\"id\" value=\"t_matrix\""),
        "template EDIT must carry the bound id: {tpl_edit}"
    );
    assert!(
        !tpl_edit.contains("action=\"/web/templates\""),
        "template EDIT must not fall through to create: {tpl_edit}"
    );
    // Blank-optional-body semantics (edit = keep stored).
    assert!(
        tpl_edit.to_lowercase().contains("keep the stored body"),
        "template EDIT must state blank-body keep-stored semantics: {tpl_edit}"
    );

    // Cross-product: the create surface must not advertise update, and the
    // edit surface must not advertise create. (Substring 'update' appears in
    // copy; scope the check to form actions.)
    for (name, html, forbidden) in [
        ("campaign-create", &create, "/web/campaigns/update"),
        ("template-create", &tpl_create, "/web/templates/update"),
        ("campaign-edit", &edit, "action=\"/web/campaigns\""),
        ("template-edit", &tpl_edit, "action=\"/web/templates\""),
    ] {
        assert!(
            !html.contains(forbidden),
            "edit-vs-create matrix [{name}]: forbidden action {forbidden:?} present: {html}"
        );
    }
}

// ─── 3. Schedule authorization copy matrix ────────────────────────────

/// GATE: every surface that lets a user arm a schedule must state the
/// auto-send truth. Copy that claims the schedule is inert is a safety
/// defect — the worker claims `status='scheduled'` rows with no human click.
#[test]
fn schedule_authorization_copy_matrix_matches_auto_send_truth() {
    use ui_foundation::view_data::CampaignEditData;

    let surfaces: [(&str, String); 3] = [
        (
            "campaign-create-editor",
            ui_foundation::leptos_views::web_campaigns_new_page(),
        ),
        (
            "campaign-edit-editor",
            ui_foundation::leptos_views::web_campaign_edit_page_with_values(&CampaignEditData {
                id: "c_sched".into(),
                name: "S".into(),
                subject: "S".into(),
                html_body: "<p>x</p>".into(),
                scheduled_at: "2026-12-01T10:00".into(),
            }),
        ),
        (
            "campaign-detail-monitor",
            ui_foundation::leptos_views::web_campaign_detail_page(),
        ),
    ];

    for (name, html) in &surfaces {
        let mentions_schedule =
            html.to_lowercase().contains("schedule") || html.to_lowercase().contains("scheduled");
        if !mentions_schedule {
            continue;
        }
        // Auto-send truth must appear wherever a schedule is offered OR
        // where a scheduled campaign is monitored.
        assert!(
            html.contains("start automatically")
                || html.contains("start automatically at")
                || html.contains("begin automatically")
                || html.contains("starts the send automatically"),
            "schedule copy matrix [{name}]: must state automatic start, got: {html}"
        );
    }

    // The create + edit editors must additionally frame the save as AUTHORIZATION.
    for (name, html) in &surfaces[..2] {
        assert!(
            html.contains("authorizes that automatic send"),
            "schedule copy matrix [{name}]: saving a schedule must be framed as authorization: {html}"
        );
        for stale in [
            "nothing sends automatically",
            "waits for you to press Start",
            "will not send until you start",
            "inert until you confirm",
        ] {
            assert!(
                !html.to_lowercase().contains(&stale.to_lowercase()),
                "schedule copy matrix [{name}]: stale inert-schedule claim {stale:?} is a safety defect: {html}"
            );
        }
    }

    // "Save as draft" must remain a distinct, non-authorizing control.
    let create = &surfaces[0].1;
    assert!(
        create.contains("name=\"as_draft\""),
        "Save as draft must be a named submit that clears the schedule: {create}"
    );
}

// ─── 4. Distinct lifecycle states (placement detail) ──────────────────

/// GATE: empty ≠ unavailable ≠ restricted ≠ failed ≠ running. Placement
/// detail is the reference lifecycle surface — completed/failed/empty/running
/// must render four different recovery stories.
#[test]
fn placement_lifecycle_states_are_distinct_and_actionable() {
    use ui_foundation::view_data::{PlacementDetailData, PlacementProviderRow};

    let base = PlacementDetailData {
        id: "t_life".into(),
        name: "Lifecycle".into(),
        status: "completed".into(),
        total_accounts: 5,
        completed_accounts: 5,
        created_at: "2026-10-01T00:00:00Z".into(),
        completed_at: "2026-10-01T00:05:00Z".into(),
        providers: vec![],
    };

    let completed_results = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
        &PlacementDetailData {
            providers: vec![PlacementProviderRow {
                provider: "Gmail".into(),
                accounts_tested: 5,
                inbox: 4,
                promotions: 1,
                spam: 0,
                absent: 0,
            }],
            ..base.clone()
        },
    );
    let completed_empty =
        ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(&base.clone());
    let failed = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
        &PlacementDetailData {
            status: "failed".into(),
            ..base.clone()
        },
    );
    let running = ui_foundation::leptos_views::web_inbox_placement_detail_page_with_data(
        &PlacementDetailData {
            status: "running".into(),
            completed_accounts: 2,
            ..base.clone()
        },
    );

    // Distinct copy — the four stories must not collapse into one string.
    assert!(
        completed_results.contains("Per-provider results"),
        "{completed_results}"
    );
    assert!(
        completed_empty.contains("no recorded results"),
        "empty completion must be honest about missing results: {completed_empty}"
    );
    assert!(failed.contains("This test failed"), "{failed}");
    assert!(
        running.contains("Results appear once the test completes")
            || running.contains("reload this page"),
        "running must describe an in-flight wait, not a failure: {running}"
    );

    // Pairwise distinctness of the status badge labels.
    let labels = [
        ("completed-results", &completed_results, "Completed"),
        ("completed-empty", &completed_empty, "Completed"),
        ("failed", &failed, "Failed"),
        ("running", &running, "Running"),
    ];
    for (name, html, label) in labels {
        assert!(
            html.contains(label),
            "lifecycle [{name}]: status badge must read {label:?}: {html}"
        );
    }
    // Failed and running must not share the empty-completion headline.
    assert!(!failed.contains("no recorded results"), "{failed}");
    assert!(!running.contains("This test failed"), "{running}");
    assert!(
        !completed_empty.contains("This test failed"),
        "{completed_empty}"
    );

    // Every terminal state offers a next action; in-flight offers a way back.
    assert!(
        completed_empty.contains("/inbox-placement/new"),
        "{completed_empty}"
    );
    assert!(failed.contains("/inbox-placement/new"), "{failed}");
    assert!(running.contains("/inbox-placement"), "{running}");
}

// ─── 5. Destructive → /confirm (no plain GET delete) ──────────────────

/// GATE: destructive actions open the signed GET /confirm interstitial.
/// A plain GET href that mutates is prefetcher- and scanner-triggerable.
#[test]
fn destructive_actions_route_through_confirm_not_plain_get_delete() {
    use ui_foundation::view_data::{
        BulkActionData, DataCell, DataRowData, ListPageData, TableData,
    };

    let mut data = ListPageData {
        title: "Lists".into(),
        description: "d".into(),
        base_path: "/lists".into(),
        delete_intent: Some("delete-list".into()),
        bulk_action: Some(BulkActionData {
            action: "/web/lists/delete-bulk".into(),
            button_label: "Delete selected".into(),
        }),
        ..Default::default()
    };
    data.table = Some(TableData {
        columns: vec!["Name".into()],
        rows: vec![DataRowData {
            id: "l_hostile".into(),
            cells: vec![DataCell::text("Hostile List")],
        }],
    });
    let list_page = ui_foundation::leptos_views::data_list_page(&data, "list");

    assert!(
        list_page.contains("action=\"/confirm\"") || list_page.contains("href=\"/confirm"),
        "delete must bind to /confirm: {list_page}"
    );
    assert!(
        list_page.contains("intent"),
        "confirm must carry a signed intent: {list_page}"
    );
    // No plain GET delete navigation on any rendered list surface.
    for forbidden in [
        "href=\"/lists/l_hostile/delete\"",
        "href=\"/web/lists/delete\"",
        "href=\"/lists/delete",
    ] {
        assert!(
            !list_page.contains(forbidden),
            "plain GET delete {forbidden:?} must not exist: {list_page}"
        );
    }

    // Static campaigns list: row Delete is an /confirm link, bulk delete is
    // a POST formaction — never a GET mutation.
    let campaigns = ui_foundation::leptos_views::web_campaigns_page();
    assert!(
        campaigns.contains("href=\"/confirm?intent=delete-campaign"),
        "campaign row delete must open /confirm: {campaigns}"
    );
    assert!(
        campaigns.contains("formaction=\"/web/campaigns/delete-bulk\""),
        "bulk delete must be a POST target: {campaigns}"
    );
    assert!(
        !campaigns.contains("href=\"/campaigns/c_spring/delete\""),
        "plain GET campaign delete must not exist: {campaigns}"
    );

    // The confirm page itself is a POST form (the actual mutation), and the
    // unsigned/tampered path states that nothing was changed.
    let confirm = ui_foundation::leptos_views::web_confirm_page(
        "delete-campaign",
        "c_x",
        "/campaigns",
        "sig_test",
        true,
    );
    assert!(
        confirm.contains("method=\"post\"") && confirm.contains("/web/confirm"),
        "the destructive mutation must POST from the confirm page: {confirm}"
    );
    assert!(
        !confirm.contains("method=\"get\" action=\"/web/campaigns/delete"),
        "confirm page must not expose a GET mutation: {confirm}"
    );
}

// ─── 6. Bulk + row nested-form impossibility ──────────────────────────

/// GATE: bulk + row workflows coexist without nested forms. Browsers drop
/// the inner form, so nesting turns every row action into a bulk submit.
#[test]
fn bulk_and_row_forms_are_never_nested() {
    use ui_foundation::view_data::{
        BulkActionData, DataCell, DataRowData, ListPageData, TableData,
    };

    let mut cases: Vec<(&str, String)> = Vec::new();

    let mut contacts = ListPageData {
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
    contacts.table = Some(TableData {
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
    cases.push((
        "contacts-bulk+row",
        ui_foundation::leptos_views::data_list_page(&contacts, "contact"),
    ));

    let mut campaigns = ListPageData {
        title: "Campaigns".into(),
        description: "d".into(),
        base_path: "/campaigns".into(),
        delete_intent: Some("delete-campaign".into()),
        bulk_action: Some(BulkActionData {
            action: "/web/campaigns/delete-bulk".into(),
            button_label: "Delete selected".into(),
        }),
        ..Default::default()
    };
    campaigns.table = Some(TableData {
        columns: vec!["Name".into()],
        rows: vec![DataRowData {
            id: "c_a".into(),
            cells: vec![DataCell::text("A")],
        }],
    });
    cases.push((
        "campaigns-bulk+row",
        ui_foundation::leptos_views::data_list_page(&campaigns, "campaign"),
    ));

    // Static campaigns page carries its own bulk form around the table.
    cases.push((
        "campaigns-static-bulk",
        ui_foundation::leptos_views::web_campaigns_page(),
    ));

    for (name, html) in &cases {
        let (max_depth, final_depth) = max_form_depth(html);
        assert!(
            max_depth <= 1,
            "nested forms [{name}] break row workflows (max depth {max_depth}): {html}"
        );
        assert_eq!(final_depth, 0, "unbalanced forms [{name}]: {html}");
    }

    // Row delete controls must target the row form id, not the bulk form.
    let contacts_html = &cases[0].1;
    assert!(
        contacts_html.contains("data-bulk-form=\"contact\""),
        "bulk form must be labelled: {contacts_html}"
    );
    assert!(
        contacts_html.contains("form=\"row-delete-c1\""),
        "row delete must bind to its sibling row form: {contacts_html}"
    );
}

// ─── 7. Pricing strings: marketing content + data scan ────────────────

/// GATE: Free-tier and annual-billing claims match the commercial authority
/// (`apps/marketing-zola/data/pricing.json` + `docs/pricing.md`):
///   * Free = 3,000/mo recurring + ONE-TIME 30,000 launch allowance
///     (never "30K/mo" as a recurring quota);
///   * Annual = 10 payments / ~16.7% (never "10% off" / "10% discount").
#[test]
fn pricing_claim_scan_rejects_stale_quota_and_discount_copy() {
    let root = marketing_root();
    assert!(root.is_dir(), "marketing root missing: {}", root.display());

    let mut files = Vec::new();
    collect_marketing_files(&root.join("content"), &mut files);
    collect_marketing_files(&root.join("data"), &mut files);
    collect_marketing_files(&root.join("templates"), &mut files);
    assert!(
        files.len() > 10,
        "marketing scan found almost no source files — walker broken? ({})",
        files.len()
    );

    // Forbidden recurring-quota / discount phrasings. The 30,000 launch
    // allowance is LEGITIMATE when paired with "one-time"/"launch"; the
    // forbidden forms claim it as the monthly quota or advertise a 10%
    // annual discount (the real figure is ~16.7% on 10 payments).
    let forbidden: &[(&str, &str)] = &[
        ("30K/mo", "recurring 30K monthly quota"),
        ("30k/mo", "recurring 30k monthly quota"),
        ("30K per month", "recurring 30K monthly quota"),
        ("30k per month", "recurring 30k monthly quota"),
        ("30,000/mo", "recurring 30,000 monthly quota"),
        ("10% off", "stale annual discount (real ≈16.7%)"),
        ("10% discount", "stale annual discount (real ≈16.7%)"),
        ("10 percent off", "stale annual discount (real ≈16.7%)"),
    ];

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(body) = std::fs::read_to_string(path) else {
            continue;
        };
        for (needle, why) in forbidden {
            if body.contains(needle) {
                offenders.push(format!("{}: {needle} ({why})", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "stale pricing claims in marketing sources:\n{}",
        offenders.join("\n")
    );

    // Positive authority pins: the commercial data file is the source of truth.
    let pricing = read_required(&root.join("data/pricing.json"));
    assert!(
        pricing.contains("\"annual_billing_months\": 10"),
        "annual billing must be 10 payments: {pricing}"
    );
    assert!(
        pricing.contains("\"annual_savings_percent\": 16.7"),
        "annual saving must be ~16.7%, never 10%: {pricing}"
    );
    assert!(
        pricing.contains("\"emails\": 30000") && pricing.contains("launch"),
        "the 30,000 figure must be the one-time launch allowance: {pricing}"
    );

    // Compare-page Free-tier cells share one authority wording.
    let compare_dir = root.join("content/compare");
    let mut free_cells = Vec::new();
    collect_marketing_files(&compare_dir, &mut files);
    for path in files.iter().filter(|p| p.starts_with(&compare_dir)) {
        let Ok(body) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in body.lines() {
            if line.contains("Free tier") || line.contains("Free Tier") {
                free_cells.push((path.display().to_string(), line.to_string()));
            }
        }
    }
    assert!(
        free_cells.len() >= 3,
        "compare pages must each declare a Free-tier cell: {free_cells:?}"
    );
    for (path, line) in &free_cells {
        assert!(
            line.contains("3,000") && line.contains("30,000"),
            "Free-tier cell on {path} must quote the 3,000/mo + 30,000 launch authority, got: {line}"
        );
        assert!(
            line.to_lowercase().contains("launch"),
            "Free-tier cell on {path} must frame 30,000 as the launch allowance, got: {line}"
        );
        assert!(
            !line.contains("30,000 emails/mo") && !line.contains("30K/mo"),
            "Free-tier cell on {path} must not claim 30k as the recurring quota: {line}"
        );
    }
}

// ─── 8. SLA / quickstart DE·ES·FR section parity ──────────────────────

/// GATE: localized SLA + quickstart bodies are real translations — non-empty,
/// same section SET as EN (not a stub that keeps only the title).
#[test]
fn sla_and_quickstart_locales_match_en_section_set() {
    let content = marketing_root().join("content");

    // ── SLA: 7 numbered sections in every locale ──────────────────────
    let sla_en = read_required(&content.join("sla/index.md"));
    let en_sections = section_headings(&sla_en);
    assert!(
        en_sections.len() >= 7,
        "EN SLA must carry the full section set, got {en_sections:?}"
    );
    // The numbered prefix ("1.", "2.", …) is the locale-stable identity.
    let en_numbers: Vec<String> = en_sections
        .iter()
        .filter_map(|h| {
            let token = h.split_whitespace().next().unwrap_or("");
            if token.ends_with('.') && token.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                Some(token.to_string())
            } else {
                None
            }
        })
        .collect();
    assert!(
        !en_numbers.is_empty(),
        "EN SLA sections must be numbered: {en_sections:?}"
    );

    for locale in ["de", "es", "fr"] {
        let path = content.join(format!("sla/index.{locale}.md"));
        let body = read_required(&path);
        let body_text = body
            .split("+++=")
            .nth(1)
            .or_else(|| body.split("\n+++\n").nth(1))
            .unwrap_or(&body);
        assert!(
            body_text.trim().len() > 400,
            "SLA {locale} body must be a real translation, not a stub ({} bytes)",
            body_text.trim().len()
        );
        let sections = section_headings(&body);
        assert_eq!(
            sections.len(),
            en_sections.len(),
            "SLA {locale} must carry the EN section set size, got {sections:?} vs {en_sections:?}"
        );
        let numbers: Vec<String> = sections
            .iter()
            .filter_map(|h| {
                let token = h.split_whitespace().next().unwrap_or("");
                if token.ends_with('.') && token.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    Some(token.to_string())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            numbers, en_numbers,
            "SLA {locale} numbered sections must match EN: {numbers:?} vs {en_numbers:?}"
        );
    }

    // ── Quickstart: 12 steps + next-steps in every locale ─────────────
    let qs_en = read_required(&content.join("quickstart/index.md"));
    let en_qs = section_headings(&qs_en);
    assert!(
        en_qs.len() >= 13,
        "EN quickstart must carry 12 steps + next steps, got {en_qs:?}"
    );
    let en_step_ids: Vec<String> = en_qs
        .iter()
        .filter_map(|h| {
            // "Step 12: …" / "Step 1: …" — the numeric id is stable.
            let lower = h.to_ascii_lowercase();
            if !lower.starts_with("step ") {
                return None;
            }
            lower
                .split_whitespace()
                .nth(1)
                .map(|n| n.trim_end_matches(':').to_string())
        })
        .collect();
    assert_eq!(
        en_step_ids.len(),
        12,
        "EN quickstart must number steps 1-12, got {en_step_ids:?}"
    );

    for locale in ["de", "es", "fr"] {
        let path = content.join(format!("quickstart/index.{locale}.md"));
        let body = read_required(&path);
        let body_text = body
            .split("+++=")
            .nth(1)
            .or_else(|| body.split("\n+++\n").nth(1))
            .unwrap_or(&body);
        assert!(
            body_text.trim().len() > 2_000,
            "quickstart {locale} body must be a real translation ({} bytes)",
            body_text.trim().len()
        );
        let sections = section_headings(&body);
        assert_eq!(
            sections.len(),
            en_qs.len(),
            "quickstart {locale} section count must match EN, got {sections:?}"
        );
        // Localized step headings keep the numeric identity ("Schritt 12:",
        // "Paso 12:", "Étape 12 :") even when the noun is translated.
        for n in 1..=12 {
            let numbered = sections
                .iter()
                .filter(|h| {
                    h.split(|c: char| c == ':' || c == ' ' || c == '　')
                        .any(|tok| tok.trim_end_matches(':') == n.to_string())
                })
                .count();
            assert!(
                numbered >= 1,
                "quickstart {locale} must keep step {n} heading, got {sections:?}"
            );
        }
    }
}

// ─── 10. Form replay keeps form id + values ───────────────────────────

/// GATE: a failed POST round-trips through the signed FormFieldMap cookie
/// and the renderer re-populates the SAME form with the SAME values and
/// linked field errors — never a sibling form, never dropped input.
#[test]
fn form_replay_keeps_form_id_values_and_linked_errors() {
    use api_server::routes::web::{
        decode_form_fields_from_headers, form_fields_set_cookie, FormFieldMap,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use ui_foundation::flash::FlashMessage;

    let secret = "test-form-field-secret-0123456789abcdef";

    // Handler-side: what `redirect_with_field_map` stores on failure.
    let mut map = FormFieldMap::new("webhook-create");
    map.set("url", "https://hooks.example.com/apex");
    map.add_value("events", "message.accepted");
    map.add_value("events", "message.delivered");
    map.error("url", "Enter an https URL.");

    // Cookie round-trip (the PRG vehicle).
    let set_cookie = form_fields_set_cookie(&map, secret, false);
    assert!(
        set_cookie.starts_with("apexmail_form_fields="),
        "cookie name must match the decoder: {set_cookie}"
    );
    let raw = set_cookie
        .split('=')
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .expect("cookie value")
        .to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_str(&format!("apexmail_form_fields={raw}")).expect("cookie header value"),
    );
    let decoded = decode_form_fields_from_headers(&headers, secret)
        .expect("signed field map must decode after the PRG round trip");

    // Identity + payload survive the cookie.
    assert_eq!(
        decoded.form_id, "webhook-create",
        "form id must survive replay"
    );
    assert_eq!(
        decoded.field_value("url"),
        Some("https://hooks.example.com/apex"),
        "typed value must survive replay"
    );
    assert_eq!(
        decoded.field_error("url"),
        Some("Enter an https URL."),
        "field error must stay linked to its control"
    );
    assert_eq!(
        decoded.values.iter().filter(|(n, _)| n == "events").count(),
        2,
        "multi-valued groups must keep every posted option"
    );

    // Tamper resistance: a flipped payload byte must NOT decode.
    let tampered = format!("v1.AAAA{}", &raw[raw.len().saturating_sub(8)..]);
    let mut bad = HeaderMap::new();
    bad.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_str(&format!("apexmail_form_fields={tampered}")).unwrap(),
    );
    assert!(
        decode_form_fields_from_headers(&bad, secret).is_none(),
        "tampered field maps must not replay"
    );

    // View-side: the SAME form re-renders with values + linked errors.
    let view = decoded.clone().into_view_data();
    assert_eq!(view.form_id, "webhook-create");
    let html = ui_foundation::axum_router::render_route_with_form_fields(
        "web",
        "/settings/webhooks",
        None,
        None,
        &[FlashMessage::error("Webhook not saved.")],
        None,
        Some(&view),
    )
    .expect("/settings/webhooks must render");
    assert!(
        html.contains("value=\"https://hooks.example.com/apex\""),
        "failed replay must re-populate the typed value on the SAME form: {html}"
    );
    assert!(
        html.contains("Enter an https URL."),
        "field error must render linked under its control: {html}"
    );
    assert!(
        html.contains("aria-invalid=\"true\""),
        "the failed control must be marked invalid: {html}"
    );

    // Combination: the map is form-scoped — replaying into a different form
    // must NOT leak values (same-form invariant).
    let foreign = ui_foundation::axum_router::render_route_with_form_fields(
        "web",
        "/contacts/new",
        None,
        None,
        &[],
        None,
        Some(&view),
    )
    .expect("/contacts/new must render");
    assert!(
        !foreign.contains("value=\"https://hooks.example.com/apex\""),
        "field maps must never replay into a different form: {foreign}"
    );
}

// ─── Combination: empty vs unavailable vs restricted vs failed ────────

/// GATE: the four "nothing to show" states are copy-distinct. Collapsing
/// them into one empty state is how users misread an outage as "no data".
#[test]
fn empty_unavailable_restricted_and_failed_states_are_copy_distinct() {
    use ui_foundation::primitives::AsyncState;

    let empty = AsyncState::Empty {
        title: "No rows yet",
        description: "Create the first one to get started.",
        action_label: None,
    }
    .render_html();
    let error = AsyncState::Error {
        title: "Could not load",
        description: "The data source failed. Retry when it is back.",
        retry_label: Some("Retry"),
    }
    .render_html();
    let loading = AsyncState::Loading {
        label: "Loading…",
        source_label: Some("live"),
    }
    .render_html();

    assert_ne!(empty, error, "empty and failed must not share markup");
    assert_ne!(empty, loading, "empty and loading must not share markup");
    assert!(empty.contains("No rows yet"), "{empty}");
    assert!(error.contains("Could not load"), "{error}");
    assert!(error.contains("Retry"), "failed must offer retry: {error}");

    // Restricted (read-only) is its own story on suppressions.
    let suppressions = ui_foundation::leptos_views::web_settings_suppressions_page();
    assert!(
        suppressions.contains("read-only") || suppressions.contains("read-only"),
        "restricted surface must say so: {suppressions}"
    );
    assert!(
        suppressions.contains("Why this list is read-only"),
        "restricted must explain the restriction, not look empty: {suppressions}"
    );

    // Unavailable ≠ zero: billing fallback must not fabricate figures.
    let billing = ui_foundation::leptos_views::web_settings_billing_page();
    assert!(
        billing.to_lowercase().contains("unavailable")
            || billing.to_lowercase().contains("not available"),
        "unavailable data must say unavailable, never a fabricated zero: {billing}"
    );
}

// ─── Combination: preview is structural, not client-fidelity ──────────

#[test]
fn preview_copy_is_structural_not_client_fidelity() {
    let editor = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        editor.contains("sanitized structural view"),
        "preview must be labeled structural: {editor}"
    );
    for lie in [
        "exactly as recipients will see",
        "pixel-perfect in every client",
        "identical to Gmail",
        "exactly as it will appear in the inbox",
    ] {
        assert!(
            !editor.to_lowercase().contains(&lie.to_lowercase()),
            "preview must not claim client fidelity ({lie:?}): {editor}"
        );
    }
}
