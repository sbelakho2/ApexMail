//! Fail-first migration completeness tests.
//!
//! These tests verify that the Rust UI migration is fully complete://! - Every route has a working view function
//! - Every rendered page uses real primitives (not placeholder HTML)
//! - All CSS class contracts are preserved
//! - All data-* and aria-* attributes are present
//! - The axum router can serve every page as valid HTML
//! - Pixel parity with deterministic rendering (same input → same output)

use crate::axum_router;
use crate::leptos_views;
use crate::pixel_parity;
use crate::primitives;
use crate::routing;
use crate::ssr;

const UI_RUST_MIGRATION_PLAN_JSON: &str =
    include_str!("../../../../../docs/development/ui-rust-migration-plan.json");
const MOLLIE_TOOL_CONTRACT_MD: &str = include_str!("../../../../../docs/tool-contracts/mollie.md");
const MOLLIE_BILLING_RENAMES_SQL: &str =
    include_str!("../../../migrations/269_mollie_billing_renames.sql");

fn rendered_routes() -> Vec<ssr::SsrRoute> {
    ssr::ssr_routes()
}

fn render_or_panic(route: &ssr::SsrRoute) -> String {
    axum_router::render_route(route.surface, route.pattern)
        .unwrap_or_else(|| panic!("missing renderer for [{}] {}", route.surface, route.pattern))
}

fn assert_no_unmigrated_markers(label: &str, html: &str) {
    let forbidden = [
        "TODO",
        "FIXME",
        "lorem ipsum",
        "__NEXT_DATA__",
        "data-reactroot",
        "next-route-announcer",
        "_next/static",
        "hydrateRoot(",
        "Under construction",
        "Coming soon",
    ];

    for marker in forbidden {
        assert!(
            !html.contains(marker),
            "{} still contains unmigrated marker {:?}",
            label,
            marker
        );
    }
}

fn assert_no_mollie_browser_embed(label: &str, html: &str) {
    // Mollie's checkout is a server-created redirect (the `_links.checkout`
    // URL). No rendered ApexMail page embeds a Mollie script, posts to a
    // browser checkout API, or exposes the webhook endpoint.
    let forbidden = [
        "js.mollie.com",
        "mollie.com/checkout/select-method",
        "/api/billing/checkout",
        "/api/checkout/create",
        "/webhooks/mollie",
    ];

    for marker in forbidden {
        assert!(
            !html.contains(marker),
            "{} should not embed Mollie browser integration marker {:?}",
            label,
            marker
        );
    }
}

fn assert_surface_wrapper(route: &ssr::SsrRoute, html: &str) {
    match route.surface {
        "web" => {
            // Batch-2 titles fix: the document title is "{Page} | ApexMail"
            // per route, no longer the hardcoded "ApexMail".
            assert!(
                html.contains(&format!(
                    "<title>{}</title>",
                    crate::axum_router::route_document_title("web", route.pattern)
                )),
                "[web] {} missing per-page web title",
                route.pattern
            );
            assert!(
                html.contains(&format!(
                    "<html lang=\"en\" class=\"{}\">",
                    leptos_views::WEB_ROOT_HTML_CLASSES
                )),
                "[web] {} missing web html font classes",
                route.pattern
            );
            // Batch-2 single-main fix: the former root-layout landmark's
            // background styling moved onto the <body>.
            assert!(
                html.contains(&format!(
                    "<body class=\"{} min-h-screen\">",
                    leptos_views::WEB_ROOT_BODY_CLASSES
                )),
                "[web] {} missing web body class",
                route.pattern
            );
            // The single landmark's id may sit anywhere in the opening tag
            // (dashboard shell emits class first).
            assert!(
                html.contains("<main") && html.contains("id=\"app-main\""),
                "[web] {} missing web main wrapper",
                route.pattern
            );
            assert!(
                !html.contains("data-marketing-shell=\"footer\""),
                "[web] {} leaked marketing shell",
                route.pattern
            );
            assert!(
                !html.contains("ApexMail Control Plane</title>"),
                "[web] {} leaked control-plane shell",
                route.pattern
            );

            if route.auth_required {
                assert!(
                    html.contains("data-sidebar-storage-key=\"apexmail-ui\""),
                    "[web] {} should include dashboard shell",
                    route.pattern
                );
            } else {
                assert!(
                    !html.contains("data-sidebar-storage-key=\"apexmail-ui\""),
                    "[web] {} should not include dashboard shell",
                    route.pattern
                );
            }
        }
        "control-plane" => {
            // Batch-2 titles fix: the CP document title follows the route
            // context ("Page | ApexMail").
            assert!(
                html.contains(&format!(
                    "<title>{}</title>",
                    crate::axum_router::route_document_title("control-plane", route.pattern)
                )),
                "[control-plane] {} missing per-page control-plane title",
                route.pattern
            );
            assert!(
                html.contains("<body class=\"\">"),
                "[control-plane] {} missing control-plane body classes",
                route.pattern
            );
            assert!(
                !html.contains("data-marketing-shell=\"footer\""),
                "[control-plane] {} leaked marketing shell",
                route.pattern
            );
            assert!(
                !html.contains("data-sidebar-storage-key=\"apexmail-ui\""),
                "[control-plane] {} leaked web dashboard shell",
                route.pattern
            );
        }
        "marketing" | "marketing-zola" => {
            assert!(
                html.contains("css/styles.css"),
                "[{}] {} missing marketing stylesheet",
                route.surface,
                route.pattern
            );
            // The Zola-built marketing footer opens with
            // `<footer aria-label="Site footer" class="...">`, so the class
            // attribute is inside the opening tag but does not directly follow
            // `<footer`. Verify a footer element whose opening tag carries a
            // class attribute.
            let footer_has_class = html.find("<footer ").is_some_and(|start| {
                html[start..]
                    .find('>')
                    .is_some_and(|end| html[start..start + end].contains("class="))
            });
            assert!(
                footer_has_class,
                "[{}] {} missing marketing footer",
                route.surface, route.pattern
            );
            assert!(
                !html.contains("data-sidebar-storage-key=\"apexmail-ui\""),
                "[{}] {} leaked web dashboard shell",
                route.surface,
                route.pattern
            );
            assert!(
                !html.contains("ApexMail Control Plane</title>"),
                "[{}] {} leaked control-plane shell",
                route.surface,
                route.pattern
            );
        }
        other => panic!("unknown surface {other}"),
    }
}

// ─── Route coverage tests ──────────────────────────────────

#[test]
fn migration_all_93_routes_have_view_functions() {
    let routes = rendered_routes();
    assert_eq!(
        routes.len(),
        routing::total_route_count(),
        "SSR route count drifted from manifest"
    );

    let mut missing = Vec::new();
    for route in &routes {
        if axum_router::render_route(route.surface, route.pattern).is_none() {
            missing.push(format!("[{}] {}", route.surface, route.pattern));
        }
    }
    assert!(
        missing.is_empty(),
        "MIGRATION INCOMPLETE: {} routes without view functions:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn migration_docs_define_rust_ui_and_current_mollie_boundary() {
    assert!(
        UI_RUST_MIGRATION_PLAN_JSON.contains("\"next\": \"axum-plus-leptos-router\""),
        "migration plan no longer requires axum + Leptos router replacement"
    );
    assert!(
        UI_RUST_MIGRATION_PLAN_JSON.contains("\"react\": \"remove-from-browser-ui-paths\""),
        "migration plan no longer requires removing React from browser UI paths"
    );
    assert!(
        UI_RUST_MIGRATION_PLAN_JSON.contains("\"radix\": \"replace-with-rust-native-primitives\""),
        "migration plan no longer requires Rust-native primitive replacement"
    );
    // The boundary is server-side: Mollie's webhook carries only an object
    // id, so verification is an authenticated fetch, not a body signature.
    assert!(
        MOLLIE_TOOL_CONTRACT_MD.contains("ApexMail") && MOLLIE_TOOL_CONTRACT_MD.contains("Mollie"),
        "Mollie tool contract no longer documents the ApexMail/Mollie boundary"
    );
    assert!(
        MOLLIE_TOOL_CONTRACT_MD.contains("/webhooks/mollie"),
        "Mollie tool contract no longer documents the webhook endpoint"
    );
    assert!(
        MOLLIE_TOOL_CONTRACT_MD.contains("Bearer")
            && MOLLIE_TOOL_CONTRACT_MD.contains("v2/payments"),
        "Mollie tool contract no longer documents fetch-verify with the Bearer key"
    );
    // The pre-cutover wire vocabulary has no Mollie analog: a contract that
    // still names it documents a protocol Mollie does not speak.
    for banned in [
        "hmacSignature",
        "notificationItems",
        "NotificationRequestItem",
        "pspReference",
        "[accepted]",
        "resultCode",
        "X-API-Key",
    ] {
        assert!(
            !MOLLIE_TOOL_CONTRACT_MD.contains(banned),
            "Mollie tool contract still carries the pre-cutover wire token {banned:?}"
        );
    }
}

#[test]
fn migration_269_renames_the_billing_schema_to_mollie() {
    // Migration 269 is the schema half of the processor switch: every
    // renamed table/column the code reads must be named there.
    for table in [
        "mollie_customers",
        "mollie_subscriptions",
        "mollie_tax_snapshots",
        "mollie_webhook_events",
        "mollie_refunds",
    ] {
        assert!(
            MOLLIE_BILLING_RENAMES_SQL.contains(table),
            "migration 269 does not create/rename {table}"
        );
    }
    // The renames the runtime SQL depends on.
    for (old_column, new_column) in [
        ("adyen_shopper_reference", "mollie_customer_id"),
        ("adyen_subscription_id", "mollie_subscription_id"),
        ("adyen_plan_code", "mollie_plan_code"),
        ("adyen_psp_reference", "mollie_payment_id"),
        ("adyen_notification_id", "mollie_event_id"),
        ("adyen_recurring_detail_reference", "mollie_mandate_id"),
        ("adyen_recurring_processing_model", "mollie_sequence_type"),
    ] {
        assert!(
            MOLLIE_BILLING_RENAMES_SQL.contains(old_column)
                && MOLLIE_BILLING_RENAMES_SQL.contains(new_column),
            "migration 269 does not rename {old_column} -> {new_column}"
        );
    }
    // The refund mapping is the only way a refund webhook (which names just
    // `re_…`) can be resolved to its payment.
    assert!(
        MOLLIE_BILLING_RENAMES_SQL.contains("CREATE TABLE IF NOT EXISTS mollie_refunds")
            && MOLLIE_BILLING_RENAMES_SQL.contains("payment_id"),
        "migration 269 does not create the refund -> payment mapping"
    );
    // The migration itself proves no schema object keeps the old processor
    // name (tables and columns), and refuses to complete otherwise.
    assert!(
        MOLLIE_BILLING_RENAMES_SQL.contains("RAISE EXCEPTION")
            && MOLLIE_BILLING_RENAMES_SQL.contains("column_name ILIKE '%adyen%'")
            && MOLLIE_BILLING_RENAMES_SQL.contains("table_name ILIKE '%adyen%'"),
        "migration 269 no longer asserts that no adyen-named schema object remains"
    );
    // ...and the proof covers indexes, constraints, functions and triggers.
    for proof in [
        "indexname ILIKE '%adyen%'",
        "conname ILIKE '%adyen%'",
        "pg_get_constraintdef(oid) ILIKE '%adyen%'",
        "proname ILIKE '%adyen%'",
        "tgname ILIKE '%adyen%'",
    ] {
        assert!(
            MOLLIE_BILLING_RENAMES_SQL.contains(proof),
            "migration 269's proof block no longer checks {proof:?}"
        );
    }

    // Triggers and the immutability function carry the processor name.
    for (old, new) in [
        (
            "trg_adyen_shoppers_updated_at",
            "trg_mollie_customers_updated_at",
        ),
        (
            "trg_adyen_subscriptions_updated_at",
            "trg_mollie_subscriptions_updated_at",
        ),
        (
            "trg_adyen_webhook_events_updated_at",
            "trg_mollie_webhook_events_updated_at",
        ),
        (
            "trg_adyen_tax_snapshots_immutable",
            "trg_mollie_tax_snapshots_immutable",
        ),
        (
            "prevent_adyen_tax_snapshot_mutation",
            "prevent_mollie_tax_snapshot_mutation",
        ),
    ] {
        assert!(
            MOLLIE_BILLING_RENAMES_SQL.contains(old) && MOLLIE_BILLING_RENAMES_SQL.contains(new),
            "migration 269 does not rename {old} -> {new}"
        );
    }
    // The replacement tax-snapshot guard reads the renamed column.
    assert!(
        MOLLIE_BILLING_RENAMES_SQL.contains("OLD.mollie_payment_id"),
        "the Mollie tax-snapshot guard must read the renamed payment column"
    );

    // CHECK allowlists must accept the values the Rust code writes, or the
    // schema rejects Mollie's own bookkeeping at insert time.
    for allowed in [
        "'mollie'",
        "'mollie_settlement'",
        "'mollie_clearing'",
        "'mollie_fees'",
    ] {
        assert!(
            MOLLIE_BILLING_RENAMES_SQL.contains(allowed),
            "migration 269 does not widen a CHECK allowlist to {allowed}"
        );
    }

    // Immediate cancellation revokes the mandate at Mollie; the column is
    // the durable evidence and the retry signal for the sweep.
    assert!(
        MOLLIE_BILLING_RENAMES_SQL.contains("mandate_revoked_at TIMESTAMPTZ"),
        "migration 269 does not add mollie_customers.mandate_revoked_at"
    );
    assert!(
        MOLLIE_BILLING_RENAMES_SQL.contains("idx_mollie_refunds_payment")
            && MOLLIE_BILLING_RENAMES_SQL.contains("idx_mollie_refunds_tenant"),
        "migration 269 does not index the refund mapping both ways"
    );
}

#[test]
fn migration_every_surface_fully_covered() {
    for surface in routing::surface_ids() {
        let routes = routing::surface_routes(surface);
        assert!(!routes.is_empty(), "surface {} has no routes", surface);

        let mut missing = Vec::new();
        for sr in &routes {
            if axum_router::render_route(surface, sr.path).is_none() {
                missing.push(sr.path.to_string());
            }
        }
        assert!(
            missing.is_empty(),
            "MIGRATION INCOMPLETE for surface '{}': {} missing pages:\n  {}",
            surface,
            missing.len(),
            missing.join("\n  ")
        );
    }
}

// ─── Primitive usage tests ──────────────────────────────────

#[test]
fn migration_primitives_render_valid_html() {
    // Every primitive struct must produce valid HTML
    let btn = primitives::Button {
        variant: "default",
        size: "default",
        label: "Test",
        disabled: false,
        loading: false,
        left_icon: None,
        right_icon: None,
        submit: true,
    };
    let html = btn.render_html();
    assert!(html.contains("<button"), "Button missing <button> tag");
    assert!(html.contains("Test"), "Button missing label");

    let card = primitives::Card {
        title: "Title",
        body: "Body",
        variant: "default",
        padding: "default",
        interactive: false,
    };
    let html = card.render_html();
    assert!(html.contains("Title"), "Card missing title");
    assert!(html.contains("Body"), "Card missing body");

    let table = primitives::Table {
        caption: Some("Cap"),
        columns: vec![primitives::TableColumn {
            label: "Col",
            align: "left",
        }],
        rows: vec![],
    };
    let html = table.render_html();
    assert!(html.contains("<table"), "Table missing <table> tag");
    assert!(html.contains("Col"), "Table missing column label");

    let input = primitives::Input {
        id: None,
        input_type: "text",
        variant: "default",
        size: "default",
        placeholder: "test",
        value: "",
        left_icon: None,
        right_icon: None,
        error: None,
        disabled: false,
        autocomplete: None,
        required: false,
        name: None,
    };
    let html = input.render_html();
    assert!(html.contains("<input"), "Input missing <input> tag");
}

// ─── DOM contract tests ────────────────────────────────────

#[test]
fn migration_login_pages_preserve_field_ids() {
    let web = leptos_views::web_login_page("");
    let ids = ["id=\"login-email\"", "id=\"password\""];
    for id in &ids {
        assert!(web.contains(id), "web login missing {}", id);
    }

    let cp = leptos_views::control_plane_login_page("");
    let cp_ids = ["id=\"login-email\"", "id=\"login-password\""];
    for id in &cp_ids {
        assert!(cp.contains(id), "control-plane login missing {}", id);
    }
}

#[test]
fn migration_forms_have_action_attributes() {
    let login = leptos_views::web_login_page("");
    assert!(
        login.contains("action=\"/web/auth/login\""),
        "login missing action"
    );

    let signup = leptos_views::web_signup_page("");
    assert!(
        signup.contains("action=\"/web/auth/signup\""),
        "signup missing action"
    );

    let forgot = leptos_views::web_forgot_password_page("");
    assert!(
        forgot.contains("action=\"/web/auth/forgot-password\""),
        "forgot missing action"
    );

    let reset = leptos_views::web_reset_password_page();
    assert!(
        reset.contains("action=\"/web/auth/reset-password\""),
        "reset missing action"
    );

    let cp_login = leptos_views::control_plane_login_page("");
    assert!(
        cp_login.contains("action=\"/web/cp/login\""),
        "cp login missing action"
    );
}

#[test]
fn migration_security_data_attributes_present() {
    let login = leptos_views::web_login_page("");
    // Dead JS-era markup purge: the hidden rate-limit slot no longer ships
    // (errors arrive via the signed flash cookie rendered server-side).
    assert!(
        !login.contains("data-error-key"),
        "JS-era rate limiting data attribute must not ship"
    );

    // MFA input attributes live on the server-rendered challenge page
    // (/login?mfa=1), not on the password step's JS-era hidden div.
    let challenge = leptos_views::web_login_mfa_challenge_page("", "ops@apexmail.ee", "/dashboard");
    let mfa_input =
        challenge.contains("inputmode=\"numeric\"") && challenge.contains("maxlength=\"6\"");
    assert!(mfa_input, "MFA input attributes missing");
}

#[test]
fn migration_sidebar_data_attributes_present() {
    let html = leptos_views::web_dashboard_layout("<div></div>", "");
    assert!(
        html.contains("data-sidebar-storage-key=\"apexmail-ui\""),
        "sidebar key missing"
    );
    // Dead JS-era markup purge: the toast store markup is gone.
    assert!(
        !html.contains("data-toast-store"),
        "toast store must not ship"
    );
    assert!(
        html.contains("aria-label=\"Primary sidebar navigation\""),
        "sidebar aria missing"
    );
}

#[test]
fn migration_marketing_shell_attributes_present() {
    let html = leptos_views::marketing_page("<div></div>");
    assert!(
        html.contains("data-marketing-shell=\"footer\""),
        "marketing footer missing"
    );
    // ARK: the marketing fallback shell composes the authority's vocabulary
    // (the type position lives in ark.css, never as a per-page font class).
    assert!(
        html.contains("apex-"),
        "ark vocabulary missing from the marketing shell"
    );
    assert!(
        !html.contains("font-apex"),
        "per-page font classes are banned (ark.css owns type)"
    );
}

#[test]
fn migration_all_rendered_routes_use_only_expected_surface_wrappers() {
    for route in rendered_routes() {
        let html = render_or_panic(&route);
        assert_surface_wrapper(&route, &html);
    }
}

#[test]
fn migration_all_rendered_routes_are_free_of_unmigrated_runtime_markers() {
    for route in rendered_routes() {
        let label = format!("[{}] {}", route.surface, route.pattern);
        let html = render_or_panic(&route);
        assert_no_unmigrated_markers(&label, &html);
    }
}

#[test]
fn migration_ui_routes_do_not_embed_mollie_browser_flow() {
    for route in rendered_routes() {
        let label = format!("[{}] {}", route.surface, route.pattern);
        let html = render_or_panic(&route);
        assert_no_mollie_browser_embed(&label, &html);
    }
}

// ─── Content completeness tests ─────────────────────────────

#[test]
fn migration_web_pages_have_page_titles() {
    let pages_and_titles: Vec<(&str, &str)> = vec![
        ("dashboard", "Dashboard"),
        ("campaigns", "Campaigns"),
        ("contacts", "Contacts"),
        ("lists", "Lists"),
        ("templates", "Templates"),
        ("reports", "Reports"),
        ("analytics", "Analytics"),
        ("events", "Events"),
        ("domains", "Domains"),
        ("settings", "Settings"),
    ];

    for (name, title) in &pages_and_titles {
        let html = axum_router::render_route("web", &format!("/{}", name))
            .or_else(|| axum_router::render_route("web", name))
            .unwrap_or_else(|| panic!("web/{} route missing", name));
        assert!(
            html.contains(&format!(">{}<", title)),
            "web/{} missing page title '{}'",
            name,
            title
        );
    }
}

#[test]
fn migration_control_plane_pages_have_titles() {
    let pages_and_titles: Vec<(&str, &str)> = vec![
        ("dashboard", "Dashboard"),
        ("tenants", "Tenants"),
        ("sales", "Sales Autopilot"),
        ("operators", "Operators"),
        ("analytics", "Analytics"),
        ("discovery", "Lead Sources"),
        ("jobs", "Jobs"),
        ("infrastructure", "Infrastructure"),
        ("domains", "Domains"),
        ("billing", "Billing"),
        ("compliance", "Compliance"),
        ("alerts", "Alerts"),
        ("settings", "Settings"),
        ("audit", "Audit Logs"),
    ];

    for (name, title) in &pages_and_titles {
        let html = axum_router::render_route("control-plane", &format!("/{}", name))
            .unwrap_or_else(|| panic!("cp/{} route missing", name));
        assert!(
            html.contains(title),
            "cp/{} missing title '{}'",
            name,
            title
        );
    }
}

#[test]
fn migration_marketing_pages_have_content() {
    // ARK copy round: the home hero states the product and where it runs
    // (no slogan), and every marketing surface keeps a distinctive keyword so
    // a build that drops a page fails loudly.
    let pages: Vec<(&str, &str)> = vec![
        ("/", "Email infrastructure for developers"),
        ("/pricing", "pricing"),
        ("/features", "Features"),
        ("/compliance", "Compliance"),
        ("/private-cloud", "Private Cloud"),
        ("/status", "System Status"),
        ("/eu-sovereign", "EU-only routing"),
    ];

    for (path, keyword) in &pages {
        let html = axum_router::render_route("marketing", path)
            .unwrap_or_else(|| panic!("marketing {} route missing", path));
        assert!(
            html.contains(keyword),
            "marketing {} missing keyword '{}'",
            path,
            keyword
        );
    }
}

#[test]
fn migration_unknown_routes_are_rejected_for_every_surface() {
    let unknown = [
        "/definitely-missing",
        "/billing/checkout",
        "/webhooks/mollie",
        "/_next/static/app.js",
    ];
    let surfaces = ["web", "control-plane", "marketing", "marketing-zola"];

    for surface in surfaces {
        for path in unknown {
            assert!(
                axum_router::render_route(surface, path).is_none(),
                "{} unexpectedly rendered unknown path {}",
                surface,
                path
            );
        }
    }
}

// ─── Cross-surface consistency tests ───────────────────────

#[test]
fn migration_web_and_cp_share_primitives() {
    let web_login = leptos_views::web_login_page("");
    let cp_login = leptos_views::control_plane_login_page("");

    // Both compose the same button primitive (ARK: apex-btn, radius 0).
    let btn_class = "apex-btn";
    assert!(
        web_login.contains(btn_class),
        "web login missing common button class"
    );
    assert!(
        cp_login.contains(btn_class),
        "cp login missing common button class"
    );

    // Both compose the shared input primitive (ARK: apex-input, 1px ink
    // rule, radius 0, the global 3px double focus outline).
    let input_class = "apex-input";
    assert!(
        web_login.contains(input_class),
        "web login missing common input class"
    );
    assert!(
        cp_login.contains(input_class),
        "cp login missing common input class"
    );
}

// ─── Rendering determinism (pixel parity prerequisite) ─────

#[test]
fn migration_rendering_is_deterministic() {
    // Same function called twice must produce identical output
    let surfaces_and_paths: Vec<(&str, &str)> = vec![
        ("web", "/"),
        ("web", "/login"),
        ("web", "/dashboard"),
        ("web", "/campaigns"),
        ("control-plane", "/dashboard"),
        ("control-plane", "/login"),
        ("marketing", "/"),
        ("marketing", "/pricing"),
    ];

    for (surface, path) in &surfaces_and_paths {
        let html1 = axum_router::render_route(surface, path).unwrap();
        let html2 = axum_router::render_route(surface, path).unwrap();
        assert_eq!(
            html1, html2,
            "[{}] {} is non-deterministic: output differs between calls",
            surface, path
        );
    }
}

#[test]
fn migration_pixel_parity_self_check() {
    // When comparing a page's HTML against itself, parity must be perfect.
    // This validates the parity framework works correctly.
    let test_pages: Vec<(&str, &str)> = vec![
        ("web", "/"),
        ("web", "/login"),
        ("web", "/dashboard"),
        ("control-plane", "/dashboard"),
        ("marketing", "/pricing"),
    ];

    for (surface, path) in &test_pages {
        let html = axum_router::render_route(surface, path).unwrap();
        let result = pixel_parity::check_parity(&html, &html);
        assert!(
            result.is_identical,
            "[{}] {} self-parity check failed:\n{}",
            surface,
            path,
            result.report()
        );
    }
}

#[test]
fn migration_pixel_parity_detects_adversarial_mutations() {
    let cases = [
        ("web", "/login", "ApexMail", "ApexXMail"),
        ("control-plane", "/dashboard", "Dashboard", "DashboardX"),
        ("marketing", "/pricing", "Start Free", "Start Paid"),
    ];

    for (surface, path, original, mutated) in cases {
        let html = axum_router::render_route(surface, path).unwrap();
        let tampered = html.replacen(original, mutated, 1);
        assert_ne!(
            tampered, html,
            "[{}] {} mutation fixture drifted: {:?} not found",
            surface, path, original
        );
        let result = pixel_parity::check_parity(&html, &tampered);
        assert!(
            !result.is_identical,
            "[{}] {} parity engine failed to detect text mutation",
            surface, path
        );
        assert!(
            result.total_diffs() > 0,
            "[{}] {} mutation produced no parity diffs",
            surface,
            path
        );
    }
}

// ─── CSS class preservation tests ──────────────────────────

#[test]
fn migration_critical_css_classes_preserved() {
    let web_home = leptos_views::web_home_page();
    let classes = pixel_parity::extract_classes(&web_home);
    let flat: Vec<&String> = classes.iter().flat_map(|c| c.iter()).collect();

    // Essential structure (ARK): the viewport shell, the page band and the
    // button primitive, and NO typography/colour utilities (the authority
    // owns every design decision; cssgen cannot compile them).
    let required = ["min-h-screen", "apex-page-title", "apex-btn"];
    for cls in &required {
        assert!(
            flat.iter().any(|c| c.as_str() == *cls),
            "web home page missing structural class '{}'",
            cls
        );
    }
    for banned in [
        "text-5xl",
        "font-bold",
        "bg-surface-50",
        "rounded-[the-old-arch]",
    ] {
        assert!(
            !flat.iter().any(|c| c.as_str() == banned),
            "web home page still carries the design utility '{}'",
            banned
        );
    }
}

#[test]
fn migration_dashboard_layout_css_classes_preserved() {
    let html = leptos_views::web_dashboard_layout("<div></div>", "");

    // Sidebar uses data attributes, not CSS classes
    assert!(
        html.contains("data-sidebar-storage-key"),
        "dashboard layout missing sidebar data attribute"
    );
    // Verify Tailwind utility classes are present
    let classes = pixel_parity::extract_classes(&html);
    let flat: Vec<&String> = classes.iter().flat_map(|c| c.iter()).collect();
    assert!(
        flat.iter()
            .any(|c| c.contains("flex") || c.contains("grid")),
        "dashboard layout missing layout CSS classes"
    );
}

// ─── Navigation link integrity tests ───────────────────────

#[test]
fn migration_settings_links_are_valid_routes() {
    let html = leptos_views::web_settings_page();
    let links = [
        "/settings/api-keys",
        "/settings/team",
        "/settings/billing",
        "/settings/dedicated-ips",
        "/settings/webhooks",
        "/settings/profile",
    ];
    for link in &links {
        assert!(html.contains(link), "settings missing link to {}", link);
        // Each linked page must exist as a renderable route
        assert!(
            axum_router::render_route("web", link).is_some(),
            "settings links to {} but no view function exists",
            link
        );
    }
}

#[test]
fn migration_cp_infrastructure_links_are_valid() {
    let html = leptos_views::control_plane_infrastructure_page();
    let links = ["/infrastructure/nodes", "/infrastructure/queues"];
    for link in &links {
        assert!(html.contains(link), "infra missing link to {}", link);
        assert!(
            axum_router::render_route("control-plane", link).is_some(),
            "infra links to {} but no view function exists",
            link
        );
    }
}

// ─── Auth requirement tests ────────────────────────────────

#[test]
fn migration_auth_requirements_match_manifest() {
    let routes = ssr::ssr_routes();

    // Public pages that should NOT require auth
    let public_paths = [
        "/",
        "/login",
        "/signup",
        "/forgot-password",
        "/reset-password",
        "/verify-email",
    ];
    for route in routes.iter().filter(|r| r.surface == "web") {
        if public_paths.contains(&route.pattern) {
            assert!(
                !route.auth_required,
                "web {} should be public",
                route.pattern
            );
        }
    }

    // Marketing pages should never require auth
    for route in routes
        .iter()
        .filter(|r| r.surface == "marketing" || r.surface == "marketing-zola")
    {
        assert!(
            !route.auth_required,
            "marketing {} should not require auth",
            route.pattern
        );
    }
}

// ─── Full HTML validity tests ──────────────────────────────

fn has_html_doctype(html: &str) -> bool {
    html.trim_start()
        .get(..15)
        .map(|prefix| prefix.eq_ignore_ascii_case("<!DOCTYPE html>"))
        .unwrap_or(false)
}

#[test]
fn migration_all_rendered_pages_have_valid_html_structure() {
    let routes = rendered_routes();

    for route in &routes {
        let html = axum_router::render_route(route.surface, route.pattern)
            .unwrap_or_else(|| panic!("[{}] {} has no renderer", route.surface, route.pattern));

        assert!(
            has_html_doctype(&html),
            "[{}] {} missing DOCTYPE",
            route.surface,
            route.pattern
        );
        assert!(
            html.contains("<html"),
            "[{}] {} missing <html>",
            route.surface,
            route.pattern
        );
        assert!(
            html.contains("</html>"),
            "[{}] {} missing </html>",
            route.surface,
            route.pattern
        );
        assert!(
            html.contains("<head>") || html.contains("<head "),
            "[{}] {} missing <head>",
            route.surface,
            route.pattern
        );
        assert!(
            html.contains("<body"),
            "[{}] {} missing <body>",
            route.surface,
            route.pattern
        );
    }
}

#[test]
fn migration_total_route_count() {
    let routes = rendered_routes();
    let web = routes.iter().filter(|r| r.surface == "web").count();
    let cp = routes
        .iter()
        .filter(|r| r.surface == "control-plane")
        .count();
    let mkt = routes.iter().filter(|r| r.surface == "marketing").count();
    let zola = routes
        .iter()
        .filter(|r| r.surface == "marketing-zola")
        .count();

    assert_eq!(
        web,
        routing::declared_route_count("web").unwrap(),
        "web route count drifted"
    );
    assert_eq!(
        cp,
        routing::declared_route_count("control-plane").unwrap(),
        "control-plane route count drifted"
    );
    assert_eq!(
        mkt,
        routing::declared_route_count("marketing").unwrap(),
        "marketing route count drifted"
    );
    assert_eq!(
        zola,
        routing::declared_route_count("marketing-zola").unwrap(),
        "marketing-zola route count drifted"
    );
    assert_eq!(
        routes.len(),
        routing::total_route_count(),
        "total route count drifted"
    );
}

/// The four visual-parity pages still RENDER (non-empty documents with
/// their shell anchors).
///
/// This test used to WRITE the renders to a machine-specific absolute path
/// (`/Users/.../reports/visual-parity/current_html`) on every normal test
/// run, an unconditional side effect whose output silently rotted, and a
/// path that cannot exist on any other checkout. File output is the explicit
/// exporter's job (`export_visual_fixtures`, or the browser suite's
/// screenshots); the parity ASSERTION stays here.
#[test]
fn visual_parity_pages_render() {
    for (surface, path) in [
        ("web", "/login"),
        ("web", "/dashboard"),
        ("control-plane", "/login"),
        ("control-plane", "/dashboard"),
    ] {
        let html = crate::axum_router::render_route(surface, path)
            .unwrap_or_else(|| panic!("[{surface}] {path} must render"));
        assert!(
            html.contains("<html lang=\"en\""),
            "[{surface}] {path} must render a full document",
        );
        assert!(
            crate::gate_support::opening_tags(&html, "main").len() == 1,
            "[{surface}] {path} must render exactly one main landmark",
        );
    }
}
