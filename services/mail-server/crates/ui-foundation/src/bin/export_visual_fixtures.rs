use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use ui_foundation::axum_router;

#[derive(Clone, Copy, Serialize)]
struct Viewport {
    width: u32,
    height: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifestEntry {
    id: String,
    surface: &'static str,
    route: &'static str,
    html_file: String,
    snapshot_file: String,
    viewport: Viewport,
}

#[derive(Serialize)]
struct FixtureManifest {
    fixtures: Vec<FixtureManifestEntry>,
}

const AUTH_FIXTURES: [(&str, &str, &str); 3] = [
    ("web-login", "web", "/login"),
    ("web-signup", "web", "/signup"),
    ("web-forgot-password", "web", "/forgot-password"),
];

const MARKETING_FIXTURES: [(&str, &str); 19] = [
    ("marketing", "/"),
    ("marketing", "/acceptable-use"),
    ("marketing", "/api-console"),
    ("marketing-zola", "/compare"),
    ("marketing", "/compare/postmark"),
    ("marketing", "/compare/resend"),
    ("marketing", "/compare/sendgrid"),
    ("marketing", "/compliance"),
    ("marketing", "/cookies"),
    ("marketing", "/dpa"),
    ("marketing", "/features"),
    ("marketing", "/email-logs"),
    ("marketing", "/pricing"),
    ("marketing", "/pricing/calculator"),
    ("marketing", "/privacy"),
    ("marketing", "/private-cloud"),
    ("marketing", "/sla"),
    ("marketing", "/status"),
    ("marketing", "/terms"),
];

const MARKETING_VIEWPORTS: [(&str, Viewport); 2] = [
    (
        "desktop",
        Viewport {
            width: 1440,
            height: 900,
        },
    ),
    (
        "mobile",
        Viewport {
            width: 375,
            height: 812,
        },
    ),
];

const FULL_ROUTE_VIEWPORTS: [(&str, Viewport); 2] = [
    (
        "desktop",
        Viewport {
            width: 1440,
            height: 900,
        },
    ),
    (
        "mobile",
        Viewport {
            width: 390,
            height: 844,
        },
    ),
];

const DEFAULT_MARKETING_PUBLIC_DIR: &str = "apps/marketing-zola/public";

fn route_file_stem(route: &str) -> String {
    if route == "/" {
        return "home".to_string();
    }

    route.trim_start_matches('/').replace('/', "-")
}

/// Fixed CSRF secret for the exported fixtures (batch-2 form-hygiene
/// triage): the full-route export previously rendered with NO secret, so
/// every POST form shipped without its `name="_csrf"` input and the
/// form-hygiene gate counted those artifacts as missing-csrf findings.
/// Production always renders with a secret; fixtures must represent
/// production. The fixed value keeps exports deterministic.
const FIXTURE_CSRF_SECRET: &str = "ui-foundation-fixture-secret-0123456789abcdef";

fn render_fixture_route(surface: &str, route: &str) -> Option<String> {
    axum_router::render_route_with_query(surface, route, None, Some(FIXTURE_CSRF_SECRET))
}

fn auth_html_file(id: &str) -> String {
    format!("{id}.html")
}

fn marketing_html_file(surface: &str, route: &str) -> String {
    format!("{}-{}.html", surface, route_file_stem(route))
}

fn full_route_html_file(surface: &str, route: &str) -> String {
    format!("{}-{}.html", surface, route_file_stem(route))
}

fn marketing_public_dir() -> PathBuf {
    std::env::var("MARKETING_PUBLIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_MARKETING_PUBLIC_DIR))
}

fn normalize_fixture_html(html: &str) -> String {
    let mut normalized = html.to_string();
    for (from, to) in [
        (
            "href=\"/assets/globals.css\"",
            "href=\"assets/globals.css\"",
        ),
        ("href=/assets/globals.css", "href=assets/globals.css"),
        ("href=\"/css/", "href=\"css/"),
        ("href=/css/", "href=css/"),
        ("href=\"https://apexmail.ee/css/", "href=\"css/"),
        ("href=https://apexmail.ee/css/", "href=css/"),
        ("href=\"/giallo.css", "href=\"giallo.css"),
        ("href=/giallo.css", "href=giallo.css"),
        ("href=\"https://apexmail.ee/giallo.css", "href=\"giallo.css"),
        ("href=https://apexmail.ee/giallo.css", "href=giallo.css"),
        ("href=\"/fonts/", "href=\"fonts/"),
        ("href=/fonts/", "href=fonts/"),
        ("href=\"https://apexmail.ee/fonts/", "href=\"fonts/"),
        ("href=https://apexmail.ee/fonts/", "href=fonts/"),
        ("src=\"/images/", "src=\"images/"),
        ("src=/images/", "src=images/"),
        ("src=\"https://apexmail.ee/images/", "src=\"images/"),
        ("src=https://apexmail.ee/images/", "src=images/"),
        ("content=\"/images/", "content=\"images/"),
        ("href=\"/icon.svg\"", "href=\"icon.svg\""),
        ("href=/icon.svg", "href=icon.svg"),
        ("href=\"/manifest.json\"", "href=\"manifest.json\""),
        ("href=/manifest.json", "href=manifest.json"),
    ] {
        normalized = normalized.replace(from, to);
    }
    normalized
}

fn rewrite_fixture_css_urls(css: &str, asset_prefix: &str) -> String {
    let mut rewritten = css.to_string();
    for asset_dir in ["fonts", "images"] {
        for quote in ["'", "\""] {
            let from = format!("url({quote}/{asset_dir}/");
            let to = format!("url({quote}{asset_prefix}{asset_dir}/");
            rewritten = rewritten.replace(&from, &to);
        }
        let from = format!("url(/{asset_dir}/");
        let to = format!("url({asset_prefix}{asset_dir}/");
        rewritten = rewritten.replace(&from, &to);
    }
    rewritten
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !src.exists() {
        return Ok(());
    }

    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = dst.join(entry.file_name());

        if entry.file_type()?.is_dir() {
            copy_dir_all(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path)?;
        }
    }

    Ok(())
}

fn rewrite_css_files(css_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !css_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(css_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("css") {
            continue;
        }

        let css = fs::read_to_string(&path)?;
        fs::write(&path, rewrite_fixture_css_urls(&css, "../"))?;
    }

    Ok(())
}

fn export_fixture_assets(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let assets_dir = out_dir.join("assets");
    fs::create_dir_all(&assets_dir)?;
    fs::write(
        assets_dir.join("globals.css"),
        rewrite_fixture_css_urls(ui_foundation::GLOBALS_CSS, "../"),
    )?;

    let marketing_public_dir = marketing_public_dir();
    for asset_dir in ["css", "fonts", "images"] {
        copy_dir_all(
            &marketing_public_dir.join(asset_dir),
            &out_dir.join(asset_dir),
        )?;
    }

    for file_name in [
        "giallo.css",
        "icon.svg",
        "manifest.json",
        "robots.txt",
        "sitemap.xml",
    ] {
        let source = marketing_public_dir.join(file_name);
        if source.exists() {
            fs::copy(source, out_dir.join(file_name))?;
        }
    }

    rewrite_css_files(&out_dir.join("css"))?;

    Ok(())
}

fn write_fixture_html(
    out_dir: &Path,
    html_file: &str,
    html: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(out_dir.join(html_file), normalize_fixture_html(html))?;
    Ok(())
}

fn export_auth_fixtures(
    out_dir: &std::path::Path,
    manifest: &mut FixtureManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for (id, surface, route) in AUTH_FIXTURES {
        let html_file = auth_html_file(id);
        let html = render_fixture_route(surface, route)
            .unwrap_or_else(|| panic!("missing renderer for [{}] {}", surface, route));
        write_fixture_html(out_dir, &html_file, &html)?;

        manifest.fixtures.push(FixtureManifestEntry {
            id: id.to_string(),
            surface,
            route,
            html_file,
            snapshot_file: format!("{id}.png"),
            viewport: Viewport {
                width: 1280,
                height: 856,
            },
        });
    }

    Ok(())
}

fn export_marketing_fixtures(
    out_dir: &std::path::Path,
    manifest: &mut FixtureManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for (surface, route) in MARKETING_FIXTURES {
        let html_file = marketing_html_file(surface, route);
        let route_stem = route_file_stem(route);
        let html = render_fixture_route(surface, route)
            .unwrap_or_else(|| panic!("missing renderer for [{}] {}", surface, route));
        write_fixture_html(out_dir, &html_file, &html)?;

        for (viewport_name, viewport) in MARKETING_VIEWPORTS {
            manifest.fixtures.push(FixtureManifestEntry {
                id: format!("{}-{}-{}", surface, route_stem, viewport_name),
                surface,
                route,
                html_file: html_file.clone(),
                snapshot_file: format!("{}-{}.png", route_stem, viewport_name),
                viewport,
            });
        }
    }

    Ok(())
}

fn export_full_route_fixtures(
    out_dir: &std::path::Path,
    manifest: &mut FixtureManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for surface in ui_foundation::routing::surface_ids() {
        for route in ui_foundation::routing::surface_routes(surface) {
            let html_file = full_route_html_file(surface, route.path);
            let html = render_fixture_route(surface, route.path)
                .unwrap_or_else(|| panic!("missing renderer for [{}] {}", surface, route.path));
            write_fixture_html(out_dir, &html_file, &html)?;

            let route_stem = route_file_stem(route.path);
            for (viewport_name, viewport) in FULL_ROUTE_VIEWPORTS {
                let id = format!("{}-{}-{}", surface, route_stem, viewport_name);
                manifest.fixtures.push(FixtureManifestEntry {
                    id: id.clone(),
                    surface,
                    route: route.path,
                    html_file: html_file.clone(),
                    snapshot_file: format!("{id}.png"),
                    viewport,
                });
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::args() // nosemgrep: rust.lang.security.args.args — reads argv for flag detection / passes constant tool-side paths — no shell, no user-input interpolation
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("services/mail-server/crates/ui-foundation/baselines/rust-ui")
        });

    run(&out_dir)
}

/// Export every visual fixture (HTML, assets, manifest) into `out_dir`.
/// Split out of `main` so the whole pipeline is exercisable by tests with a
/// temporary directory and controlled env — including the
/// `APEX_EXPORT_ALL_UI_ROUTES` full-surface mode.
fn run(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(out_dir)?;
    export_fixture_assets(out_dir)?;

    let mut manifest = FixtureManifest {
        fixtures: Vec::new(),
    };

    if std::env::var("APEX_EXPORT_ALL_UI_ROUTES").as_deref() == Ok("1") {
        export_full_route_fixtures(out_dir, &mut manifest)?;
    } else {
        export_auth_fixtures(out_dir, &mut manifest)?;
        export_marketing_fixtures(out_dir, &mut manifest)?;
    }

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(out_dir.join("manifest.json"), manifest_json)?;

    tracing::info!(
        count = manifest.fixtures.len(),
        out_dir = %out_dir.display(),
        "Exported visual fixtures"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate process environment variables.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "export_fixtures_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // ── pure naming helpers ─────────────────────────────────────────────

    #[test]
    fn route_file_stem_flattens_routes() {
        assert_eq!(route_file_stem("/"), "home");
        assert_eq!(route_file_stem("/signup"), "signup");
        assert_eq!(route_file_stem("/pricing/calculator"), "pricing-calculator");
        assert_eq!(route_file_stem("/compare/postmark"), "compare-postmark");
    }

    #[test]
    fn html_file_names_are_surface_prefixed_and_stable() {
        assert_eq!(auth_html_file("web-login"), "web-login.html");
        assert_eq!(
            marketing_html_file("marketing", "/pricing"),
            "marketing-pricing.html"
        );
        assert_eq!(
            marketing_html_file("marketing", "/pricing/calculator"),
            "marketing-pricing-calculator.html"
        );
        assert_eq!(
            full_route_html_file("marketing-zola", "/compare"),
            "marketing-zola-compare.html"
        );
    }

    #[test]
    fn marketing_public_dir_defaults_and_overrides() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var("MARKETING_PUBLIC_DIR");
        assert_eq!(
            marketing_public_dir(),
            PathBuf::from(DEFAULT_MARKETING_PUBLIC_DIR)
        );
        std::env::set_var("MARKETING_PUBLIC_DIR", "/tmp/some-custom-public");
        assert_eq!(
            marketing_public_dir(),
            PathBuf::from("/tmp/some-custom-public")
        );
        std::env::remove_var("MARKETING_PUBLIC_DIR");
    }

    // ── normalization / rewriting ───────────────────────────────────────

    #[test]
    fn normalize_fixture_html_rewrites_every_asset_reference_class() {
        // Quoted, unquoted, and absolute-production variants must all end
        // up relative so the exported fixture renders from the filesystem.
        let cases = [
            (
                "href=\"/assets/globals.css\"",
                "href=\"assets/globals.css\"",
            ),
            ("href=/assets/globals.css", "href=assets/globals.css"),
            ("href=\"/css/site.css\"", "href=\"css/site.css\""),
            ("href=/css/site.css", "href=css/site.css"),
            (
                "href=\"https://apexmail.ee/css/site.css\"",
                "href=\"css/site.css\"",
            ),
            (
                "href=\"https://apexmail.ee/fonts/x.woff2\"",
                "href=\"fonts/x.woff2\"",
            ),
            ("href=\"/fonts/x.woff2\"", "href=\"fonts/x.woff2\""),
            ("src=\"/images/logo.png\"", "src=\"images/logo.png\""),
            (
                "src=\"https://apexmail.ee/images/logo.png\"",
                "src=\"images/logo.png\"",
            ),
            ("content=\"/images/og.png\"", "content=\"images/og.png\""),
            ("href=\"/icon.svg\"", "href=\"icon.svg\""),
            ("href=\"/manifest.json\"", "href=\"manifest.json\""),
        ];
        for (from, to) in cases {
            assert_eq!(
                normalize_fixture_html(from),
                to,
                "normalization broken for {from}"
            );
        }
        // Already-relative content passes through untouched.
        let untouched = "<html><body>rendered</body></html>";
        assert_eq!(normalize_fixture_html(untouched), untouched);
    }

    #[test]
    fn rewrite_fixture_css_urls_prefixes_asset_dirs_with_the_prefix() {
        let css = "a{background:url('/images/a.png')}\
                   b{background:url(\"/fonts/x.woff2\")}\
                   c{background:url(/images/c.png)}\
                   d{background:url('../already/relative.png')}";
        let rewritten = rewrite_fixture_css_urls(css, "../");
        assert!(rewritten.contains("url('../images/a.png')"), "{rewritten}");
        assert!(
            rewritten.contains("url(\"../fonts/x.woff2\")"),
            "{rewritten}"
        );
        assert!(rewritten.contains("url(../images/c.png)"), "{rewritten}");
        assert!(
            rewritten.contains("url('../already/relative.png')"),
            "already-relative urls must be untouched: {rewritten}"
        );
    }

    // ── filesystem helpers ──────────────────────────────────────────────

    #[test]
    fn copy_dir_all_copies_a_nested_tree_and_tolerates_a_missing_source() {
        let src = temp_dir("copy_src");
        let dst = temp_dir("copy_dst");
        std::fs::create_dir_all(src.join("fonts/deep")).expect("mkdir");
        std::fs::write(src.join("fonts/inter.woff2"), b"W2").expect("write");
        std::fs::write(src.join("fonts/deep/nested.css"), b"body{}").expect("write");

        // A missing source is a no-op, not an error.
        assert!(copy_dir_all(&src.join("does-not-exist"), &dst.join("x")).is_ok());

        copy_dir_all(&src, &dst).expect("copy");
        assert_eq!(
            std::fs::read(dst.join("fonts/inter.woff2")).expect("copied file"),
            b"W2"
        );
        assert_eq!(
            std::fs::read(dst.join("fonts/deep/nested.css")).expect("nested file"),
            b"body{}"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn rewrite_css_files_rewrites_only_css_and_tolerates_a_missing_dir() {
        let dir = temp_dir("css_rewrite");
        // Missing directory: no-op success.
        assert!(rewrite_css_files(&dir.join("absent")).is_ok());

        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("site.css"), "a{background:url('/images/a.png')}")
            .expect("write css");
        std::fs::write(dir.join("notes.txt"), "url('/images/keep.png')").expect("write txt");

        rewrite_css_files(&dir).expect("rewrite");
        let css = std::fs::read_to_string(dir.join("site.css")).expect("read css");
        assert!(css.contains("url('../images/a.png')"), "{css}");
        let txt = std::fs::read_to_string(dir.join("notes.txt")).expect("read txt");
        assert!(
            txt.contains("url('/images/keep.png')"),
            "non-css untouched: {txt}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_fixture_assets_writes_globals_and_copies_the_marketing_public_tree() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let public = temp_dir("public");
        let out = temp_dir("assets_out");
        for dir in ["css", "fonts", "images"] {
            std::fs::create_dir_all(public.join(dir)).expect("mkdir");
        }
        std::fs::write(
            public.join("css/site.css"),
            "a{background:url('/images/x.png')}",
        )
        .expect("write");
        std::fs::write(public.join("fonts/inter.woff2"), b"W2").expect("write");
        std::fs::write(public.join("images/logo.png"), b"PNG").expect("write");
        for file in [
            "giallo.css",
            "icon.svg",
            "manifest.json",
            "robots.txt",
            "sitemap.xml",
        ] {
            std::fs::write(public.join(file), format!("/* {file} */")).expect("write");
        }
        std::env::set_var("MARKETING_PUBLIC_DIR", &public);

        export_fixture_assets(&out).expect("export assets");

        // globals.css is generated from the crate's own stylesheet, with
        // asset urls rewritten relative to the fixture root.
        let globals = std::fs::read_to_string(out.join("assets/globals.css")).expect("globals");
        assert!(!globals.contains("href="), "globals.css is css, not html");
        // Top-level marketing files are copied when present.
        for file in [
            "giallo.css",
            "icon.svg",
            "manifest.json",
            "robots.txt",
            "sitemap.xml",
        ] {
            assert!(out.join(file).exists(), "{file} must be copied");
        }
        // Copied css was rewritten.
        let css = std::fs::read_to_string(out.join("css/site.css")).expect("copied css");
        assert!(css.contains("url('../images/x.png')"), "{css}");
        assert!(out.join("fonts/inter.woff2").exists());
        assert!(out.join("images/logo.png").exists());

        std::env::remove_var("MARKETING_PUBLIC_DIR");
        std::fs::remove_dir_all(&public).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    // ── export pipeline ─────────────────────────────────────────────────

    #[test]
    fn export_auth_fixtures_writes_three_pages_and_manifest_entries() {
        let out = temp_dir("auth_out");
        let mut manifest = FixtureManifest {
            fixtures: Vec::new(),
        };
        export_auth_fixtures(&out, &mut manifest).expect("auth fixtures");
        assert_eq!(manifest.fixtures.len(), AUTH_FIXTURES.len());
        for entry in &manifest.fixtures {
            assert!(entry.surface == "web", "surface: {}", entry.surface);
            assert_eq!(entry.viewport.width, 1280);
            assert_eq!(entry.viewport.height, 856);
            let html = std::fs::read_to_string(out.join(&entry.html_file))
                .expect("auth html must be written");
            assert!(!html.is_empty());
            assert!(
                !html.contains("href=\"/assets/"),
                "exported html must be normalized"
            );
            assert_eq!(entry.snapshot_file, format!("{}.png", entry.id));
        }
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn export_marketing_fixtures_writes_every_route_for_both_viewports() {
        let out = temp_dir("marketing_out");
        let mut manifest = FixtureManifest {
            fixtures: Vec::new(),
        };
        export_marketing_fixtures(&out, &mut manifest).expect("marketing fixtures");
        assert_eq!(
            manifest.fixtures.len(),
            MARKETING_FIXTURES.len() * MARKETING_VIEWPORTS.len(),
            "one entry per route × viewport"
        );
        let ids: std::collections::HashSet<String> =
            manifest.fixtures.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids.len(), manifest.fixtures.len(), "ids must be unique");
        for entry in &manifest.fixtures {
            assert!(
                out.join(&entry.html_file).exists(),
                "{} must be written",
                entry.html_file
            );
        }
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn run_exports_default_manifest_and_every_entry_has_a_html_file() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let public = temp_dir("run_public");
        std::fs::create_dir_all(public.join("css")).expect("mkdir");
        std::env::set_var("MARKETING_PUBLIC_DIR", &public);
        std::env::remove_var("APEX_EXPORT_ALL_UI_ROUTES");

        let out = temp_dir("run_out");
        run(&out).expect("run");

        // The manifest is consumed by the snapshot tooling, so its JSON shape
        // (fixtures[].{id,surface,route,htmlFile,snapshotFile,viewport}) is
        // asserted through serde_json::Value.
        let manifest_json = std::fs::read_to_string(out.join("manifest.json")).expect("manifest");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_json).expect("manifest json");
        let fixtures = manifest["fixtures"].as_array().expect("fixtures array");
        assert_eq!(
            fixtures.len(),
            AUTH_FIXTURES.len() + MARKETING_FIXTURES.len() * MARKETING_VIEWPORTS.len()
        );
        for entry in fixtures {
            assert!(entry["id"].is_string(), "{entry}");
            assert!(entry["surface"].is_string(), "{entry}");
            assert!(entry["route"].is_string(), "{entry}");
            let html_file = entry["htmlFile"].as_str().expect("htmlFile");
            assert!(out.join(html_file).exists(), "{html_file} must exist");
            assert!(entry["snapshotFile"].is_string(), "{entry}");
            assert!(entry["viewport"]["width"].is_u64(), "{entry}");
            assert!(entry["viewport"]["height"].is_u64(), "{entry}");
        }

        // Full-route mode exports at least the default set (every surface).
        std::env::set_var("APEX_EXPORT_ALL_UI_ROUTES", "1");
        let full_out = temp_dir("run_full_out");
        run(&full_out).expect("full run");
        let full_json = std::fs::read_to_string(full_out.join("manifest.json")).expect("manifest");
        let full: serde_json::Value = serde_json::from_str(&full_json).expect("manifest json");
        let full_fixtures = full["fixtures"].as_array().expect("fixtures array");
        assert!(
            full_fixtures.len() >= fixtures.len(),
            "full-route mode must cover at least the default set"
        );
        for entry in full_fixtures {
            let html_file = entry["htmlFile"].as_str().expect("htmlFile");
            assert!(full_out.join(html_file).exists(), "{html_file} must exist");
        }

        std::env::remove_var("MARKETING_PUBLIC_DIR");
        std::env::remove_var("APEX_EXPORT_ALL_UI_ROUTES");
        std::fs::remove_dir_all(&public).ok();
        std::fs::remove_dir_all(&out).ok();
        std::fs::remove_dir_all(&full_out).ok();
    }
}
