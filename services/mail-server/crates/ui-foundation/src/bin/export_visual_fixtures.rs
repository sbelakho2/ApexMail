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
        let html = axum_router::render_route(surface, route)
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
        let html = axum_router::render_route(surface, route)
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
            let html = axum_router::render_route(surface, route.path)
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

    fs::create_dir_all(&out_dir)?;
    export_fixture_assets(&out_dir)?;

    let mut manifest = FixtureManifest {
        fixtures: Vec::new(),
    };

    if std::env::var("APEX_EXPORT_ALL_UI_ROUTES").as_deref() == Ok("1") {
        export_full_route_fixtures(&out_dir, &mut manifest)?;
    } else {
        export_auth_fixtures(&out_dir, &mut manifest)?;
        export_marketing_fixtures(&out_dir, &mut manifest)?;
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
