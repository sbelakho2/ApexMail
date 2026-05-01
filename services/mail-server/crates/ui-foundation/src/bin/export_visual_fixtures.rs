use std::fs;
use std::path::PathBuf;

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

const AUTH_FIXTURES: [(&str, &'static str, &'static str); 3] = [
    ("web-login", "web", "/login"),
    ("web-signup", "web", "/signup"),
    ("web-forgot-password", "web", "/forgot-password"),
];

const MARKETING_FIXTURES: [(&str, &str); 20] = [
    ("marketing", "/"),
    ("marketing", "/acceptable-use"),
    ("marketing", "/api-console"),
    ("marketing", "/case-studies"),
    ("marketing-zola", "/compare"),
    ("marketing", "/compare/postmark"),
    ("marketing", "/compare/resend"),
    ("marketing", "/compare/sendgrid"),
    ("marketing", "/compliance"),
    ("marketing", "/cookies"),
    ("marketing", "/dpa"),
    ("marketing", "/features"),
    ("marketing", "/forensic"),
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

fn export_auth_fixtures(
    out_dir: &PathBuf,
    manifest: &mut FixtureManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for (id, surface, route) in AUTH_FIXTURES {
        let html_file = auth_html_file(id);
        let html = axum_router::render_route(surface, route)
            .unwrap_or_else(|| panic!("missing renderer for [{}] {}", surface, route));
        fs::write(out_dir.join(&html_file), html)?;

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
    out_dir: &PathBuf,
    manifest: &mut FixtureManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for (surface, route) in MARKETING_FIXTURES {
        let html_file = marketing_html_file(surface, route);
        let route_stem = route_file_stem(route);
        let html = axum_router::render_route(surface, route)
            .unwrap_or_else(|| panic!("missing renderer for [{}] {}", surface, route));
        fs::write(out_dir.join(&html_file), html)?;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("services/mail-server/crates/ui-foundation/baselines/rust-ui")
        });

    fs::create_dir_all(&out_dir)?;

    let mut manifest = FixtureManifest {
        fixtures: Vec::new(),
    };

    export_auth_fixtures(&out_dir, &mut manifest)?;
    export_marketing_fixtures(&out_dir, &mut manifest)?;

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(out_dir.join("manifest.json"), manifest_json)?;

    println!(
        "exported {} visual fixtures to {}",
        manifest.fixtures.len(),
        out_dir.display()
    );

    Ok(())
}
