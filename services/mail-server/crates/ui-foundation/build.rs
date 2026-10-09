//! Build script: keep `cargo build -p ui-foundation` working on a fresh
//! checkout (pipeline finding F5).
//!
//! `src/axum_router.rs` embeds the Zola build output
//! (`apps/marketing-zola/public/**`) with 100+ `include_str!`s. That directory
//! is generated output and gitignored, so a bare clone cannot compile the
//! crate until the marketing site is built. Docker images always COPY a built
//! `public/` in, and the CI pipeline builds it before the test stage — but a
//! fresh `cargo build` must not depend on that.
//!
//! This script picks the directory the includes resolve against:
//!
//! * `apps/marketing-zola/public` when it exists (built site — production,
//!   Docker, dev after `make marketing`), embedding the real pages as before;
//! * otherwise a generated fallback tree under `OUT_DIR`, with one minimal
//!   placeholder page per included route, so the crate compiles from a bare
//!   clone. The fallback emits a `cargo:warning` pointing at the build
//!   command.
//!
//! The route list is derived from `src/axum_router.rs` itself (every
//! `env!("APX_MARKETING_PUBLIC_DIR")` include), so new routes cannot miss a
//! fallback. No source-tree files are written: the fallback lives in OUT_DIR.

use std::fs;
use std::path::PathBuf;

/// Marker the `include_str!` calls in `src/axum_router.rs` use for the
/// marketing public directory.
const ENV_NAME: &str = "APX_MARKETING_PUBLIC_DIR";

fn main() {
    // Declared so `cfg!(marketing_public_built)` in src/lib.rs does not warn
    // about an unexpected cfg name. The cfg itself is only set below when the
    // real Zola build output exists.
    println!("cargo::rustc-check-cfg=cfg(marketing_public_built)");
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is always set by cargo when running a build script"),
    );
    let router_src_path = manifest_dir.join("src/axum_router.rs");
    let router_src = fs::read_to_string(&router_src_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", router_src_path.display()));
    println!("cargo:rerun-if-changed={}", router_src_path.display());

    // Collect every include path relative to the marketing public dir.
    // The include sites look like concat!(env!("APX_MARKETING_PUBLIC_DIR"),
    // "/route/index.html"); rustfmt may lay the concat! arguments out across
    // lines, so after each env! marker we scan forward through whitespace and
    // punctuation to the next string literal instead of assuming adjacency.
    let marker = format!("env!(\"{ENV_NAME}\")");
    let mut relpaths: Vec<String> = Vec::new();
    let mut rest = router_src.as_str();
    while let Some(pos) = rest.find(&marker) {
        let after = &rest[pos + marker.len()..];
        let start = after.find('"').unwrap_or_else(|| {
            panic!("no include path string literal after {ENV_NAME} marker in axum_router.rs")
        });
        let path_part = &after[start + 1..];
        let end = path_part
            .find('"')
            .unwrap_or_else(|| panic!("unterminated include path after marker in axum_router.rs"));
        let candidate = &path_part[..end];
        // Every include-site literal is an absolute marketing path
        // ("/route/index.html"). A bare `env!("…")` used elsewhere (the
        // test-only `Path::new(env!(...))`) makes the scan see the next `"`
        // in the file, which can be an empty string — skipping non-`/`
        // candidates keeps the fallback tree and the completeness check
        // honest instead of manufacturing an empty route.
        if candidate.starts_with('/') {
            relpaths.push(candidate.to_string());
        }
        rest = &path_part[end..];
    }
    assert!(
        !relpaths.is_empty(),
        "no {ENV_NAME} includes found in src/axum_router.rs — did the include style change?"
    );

    // Locate the repo root (the crate lives at <root>/services/mail-server/crates/ui-foundation).
    let ws_root = manifest_dir
        .ancestors()
        .find(|p| p.join("apps/marketing-zola").is_dir())
        .unwrap_or_else(|| {
            panic!(
                "could not locate apps/marketing-zola above {}",
                manifest_dir.display()
            )
        });
    let public_dir = ws_root.join("apps/marketing-zola/public");
    println!(
        "cargo:rerun-if-changed={}",
        public_dir.join("index.html").display()
    );

    // COMPLETENESS, not merely "an index.html exists" (review §5.2 build.rs:
    // "Require complete, provenance-stamped marketing output — not merely an
    // existing homepage — to establish build freshness"). Every route the
    // router includes must be present, otherwise the tree is treated as
    // unbuilt and the OUT_DIR placeholders are embedded with a loud warning
    // naming exactly what is missing.
    let mut missing: Vec<String> = relpaths
        .iter()
        .filter(|relpath| !public_dir.join(relpath.trim_start_matches('/')).is_file())
        .cloned()
        .collect();
    missing.sort();

    // PROVENANCE: the Docker build stamps public/build-provenance.json with
    // the source revision and pinned toolchain versions. When the stamp is
    // present it must be well-formed and name a stylesheet the tree actually
    // ships; a malformed stamp disqualifies the output. A missing stamp is a
    // local `zola build` (nothing to claim) and is reported as `unstamped`
    // through APX_MARKETING_PROVENANCE rather than silently trusted.
    let provenance_path = public_dir.join("build-provenance.json");
    println!("cargo:rerun-if-changed={}", provenance_path.display());
    let mut provenance_note = String::from("unstamped");
    if provenance_path.is_file() {
        match fs::read_to_string(&provenance_path) {
            Ok(raw) => {
                let revision = json_field(&raw, "source_revision");
                let zola = json_field(&raw, "zola");
                let tailwind = json_field(&raw, "tailwindcss");
                let sheet = json_field(&raw, "styled_sheet");
                match (revision, sheet) {
                    (Some(revision), Some(sheet)) if !sheet.is_empty() => {
                        if public_dir.join(&sheet).is_file() {
                            println!(
                                "cargo:rustc-env=APX_MARKETING_PROVENANCE=revision={revision} zola={} tailwindcss={} styled_sheet={sheet}",
                                zola.unwrap_or_default(),
                                tailwind.unwrap_or_default(),
                            );
                            provenance_note = format!("stamped revision={revision}");
                        } else {
                            println!(
                                "cargo:warning=marketing output rejected: build-provenance.json names styled_sheet {sheet:?} which the tree does not ship"
                            );
                            missing.push(
                                "build-provenance.json (names a missing stylesheet)".to_string(),
                            );
                        }
                    }
                    _ => {
                        println!(
                            "cargo:warning=marketing output rejected: build-provenance.json is not a well-formed stamp (needs source_revision + styled_sheet)"
                        );
                        missing.push("build-provenance.json (malformed)".to_string());
                    }
                }
            }
            Err(e) => {
                println!("cargo:warning=marketing output rejected: cannot read build-provenance.json: {e}");
                missing.push("build-provenance.json (unreadable)".to_string());
            }
        }
    }

    if missing.is_empty() {
        // Complete (and, when stamped, provenance-checked) build output:
        // embed the actual pages, exactly as before.
        println!("cargo:rustc-cfg=marketing_public_built");
        println!("cargo:rustc-env={ENV_NAME}={}", public_dir.display());
        println!(
            "cargo:warning=marketing output embedded ({provenance_note}): {} routes",
            relpaths.len()
        );
        return;
    }
    println!(
        "cargo:warning=marketing output is INCOMPLETE: {} of {} included routes missing ({}) — embedding placeholders from OUT_DIR instead",
        missing.len(),
        relpaths.len(),
        missing.join(", ")
    );

    // Fresh checkout: generate a placeholder per included route under OUT_DIR.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let fallback_root = out_dir.join("marketing-public");
    for relpath in &relpaths {
        let target = fallback_root.join(relpath.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("failed to create {}: {e}", parent.display()));
        }
        let route = relpath
            .trim_end_matches("/index.html")
            .trim_start_matches('/')
            .to_string();
        let route = if route.is_empty() {
            "/"
        } else {
            &format!("/{route}")
        };
        let page = format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <title>ApexMail — {route}</title>\n</head>\n<body>\n\
             <h1>ApexMail</h1>\n\
             <p>This is a build placeholder for the marketing route <code>{route}</code>: \
             apps/marketing-zola/public has not been built yet. Build the Zola site \
             (see apps/marketing-zola/README or the Makefile marketing target) and \
             rebuild to embed the real page.</p>\n</body>\n</html>\n"
        );
        fs::write(&target, page)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", target.display()));
    }
    println!("cargo:warning=apps/marketing-zola/public not built (or incomplete) — embedding placeholder pages for {} marketing routes under OUT_DIR", relpaths.len());
    println!("cargo:rustc-env={ENV_NAME}={}", fallback_root.display());
}

/// Extract a flat `"key": "value"` string from a small JSON object without a
/// JSON dependency (build scripts have none): the first occurrence of the
/// quoted key followed by a quoted scalar. Returns `None` when the key is
/// absent or the value is not a plain string.
fn json_field(raw: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut rest = raw;
    while let Some(pos) = rest.find(&needle) {
        let after = rest[pos + needle.len()..].trim_start();
        if let Some(after) = after.strip_prefix(':') {
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                if let Some(end) = after.find('"') {
                    return Some(after[..end].to_string());
                }
            }
        }
        rest = &rest[pos + needle.len()..];
    }
    None
}
