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
        relpaths.push(path_part[..end].to_string());
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

    if public_dir.join("index.html").is_file() {
        // Real build output exists: embed the actual pages, exactly as before.
        println!("cargo:rustc-cfg=marketing_public_built");
        println!("cargo:rustc-env={ENV_NAME}={}", public_dir.display());
        return;
    }

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
    println!("cargo:warning=apps/marketing-zola/public not built — embedding placeholder pages for {} marketing routes under OUT_DIR", relpaths.len());
    println!("cargo:rustc-env={ENV_NAME}={}", fallback_root.display());
}
