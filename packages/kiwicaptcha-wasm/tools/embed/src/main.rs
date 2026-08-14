//! Regenerates `assets/kiwicaptcha-wasm.js` from the wasm-bindgen `--target web` output.
//!
//! The wasm-bindgen web glue uses ESM (`export`, `import.meta.url`) and fetches
//! the .wasm over the network. The widget needs a single self-contained inline
//! script with no external requests, so this tool:
//!   1. strips all ESM syntax (`export function` -> `function`, drops export tails)
//!   2. removes the fetch/URL loading branch (we always pass bytes directly)
//!   3. inlines the .wasm binary as base64
//!   4. wraps everything in an IIFE exposing `window.__kiwiCaptchaWasm.load()`
//!
//! Pure Rust, no Node.js. Usage: `kiwicaptcha-embed [pkgDir] [outFile]`

use std::env;
use std::fs;
use std::path::PathBuf;

use base64::Engine;

fn is_js_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}')
}

fn skip_js_ws(s: &str) -> &str {
    s.trim_start_matches(is_js_ws)
}

/// Drop every line matching `/^export\s*\{[^}]*\};?\s*$/gm`, including its
/// trailing newline (the greedy `\s*` consumes it). Handles both the
/// `export { ... };` and `export { ... }` (no semicolon) forms.
fn remove_export_tails(glue: &str) -> String {
    let mut out = String::with_capacity(glue.len());
    for line in glue.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let is_export_tail = if let Some(rest) = content.strip_prefix("export") {
            let rest = skip_js_ws(rest);
            if let Some(rest) = rest.strip_prefix('{') {
                match rest.find('}') {
                    Some(idx) => {
                        let after = &rest[idx + 1..];
                        let after = after.strip_prefix(';').unwrap_or(after);
                        after.chars().all(is_js_ws)
                    }
                    None => false,
                }
            } else {
                false
            }
        } else {
            false
        };
        if !is_export_tail {
            out.push_str(line);
        }
    }
    out
}

/// Remove `/if \(module_or_path === undefined\) \{\s*module_or_path = new URL\([^;]+;\s*\}/s`.
/// The match starts at `if (...)` (leading indent stays), ends at the closing
/// brace, and does NOT consume the newline after it.
fn remove_url_branch(glue: &str) -> String {
    const START: &str = "if (module_or_path === undefined) {";
    const MID: &str = "module_or_path = new URL(";
    let mut out = String::with_capacity(glue.len());
    let mut rest = glue;
    loop {
        let Some(pos) = rest.find(START) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        let tail = skip_js_ws(&rest[pos + START.len()..]);
        let Some(after_mid) = tail.strip_prefix(MID) else {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        };
        let Some(semi_rel) = after_mid.find(';') else {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        };
        if semi_rel == 0 {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        }
        let after_semi = skip_js_ws(&after_mid[semi_rel + 1..]);
        let Some(after_brace) = after_semi.strip_prefix('}') else {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        };
        rest = after_brace;
    }
}

/// Remove `/if \(typeof module_or_path === 'string' \|\| ... \)\) \{\s*module_or_path = fetch\(module_or_path\);\s*\}/s`.
/// Same match semantics as `remove_url_branch`.
fn remove_fetch_branch(glue: &str) -> String {
    const START: &str = "if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {";
    const MID: &str = "module_or_path = fetch(module_or_path);";
    let mut out = String::with_capacity(glue.len());
    let mut rest = glue;
    loop {
        let Some(pos) = rest.find(START) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        let tail = skip_js_ws(&rest[pos + START.len()..]);
        let Some(after_mid) = tail.strip_prefix(MID) else {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        };
        let Some(after_brace) = skip_js_ws(after_mid).strip_prefix('}') else {
            out.push_str(START);
            rest = &rest[pos + START.len()..];
            continue;
        };
        rest = after_brace;
    }
}

/// Remove every `/\/\/#sourceMappingURL=[^\n]*/g` marker (up to, not including, the newline).
fn remove_source_map_urls(glue: &str) -> String {
    const MARK: &str = "//#sourceMappingURL=";
    let mut out = String::with_capacity(glue.len());
    let mut rest = glue;
    loop {
        let Some(pos) = rest.find(MARK) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        rest = &rest[pos + MARK.len()..];
        match rest.find('\n') {
            Some(nl) => {
                out.push('\n');
                rest = &rest[nl + 1..];
            }
            None => return out,
        }
    }
}

/// Replace every `/import\.meta\.[a-zA-Z]+/g` with `location.href`.
fn replace_import_meta(glue: &str) -> String {
    const MARK: &str = "import.meta.";
    let mut out = String::with_capacity(glue.len());
    let mut rest = glue;
    loop {
        let Some(pos) = rest.find(MARK) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        let after = &rest[pos + MARK.len()..];
        let ident_len = after
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .map(char::len_utf8)
            .sum::<usize>();
        if ident_len == 0 {
            out.push_str(MARK);
            rest = after;
            continue;
        }
        out.push_str("location.href");
        rest = &after[ident_len..];
    }
}

fn transform(glue_raw: &str) -> String {
    // Order matters: strip `export function` before the export-tail pass, and
    // remove the URL branch (which contains import.meta.url) before rewriting
    // any remaining import.meta references.
    let mut glue = glue_raw.replace("export function", "function");
    glue = remove_export_tails(&glue);
    glue = remove_url_branch(&glue);
    glue = remove_fetch_branch(&glue);
    glue = glue.replace("//#endregion", "");
    glue = remove_source_map_urls(&glue);
    glue = replace_import_meta(&glue);
    glue
}

fn main() {
    let mut args = env::args().skip(1);
    let pkg_dir = args.next().unwrap_or_else(|| "pkg".to_string());
    let out_file = args
        .next()
        .unwrap_or_else(|| "assets/kiwicaptcha-wasm.js".to_string());

    let glue_path = PathBuf::from(&pkg_dir).join("kiwicaptcha_wasm.js");
    let wasm_path = PathBuf::from(&pkg_dir).join("kiwicaptcha_wasm_bg.wasm");

    let glue_raw = fs::read_to_string(&glue_path).unwrap_or_else(|err| {
        eprintln!("FATAL: cannot read {}: {err}", glue_path.display());
        std::process::exit(1);
    });
    let wasm = fs::read(&wasm_path).unwrap_or_else(|err| {
        eprintln!("FATAL: cannot read {}: {err}", wasm_path.display());
        std::process::exit(1);
    });

    let glue = transform(&glue_raw);

    // Sanity checks: the transformed glue must be plain classic JS.
    // A plain `contains("export ")` would false-positive on prose inside
    // wasm-bindgen's copied doc comments, so only line-leading ESM
    // statements and live `import.meta` references are rejected.
    let has_esm = glue.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("export ") || t.starts_with("import ")
    });
    let has_import_meta = glue.contains("import.meta");
    if has_esm || has_import_meta {
        eprintln!("FATAL: transformed glue still contains ESM/import.meta");
        for (i, line) in glue.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("export ") || t.starts_with("import ") || line.contains("import.meta")
            {
                eprintln!(
                    "  line {}: {}",
                    i + 1,
                    line.chars().take(120).collect::<String>()
                );
            }
        }
        std::process::exit(1);
    }

    // Inline the wasm as base64.
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wasm);

    let banner = "/* Generated by packages/kiwicaptcha-wasm/tools/embed — do not edit. */\n\
                  /* Source: wasm-bindgen --target web (wasm-bindgen 0.2.127), wasm inlined as base64. */\n";
    let output = format!(
        "{banner}(function () {{\n  \"use strict\";\n  var KIWI_WASM_B64 = \"{b64}\";\n{glue}\n  async function load() {{\n    var bytes = Uint8Array.from(atob(KIWI_WASM_B64), function (c) {{ return c.charCodeAt(0); }});\n    return __wbg_init(bytes);\n  }}\n  if (typeof window !== \"undefined\") {{\n    window.__kiwiCaptchaWasm = {{ load: load, initSync: initSync }};\n  }}\n}})();\n"
    );

    fs::write(&out_file, &output).unwrap_or_else(|err| {
        eprintln!("FATAL: cannot write {}: {err}", out_file);
        std::process::exit(1);
    });
    println!(
        "wrote {out_file} ({} bytes, wasm {} bytes)",
        output.len(),
        wasm.len()
    );
}
