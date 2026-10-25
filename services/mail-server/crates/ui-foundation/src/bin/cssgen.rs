//! cssgen — the all-Rust CSS build for every ApexMail surface.
//!
//! Replaces the vendored Tailwind CLI and its JavaScript config files: the
//! repo is Rust, and the CSS build is Rust too. The pipeline is:
//!
//!   1. emit the fixed base reset (preflight-equivalent, ~60 lines),
//!   2. inline the authored authority `assets/ark.css` (fonts, tokens, the
//!      apex-* vocabulary) plus any `--include` extras, verbatim,
//!   3. scan the content authorities (`.rs` renderers, `.html` templates,
//!      `.md` content, authored `.css`) for class tokens,
//!   4. resolve ONLY the structural utility whitelist (layout grammar:
//!      display, flex/grid, spacing, sizing, positioning, alignment) and
//!      the fixed KiwiCaptcha widget list — a colour/typography/effect
//!      utility CANNOT compile because it is not in the grammar, so the
//!      compiled artifact can never carry a design decision that ark.css
//!      does not own,
//!   5. write the artifact, or with `--check` fail when it would change.
//!
//! Radius utilities are a deliberate exception: every `rounded-*` step
//! resolves to the zero tokens, so a straggler compiles to the honest
//! value while tools/check_ark_law.py removes it from the renderers.
//!
//! Usage:
//!   cargo run -p ui-foundation --bin cssgen -- \
//!     --ark assets/ark.css \
//!     [--include assets/globals.input.css] ... \
//!     --content 'crates/ui-foundation/src/**/*.rs' ... \
//!     --out assets/globals.css [--check]
//!
//! `--content` arguments are glob patterns; `**` spans directories. Only
//! std is used — no regex, no walkdir.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ark: Option<PathBuf> = None;
    let mut includes: Vec<PathBuf> = Vec::new();
    let mut contents: Vec<String> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ark" => {
                i += 1;
                ark = args.get(i).map(PathBuf::from);
            }
            "--include" => {
                i += 1;
                match args.get(i) {
                    Some(p) => includes.push(PathBuf::from(p)),
                    None => return fail("--include needs a path"),
                }
            }
            "--content" => {
                i += 1;
                match args.get(i) {
                    Some(p) => contents.push(p.clone()),
                    None => return fail("--content needs a glob"),
                }
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--check" => check = true,
            other => return fail(&format!("unknown argument {other:?}")),
        }
        i += 1;
    }
    let (Some(ark), Some(out)) = (ark, out) else {
        return fail("usage: cssgen --ark <authority.css> [--include <css>]... --content <glob>... --out <artifact.css> [--check]");
    };

    let mut sheet = String::new();
    sheet.push_str(BANNER);
    sheet.push_str("@layer base {\n");
    sheet.push_str(BASE_RESET);
    sheet.push_str("}\n");

    for path in std::iter::once(&ark).chain(includes.iter()) {
        let css = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return fail(&format!("cannot read {}: {e}", path.display())),
        };
        sheet.push_str(&format!("\n/* ── inlined from {} ── */\n", path.display()));
        sheet.push_str(&css);
        if !css.ends_with('\n') {
            sheet.push('\n');
        }
    }

    let mut files = BTreeSet::new();
    for pattern in &contents {
        let path = Path::new(pattern);
        if path.is_dir() {
            if let Err(e) = collect_dir(path, &mut files) {
                return fail(&format!("scan {pattern:?}: {e}"));
            }
        } else if let Err(e) = collect_glob(path, &mut files) {
            return fail(&format!("glob {pattern:?}: {e}"));
        }
    }
    if files.is_empty() {
        return fail("no content files matched — refusing to emit an empty utility layer");
    }

    let mut tokens: BTreeSet<String> = BTreeSet::new();
    for file in &files {
        // The generator must never scan itself: its doc comments and string
        // literals contain class-shaped text that would pollute the report.
        if file.ends_with("src/bin/cssgen.rs") {
            continue;
        }
        let src = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => return fail(&format!("cannot read {}: {e}", file.display())),
        };
        for token in class_tokens(&src) {
            tokens.insert(token);
        }
    }

    // Emit unprefixed rules first, then each breakpoint in ascending width,
    // so a larger breakpoint always overrides a smaller one in the cascade.
    let mut resolved: Vec<(usize, String)> = Vec::new();
    let mut unresolved: Vec<&String> = Vec::new();
    for token in &tokens {
        match resolve_utility(token) {
            Some(css) => {
                let rank = match token.split_once(':') {
                    Some((p, _)) => BREAKPOINTS
                        .iter()
                        .position(|(n, _)| *n == p)
                        .map_or(0, |i| i + 1),
                    None => 0,
                };
                resolved.push((rank, css));
            }
            None => {
                // Not in the structural grammar: design utilities must fail
                // to compile here, and check_ark_law.py names them. Pure
                // vocabulary words (apex-*, data-*, aria-*, test hooks) are
                // simply not utilities and are ignored.
                if is_utility_shaped(token) {
                    unresolved.push(token);
                }
            }
        }
    }
    if !unresolved.is_empty() {
        // Print for the developer, but do not fail the build: the law gate
        // owns the renderers, and mid-sweep runs must still compile. The
        // unresolved classes simply have no rule (GATE K names any that a
        // rendered page still uses).
        eprintln!(
            "cssgen: {} scanned class token(s) have no rule in the structural grammar (design utilities must live in ark.css):",
            unresolved.len()
        );
        for token in unresolved.iter().take(40) {
            eprintln!("  {token}");
        }
        if unresolved.len() > 40 {
            eprintln!("  … and {} more", unresolved.len() - 40);
        }
    }

    resolved.sort();
    let utilities: String = resolved.into_iter().map(|(_, css)| css).collect();
    sheet.push_str("\n/* ── structural utility layer (resolved from the renderers) ── */\n");
    sheet.push_str(&utilities);
    sheet.push_str(
        "\n/* ── fixed KiwiCaptcha widget classes (runtime-injected, ARK tokens) ── */\n",
    );
    sheet.push_str(KIWI_WIDGET_FIXED);

    let hash = fnv1a(sheet.as_bytes());
    let sheet = format!("/* artifact hash {hash:016x}; regenerated by `cargo run -p ui-foundation --bin cssgen` — do not hand-edit */\n{sheet}");

    let out = out.as_path();
    if check {
        match fs::read_to_string(out) {
            Ok(existing) if existing == sheet => {
                println!("cssgen: {} is up to date", out.display());
                return ExitCode::SUCCESS;
            }
            Ok(_) => {
                eprintln!(
                    "cssgen: {} is stale — rerun cssgen to regenerate",
                    out.display()
                );
                return ExitCode::FAILURE;
            }
            Err(_) => {
                eprintln!("cssgen: {} does not exist", out.display());
                return ExitCode::FAILURE;
            }
        }
    }
    if let Err(e) = fs::write(out, &sheet) {
        return fail(&format!("cannot write {}: {e}", out.display()));
    }
    println!(
        "cssgen: wrote {} ({} files scanned, {} bytes)",
        out.display(),
        files.len(),
        sheet.len()
    );
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("cssgen: {msg}");
    ExitCode::FAILURE
}

const BANNER: &str = r#"/* ApexMail compiled stylesheet — ALL-RUST BUILD (cssgen).
   Authority: assets/ark.css (the design law). This artifact adds only the
   base reset and the STRUCTURAL utility whitelist resolved from the
   renderers. Colour, typography, rules, texture and motion cannot enter
   through utilities: they are not in the grammar. Regenerate with
   `cargo run -p ui-foundation --bin cssgen` (see the file header). */
"#;

/// Preflight-equivalent reset: everything ark.css and the vocabulary rely
/// on, and nothing more.
const BASE_RESET: &str = r#"/* ── base reset ── */
*, ::before, ::after { box-sizing: border-box; border-width: 0; border-style: solid; border-color: rgb(var(--border, 196 205 213)); border-radius: 0; }
html { -webkit-text-size-adjust: 100%; tab-size: 4; }
body { margin: 0; }
hr { height: 0; color: inherit; border-top-width: 1px; }
abbr[title] { text-decoration: underline dotted; }
b, strong { font-weight: bolder; }
small { font-size: 80%; }
code, kbd, samp, pre { font-family: var(--font-mono, monospace); font-size: 1em; }
sub, sup { font-size: 75%; line-height: 0; position: relative; vertical-align: baseline; }
sub { bottom: -0.25em; }
sup { top: -0.5em; }
table { text-indent: 0; border-color: inherit; border-collapse: collapse; }
button, input, optgroup, select, textarea { font-family: inherit; font-feature-settings: inherit; font-variation-settings: inherit; font-size: 100%; font-weight: inherit; line-height: inherit; color: inherit; margin: 0; padding: 0; }
button, select { text-transform: none; }
button, [type='button'], [type='reset'], [type='submit'] { -webkit-appearance: button; background-color: transparent; background-image: none; cursor: pointer; }
:disabled { cursor: default; }
::-webkit-inner-spin-button, ::-webkit-outer-spin-button { height: auto; }
[type='search'] { -webkit-appearance: textfield; outline-offset: -2px; }
::-webkit-search-decoration { -webkit-appearance: none; }
::-webkit-file-upload-button { -webkit-appearance: button; font: inherit; }
blockquote, dl, dd, h1, h2, h3, h4, h5, h6, figure, p, pre { margin: 0; }
ol, ul { list-style: none; margin: 0; padding: 0; }
fieldset { margin: 0; padding: 0; min-width: 0; }
legend { padding: 0; }
menu, ol, ul { list-style: none; }
img, svg, video, canvas, audio, iframe, embed, object { display: block; vertical-align: middle; }
img, video { max-width: 100%; height: auto; }
input::placeholder, textarea::placeholder { opacity: 1; }
[hidden] { display: none !important; }
"#;

/// KiwiCaptcha injects these at runtime; they are not in any scanned
/// source. They resolve to ARK tokens (brand = the blue ramp).
const KIWI_WIDGET_FIXED: &str = r#".bg-brand-50 { background-color: rgb(var(--brand-50)) }
.bg-brand-100 { background-color: rgb(var(--brand-100)) }
.bg-brand-500 { background-color: rgb(var(--brand-500)) }
.text-brand-600 { color: rgb(var(--brand-600)) }
.text-brand-700 { color: rgb(var(--brand-700)) }
.border-brand-200 { border-color: rgb(var(--brand-200)) }
.border-brand-300 { border-color: rgb(var(--brand-300)) }
.bg-success-50 { background-color: rgb(var(--success-50)) }
.text-success-600 { color: rgb(var(--success-600)) }
.text-success-700 { color: rgb(var(--success-700)) }
.border-success-200 { border-color: rgb(var(--success-200)) }
.border-success-50 { border-color: rgb(var(--success-50)) }
.bg-primary\/5 { background-color: rgb(var(--primary) / 0.05) }
.bg-primary\/10 { background-color: rgb(var(--primary) / 0.1) }
.border-primary\/30 { border-color: rgb(var(--primary) / 0.3) }
.font-mono { font-family: var(--font-mono) }
.tabular-nums { font-variant-numeric: tabular-nums }
@media (min-width: 768px) { .md\:ml-16 { margin-left: 4rem } .md\:ml-56 { margin-left: 14rem } .md\:ml-60 { margin-left: 15rem } .md\:ml-64 { margin-left: 16rem } }
"#;

/* ── scanning ── */

/// Same token grammar the previous pipeline used: a maximal run of
/// characters a class name may carry. Merged junk is filtered later by the
/// grammar resolver, so over-matching is harmless.
fn class_tokens(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in src.chars() {
        if c.is_ascii_alphanumeric() || "-_:[]().,%".contains(c) {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Heuristic: does this token LOOK like a utility (so an unresolved one is
/// worth reporting)? Structural prefixes and color/typography prefixes.
fn is_utility_shaped(token: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "bg-",
        "text-",
        "border-",
        "font-",
        "tracking-",
        "leading-",
        "shadow-",
        "ring-",
        "rounded-",
        "opacity-",
        "blur-",
        "backdrop-blur-",
        "bg-gradient",
        "from-",
        "to-",
        "via-",
        "divide-",
        "uppercase",
        "lowercase",
        "capitalize",
        "italic",
        "underline",
        "line-through",
        "truncate",
        "antialiased",
        "transition-",
        "duration-",
        "ease-",
        "delay-",
        "animate-",
        "scale-",
        "translate-",
        "rotate-",
        "skew-",
        "invert-",
        "grayscale-",
        "outline-",
        "accent-",
        "caret-",
        "fill-",
        "stroke-",
        "placeholder-",
        "decoration-",
        "align-",
        "content-",
        "self-",
        "place-",
        "order-",
        "gap-",
        "space-",
        "p",
        "m",
        "w-",
        "h-",
        "min-w-",
        "min-h-",
        "max-w-",
        "max-h-",
        "size-",
        "flex",
        "basis-full",
        "basis-auto",
        "basis-0",
        "grid",
        "col-",
        "row-",
        "auto-cols",
        "auto-rows",
        "items-",
        "justify-",
        "inset",
        "top-",
        "right-",
        "bottom-",
        "left-",
        "z-",
        "overflow-",
        "overscroll-",
        "object-",
        "whitespace-",
        "break-",
        "float-",
        "clear-",
        "sr-only",
        "not-sr-only",
        "cursor-",
        "pointer-events-",
        "select-none",
        "resize-",
        "snap-",
        "scroll-",
        "touch-",
        "will-change-",
        "appearance-",
        "list-",
        "columns-",
        "aspect-",
        "leading",
        "leading-",
    ];
    let base = token.rsplit(':').next().unwrap_or(token);
    let base = base.strip_prefix('-').unwrap_or(base);
    PREFIXES.iter().any(|p| match *p {
        "p" | "m" => {
            base == "p"
                || base == "m"
                || base.starts_with("p-")
                || base.starts_with("px-")
                || base.starts_with("py-")
                || base.starts_with("pt-")
                || base.starts_with("pr-")
                || base.starts_with("pb-")
                || base.starts_with("pl-")
                || base.starts_with("m-")
                || base.starts_with("mx-")
                || base.starts_with("my-")
                || base.starts_with("mt-")
                || base.starts_with("mr-")
                || base.starts_with("mb-")
                || base.starts_with("ml-")
        }
        "flex" => base.starts_with("flex"),
        "grid" => base.starts_with("grid"),
        "inset" => base.starts_with("inset"),
        "top-" => base.starts_with("top-"),
        "right-" => base.starts_with("right-"),
        "bottom-" => base.starts_with("bottom-"),
        "left-" => base.starts_with("left-"),
        "leading" => base == "leading",
        other => base == other,
    })
}

/* ── glob (std-only) ── */

/// Recursively collect scannable source files (.rs/.html/.md/.css) under a
/// directory. Directory arguments keep the documented recipes free of glob
/// strings — `**/*.rs` inside a CSS comment would terminate the comment.
fn collect_dir(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_dir(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "html" | "md" | "css")
        ) {
            out.insert(path);
        }
    }
    Ok(())
}

fn collect_glob(pattern: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let parts: Vec<String> = pattern
        .to_string_lossy()
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(str::to_string)
        .collect();
    // Lead with any `..` components as a literal base directory.
    let mut base = PathBuf::new();
    let mut rest = parts.as_slice();
    while let Some(first) = rest.first() {
        if first == ".." {
            base.push("..");
            rest = &rest[1..];
        } else {
            break;
        }
    }
    walk_parts(&base, rest, out)
}

fn walk_parts(dir: &Path, parts: &[String], out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let Some(first) = parts.first() else {
        return Ok(());
    };
    if first == "**" {
        // `**` spans zero or more directories: match here and recurse deeper.
        walk_parts(dir, &parts[1..], out)?;
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return Ok(()),
        };
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for entry in entries {
            if entry.is_dir() {
                walk_parts(&entry, parts, out)?;
            }
        }
        return Ok(());
    }
    let pat = first.trim_start_matches("./");
    let rd = match fs::read_dir(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }) {
        Ok(rd) => rd,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut names: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        if !glob_match(pat, &name) {
            continue;
        }
        let path = dir.join(&name);
        if parts.len() == 1 {
            if path.is_file() {
                out.insert(path);
            }
        } else if path.is_dir() {
            walk_parts(&path, &parts[1..], out)?;
        }
    }
    Ok(())
}

fn glob_match(pat: &str, name: &str) -> bool {
    if pat == "*" {
        return true;
    }
    match pat.split_once('*') {
        Some((pre, post)) => {
            name.starts_with(pre) && name.ends_with(post) && name.len() >= pre.len() + post.len()
        }
        None => pat == name,
    }
}

/* ── the structural grammar ── */

const BREAKPOINTS: [(&str, &str); 5] = [
    ("sm", "640px"),
    ("md", "768px"),
    ("lg", "1024px"),
    ("xl", "1280px"),
    ("2xl", "1536px"),
];

/// Escape a class token for use as a CSS selector.
fn escape_selector(token: &str) -> String {
    let mut out = String::with_capacity(token.len() + 8);
    for c in token.chars() {
        match c {
            ':' | '[' | ']' | '(' | ')' | ',' | '.' | '/' | '%' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Tailwind spacing scale → rem. `None` for steps we do not carry.
fn spacing(n: &str) -> Option<&'static str> {
    Some(match n {
        "0" => "0px",
        "px" => "1px",
        "0.5" => "0.125rem",
        "1" => "0.25rem",
        "1.5" => "0.375rem",
        "2" => "0.5rem",
        "2.5" => "0.625rem",
        "3" => "0.75rem",
        "3.5" => "0.875rem",
        "4" => "1rem",
        "5" => "1.25rem",
        "6" => "1.5rem",
        "7" => "1.75rem",
        "8" => "2rem",
        "9" => "2.25rem",
        "10" => "2.5rem",
        "11" => "2.75rem",
        "12" => "3rem",
        "14" => "3.5rem",
        "16" => "4rem",
        "20" => "5rem",
        "24" => "6rem",
        "28" => "7rem",
        "32" => "8rem",
        "36" => "9rem",
        "40" => "10rem",
        "44" => "11rem",
        "48" => "12rem",
        "56" => "14rem",
        "60" => "15rem",
        "64" => "16rem",
        "72" => "18rem",
        "80" => "20rem",
        "96" => "24rem",
        _ => return None,
    })
}

fn length_or_arbitrary(value: &str, family: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        return Some(inner.replace('_', " "));
    }
    if family == "w"
        || family == "h"
        || family == "size"
        || family == "min-w"
        || family == "min-h"
        || family == "max-w"
        || family == "max-h"
    {
        match value {
            "auto" => return Some("auto".into()),
            "full" => return Some("100%".into()),
            "screen" => return Some("100vh".into()),
            "min" => return Some("min-content".into()),
            "max" => return Some("max-content".into()),
            "fit" => return Some("fit-content".into()),
            "px" => return Some("1px".into()),
            "prose" => return Some("65ch".into()),
            "none" => return Some("none".into()),
            _ => {}
        }
    }
    spacing(value).map(str::to_string)
}

/// Emit one resolved rule, honouring an optional responsive prefix.
fn rule(token: &str, body: &str) -> Option<String> {
    let (prefix, base) = match token.split_once(':') {
        Some((p, b)) => (p, b),
        None => (token, token),
    };
    let sel = escape_selector(token);
    let css = format!(".{sel} {{ {body} }}\n");
    match BREAKPOINTS.iter().find(|(name, _)| *name == prefix) {
        Some((_, width)) => Some(format!(
            "@media (min-width: {width}) {{ .{sel} {{ {body} }} }}\n"
        )),
        None if prefix == base => Some(css),
        None => None, // unknown variant (hover:, dark:, …) — not structural
    }
}

/// Resolve a token, honouring a leading `-` on spacing/inset families
/// (`-mt-2`, `md:-mx-4`) by negating the resolved length.
fn resolve_utility(token: &str) -> Option<String> {
    let (prefix, base) = match token.split_once(':') {
        Some((p, b)) => (p, b),
        None => ("", token),
    };
    if let Some(positive) = base.strip_prefix('-') {
        let negatable = positive.starts_with("m-")
            || positive.starts_with("mx-")
            || positive.starts_with("my-")
            || positive.starts_with("mt-")
            || positive.starts_with("mr-")
            || positive.starts_with("mb-")
            || positive.starts_with("ml-")
            || positive.starts_with("inset")
            || positive.starts_with("top-")
            || positive.starts_with("right-")
            || positive.starts_with("bottom-")
            || positive.starts_with("left-");
        if !negatable {
            return None;
        }
        let positive_token = if prefix.is_empty() {
            positive.to_string()
        } else {
            format!("{prefix}:{positive}")
        };
        let css = resolve_utility_positive(&positive_token)?;
        // Re-key the selector to the negative token and negate each length.
        let negated = css
            .replace(
                &format!(".{}", escape_selector(&positive_token)),
                &format!(".{}", escape_selector(token)),
            )
            .replace(": ", ": -")
            .replace(": -0px", ": 0px")
            .replace(": -auto", ": auto");
        return Some(negated);
    }
    resolve_utility_positive(token)
}

fn resolve_utility_positive(token: &str) -> Option<String> {
    let (_prefix, base) = match token.split_once(':') {
        Some((p, b)) => (p, b),
        None => ("", token),
    };

    // Border widths: the colour is the reset's token default, so only the
    // width/side carriers exist. Bare `border` = the 1px hairline.
    if base == "border" {
        return rule(token, "border-width: 1px");
    }
    const BORDER_SIDES: [(&str, &[&str]); 6] = [
        ("border-t", &["top"]),
        ("border-b", &["bottom"]),
        ("border-l", &["left"]),
        ("border-r", &["right"]),
        ("border-x", &["left", "right"]),
        ("border-y", &["top", "bottom"]),
    ];
    for (fam, sides) in BORDER_SIDES {
        if base == fam || base.starts_with(&format!("{fam}-")) {
            let v = base.strip_prefix(fam).unwrap_or("").trim_start_matches('-');
            let width = match v {
                "" | "1" => "1px",
                "0" => "0px",
                "2" => "2px",
                "4" => "4px",
                "8" => "8px",
                _ => return None,
            };
            let mut out = String::new();
            for side in sides {
                let _ = write!(out, "border-{side}-width: {width}; ");
            }
            out.pop();
            return rule(token, out.trim_end());
        }
    }

    // Radius: every step resolves to the zero tokens (the honest value).
    if base == "rounded" || base.starts_with("rounded-") || base.starts_with("-rounded") {
        if base == "rounded-none" {
            return rule(token, "border-radius: 0px");
        }
        return rule(token, "border-radius: var(--radius, 0px)");
    }
    if base == "rounded-t"
        || base == "rounded-b"
        || base == "rounded-l"
        || base == "rounded-r"
        || base.starts_with("rounded-t-")
        || base.starts_with("rounded-b-")
        || base.starts_with("rounded-l-")
        || base.starts_with("rounded-r-")
    {
        return rule(token, "border-radius: var(--radius, 0px)");
    }

    // Display.
    for (name, val) in [
        ("block", "block"),
        ("inline-block", "inline-block"),
        ("inline", "inline"),
        ("flex", "flex"),
        ("inline-flex", "inline-flex"),
        ("grid", "grid"),
        ("hidden", "none"),
        ("contents", "contents"),
        ("table", "table"),
        ("flow-root", "flow-root"),
    ] {
        if base == name {
            return rule(token, &format!("display: {val}"));
        }
    }

    // Flex / grid item behaviour. grow/shrink are LONGHANDS: the `flex: 0`
    // shorthand means `0 1 0%` and collapses the element's flex-basis to
    // zero — a `shrink-0` wordmark SVG rendered zero pixels wide (ARK
    // marketing sweep 2026-10-25). flex-1/auto/initial/none are shorthands
    // by contract.
    for (name, prop, val) in [
        ("flex-1", "flex", "1 1 0%"),
        ("flex-auto", "flex", "1 1 auto"),
        ("flex-initial", "flex", "0 1 auto"),
        ("flex-none", "flex", "none"),
        ("flex-col", "flex-direction", "column"),
        ("flex-row", "flex-direction", "row"),
        ("flex-wrap", "flex-wrap", "wrap"),
        ("flex-nowrap", "flex-wrap", "nowrap"),
        ("grow", "flex-grow", "1"),
        ("grow-0", "flex-grow", "0"),
        ("shrink", "flex-shrink", "1"),
        ("shrink-0", "flex-shrink", "0"),
        // Longhand spellings are the same declarations (Tailwind v3 emits
        // both names); previously they resolved to nothing.
        ("flex-grow", "flex-grow", "1"),
        ("flex-grow-0", "flex-grow", "0"),
        ("flex-shrink", "flex-shrink", "1"),
        ("flex-shrink-0", "flex-shrink", "0"),
        ("basis-full", "flex-basis", "100%"),
        ("basis-auto", "flex-basis", "auto"),
        ("basis-0", "flex-basis", "0%"),
    ] {
        if base == name {
            return rule(token, &format!("{prop}: {val}"));
        }
    }
    for kind in [
        "items",
        "justify",
        "self",
        "content",
        "place-items",
        "place-content",
    ] {
        if let Some(v) = base.strip_prefix(&format!("{kind}-")) {
            let val = match v {
                "start" => "flex-start",
                "end" => "flex-end",
                "between" if kind == "justify" || kind == "content" || kind == "place-content" => {
                    "space-between"
                }
                "around" if kind == "justify" || kind == "content" => "space-around",
                "evenly" if kind == "justify" || kind == "content" => "space-evenly",
                "stretch" | "center" | "baseline" => v,
                _ => return None,
            };
            let prop = match kind {
                "items" => "align-items",
                "justify" => "justify-content",
                "self" => "align-self",
                "content" => "align-content",
                "place-items" => "place-items",
                _ => "place-content",
            };
            return rule(token, &format!("{prop}: {val}"));
        }
    }

    // Gap.
    if let Some(v) = base.strip_prefix("gap-") {
        if let Some(len) = length_or_arbitrary(v, "gap") {
            return rule(token, &format!("gap: {len}"));
        }
        return None;
    }
    if let Some(axis) = base.strip_prefix("gap-x-") {
        if let Some(len) = length_or_arbitrary(axis, "gap") {
            return rule(token, &format!("column-gap: {len}"));
        }
        return None;
    }
    if let Some(axis) = base.strip_prefix("gap-y-") {
        if let Some(len) = length_or_arbitrary(axis, "gap") {
            return rule(token, &format!("row-gap: {len}"));
        }
        return None;
    }

    // Grid tracks.
    if let Some(v) = base.strip_prefix("grid-cols-") {
        let val = if let Some(inner) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            format!("repeat({}, minmax(0, 1fr))", inner.replace('_', " "))
        } else if v == "none" {
            "none".to_string()
        } else {
            let n: u32 = v.parse().ok()?;
            format!("repeat({n}, minmax(0, 1fr))")
        };
        return rule(token, &format!("grid-template-columns: {val}"));
    }
    if let Some(v) = base.strip_prefix("grid-rows-") {
        let val = if let Some(inner) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            format!("repeat({}, minmax(0, 1fr))", inner.replace('_', " "))
        } else {
            let n: u32 = v.parse().ok()?;
            format!("repeat({n}, minmax(0, 1fr))")
        };
        return rule(token, &format!("grid-template-rows: {val}"));
    }
    if let Some(v) = base.strip_prefix("col-span-") {
        let val = match v {
            "full" => "1 / -1".to_string(),
            "auto" => "auto".to_string(),
            n => n.to_string(),
        };
        return rule(token, &format!("grid-column: span {val} / span {val}"));
    }
    if let Some(n) = base.strip_prefix("row-span-") {
        return rule(token, &format!("grid-row: span {n} / span {n}"));
    }

    // Spacing.
    const SIDES: [(&str, &str); 4] = [("t", "top"), ("r", "right"), ("b", "bottom"), ("l", "left")];
    for (fam, prop) in [("p", "padding"), ("m", "margin")] {
        if let Some(v) = base.strip_prefix(&format!("{fam}-")) {
            let value = if prop == "margin" && v == "auto" {
                "auto".to_string()
            } else {
                spacing(v)?.to_string()
            };
            return rule(token, &format!("{prop}: {value}"));
        }
        if let Some(v) = base.strip_prefix(&format!("{fam}x-")) {
            let value = if prop == "margin" && v == "auto" {
                "auto".to_string()
            } else {
                spacing(v)?.to_string()
            };
            return rule(
                token,
                &format!("{prop}-left: {value}; {prop}-right: {value}"),
            );
        }
        if let Some(v) = base.strip_prefix(&format!("{fam}y-")) {
            let value = if prop == "margin" && v == "auto" {
                "auto".to_string()
            } else {
                spacing(v)?.to_string()
            };
            return rule(
                token,
                &format!("{prop}-top: {value}; {prop}-bottom: {value}"),
            );
        }
        for (side, css_side) in SIDES {
            if let Some(v) = base.strip_prefix(&format!("{fam}{side}-")) {
                let value = if prop == "margin" && v == "auto" {
                    "auto".to_string()
                } else {
                    spacing(v)?.to_string()
                };
                return rule(token, &format!("{prop}-{css_side}: {value}"));
            }
        }
    }

    // Sizing.
    // Named max-width measures (page frames, prose columns).
    const MAX_W: [(&str, &str); 9] = [
        ("max-w-xs", "20rem"),
        ("max-w-sm", "24rem"),
        ("max-w-md", "28rem"),
        ("max-w-lg", "32rem"),
        ("max-w-xl", "36rem"),
        ("max-w-2xl", "42rem"),
        ("max-w-3xl", "48rem"),
        ("max-w-7xl", "80rem"),
        ("max-w-5xl", "64rem"),
    ];
    for (name, val) in MAX_W {
        if base == name {
            return rule(token, &format!("max-width: {val}"));
        }
    }
    if base == "max-w-4xl" {
        return rule(token, "max-width: 56rem");
    }
    if base == "max-w-6xl" {
        return rule(token, "max-width: 72rem");
    }

    const SIZING: [(&str, &[&str]); 6] = [
        ("w", &["width"]),
        ("h", &["height"]),
        ("min-w", &["min-width"]),
        ("min-h", &["min-height"]),
        ("max-w", &["max-width"]),
        ("max-h", &["max-height"]),
    ];
    for (fam, props) in SIZING {
        if let Some(v) = base.strip_prefix(&format!("{fam}-")) {
            if let Some(len) = length_or_arbitrary(v, fam) {
                let mut out = String::new();
                for p in props {
                    let _ = write!(out, "{p}: {len}; ");
                }
                out.pop();
                return rule(token, out.trim_end());
            }
            return None;
        }
    }

    // Positioning.
    for (name, val) in [
        ("static", "static"),
        ("fixed", "fixed"),
        ("absolute", "absolute"),
        ("relative", "relative"),
        ("sticky", "sticky"),
    ] {
        if base == name {
            return rule(token, &format!("position: {val}"));
        }
    }
    if let Some(v) = base.strip_prefix("z-") {
        if v == "auto" {
            return rule(token, "z-index: auto");
        }
        let n: i32 = v.parse().ok()?;
        return rule(token, &format!("z-index: {n}"));
    }
    const INSETS: [(&str, &[&str]); 7] = [
        ("inset", &["top", "right", "bottom", "left"]),
        ("inset-x", &["right", "left"]),
        ("inset-y", &["top", "bottom"]),
        ("top", &["top"]),
        ("right", &["right"]),
        ("bottom", &["bottom"]),
        ("left", &["left"]),
    ];
    for (fam, props) in INSETS {
        if let Some(v) = base.strip_prefix(&format!("{fam}-")) {
            let val = match v {
                "auto" => "auto".to_string(),
                "px" => "1px".to_string(),
                "full" => "100%".to_string(),
                "0" => "0px".to_string(),
                other => spacing(other)?.to_string(),
            };
            let mut out = String::new();
            for p in props {
                let _ = write!(out, "{p}: {val}; ");
            }
            out.pop();
            return rule(token, out.trim_end());
        }
    }

    // Anchor scroll margins (structural offsets for in-page targets).
    for fam in [
        "scroll-mt",
        "scroll-mb",
        "scroll-m",
        "scroll-ml",
        "scroll-mr",
    ] {
        if let Some(v) = base.strip_prefix(&format!("{fam}-")) {
            if let Some(len) = spacing(v) {
                let prop = match fam {
                    "scroll-mt" => "scroll-margin-top",
                    "scroll-mb" => "scroll-margin-bottom",
                    "scroll-ml" => "scroll-margin-left",
                    "scroll-mr" => "scroll-margin-right",
                    _ => "scroll-margin",
                };
                return rule(token, &format!("{prop}: {len}"));
            }
        }
    }

    // Overflow and friends.
    for prop in ["auto", "hidden", "visible", "scroll", "clip"] {
        if base == format!("overflow-{prop}") {
            return rule(token, &format!("overflow: {prop}"));
        }
        if base == format!("overflow-x-{prop}") {
            return rule(token, &format!("overflow-x: {prop}"));
        }
        if base == format!("overflow-y-{prop}") {
            return rule(token, &format!("overflow-y: {prop}"));
        }
    }
    if base == "caption-bottom" {
        return rule(token, "caption-side: bottom");
    }
    if base == "caption-top" {
        return rule(token, "caption-side: top");
    }

    if base == "object-contain" {
        return rule(token, "object-fit: contain");
    }
    if base == "object-cover" {
        return rule(token, "object-fit: cover");
    }
    if base == "aspect-square" {
        return rule(token, "aspect-ratio: 1 / 1");
    }
    if base == "aspect-video" {
        return rule(token, "aspect-ratio: 16 / 9");
    }

    // Text behaviour (alignment and wrapping only — never typography).
    for (name, val) in [
        ("text-left", "left"),
        ("text-center", "center"),
        ("text-right", "right"),
        ("text-justify", "justify"),
        ("whitespace-nowrap", "nowrap"),
        ("whitespace-pre", "pre"),
        ("whitespace-pre-wrap", "pre-wrap"),
        ("whitespace-normal", "normal"),
        ("break-words", "break-word"),
        ("break-all", "break-all"),
        ("break-normal", "normal"),
    ] {
        if base == name {
            let prop = if name.starts_with("text-") {
                "text-align"
            } else {
                "word-break"
            };
            if name.starts_with("whitespace-") {
                return rule(token, &format!("white-space: {val}"));
            }
            return rule(token, &format!("{prop}: {val}"));
        }
    }
    for (name, val) in [
        ("align-baseline", "baseline"),
        ("align-top", "top"),
        ("align-middle", "middle"),
        ("align-bottom", "bottom"),
        ("align-text-top", "text-top"),
        ("align-text-bottom", "text-bottom"),
    ] {
        if base == name {
            return rule(token, &format!("vertical-align: {val}"));
        }
    }

    // Interaction-adjacent structure.
    for (name, val) in [
        ("visible", "visible"),
        ("invisible", "hidden"),
        ("pointer-events-none", "none"),
        ("pointer-events-auto", "auto"),
        ("cursor-pointer", "pointer"),
        ("cursor-not-allowed", "not-allowed"),
        ("cursor-default", "default"),
        ("sr-only", "sr"),
        ("list-none", "none"),
        ("list-disc", "disc"),
        ("list-decimal", "decimal"),
    ] {
        if base == name {
            if val == "sr" {
                return Some(format!(
                    ".{sel} {{ position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border-width: 0 }}\n",
                    sel = escape_selector(token)
                ));
            }
            let prop = match name {
                n if n.starts_with("pointer-events") => "pointer-events",
                n if n.starts_with("cursor") => "cursor",
                n if n.starts_with("list-") => "list-style-type",
                _ => "visibility",
            };
            return rule(token, &format!("{prop}: {val}"));
        }
    }
    if base == "order-first" {
        return rule(token, "order: -9999");
    }
    if base == "order-last" {
        return rule(token, "order: 9999");
    }
    if let Some(n) = base.strip_prefix("order-") {
        let n: i32 = n.parse().ok()?;
        return rule(token, &format!("order: {n}"));
    }
    None
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
