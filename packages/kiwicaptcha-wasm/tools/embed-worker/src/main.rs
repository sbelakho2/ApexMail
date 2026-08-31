//! Regenerates the `workerSource` section inside `assets/kiwicaptcha-wasm.js`
//! (the wasm glue) from the standalone `assets/kiwi-worker.js`:
//! kiwi-worker.js is the source of truth; the glue's embedded copy is
//! machine-generated so the two can never drift by hand.
//!
//! The widget driver no longer embeds the worker bytes. Instead the glue
//! carries them as `window.__kiwiCaptchaWasm.workerSource`:
//!
//! - inline mode renders the glue (and the driver) into the page, so the
//!   driver reads the worker source off the glue and builds the historical
//!   Blob worker — zero requests, byte-identical worker behavior;
//! - files mode fetches the versioned `worker.<hash>.js` asset directly and
//!   constructs a same-origin Worker from the fetched source, never touching
//!   the glue's copy.
//!
//! The tool is part of the pure-Rust build pipeline — build.sh invokes it
//! (--locked) after the glue is generated, so the worker section is appended
//! to a fresh `kiwicaptcha-wasm.js`:
//!
//! ```sh
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --            # regenerate
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml -- --check    # exit 1 on drift (CI)
//! ```
//!
//! The generated section is delimited by explicit sentinel comments
//! (`KIWI_WORKER_SRC_BEGIN` … `KIWI_WORKER_SRC_END`) in the glue — the
//! whole span is replaced wholesale, so no JavaScript token parsing can
//! ever misfire. The embedded value is a JSON string literal (quotes and
//! backslashes escaped), so the executed bytes are identical to the
//! standalone file. A closing-script-tag sequence is rejected with an ASCII
//! case-insensitive scan: the glue is inlined into pages by the renderers,
//! so `</script>` in any casing would terminate the page's script element.

use std::{env, fs, path::PathBuf, process};

/// Sentinel comments delimiting the machine-written section in
/// `kiwicaptcha-wasm.js`. Both are unique in the glue.
const BEGIN: &str = "// KIWI_WORKER_SRC_BEGIN";
const END: &str = "// KIWI_WORKER_SRC_END";

/// Escape a string for embedding as a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn generated_section(worker_src: &str) -> String {
    format!(
        "{BEGIN} — generated section (tools/embed-worker): the whole span\n\
         // from this marker to the KIWI_WORKER_SRC_END marker is machine-written.\n\
         window.__kiwiCaptchaWasm = window.__kiwiCaptchaWasm || {{}};\n\
         window.__kiwiCaptchaWasm.workerSource = \"{escaped}\";\n\
         {END} — generated section (tools/embed-worker): the whole span\n\
         // from the KIWI_WORKER_SRC_BEGIN marker to this marker is machine-written.\n",
        escaped = json_escape(worker_src)
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let check = args.iter().any(|a| a == "--check");

    // tools/embed-worker -> packages/kiwicaptcha-wasm
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worker_path = root.join("assets/kiwi-worker.js");
    let glue_path = root.join("assets/kiwicaptcha-wasm.js");

    let worker_src = fs::read_to_string(&worker_path).expect("read assets/kiwi-worker.js");
    let glue = fs::read_to_string(&glue_path).expect("read assets/kiwicaptcha-wasm.js");

    // ASCII case-insensitive scan: `</ScRiPt>` must be rejected too — HTML
    // script end tags are case-insensitive.
    if worker_src.to_ascii_lowercase().contains("</script") {
        die("kiwi-worker.js must not contain a closing-script-tag sequence (the glue is inlined into pages)");
    }

    let section = generated_section(&worker_src);

    // Replace the span between the sentinels (from the begin-marker line start
    // through the END marker line AND its continuation line); when the
    // glue is freshly generated (build.sh) the sentinels are absent, so
    // the section is appended at the end.
    let regenerated = match glue.find(BEGIN) {
        Some(begin_idx) => {
            let end_idx = glue
                .find(END)
                .unwrap_or_else(|| die("kiwicaptcha-wasm.js: KIWI_WORKER_SRC_END sentinel not found"));
            if begin_idx >= end_idx {
                die("kiwicaptcha-wasm.js: sentinels out of order (BEGIN must precede END)");
            }
            let between = &glue[begin_idx..end_idx];
            if !between.contains("window.__kiwiCaptchaWasm.workerSource = \"")
                || !between.trim_end().ends_with(';')
            {
                die("kiwicaptcha-wasm.js: generated section between the sentinels does not match the workerSource assignment");
            }
            let begin_line_start = glue[..begin_idx].rfind('\n').map_or(0, |i| i + 1);
            let end_line_end = end_idx + glue[end_idx..].find('\n').expect("newline after END");
            let mut tail_start = end_line_end + 1;
            if glue[tail_start..].starts_with("// from the KIWI_WORKER_SRC_BEGIN marker") {
                tail_start += glue[tail_start..].find('\n').map_or(0, |i| i + 1);
            }
            let head = &glue[..begin_line_start];
            let tail = &glue[tail_start..];
            format!("{head}{section}{tail}")
        }
        None => {
            if glue.contains("KIWI_WORKER_SRC_END") {
                die("kiwicaptcha-wasm.js: KIWI_WORKER_SRC_END present without KIWI_WORKER_SRC_BEGIN");
            }
            format!("{glue}{section}")
        }
    };

    if check {
        if regenerated != glue {
            eprintln!(
                "DRIFT: assets/kiwicaptcha-wasm.js embeds a stale copy of assets/kiwi-worker.js"
            );
            eprintln!("run: cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --  (or packages/kiwicaptcha-wasm/build.sh)");
            process::exit(1);
        }
        println!("worker source in sync (kiwicaptcha-wasm.js <-> kiwi-worker.js)");
    } else {
        fs::write(&glue_path, regenerated).expect("write assets/kiwicaptcha-wasm.js");
        println!("kiwicaptcha-wasm.js updated from assets/kiwi-worker.js");
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}
