//! Regenerates the `KIWI_WORKER_SRC` template literal inside
//! `assets/widget-driver.js` FROM the standalone `assets/kiwi-worker.js`:
//! kiwi-worker.js is the source of truth; the
//! driver's embedded copy is machine-generated so the two can never drift
//! by hand. The tool is part of the PURE-RUST build pipeline — build.sh
//! invokes it (--locked) before the solver build.
//!
//! ```sh
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --            # regenerate
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml -- --check    # exit 1 on drift (CI)
//! ```
//!
//! The generated section is delimited by EXPLICIT SENTINEL COMMENTS
//! (`KIWI_WORKER_SRC_BEGIN` … `KIWI_WORKER_SRC_END`) in the driver — the
//! whole span is replaced wholesale, so no JavaScript token parsing (e.g.
//! the first `` `; `` occurrence) can ever misfire, even if the worker
//! source legitimately contains a backtick-semicolon sequence. The
//! embedded literal is escaped for template-literal semantics (backslashes,
//! backticks, `${`), so the executed bytes are identical to the standalone
//! file. A closing-script-tag sequence is REJECTED with an ASCII
//! case-insensitive scan: the driver is inlined into pages by the
//! renderers, so `</script>` in any casing would terminate the page's
//! script element.

use std::{env, fs, path::PathBuf, process};

/// Sentinel comments delimiting the machine-written section in
/// `widget-driver.js`. Both are unique in the driver.
const BEGIN: &str = "// KIWI_WORKER_SRC_BEGIN";
const END: &str = "// KIWI_WORKER_SRC_END";

fn main() {
    let args: Vec<String> = env::args().collect();
    let check = args.iter().any(|a| a == "--check");

    // tools/embed-worker -> packages/kiwicaptcha-wasm
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worker_path = root.join("assets/kiwi-worker.js");
    let driver_path = root.join("assets/widget-driver.js");

    let worker_src = fs::read_to_string(&worker_path).expect("read assets/kiwi-worker.js");
    let driver = fs::read_to_string(&driver_path).expect("read assets/widget-driver.js");

    // ASCII case-insensitive scan: `</ScRiPt>` must be
    // rejected too — HTML script end tags are case-insensitive.
    if worker_src.to_ascii_lowercase().contains("</script") {
        die("kiwi-worker.js must not contain a closing-script-tag sequence (the driver is inlined into pages)");
    }

    let begin_idx = driver
        .find(BEGIN)
        .unwrap_or_else(|| die("widget-driver.js: KIWI_WORKER_SRC_BEGIN sentinel not found"));
    let end_idx = driver
        .find(END)
        .unwrap_or_else(|| die("widget-driver.js: KIWI_WORKER_SRC_END sentinel not found"));
    if begin_idx >= end_idx {
        die("widget-driver.js: sentinels out of order (BEGIN must precede END)");
    }

    // The assignment between the sentinels must be the literal we own:
    // the span opens the KIWI_WORKER_SRC template literal and closes it
    // with `;` before the END marker.
    let between = &driver[begin_idx..end_idx];
    if !between.contains("var KIWI_WORKER_SRC = `") || !between.trim_end().ends_with("`;") {
        die("widget-driver.js: generated section between the sentinels does not match the KIWI_WORKER_SRC assignment");
    }

    // Replace whole LINES: the generated section spans from the BEGIN
    // marker line through the END marker line AND its continuation line
    // (the canonical block's shape); the head/tail boundaries land on line
    // starts so nothing is duplicated or dropped, and regeneration is
    // idempotent against the canonical block.
    let begin_line_start = driver[..begin_idx].rfind('\n').map_or(0, |i| i + 1);
    let end_line_end = end_idx + driver[end_idx..].find('\n').expect("newline after END");
    let mut tail_start = end_line_end + 1;
    // The canonical END block's continuation line (fixed pattern) is part
    // of the generated section — consume it too.
    if driver[tail_start..].starts_with("// from the KIWI_WORKER_SRC_BEGIN marker") {
        tail_start += driver[tail_start..].find('\n').map_or(0, |i| i + 1);
    }
    let head = &driver[..begin_line_start];
    let tail = &driver[tail_start..];

    let escaped = worker_src
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace("${", "\\${");

    let regenerated = format!(
        "{head}{BEGIN} — generated section (tools/embed-worker): the whole span\n// from this marker to the KIWI_WORKER_SRC_END marker is machine-written.\n  var KIWI_WORKER_SRC = `{escaped}`;\n{END} — generated section (tools/embed-worker): the whole span\n// from the KIWI_WORKER_SRC_BEGIN marker to this marker is machine-written.\n{tail}"
    );

    if check {
        if regenerated != driver {
            eprintln!(
                "DRIFT: assets/widget-driver.js embeds a stale copy of assets/kiwi-worker.js"
            );
            eprintln!("run: cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --  (or packages/kiwicaptcha-wasm/build.sh)");
            process::exit(1);
        }
        println!("worker source in sync (widget-driver.js <-> kiwi-worker.js)");
    } else {
        fs::write(&driver_path, regenerated).expect("write assets/widget-driver.js");
        println!("widget-driver.js updated from assets/kiwi-worker.js");
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}
