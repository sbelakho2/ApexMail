//! Regenerates the `KIWI_WORKER_SRC` template literal inside
//! `assets/widget-driver.js` FROM the standalone `assets/kiwi-worker.js`
//! (audit rounds 15–16): kiwi-worker.js is the source of truth; the
//! driver's embedded copy is machine-generated so the two can never drift
//! by hand. The tool is part of the PURE-RUST build pipeline — build.sh
//! invokes it (--locked) before the solver build.
//!
//! ```sh
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml --            # regenerate
//! cargo run --locked --manifest-path tools/embed-worker/Cargo.toml -- --check    # exit 1 on drift (CI)
//! ```
//!
//! The embedded literal is escaped for template-literal semantics:
//! backslashes, backticks and `${` sequences in the worker source (e.g. in
//! comments) become `\\`, `\`` and `\${` — the executed bytes are identical
//! to the standalone file. A closing-script-tag sequence is REJECTED: the
//! driver is inlined into pages by the renderers, so `</script>` inside the
//! literal would terminate the page's script element.

use std::{env, fs, path::PathBuf, process};

const OPEN: &str = "var KIWI_WORKER_SRC = `";
const CLOSE: &str = "`;";

fn main() {
    let args: Vec<String> = env::args().collect();
    let check = args.iter().any(|a| a == "--check");

    // tools/embed-worker -> packages/kiwicaptcha-wasm
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let worker_path = root.join("assets/kiwi-worker.js");
    let driver_path = root.join("assets/widget-driver.js");

    let worker_src = fs::read_to_string(&worker_path).expect("read assets/kiwi-worker.js");
    let driver = fs::read_to_string(&driver_path).expect("read assets/widget-driver.js");

    if worker_src.contains("</script") || worker_src.contains("</SCRIPT") {
        eprintln!("kiwi-worker.js must not contain a closing-script-tag sequence (the driver is inlined into pages)");
        process::exit(1);
    }

    let escaped = worker_src
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace("${", "\\${");

    let start = driver
        .find(OPEN)
        .unwrap_or_else(|| die("widget-driver.js: KIWI_WORKER_SRC opening marker not found"));
    let after = start + OPEN.len();
    let rel = &driver[after..];
    let end = after
        + rel
            .find(CLOSE)
            .unwrap_or_else(|| die("widget-driver.js: KIWI_WORKER_SRC closing marker not found"));
    let regenerated = format!("{}{}{}", &driver[..after], escaped, &driver[end..]);

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
