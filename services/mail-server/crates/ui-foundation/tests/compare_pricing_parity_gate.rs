//! Compare-page pricing-parity gate (audit SM11 F3): the python checker
//! `tools/check-compare-pricing-parity.py` is the enforcement for compare-page
//! locale parity (`pricing_as_of` agreement + plan vocabulary — a retired
//! "Scale"/"Starter" name in an ApexMail cell must never come back). The
//! checker only has teeth if something actually RUNS it, so `cargo test` on
//! this crate invokes it against the working tree and fails the suite on any
//! violation — the same gate `ci/stages` can call, now wired at the module
//! level. Pure stdlib python over repo files: hermetic (no network, no DB).

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("CARGO_MANIFEST_DIR is services/mail-server/crates/ui-foundation")
        .to_path_buf()
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// The gate must pass on the tree as committed. A missing required tool is a
/// FAILURE, not a green skip (review §14.1 `compare_pricing_parity_gate.rs`:
/// "Missing required tooling in CI should fail, not appear as a successful
/// skip") — a CI image without python3 used to report this gate as passing
/// while nothing ran. python3 is already a hard requirement of the UI gate
/// battery (`tools/check_ui_*.py`), so failing here is consistent.
#[test]
fn compare_pricing_parity_gate_passes_on_the_working_tree() {
    let script = repo_root().join("tools/check-compare-pricing-parity.py");
    assert!(
        script.is_file(),
        "parity gate script missing: {}",
        script.display()
    );
    assert!(
        python3_available(),
        "python3 is required to run the compare pricing-parity gate \
         (tools/check-compare-pricing-parity.py); install python3 in the CI image \
         instead of letting this gate report a green skip"
    );
    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root())
        .output()
        .expect("spawn python3 for the compare pricing-parity gate");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "compare pricing-parity gate FAILED — locale pricing_as_of/plan-vocabulary \
         drift is present (audit SM11 F3 regressed)\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("compare pricing parity OK"),
        "gate exited 0 but did not print its OK line — treating as failure\nstdout: {stdout}"
    );
}
