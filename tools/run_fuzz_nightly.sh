#!/usr/bin/env bash
# =============================================================================
# tools/run_fuzz_nightly.sh — coverage-guided fuzzing for every parser (T7)
# =============================================================================
# The audit's prescription (30 Oct, "Tests and enforcement", T7): every
# parser gets a coverage-guided target, corpora are committed, crashes become
# committed regression tests, and a deterministic smoke run proves the
# harness works in the normal lane without paying for a nightly.
#
# Lane shape:
#   * `--smoke`      deterministic, seconds: runs the workspace smoke test
#                    (crates/fuzz-tests/tests/fuzz_smoke.rs) over the
#                    committed corpora + a fixed seeded input set. This is
#                    the normal-lane lane `test.fuzz-smoke`.
#   * (default)      the nightly engine: `cargo fuzz run <target>
#                    -max_total_time=<seconds>` per target (default 600 s =
#                    10 minutes), from crates/fuzz-tests/fuzz. Every crash
#                    artifact is copied into the target's
#                    corpus/regression/ directory AND a compilable regression
#                    test skeleton is generated in
#                    crates/fuzz-tests/tests/generated/ (the audit: "Every
#                    crash becomes a committed regression test before its
#                    fix merges").
#   * `--from-artifact PATH`
#                    turn an existing crash artifact into the committed
#                    corpus seed + generated regression test WITHOUT running
#                    a fuzzing session. Target inferred from the path (or
#                    pass --target).
#
# Scheduling (the pipeline's periodic mechanism):
#   `ci/pipeline.sh run --fuzz-nightly` executes this script once per UTC day
#   before the stage line (the same shape as the deps agent's --daily
#   fresh-DB cargo-audit lane): a `.last-fuzz-nightly` marker makes the
#   5-minute host timer cheap, and CI_FUZZ_FORCE=1 forces a run. The host
#   unit ci/units/apexmail-pipeline.service passes --fuzz-nightly. A standalone
#   operator/cron invocation is equally valid:
#
#       FUZZ_SECONDS=600 bash tools/run_fuzz_nightly.sh
#       bash tools/run_fuzz_nightly.sh --smoke
#       bash tools/run_fuzz_nightly.sh --from-artifact \
#           crates/fuzz-tests/fuzz/artifacts/fuzz_spf_record/crash-abc123
#
# Nightly prerequisites: rustup nightly + `cargo install cargo-fuzz` (the CI
# image/install.sh carries them; a missing engine FAILS the nightly closed).
# `--smoke` needs only the stable workspace toolchain.
# =============================================================================
set -eu

CI_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPO_ROOT=$CI_ROOT
FUZZ_DIR="$REPO_ROOT/services/mail-server/crates/fuzz-tests/fuzz"
CORPUS_DIR="$FUZZ_DIR/corpus"
TARGET_DIR="$FUZZ_DIR/fuzz_targets"
ARTIFACT_DIR="$FUZZ_DIR/artifacts"
GENERATED_DIR="$REPO_ROOT/services/mail-server/crates/fuzz-tests/tests/generated"
SMOKE_TEST="$REPO_ROOT/services/mail-server/crates/fuzz-tests/tests/fuzz_smoke.rs"
WS="$REPO_ROOT/services/mail-server"

# Targets whose driver cannot live in the main workspace crate tree (the
# imap-proto-patched crate is a nested Cargo workspace). They still run in the
# nightly engine and keep their committed corpora; the fuzz-lite smoke test
# cannot link them and says so.
SMOKE_EXEMPT="fuzz_imap_response"

FUZZ_SECONDS=${FUZZ_SECONDS:-600}
MODE=nightly
FROM_ARTIFACT=''
ONLY_TARGETS=''
DRY_RUN=${CI_DRY_RUN:-0}

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case $1 in
        --smoke)        MODE=smoke; shift ;;
        --from-artifact) MODE=from-artifact; FROM_ARTIFACT=$2; shift 2 ;;
        --target)       ONLY_TARGETS=$2; shift 2 ;;
        --seconds)      FUZZ_SECONDS=$2; shift 2 ;;
        --targets)      ONLY_TARGETS=$2; shift 2 ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

log() { printf '[fuzz] %s\n' "$*"; }
warn() { printf '[fuzz] WARN: %s\n' "$*" >&2; }
die() { printf '[fuzz] ERROR: %s\n' "$*" >&2; exit 1; }

targets() {
    if [ -n "$ONLY_TARGETS" ]; then
        printf '%s\n' "$ONLY_TARGETS" | tr ',' ' '
        return
    fi
    for path in "$TARGET_DIR"/fuzz_*.rs; do
        [ -f "$path" ] || continue
        basename "$path" .rs
    done
}

# Corpus/target/target-list cross-checks: a target without a committed corpus
# (or a corpus without a target) is a harness that silently fuzzes nothing.
check_inventory() {
    for target in $(targets); do
        slug=${target#fuzz_}
        [ -f "$TARGET_DIR/$target.rs" ] || die "target $target has no fuzz_targets/$target.rs"
        [ -d "$CORPUS_DIR/$slug" ] || die "target $target has no committed corpus ($CORPUS_DIR/$slug)"
        find "$CORPUS_DIR/$slug" -type f | grep -q . \
            || die "target $target's corpus directory is empty"
    done

    if [ -f "$SMOKE_TEST" ]; then
        _listed=$(sed -n '/^const TARGETS: &\[&str\] = &\[/,/^\];/p' "$SMOKE_TEST" \
            | grep -o '"[a-z_]*"' | tr -d '"' | sort)
        _actual=$(targets | sort)
        for target in $_actual; do
            case " $SMOKE_EXEMPT " in
                *" $target "*) continue ;;
            esac
            slug=${target#fuzz_}
            printf '%s\n' "$_listed" | grep -qx "$slug" \
                || die "target $target is not in the fuzz-lite smoke TARGETS list ($SMOKE_TEST)"
        done
    fi
}

run_smoke() {
    check_inventory
    log "smoke: deterministic fuzz-lite over committed corpora + fixed seeded inputs"
    if [ "$DRY_RUN" = 1 ]; then
        log "dry-run: cargo nextest run -p fuzz-tests --test fuzz_smoke"
        return 0
    fi
    ( cd "$WS" && cargo nextest run -p fuzz-tests --test fuzz_smoke --no-fail-fast )
    log "smoke: PASS"
}

require_nightly() {
    command -v cargo-fuzz >/dev/null 2>&1 \
        || die "cargo-fuzz missing — install it (cargo install cargo-fuzz) to run the nightly engine"
    cargo +nightly --version >/dev/null 2>&1 \
        || die "rustup nightly missing — install it (rustup toolchain install nightly) for libFuzzer"
}

target_from_artifact() {
    # .../artifacts/<target>/crash-<hash> -> <target>
    _parent=$(basename "$(dirname "$1")")
    case $_parent in
        fuzz_*) printf '%s' "$_parent" ;;
        *) return 1 ;;
    esac
}

# Copy one crash artifact into the committed corpus and generate a compile-
# able regression test from it (for every target whose driver is linkable in
# the workspace crate).
commit_artifact() {
    _target=$1
    _artifact=$2
    case $_target in
        fuzz_smtp_*)      _driver=smtp_command ;;
        fuzz_mime_message) _driver=mime_message ;;
        fuzz_dkim_signature) _driver=dkim_signature ;;
        fuzz_spf_record)  _driver=spf_record ;;
        fuzz_dmarc_record) _driver=dmarc_record ;;
        fuzz_webhook_signature) _driver=webhook_signature ;;
        fuzz_template_source) _driver=template_source ;;
        fuzz_csv_report)  _driver=csv_report ;;
        fuzz_tracking_token) _driver=tracking_token ;;
        fuzz_mail_proto)  _driver=mail_proto ;;
        fuzz_imap_response) _driver='' ;;
        *) die "unknown target $_target — update commit_artifact in $0" ;;
    esac
    # smtp_envelope needs its own driver, not the command one.
    if [ "$_target" = fuzz_smtp_envelope ]; then
        _driver=smtp_envelope
    fi

    _name=$(basename "$_artifact")
    _slug=${_target#fuzz_}
    _dest_dir="$CORPUS_DIR/$_slug/regression"
    mkdir -p "$_dest_dir"
    cp "$_artifact" "$_dest_dir/$_name"
    log "committed artifact: $_dest_dir/$_name"

    if [ -z "$_driver" ]; then
        mkdir -p "$FUZZ_DIR/regressions"
        cat >"$FUZZ_DIR/regressions/${_name}.rs" <<EOF
// Regression skeleton generated from $_artifact on $(date -u +%Y-%m-%dT%H:%M:%SZ).
// The driver for $_target cannot be linked from the main workspace crate tree
// (imap-proto-patched is a nested workspace), so the committed corpus seed is
// replayed by the nightly engine:
//   cd services/mail-server/crates/fuzz-tests/fuzz
//   cargo fuzz run $_target corpus/$_target/regression/$_name
EOF
        return 0
    fi

    mkdir -p "$GENERATED_DIR"
    _file_slug=$(printf '%s' "$_name" | tr -c 'a-zA-Z0-9' '_' | cut -c1-60)
    _file="$GENERATED_DIR/regression_${_target}_${_file_slug}.rs"
    _rel="../../fuzz/corpus/$_slug/regression/$_name"
    cat >"$_file" <<EOF
//! GENERATED regression test from a real fuzzing crash.
//!
//! Artifact: $_artifact
//! Committed seed: $_dest_dir/$_name
//!
//! The audit's rule: every crash becomes a committed regression test before
//! its fix merges. This skeleton replays the exact crashing input through the
//! SAME driver the libFuzzer target calls, so the fix can never regress.
//!
//! Source: \`tools/run_fuzz_nightly.sh --from-artifact $_artifact\`.
#![allow(clippy::all)]

#[test]
fn regression_${_target}_${_file_slug}() {
    let input: &[u8] = include_bytes!("$_rel");
EOF
    case $_driver in
        webhook_signature)
            cat >>"$_file" <<'EOF'
    let split = input
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(input.len());
    let (header, payload) = input.split_at(split);
    let payload = payload.strip_prefix(b"\n").unwrap_or(payload);
    fuzz_tests::fuzz_api::webhook_signature(header, payload);
EOF
            ;;
        mail_proto)
            cat >>"$_file" <<'EOF'
    fuzz_tests::fuzz_api::mail_proto_decode(input);
EOF
            ;;
        *)
            cat >>"$_file" <<EOF
    fuzz_tests::fuzz_api::${_driver}(&String::from_utf8_lossy(input));
EOF
            ;;
    esac
    cat >>"$_file" <<'EOF'
}
EOF
    log "generated regression test: $_file"
}

run_from_artifact() {
    [ -n "$FROM_ARTIFACT" ] || die "--from-artifact needs a file path"
    [ -f "$FROM_ARTIFACT" ] || die "artifact not found: $FROM_ARTIFACT"
    _target=$ONLY_TARGETS
    if [ -z "$_target" ]; then
        _target=$(target_from_artifact "$FROM_ARTIFACT") \
            || die "cannot infer the target from $FROM_ARTIFACT — pass --target fuzz_<name>"
    fi
    [ -f "$TARGET_DIR/$_target.rs" ] || die "unknown target: $_target"
    log "from-artifact: $_target <- $FROM_ARTIFACT"
    if [ "$DRY_RUN" = 1 ]; then
        log "dry-run: would copy the artifact and generate the regression skeleton"
        return 0
    fi
    commit_artifact "$_target" "$FROM_ARTIFACT"
    log "next: fix the bug, then run the generated test + this target under the nightly engine"
}

run_nightly() {
    check_inventory
    [ "$DRY_RUN" = 1 ] || require_nightly
    _failed=0
    for target in $(targets); do
        log "=== $target: ${FUZZ_SECONDS}s ==="
        _before=$(find "$ARTIFACT_DIR/$target" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
        if [ "$DRY_RUN" = 1 ]; then
            log "dry-run: cargo +nightly fuzz run $target -max_total_time=$FUZZ_SECONDS -- -rss_limit_mb=2048"
            continue
        fi
        _rc=0
        ( cd "$FUZZ_DIR" && cargo +nightly fuzz run "$target" \
            -max_total_time="$FUZZ_SECONDS" -- -rss_limit_mb=2048 ) || _rc=$?
        _after=$(find "$ARTIFACT_DIR/$target" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
        if [ "$_rc" -ne 0 ] || [ "$_after" -gt "$_before" ]; then
            _failed=1
            warn "$target: FUZZER FOUND A CRASH (exit $_rc, artifacts before=$_before after=$_after)"
            for artifact in $(find "$ARTIFACT_DIR/$target" -maxdepth 1 -type f 2>/dev/null); do
                commit_artifact "$target" "$artifact"
            done
        else
            log "$target: no crash in ${FUZZ_SECONDS}s"
        fi
    done
    [ "$_failed" -eq 0 ] || die "nightly fuzzing found at least one crash — the artifacts + generated regression tests are committed; fix before merging"
    log "nightly: all targets clean"
}

case $MODE in
    smoke) run_smoke ;;
    from-artifact) run_from_artifact ;;
    nightly) run_nightly ;;
esac
