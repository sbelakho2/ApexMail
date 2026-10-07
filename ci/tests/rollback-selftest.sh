#!/bin/sh
# =============================================================================
# ci/tests/rollback-selftest.sh — synthetic image fixture for the pipeline's
# verify-stage auto-rollback contract (audit P1 items 1-2).
# =============================================================================
# Proves, against the REAL production functions and a stub `docker`:
#
#   1. ci/stages/deploy.sh record_deploy_state() captures the previously
#      VERIFIED sha into $RUN_DIR/pre-deploy-sha before the new rollout (the
#      file whose absence made the rollback trigger dead) and records the new
#      sha in $RUN_DIR/deployed-sha without touching .last-deployed-sha.
#   2. ci/stages/verify.sh rollback_to_previous_sha() retags the rollback
#      target — including the compose key `tracking` → image
#      `tracking-service` mapping that the old loop got wrong.
#   3. A missing CANONICAL image ABORTS the rollback (no compose up, no
#      "ROLLBACK COMPLETE"): the policy is no longer inverted.
#   4. A missing EXTRA_ROLLBACK_IMAGES name only warns and the rollback still
#      completes.
#   5. With no pre-deploy-sha and .last-deployed-sha == the running sha, the
#      rollback refuses (no previous verified target) — the old trigger's
#      only reachable branch, now honest.
#   6. The rollback path never advances .last-deployed-sha (only a green
#      verify does).
#
# No docker daemon, no network, no host mutation: everything lives in a
# mktemp dir and the stub PATH. Exit 0 = all assertions hold.
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
DEPLOY_STAGE="$REPO_ROOT/ci/stages/deploy.sh"
VERIFY_STAGE="$REPO_ROOT/ci/stages/verify.sh"

_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-rollback-selftest.XXXXXX")
if [ "${ROLLBACK_SELFTEST_KEEP:-0}" = 1 ]; then
    echo "rollback-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()   { printf 'ok   %s\n' "$*"; }
_bad()  { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

# --- stub docker -------------------------------------------------------------
mkdir -p "$_work/bin" "$_work/images"
cat >"$_work/bin/docker" <<'STUB'
#!/bin/sh
# Records invocations; image existence is decided by marker files under
# $STUB_IMAGES named <repo>__<tag> with '/' and ':' replaced by '_'.
_log=${STUB_LOG:?}
case "$1" in
    image)
        case "$2" in
            inspect)
                _ref=$3
                _key=$(printf '%s' "$_ref" | tr '/:' '__')
                [ -f "${STUB_IMAGES:?}/$_key" ] && exit 0
                exit 1
                ;;
            *) exit 0 ;;
        esac
        ;;
    tag)
        printf 'tag %s %s\n' "$2" "$3" >>"$_log"
        exit 0
        ;;
    compose)
        shift
        printf 'compose %s\n' "$*" >>"$_log"
        exit 0
        ;;
    *) exit 0 ;;
esac
STUB
chmod +x "$_work/bin/docker"
export PATH="$_work/bin:$PATH"

# --- fixture ci_root (lib.sh contract + the state file) ----------------------
_ci_root="$_work/ci"
mkdir -p "$_ci_root" "$_work/run"
ln -s "$REPO_ROOT/ci/lib.sh" "$_ci_root/lib.sh"

PREV_SHA="aaaa111122223333444455556666777788889999"
NEW_SHA="bbbb111122223333444455556666777788889999"

_make_images() {
    # $1 = sha, $2 = "missing-service-key" or "-"
    rm -rf "$_work/images"
    mkdir -p "$_work/images"
    # real canonical key→image mapping, read from the stage under test
    # (drop the leading VAR= of the assignment's first line)
    _svcs=$(sed -n '/^VERIFY_SERVICES=/,/"$/p' "$VERIFY_STAGE" | tr -d '"' | sed 's/^[A-Z_]*=//' | tr '\n' ' ')
    for _key in $_svcs; do
        _img=$_key
        [ "$_key" = tracking ] && _img=tracking-service   # the one divergence
        [ "$_key" = "$2" ] && continue
        # marker name = the ref with '/' and ':' folded to '_' (stub contract)
        : >"$_work/images/ghcr.io_sbelakho2_apexmail_${_img}_$1"
    done
}

_run_rollback() {
    # $1 = stub log file, $2 = output log name (stderr/stdout capture)
    _rc=0
    STUB_LOG="$1" STUB_IMAGES="$_work/images" CI_ROOT="$_ci_root" RUN_DIR="$_work/run" \
        CI_SHA="${CI_SHA:?}" CI_ROLLBACK_ON_VERIFY_FAIL=1 \
        CI_STAGE_LOG="$_work/stage.log" \
        EXTRA_ROLLBACK_IMAGES="${EXTRA_ROLLBACK_IMAGES:-}" \
        CI_VERIFY_ROLLBACK_SELFTEST=1 sh "$VERIFY_STAGE" >"$_work/$2" 2>&1 || _rc=$?
    return "$_rc"
}

# --- 1. deploy stage: capture the pre-deploy VERIFIED sha --------------------
printf '%s\n' "$PREV_SHA" >"$_ci_root/.last-deployed-sha"
rm -f "$_work/run/pre-deploy-sha" "$_work/run/deployed-sha"
CI_ROOT="$_ci_root" RUN_DIR="$_work/run" CI_SHA="$NEW_SHA" CI_DEPLOY_STATE_SELFTEST=1 \
    sh "$DEPLOY_STAGE" >"$_work/deploy-state.log" 2>&1 || true
if [ "$(tr -d '[:space:]' <"$_work/run/pre-deploy-sha" 2>/dev/null)" = "$PREV_SHA" ]; then
    _ok "deploy: pre-deploy-sha captured the previously verified sha"
else
    _bad "deploy: pre-deploy-sha missing/wrong — $(cat "$_work/run/pre-deploy-sha" 2>/dev/null || echo missing)"
fi
if [ "$(tr -d '[:space:]' <"$_work/run/deployed-sha" 2>/dev/null)" = "$NEW_SHA" ]; then
    _ok "deploy: deployed-sha recorded this run's rollout sha"
else
    _bad "deploy: deployed-sha missing/wrong"
fi
if [ "$(tr -d '[:space:]' <"$_ci_root/.last-deployed-sha")" = "$PREV_SHA" ]; then
    _ok "deploy: .last-deployed-sha NOT advanced before verification"
else
    _bad "deploy: .last-deployed-sha was overwritten before verify (the P1 bug)"
fi

# --- 2. all canonical images present: rollback retags everything -------------
_make_images "$PREV_SHA" "-"
: >"$_work/log-a"
CI_SHA="$NEW_SHA" _run_rollback "$_work/log-a" out-a.log || true
if grep -q "tag ghcr.io/sbelakho2/apexmail/tracking-service:${PREV_SHA} ghcr.io/sbelakho2/apexmail/tracking-service:latest" "$_work/log-a"; then
    _ok "rollback: compose key 'tracking' inspected/retagged as image 'tracking-service'"
else
    _bad "rollback: tracking-service was NOT retagged (the P1 mapping bug)"
fi
if grep -q "tag ghcr.io/sbelakho2/apexmail/tracking:${PREV_SHA}" "$_work/log-a"; then
    _bad "rollback: retagged the nonexistent 'tracking' image repository"
else
    _ok "rollback: no retag of the nonexistent 'tracking:<sha>' image"
fi
if grep -q "up -d --remove-orphans" "$_work/log-a" && grep -q "ROLLBACK COMPLETE" "$_work/out-a.log"; then
    _ok "rollback: compose up ran and completed with all canonical images present"
else
    _bad "rollback: expected compose up + ROLLBACK COMPLETE"
fi
if grep -q "redis-backup" "$_work/log-a"; then
    _ok "rollback: canonical list includes the backup schedulers (redis-backup)"
else
    _bad "rollback: backup schedulers missing from the rollback compose up"
fi

# --- 3. missing CANONICAL image aborts ---------------------------------------
_make_images "$PREV_SHA" "mta"
: >"$_work/log-b"
CI_SHA="$NEW_SHA" _run_rollback "$_work/log-b" out-b.log || true
if grep -q "ROLLBACK ABORTED" "$_work/out-b.log"; then
    _ok "rollback: missing canonical image (mta) aborts"
else
    _bad "rollback: missing canonical image did NOT abort"
fi
if grep -q "up -d --remove-orphans" "$_work/log-b"; then
    _bad "rollback: compose up ran despite a missing canonical image (mixed-version stack)"
else
    _ok "rollback: no compose up after the abort"
fi
if grep -q "ROLLBACK COMPLETE" "$_work/out-b.log"; then
    _bad "rollback: claimed COMPLETE despite a missing canonical image"
else
    _ok "rollback: no false COMPLETE claim"
fi

# --- 4. missing EXTRA image only warns, rollback still completes --------------
_make_images "$PREV_SHA" "redis"
: >"$_work/log-c"
CI_SHA="$NEW_SHA" EXTRA_ROLLBACK_IMAGES="redis" _run_rollback "$_work/log-c" out-c.log || true
if grep -q "ROLLBACK COMPLETE" "$_work/out-c.log" && ! grep -q "ROLLBACK ABORTED" "$_work/out-c.log"; then
    _ok "rollback: missing EXTRA_ROLLBACK_IMAGES name (redis) warns only"
else
    _bad "rollback: EXTRA missing name aborted the rollback (policy inverted)"
fi

# --- 5. no pre-deploy-sha + .last-deployed-sha == CI_SHA refuses --------------
rm -f "$_work/run/pre-deploy-sha"
printf '%s\n' "$NEW_SHA" >"$_ci_root/.last-deployed-sha"
_make_images "$PREV_SHA" "-"
: >"$_work/log-d"
CI_SHA="$NEW_SHA" _run_rollback "$_work/log-d" out-d.log || true
if grep -q "no previous VERIFIED sha" "$_work/out-d.log" && ! grep -q "tag " "$_work/log-d"; then
    _ok "rollback: refuses when the only recorded sha is the running one"
else
    _bad "rollback: did not refuse the self-referential trigger"
fi

# --- 6. rollback never advances .last-deployed-sha ----------------------------
if [ "$(tr -d '[:space:]' <"$_ci_root/.last-deployed-sha")" = "$NEW_SHA" ]; then
    _ok "rollback: .last-deployed-sha untouched by the failure path"
else
    _bad "rollback: .last-deployed-sha changed during rollback"
fi

# --- 7. teeth: the PRE-FIX (HEAD) verify.sh fails the same fixture ------------
# A fixture that passes on the fixed code proves nothing unless it fails on
# the broken code. HEAD's verify.sh is extracted, the rollback call is
# injected in place of its stage_main, and the SAME image fixture is run: the
# old loop must (a) never retag tracking-service and (b) still claim
# "ROLLBACK COMPLETE" with a canonical image missing.
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e "HEAD:ci/stages/verify.sh" 2>/dev/null; then
    git -C "$REPO_ROOT" show "HEAD:ci/stages/verify.sh" >"$_work/old-verify.sh"
    awk '/^stage_main$/ && !_done { print "rollback_to_previous_sha; exit 0"; _done=1 } { print }' \
        "$_work/old-verify.sh" >"$_work/old-verify-hooked.sh"
    if grep -q 'rollback_to_previous_sha; exit 0' "$_work/old-verify-hooked.sh"; then
        _make_images "$PREV_SHA" "-"
        printf '%s\n' "$PREV_SHA" >"$_ci_root/.last-deployed-sha"
        : >"$_work/old-log-a"
        STUB_LOG="$_work/old-log-a" STUB_IMAGES="$_work/images" CI_ROOT="$_ci_root" \
            RUN_DIR="$_work/run" CI_SHA="$NEW_SHA" CI_STAGE_LOG="$_work/stage.log" \
            CI_ROLLBACK_ON_VERIFY_FAIL=1 EXTRA_ROLLBACK_IMAGES='' \
            sh "$_work/old-verify-hooked.sh" >"$_work/old-out-a.log" 2>&1 || true
        if grep -q "tag ghcr.io/sbelakho2/apexmail/tracking-service:${PREV_SHA}" "$_work/old-log-a"; then
            _bad "teeth: HEAD verify.sh unexpectedly retagged tracking-service (fixture no longer discriminates)"
        else
            _ok "teeth: HEAD verify.sh does NOT retag tracking-service (bug reproduced)"
        fi
        if grep -q "ROLLBACK COMPLETE" "$_work/old-out-a.log"; then
            _ok "teeth: HEAD verify.sh claims ROLLBACK COMPLETE with tracking left on the new image"
        else
            _bad "teeth: HEAD verify.sh did not reproduce the silent-skip success claim"
        fi
        _make_images "$PREV_SHA" "mta"
        : >"$_work/old-log-b"
        STUB_LOG="$_work/old-log-b" STUB_IMAGES="$_work/images" CI_ROOT="$_ci_root" \
            RUN_DIR="$_work/run" CI_SHA="$NEW_SHA" CI_STAGE_LOG="$_work/stage.log" \
            CI_ROLLBACK_ON_VERIFY_FAIL=1 EXTRA_ROLLBACK_IMAGES='' \
            sh "$_work/old-verify-hooked.sh" >"$_work/old-out-b.log" 2>&1 || true
        if grep -q "up -d --remove-orphans" "$_work/old-log-b" && grep -q "ROLLBACK COMPLETE" "$_work/old-out-b.log"; then
            _ok "teeth: HEAD verify.sh retags a SUBSET and claims COMPLETE (missing canonical not fatal)"
        else
            _bad "teeth: HEAD verify.sh did not reproduce the missing-canonical silent skip"
        fi
    else
        _bad "teeth: could not inject the rollback probe into HEAD verify.sh"
    fi
else
    echo "skip teeth probe: git/HEAD:ci/stages/verify.sh unavailable" >&2
fi

if [ "$_fail" -eq 0 ]; then
    echo "rollback-selftest: ALL OK"
    exit 0
fi
echo "rollback-selftest: $_fail assertion(s) FAILED" >&2
exit 1
