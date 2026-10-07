#!/usr/bin/env bash
# =============================================================================
# deploy/tests/deploy-unit-cleanup-selftest.sh — fixture for the manual
# deploy's systemd cleanup (audit P1 item 4).
# =============================================================================
# Runs the REAL remove_retired_bare_metal_units() (extracted verbatim from
# deploy/scripts/deploy.sh) against a synthetic unit directory and asserts:
#
#   1. the three retired bare-metal units (apexmail-{imap,mta,status}.service)
#      are removed;
#   2. the pipeline's own units (apexmail-pipeline.service, ...-webhook.service,
#      apexmail-tls-renew-restart.service/.path) SURVIVE;
#   3. TEETH: the pre-fix (HEAD) `rm -f /etc/systemd/system/apexmail-*.service`
#      would delete the pipeline units too (path-substituted to the fixture).
#
# No systemd, no host mutation: mktemp dir + a stub `systemctl` on PATH.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
_work="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-unit-cleanup-selftest.XXXXXX")"
if [[ "${ROLLBACK_SELFTEST_KEEP:-0}" == 1 ]]; then
    echo "deploy-unit-cleanup-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

_units="$_work/units"
mkdir -p "$_units" "$_work/bin"
for u in apexmail-imap apexmail-mta apexmail-status apexmail-tls-renew-restart \
         apexmail-pipeline apexmail-pipeline-webhook; do
    echo "# synthetic $u" > "$_units/$u.service"
done
echo "# synthetic path unit" > "$_units/apexmail-tls-renew-restart.path"
# a non-apexmail unit must never be touched
echo "# unrelated" > "$_units/other.service"

cat > "$_work/bin/systemctl" <<'STUB'
#!/bin/sh
# Records the calls; never touches the real systemd.
printf 'systemctl %s\n' "$*" >>"${SYSTEMCTL_LOG:?}"
exit 0
STUB
chmod +x "$_work/bin/systemctl"
export PATH="$_work/bin:$PATH"

_extract_fn() { # <file> <fn> <out>
    sed -n "/^${2}()/,/^}/p" "$1" >"$3"
    grep -q "^${2}()" "$3"
}

# --- run the REAL (fixed) cleanup --------------------------------------------
if _extract_fn "$REPO_ROOT/deploy/scripts/deploy.sh" remove_retired_bare_metal_units "$_work/fn.sh"; then
    : > "$_work/systemctl.log"
    SYSTEMD_UNIT_DIR="$_units" SYSTEMCTL_LOG="$_work/systemctl.log" bash -c '
        set -euo pipefail
        . "'"$_work"'/fn.sh"
        remove_retired_bare_metal_units
    ' >"$_work/out.log" 2>&1 || true
else
    _bad "could not extract remove_retired_bare_metal_units() from the live deploy.sh"
fi

for u in apexmail-imap apexmail-mta apexmail-status; do
    if [[ ! -e "$_units/$u.service" ]]; then
        _ok "cleanup: retired unit $u.service removed"
    else
        _bad "cleanup: retired unit $u.service survived"
    fi
done
for u in apexmail-pipeline.service apexmail-pipeline-webhook.service \
         apexmail-tls-renew-restart.service apexmail-tls-renew-restart.path \
         other.service; do
    if [[ -e "$_units/$u" ]]; then
        _ok "cleanup: $u survives"
    else
        _bad "cleanup: $u was deleted (the P1 glob bug)"
    fi
done
if grep -q 'daemon-reload' "$_work/systemctl.log"; then
    _ok "cleanup: systemd daemon-reload issued after the removals"
else
    _bad "cleanup: no daemon-reload after unit removals"
fi

# --- teeth: HEAD's glob deletes the pipeline units too -----------------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:deploy/scripts/deploy.sh 2>/dev/null; then
    _old_rm="$(git -C "$REPO_ROOT" show HEAD:deploy/scripts/deploy.sh \
        | grep -E '^rm -f /etc/systemd/system/apexmail-\*\.service' | head -1 || true)"
    if [[ -n "$_old_rm" ]]; then
        # path-substitute ONLY (the fixture cannot write /etc); the glob shape
        # under test is unchanged.
        _old_rm_sub="${_old_rm//\/etc\/systemd\/system/$_units}"
        mkdir -p "$_work/old-fixture"
        for u in apexmail-imap.service apexmail-pipeline.service \
                 apexmail-pipeline-webhook.service apexmail-tls-renew-restart.service; do
            echo "# synthetic" > "$_work/old-fixture/$u"
        done
        _old_rm_sub="${_old_rm_sub//$_units/$_work\/old-fixture}"
        bash -c "$_old_rm_sub" 2>/dev/null || true
        if [[ ! -e "$_work/old-fixture/apexmail-pipeline.service" ]]; then
            _ok "teeth: HEAD glob deleted apexmail-pipeline.service (bug reproduced)"
        else
            _bad "teeth: HEAD glob did not reproduce the pipeline-unit deletion"
        fi
    else
        _bad "teeth: could not locate the HEAD rm-glob line"
    fi
else
    echo "skip teeth probe: git/HEAD:deploy/scripts/deploy.sh unavailable" >&2
fi

if [[ "$_fail" -eq 0 ]]; then
    echo "deploy-unit-cleanup-selftest: ALL OK"
    exit 0
fi
echo "deploy-unit-cleanup-selftest: $_fail assertion(s) FAILED" >&2
exit 1
