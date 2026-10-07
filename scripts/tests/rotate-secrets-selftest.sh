#!/usr/bin/env bash
# =============================================================================
# scripts/tests/rotate-secrets-selftest.sh — local dry-run for
# scripts/rotate-secrets.sh backup/rollback (audit P1 item 5).
# =============================================================================
# In a temp dep dir with a real rendered-secret file and a stub `docker`:
#
#   1. rotate (--api-key-hash) then rollback restores the ORIGINAL contents;
#   2. the backup dir contains an index.txt naming the rotated key;
#   3. TEETH: the pre-fix (HEAD) script snapshots zero files (no index.txt)
#      and --rollback exits 1 — the failure the fix removes;
#   4. an action whose PROD_*_FILE does not exist hard-fails BEFORE writing
#      anything (no silent rotation without a recoverable copy).
#
# No docker, no production access: mktemp dir + stub PATH.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
_work="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-rotate-selftest.XXXXXX")"
if [[ "${ROTATE_SELFTEST_KEEP:-0}" == 1 ]]; then
    echo "rotate-secrets-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

mkdir -p "$_work/bin" "$_work/dep/secrets"
cat > "$_work/bin/docker" <<'STUB'
#!/bin/sh
# Every docker invocation succeeds and is recorded; no daemon is touched.
printf 'docker %s\n' "$*" >>"${DOCKER_LOG:?}"
exit 0
STUB
chmod +x "$_work/bin/docker"
export PATH="$_work/bin:$PATH"

_secret="$_work/dep/secrets/api_key_hash_secret.txt"
_old_value='old-secret-value-0123456789abcdef'
printf '%s' "$_old_value" > "$_secret"
cat > "$_work/dep/.env" <<EOF
PROD_API_KEY_HASH_SECRET_FILE=$_secret
EOF

_run() { # <script> <backup_dir> [args...]
    local _script="$1" _backup="$2"; shift 2
    DOCKER_LOG="$_work/docker.log" DEPLOY_DIR="$_work/dep" ENV_FILE="$_work/dep/.env" \
        BACKUP_DIR="$_backup" bash "$_script" "$@"
}

# --- 1+2. rotate then rollback restores the file -----------------------------
_rc=0
_run "$REPO_ROOT/scripts/rotate-secrets.sh" "$_work/backups" --api-key-hash --force \
    >"$_work/rotate.log" 2>&1 || _rc=$?
if [[ "$_rc" -eq 0 ]]; then
    _ok "rotate: --api-key-hash exited 0"
else
    _bad "rotate: --api-key-hash exited $_rc — $(tail -3 "$_work/rotate.log")"
fi
_new_value="$(cat "$_secret")"
if [[ -n "$_new_value" && "$_new_value" != "$_old_value" ]]; then
    _ok "rotate: secret file content changed"
else
    _bad "rotate: secret file did not change"
fi
_latest="$(ls -td "$_work/backups"/*/ 2>/dev/null | head -1 || true)"
if [[ -s "${_latest:-/nonexistent}/index.txt" ]] && grep -q 'PROD_API_KEY_HASH_SECRET_FILE' "${_latest}/index.txt"; then
    _ok "rotate: backup index.txt records the rotated key ($(wc -l < "${_latest}/index.txt" | tr -d ' ') entry)"
else
    _bad "rotate: backup index.txt missing/empty — $(ls -la "$_work/backups" 2>/dev/null | tail -3)"
fi

_rc=0
_run "$REPO_ROOT/scripts/rotate-secrets.sh" "$_work/backups" --rollback >"$_work/rollback.log" 2>&1 || _rc=$?
if [[ "$_rc" -eq 0 && "$(cat "$_secret")" == "$_old_value" ]]; then
    _ok "rollback: restored the original secret contents"
else
    _bad "rollback: exit $_rc, content '$(cat "$_secret")' (expected the original)"
fi

# --- 3. teeth: HEAD snapshots zero files and cannot roll back ----------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:scripts/rotate-secrets.sh 2>/dev/null; then
    git -C "$REPO_ROOT" show HEAD:scripts/rotate-secrets.sh > "$_work/old-rotate.sh"
    # Local shell is bash 3.2 on macOS, where `set -u` + an EMPTY array makes
    # `for x in "${arr[@]}"` abort ("unbound variable"); on the deploy host's
    # bash >= 4.4 the same loop iterates zero times (the audited behavior).
    # The `${arr[@]+"${arr[@]}"}` shim is a no-op on bash >= 4.4 and makes this
    # machine reproduce the deploy-host semantics; the code under test is
    # otherwise byte-identical to HEAD.
    perl -0pi -e 's/for key in "\$\{BACKUP_KEYS\[@\]\}"; do/for key in \$\{BACKUP_KEYS[\@]+"\$\{BACKUP_KEYS[\@]\}"\}; do/' \
        "$_work/old-rotate.sh"
    if ! grep -q 'BACKUP_KEYS\[@\]+' "$_work/old-rotate.sh"; then
        _bad "teeth: could not apply the bash-3.2 empty-array shim to HEAD's script"
    fi
    printf '%s' "$_old_value" > "$_secret"
    _rc=0
    _run "$_work/old-rotate.sh" "$_work/old-backups" --api-key-hash --force \
        >"$_work/old-rotate.log" 2>&1 || _rc=$?
    if [[ "$_rc" -eq 0 ]] && grep -q '(0 files' "$_work/old-rotate.log"; then
        _ok "teeth: HEAD rotate reports a 0-file backup"
    else
        _bad "teeth: HEAD rotate did not reproduce the empty backup (exit $_rc)"
    fi
    _old_latest="$(ls -td "$_work/old-backups"/*/ 2>/dev/null | head -1 || true)"
    if [[ -n "$_old_latest" && ! -f "$_old_latest/index.txt" ]]; then
        _ok "teeth: HEAD backup has no index.txt (rollback target unrecoverable)"
    else
        _bad "teeth: HEAD backup unexpectedly carried an index.txt"
    fi
    _rc=0
    _run "$_work/old-rotate.sh" "$_work/old-backups" --rollback >"$_work/old-rollback.log" 2>&1 || _rc=$?
    if [[ "$_rc" -ne 0 ]] && grep -q 'No backup found to roll back to' "$_work/old-rollback.log"; then
        _ok "teeth: HEAD --rollback cannot find a backup (bug reproduced)"
    else
        _bad "teeth: HEAD --rollback exited $_rc — expected the 'No backup found' failure"
    fi
else
    echo "skip teeth probe: git/HEAD:scripts/rotate-secrets.sh unavailable" >&2
fi

# --- 4. missing PROD_*_FILE hard-fails before writing ------------------------
cat > "$_work/dep/.env" <<EOF
PROD_API_KEY_HASH_SECRET_FILE=$_work/dep/secrets/does-not-exist.txt
EOF
printf '%s' "$_old_value" > "$_secret"
_rc=0
_run "$REPO_ROOT/scripts/rotate-secrets.sh" "$_work/backups2" --api-key-hash --force \
    >"$_work/missing.log" 2>&1 || _rc=$?
if [[ "$_rc" -ne 0 ]] && grep -q 'secrets backup is EMPTY' "$_work/missing.log"; then
    _ok "missing file: hard-fails before rotating (no silent unrecoverable rotation)"
else
    _bad "missing file: exit $_rc without the empty-backup refusal"
fi
if grep -q 'Rotation complete' "$_work/missing.log"; then
    _bad "missing file: rotation still reported complete"
else
    _ok "missing file: no 'Rotation complete' claim"
fi

if [[ "$_fail" -eq 0 ]]; then
    echo "rotate-secrets-selftest: ALL OK"
    exit 0
fi
echo "rotate-secrets-selftest: $_fail assertion(s) FAILED" >&2
exit 1
