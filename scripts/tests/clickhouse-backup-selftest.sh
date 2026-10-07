#!/bin/sh
# =============================================================================
# scripts/tests/clickhouse-backup-selftest.sh — fixture for
# scripts/clickhouse-backup.sh (audit P2 item 9).
# =============================================================================
# Stubs `clickhouse-client` and asserts:
#
#   1. a FAILING table-listing query exits non-zero, prints ERROR and never
#      claims "Backup complete" (the old script reported success on an empty
#      backup);
#   2. an EMPTY database likewise refuses to report an empty backup;
#   3. a healthy run succeeds, writes a verified manifest and prunes only
#      afterwards — a failed run does NOT prune an older good archive;
#   4. TEETH: the pre-fix (HEAD) script does exactly the opposite: exit 0,
#      "Backup complete", and the older good archive pruned.
#
# No ClickHouse, no network: stub PATH + mktemp dir.
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-chbackup-selftest.XXXXXX")
if [ "${CHBACKUP_SELFTEST_KEEP:-0}" = 1 ]; then
    echo "clickhouse-backup-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

mkdir -p "$_work/bin"
cat > "$_work/bin/clickhouse-client" <<'STUB'
#!/bin/sh
# $@: --host ... --port ... --user ... --query "<sql>"
_sql=''
for _a in "$@"; do _sql=$_a; done
case "$_sql" in
    *system.tables*)
        case "${CH_STUB_MODE:-ok}" in
            fail)  echo "Code: 516. DB::Exception: Authentication failed" >&2; exit 210 ;;
            empty) exit 0 ;;
            ok)    printf 'apexmail\tusers\napexmail\tsessions\n' ;;
        esac
        ;;
    "SHOW CREATE TABLE"*) echo "CREATE TABLE ${_sql##*TABLE } (id UInt64) ENGINE = MergeTree ORDER BY id" ;;
    *"FORMAT Native"*)    printf 'native-data-bytes' ;;
    *) exit 0 ;;
esac
STUB
chmod +x "$_work/bin/clickhouse-client"
export PATH="$_work/bin:$PATH"

_run_backup() { # <script> <backup_dir>
    CLICKHOUSE_PASSWORD=test-password BACKUP_DIR="$2" BACKUP_RETENTION_DAYS=0 \
        sh "$1" backup >"$_work/out.log" 2>&1
}

# an older GOOD archive that must survive a failed run
_old_archive=""
_seed_old_archive() {
    _old_archive="$1/20200101_000000"
    mkdir -p "$_old_archive"
    printf 'apexmail\tusers\n' > "$_old_archive/manifest"
    printf 'CREATE TABLE users (id UInt64)' > "$_old_archive/1.schema.sql"
    printf 'data' > "$_old_archive/1.data.native"
    touch -t 202001010000 "$_old_archive"
}

# --- 1. failing query --------------------------------------------------------
_seed_old_archive "$_work/backups-a"
_rc=0
CH_STUB_MODE=fail _run_backup "$REPO_ROOT/scripts/clickhouse-backup.sh" "$_work/backups-a" || _rc=$?
if [ "$_rc" -ne 0 ]; then
    _ok "fail mode: exits non-zero ($_rc)"
else
    _bad "fail mode: exited 0 on a failed query"
fi
if grep -q 'ERROR' "$_work/out.log"; then
    _ok "fail mode: reports ERROR"
else
    _bad "fail mode: no ERROR in output"
fi
if grep -q 'Backup complete' "$_work/out.log"; then
    _bad "fail mode: still claims 'Backup complete'"
else
    _ok "fail mode: no false success claim"
fi
if [ -e "$_old_archive" ]; then
    _ok "fail mode: older good archive NOT pruned"
else
    _bad "fail mode: pruned the older good archive"
fi
if [ -n "$(find "$_work/backups-a" -mindepth 1 -maxdepth 1 -type d ! -name 20200101_000000 2>/dev/null)" ]; then
    _bad "fail mode: left a partial backup directory behind"
else
    _ok "fail mode: partial backup directory removed"
fi

# --- 2. empty database -------------------------------------------------------
_rc=0
CH_STUB_MODE=empty _run_backup "$REPO_ROOT/scripts/clickhouse-backup.sh" "$_work/backups-b" || _rc=$?
if [ "$_rc" -ne 0 ] && grep -q 'refusing to report an empty backup' "$_work/out.log"; then
    _ok "empty mode: refuses to report an empty backup"
else
    _bad "empty mode: exit $_rc without the empty-backup refusal"
fi

# --- 3. healthy run ----------------------------------------------------------
_rc=0
CH_STUB_MODE=ok _run_backup "$REPO_ROOT/scripts/clickhouse-backup.sh" "$_work/backups-c" || _rc=$?
if [ "$_rc" -eq 0 ] && grep -q 'Backup complete' "$_work/out.log"; then
    _new_archive=$(ls -d "$_work/backups-c"/*/ 2>/dev/null | head -1)
    if [ -f "${_new_archive}manifest" ] && [ -s "${_new_archive}1.schema.sql" ]; then
        _ok "ok mode: verified backup written ($(wc -l < "${_new_archive}manifest" | tr -d ' ') tables)"
    else
        _bad "ok mode: manifest/schema missing"
    fi
else
    _bad "ok mode: healthy run failed (exit $_rc)"
fi

# --- 4. teeth: HEAD prunes the good archive on a failed backup ---------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:scripts/clickhouse-backup.sh 2>/dev/null; then
    git -C "$REPO_ROOT" show HEAD:scripts/clickhouse-backup.sh > "$_work/old-backup.sh"
    _seed_old_archive "$_work/backups-old"
    _rc=0
    CH_STUB_MODE=fail _run_backup "$_work/old-backup.sh" "$_work/backups-old" || _rc=$?
    if [ "$_rc" -eq 0 ] && grep -q 'Backup complete' "$_work/out.log"; then
        _ok "teeth: HEAD reports success on a FAILED query (exit 0 + 'Backup complete')"
    else
        _bad "teeth: HEAD did not reproduce the false success (exit $_rc)"
    fi
    if [ -e "$_old_archive" ]; then
        _bad "teeth: HEAD did not prune the older archive — prune-after-failure not reproduced"
    else
        _ok "teeth: HEAD pruned the older good archive after the failed backup"
    fi
else
    echo "skip teeth probe: git/HEAD:scripts/clickhouse-backup.sh unavailable" >&2
fi

if [ "$_fail" -eq 0 ]; then
    echo "clickhouse-backup-selftest: ALL OK"
    exit 0
fi
echo "clickhouse-backup-selftest: $_fail assertion(s) FAILED" >&2
exit 1
