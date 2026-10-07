#!/usr/bin/env bash
# =============================================================================
# deploy/tests/deploy-rollback-selftest.sh — dry-run harness for the manual
# deploy path's rollback override precedence + pin fallback (audit P1 item 3,
# P3 non-git deploy dir).
# =============================================================================
# Runs the REAL production functions (extracted verbatim from
# deploy/scripts/deploy.sh — the functions are self-contained; the full script
# needs bash 4 for `declare -A` and a live /opt/apexmail, so a function-level
# harness keeps the proof infrastructure-free) against a stub `docker` that
# records every invocation. Asserts:
#
#   1. rollback_images() does NOT compose with the Step-3.5 digest override
#      (which pins the failed new images — reusing it was the no-op bug);
#   2. it composes base + prod + its OWN rollback override pinning the
#      :pre-deploy baseline tags;
#   3. it still retags :pre-deploy → :latest for every image;
#   4. TEETH: the pre-fix (HEAD) rollback_images() DOES pass the digest
#      override to compose — the harness fails on the broken code;
#   5. fallback_pin_tag() yields a unique local tag when a repo digest is
#      unavailable (the non-git deploy dir path no longer hard-fails) and
#      returns non-zero when tagging fails.
#
# No docker daemon, no host mutation: mktemp dir + stub PATH.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
_work="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-manual-rollback-selftest.XXXXXX")"
if [[ "${ROLLBACK_SELFTEST_KEEP:-0}" == 1 ]]; then
    echo "deploy-rollback-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

# --- fixtures ----------------------------------------------------------------
mkdir -p "$_work/dep/ci/runs/selftest" "$_work/bin" "$_work/images"
: > "$_work/dep/.env"
_override="$_work/dep/ci/runs/selftest/docker-compose.digest-override.yml"
{
    echo "# synthetic Step 3.5 digest override (pins the FAILED images)"
    echo "services:"
    echo "  api-server:"
    echo "    image: ghcr.io/sbelakho2/apexmail/api-server:bbbb111122223333444455556666777788889999"
} > "$_override"

cat > "$_work/bin/docker" <<'STUB'
#!/bin/sh
_log=${STUB_LOG:?}
case "$1" in
    image)
        case "$2" in
            inspect)
                _key=$(printf '%s' "$3" | tr '/:' '__')
                [ -f "${STUB_IMAGES:?}/$_key" ] && exit 0
                exit 1
                ;;
            *) exit 0 ;;
        esac
        ;;
    tag)
        if [ "${STUB_TAG_FAIL:-0}" = 1 ]; then exit 1; fi
        printf 'tag %s %s\n' "$2" "$3" >>"$_log"
        exit 0
        ;;
    compose)
        shift
        printf 'compose %s\n' "$*" >>"$_log"
        exit 0
        ;;
    ps|rmi|prune|inspect|exec)
        printf 'docker-%s\n' "$1" >>"$_log"
        exit 0
        ;;
    *) exit 0 ;;
esac
STUB
chmod +x "$_work/bin/docker"
export PATH="$_work/bin:$PATH"

# Every image the script's ALL_IMAGES builds has a :pre-deploy baseline
# (mirror of the production list: all tags are :latest).
_all="ghcr.io/sbelakho2/apexmail/marketing:latest ghcr.io/sbelakho2/apexmail/tracking-service:latest
      ghcr.io/sbelakho2/apexmail/postgres-backup:latest ghcr.io/sbelakho2/apexmail/clickhouse-backup:latest
      ghcr.io/sbelakho2/apexmail/redis-backup:latest ghcr.io/sbelakho2/apexmail/analytics-backup:latest
      ghcr.io/sbelakho2/apexmail/api-server:latest ghcr.io/sbelakho2/apexmail/mta:latest
      ghcr.io/sbelakho2/apexmail/imap-server:latest ghcr.io/sbelakho2/apexmail/mailstore:latest
      ghcr.io/sbelakho2/apexmail/worker:latest ghcr.io/sbelakho2/apexmail/enterprise:latest
      ghcr.io/sbelakho2/apexmail/observability:latest ghcr.io/sbelakho2/apexmail/status-server:latest
      ghcr.io/sbelakho2/apexmail/billing-service:latest ghcr.io/sbelakho2/apexmail/sales-autopilot:latest
      ghcr.io/sbelakho2/apexmail/compliance:latest ghcr.io/sbelakho2/apexmail/analytics-worker:latest
      ghcr.io/sbelakho2/apexmail/pdf-renderer:latest ghcr.io/sbelakho2/apexmail/ai-service:latest
      ghcr.io/sbelakho2/apexmail/migrator:latest"
for _img in $_all; do
    : > "$_work/images/$(printf '%s' "${_img%:latest}:pre-deploy" | tr '/:' '__')"
done

_extract_fn() { # <file> <fn> <out> — extract one top-level function verbatim
    sed -n "/^${2}()/,/^}/p" "$1" >"$3"
    grep -q "^${2}()" "$3"
}

# --- run the REAL (fixed) rollback_images ------------------------------------
if _extract_fn "$REPO_ROOT/deploy/scripts/deploy.sh" rollback_images "$_work/new-fn.sh"; then
    : > "$_work/stub.log"
    STUB_LOG="$_work/stub.log" STUB_IMAGES="$_work/images" bash -c '
        set -euo pipefail
        warn()  { echo "warn $*" >&2; }
        error() { echo "error $*" >&2; }
        ROLLBACK_BASELINE=1
        NGINX_NAME=""
        ALL_IMAGES="'"$_all"'"
        ENV_FILE="'"$_work"'/dep/.env"
        MANUAL_RUN_DIR="'"$_work"'/dep/ci/runs/selftest"
        _override="'"$_override"'"
        COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml -f '"$_override"'"
        . "'"$_work"'/new-fn.sh"
        rollback_images
    ' >"$_work/out.log" 2>&1 || true
    _compose_up="$(grep '^compose .*up -d --remove-orphans' "$_work/stub.log" | head -1 || true)"
else
    _bad "could not extract rollback_images() from the live deploy.sh"
    _compose_up=""
fi

if [[ -n "$_compose_up" ]]; then
    _ok "deploy: rollback ran a compose up"
else
    _bad "deploy: no rollback compose up in the stub log — see $_work/out.log"
fi
if grep -q 'docker-compose.digest-override.yml' <<<"$_compose_up"; then
    _bad "deploy: rollback composed WITH the digest override (pins the failed images — the P1 no-op)"
else
    _ok "deploy: rollback does NOT compose with the Step-3.5 digest override"
fi
if grep -q 'docker-compose.rollback-override.yml' <<<"$_compose_up"; then
    _ok "deploy: rollback uses its own baseline-pinning override"
else
    _bad "deploy: rollback override missing from the compose up"
fi
if grep -q 'compose -f docker-compose.yml -f docker-compose.prod.yml ' <<<"$_compose_up" \
   && grep -q -- '--profile monitoring up -d --remove-orphans' <<<"$_compose_up"; then
    _ok "deploy: base + prod + rollback override with the monitoring profile"
else
    _bad "deploy: unexpected compose invocation: ${_compose_up:-none}"
fi
_rb_override="$_work/dep/ci/runs/selftest/docker-compose.rollback-override.yml"
if [[ -s "$_rb_override" ]] \
   && grep -q 'image: ghcr.io/sbelakho2/apexmail/api-server:pre-deploy' "$_rb_override" \
   && grep -q 'image: ghcr.io/sbelakho2/apexmail/tracking-service:pre-deploy' "$_rb_override"; then
    _ok "deploy: rollback override pins :pre-deploy baselines (incl. tracking-service key mapping)"
else
    _bad "deploy: rollback override content wrong — $(head -8 "$_rb_override" 2>/dev/null || echo missing)"
fi
if grep -q 'tag ghcr.io/sbelakho2/apexmail/api-server:pre-deploy ghcr.io/sbelakho2/apexmail/api-server:latest' "$_work/stub.log"; then
    _ok "deploy: :pre-deploy retagged back onto :latest"
else
    _bad "deploy: no :pre-deploy → :latest retag"
fi
if grep -q 'ROLLBACK COMPLETE' "$_work/out.log"; then
    _ok "deploy: rollback reported completion"
else
    _bad "deploy: no ROLLBACK COMPLETE in $_work/out.log"
fi

# --- teeth: HEAD's rollback_images() reuses the digest override --------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:deploy/scripts/deploy.sh 2>/dev/null; then
    git -C "$REPO_ROOT" show HEAD:deploy/scripts/deploy.sh > "$_work/old-deploy.sh"
    if _extract_fn "$_work/old-deploy.sh" rollback_images "$_work/old-fn.sh"; then
        : > "$_work/old-stub.log"
        STUB_LOG="$_work/old-stub.log" STUB_IMAGES="$_work/images" bash -c '
            set -euo pipefail
            warn()  { echo "warn $*" >&2; }
            error() { echo "error $*" >&2; }
            ROLLBACK_BASELINE=1
            NGINX_NAME=""
            ALL_IMAGES="'"$_all"'"
            ENV_FILE="'"$_work"'/dep/.env"
            COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml -f '"$_override"'"
            . "'"$_work"'/old-fn.sh"
            rollback_images
        ' >"$_work/old-out.log" 2>&1 || true
        _old_up="$(grep '^compose .*up -d --remove-orphans' "$_work/old-stub.log" | head -1 || true)"
        if grep -q 'docker-compose.digest-override.yml' <<<"$_old_up"; then
            _ok "teeth: HEAD rollback DOES compose with the digest override (bug reproduced)"
        else
            _bad "teeth: HEAD rollback did not reuse the digest override — harness lost its teeth (${_old_up:-no compose up})"
        fi
        if grep -q 'ROLLBACK COMPLETE' "$_work/old-out.log"; then
            _ok "teeth: HEAD rollback claims ROLLBACK COMPLETE while pinned to the failed images"
        else
            _bad "teeth: HEAD rollback did not reproduce the false success claim"
        fi
    else
        _bad "teeth: could not extract rollback_images() from HEAD"
    fi
else
    echo "skip teeth probe: git/HEAD:deploy/scripts/deploy.sh unavailable" >&2
fi

# --- fallback_pin_tag: the non-git deploy dir no longer hard-fails -----------
if _extract_fn "$REPO_ROOT/deploy/scripts/deploy.sh" fallback_pin_tag "$_work/fpt-fn.sh"; then
    : > "$_work/fpt-stub.log"
    _tag="$(STUB_LOG="$_work/fpt-stub.log" STUB_IMAGES="$_work/images" bash -c '
        set -euo pipefail
        . "'"$_work"'/fpt-fn.sh"
        fallback_pin_tag "ghcr.io/sbelakho2/apexmail/api-server:latest"
    ' 2>/dev/null || true)"
    if [[ "$_tag" == manual-* ]] && grep -q "tag ghcr.io/sbelakho2/apexmail/api-server:latest ghcr.io/sbelakho2/apexmail/api-server:${_tag}" "$_work/fpt-stub.log"; then
        _ok "fallback_pin_tag: tagged an unpinnable image with a unique local tag (${_tag})"
    else
        _bad "fallback_pin_tag: no manual tag produced (got '${_tag:-empty}')"
    fi
    _rc=0
    STUB_TAG_FAIL=1 STUB_LOG="$_work/fpt-stub.log" bash -c '
        set -euo pipefail
        . "'"$_work"'/fpt-fn.sh"
        fallback_pin_tag "ghcr.io/sbelakho2/apexmail/api-server:latest"
    ' >/dev/null 2>&1 || _rc=$?
    if [[ "$_rc" -ne 0 ]]; then
        _ok "fallback_pin_tag: returns non-zero when tagging fails (caller warns/skips)"
    else
        _bad "fallback_pin_tag: reported success when docker tag failed"
    fi
else
    _bad "could not extract fallback_pin_tag() from the live deploy.sh"
fi

if [[ "$_fail" -eq 0 ]]; then
    echo "deploy-rollback-selftest: ALL OK"
    exit 0
fi
echo "deploy-rollback-selftest: $_fail assertion(s) FAILED" >&2
exit 1
