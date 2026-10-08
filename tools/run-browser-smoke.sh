#!/usr/bin/env bash
# Browser smoke lane runner (browser_smoke.py).
#
# Usage against the compose stack (the api-server answers on 127.0.0.1:8080;
# the lane's own default of http://127.0.0.1:3000 is the legacy dev port):
#   BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 tools/run-browser-smoke.sh
#   BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 tools/run-browser-smoke.sh --group control-plane
# Authenticated mode (optional): BROWSER_TEST_WEB_COOKIE / BROWSER_TEST_CP_COOKIE
# carry session cookies and switch the gated checks from the login-gate
# assertions to the real console content.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${APEXMAIL_BROWSER_SMOKE_VENV:-$ROOT_DIR/.venv/browser-smoke}"
PYTHON_BIN="${PYTHON:-python3}"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

if ! "$VENV_DIR/bin/python" -m pip show playwright >/dev/null 2>&1; then
  "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
  "$VENV_DIR/bin/python" -m pip install playwright
fi

exec "$VENV_DIR/bin/python" "$ROOT_DIR/tools/browser_smoke.py" "$@"
