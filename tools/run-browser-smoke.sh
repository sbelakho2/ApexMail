#!/usr/bin/env bash
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
