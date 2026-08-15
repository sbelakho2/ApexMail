#!/usr/bin/env bash
# Regenerates the browser assets: assets/kiwicaptcha-wasm.js (the widget's
# embedded WASM + glue) and the KIWI_WORKER_SRC literal inside
# assets/widget-driver.js (generated from assets/kiwi-worker.js by the
# kiwicaptcha-embed-worker tool, audit round 16).
# Requires: cargo, the wasm32-unknown-unknown target, and wasm-bindgen-cli
# (a Rust binary; installed via `cargo install` if missing).
# Pure Rust pipeline — no Node.js, no wasm-pack.
set -euo pipefail
cd "$(dirname "$0")"

WASM_BINDGEN_VERSION="0.2.127"
WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:-wasm-bindgen}"

if ! command -v "$WASM_BINDGEN_BIN" >/dev/null 2>&1; then
  echo "wasm-bindgen-cli not found; installing ${WASM_BINDGEN_VERSION} via cargo (--locked)..." >&2
  cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked
fi

# Version-lock (audit round 14): a DIFFERENT wasm-bindgen binary already on
# the machine must never be silently accepted — the emitted glue is
# bindgen-version-specific, so a mismatched binary would produce release
# bytes that differ from the pinned build. The installed version is read
# from `wasm-bindgen --version` ("wasm-bindgen 0.2.127") and compared with
# the pin exactly. Set WASM_BINDGEN_BIN to point at the pinned binary when
# several are installed (e.g. ~/.cargo/bin/wasm-bindgen).
BINDGEN_INSTALLED="$("$WASM_BINDGEN_BIN" --version 2>/dev/null || true)"
BINDGEN_VERSION_READ="$(printf '%s' "$BINDGEN_INSTALLED" | sed -n 's/.*\(0\.2\.[0-9][0-9]*\).*/\1/p')"
if [ "$BINDGEN_VERSION_READ" != "$WASM_BINDGEN_VERSION" ]; then
  echo "wasm-bindgen version mismatch: found '$BINDGEN_INSTALLED', required ${WASM_BINDGEN_VERSION}" >&2
  echo "install the pinned version: cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION}" >&2
  echo "or set WASM_BINDGEN_BIN to the pinned binary (release bytes are bindgen-version-specific)" >&2
  exit 1
fi
echo "wasm-bindgen ${WASM_BINDGEN_VERSION} verified"

# Audit round 16: the embedded worker literal is regenerated from
# assets/kiwi-worker.js on every build (the standalone file is the source
# of truth; CI's --check step fails on any manual drift).
cargo run --release --locked --manifest-path tools/embed-worker/Cargo.toml --

cargo build --release --locked --target wasm32-unknown-unknown

# Optimize the wasm with binaryen (wasm-opt -O). wasm-opt is a C++ binary —
# NOT Node.js; -O typically shrinks the wasm ~20% and speeds up the hot
# solver loops. Download a pinned, checksum-verified wasm-opt on first use
# (no package managers, no runtime deps); the tarball is verified with
# SHA-256 before extraction. Audit round 22 wording: in NON-STRICT mode
# optimization may be SKIPPED when wasm-opt is unavailable/unverifiable (a
# larger, slower artifact — the build id changes, so a mixed-version
# deployment can never pair an optimized with an unoptimized artifact); in
# STRICT mode (WASM_OPT_STRICT=1, used by the release pipeline) a missing
# or unverifiable optimizer is FATAL. Set WASM_OPT_SHA256 to override the
# expected hash for any platform.
# Known hashes (computed with `shasum -a 256` at pin time):
#   Darwin-arm64  version_119: c12dffafb3e3274026268e90577bd86d98186f7be32457618672f8ca437d8d53
#   Linux-x86_64  version_119: 716bcf9f5f36a6f466239fbb09a925eeaf54c46411ccefac979ec649e7c06d2d
# Known hashes per platform (computed with `shasum -a 256` at pin time).
# Note: macOS ships GNU bash 3.2, which has no associative arrays, so the
# {"platform": "sha256"} map is expressed as a function (same semantics).
known_wasm_opt_sha256() {
  case "${OS}-${ARCH}" in
    Darwin-arm64) echo "c12dffafb3e3274026268e90577bd86d98186f7be32457618672f8ca437d8d53" ;;
    Linux-x86_64) echo "716bcf9f5f36a6f466239fbb09a925eeaf54c46411ccefac979ec649e7c06d2d" ;;
    *) echo "" ;;
  esac
}


sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
WASM_OPT_BIN="${WASM_OPT_BIN:-}"
# An env-supplied binary is NEVER downloaded/verified by us — in strict
# mode it must be authenticated by an explicit trusted executable SHA-256
# (WASM_OPT_BIN_SHA256) rather than its version text alone.
WASM_OPT_ENV_SUPPLIED=0
if [[ -n "$WASM_OPT_BIN" ]]; then
  WASM_OPT_ENV_SUPPLIED=1
fi
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/kiwicaptcha-wasm"
if [[ -z "$WASM_OPT_BIN" ]]; then
  WASM_OPT_BIN="$CACHE_DIR/wasm-opt"
fi

# Per-run verification (audit round 15): a PRE-EXISTING or CACHED wasm-opt
# is authenticated on EVERY build — the version string must be exactly the
# pinned binaryen (version_119), and a binary we downloaded ourselves must
# still match the SHA-256 recorded at download time (a replaced or
# corrupted cached executable fails closed instead of satisfying "strict").
verify_wasm_opt() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then return 1; fi
  local ver
  ver="$("$bin" --version 2>/dev/null || true)"
  case "$ver" in
    "wasm-opt version 119 "*|*"version_119"*) ;;
    *)
      echo "wasm-opt version mismatch: '$ver' (pinned: version_119)" >&2
      return 1
      ;;
  esac
  if [[ -f "$CACHE_DIR/wasm-opt.bin.sha256" ]]; then
    local expected actual
    expected="$(cat "$CACHE_DIR/wasm-opt.bin.sha256")"
    actual="$(sha256_of "$bin")"
    if [[ "$actual" != "$expected" ]]; then
      echo "wasm-opt executable SHA-256 mismatch (cached binary replaced or corrupted)" >&2
      return 1
    fi
  elif [[ "${WASM_OPT_STRICT:-0}" == "1" ]]; then
    # Audit rounds 16-17: in STRICT mode there is NO version-text-only
    # exception — the trusted executable hash is mandatory for EVERY
    # binary, whether env-supplied or cached.
    if [[ "$WASM_OPT_ENV_SUPPLIED" == "1" ]]; then
      # An externally supplied binary must be authenticated by an
      # EXPLICIT trusted SHA (WASM_OPT_BIN_SHA256) — version text alone
      # can be spoofed by an altered executable.
      if [[ -z "${WASM_OPT_BIN_SHA256:-}" ]]; then
        echo "WASM_OPT_STRICT=1 with an env-supplied WASM_OPT_BIN requires WASM_OPT_BIN_SHA256 (the trusted executable SHA-256)" >&2
        return 1
      fi
      local actual
      actual="$(sha256_of "$bin")"
      if [[ "$actual" != "$WASM_OPT_BIN_SHA256" ]]; then
        echo "wasm-opt executable SHA-256 mismatch (expected \$WASM_OPT_BIN_SHA256)" >&2
        return 1
      fi
    else
      # A cached/default binary without its trusted-hash record: delete it
      # so the next run redownloads from the pinned verified archive (or
      # fails) — an arbitrary replaced executable can never satisfy
      # "strict".
      echo "wasm-opt strict: cached executable lacks its trusted SHA-256 record — removing it for redownload" >&2
      rm -f "$bin"
      return 1
    fi
  fi
  return 0
}
if [[ ! -x "$WASM_OPT_BIN" ]]; then
  mkdir -p "$(dirname "$WASM_OPT_BIN")"
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  case "${OS}-${ARCH}" in
    Linux-x86_64)  WASM_OPT_ARCH="x86_64-linux" ;;
    Linux-aarch64) WASM_OPT_ARCH="aarch64-linux" ;;
    Darwin-arm64)  WASM_OPT_ARCH="arm64-macos" ;;
    Darwin-x86_64) WASM_OPT_ARCH="x86_64-macos" ;;
    *)             WASM_OPT_ARCH="" ;;
  esac
  if [[ -n "$WASM_OPT_ARCH" ]]; then
    WASM_OPT_VERSION="version_119"
    WASM_OPT_URL="https://github.com/WebAssembly/binaryen/releases/download/${WASM_OPT_VERSION}/binaryen-${WASM_OPT_VERSION}-${WASM_OPT_ARCH}.tar.gz"
    EXPECTED_SHA256="${WASM_OPT_SHA256:-$(known_wasm_opt_sha256)}"
    if [[ -z "$EXPECTED_SHA256" ]]; then
      echo "no known SHA-256 for ${OS}-${ARCH} — skipping optimization" >&2
      WASM_OPT_BIN=""
    elif curl -fsSL "$WASM_OPT_URL" -o "$CACHE_DIR/binaryen.tar.gz" 2>/dev/null; then
      ACTUAL_SHA256="$(sha256_of "$CACHE_DIR/binaryen.tar.gz")"
      if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
        echo "binaryen tarball SHA-256 mismatch (got $ACTUAL_SHA256, expected $EXPECTED_SHA256) — skipping optimization" >&2
        WASM_OPT_BIN=""
      else
        tar xzf "$CACHE_DIR/binaryen.tar.gz" -C "$CACHE_DIR"
        # wasm-opt links against libbinaryen (shared lib on macOS, static on
        # Linux); keep the extracted tree and reference the binary in place so
        # the rpath resolves regardless of platform.
        BIN_DIR="$(find "$CACHE_DIR" -path "*/bin/wasm-opt" -type f | head -1)"
        if [[ -n "$BIN_DIR" ]]; then
          WASM_OPT_BIN="$BIN_DIR"
          # Record the EXECUTABLE's hash (not just the tarball's) so every
          # later build can detect a replaced/corrupted cached binary.
          sha256_of "$WASM_OPT_BIN" > "$CACHE_DIR/wasm-opt.bin.sha256"
          echo "wasm-opt ready at $WASM_OPT_BIN (tarball + executable SHA-256 verified)"
        else
          echo "wasm-opt not found in binaryen archive — continuing without optimization" >&2
          WASM_OPT_BIN=""
        fi
      fi
    else
      echo "wasm-opt download failed — continuing without optimization" >&2
      WASM_OPT_BIN=""
    fi
  fi
fi
# Every resolved binary (freshly downloaded, cached, or env-provided) is
# authenticated per run before it may optimize a release artifact.
if [[ -n "$WASM_OPT_BIN" ]] && ! verify_wasm_opt "$WASM_OPT_BIN"; then
  echo "wasm-opt failed per-run verification — skipping optimization" >&2
  WASM_OPT_BIN=""
fi
# Release-build determinism (audit round 14): with WASM_OPT_STRICT=1 the
# pipeline FAILS instead of silently skipping optimization when wasm-opt is
# unavailable/unverifiable — a release build must either use the pinned
# binaryen at the known SHA-256 or not exist. GitHub CI (ubuntu-latest,
# x86_64-linux) now has a pinned hash, so a release job built there is
# byte-deterministic end to end.
if [[ "${WASM_OPT_STRICT:-0}" == "1" && ( -z "$WASM_OPT_BIN" || ! -x "$WASM_OPT_BIN" ) ]]; then
  echo "WASM_OPT_STRICT=1: wasm-opt unavailable/unverifiable — refusing to build a non-deterministic release" >&2
  exit 1
fi
if [[ -n "$WASM_OPT_BIN" && -x "$WASM_OPT_BIN" ]]; then
  "$WASM_OPT_BIN" -O target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm \
      -o target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.opt.wasm
  mv target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.opt.wasm \
     target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm
fi

"$WASM_BINDGEN_BIN" --target web --out-dir pkg target/wasm32-unknown-unknown/release/kiwicaptcha_wasm.wasm
cargo run --release --locked --manifest-path tools/embed/Cargo.toml -- pkg assets/kiwicaptcha-wasm.js
echo "assets/kiwicaptcha-wasm.js regenerated"

# Audit round 18: the core crate embeds the assets from ITS OWN
# resources/ directory (cargo package verification builds the tarball in
# isolation and cannot reach outside the crate) — keep the copies
# byte-identical; CI enforces it (widget-assets parity job).
cp assets/widget-driver.js assets/widget.css assets/kiwicaptcha-wasm.js ../kiwicaptcha/resources/
echo "kiwicaptcha core resources synced"
