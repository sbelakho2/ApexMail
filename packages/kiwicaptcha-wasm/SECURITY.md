# KiwiCaptcha WASM — Security & Supply-Chain Notes

This package ships four browser assets (`assets/`):

| Asset | Purpose |
|---|---|
| `kiwicaptcha-wasm.js` | wasm-bindgen glue with the Argon2id/SHA-256 solver wasm inlined as base64; also carries the embedded worker source as `window.__kiwiCaptchaWasm.workerSource` (generated from `kiwi-worker.js`). |
| `kiwi-worker.js` | standalone same-origin worker solver; served as the versioned `worker.<hash>.js` asset in files mode. |
| `widget-driver.js` | the widget driver and the solver protocol id; reads the worker source off the glue (inline mode) or fetches the worker asset (files mode) — it no longer embeds the worker bytes. |
| `widget.css` | the widget stylesheet (first-class release asset; SRI-capable via `<link>`). |

Everything below is guidance for integrators who serve these assets (self-hosted or via a CDN).
The exact release URLs are the integrator's choice.
This file gives the patterns and the hash command.

## SRI (Subresource Integrity)

Compute the sha384-base64 hashes with the bundled tool:

```sh
node packages/kiwicaptcha-wasm/tools/sri-hashes.mjs
```

The tool prints one sha384 value per asset.
Do not copy values from examples or from an older build.
Each release's authoritative hashes are the attached `SRI.txt` and `SHA256SUMS` release artifacts (both SLSA-attested); the shape is:

```
kiwicaptcha-wasm.js  sha384-<VALUE-FROM-SRI.txt>
kiwi-worker.js       sha384-<VALUE-FROM-SRI.txt>
widget-driver.js     sha384-<VALUE-FROM-SRI.txt>
widget.css           sha384-<VALUE-FROM-SRI.txt>
```

Use the SRI script-tag pattern for every asset you serve:

```html
<script src="https://cdn.example.com/kiwicaptcha/v1.6.20/widget-driver.js"
        integrity="sha384-osA8vjEQw8Gbqp8Z7Ap9Avv1rH03DOAJVKB7bFMvDSbgZ7N+UU7zFEdKrMfocdQR"
        crossorigin="anonymous"></script>
```

The example path uses the release version.
The solver protocol id is a protocol/ABI label, not an artifact identity; see the Immutable versioned URLs section below.

Notes:

- `integrity` + `crossorigin="anonymous"` are a pair.
  An SRI-protected cross-origin script without `crossorigin` will be blocked.
- Re-run the tool after every rebuild and update the tags.
  A hash mismatch means the bytes on the wire are not the bytes you pinned.
- **Workers cannot use `integrity=`:** `new Worker(url)` has no SRI parameter, so the worker source must be protected differently.
  - files mode: the driver fetches the versioned `worker.<hash>.js` asset itself and verifies the page-issued SRI digest against the fetched bytes. Only then does it construct a same-origin Worker from the content-addressed URL. The constructor serves exactly the verified bytes (immutable cache, hash in the URL), so unverified worker code never runs. A worker URL without the SRI digest keeps the legacy direct-construction path.
  - the bundled driver's inline tier builds a Blob worker from the glue's embedded worker source (local code, no network fetch at all).
  - The worker's own protocol-id handshake (`ready`/`done` messages, plus the wasm glue's exported `solver_protocol_version()` verified before `ready`) makes the driver refuse a stale/mismatched worker.
    A cached old worker can never contribute a solution.

## Immutable versioned URLs — never a mutable `latest.js`

- Every asset must be served from an immutable, versioned URL path.
  The version is the release tag (or a content address, the strongest form, below), e.g. `/kiwicaptcha/v1.6.20/widget-driver.js`.
  The solver protocol id (see the protocol-id section below) is an ABI/protocol label.
  Multiple byte-different compatible releases legitimately share it, so it must never be used as the URL version.
  A "v2026-08-r1" path would silently serve any compatible release's bytes.
- Never publish a mutable `latest.js`/`latest.css` alias: a compromised or replaced "latest" file is indistinguishable from a release to SRI pinning that follows the URL.
- Content-addressed naming is the strongest form.
  The runtime wasm is embedded inside `kiwicaptcha-wasm.js`.
  The release pipeline publishes the tag-bound JS/CSS artifacts + SHA256SUMS + SRI + SLSA provenance; the release object is immutable under GitHub's Immutable Releases setting, enabled as of v1.6.11.
  There is currently no standalone raw `.wasm` artifact on the release.
  Integrators who need the raw wasm may extract it once and serve it under a content-addressed name such as `argon-solver.<sha256>.wasm` at their CDN layer, or apply the `<name>.<hash>.<ext>` pattern to the `kiwicaptcha-wasm.js` glue directly.
  A URL change then *proves* a content change, and SRI on top of it is belt-and-braces.
- The stable asset names in this package (`assets/kiwicaptcha-wasm.js`, `assets/kiwi-worker.js`, `assets/widget-driver.js`) stay unchanged between builds; the bundle's own asset versioning content-addresses them.
  That is why SRI is mandatory.
  The filename alone never proves which build you served.

## Self-hosting guidance

- Self-host the assets: the widget refuses cross-origin challenge endpoints and self-hosting means no third party ever executes script on your pages.
  Download the release artifacts once, verify the hashes below, and serve them from your own origin (or a CDN you control) at a versioned path.
- Pin exact build tool versions.
  `build.sh` pins `wasm-bindgen` 0.2.127 and verifies the binaryen (`wasm-opt`) tarball by SHA-256 before extracting it (see the `known_wasm_opt_sha256` table).
- Commit lockfiles: `Cargo.lock` (this package, `tools/embed`, the risk crates) pins every Rust dependency; the browser-test suite commits `package-lock.json`.
  The PHP core and Symfony bundle do not commit a Composer lockfile (library convention: the lock is a per-application artifact).
  CI installs the published dependency constraints and runs `composer audit` on every push, and release CI runs clean-room installs of the published packages.
  A supply-chain change to any committed pinned dependency shows up as a lockfile diff in review.
  PHP changes surface in the `composer audit`/clean-room jobs instead.
- Rebuilds must be reproducible and reviewed: the only artifacts that are allowed to reach production are those produced by the pinned pipeline in `build.sh`.

## Release hashes + artifact attestations

For each release:

1) Build, then record hashes:
   ```sh
   shasum -a 256 assets/kiwicaptcha-wasm.js assets/kiwi-worker.js assets/widget-driver.js
   node tools/sri-hashes.mjs
   ```
2) Publish the hash list as the attached `SHA256SUMS`/`SRI.txt` manifests (SHA-256 for artifact verification, sha384 SRI form for script tags).
   Both manifests are SLSA-attested release assets; the release notes reference them.
3) Attest the artifacts with GitHub artifact attestations.
   The producer is the release workflow, `actions/attest-build-provenance` (SLSA provenance, tied to the OIDC identity of the repository/runner).
   `gh attestation create` does not exist.
   The release pipeline already attests all four assets on every `v*` tag; the consumer side verifies:
   ```sh
   gh attestation verify assets/kiwicaptcha-wasm.js --repo <org>/<repo>
   ```
4) Publish the protocol id (see the protocol-id section below) alongside the hashes so integrators can tell which driver/worker pair a release contains.
   The attached `SHA256SUMS`/`SRI.txt` manifests are the authoritative record of the exact release bytes.
   Version immutable resource URLs by release or content identity (e.g. `/v1.6.19/widget-driver.js` or `widget-driver.<sha256>.js`), never by the protocol id alone.
   Several byte-different compatible releases can legitimately share one protocol id.

## Solver protocol-id coupling (versioned-resource expectation)

The widget driver embeds a solver protocol id constant, a protocol/ABI generation label, not an artifact identity:

```js
var KIWI_SOLVER_PROTOCOL_ID = "2026-08-r2";   // widget-driver.js
var KIWI_SOLVER_PROTOCOL_VERSION = 2;           // integer, checked against
                                                // the wasm export
```

Exact byte identity is guaranteed by the release tag + `SHA256SUMS` + `SRI.txt` + SLSA attestation, never by this label.

The worker (the standalone `kiwi-worker.js`, its copy embedded in the glue, and the fetched files-mode asset) declares the same constant and reports it in its handshake messages:

- on startup: `{ type: "ready", v: 1, buildId: "2026-08-r2" }`
- on success: `{ type: "done", v: 1, counter: <n>, buildId: "2026-08-r2" }`

The driver validates the worker's protocol id against its own constant (and the worker validates the wasm's integer protocol version).
On a mismatch the widget enters the controlled `kiwi:solver-mismatch` state with a clear error message and never accepts a solution from the mismatched worker.
No invalid tokens are produced, and there is no fallback to a stale worker.

Expectation for integrators: the driver, the worker, and the wasm glue served to a page must come from the **same build id**.
Mixed versions (e.g. a cached `kiwi-worker.js` from an older release next to a new driver) produce the controlled mismatch state until the serving layer is corrected.
When the solver protocol changes, bump `KIWI_SOLVER_PROTOCOL_ID` + `KIWI_SOLVER_PROTOCOL_VERSION` in `kiwi-worker.js` (the generator embeds it into the glue) and the Rust `SOLVER_PROTOCOL_VERSION` constant (they must stay identical), rebuild, and re-run the SRI tool.

## Widget runtime guarantees (recap)

- The result token lives in memory only, never in `localStorage`/`sessionStorage`.
- A persisted `pageshow` (BFCache restore) clears the solved state and reacquires on the next interaction; it never auto-solves on restore.
- Any failed/expired challenge response resets the widget to idle and it reacquires (bounded retries, then click-to-retry).
  It never sticks in a failed state.
- `data-kiwi-request-binding` (when set on the container) is forwarded as `request_binding` in the challenge request body and echoed into a hidden `kiwi_request_binding` input next to the token input.
  Server-side binding enforcement is the bundle's job.
