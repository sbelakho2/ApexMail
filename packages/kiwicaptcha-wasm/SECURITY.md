# KiwiCaptcha WASM — Security & Supply-Chain Notes

This package ships four browser assets (`assets/`):

| Asset | Purpose |
|---|---|
| `kiwicaptcha-wasm.js` | wasm-bindgen glue with the Argon2id/SHA-256 solver wasm inlined as base64 |
| `kiwi-worker.js` | standalone same-origin worker solver (`data-kiwi-worker-src`) |
| `widget-driver.js` | the widget driver; embeds the worker source and the solver build id |
| `widget.css` | the widget stylesheet (first-class release asset since round 18; SRI-capable via `<link>`) |

Everything below is guidance for integrators who serve these assets (self-hosted
or via a CDN). The exact release URLs are the integrator's choice — this file
gives the patterns and the hash command.

## 1. SRI (Subresource Integrity)

Compute the sha384-base64 hashes with the bundled tool:

```sh
node packages/kiwicaptcha-wasm/tools/sri-hashes.mjs
```

Example output (run against a build — all FOUR release assets):

```
kiwicaptcha-wasm.js  sha384-lYQhEK3o/D8piurwe1556/gKHmzDoNv5gumBBIKUCsKQ0ogSvB1HySZm6NeNVdzq
kiwi-worker.js       sha384-bz5IPxD4I2OK/gEaeUsMGXB0A5caYw5LwU/fQXbxpzQ048kk8K2NsWM/GO3EL9Ii
widget-driver.js     sha384-osA8vjEQw8Gbqp8Z7Ap9Avv1rH03DOAJVKB7bFMvDSbgZ7N+UU7zFEdKrMfocdQR
widget.css           sha384-rNPQbDhqKmTBO3cn6mUfG5zR4OeKjMsJ5i1lPv9d9YvTdm1g5iw4yLfRo0PYT8
```

Use the SRI script-tag pattern for every asset you serve:

```html
<script src="https://cdn.example.com/kiwicaptcha/2026-08-r1/widget-driver.js"
        integrity="sha384-osA8vjEQw8Gbqp8Z7Ap9Avv1rH03DOAJVKB7bFMvDSbgZ7N+UU7zFEdKrMfocdQR"
        crossorigin="anonymous"></script>
```

Notes:

- `integrity` + `crossorigin="anonymous"` are a pair — an SRI-protected
  cross-origin script without `crossorigin` will be blocked.
- Re-run the tool after every rebuild and update the tags; a hash mismatch
  means the bytes on the wire are not the bytes you pinned.
- **Workers cannot use `integrity=` (audit round 15):** `new Worker(url)`
  has no SRI parameter, so the standalone `kiwi-worker.js` served via
  `data-kiwi-worker-src` must be protected differently:
  - serve it from an **immutable, versioned, same-origin URL**
    (e.g. `/kiwicaptcha/2026-08-r1/kiwi-worker.js`) — never a mutable
    `latest.js` alias;
  - publish the content-addressed release hash (`argon-solver.<sha256>`-
    style naming, or the §4 release-hash list) and verify it in the
    release pipeline;
  - the worker's own build-id handshake (`ready`/`done` messages) makes
    the DRIVER refuse a stale/mismatched worker — a cached old worker can
    never contribute a solution.
  If runtime integrity checking of the worker is required, the driver
  would have to fetch the worker source with `integrity` checking itself
  and instantiate a Blob worker from the verified bytes — the bundled
  driver's default Blob-worker path already constructs the worker from
  locally embedded source (no network fetch at all).

## 2. Immutable versioned URLs — never a mutable `latest.js`

- Every asset must be served from an immutable, versioned URL path. The
  version is the solver build id (see §5), e.g.
  `/kiwicaptcha/2026-08-r1/widget-driver.js`.
- Never publish a mutable `latest.js`/`latest.css` alias: a compromised or
  replaced "latest" file is indistinguishable from a release to SRI pinning
  that follows the URL.
- Content-addressed naming is the strongest form: the runtime wasm is
  EMBEDDED inside `kiwicaptcha-wasm.js` (the release pipeline publishes
  the tag-bound JS/CSS artifacts + SHA256SUMS + SRI + SLSA provenance;
  the release object is immutable under GitHub's Immutable Releases
  setting, enabled as of v1.6.11 — there is currently no standalone raw
  `.wasm` artifact on the release).
  Integrators who need the raw wasm may extract it once and serve it under
  a content-addressed name such as `argon-solver.<sha256>.wasm` at their
  CDN layer, or apply the `<name>.<hash>.<ext>` pattern to the
  `kiwicaptcha-wasm.js` glue directly — a URL change then *proves* a
  content change, and SRI on top of it is belt-and-braces.
- The stable asset names in this package (`assets/kiwicaptcha-wasm.js`,
  `assets/kiwi-worker.js`, `assets/widget-driver.js`) stay unchanged between
  builds; the bundle's own asset versioning content-addresses them. That is
  why SRI is mandatory — the filename alone never proves which build you
  served.

## 3. Self-hosting guidance

- Self-host the assets: the widget refuses cross-origin challenge endpoints
  and self-hosting means no third party ever executes script on your pages.
  Download the release artifacts once, verify the hashes below, and serve
  them from your own origin (or a CDN you control) at a versioned path.
- Pin exact build tool versions. `build.sh` pins `wasm-bindgen` 0.2.127 and
  verifies the binaryen (`wasm-opt`) tarball by SHA-256 before extracting it
  (see the `known_wasm_opt_sha256` table).
- Commit lockfiles: `Cargo.lock` (this package, `tools/embed`, the risk
  crates) pins every Rust dependency; the browser-test suite commits
  `package-lock.json`. The PHP core and Symfony bundle do NOT commit a
  Composer lockfile (library convention: the lock is a per-application
  artifact); CI installs the published dependency constraints and runs
  `composer audit` on every push, and release CI runs clean-room installs
  of the published packages. A supply-chain change to any committed pinned
  dependency shows up as a lockfile diff in review; PHP changes surface in
  the `composer audit`/clean-room jobs instead.
- Rebuilds must be reproducible and reviewed: the only artifacts that are
  allowed to reach production are those produced by the pinned pipeline in
  `build.sh`.

## 4. Release hashes + artifact attestations

For each release:

1. Build, then record hashes:
   ```sh
   shasum -a 256 assets/kiwicaptcha-wasm.js assets/kiwi-worker.js assets/widget-driver.js
   node tools/sri-hashes.mjs
   ```
2. Publish the hash list as the attached `SHA256SUMS`/`SRI.txt` manifests
   (SHA-256 for artifact verification, sha384 SRI form for script tags) —
   both manifests are SLSA-attested release assets; the release notes
   reference them.
3. Attest the artifacts with GitHub artifact attestations. The
   PRODUCER is the release workflow — `actions/attest-build-provenance`
   (SLSA provenance, tied to the OIDC identity of the repository/runner);
   `gh attestation create` does NOT exist. The release pipeline already
   attests all four assets on every `v*` tag; the CONSUMER side verifies:
   ```sh
   gh attestation verify assets/kiwicaptcha-wasm.js --repo <org>/<repo>
   ```
4. Publish the build id (see §5) alongside the hashes so integrators can
   tell which driver/worker pair a release contains.

## 5. Solver build-id coupling (versioned-resource expectation)

The widget driver embeds a solver build id constant:

```js
var KIWI_SOLVER_BUILD_ID = "2026-08-r1";   // widget-driver.js
```

The worker (both the standalone `kiwi-worker.js` and the copy embedded in the
driver) declares the same constant and reports it in its handshake messages:

- on startup: `{ type: "ready", v: 1, buildId: "2026-08-r1" }`
- on success: `{ type: "done", v: 1, counter: <n>, buildId: "2026-08-r1" }`

The driver validates the worker's build id against its own constant. On a
mismatch the widget enters the controlled `kiwi:solver-mismatch` state with a
clear error message and **never** accepts a solution from the mismatched
worker (no invalid tokens are produced, and there is no fallback to a stale
worker).

Expectation for integrators: the driver, the worker, and the wasm glue served
to a page must come from the **same build id**. Mixed versions (e.g. a cached
`kiwi-worker.js` from an older release next to a new driver) produce the
controlled mismatch state until the serving layer is corrected. When the
solver is bumped, bump `KIWI_SOLVER_BUILD_ID` in `widget-driver.js` and
`kiwi-worker.js` (they must stay identical), rebuild, and re-run the SRI tool.

## 6. Widget runtime guarantees (recap)

- The result token lives in memory only — no `localStorage`/`sessionStorage`.
- A persisted `pageshow` (BFCache restore) clears the solved state and
  reacquires on the next interaction; it never auto-solves on restore.
- Any failed/expired challenge response resets the widget to idle and it
  reacquires (bounded retries, then click-to-retry) — it never sticks in a
  failed state.
- `data-kiwi-request-binding` (when set on the container) is forwarded as
  `request_binding` in the challenge request body and echoed into a hidden
  `kiwi_request_binding` input next to the token input. Server-side binding
  enforcement is the bundle's job.
