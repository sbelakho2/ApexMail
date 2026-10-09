# ui-foundation

Server-side UI rendering for the ApexMail console, control plane, marketing
fallbacks, sandbox result pages, and system emails — design-system primitives,
shells, and HTML generation. **Zero client-side JavaScript**: every interaction
is a native form post, a native disclosure, or a plain link.

## Surface ownership (who renders what)

| Surface | Rendered by | Notes |
|---|---|---|
| Customer console (`web`, `/web/*`) | this crate (`leptos_views`, `view_data`, `shell`, `primitives`) + `api-server/src/routes/web*.rs` loaders | Console pages compose the shared `data_list_page` / `web_*_page` builders; the api-server owns sessions, RBAC and the POST handlers. |
| Control plane (`control-plane`, `/cp/*` and bare aliases) | same, plus `ControlPlaneShell` | `/cp/audit` and `/audit` address the same page; the nav's active cell is the single longest match (see `shell::active_href`). |
| Marketing (`marketing-zola`) | `apps/marketing-zola` (Zola) for every built page | `axum_router::marketing_static_document` embeds the built `public/**/index.html`; this crate's `MarketingShell` and the `marketing_*_page` views are **fallbacks** for routes with no built document, not a second design system. |
| Sandbox / grader result pages (`api.apexmail.ee/explorer/*`) | `explorer.rs` | Standalone dark documents with an embedded stylesheet (no cross-origin CSS). Return links are absolute marketing-origin URLs. |
| Transactional email HTML/text | `api-server/src/routes/{auth,forgot_password,system_sender}.rs` | The shared shell contract lives there; this crate supplies primitives only. |

`routing.rs` reads `docs/development/ui-baseline-manifest.json` as the route
inventory (web / control-plane / marketing / marketing-zola, 130 entries
including the `/cp` aliases); `ssr.rs` cross-checks the rendered coverage.

## Native PRG behaviour

Every mutation is `POST → 303 redirect → GET`, and the GET renders the
outcome:

* **Flash messages** ride a signed, bounded cookie (`flash.rs`):
  `apexmail_flash` HMAC-SHA256 over `v1.<base64url(json)>.<base64url(hmac)>`,
  `Max-Age=60`, `HttpOnly`, `SameSite=Lax`. The encoder truncates texts and
  drops trailing messages to stay inside a 3072-byte value (browsers silently
  drop larger cookies); the decoder rejects tampered, malformed or oversized
  values and never panics.
* **Failed-form replay** (`axum_router::inject_form_field_state`) is scoped to
  the failing form: on a marked page only the matching `data-form-id`
  element is touched; on an unmarked page a field name carried by more than
  one form is dropped rather than guessed. Checked/selected state is
  REPLACED (never accumulated), and each failed control gains
  `aria-invalid` plus an `aria-describedby` pointing at its
  `<control-id>-error` paragraph.
* **Destructive actions** go through the typed `/confirm` page with an
  HMAC-signed `(intent, id, expiry)` tuple (`flash.rs`); CSRF tokens are
  HMAC-signed `nonce.signature` values (`csrf.rs`) with a real token injected
  into every POST form by the render pass.

## Embedded assets and the stylesheet authority

* `assets/globals.input.css` is the **authored authority** (tokens, layer
  components, utilities) and `assets/globals.css` is the **compiled
  artifact** served at `/assets/globals.css?v=<content hash>`
  (`lib.rs::globals_css_url`). Regenerate the artifact with the repo recipe:
  `apps/marketing-zola/tailwindcss -c crates/ui-foundation/tailwind.config.js
  -i crates/ui-foundation/assets/globals.input.css -o
  crates/ui-foundation/assets/globals.css` (from `services/mail-server`).
  Do not hand-edit `globals.css`; `tokens.rs::source_artifact_drift` and the
  class-integrity gate fail when the two diverge.
* Tailwind CLI resolution (`tools/dev-start.sh::resolve_tailwind_cli`): the
  vendored `apps/marketing-zola/tailwindcss` (official v3.4.17) is used when
  it is executable on the current host; otherwise a `tailwindcss` on `PATH`
  is used; otherwise the build fails with the official download URL for the
  host platform
  (`https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-<macos|linux>-<arm64|x64>`).
  Re-fetch the vendored binary from that URL when a checkout has a
  foreign-platform copy.
* `tailwind.config.js` scans every renderer that can emit a class:
  `./src/**/*.rs`, `./assets/globals.input.css`, and
  `../../api-server/src/**/*.rs`.
* Icons come from `baselines/web/icons.baseline.txt` through `icons.rs`
  (24×24 viewBox, `currentColor`, round caps, escaped class names).

## Fallback semantics

* **Marketing**: when `apps/marketing-zola/public` is missing **or
  incomplete** (any route the router includes is absent) `build.rs` embeds
  minimal placeholder pages generated under `OUT_DIR` and emits a
  `cargo:warning` naming the missing routes; a well-formed
  `public/build-provenance.json` is required when the tree is stamped (the
  Docker build writes it) and its `styled_sheet` must exist. `lib.rs`'s
  `MARKETING_PUBLIC_BUILT` tells tests whether the real pages are embedded.
* **Console**: data-backed list pages fall back to the static demo page only
  when no loader data is present; unavailable data renders as
  "unavailable" — never as a fabricated zero.

## Fixture authority

* `baselines/rust-ui/**` + `docs/development/ui-baseline-manifest.json` are
  the committed render baselines, regenerated by
  `APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation --bin export_visual_fixtures -- <dir>`
  (they carry the renderer/CSS/marketing hashes; `pixel_parity.rs` compares
  current renders against them).
* `crates/ui-foundation/goldens/**` are the checked-in skeleton goldens
  (`UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation -E 'test(golden_)'`).
* `fixture_states.rs` renders the stateful bot-surface fixtures (assistant,
  AI drafts, timeline, alert rules, tracking domain) that the gates sweep.
* `tools/contrast-audit/fixtures/**` is the browser/contrast/layout harness
  input, exported from the same exporter — it is a derivative, never an
  authority.

## Development

```sh
cargo test -p ui-foundation          # 500+ tests incl. the UI gates
cargo clippy -p ui-foundation
cargo run -p ui-foundation --bin export_visual_fixtures -- crates/ui-foundation/baselines/rust-ui
python3 tools/verify_qr_interop.py   # independent ISO/IEC 18004 QR conformance (stdin protocol)
```
