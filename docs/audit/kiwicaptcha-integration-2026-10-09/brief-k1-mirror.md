# Lane K1 — refresh the KiwiCaptcha mirrors to the upstream GitHub head (byte-identical)

You are an extremely rigorous mirror-refresh lane. **The KiwiCaptcha project is a separate repository:
you never EDIT its content.** Your job is to make ApexMail's mirrors byte-identical copies of the
upstream head — that is exactly the standing owner instruction "simply use the latest version".
ZERO SKIPS: every step evidenced with literal commands/outputs.

## Upstream

- Source: `https://github.com/Bel-Consulting-OU/kiwicaptcha` — local clone at
  `/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone`.
- Confirm freshness yourself: `git fetch origin && git rev-parse HEAD origin/main` (expected
  `ab1316b7…` for both; if origin/main moved, use the NEW sha), and `git status --short` (the
  upstream tree must have no uncommitted changes that change the mirrored bytes; if it is dirty,
  record exactly what is dirty and STOP for the orchestrator's decision — do not mirror dirty
  state).
- Record the mirrored sha and the package version (`packages/kiwicaptcha/Cargo.toml` version).

## ApexMail mirror surface (replicate the precedent exactly)

The previous mirror commit `c10db774` ("full mirror replacement with the standalone repo at
b32ec01e") replaced: `packages/kiwicaptcha`, `packages/kiwicaptcha-php`,
`packages/kiwicaptcha-risk`, `packages/kiwicaptcha-risk-php`, `packages/kiwicaptcha-wasm`, and
`tests/browser`. Inspect `git show --name-only c10db774` and `git show --stat ab4a6b0`-style history
to derive the EXACT inclusion/exclusion set (build artifacts such as `target/`, `node_modules/`,
`vendor/`, and generated caches were excluded; `.phpunit.result.cache` and some lockfiles were
included — mirror the precedent per-file, do not guess).

## Method

1. For each mirrored directory, produce a diff inventory vs upstream HEAD (`diff -rq` with the
   precedent's excludes) BEFORE changing anything; save it as evidence.
2. Replace the trees with byte-identical copies (`rsync -a --delete` with the same excludes), then
   prove: `diff -rq` returns no differences for every mirrored dir (excluding the precedent's
   excluded paths), and the embedded widget resources
   (`packages/kiwicaptcha/resources/{widget-driver.js,widget.css,kiwicaptcha-wasm.js,kiwi-worker.js}`)
   are byte-identical to their canonical upstream counterparts (check upstream's build/provenance
   rules — the wasm package's assets are canonical; record the comparison).
3. **ApexMail-side glue only**: if the refreshed crate's API drifted such that ApexMail no longer
   compiles, make the MINIMAL ApexMail-side call-site adaptations (never inside `packages/**`),
   document each, and keep them behavior-preserving. If a drift is not mechanically fixable, STOP
   and report for the orchestrator.
4. Verify (literal outputs in the report):
   - `cd packages/kiwicaptcha && cargo test` (default features) — the crate's own suite on the
     refreshed code; if the crate's suite needs Redis features, run the documented command from its
     README and say so.
   - `cd services/mail-server && cargo check -p api-server -p integration-tests` and
     `cargo nextest run -p api-server --lib -E 'test(kiwi) | test(schema_contract) | test(concurrency)'`.
   - The api-server test env: `TEST_DATABASE_URL=postgres://apexmail:<secrets/postgres_password.txt>@127.0.0.1:5432/apexmail`,
     `TEST_DATABASE_ADMIN_URL=…:5432/postgres`, `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`.
   - `cd tests/browser && npm ci && BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 ./node_modules/.bin/playwright test`
     (the suite is part of the mirror surface; it must pass against the live stack).
5. `cargo fmt` on any ApexMail-side Rust you touched.

## Constraints

- Never edit files under `packages/**` or `tests/browser/**` after copying (they are upstream bytes).
  The ONLY exception is ApexMail-side call sites outside those trees.
- No `git commit` (the orchestrator commits). Do not touch docker-compose or api-server routes (lane
  K2 owns those).
- KiwiCaptcha's own repo at `/Users/sabelakhoua/IdeaProjects/kiwicaptcha-standalone` is READ-ONLY for
  you (fetch yes, edit never).

## Deliverable

`docs/audit/kiwicaptcha-integration-2026-10-09/lane-k1-mirror.md`: the mirrored sha + version, the
before/after diff inventory, the file/addition/deletion counts per mirrored dir, the resource-parity
proof, the exact test commands + outputs, any ApexMail-side adaptations, zero-skips appendix, final
orchestrator paragraph.
