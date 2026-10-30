# fuzz/ — coverage-guided fuzzing for every ApexMail parser (T7)

Real libFuzzer targets (cargo-fuzz) for every parser that consumes
attacker-influenced bytes, plus committed seed corpora and a crash →
regression-test pipeline.

```sh
cd crates/fuzz-tests/fuzz
cargo +nightly fuzz run fuzz_spf_record -max_total_time=600 -- -rss_limit_mb=2048
```

`fuzz.toml` caps every session at `max_total_time = 600` (10 minutes) and
2 GB RSS; the CLI flags override the cap deliberately. Never start an
uncapped session in CI.

## Targets

| Target | Production surface |
| ------ | ------------------ |
| `fuzz_mail_proto` | `mail_proto::decode_with_limits::<StoreMessageRequest>` (protobuf, 64 MB limit) |
| `fuzz_imap_response` | `imap_proto::parse_response` (IMAP server responses) |
| `fuzz_smtp_command` | mta SMTP command-line tokenizer (`split_verb`, submission/inbound) |
| `fuzz_smtp_envelope` | mta `MAIL FROM:` / `RCPT TO:` address extractor (`extract_addr_safe`) |
| `fuzz_mime_message` | `mail-parser` — the MIME/header parser the submission path runs |
| `fuzz_dkim_signature` | `mail-auth` DKIM-Signature header parser |
| `fuzz_spf_record` | `mail-auth` `SpfRecord` TXT-record parser |
| `fuzz_dmarc_record` | `mail-auth` `DmarcRecord` TXT-record parser |
| `fuzz_webhook_signature` | billing-service Stripe-Signature HMAC verifier (`stripe_events::verify_signature`) |
| `fuzz_template_source` | template-renderer `validate_source` + `transpile` |
| `fuzz_csv_report` | mta SNDS postmaster CSV report parser (`postmaster::snds::parse_csv`) |
| `fuzz_tracking_token` | tracking-service `TrackingCodec::decode` / unsubscribe verify |

The drivers live in the parent workspace crate
(`crates/fuzz-tests/src/fuzz_api.rs`) and are shared by these targets and the
deterministic fuzz-lite smoke test (`crates/fuzz-tests/tests/fuzz_smoke.rs`),
so the smoke lane exercises exactly the code the nightly engine fuzzes.

## Corpora

`corpus/<slug>/` carries hand-built VALID seeds (grammar-plausible inputs) so
libFuzzer starts useful; `corpus/<slug>/regression/` is where
`tools/run_fuzz_nightly.sh` commits a crashing input. Corpora grow only
intentionally — a crash artifact is copied in, never a stale `artifacts/`
directory.

## Oracles

Beyond crash detection each driver asserts parser invariants (see
`fuzz_api.rs`): IMAP parses consume at least one byte; protobuf decode
re-encodes and decodes again; SMTP verbs never contain whitespace and an
envelope address is exactly the bracketed slice; MIME parsing is
deterministic; SPF/DMARC parse deterministically; template validation and
transpilation are deterministic; the CSV and tracking decoders are
deterministic for the same input.

The smoke run surfaced one benign asymmetry worth knowing: `transpile`
accepts a few sources `validate_source` rejects. It is documented in
`fuzz_api.rs`; it is not a crash and does not fail the smoke lane.

## Smoke mode (normal CI lane, `test.fuzz-smoke`)

```sh
bash tools/run_fuzz_nightly.sh --smoke
```

Runs `cargo nextest run -p fuzz-tests --test fuzz_smoke` on the stable
toolchain: every committed corpus seed plus a fixed seeded input set (48 per
target) through every driver. It also cross-checks that each target has a
non-empty corpus and appears in the smoke `TARGETS` list. No nightly
toolchain, no libFuzzer, seconds not hours — this is the proof the harness
works that the gate line runs.

## Nightly mode and crash handling

```sh
bash tools/run_fuzz_nightly.sh                  # 10 min per target (FUZZ_SECONDS=600)
bash tools/run_fuzz_nightly.sh --seconds 120    # shorter operator run
bash tools/run_fuzz_nightly.sh --targets fuzz_spf_record,fuzz_dkim_signature
bash tools/run_fuzz_nightly.sh --from-artifact \
    crates/fuzz-tests/fuzz/artifacts/fuzz_spf_record/crash-abc123
```

For each target the script runs `cargo +nightly fuzz run <target>
-max_total_time=<seconds>` and, when a crash artifact appears (or the process
exits non-zero):

1. copies the artifact to `corpus/<slug>/regression/<name>` (committed seed);
2. generates a compilable regression test at
   `crates/fuzz-tests/tests/generated/regression_<target>_<name>.rs` that
   `include_bytes!`s the committed seed and calls the same driver. The audit's
   rule — every crash becomes a committed regression test before its fix
   merges — is therefore mechanical;
3. exits non-zero so the nightly lane fails.

`--from-artifact` performs steps 1–2 for an existing artifact without a
fuzzing session. For `fuzz_imap_response` the generated skeleton is written
under `fuzz/regressions/` instead: `imap-proto-patched` is a nested Cargo
workspace, so the main workspace test crate cannot link it; the committed
corpus seed is still replayed by the nightly engine.

Nightly prerequisites: rustup nightly + `cargo install cargo-fuzz` (the CI
image / `ci/install.sh` carries them). A missing engine fails the nightly
closed; `--smoke` needs only stable cargo.

## Scheduling

`ci/pipeline.sh run --fuzz-nightly` drives the nightly script before the
stage line, once per UTC day (marker `ci/runs/.last-fuzz-nightly`,
`CI_FUZZ_FORCE=1` to override) — the same periodic shape as the deps agent's
`--daily` fresh-DB cargo-audit lane. The host unit
`ci/units/apexmail-pipeline.service` passes both `--daily` and
`--fuzz-nightly`. A standalone cron/systemd timer may invoke
`tools/run_fuzz_nightly.sh` directly instead.

## Known gaps at this HEAD (honest inventory)

- `imap-proto-patched` is a **nested workspace**, so its parser cannot be
  linked by the workspace crate; `fuzz_imap_response` is nightly-only and
  exempt from the smoke list (documented in the script's `SMOKE_EXEMPT`).
- The **IMAP command parser** lives inside the `imap-server` binary (no
  library target); fuzzing it requires extracting it into a library, which
  this change deliberately does not do.
- **Compat-endpoint JSON** parsers (D1) and the **SES/SNS verification**
  helpers live in `api-server` and are private; `api-server` is outside this
  change's allowed edit surface. Their in-crate suites exercise them.
- The **Mollie webhook** is fetch-verified (no signature HMAC to fuzz); the
  Stripe-Signature verifier is the HMAC surface this wave added, and it is
  the one `fuzz_webhook_signature` drives.
- The **contacts CSV importer** (D2) parser is private to `api-server`; the
  CSV target drives the mta SNDS CSV parser instead.
