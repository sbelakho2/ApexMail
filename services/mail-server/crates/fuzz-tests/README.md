# fuzz-tests

Fuzz / property-based test helpers for the ApexMail mail-server workspace.

## Running

```sh
cargo test -p fuzz-tests
```

## Reproducibility (SM12 F12)

All random input generation draws from a `StdRng` seeded from the
`FUZZ_SEED` environment variable (default: `6840310201905667821`, a fixed
constant — CI failures without an explicit seed are still replayable). The
seed in effect is printed once per process on first use:

```text
fuzz-tests: RNG seed = 6840310201905667821 (set FUZZ_SEED=<u64> to reproduce a failure)
```

Replay a failure exactly:

```sh
FUZZ_SEED=<printed seed> cargo test -p fuzz-tests
```

Under nextest (one test per process, what CI uses) each test's input stream
is fully deterministic. Under parallel `cargo test`, thread interleaving
decides which test consumes which per-call generator nonce.

## Real libFuzzer targets

`fuzz/` is a cargo-fuzz subproject (its own workspace, excluded from the
mail-server workspace) with coverage-guided targets for the wire parsers:

* `fuzz_mail_proto` — `mail_proto::decode_with_limits::<StoreMessageRequest>`
* `fuzz_imap_response` — `imap_proto::parse_response`

```sh
cargo install cargo-fuzz   # requires a nightly toolchain for -Zsanitizer
cd crates/fuzz-tests/fuzz
cargo fuzz run fuzz_mail_proto -max_total_time=600
```

`fuzz/fuzz.toml` time-caps every session (600 s); `fuzz/corpus/` carries
seed inputs of valid traffic. See `fuzz/README.md`.
