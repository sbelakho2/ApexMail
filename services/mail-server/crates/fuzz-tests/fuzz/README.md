# fuzz/ — cargo-fuzz (libFuzzer) targets for ApexMail wire parsers

Real coverage-guided fuzzing for the two parser surfaces that consume
attacker-influenced bytes (SM12 F12). The in-crate suites in
`crates/fuzz-tests/tests/` are seeded-random smoke tests with oracles; THIS
directory is the actual fuzzer engine.

> **Note:** `cargo fuzz` (https://github.com/rust-fuzz/cargo-fuzz) is likely
> not installed on developer machines — install with
> `cargo install cargo-fuzz`. This subproject is a separate workspace (see
> the empty `[workspace]` table in `Cargo.toml`) and is deliberately not
> built by the parent workspace's `cargo check/test`.

## Targets

| Target                 | Production surface                                             |
| ---------------------- | -------------------------------------------------------------- |
| `fuzz_mail_proto`      | `mail_proto::decode_with_limits::<StoreMessageRequest>` (protobuf decode with the 64 MB limit) |
| `fuzz_imap_response`   | `imap_proto::parse_response` (IMAP server response parser)      |

## Running

```sh
cd crates/fuzz-tests/fuzz

# 10-minute time-capped session against the protobuf parser
cargo fuzz run fuzz_mail_proto -max_total_time=600 -- -rss_limit_mb=2048

# 10-minute time-capped session against the IMAP parser
cargo fuzz run fuzz_imap_response -max_total_time=600 -- -rss_limit_mb=2048
```

`fuzz.toml` caps every session at `max_total_time = 600` when the CLI flag
is absent — never start an uncapped session in CI.

## Seed corpus

`corpus/<target>/` carries hand-built seeds of VALID inputs (a canonical
`StoreMessageRequest` encoding; real IMAP `* OK`, `* n FETCH`, `* n EXISTS`
responses) so libFuzzer starts from grammar-plausible inputs instead of
zero bytes. The corpus is committed and grows only intentionally: move any
crashing input from `artifacts/` into the corpus as a regression seed after
fixing the bug.

## Oracles

Beyond crash detection, each target asserts parser invariants:

* `fuzz_mail_proto` — a successfully decoded message must re-encode and
  decode again (stability), and no decoded field may exceed the input size.
* `fuzz_imap_response` — a successful parse must consume at least one byte
  (an Ok consuming nothing would loop forever in callers that advance past
  the parsed prefix).

## Fuzzing cadence

Not wired into CI gates (libFuzzer needs nightly `-Zsanitizer` toolchains);
run locally before releases touching `mail-proto` or `imap-proto-patched`.
