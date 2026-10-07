# Supply-chain vetting policy (cargo-vet)

**Status: explicit, audited split — not full provenance.**

`config.toml`, `audits.toml` and `imports.lock` drive `cargo vet --locked`,
which the CI security lane runs as a REQUIRED check
(`ci/stages/security.sh`, "cargo vet (supply-chain/config.toml … REQUIRED)").

## What a green run means (and does not mean)

As of 2026-10-07 (coverage audit U-10) the store imports **9 peer audit sets**:

| Peer | Audit source |
|---|---|
| actix | actix/supply-chain |
| ariel-os | ariel-os/ariel-os |
| bytecode-alliance | bytecodealliance/wasmtime |
| embark-studios | EmbarkStudios/rust-ecosystem |
| fermyon | fermyon/spin |
| google | google/supply-chain |
| isrg | divviup/libprio-rs |
| mozilla | mozilla/supply-chain |
| zcash | zcash/rust-ecosystem |

`cargo vet --locked` reports the split on every run, e.g.:

```
Vetting Succeeded (164 fully audited, 16 partially audited, 586 exempted)
```

* **fully/partially audited** = a real audit path from one of the imported
  peers covers the crate.
* **exempted** = `[[exemptions.*]]` blocks in `config.toml`: this repository
  self-asserts `safe-to-deploy`/`safe-to-run` with **no review**. They are a
  backlog, not evidence.

So a green vet run means "every lockfile crate is either covered by an
imported audit or explicitly self-exempted here". It must **never** be cited
as "all third-party dependencies were review-verified". Quote the split.

## History (why this file exists)

Before 2026-10-07 the store had **766 exemptions, zero imported audits and no
first-party audits** — `cargo vet` could not say anything about provenance at
all, and the lane was actually RED (4 crates, incl. `rustls`/`aws-lc-rs`,
unvetted in the lockfile). The U-10 fix imported the 9 peer sets above and ran
`cargo vet regenerate exemptions`, which:

* removed 180 exemptions now covered by real imported audits
  (766 → 586 self-exemptions, 180 crates with real audit paths), and
* restored `cargo vet --locked` to green by adding exemptions for the
  crates no peer covers (the same self-exemption status those crates always
  had — now visible in the split above).

First-party audits (`audits.toml`) are still empty by design; add an
`[[audits.*]]` entry only together with a real human review record.

## Maintenance

* To shrink the exemption set: `cargo vet import <peer>` (peers list:
  `https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml`),
  then `cargo vet regenerate exemptions`.
* `config.toml` is canonically formatted by cargo-vet: run `cargo vet fmt`
  after hand edits (vet fails closed on an unformatted store). Free-form
  comments are stripped by the formatter — policy lives in this README, not
  in the TOML.
* Do not regenerate exemptions without recording the before/after split in
  the change description.
