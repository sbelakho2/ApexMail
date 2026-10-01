# imap-proto-patched

**STATUS: UNWIRED — this crate is NOT compiled by the ApexMail workspace and
no crate depends on it.** It exists only as the target of the
`[patch.crates-io] imap-proto` entry in `services/mail-server/Cargo.toml`
(kept so the patch reference resolves if a transitive dependency ever pulls
`imap-proto` from crates.io). The security hardening below is therefore
**NOT active** in the running IMAP server by virtue of this crate.

## Where the protections actually live

The protections this patched fork carries were re-implemented where they are
needed, inside `crates/imap-server` itself:

| Vendored patch here | Live protection in imap-server |
| --- | --- |
| `MAX_BODYSTRUCTURE_DEPTH = 64` paren-depth cap (`src/body_structure.rs:258`) | `MAX_MIME_DEPTH = 64` + `StructureDepthError` in `crates/imap-server/src/main.rs` — `format_structure_region` (BODYSTRUCTURE/BODY rendering) and `extract_body_part` (BODY[n] descent) both refuse to recurse/copy deeper than the cap (SM2-F1) |
| NIL-INTERNALDATE `unwrap()` fix (`src/rfc3501.rs:376-382`) | n/a — imap-server formats internal dates itself (`format_internal_date`) and never parses them from the wire |
| Multibyte `resp_text` slicing fix (`src/rfc3501.rs:459-479`) | n/a — imap-server writes response text as owned `String`s; its header/token helpers are byte-based and char-boundary safe (SM2-F6) |

If you touch this crate expecting its parser to guard the server: it won't.
imap-server renders BODYSTRUCTURE/ENVELOPE data from stored raw messages with
its own (depth-capped) code; it does not parse IMAP byte streams through this
codec. Any change to MIME nesting limits must go to
`crates/imap-server/src/main.rs` (`MAX_MIME_DEPTH`).

## Origin

Vendored fork of `imap-proto 0.10.2` (upstream: dead backend patches for the
trailing-semicolon future-incompat issue, https://github.com/rust-lang/rust/issues/79813,
plus the hardening listed above).
