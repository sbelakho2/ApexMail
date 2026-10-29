# Brief — IMPLEMENT the skipped signer-id check (compliance signing)

Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail. Owner directive: no
"not implemented" end states. `crates/compliance/src/signing.rs:2410-2417`
records `signer_id_matches_certificate` as **not_performed** whenever a
SignerInfo identifies its signer by **subjectKeyIdentifier (SKI)** — the
signature verification path silently skips proving the signer-id actually
matches the certificate in that arm. Implement the check.

## Implement
1. In `compliance/src/signing.rs` (the `(Some(SignerId::SubjectKeyIdentifier(
   key_id)), _)` arm): locate the candidate certificate(s) and match the SKI
   against the certificate's SubjectKeyIdentifier extension (RFC 5280
   §4.2.1.2; compare the extension value to the SignerInfo key_id octets per
   RFC 5652 §5.3) — use the existing DER/x509 utilities in the file (there is
   already issuer/serial matching; mirror its verdict shape:
   CheckVerdict::pass/not_performed with a precise reason).
   - SKI present and equal → the check PASSES (same shape as the serial arm).
   - SKI absent from the cert, or no candidate matches → the check FAILS with
     the specific reason (never silently not_performed).
   - Multiple candidate certs: any matching cert satisfies the check; if none
     match, fail with the list of candidate SKIs (hex).
2. Tests: craft certificates/ASN.1 fixtures consistent with the file's
   existing test style — SKI-match pass, SKI-mismatch fail, missing SKI
   extension fail, and the verify path's overall verdict for a tampered
   signer id (must NOT verify). Prove fail-before: with the old arm, the
   SKI-mismatch case reports not_performed and verification does not fail.
3. Search the same file for other `not_performed` arms that can be
   implemented with existing utilities and implement them too, or justify
   each remaining not_performed with a line in your report (there are
   legitimate ones for unsupported algorithms — no fabrication).

## Rules
- Can-fail proofs with commands; keep `cargo nextest run -p compliance` green
  (TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail).
- Own `crates/compliance/src/signing.rs` + its tests ONLY. No docker builds.
- Report: `docs/audit/dogfood-2026-10-06/fix-report-signing-ski.md`.
