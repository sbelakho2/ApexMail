# Fix report — the signer-id check stops skipping subjectKeyIdentifier signer ids

Agent: `signing-ski`. Date: 2026-10-07. Base revision: `97a8877b` (main) +
working tree (sibling agents' changes present; the tree was clean at start).
Deliverable of `docs/audit/dogfood-2026-10-06/brief-signing-ski.md`.

**Ownership.** Exactly one file was edited:
`services/mail-server/crates/compliance/src/signing.rs` (implementation +
inline `timestamp_tests` + module docs). No other file, no docker, no
dependency changes. Sibling agents concurrently edited other files in this
working tree (migrations, retention sweep, SDKs, docs); none of those edits
are mine.

## Status table

| Item | Status | One-line evidence |
|---|---|---|
| 1 implement the SKI arm | **FIXED** | `signing.rs:2421` matches the sid against every candidate cert's SubjectKeyIdentifier; match → Pass, absent/no-match/no-cert → Fail with the candidate SKIs (hex); fail-before run: NotPerformed + `all_passed == true` |
| 2 tests + fail-before | **FIXED** | 7 new/rewritten unit tests, real ECDSA signature fixture; old arm: 0/7 pass ("expected Fail, got NotPerformed"); new arm: 7/7 and 100/100 signing tests |
| 3 other `not_performed` arms | **AUDITED** | only the SKI arm was implementable with existing utilities; every remaining arm justified in the table below |

Verification (final, on the edited file):

```
$ cd services/mail-server
$ TEST_DATABASE_URL=postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail \
  TEST_REDIS_URL=redis://127.0.0.1:6379 \
  cargo nextest run -p compliance
     Summary [ 125.478s] 880 tests run: 880 passed, 0 skipped
$ rustfmt --edition 2021 --check crates/compliance/src/signing.rs   # clean
$ grep -n "not implemented" crates/compliance/src/signing.rs        # no matches
```

`TEST_REDIS_URL` is required by the workspace convention for the
`bin/compliance-server` cron-matrix test (`server.rs:469` reads
`TEST_REDIS_URL`, defaulting to an unparseable empty URL); with only
`TEST_DATABASE_URL` set that one unrelated test fails on pool construction.
Redis is up locally (`redis-cli ping` → `PONG`).

## Item 1 — implementation

Arm: `signing.rs:2421` (was `2407-2416`). Helper:
`certificate_subject_key_identifier` at `signing.rs:2518`.

```
(Some(SignerId::SubjectKeyIdentifier(key_id)), _) => {
    // every parseable cert in SignedData.certificates is a candidate
    // (the signing cert is not necessarily the first); its SKI extension
    // value (RFC 5280 §4.2.1.2) is compared octet-for-octet with the
    // SignerInfo key_id (RFC 5652 §5.3, [0] IMPLICIT OCTET STRING).
    // any match → Pass; otherwise → Fail naming the presented id and
    // every candidate's SKI (hex), or "<no subjectKeyIdentifier extension>".
}
```

* **Match → `Pass`** with the same check id and outcome as the
  issuerAndSerial pass arm.
* **No match / SKI absent / no parseable certificate → `Fail`** with a
  precise reason — never `not_performed`. The fail detail carries the
  presented key id and the candidate list: `hex(extension value)` for each
  cert that has one, `<no subjectKeyIdentifier extension>` for each that
  does not, and a distinct message when `SignedData` carries no parseable
  certificate at all.
* **Multiple candidates:** scanned in order; any matching certificate
  (including one that is not the first) satisfies the check.
* Extraction uses the file's existing x509 tooling (`X509Certificate::
  extensions()` / `ParsedExtension::SubjectKeyIdentifier`, the same parser
  already used for `raw_serial()` and the issuer name); no new dependency.

**One judgment call beyond the literal bullets: the verdict is `required:
true`.** The brief's test section demands "the verify path's overall verdict
for a tampered signer id (must NOT verify)". `all_passed()` ignores optional
failures ("Optional failures are reported in checks but do not block"), so a
`required: false` fail would leave `TimeStampClient::timestamp_at` accepting
a token whose sid names a different certificate. The CMS signature does not
cover the sid (RFC 5652 §5.3 — it lives outside `signedAttrs`; the new test
proves the signature still verifies after tampering), so this comparison is
the only binding and it must gate. The pre-existing issuerAndSerial arm was
left untouched as the brief designates it ("there is already issuer/serial
matching; mirror its verdict shape"), which means that arm's mismatch also
remains optional — see Observations.

Module docs gained one bullet (line ~31) stating the required SKI binding and
the optional serial comparison.

## Item 2 — tests and fail-before proof

Fixture provenance (embedded as hex constants in `timestamp_tests`; nothing
generated at test time):

```
$ openssl ecparam -name prime256v1 -genkey -noout -out key.pem
$ openssl req -new -x509 -key key.pem -sha256 -days 3650 \
    -subj "/C=EE/O=ApexMail Test Fixture/CN=ApexMail SKI Unit Fixture (NOT PRODUCTION)" \
    -addext "subjectKeyIdentifier=hash" -addext "basicConstraints=critical,CA:FALSE"
# cert 500 bytes, SKI = 8eb0b885dba6ce931669864162b55730092927f0
# decoy: second EC key/cert, SKI = ce3c5000ecc909c147b1c223be672a15ba916da0
# no-SKI: -addext subjectKeyIdentifier=none  (basicConstraints only)
# signature: openssl dgst -sha256 -sign key.pem over the signed-attributes
#   SET DER rebuilt exactly as the test builds it (contentType,
#   messageDigest = SHA-256(TSTInfo), SigningCertificateV2 =
#   SHA-256(cert)); `openssl dgst -verify` → "Verified OK"
```

The signature is real, so `token_signature_valid` passes in the match case
and stays **passing** in the tampered case (it is not covered by the
signature) — this is what isolates the signer-id verdict.

New/rewritten tests (`signing.rs:3572-3782`):

| Test | What it pins |
|---|---|
| `subject_key_identifier_match_passes_and_verifies` | SKI match → Pass; all 13 checks pass, `all_passed`/`strictly_passed` true |
| `tampered_subject_key_identifier_fails_the_whole_verification` | one octet flipped → Fail (names both ids), `all_passed` false, `has_failures` true, failing-checks list is exactly `[signer_id_matches_certificate]`, signature still valid |
| `subject_key_identifier_no_match_lists_every_candidate_ski` | two candidates, none match → Fail detail lists both candidate SKIs (hex) |
| `subject_key_identifier_matches_any_candidate_certificate` | matching SKI on the second cert → Pass (scans all candidates) |
| `subject_key_identifier_absent_from_the_certificate_fails` | cert with extensions but no SKI → Fail, "no subjectKeyIdentifier extension" |
| `subject_key_identifier_without_any_candidate_fails_closed` | no certificates in SignedData → Fail, never `not_performed` |
| `subject_key_identifier_mismatch_fails_and_unknown_ids_are_reported` | RSA fixture cert, synthetic SKI → Fail naming `717afd…`; an unrecognised sid TLV stays `NotPerformed` |

Supporting test-harness change: `response_with_certificates` (explicit cert
list) with `response` delegating to it, so multi-candidate tokens are
reachable.

**Fail-before (reproduced).** The implementation arm was temporarily restored
to HEAD's `not_performed` version (tests kept), then:

```
$ cargo test -p compliance --lib tampered_subject_key_identifier_fails_the_whole_verification -- --nocapture
thread ... panicked at crates/compliance/src/signing.rs:3590:13:
a tampered signer id must not verify; checks: [
  ... every status/imprint/nonce/genTime/cert/digest/attrs/ESS check: Pass ...
  CheckVerdict { check: "signer_id_matches_certificate", required: false,
                 outcome: NotPerformed { reason: "SignerInfo identifies the signer by
                 subjectKeyIdentifier 8eb0b885dba6ce931669864162b55730092927f1; key-id
                 matching is not implemented" }, note: None },
  CheckVerdict { check: "token_signature_valid", required: true, outcome: Pass, note: None } ]
test ... FAILED

$ cargo test -p compliance --lib subject_key_identifier -- --nocapture
test result: FAILED. 0 passed; 7 failed; 0 ignored; 0 measured; 630 filtered out
```

That is exactly the brief's fail-before shape: the mismatch was reported
`not_performed`, every other check — including the real CMS signature —
passed, so `all_passed()` was true and verification did not fail. After
restoring the implemented arm: `7 passed; 0 failed`, and the full signing
set is 100/100 under nextest.

## Item 3 — remaining `not_performed` arms (audited)

Only the SKI arm could be implemented with existing utilities; every other
arm is a missing/unsupported *operand*, not skipped work, so each stays and
is justified here.

| Site | Check | Why `not_performed` is the honest verdict |
|---|---|---|
| 2177 | `gen_time_within_tolerance` | `genTime` did not parse — no instant to compare; `gen_time_parses` already fails (required) |
| 2236-2251 | message-digest / ESS / signer-id / token-signature | `SignedData` has no SignerInfo — nothing to check; the same branch fails `signed_attrs_content_type` (required) |
| 2316 | message-digest match | signer digest algorithm outside the supported hashing set (module hashes SHA-256/384/512 only; SHA-1 deliberately refused) |
| 2331 | message-digest match | signedAttrs carry no messageDigest attribute — absent input |
| 2340/2367/2383 | ESS hash match | no parseable certificate / unsupported ESS hash algorithm / no signingCertificateV2 attribute — absent or unsupported input |
| 2407 | serial arm | issuer `Name` did not re-parse — no comparable operand (reported precisely) |
| 2468 | serial arm | no parseable certificate to compare against |
| 2475 | signer id | sid TLV is neither SEQUENCE nor `[0]`; RFC 5652 §5.3 defines exactly those two CHOICE alternatives, so there is no defined value to compare |
| 2490/2496 | `token_signature_valid` | algorithm outside the `ring`-backed supported set, or no certificate → no verifier/key. The brief explicitly allows unsupported-algorithm `not_performed` |
| 4511 | ASiC `mimetype_exact` | no `mimetype` member — absent input |
| 4884 | ASiC `signer_certificate_parses` | container lists no certificates — absent input |
| 4930/4948/4963 | ASiC `signature_value_over_raw_signed_info` | unsupported signature algorithm / `SignatureValue` did not decode / no parseable signing certificate — no verifier, key or signature bytes |
| 4987/4993/5004 | ASiC XAdES digest match | unsupported digest algorithm / no parseable signing certificate / no `CertDigest` element — absent or unsupported input |

None of these has the data in hand and skips the comparison; the SKI arm was
the only such case (the certificate DER was already parsed and available).

## Observations

* **Serial-arm asymmetry (left as briefed).** The issuerAndSerial mismatch
  remains an optional fail, so `all_passed()` alone would still accept a
  token whose serial/issuer names another certificate. The brief fixed the
  serial arm as the model ("mirror its verdict shape"), so I did not change
  it; if uniform gating is wanted, promote that arm's verdicts to
  `required: true` — the change is the three boolean literals in the same
  match.
* **Malformed SKI extension.** `x509-parser`'s `ParsedExtension` reports a
  parse error for a malformed SubjectKeyIdentifier extension; the helper
  treats it like an absent extension (fail, candidate shown as
  `<no subjectKeyIdentifier extension>`). Distinguishing the two in the
  fail detail would be cosmetic; no test pins a malformed extension.
* **Concurrent-infrastructure interlude (not caused by this change).** Mid
  task the full suite was red because three sibling sessions had each added
  a different `246_*.sql` migration (duplicate version), which made the
  embedded chain fail on a fresh database:
  `migrator: failed to apply migrations: ... duplicate key value violates
  unique constraint "_sqlx_migrations_pkey"`. All 209 failures in that run
  were the same `canonical test-database provisioning failed` panic and 0
  were signing tests. The siblings renumbered to 246/247/248 at 23:41 and
  the rerun above is green (880/880).
* Contract limitations (no chain validation, no revocation, no validity
  window enforcement) are unchanged and remain listed in the module's
  NOT PROVEN documentation.
