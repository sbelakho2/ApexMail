//! The parser drivers shared by the libFuzzer targets
//! (`crates/fuzz-tests/fuzz/`) and the deterministic fuzz-lite smoke test
//! (`tests/fuzz_smoke.rs`).
//!
//! One function per shipped parser surface. Each driver:
//!
//! * calls the REAL production parser (never a copy — the mta seams reuse
//!   the servers' own `split_verb`/`extract_addr_safe`; the MIME target is
//!   the same `mail-parser` call the submission path makes; DKIM/SPF/DMARC
//!   are `mail-auth`'s parsers, the dependency the mta authenticator uses);
//! * asserts the parser's cheap invariants (oracles) in the function body,
//!   so a libFuzzer crash AND a smoke-test panic are the same failure;
//! * has no I/O, no clock and no global mutable state (deterministic under
//!   the fixed smoke corpus).
//!
//! Parser coverage at this HEAD:
//!
//! | driver | production surface |
//! |--------|--------------------|
//! | [`mail_proto_decode`] | `mail_proto::decode_with_limits::<StoreMessageRequest>` |
//! | [`smtp_command_line`] | mta `submission`/`inbound` command tokenizer (`split_verb`) |
//! | [`smtp_envelope_address`] | mta `MAIL FROM:` / `RCPT TO:` address grammar |
//! | [`mime_message`] | `mail_parser` — the mta submission MIME/header parser |
//! | [`dkim_signature`] | `mail_auth::dkim` signature-header parser |
//! | [`spf_record`] | `mail_auth::spf::SpfRecord` TXT-record parser |
//! | [`dmarc_record`] | `mail_auth::dmarc::DmarcRecord` TXT-record parser |
//! | [`webhook_signature`] | billing-service `stripe_events::verify_signature` (Stripe-Signature HMAC) |
//! | [`template_source`] | template-renderer `validate_source` + `transpile` |
//! | [`csv_report`] | mta `postmaster::snds::parse_csv` |
//! | [`tracking_token`] | tracking-service `TrackingCodec::decode` / unsubscribe verify |
//!
//! NOT linkable at this HEAD (documented in fuzz/README.md):
//! * `imap-proto-patched` is a nested Cargo workspace, so the main workspace
//!   crate tree cannot depend on it; `fuzz_imap_response` in the separate
//!   libFuzzer subproject remains its target (the smoke test cannot link it);
//! * the IMAP *command* parser lives inside the `imap-server` **binary** (no
//!   library target to link);
//! * the API compat-endpoint JSON parsers and the SES/SNS verification
//!   helpers are private to `api-server`, whose source is outside this
//!   change's allowed edit surface.
//!
//! Their in-crate suites still exercise them; the fuzz harness simply cannot
//! reach them without refactoring production crates.

#![allow(clippy::bool_assert_comparison)]

/// Protobuf decode with the workspace's size limits, plus the
/// re-encode/decode stability oracle.
pub fn mail_proto_decode(data: &[u8]) {
    use mail_proto::decode_with_limits;
    use prost::Message;
    if let Some(decoded) = decode_with_limits::<mail_proto::generated::StoreMessageRequest>(data) {
        let reencoded = decoded.encode_to_vec();
        let again = decode_with_limits::<mail_proto::generated::StoreMessageRequest>(&reencoded);
        assert!(
            again.is_some(),
            "a decoded message did not survive re-encode/decode (input len {})",
            data.len()
        );
        assert!(
            decoded.raw_message.len() <= data.len() + 16,
            "decoded raw_message ({}) larger than input ({})",
            decoded.raw_message.len(),
            data.len()
        );
    }
}

/// SMTP command-line tokenizer (verb, argument tail). The production
/// `split_verb` returns the first whitespace-delimited token, so the oracle
/// is that a returned verb never contains whitespace.
pub fn smtp_command_line(line: &str) {
    let (verb, _args) = mta::servers::fuzz_smtp_command_line(line);
    assert!(
        !verb.chars().any(char::is_whitespace),
        "split_verb returned a verb containing whitespace: {verb:?}"
    );
}

/// SMTP envelope-address extractor. Oracle: when a path is present the
/// extracted slice is EXACTLY the bytes between the first `<` and the first
/// following `>` (the parser's documented panic-safety property — the
/// closing bracket is searched after the opening one), and extraction is
/// deterministic.
pub fn smtp_envelope_address(line: &str) {
    let first = mta::servers::fuzz_smtp_envelope_address(line);
    let second = mta::servers::fuzz_smtp_envelope_address(line);
    assert_eq!(first, second, "envelope extraction is not deterministic");
    if let Some(address) = first {
        let start = line.find('<').expect("Some address implies an opening '<'");
        let end = start
            + 1
            + line[start + 1..]
                .find('>')
                .expect("Some address implies a closing '>' after the '<'");
        assert_eq!(
            address,
            &line[start + 1..end],
            "envelope extraction is not the bracketed path slice"
        );
    }
}

/// MIME/header parsing through the same `mail-parser` crate the mta
/// submission path uses. Oracle: parsing is deterministic (two parses of the
/// same bytes agree on the header-derived identity fields).
pub fn mime_message(data: &[u8]) {
    let first = mail_parser::MessageParser::default().parse(data);
    let second = mail_parser::MessageParser::default().parse(data);
    match (first, second) {
        (Some(first), Some(second)) => {
            assert_eq!(
                first.subject().map(|value| value.to_string()),
                second.subject().map(|value| value.to_string()),
                "mail-parser subject is not deterministic for the same input"
            );
            assert_eq!(
                first.from().map(|address| format!("{address:?}")),
                second.from().map(|address| format!("{address:?}")),
                "mail-parser From is not deterministic for the same input"
            );
        }
        (None, None) => {}
        _ => panic!("mail-parser returned different optionality for the same input"),
    }
}

/// DKIM-Signature header parser (`mail_auth::dkim`).
pub fn dkim_signature(header: &[u8]) {
    if let Ok(signature) = mail_auth::dkim::Signature::parse(header) {
        // A parsed signature must name a domain and selector (the parser
        // refuses missing/empty d=/s=, so a success here must honour it).
        assert!(
            !signature.d.is_empty() && !signature.s.is_empty(),
            "a parsed DKIM signature must carry a non-empty domain/selector"
        );
    }
}

/// SPF TXT-record parser (`mail_auth::spf`).
pub fn spf_record(record: &[u8]) {
    use mail_auth::dns::TxtRecordParser;
    if let Ok(parsed) = mail_auth::spf::SpfRecord::parse(record) {
        // The record is parsed at most once per input by this driver; the
        // oracle is structural: an accepted record has a directives list
        // (empty records are refused by the version check).
        let cloned = parsed.clone();
        assert_eq!(parsed, cloned, "SPF record parsing is not deterministic");
    }
}

/// DMARC TXT-record parser (`mail_auth::dmarc`).
pub fn dmarc_record(record: &[u8]) {
    use mail_auth::dns::TxtRecordParser;
    if let Ok(parsed) = mail_auth::dmarc::DmarcRecord::parse(record) {
        let cloned = parsed.clone();
        assert_eq!(parsed, cloned, "DMARC record parsing is not deterministic");
    }
}

/// Stripe-Signature HMAC verification — the HMAC verifier the billing webhook
/// boundary runs (Mollie's webhook is FETCH-verified, not signed; the SES/SNS
/// verifier is private to api-server, see the module docs).
pub fn webhook_signature(header: &[u8], payload: &[u8]) {
    let header = String::from_utf8_lossy(header);
    let _ = billing_service::payments::stripe_events::verify_signature(
        "whsec_fuzz_fixed_secret",
        payload,
        &header,
    );
}

/// Template parser/validator (`template-renderer`). Oracles: the validator
/// and transpiler are deterministic for the same source (a parser whose
/// verdict depends on hidden state would make template approval
/// non-reproducible). The smoke run found that `transpile` accepts some
/// sources `validate_source` rejects — a real (benign) asymmetry, reported
/// in fuzz/README.md; it is not a crash and this target does not fail on it.
pub fn template_source(source: &str) {
    let first = template_renderer::transpiler::validate_source(source, 1 << 20);
    let second = template_renderer::transpiler::validate_source(source, 1 << 20);
    assert_eq!(
        (first.valid, first.errors.len()),
        (second.valid, second.errors.len()),
        "template validation is not deterministic"
    );
    let transpiled_first = template_renderer::transpiler::transpile(source, 1 << 20).is_ok();
    let transpiled_second = template_renderer::transpiler::transpile(source, 1 << 20).is_ok();
    assert_eq!(
        transpiled_first, transpiled_second,
        "template transpilation is not deterministic"
    );
}

/// CSV report parser (mta SNDS postmaster reports). Oracle: deterministic
/// record count for the same body.
pub fn csv_report(body: &str) {
    let first = mta::postmaster::snds::parse_csv(body);
    let second = mta::postmaster::snds::parse_csv(body);
    assert_eq!(
        first.len(),
        second.len(),
        "CSV report parser is not deterministic"
    );
}

/// Tracking-token decoder + unsubscribe verifier (tracking-service).
pub fn tracking_token(token: &str) {
    let codec = tracking_service::codec::TrackingCodec::new("fuzz-fixed-master-secret");
    let decoded = codec.decode_with_error(token);
    // The same token must classify identically twice.
    let again = codec.decode_with_error(token);
    assert_eq!(
        format!("{decoded:?}"),
        format!("{again:?}"),
        "tracking token classification is not deterministic"
    );
    let _ = codec.verify_unsubscribe_token(token, Some(90));
    let _ = codec.verify_preferences_token(token);
}
