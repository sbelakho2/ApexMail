//! CI cross-language harness: loads a PHP-issued record (the PHP job's
//! record env var), solves it with the Rust solver, and verifies it with
//! verify_solution. Skips (returns) when the env var is unset so local
//! `cargo test` stays hermetic.
//!
//! # Shared runtime envelope protocol
//!
//! The runtime envelope carried on every stored record is `state`,
//! `consumed_result`, `operation_identity`, `resume_owner`,
//! `resume_until`. The resume-derivation claim is single-key and
//! envelope-embedded: both languages splice `resume_owner` and
//! `resume_until` into the record itself with one Lua script. A claim
//! held by one language refuses the other, and the loser's recovery
//! resolves the winner's committed outcome.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kiwicaptcha::verify::{
    solve_for_test, verify_solution, RequestBindingExpectation, VerifyContext, VerifyError,
    VerifyOutcome,
};

/// The shared cross-language signing secret (kid 1) both language
/// harnesses configure. Held here so the interop cases never repeat the
/// literal.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[cfg(feature = "redis")]
fn into_pending(
    state: kiwicaptcha::redis_verify::RuntimeState,
) -> Option<Box<kiwicaptcha::ChallengeRecord>> {
    match state {
        kiwicaptcha::redis_verify::RuntimeState::Pending(record) => Some(record),
        _ => None,
    }
}

#[test]
fn rust_verifies_php_issued_record() {
    let Ok(path) = std::env::var("KC_PHP_RECORD") else {
        eprintln!("KC_PHP_RECORD unset — cross-language test skipped");
        return;
    };
    let json = std::fs::read_to_string(&path).expect("KC_PHP_RECORD file");
    let record: kiwicaptcha::ChallengeRecord =
        serde_json::from_str(&json).expect("PHP JSON must deserialize into the Rust record");
    assert_eq!(record.protocol_version, 2);
    assert_eq!(record.scope, "login");

    let counter = solve_for_test(&record).expect("Rust solver finds a counter");
    let mut rec = record;
    let now_ns = rec.issued_at_ns + 1_000_000;
    let mut ctx = VerifyContext {
        record: &mut rec,
        secret_key: "0123456789abcdef0123456789abcdef",
        secrets_by_kid: None,
        revoked_kids: None,
        counter,
        duration_ms: 5000,
        now_unix: Some(&mut || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
    };
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "Rust must accept a PHP-issued challenge"
    );

    // Cross-language binding: a wrong IP must be rejected.
    let mut rec2 = rec.clone();
    let mut ctx2 = VerifyContext {
        record: &mut rec2,
        secret_key: "0123456789abcdef0123456789abcdef",
        secrets_by_kid: None,
        revoked_kids: None,
        counter,
        duration_ms: 5000,
        now_unix: Some(&mut || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("9.9.9.9"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
    };
    assert_eq!(
        verify_solution(&mut ctx2),
        VerifyOutcome::Invalid(VerifyError::IpMismatch)
    );
    println!("RUST_VERIFIES_PHP: OK (counter={counter})");
}

#[test]
fn rust_issues_record_for_php() {
    // Reverse direction: Rust issues a record and writes the
    // language-neutral JSON for the PHP job to solve + verify. The
    // algorithm and the output path come from env vars; skips when the
    // output env var is unset.
    let Ok(path) = std::env::var("KC_RUST_RECORD") else {
        eprintln!("KC_RUST_RECORD unset — reverse cross-language test skipped");
        return;
    };
    let algo_name = std::env::var("KC_RUST_ALGO").unwrap_or_else(|_| "sha256".to_string());
    let (algorithm, m_kib, t, p, target_bits, argon2_target_bits) = if algo_name == "argon2id" {
        (
            kiwicaptcha::challenge::PoWAlgorithm::Argon2id,
            64u32,
            3u32,
            1u32,
            4u32,
            4u32,
        )
    } else {
        (
            kiwicaptcha::challenge::PoWAlgorithm::Sha256,
            0u32,
            1u32,
            1u32,
            8u32,
            8u32,
        )
    };
    let config = kiwicaptcha::challenge::ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        algorithm,
        m_kib,
        t,
        p,
        target_bits,
        argon2_target_bits,
        ttl_secs: 120,
        min_duration_ms: None,
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: kiwicaptcha::challenge::BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let issued = kiwicaptcha::challenge::issue_challenge(
        &config,
        "login",
        "198.51.100.7",
        now_unix,
        now_ns,
        0,
        None,
    )
    .expect("issue");
    std::fs::write(
        &path,
        serde_json::to_string(&issued.record).expect("serialize"),
    )
    .expect("write");
    println!("RUST_ISSUED {}", algo_name);
}

/// Four-way real-Redis runtime-state interoperability: PHP and
/// Rust must operate on the same Redis records with the same runtime
/// envelope (state marker + consumed_result + operation_identity +
/// resume_owner + resume_until). The resume-derivation claim is
/// single-key and envelope-embedded in both languages, so a claim held
/// by one language refuses the other. Runs
/// only when a Redis URL is provided and the PHP core's autoloader is
/// reachable from this crate.
///
/// Directions covered:
///  - PHP issue/store -> Rust consume/verify (success + replay)
///  - Rust issue/store -> PHP consume/verify (success + replay)
///  - PHP claim (short TTL) -> Rust claim refused -> expiry takeover ->
///    Rust claim -> PHP claim refused -> PHP release -> Rust claim +
///    commit, read back from PHP with the claim fields gone
///  - PHP claim + commitResultResume -> Rust re-reads the committed
///    result with the claim fields gone
#[test]
#[cfg(feature = "redis")]
fn redis_runtime_state_interop_with_php() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — redis interop test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — interop test skipped");
        return;
    }
    let php_bin = std::env::var("KC_PHP_BIN").unwrap_or_else(|_| "php".to_string());
    let prefix = format!("kiwicaptcha:interop{}:", std::process::id());
    let client = match redis::Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis URL invalid: {e} — interop test skipped");
            return;
        }
    };
    // Verify connectivity; skip when Redis is unreachable.
    {
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Redis unreachable — interop test skipped");
                return;
            }
        };
        let _: () = redis::cmd("PING").query(&mut conn).unwrap_or_default();
    }

    let php_script = |body: &str| -> Result<String, String> {
        let code = format!("require '{}'; {}", php_autoload, body);
        let out = std::process::Command::new(&php_bin)
            .args(["-r", &code])
            .env("KC_INTEROP_REDIS", &url)
            .env("KC_INTEROP_PREFIX", &prefix)
            .output()
            .map_err(|e| format!("php spawn failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            return Err(format!(
                "php failed ({}): {} {}",
                out.status,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(stdout)
    };

    // 1. PHP issue/store -> Rust consume/verify.
    let php_issue = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$issuer = new KiwiCaptcha\Issuer(new KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', algorithm: KiwiCaptcha\PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
$ch = $issuer->issue('login', '127.0.0.1');
$raw = $client->get(getenv('KC_INTEROP_PREFIX') . $ch->nonce);
if (!str_contains($raw, '"state":"pending"')) { fwrite(STDERR, 'PHP-written record lacks the state marker'); exit(2); }
if (!str_contains($raw, '"consumed_result":null')) { fwrite(STDERR, 'PHP-written record lacks consumed_result:null'); exit(3); }
if (!str_contains($raw, '"operation_identity":null')) { fwrite(STDERR, 'PHP-written record lacks operation_identity:null'); exit(7); }
echo $ch->nonce;
"#;
    let nonce = php_script(php_issue).expect("PHP must issue + store a record");
    #[cfg(feature = "redis")]
    let store = kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone());
    let consumed = store
        .consume(&nonce)
        .expect("Rust must consume the PHP-written record")
        .expect("Rust consume must find the PHP-written record");
    assert!(
        consumed.first,
        "Rust must win the pending->consumed transition on a PHP-written record"
    );

    // 2. PHP consume+commit -> Rust replay reads the committed outcome.
    let php_consume_commit = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = stream_get_contents(STDIN);
$storage->consume(trim($nonce));
$storage->commitResult(trim($nonce), true, null);
echo 'ok';
"#;
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_consume_commit,
        nonce.as_bytes(),
    )
    .expect("PHP consume+commit must succeed");

    // Rust replay reads the committed boolean result.
    let replayed = store
        .consume(&nonce)
        .expect("Rust replay consume must work")
        .expect("Rust replay must find the record");
    assert!(
        !replayed.first,
        "Rust replay must observe the already-consumed state"
    );
    let result = replayed
        .stored_result
        .expect("Rust replay must read the PHP-committed result");
    assert!(
        result.valid,
        "PHP-committed valid=true must deserialize as a Rust boolean"
    );

    // 3. Rust issue/store -> PHP consume/verify reads the runtime envelope.
    let rust_record = issue_record_for_interop();
    let rust_nonce = rust_record.nonce.clone();
    store
        .store(&rust_record)
        .expect("Rust must issue + store a record");
    let php_consume = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = stream_get_contents(STDIN);
$consumed = $storage->consume(trim($nonce));
if ($consumed === null || !$consumed->consumedNow) { fwrite(STDERR, 'PHP must consume the Rust-written record'); exit(4); }
echo 'ok';
"#;
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_consume,
        rust_nonce.as_bytes(),
    )
    .expect("PHP must consume the Rust-written record");

    // 4. Rust consume+commit -> PHP replay reads the committed boolean.
    let php_replay = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = stream_get_contents(STDIN);
$consumed = $storage->consume(trim($nonce));
if ($consumed === null || !$consumed->consumedBefore) { fwrite(STDERR, 'PHP replay must observe consumed_before'); exit(5); }
if ($consumed->consumedResult === null || !$consumed->consumedResult->valid) { fwrite(STDERR, 'PHP replay must read the Rust-committed valid=true boolean'); exit(6); }
echo 'ok';
"#;
    // Commit the Rust side first.
    store
        .commit_result(&rust_nonce, true, None)
        .expect("Rust must commit its result");
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_replay,
        rust_nonce.as_bytes(),
    )
    .expect("PHP replay must read the Rust-committed boolean");

    // 5. The shared resume-claim protocol, PHP side first: a PHP claim
    //    (short 2s lease) embeds resume_owner / resume_until in the
    //    record envelope, and the Rust claim on the same record is
    //    refused (live cross-refusal in the Rust direction).
    let claim_record = issue_record_for_interop();
    let claim_nonce = claim_record.nonce.clone();
    store
        .store(&claim_record)
        .expect("Rust must store the claim record");
    assert!(
        store
            .consume(&claim_nonce)
            .expect("Rust must consume the claim record")
            .expect("claim record found")
            .first
    );
    let php_claim = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(stream_get_contents(STDIN));
$owner = $storage->claimResumeDerivation($nonce, 2);
if ($owner === null) { fwrite(STDERR, 'PHP must take the short-lease claim'); exit(8); }
echo $owner;
"#;
    let php_owner = php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_claim,
        claim_nonce.as_bytes(),
    )
    .expect("PHP must claim the record");
    assert_eq!(php_owner.trim().len(), 32, "PHP claim owner is hex");
    assert!(
        store
            .claim_resume_derivation(&claim_nonce, 60)
            .expect("Rust claim must run")
            .is_none(),
        "Rust must refuse a claim while the PHP claim is live"
    );

    // 6. Wait past the PHP lease: a crashed PHP recovery never
    //    released, but once resume_until passes the Rust recovery may
    //    take over the same record. Poll with a deadline instead of
    //    sleeping a fixed 3s: the 2s lease leaves only a 1s margin and
    //    a fixed sleep is flaky under CI load (the lease is measured by
    //    the Redis server clock). Retry every 250ms until the claim is
    //    taken or the 15s deadline passes.
    let claim_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut rust_owner = None;
    while std::time::Instant::now() < claim_deadline {
        if let Ok(Some(owner)) = store.claim_resume_derivation(&claim_nonce, 60) {
            rust_owner = Some(owner);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let rust_owner = rust_owner.expect("Rust must take over the record once the PHP lease expires");

    // 7. Cross-refusal the other direction: the PHP claim on the
    //    Rust-held record is refused, and PHP releases the Rust claim.
    let php_cross_refuse = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(fgets(STDIN));
$owner = trim(fgets(STDIN));
if ($storage->claimResumeDerivation($nonce, 2) !== null) { fwrite(STDERR, 'PHP claim must be refused while the Rust claim is live'); exit(9); }
if (!$storage->releaseResumeDerivation($nonce, $owner)) { fwrite(STDERR, 'PHP must release the Rust claim'); exit(10); }
echo 'ok';
"#;
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_cross_refuse,
        format!("{}\n{}", claim_nonce, rust_owner).as_bytes(),
    )
    .expect("PHP must observe the Rust claim and release it");

    // 8. Single-owner under mixed attempts: after the PHP release, the
    //    Rust recovery claims again and commits through the fenced
    //    single-key commit, which clears the claim fields atomically.
    let rust_owner_2 = store
        .claim_resume_derivation(&claim_nonce, 60)
        .expect("the re-claim must run")
        .expect("Rust must re-claim after the PHP release");
    assert!(
        store
            .commit_result_clearing_claim(&claim_nonce, true, None, &rust_owner_2)
            .expect("the fenced commit must run"),
        "Rust must commit its recovered result"
    );

    // 9. PHP re-reads the committed outcome, cannot claim the record
    //    anymore (it is no longer resultless), and the raw envelope no
    //    longer carries the claim fields.
    let php_read_back = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(stream_get_contents(STDIN));
$consumed = $storage->consumedState($nonce);
if ($consumed === null || $consumed->consumedResult === null || !$consumed->consumedResult->valid) { fwrite(STDERR, 'PHP must read the Rust-committed result'); exit(11); }
if ($storage->claimResumeDerivation($nonce, 2) !== null) { fwrite(STDERR, 'PHP claim must be refused on a committed record'); exit(12); }
$raw = $client->get(getenv('KC_INTEROP_PREFIX') . $nonce);
if (str_contains($raw, 'resume_owner')) { fwrite(STDERR, 'the claim fields must be gone from the raw envelope'); exit(13); }
echo 'ok';
"#;
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_read_back,
        claim_nonce.as_bytes(),
    )
    .expect("PHP must read the committed outcome with the claim cleared");

    // 10. The PHP claim + commitResultResume direction: PHP claims,
    //     derives and commits through its fenced commit; Rust then
    //     re-reads the same record and sees the committed result with
    //     the claim fields stripped from the raw envelope.
    let php_commit_record = issue_record_for_interop();
    let php_commit_nonce = php_commit_record.nonce.clone();
    store
        .store(&php_commit_record)
        .expect("Rust must store the PHP-commit record");
    assert!(
        store
            .consume(&php_commit_nonce)
            .expect("Rust must consume the PHP-commit record")
            .expect("PHP-commit record found")
            .first
    );
    let php_claim_and_commit = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(stream_get_contents(STDIN));
$owner = $storage->claimResumeDerivation($nonce, 2);
if ($owner === null) { fwrite(STDERR, 'PHP must claim the commit record'); exit(14); }
if (!$storage->commitResultResume($nonce, true, null, $owner)) { fwrite(STDERR, 'PHP commitResultResume must land'); exit(15); }
echo 'ok';
"#;
    php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_claim_and_commit,
        php_commit_nonce.as_bytes(),
    )
    .expect("PHP must claim and commit its recovered result");

    // 11. Rust re-reads the PHP-committed outcome: the committed result
    //     is readable and the claim fields are gone from the raw JSON.
    let state = store
        .consumed_state(&php_commit_nonce)
        .expect("Rust must read the PHP-committed record")
        .expect("the PHP-committed record is retained");
    let result = state
        .stored_result
        .expect("Rust must read the PHP-committed result");
    assert!(
        result.valid,
        "the PHP-committed valid=true result is readable in Rust"
    );
    let mut conn = client
        .get_connection()
        .expect("a Redis connection for the raw read");
    let raw: String = redis::cmd("GET")
        .arg(format!("{prefix}{php_commit_nonce}"))
        .query(&mut conn)
        .expect("raw read of the PHP-committed record");
    assert!(
        !raw.contains("resume_owner"),
        "the PHP commit cleared the claim fields from the raw envelope"
    );
}

/// The decoy grammar vocabularies must be byte-identical across the two
/// cores: the PHP `Issuer::DECOY_GRAMMAR_SLOT*` constants and the Rust
/// `DECOY_GRAMMAR_SLOT*` constants (same words, same order), so a name
/// issued by one language has exactly the same plausible-name surface
/// when the other core picks it. Skips when the PHP core's autoloader is
/// unreachable from this crate.
#[test]
fn decoy_grammar_vocabularies_match_php() {
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — decoy grammar parity test skipped");
        return;
    }
    let php_bin = std::env::var("KC_PHP_BIN").unwrap_or_else(|_| "php".to_string());
    let code = format!(
        "require '{}'; echo json_encode([\\KiwiCaptcha\\Issuer::DECOY_GRAMMAR_SLOT1_QUALIFIER, \\KiwiCaptcha\\Issuer::DECOY_GRAMMAR_SLOT2_CATEGORY, \\KiwiCaptcha\\Issuer::DECOY_GRAMMAR_SLOT3_FORM]);",
        php_autoload
    );
    let out = std::process::Command::new(&php_bin)
        .args(["-r", &code])
        .output();
    let Ok(out) = out else {
        eprintln!("php spawn failed — decoy grammar parity test skipped");
        return;
    };
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        eprintln!("php failed — decoy grammar parity test skipped: {stdout}");
        return;
    }
    let php_vocabs: Vec<Vec<String>> = serde_json::from_str(stdout.trim())
        .expect("PHP must emit the three vocabulary arrays as JSON");
    assert_eq!(
        php_vocabs.len(),
        3,
        "PHP must expose exactly three grammar vocabularies"
    );
    let rust_vocabs = [
        kiwicaptcha::DECOY_GRAMMAR_SLOT1_QUALIFIER,
        kiwicaptcha::DECOY_GRAMMAR_SLOT2_CATEGORY,
        kiwicaptcha::DECOY_GRAMMAR_SLOT3_FORM,
    ];
    for (i, php_vocab) in php_vocabs.iter().enumerate() {
        let rust_vocab = rust_vocabs[i];
        assert_eq!(
            php_vocab.len(),
            rust_vocab.len(),
            "grammar slot {} must hold the same number of words in both languages",
            i + 1
        );
        for (w, rust_w) in php_vocab.iter().zip(rust_vocab.iter()) {
            assert_eq!(
                w,
                rust_w,
                "grammar slot {} must be identical across PHP and Rust (same words, same order)",
                i + 1
            );
        }
    }
    assert_eq!(
        kiwicaptcha::decoy_grammar_space_size(),
        27_840,
        "the shared grammar space is 32 * 29 * 30"
    );
    println!("DECOY_GRAMMAR_PHP_PARITY: OK (3 vocabularies identical)");
}

/// Real-Redis protocol-v3 decoy interop: the decoy-armed issuance
/// canonical (protocol v3, the `|decoy_field` segment appended after the
/// kid) must verify across languages, and the v2-plus-decoy combination
/// must be rejected on both sides. Runs only when a Redis URL is
/// provided and the PHP core's autoloader is reachable from this crate.
///
/// Directions covered:
///  - PHP armed issuance (protocol v3 + decoy) -> Rust production
///    verifier verifies fresh (stored record rides protocol_version 3
///    and the exact armed decoy name)
///  - Rust armed issuance (protocol v3 + decoy) -> PHP verifier
///    verifies fresh and exposes the same authenticated decoy name
///  - PHP writes a v2 record carrying decoy_field -> Rust rejects with
///    MalformedRecord (the structural gate, before any signature work)
///  - Rust writes a v2 record carrying decoy_field -> PHP rejects
///    (the parser gate fails the envelope decode closed)
#[test]
#[cfg(feature = "redis")]
fn redis_v3_decoy_interop_with_php() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — v3 decoy interop test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — v3 decoy interop test skipped");
        return;
    }
    let php_bin = std::env::var("KC_PHP_BIN").unwrap_or_else(|_| "php".to_string());
    let prefix = format!("kiwicaptcha:v3interop{}:", std::process::id());
    let client = match redis::Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis URL invalid: {e} — v3 decoy interop test skipped");
            return;
        }
    };
    {
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Redis unreachable — v3 decoy interop test skipped");
                return;
            }
        };
        let _: () = redis::cmd("PING").query(&mut conn).unwrap_or_default();
    }

    let php_script = |body: &str| -> Result<String, String> {
        let code = format!("require '{}'; {}", php_autoload, body);
        let out = std::process::Command::new(&php_bin)
            .args(["-r", &code])
            .env("KC_INTEROP_REDIS", &url)
            .env("KC_INTEROP_PREFIX", &prefix)
            .output()
            .map_err(|e| format!("php spawn failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            return Err(format!(
                "php failed ({}): {} {}",
                out.status,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(stdout)
    };

    let store = kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone());
    let verifier = kiwicaptcha::redis_verify::ProductionVerifier::new(
        kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone()),
        SECRET,
    );

    // 1. PHP armed issuance (protocol v3) -> Rust production verifier.
    //    The PHP script asserts the stored envelope carries
    //    protocol_version 3 and the armed decoy name, then hands the
    //    nonce and the name to Rust.
    let php_issue_armed = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$issuer = new KiwiCaptcha\Issuer(new KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage);
$ch = $issuer->issueWithDecoyField('login', '127.0.0.1', true);
if ($ch->decoyField === null) { fwrite(STDERR, 'armed issuance must expose a decoy field'); exit(2); }
$raw = $client->get(getenv('KC_INTEROP_PREFIX') . $ch->nonce);
if (!str_contains($raw, '"protocol_version":3')) { fwrite(STDERR, 'the stored armed record must be protocol v3'); exit(3); }
if (!str_contains($raw, '"decoy_field":"' . $ch->decoyField . '"')) { fwrite(STDERR, 'the stored armed record must carry the decoy name'); exit(4); }
echo $ch->nonce . "\n" . $ch->decoyField;
"#;
    let issued = php_script(php_issue_armed).expect("PHP must issue the armed v3 record");
    let mut issued_lines = issued.lines();
    let nonce = issued_lines.next().expect("the armed nonce");
    let decoy = issued_lines.next().expect("the armed decoy name");
    let state = into_pending(
        store
            .runtime_state(nonce)
            .expect("Rust must read the PHP-armed record"),
    )
    .expect("the PHP-armed record is pending");
    assert_eq!(
        state.protocol_version, 3,
        "a PHP armed issuance stores protocol v3"
    );
    assert_eq!(
        state.decoy_field.as_deref(),
        Some(decoy),
        "the PHP armed record carries the exact armed decoy name"
    );
    let counter = solve_for_test(&state).expect("Rust solver finds a counter");
    let token = encode_token(nonce, counter);
    let outcome = verifier.verify(
        &token,
        "login",
        "127.0.0.1",
        state.issued_at_ns + 1_000_000,
        None,
        RequestBindingExpectation::Unenforced,
    );
    match outcome {
        VerifyOutcome::Valid {
            from_stored_result,
            solve_duration_ms,
            ..
        } => {
            assert!(
                !from_stored_result,
                "the PHP-armed record verifies as a fresh derivation"
            );
            assert!(
                solve_duration_ms.is_some(),
                "a fresh derivation carries the server-measured duration"
            );
        }
        other => panic!("Rust must verify a PHP-issued armed v3 challenge, got {other:?}"),
    }
    println!("RUST_VERIFIES_PHP_ARMED_V3: OK (decoy={decoy}, counter={counter})");

    // 2. Rust armed issuance (protocol v3) -> PHP verifier.
    let rust_armed = issue_armed_for_interop();
    assert_eq!(
        rust_armed.record.protocol_version, 3,
        "a Rust armed issuance stores protocol v3"
    );
    let rust_decoy = rust_armed
        .record
        .decoy_field
        .clone()
        .expect("the Rust armed issuance carries a decoy");
    let rust_nonce = rust_armed.record.nonce.clone();
    store
        .store(&rust_armed.record)
        .expect("Rust must store the armed record");
    let rust_counter = solve_for_test(&rust_armed.record).expect("Rust solver for its own record");
    let php_verify_armed = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(fgets(STDIN));
$counter = (int) trim(fgets(STDIN));
$token = KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
$outcome = (new KiwiCaptcha\Verifier($storage))->verify($token, '0123456789abcdef0123456789abcdef', 'login', '127.0.0.1');
echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code(), 'decoy' => $outcome->decoyField()]);
"#;
    let php_armed_result = php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_verify_armed,
        format!("{rust_nonce}\n{rust_counter}\n").as_bytes(),
    )
    .expect("PHP must verify the Rust-armed record");
    let php_armed: serde_json::Value =
        serde_json::from_str(&php_armed_result).expect("the PHP verifier result is JSON");
    assert_eq!(
        php_armed["ok"], true,
        "PHP must verify a Rust-issued armed v3 challenge: {php_armed_result}"
    );
    assert_eq!(
        php_armed["decoy"].as_str(),
        Some(rust_decoy.as_str()),
        "the PHP outcome exposes the exact authenticated decoy name"
    );
    println!("PHP_VERIFIES_RUST_ARMED_V3: OK (decoy={rust_decoy})");

    // 3. PHP writes a v2 record carrying decoy_field -> Rust rejects.
    //    The PHP script patches the stored armed envelope back to
    //    protocol v2 (keeping the decoy key) and rewrites it raw, the
    //    only way a conforming storage can ever present the
    //    combination.
    let php_write_v2_decoy = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$issuer = new KiwiCaptcha\Issuer(new KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8, ttlSecs: 120, minDurationMs: 0), $storage);
$ch = $issuer->issueWithDecoyField('login', '127.0.0.1', true);
$raw = $client->get(getenv('KC_INTEROP_PREFIX') . $ch->nonce);
$data = json_decode($raw, true);
if (!isset($data['decoy_field'])) { fwrite(STDERR, 'the armed record must carry decoy_field'); exit(5); }
$data['protocol_version'] = 2;
$client->set(getenv('KC_INTEROP_PREFIX') . $ch->nonce, json_encode($data));
echo $ch->nonce;
"#;
    let v2_decoy_nonce =
        php_script(php_write_v2_decoy).expect("PHP must write the v2-plus-decoy record");
    let v2_decoy_state = into_pending(
        store
            .runtime_state(&v2_decoy_nonce)
            .expect("Rust must read the v2-plus-decoy record"),
    )
    .expect("the v2-plus-decoy record is pending");
    assert_eq!(
        v2_decoy_state.protocol_version, 2,
        "the patched record is protocol v2"
    );
    assert!(
        v2_decoy_state.decoy_field.is_some(),
        "the patched record still carries the decoy"
    );
    let v2_counter =
        solve_for_test(&v2_decoy_state).expect("Rust solver for the v2-plus-decoy record");
    let v2_token = encode_token(&v2_decoy_nonce, v2_counter);
    assert_eq!(
        verifier.verify(
            &v2_token,
            "login",
            "127.0.0.1",
            v2_decoy_state.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        ),
        VerifyOutcome::Invalid(VerifyError::MalformedRecord),
        "Rust must reject a PHP-written v2 record carrying decoy_field"
    );
    println!("RUST_REJECTS_PHP_V2_PLUS_DECOY: OK");

    // 4. Rust writes a v2 record carrying decoy_field -> PHP rejects.
    //    The record is armed, then re-versioned to 2 before storage, so
    //    the JSON a conforming verifier reads is exactly the rejected
    //    combination.
    let mut v2_decoy_rust = issue_armed_for_interop().record;
    v2_decoy_rust.protocol_version = 2;
    store
        .store(&v2_decoy_rust)
        .expect("Rust must store the v2-plus-decoy record");
    let rust_v2_counter =
        solve_for_test(&v2_decoy_rust).expect("Rust solver for the stored v2 record");
    let php_reject_v2 = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$nonce = trim(fgets(STDIN));
$counter = (int) trim(fgets(STDIN));
$token = KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
$outcome = (new KiwiCaptcha\Verifier($storage))->verify($token, '0123456789abcdef0123456789abcdef', 'login', '127.0.0.1');
echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
"#;
    let php_reject_result = php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_reject_v2,
        format!("{}\n{rust_v2_counter}\n", v2_decoy_rust.nonce).as_bytes(),
    )
    .expect("PHP must reject the Rust-written v2-plus-decoy record");
    let php_reject: serde_json::Value =
        serde_json::from_str(&php_reject_result).expect("the PHP rejection result is JSON");
    assert_eq!(
        php_reject["ok"], false,
        "PHP must reject a Rust-written v2 record carrying decoy_field: {php_reject_result}"
    );
    let code = php_reject["code"].as_str().unwrap_or_default();
    assert!(
        code == "malformed_record" || code == "record_not_found",
        "the PHP rejection is the parser gate (record_not_found) or the verifier gate (malformed_record), got {code}"
    );
    println!("PHP_REJECTS_RUST_V2_PLUS_DECOY: OK (code={code})");
}

/// Real-Redis protocol-v4 execution interop: PHP issues an
/// execution-armed (protocol v4) challenge, solves the PoW in PHP and
/// serializes the real digest:trace solution token (executed trace +
/// digest over the trace + base64url, exactly like the PHP test
/// harness). Rust decodes the serialized token with
/// [`kiwicaptcha::token::SolutionToken::decode`] — exercising the
/// digest:trace wire grammar — and verifies the stored record through
/// the production verifier, which enforces the execution binding.
/// A second PHP challenge with a tampered digest fails with the
/// deterministic ExecutionMismatch. The reverse direction runs through
/// the same Redis: Rust issues, stores, solves and serializes the
/// digest:trace token, and PHP loads the record by nonce and verifies
/// through the real verifier. Runs only when a Redis URL is
/// provided and the PHP core's autoloader is reachable from this
/// crate.
#[test]
#[cfg(feature = "redis")]
fn redis_v4_execution_interop_with_php() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — v4 execution interop test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — v4 execution interop test skipped");
        return;
    }
    let php_bin = std::env::var("KC_PHP_BIN").unwrap_or_else(|_| "php".to_string());
    let prefix = format!("kiwicaptcha:v4exec{}:", std::process::id());
    let client = match redis::Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis URL invalid: {e} — v4 execution interop test skipped");
            return;
        }
    };
    {
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Redis unreachable — v4 execution interop test skipped");
                return;
            }
        };
        let _: () = redis::cmd("PING").query(&mut conn).unwrap_or_default();
    }

    let php_script = |body: &str| -> Result<String, String> {
        let code = format!("require '{}'; {}", php_autoload, body);
        let out = std::process::Command::new(&php_bin)
            .args(["-r", &code])
            .env("KC_INTEROP_REDIS", &url)
            .env("KC_INTEROP_PREFIX", &prefix)
            .output()
            .map_err(|e| format!("php spawn failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            return Err(format!(
                "php failed ({}): {} {}",
                out.status,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(stdout)
    };

    // The PHP issue + solve + serialize body: an execution-armed v4
    // challenge is issued into the shared Redis prefix, the PoW is
    // solved in pure PHP, and the token is serialized with the real
    // digest:trace evidence (executed trace, digest over the trace,
    // base64url unpadded).
    let php_issue_armed = |tamper_digest: bool| -> String {
        let tamper = if tamper_digest { "1" } else { "0" };
        format!(
            r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$issuer = new KiwiCaptcha\Issuer(new KiwiCaptcha\Config(secretKey: '0123456789abcdef0123456789abcdef', targetBits: 8, ttlSecs: 120, minDurationMs: 0, executionKey: '0123456789abcdef0123456789abcdef'), $storage);
$ch = $issuer->issueWithExecutionField('login', '127.0.0.1', true, executionAction: 'login-action');
$raw = $client->get(getenv('KC_INTEROP_PREFIX') . $ch->nonce);
if (!str_contains($raw, '"protocol_version":4')) {{ fwrite(STDERR, 'the stored armed record must be protocol v4'); exit(2); }}
if (!str_contains($raw, '"execution_program":')) {{ fwrite(STDERR, 'the stored armed record must carry the execution program'); exit(3); }}
$record = $storage->find($ch->nonce);
$counter = 0;
do {{ $hash = hash('sha256', $record->prefix . $counter . base64_decode($record->salt, true), true); $counter++; }} while (KiwiCaptcha\Verifier::leadingZeroBits($hash) < $record->targetBits);
--$counter;
$program = KiwiCaptcha\ExecutionChallengeGenerator::decode($ch->executionProgram);
if ($program === null) {{ fwrite(STDERR, 'the issued program must parse'); exit(4); }}
$trace = KiwiCaptcha\Tests\Support\ExecutionTraceFixture::executedTraceFor($program);
$digest = KiwiCaptcha\ExecutionChallengeGenerator::digestOverTrace($ch->executionProgram, $ch->nonce, $trace);
if ($digest === null) {{ fwrite(STDERR, 'the digest over the executed trace must compute'); exit(5); }}
if ('{tamper}' === '1') {{ $digest[0] = $digest[0] === '0' ? '1' : '0'; }}
$token = KiwiCaptcha\SolutionToken::create($ch->nonce, $counter, 5000, [], $digest, base64_encode($trace))->encode();
echo $ch->nonce . "\n" . $token;
"#
        )
    };

    // 1. The positive direction: PHP issues, solves and serializes the
    //    real digest:trace token; Rust decodes it (the wire grammar)
    //    and verifies the stored record through the production
    //    verifier.
    let issued = php_script(&php_issue_armed(false))
        .expect("PHP must issue and serialize the armed v4 token");
    let mut issued_lines = issued.lines();
    let nonce = issued_lines.next().expect("the armed nonce");
    let token = issued_lines
        .next()
        .expect("the serialized digest:trace token");

    let decoded = kiwicaptcha::token::SolutionToken::decode(token)
        .expect("Rust must decode the PHP-serialized digest:trace token");
    assert_eq!(
        decoded.execution_digest.as_deref().map(str::len),
        Some(64),
        "the digest wire field must survive the decode"
    );
    assert!(
        decoded.execution_trace.is_some(),
        "the trace wire field must survive the decode"
    );

    let store = kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone());
    let state = into_pending(
        store
            .runtime_state(nonce)
            .expect("Rust must read the PHP-armed record"),
    )
    .expect("the PHP-armed record is pending");
    assert_eq!(
        state.protocol_version, 4,
        "a PHP armed issuance stores protocol v4"
    );
    let program = state
        .execution_program
        .as_deref()
        .expect("the PHP-armed record carries the program");

    // The recomputed expected digest over the decoded trace must equal
    // the digest the PHP side serialized (the decode preserved both
    // halves of the fifth segment).
    let trace_b64 = decoded.execution_trace.as_deref().expect("trace");
    let trace = {
        let standard: String = trace_b64
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();
        let padded = format!("{standard}{}", "=".repeat((4 - standard.len() % 4) % 4));
        String::from_utf8(B64.decode(padded).expect("canonical base64url trace"))
            .expect("the trace is UTF-8")
    };
    let expected =
        kiwicaptcha::execution::expected_digest_over_trace(program, &state.nonce, &trace)
            .expect("the digest over the executed trace recomputes");
    assert_eq!(
        expected,
        decoded.execution_digest.as_deref().expect("digest"),
        "the PHP digest over the executed trace must match the Rust recomputation"
    );

    let verifier = kiwicaptcha::redis_verify::ProductionVerifier::new(
        kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone()),
        SECRET,
    );
    let outcome = verifier.verify(
        token,
        "login",
        "127.0.0.1",
        state.issued_at_ns + 1_000_000,
        None,
        RequestBindingExpectation::Unenforced,
    );
    match outcome {
        VerifyOutcome::Valid {
            from_stored_result,
            solve_duration_ms,
            ..
        } => {
            assert!(
                !from_stored_result,
                "the PHP-armed v4 record verifies as a fresh derivation"
            );
            assert!(
                solve_duration_ms.is_some(),
                "a fresh derivation carries the server-measured duration"
            );
        }
        other => panic!(
            "Rust must verify a PHP-issued armed v4 challenge through the production verifier, got {other:?}"
        ),
    }
    println!("RUST_VERIFIES_PHP_ARMED_V4_EXECUTION: OK (digest={expected})");

    // 2. The negative direction: a tampered digest on a second
    //    PHP-issued armed challenge decodes cleanly (it is still 64
    //    hex) but fails the execution binding with the deterministic
    //    ExecutionMismatch.
    let tampered = php_script(&php_issue_armed(true))
        .expect("PHP must issue and serialize the tampered armed v4 token");
    let mut tampered_lines = tampered.lines();
    let tampered_nonce = tampered_lines.next().expect("the tampered nonce");
    let tampered_token = tampered_lines.next().expect("the tampered token");
    let tampered_decoded = kiwicaptcha::token::SolutionToken::decode(tampered_token)
        .expect("the tampered digest token still decodes (64 hex)");
    assert_eq!(
        tampered_decoded.execution_digest.as_deref().map(str::len),
        Some(64)
    );
    assert_ne!(
        tampered_decoded.execution_digest.as_deref(),
        Some(expected.as_str()),
        "the tampered digest must differ from the expected digest"
    );
    let tampered_state = into_pending(
        store
            .runtime_state(tampered_nonce)
            .expect("Rust must read the tampered record"),
    )
    .expect("the tampered record is pending");
    assert_eq!(
        verifier.verify(
            tampered_token,
            "login",
            "127.0.0.1",
            tampered_state.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        ),
        VerifyOutcome::Invalid(VerifyError::ExecutionMismatch),
        "a tampered execution digest must fail closed through the production verifier"
    );
    println!("RUST_REJECTS_PHP_TAMPERED_V4_EXECUTION: OK");

    // 3. The reverse direction through the same Redis: Rust issues an
    //    execution-armed (protocol v4) record, stores it through the
    //    production store, solves the PoW and serializes the real
    //    digest:trace token. PHP loads the record by nonce and verifies
    //    the Rust-serialized token through the real verifier, which
    //    enforces the execution binding.
    let reverse = issue_v4_execution_for_interop("127.0.0.1", false);
    assert_eq!(
        reverse.protocol_version, 4,
        "a Rust armed issuance stores protocol v4"
    );
    store
        .store(&reverse)
        .expect("Rust must store the reverse armed record");
    let reverse_counter =
        solve_for_test(&reverse).expect("Rust solver for the reverse armed record");
    let reverse_token = digest_trace_token(&reverse, reverse_counter);
    let php_verify_v4_armed = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$token = trim(stream_get_contents(STDIN));
$outcome = (new KiwiCaptcha\Verifier($storage))->verify($token, '0123456789abcdef0123456789abcdef', 'login', '127.0.0.1');
echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
"#;
    let php_v4_result = php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        php_verify_v4_armed,
        reverse_token.as_bytes(),
    )
    .expect("PHP must verify the Rust-issued armed v4 record");
    let php_v4: serde_json::Value =
        serde_json::from_str(&php_v4_result).expect("the PHP verifier result is JSON");
    assert_eq!(
        php_v4["ok"], true,
        "PHP must verify a Rust-issued armed v4 challenge through real Redis: {php_v4_result}"
    );
    println!("PHP_VERIFIES_RUST_ARMED_V4_EXECUTION: OK (counter={reverse_counter})");
}

#[cfg(feature = "redis")]
fn encode_token(nonce: &str, counter: u64) -> String {
    kiwicaptcha::token::SolutionToken {
        nonce: nonce.into(),
        counter,
        duration_ms: 5000,
        rsw_proof: None,
        telemetry: serde_json::json!({}),
        execution_digest: None,
        execution_trace: None,
    }
    .encode()
}

#[cfg(feature = "redis")]
fn issue_armed_for_interop() -> kiwicaptcha::challenge::Issued {
    use kiwicaptcha::challenge::{
        issue_challenge_with_decoy, BindingMode, ChallengeConfig, PoWAlgorithm,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let config = ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    issue_challenge_with_decoy(&config, "login", "127.0.0.1", now, now_ns, 0, None, true)
        .expect("armed issue")
}

/// Issue an execution-armed (protocol v4) record, the canonical surface
/// mirror of the PHP `issueWithExecutionField` interop issuance
/// (execution version 1, action "login-action"). The decoy surface is
/// armed on request.
#[cfg(feature = "redis")]
fn issue_v4_execution_for_interop(
    client_ip: &str,
    arm_decoy_field: bool,
) -> kiwicaptcha::challenge::ChallengeRecord {
    use kiwicaptcha::challenge::{
        issue_challenge_with_execution, BindingMode, ChallengeConfig, PoWAlgorithm,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let config = ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: Some(SECRET.into()),
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    issue_challenge_with_execution(
        &config,
        "login",
        client_ip,
        now,
        now_ns,
        0,
        None,
        true,
        Some("login-action"),
        Some(1),
        arm_decoy_field,
    )
    .expect("v4 execution issue")
    .record
}

/// The digest:trace solution token for an execution-armed record, built
/// exactly like the interpreter: decode the stored program, execute it
/// (the browser-equivalent executed trace), digest over the executed
/// trace, and serialize the token with the trace in its base64url
/// wire form.
#[cfg(feature = "redis")]
fn digest_trace_token(record: &kiwicaptcha::challenge::ChallengeRecord, counter: u64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let program = record
        .execution_program
        .as_deref()
        .expect("the execution-armed record carries the program");
    let decoded =
        kiwicaptcha::execution::decode(program).expect("the issued program must decode in Rust");
    let trace = kiwicaptcha::execution::fixtures::executed_trace_for(&decoded);
    let digest = kiwicaptcha::execution::expected_digest_over_trace(program, &record.nonce, &trace)
        .expect("the digest over the executed trace must compute in Rust");
    kiwicaptcha::token::SolutionToken {
        nonce: record.nonce.clone(),
        counter,
        duration_ms: 5000,
        telemetry: serde_json::json!({}),
        execution_digest: Some(digest),
        execution_trace: Some(URL_SAFE_NO_PAD.encode(trace.as_bytes())),
        rsw_proof: None,
    }
    .encode()
}

#[cfg(feature = "redis")]
fn php_script_with_input(
    php_bin: &str,
    autoload: &str,
    url: &str,
    prefix: &str,
    body: &str,
    input: &[u8],
) -> Result<String, String> {
    let code = format!("require '{}'; {}", autoload, body);
    let out = std::process::Command::new(php_bin)
        .args(["-r", &code])
        .env("KC_INTEROP_REDIS", url)
        .env("KC_INTEROP_PREFIX", prefix)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input)?;
            child.wait_with_output()
        })
        .map_err(|e| format!("php spawn failed: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(format!(
            "php failed ({}): {} {}",
            out.status,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}

#[test]
fn rust_verifies_php_issued_v4_record() {
    // The v4 direction: PHP issues an execution-armed
    // (protocol v4) record. Rust must reconstruct the byte-exact
    // canonical (the `|execution_version|execution_commitment` segments
    // inside the HMAC input), verify the commitment equivalence
    // `SHA256(stored program) == signed commitment`, and verify the
    // solved token with the recomputed execution digest.
    let Ok(path) = std::env::var("KC_PHP_RECORD") else {
        eprintln!("KC_PHP_RECORD unset — v4 cross-language test skipped");
        return;
    };
    let json = std::fs::read_to_string(&path).expect("KC_PHP_RECORD file");
    let record: kiwicaptcha::ChallengeRecord =
        serde_json::from_str(&json).expect("PHP JSON must deserialize into the Rust record");
    if record.protocol_version != 4 {
        eprintln!("KC_PHP_RECORD is not a v4 record — v4 cross-language test skipped");
        return;
    }
    assert_eq!(record.scope, "login");
    assert!(record.execution_program.is_some());
    assert_eq!(
        record.execution_version,
        Some(1),
        "execution_version is the canonical byte 1"
    );
    let program = record.execution_program.as_deref().expect("armed");
    let commitment = record.execution_commitment.as_deref().expect("armed");
    assert_eq!(commitment.len(), 64);
    assert_eq!(
        kiwicaptcha::challenge::execution_commitment(program),
        commitment,
        "the PHP-written commitment must equal the Rust recomputed SHA-256 of the stored program"
    );
    // The canonical reconstruction is byte-exact: the signed challenge
    // string is base64(canonical).signature, and the Rust reconstruction
    // must reproduce the exact bytes PHP signed.
    let canonical_from_challenge = {
        let dot = record.challenge.find('.').expect("challenge separator");
        B64.decode(&record.challenge[..dot])
            .expect("canonical base64")
    };
    let canonical_reconstructed = kiwicaptcha::challenge::canonical_signing_input_v2(&record);
    assert_eq!(
        canonical_reconstructed.as_bytes(),
        canonical_from_challenge,
        "the Rust canonical reconstruction must be byte-exact against the PHP-signed canonical"
    );
    assert!(canonical_reconstructed.ends_with(&format!("|1|{commitment}")));

    let digest = kiwicaptcha::execution::expected_digest(program, &record.nonce)
        .expect("the PHP-issued program must parse in Rust");
    let counter = solve_for_test(&record).expect("Rust solver finds a counter");
    let mut rec = record;
    let now_ns = rec.issued_at_ns + 1_000_000;
    let mut ctx = VerifyContext {
        record: &mut rec,
        secret_key: SECRET,
        secrets_by_kid: None,
        revoked_kids: None,
        counter,
        duration_ms: 5000,
        now_unix: Some(&mut || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: Some(&digest),
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
    };
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "Rust must accept a PHP-issued protocol v4 challenge"
    );
    println!("RUST_VERIFIES_PHP_V4: OK (counter={counter})");
}

#[test]
#[cfg(feature = "redis")]
fn rust_issues_v4_execution_record_for_php() {
    // Reverse direction, required-CI: Rust issues an execution-armed
    // (protocol v4) record with the decoy armed too, stores it through
    // the production Redis store, solves the PoW and serializes the
    // real digest:trace token exactly like the interpreter (decode,
    // executed trace, digest over the trace, base64url trace). The
    // record JSON plus the token (a top-level `solution_token` sibling;
    // the bare record keeps its exact serde key set) is written for the
    // PHP fixture tests/CrossLanguageVerify.php to solve and verify.
    // The PHP side decodes the token and asserts its digest and trace
    // equal the values it recomputes from the stored program. Skips
    // when the output env var, the Redis URL or the PHP autoloader is
    // missing.
    let Ok(path) = std::env::var("KC_RUST_RECORD") else {
        eprintln!("KC_RUST_RECORD unset — reverse v4 execution cross-language test skipped");
        return;
    };
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — reverse v4 execution cross-language test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — reverse v4 execution test skipped");
        return;
    }
    let client = match redis::Client::open(url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis URL invalid: {e} — reverse v4 execution test skipped");
            return;
        }
    };
    {
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Redis unreachable — reverse v4 execution test skipped");
                return;
            }
        };
        let _: () = redis::cmd("PING").query(&mut conn).unwrap_or_default();
    }

    let record = issue_v4_execution_for_interop("198.51.100.7", true);
    assert_eq!(record.protocol_version, 4);
    assert_eq!(
        record.execution_version,
        Some(1),
        "execution_version is the canonical byte 1"
    );
    let program = record.execution_program.as_deref().expect("armed");
    assert!(
        record.decoy_field.is_some(),
        "the v4 record carries the decoy segment"
    );
    assert_eq!(
        kiwicaptcha::challenge::execution_commitment(program),
        record
            .execution_commitment
            .as_deref()
            .expect("armed commitment"),
        "the Rust-issued commitment equals the SHA-256 of the stored program"
    );
    let counter = solve_for_test(&record).expect("Rust solver finds a counter");
    let token = digest_trace_token(&record, counter);

    // The record is stored through the production Redis store and read
    // back as a pending protocol-v4 armed record, so the storage write
    // path the PHP core mirrors is the production one.
    let store = kiwicaptcha::redis_verify::RedisChallengeStore::new(
        client,
        format!("kiwicaptcha:v4rev{}:", std::process::id()),
    );
    store
        .store(&record)
        .expect("Rust must store the execution-armed record");
    let stored = into_pending(
        store
            .runtime_state(&record.nonce)
            .expect("Rust must read the stored record"),
    )
    .expect("the stored record is pending");
    assert_eq!(
        stored.protocol_version, 4,
        "the production store round-trips protocol v4"
    );
    assert!(
        stored.execution_program.is_some(),
        "the production store round-trips the execution program"
    );

    let mut file = serde_json::to_value(&record)
        .expect("serialize")
        .as_object()
        .expect("the record serializes as a JSON object")
        .clone();
    file.insert(
        "solution_token".to_string(),
        serde_json::Value::String(token),
    );
    std::fs::write(
        &path,
        serde_json::to_string(&serde_json::Value::Object(file)).expect("serialize"),
    )
    .expect("write");
    println!("RUST_ISSUED v4 execution (record + digest:trace token)");
}

#[cfg(feature = "redis")]
fn issue_record_for_interop() -> kiwicaptcha::challenge::ChallengeRecord {
    use kiwicaptcha::challenge::{issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let config = ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    let issued = issue_challenge(
        &config,
        "login",
        "127.0.0.1",
        now,
        now * 1_000_000_000,
        0,
        None,
    )
    .expect("issue");
    issued.record
}

/// RSW cross-language harness (PHP issue -> Rust verify): reads a
/// PHP-issued rsw record file (env KC_PHP_RSW_RECORD) whose top-level
/// siblings carry the trapdoor pair, solves the challenge with the
/// browser-equivalent sequential squarer, and verifies it with
/// verify_solution. Skips (returns) when the env var is unset so local
/// `cargo test` stays hermetic.
#[test]
fn rust_verifies_php_issued_rsw_record() {
    let Ok(path) = std::env::var("KC_PHP_RSW_RECORD") else {
        eprintln!("KC_PHP_RSW_RECORD unset — rsw cross-language test skipped");
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("KC_PHP_RSW_RECORD file");
    let mut data: serde_json::Value =
        serde_json::from_str(&raw).expect("PHP JSON must parse into a value");
    let modulus = data
        .get("rsw_modulus_n")
        .and_then(|v| v.as_str())
        .expect("the PHP rsw record file carries rsw_modulus_n")
        .to_string();
    let lambda = data
        .get("rsw_lambda")
        .and_then(|v| v.as_str())
        .expect("the PHP rsw record file carries rsw_lambda")
        .to_string();
    if let Some(obj) = data.as_object_mut() {
        obj.remove("rsw_modulus_n");
        obj.remove("rsw_lambda");
    }
    let mut record: kiwicaptcha::ChallengeRecord =
        serde_json::from_value(data).expect("PHP JSON must deserialize into the Rust record");
    assert_eq!(record.algorithm, kiwicaptcha::challenge::PoWAlgorithm::Rsw);
    assert_eq!(
        record.protocol_version, 2,
        "PHP rsw issuance stays protocol v2"
    );

    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &record.prefix,
        &record.nonce,
        record.t as u64,
    );
    let now_ns = record.issued_at_ns + 1_000_000;
    let outcome = verify_solution(&mut kiwicaptcha::verify::VerifyContext {
        record: &mut record,
        secret_key: "0123456789abcdef0123456789abcdef",
        secrets_by_kid: None,
        revoked_kids: None,
        counter: 0,
        duration_ms: 5000,
        now_unix: None,
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: Some(&proof),
        rsw_modulus_n: Some(&modulus),
        rsw_lambda: Some(&lambda),
    });
    assert!(
        matches!(outcome, VerifyOutcome::Valid { .. }),
        "Rust must accept a PHP-issued rsw challenge"
    );
    println!("RUST_VERIFIES_PHP_RSW: OK (t={})", record.t);
}

/// RSW cross-language harness (Rust issue -> PHP verify): issues an rsw
/// record (env KC_RUST_RSW_RECORD) and writes the language-neutral JSON
/// plus the trapdoor pair as top-level siblings for the PHP job to
/// solve and verify. Skips when the output env var is unset.
#[test]
fn rust_issues_rsw_record_for_php() {
    let Ok(path) = std::env::var("KC_RUST_RSW_RECORD") else {
        eprintln!("KC_RUST_RSW_RECORD unset — reverse rsw cross-language test skipped");
        return;
    };
    use kiwicaptcha::challenge::{issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let config = ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: Some(kiwicaptcha::rsw::fixtures::MODULUS_N_B64.into()),
        rsw_lambda: Some(kiwicaptcha::rsw::fixtures::LAMBDA_B64.into()),
        rsw_t: kiwicaptcha::challenge::MIN_RSW_T,
        algorithm: PoWAlgorithm::Rsw,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    let issued =
        issue_challenge(&config, "login", "198.51.100.7", now, now_ns, 0, None).expect("issue");
    let mut top = serde_json::to_value(&issued.record).expect("serialize");
    if let Some(obj) = top.as_object_mut() {
        obj.insert(
            "rsw_modulus_n".to_string(),
            kiwicaptcha::rsw::fixtures::MODULUS_N_B64.into(),
        );
        obj.insert(
            "rsw_lambda".to_string(),
            kiwicaptcha::rsw::fixtures::LAMBDA_B64.into(),
        );
    }
    std::fs::write(&path, serde_json::to_string(&top).expect("serialize")).expect("write");
    println!(
        "RUST_ISSUED rsw nonce={} (record + trapdoor siblings)",
        issued.record.nonce
    );
}

/// Real-Redis rsw interop with PHP in both directions: PHP issues an
/// rsw challenge into the shared store and Rust verifies the solved
/// token through the production verifier, then Rust issues and PHP
/// verifies through the real PHP verifier. Runs only when a Redis URL
/// is provided and the PHP core's autoloader is reachable from this
/// crate.
#[test]
#[cfg(feature = "redis")]
fn redis_rsw_interop_with_php() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — rsw redis interop test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kiwicaptcha-php/vendor/autoload.php"
    );
    if !std::path::Path::new(php_autoload).exists() {
        eprintln!("PHP core autoloader not found — rsw redis interop test skipped");
        return;
    }
    let php_bin = std::env::var("KC_PHP_BIN").unwrap_or_else(|_| "php".to_string());
    let prefix = format!("kiwicaptcha:rswinterop{}:", std::process::id());
    let client = match redis::Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis URL invalid: {e} — rsw redis interop test skipped");
            return;
        }
    };
    {
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Redis unreachable — rsw redis interop test skipped");
                return;
            }
        };
        let _: () = redis::cmd("PING").query(&mut conn).unwrap_or_default();
    }

    let php_script = |body: &str| -> Result<String, String> {
        let code = format!("require '{}'; {}", php_autoload, body);
        let out = std::process::Command::new(&php_bin)
            .args(["-r", &code])
            .env("KC_INTEROP_REDIS", &url)
            .env("KC_INTEROP_PREFIX", &prefix)
            .env(
                "KC_INTEROP_RSW_N",
                kiwicaptcha::rsw::fixtures::MODULUS_N_B64,
            )
            .env(
                "KC_INTEROP_RSW_LAMBDA",
                kiwicaptcha::rsw::fixtures::LAMBDA_B64,
            )
            .output()
            .map_err(|e| format!("php spawn failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            return Err(format!(
                "php failed ({}): {} {}",
                out.status,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(stdout)
    };

    // 1. PHP issue + sequential solve -> Rust production verifier.
    let php_issue_solve = r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$issuer = new KiwiCaptcha\Issuer(new KiwiCaptcha\Config(
    secretKey: '0123456789abcdef0123456789abcdef',
    algorithm: KiwiCaptcha\PoWAlgorithm::Rsw,
    ttlSecs: 120,
    minDurationMs: 0,
    rswModulusN: getenv('KC_INTEROP_RSW_N'),
    rswLambda: getenv('KC_INTEROP_RSW_LAMBDA'),
    rswT: KiwiCaptcha\Config::MIN_RSW_T,
), $storage);
$ch = $issuer->issue('login', '127.0.0.1');
$proof = KiwiCaptcha\Tests\Support\RswFixture::sequentialProof($ch->prefix, $ch->nonce, $ch->t);
$token = KiwiCaptcha\SolutionToken::create($ch->nonce, 0, 5000, [], null, null, $proof)->encode();
echo $token;
"#;
    let php_token =
        php_script(php_issue_solve).expect("PHP must issue and solve the rsw challenge");
    let verifier = kiwicaptcha::redis_verify::ProductionVerifier::new(
        kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone()),
        "0123456789abcdef0123456789abcdef",
    )
    .with_rsw_trapdoor(
        kiwicaptcha::rsw::fixtures::MODULUS_N_B64,
        kiwicaptcha::rsw::fixtures::LAMBDA_B64,
    );
    let store = kiwicaptcha::redis_verify::RedisChallengeStore::new(client.clone(), prefix.clone());
    let outcome = verifier.verify(
        php_token.trim(),
        "login",
        "127.0.0.1",
        kiwicaptcha::challenge::now_epoch_micros(),
        None,
        RequestBindingExpectation::Unenforced,
    );
    match outcome {
        VerifyOutcome::Valid { .. } => {}
        other => panic!("Rust must verify the PHP-issued rsw challenge, got {other:?}"),
    }
    println!("RUST_VERIFIES_PHP_RSW_REDIS: OK");

    // 2. Rust issue + sequential solve -> PHP verifier.
    let rust_issued = {
        use kiwicaptcha::challenge::{issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let config = ChallengeConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: Some(kiwicaptcha::rsw::fixtures::MODULUS_N_B64.into()),
            rsw_lambda: Some(kiwicaptcha::rsw::fixtures::LAMBDA_B64.into()),
            rsw_t: kiwicaptcha::challenge::MIN_RSW_T,
            algorithm: PoWAlgorithm::Rsw,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            ttl_secs: 120,
            min_duration_ms: Some(0),
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 20,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        };
        issue_challenge(&config, "login", "127.0.0.1", now, now_ns, 0, None).expect("issue")
    };
    store
        .store(&rust_issued.record)
        .expect("Rust must store the rsw record");
    let rust_proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &rust_issued.record.prefix,
        &rust_issued.record.nonce,
        rust_issued.record.t as u64,
    );
    let rust_token = kiwicaptcha::token::SolutionToken {
        nonce: rust_issued.record.nonce.clone(),
        counter: 0,
        duration_ms: 5000,
        telemetry: serde_json::json!({}),
        execution_digest: None,
        execution_trace: None,
        rsw_proof: Some(rust_proof),
    }
    .encode();
    // The fixture trapdoor pair is inlined (the shared php_script_with_input
    // helper sets no extra env): the values are the same fixture constants
    // both sides embed.
    let php_verify = format!(
        r#"
$client = new \Predis\Client(getenv('KC_INTEROP_REDIS'), ['timeout' => 5.0, 'read_write_timeout' => 5.0]);
$storage = new KiwiCaptcha\Storage\RedisStorage($client, getenv('KC_INTEROP_PREFIX'));
$token = trim(stream_get_contents(STDIN));
$outcome = (new KiwiCaptcha\Verifier($storage, rswModulusN: '{N}', rswLambda: '{L}'))
    ->verify($token, '0123456789abcdef0123456789abcdef', 'login', '127.0.0.1');
echo json_encode(['ok' => $outcome->isOk(), 'code' => $outcome->code()]);
"#,
        N = kiwicaptcha::rsw::fixtures::MODULUS_N_B64,
        L = kiwicaptcha::rsw::fixtures::LAMBDA_B64
    );
    let php_result = php_script_with_input(
        &php_bin,
        php_autoload,
        &url,
        &prefix,
        &php_verify,
        rust_token.as_bytes(),
    )
    .expect("PHP must verify the Rust-issued rsw record");
    let php_json: serde_json::Value =
        serde_json::from_str(&php_result).expect("the PHP verifier result is JSON");
    assert_eq!(
        php_json["ok"], true,
        "PHP must verify a Rust-issued rsw challenge through real Redis: {php_result}"
    );
    println!("PHP_VERIFIES_RUST_RSW_REDIS: OK");
}
