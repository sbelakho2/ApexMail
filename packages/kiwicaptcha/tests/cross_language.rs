//! CI cross-language harness: loads a PHP-issued record (the PHP job's
//! record env var), solves it with the Rust solver, and verifies it with
//! verify_solution. Skips (returns) when the env var is unset so local
//! `cargo test` stays hermetic.

use kiwicaptcha::verify::{
    solve_for_test, verify_solution, RequestBindingExpectation, VerifyContext, VerifyError, VerifyOutcome,
};

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
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
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
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("9.9.9.9"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
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
/// envelope (state marker + consumed_result + operation_identity). Runs
/// only when a Redis URL is provided and the PHP core's autoloader is
/// reachable from this crate.
///
/// Directions covered:
///  - PHP issue/store -> Rust consume/verify (success + replay)
///  - Rust issue/store -> PHP consume/verify (success + replay)
#[test]
#[cfg(feature = "redis")]
fn redis_runtime_state_interop_with_php() {
    let Ok(url) = std::env::var("KC_REDIS_URL") else {
        eprintln!("KC_REDIS_URL unset — redis interop test skipped");
        return;
    };
    let php_autoload = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../kiwicaptcha-php/vendor/autoload.php"
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
