//! Connection-level adversarial tests for the IMAP server: TLS configuration
//! validation, listener binding, the accept loops' admission control, and the
//! full pre-STARTTLS plaintext state machine (`handle_plaintext_with_starttls`)
//! driven over REAL loopback TCP sockets (127.0.0.1:0) with a real TLS
//! handshake on the upgrade path.

use super::*;
use crate::adversarial_tests::{mock_connected_client, MockMailstore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::TlsConnector;

const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUVwhxJa9wz86lWTzyVQVC9bHNeXUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwOTE5MjIxMVoXDTM2MDgw
NjE5MjIxMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA6qhnhEk3kzT8KOzUcXhTbsoxnYx7zXwW8UPFQ4bshey8
Elbk3+cJBbwsknhHIebiJ8ZcaOqdzJk+5iv/fyGfE6BEGn+CEWvGMp+N3M3TmEsA
hph9mYlSeDlwv0j3+0KUBnLa9yM3MIuZYHglll+NVpc3yEo8DtVp0qNRvyykxojO
t2lB9/BZRBY4ReKIfw97HAjsM2iJ6DSUFNi0Gj1KYdRts8YeYsnzavjFT+DtmJeL
v8xejwba10wJCsajtdS+iL3rGw+szNaWshvdSEA3ZEqEqBwyJnch6gxDAGWwmjOQ
aLDg+VPTBqxlXQx2Igygf/AkAZuP893RUEYwLO9BwQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBS7l0LAXjJdC3qid0GAZlqF97CDzzAfBgNVHSMEGDAWgBS7l0LAXjJdC3qi
d0GAZlqF97CDzzAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAN7qZaPKPucQtxzwLQAgAGNmJbTpbszbNUv/eUvxLSOQuaQf
GO2K6KNKgDPt1E0jN6hpuJHY86G2wjxW3g4i+IUrHsv8dP+qOHDOG2SknYfxagph
ekb7NYuL/SpggUljQQD26flq7dpV7RXdL1q4XFHoHFjQIvNEZjyg0cDheAcwXdig
YzD9bl7yCpnvXHy4p7G0SYXAYkK8DG5FcS/ECTJw/gjMEDsIPLqPHNsC2uaq+C0R
fwY+YpZkXTmxfHPbSn0EKcbKj1lHFsvSm9ckfUjEJV5vcIk5+TewmU4cEzQloK9v
MpuYqjOkD826HkH+KCOEK4qVsx1p1MM0ASjES0E=
-----END CERTIFICATE-----"#;
const KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqqGeESTeTNPwo
7NRxeFNuyjGdjHvNfBbxQ8VDhuyF7LwSVuTf5wkFvCySeEch5uInxlxo6p3MmT7m
K/9/IZ8ToEQaf4IRa8Yyn43czdOYSwCGmH2ZiVJ4OXC/SPf7QpQGctr3Izcwi5lg
eCWWX41WlzfISjwO1WnSo1G/LKTGiM63aUH38FlEFjhF4oh/D3scCOwzaInoNJQU
2LQaPUph1G2zxh5iyfNq+MVP4O2Yl4u/zF6PBtrXTAkKxqO11L6IvesbD6zM1pay
G91IQDdkSoSoHDImdyHqDEMAZbCaM5BosOD5U9MGrGVdDHYiDKB/8CQBm4/z3dFQ
RjAs70HBAgMBAAECggEAAXIkUaUJGPDLEzY63KBf/Ls1lS2++0oWAtpu3Cq4GT7n
PYJwLnZAKKszN9uSfiGr3/B9pCaabm7dC6pmnI4cqqB6nPJvTuvL5MbVhyBUSwBe
zmWBBB27zqp1cLNKll9vla7WXS6YDeY1Taot2pxn/LoprYPyFOoRGOt5UukLsp61
CIIljP/VXW+OdAZMVBSLDDoJTbs5Hiyr/KlZ5v6ABun8wFUrkZfiDqCgzZO2+dWP
+hGmwSfBdufB+tSpPjsNIWpezrcfRpK3AVz8aiesuacxu99wTwY/0qjpbKPwucqT
G4HlQ4ZitA6m2SJUXw/E+Ij7ziT1UZzx8ltRrMrDQQKBgQD5oaWTnlAk4BJmcPUp
G7uA7uanr6r3vNR6awTn5tvqoOcDrWSWzM3YzBFD0Z4vWNDcLAB8TacCyIjQwxFl
cP3hNdhO5r0IuoIoJkbrcGeVPNoEJ0xNDpCAFrzi2CS27vqc518BSBhXgtPNMC7B
cOosHobInSi/rIgZPTPjGU8J4QKBgQDwpPbgEBSzfKuSYnUX0+/Zg9BZWEIBVd1x
Ny8B6GXCOuA75lYuTuSrylTyfCZCwTzXMhXuWAgpvHHoiyKYAL1vjSQmv8JDRO79
DtQsl8yqB3nEGJM8pHveEcO7kpEtMIUM+E3HfmvLvzaFDfd/HL0oyUBAP8oLtOG/
A+LaYPfz4QKBgQD3ybHOhv3srJL3Jrbj2EhV4k4IM0JU6RZMccCL5Md07cSCDPJl
EeReh6m3lPIc819WvUK6IGZgR+guuQKim/cWPtl48GbBrEiYS+5ns8rOA3oxV0TQ
1F0xF+Dkl0JSZ4NSjgPrBMJM02skKOiwUUHRC3gk2INjR4JM80h2619eYQKBgGGM
HV76ZcnUMaBnNNvx13ouyphNBISSD+/C1NVLJWS0hQ0C89BVvrA8lm6tEL1io40A
Co/RM43ni60eKWnAcwnzBsKGXPLz0ITYK/3fkuEhoqRw6c5dRrDgNp2kbiEJWAXH
6Y+CmaO/4RPSc48dUThlTBw/P2G7cv8BTkYDpL9BAoGAOnK0/9XWEoUAjVlPJnZh
RSWoMFYTY/7nu3u6377ccMjpQkaZLMb0y8uI+LYAlKJ+LN+ORNxS9LeGv3jHCRuL
++Z2Nalu581oXeFgZM/i7pCe0bdvqZ0xQZpQA5hJ0qDAYDvM098UF30cMS6NiGoP
KihCoEUsqFfVk4/gsIHZAN0=
-----END PRIVATE KEY-----"#;

/// The test binary never runs `main`, so the process-level ring
/// CryptoProvider that `main` installs is absent here — install it once for
/// every test that builds a rustls config (same provider as production).
fn ensure_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

fn tokenless_interceptor() -> InternalServiceAuthInterceptor {
    InternalServiceAuthInterceptor::new(None).expect("tokenless interceptor is constructible")
}

/// Write a file next to the other fixtures (temp dir under std::env::temp_dir)
/// and return its path. Each call gets a unique name.
fn temp_fixture(name: &str, contents: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("apexmail_imap_conn_tests_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");
    let path = dir.join(format!(
        "{name}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::write(&path, contents).expect("write temp fixture");
    path
}

fn test_acceptor() -> TlsAcceptor {
    ensure_crypto_provider();
    let cert_path = temp_fixture("cert.pem", CERT);
    let key_path = temp_fixture("key.pem", KEY);
    configure_tls(
        Some(cert_path.to_str().unwrap()),
        Some(key_path.to_str().unwrap()),
    )
    .expect("test cert/key configure a TLS acceptor")
    .expect("acceptor is Some for valid material")
}

fn test_tls_connector() -> TlsConnector {
    ensure_crypto_provider();
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(CERT.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<_>>()
        .expect("parse test cert");
    roots.add_parsable_certificates(certs);
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Read one CRLF-terminated line from `stream` with a timeout.
async fn read_line_tok<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(10), read_until_crlf(reader, &mut buf))
        .await
        .expect("line read within timeout")
        .expect("stream alive");
    assert!(n > 0, "connection closed before a full line arrived");
    String::from_utf8_lossy(&buf).into_owned()
}

async fn read_until_crlf<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(buf.len());
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(buf.len());
        }
    }
}

/// A server task that accepts ONE connection and runs `handle_connection`
/// (or a custom wrapper) on it; the client side is returned to the test.
struct OneShotServer {
    addr: std::net::SocketAddr,
    done: tokio::task::JoinHandle<Result<()>>,
}

async fn start_handle_connection(
    tls: Option<TlsAcceptor>,
    mailstore_addr: &str,
    is_tls: bool,
    allow_insecure_auth: bool,
) -> OneShotServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    let mailstore = mailstore_addr.to_string();
    let auth = tokenless_interceptor();
    let done = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept one connection");
        handle_connection(stream, tls, mailstore, auth, is_tls, allow_insecure_auth).await
    });
    OneShotServer { addr, done }
}

// ── configure_tls validation arms ───────────────────────────────────────────

#[test]
fn configure_tls_without_cert_defaults_to_none() {
    ensure_crypto_provider();
    // Only assert the default-path branch when the production default path is
    // genuinely absent (true on dev/CI machines): with no default cert there
    // is no implicit-TLS listener.
    if !std::path::Path::new("/opt/apexmail/certs/apexmail.crt").exists() {
        let acceptor = configure_tls(None, None).expect("missing default cert is not fatal");
        assert!(acceptor.is_none(), "no default cert => no IMAPS acceptor");
    }
}

#[test]
fn configure_tls_explicit_cert_but_missing_default_key_defaults_to_none() {
    ensure_crypto_provider();
    if !std::path::Path::new("/opt/apexmail/certs/apexmail.key").exists() {
        let cert = temp_fixture("ok-cert-4.pem", CERT);
        let acceptor = configure_tls(Some(cert.to_str().unwrap()), None)
            .expect("missing default key is not fatal");
        assert!(acceptor.is_none(), "no default key => no IMAPS acceptor");
    }
}

// ── bind_listeners ──────────────────────────────────────────────────────────

fn cli_with(listen_addr: &str, imap_port: u16, imaps_port: u16) -> Cli {
    Cli {
        listen_addr: listen_addr.to_string(),
        imap_port,
        imaps_port,
        mailstore_addr: "http://127.0.0.1:50051".to_string(),
        tls_cert_path: None,
        tls_key_path: None,
        allow_insecure_auth: false,
    }
}

#[tokio::test]
async fn bind_listeners_rejects_an_unparseable_listen_addr() {
    let cli = cli_with("not-a-listen-addr!", 0, 0);
    let err = bind_listeners(&cli, false)
        .await
        .expect_err("bad addr must fail");
    assert!(
        format!("{err:#}").contains("Failed to bind IMAP on"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn bind_listeners_without_tls_binds_only_imap() {
    // Reserve a port, release it, and rebind it for IMAP.
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let cli = cli_with("127.0.0.1", port, 0);
    let (imap, imaps) = bind_listeners(&cli, false).await.expect("bind succeeds");
    assert_eq!(imap.local_addr().expect("imap addr").port(), port);
    assert!(imaps.is_none(), "no TLS configured => no IMAPS listener");
}

#[tokio::test]
async fn bind_listeners_imaps_port_conflict_is_an_error() {
    // Hold the IMAPS port with a socket the binder cannot take.
    let squatter = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("squatter bind");
    let port = squatter.local_addr().expect("squatter addr").port();
    let cli = cli_with("127.0.0.1", 0, port);
    let err = bind_listeners(&cli, true)
        .await
        .expect_err("IMAPS port in use");
    assert!(
        format!("{err:#}").contains("Failed to bind IMAPS on"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn bind_listeners_with_tls_binds_both_ports() {
    let cli = cli_with("127.0.0.1", 0, 0);
    let (imap, imaps) = bind_listeners(&cli, true).await.expect("both bind");
    assert!(imaps.is_some(), "TLS configured => IMAPS listener bound");
    assert_ne!(
        imap.local_addr().expect("imap addr").port(),
        imaps
            .expect("checked some")
            .local_addr()
            .expect("imaps addr")
            .port(),
        "distinct ephemeral ports must be assigned"
    );
}

// ── accept-loop admission control ───────────────────────────────────────────

/// Drive `run_imap_accept_loop` over a loopback listener and observe the
/// BYE an over-cap connection receives.
#[tokio::test]
async fn imap_accept_loop_rejects_over_cap_connections_with_bye() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let limiter = Arc::new(Mutex::new(ConnectionLimiter::default()));
    // Saturate the TOTAL cap so the very first connection is over-cap.
    {
        let mut g = limiter.lock().await;
        while g.try_acquire(std::net::IpAddr::from([127, 0, 0, 1])) {}
    }
    let task = tokio::spawn(run_imap_accept_loop(
        listener,
        None,
        "http://127.0.0.1:1".to_string(),
        tokenless_interceptor(),
        false,
        limiter,
    ));
    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let line = read_line_tok(&mut client).await;
    assert!(
        line.starts_with("* BYE"),
        "over-cap connection must be rejected with BYE, got {line:?}"
    );
    task.abort();
}

#[tokio::test]
async fn imaps_accept_loop_rejects_per_ip_cap_connections_with_bye() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let limiter = Arc::new(Mutex::new(ConnectionLimiter::default()));
    // Saturate only the per-IP cap (total stays far below the limit).
    {
        let mut g = limiter.lock().await;
        let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(g.try_acquire(loopback), "per-IP slots must be available");
        }
        assert!(!g.try_acquire(loopback), "per-IP cap must now hold");
    }
    let task = tokio::spawn(run_imaps_accept_loop(
        listener,
        test_acceptor(),
        "http://127.0.0.1:1".to_string(),
        tokenless_interceptor(),
        limiter,
    ));
    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let line = read_line_tok(&mut client).await;
    assert!(
        line.starts_with("* BYE"),
        "per-IP over-cap connection must be rejected with BYE, got {line:?}"
    );
    task.abort();
}

/// The limiter's slot is RELEASED when a connection task finishes, so a
/// normal connection followed by a close leaves room for the next one.
#[tokio::test]
async fn imap_accept_loop_releases_slot_when_connection_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let limiter = Arc::new(Mutex::new(ConnectionLimiter::default()));
    {
        let mut g = limiter.lock().await;
        // Leave exactly ONE per-IP slot.
        let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
        for _ in 0..MAX_CONNECTIONS_PER_IP - 1 {
            assert!(g.try_acquire(loopback));
        }
    }
    let task = tokio::spawn(run_imap_accept_loop(
        listener,
        None,
        "http://127.0.0.1:1".to_string(),
        tokenless_interceptor(),
        false,
        limiter.clone(),
    ));
    // First connection takes the last slot and gets the plaintext greeting.
    let mut first = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect 1");
    let greeting = read_line_tok(&mut first).await;
    assert!(
        greeting.starts_with("* OK"),
        "greeting expected, got {greeting:?}"
    );
    first
        .write_all(b"a1 LOGOUT\r\n")
        .await
        .expect("logout write");
    let mut bye = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), first.read(&mut bye)).await;
    drop(first);
    // Give the release path a moment, then a second connection must ALSO be
    // admitted (the slot was freed when the first task finished).
    let mut admitted = false;
    for _ in 0..50 {
        let mut second = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect 2");
        let line = read_line_tok(&mut second).await;
        if line.starts_with("* OK") {
            admitted = true;
            break;
        }
        assert!(line.starts_with("* BYE"), "unexpected line {line:?}");
    }
    assert!(admitted, "released slot must admit the next connection");
    task.abort();
}

// ── handle_connection ───────────────────────────────────────────────────────

#[tokio::test]
async fn handle_connection_plaintext_without_tls_serves_greeting_and_commands() {
    let server = start_handle_connection(None, "http://127.0.0.1:1", false, false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let greeting = read_line_tok(&mut client).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting:?}");
    assert!(
        greeting.contains("LOGINDISABLED"),
        "plaintext without a cert must not advertise auth: {greeting:?}"
    );
    assert!(
        !greeting.contains("STARTTLS"),
        "no TLS configured => STARTTLS must not be advertised: {greeting:?}"
    );
    client.write_all(b"a1 NOOP\r\n").await.expect("noop write");
    let line = read_line_tok(&mut client).await;
    assert!(line.starts_with("a1 OK"), "NOOP over plaintext: {line:?}");
    client
        .write_all(b"a2 LOGOUT\r\n")
        .await
        .expect("logout write");
    let bye = read_line_tok(&mut client).await;
    assert!(bye.starts_with("* BYE"), "BYE expected: {bye:?}");
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    assert!(result.is_ok(), "clean plaintext session: {result:?}");
}

#[tokio::test]
async fn handle_connection_invalid_mailstore_addr_is_an_error() {
    let server = start_handle_connection(None, "not a valid uri at all", false, false).await;
    // The client may connect; the parse failure happens before any write.
    let _client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    let err = result.expect_err("invalid uri must surface an error");
    assert!(
        format!("{err:#}").contains("Invalid mailstore address"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn handle_connection_imaps_greets_over_tls_and_permits_auth() {
    let server =
        start_handle_connection(Some(test_acceptor()), "http://127.0.0.1:1", true, false).await;
    let tcp = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let connector = test_tls_connector();
    let mut tls = connector
        .connect(
            ServerName::try_from("localhost").expect("ServerName from localhost"),
            tcp,
        )
        .await
        .expect("TLS handshake against the test cert");
    let greeting = read_line_tok(&mut tls).await;
    assert!(
        greeting.starts_with("* OK"),
        "greeting over TLS: {greeting:?}"
    );
    assert!(
        greeting.contains("AUTH=PLAIN"),
        "TLS session must advertise AUTH=PLAIN: {greeting:?}"
    );
    assert!(
        !greeting.contains("STARTTLS"),
        "RFC 3501 §6.2.1: STARTTLS must not be advertised on TLS: {greeting:?}"
    );
    tls.write_all(b"a1 CAPABILITY\r\n")
        .await
        .expect("cap write");
    let line = read_line_tok(&mut tls).await;
    assert!(line.starts_with("* CAPABILITY"), "capability: {line:?}");
    let tagged = read_line_tok(&mut tls).await;
    assert!(
        tagged.starts_with("a1 OK"),
        "capability tagged OK: {tagged:?}"
    );
    tls.shutdown().await.expect("tls shutdown");
}

#[tokio::test]
async fn handle_connection_imaps_handshake_failure_is_swallowed() {
    let server =
        start_handle_connection(Some(test_acceptor()), "http://127.0.0.1:1", true, false).await;
    // A plaintext client jabbering garbage at an implicit-TLS port: the
    // handshake must fail and handle_connection returns Ok(()) (logged warn).
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    client
        .write_all(b"garbage not a tls client hello\r\n")
        .await
        .expect("garbage write");
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    assert!(
        result.is_ok(),
        "handshake failure must be a logged warn, not a connection error: {result:?}"
    );
}

// ── handle_plaintext_with_starttls state machine ────────────────────────────

/// A loopback server running the REAL pre-STARTTLS loop against a mock
/// mailstore, so LOGIN can be driven end-to-end.
struct StarttlsServer {
    addr: std::net::SocketAddr,
    done: tokio::task::JoinHandle<Result<()>>,
}

async fn start_starttls(
    acceptor: TlsAcceptor,
    mock: MockMailstore,
    allow_insecure_auth: bool,
) -> StarttlsServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut raw = ImapSession::new(mock_connected_client(mock));
    raw.tls_active = false;
    raw.allow_insecure_auth = allow_insecure_auth;
    raw.peer_ip = "127.0.0.1".to_string();
    let session = Arc::new(Mutex::new(raw));
    let done = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        handle_plaintext_with_starttls(stream, acceptor, session, allow_insecure_auth).await
    });
    StarttlsServer { addr, done }
}

#[tokio::test]
async fn pre_starttls_loop_greets_with_starttls_and_logindisabled() {
    let server = start_starttls(test_acceptor(), MockMailstore::new(), false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let greeting = read_line_tok(&mut client).await;
    assert!(greeting.starts_with("* OK"), "greeting: {greeting:?}");
    assert!(
        greeting.contains("STARTTLS"),
        "STARTTLS must be advertised on plaintext with a cert: {greeting:?}"
    );
    assert!(
        greeting.contains("LOGINDISABLED"),
        "auth must be disabled before STARTTLS: {greeting:?}"
    );
    client
        .write_all(b"a1 LOGOUT\r\n")
        .await
        .expect("logout write");
    let bye = read_line_tok(&mut client).await;
    assert!(bye.starts_with("* BYE"), "BYE: {bye:?}");
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a1 OK"), "LOGOUT tagged OK: {ok:?}");
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    assert!(result.is_ok());
}

#[tokio::test]
async fn pre_starttls_loop_answers_capability_and_noop_and_rejects_others() {
    let server = start_starttls(test_acceptor(), MockMailstore::new(), false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let _greeting = read_line_tok(&mut client).await;

    client
        .write_all(b"a1 CAPABILITY\r\n")
        .await
        .expect("cap write");
    let untagged = read_line_tok(&mut client).await;
    assert!(
        untagged.starts_with("* CAPABILITY"),
        "cap list: {untagged:?}"
    );
    assert!(
        untagged.contains("STARTTLS"),
        "cap must include STARTTLS: {untagged:?}"
    );
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a1 OK"), "CAPABILITY tagged OK: {ok:?}");

    client.write_all(b"a2 NOOP\r\n").await.expect("noop write");
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a2 OK"), "NOOP: {ok:?}");

    // RFC 3501 §6.2.1: only CAPABILITY, NOOP, STARTTLS (and the auth policy
    // routing) are allowed before the upgrade.
    client
        .write_all(b"a3 SELECT INBOX\r\n")
        .await
        .expect("select write");
    let bad = read_line_tok(&mut client).await;
    assert!(
        bad.starts_with("a3 BAD"),
        "SELECT before STARTTLS must be BAD: {bad:?}"
    );
    assert!(
        bad.contains("not allowed before STARTTLS"),
        "BAD reason: {bad:?}"
    );

    // The loop keeps serving after a BAD.
    client.write_all(b"a4 NOOP\r\n").await.expect("noop write");
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a4 OK"), "loop continues after BAD: {ok:?}");
    client
        .write_all(b"a5 LOGOUT\r\n")
        .await
        .expect("logout write");
    let _ = read_line_tok(&mut client).await;
    let _ = read_line_tok(&mut client).await;
}

#[tokio::test]
async fn pre_starttls_login_is_refused_with_privacy_required() {
    let mock = MockMailstore::new();
    mock.add_account("user@example.test", "acct-9", "pass");
    let server = start_starttls(test_acceptor(), mock, false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let _greeting = read_line_tok(&mut client).await;
    client
        .write_all(b"a1 LOGIN user@example.test pass\r\n")
        .await
        .expect("login write");
    let no = read_line_tok(&mut client).await;
    assert!(
        no.starts_with("a1 NO") && no.contains("[PRIVACYREQUIRED]"),
        "LOGIN before STARTTLS must be NO [PRIVACYREQUIRED]: {no:?}"
    );
    client
        .write_all(b"a2 LOGOUT\r\n")
        .await
        .expect("logout write");
    let _ = read_line_tok(&mut client).await;
    let _ = read_line_tok(&mut client).await;
}

/// IMAP_ALLOW_INSECURE_AUTH=true: a successful plaintext LOGIN continues the
/// session inside `serve` — CAPABILITY after auth must answer normally.
#[tokio::test]
async fn pre_starttls_insecure_auth_login_continues_the_session() {
    let mock = MockMailstore::new();
    mock.add_account("user@example.test", "acct-10", "pass");
    let server = start_starttls(test_acceptor(), mock, true).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let greeting = read_line_tok(&mut client).await;
    assert!(
        greeting.contains("AUTH=PLAIN"),
        "insecure auth must advertise AUTH=PLAIN: {greeting:?}"
    );
    assert!(
        !greeting.contains("LOGINDISABLED"),
        "insecure auth must not claim LOGINDISABLED: {greeting:?}"
    );
    client
        .write_all(b"a1 LOGIN user@example.test pass\r\n")
        .await
        .expect("login write");
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a1 OK"), "LOGIN must succeed: {ok:?}");
    // The session continues inside serve(): a follow-up command answers.
    client
        .write_all(b"a2 CAPABILITY\r\n")
        .await
        .expect("cap write");
    let untagged = read_line_tok(&mut client).await;
    assert!(
        untagged.starts_with("* CAPABILITY"),
        "post-auth capability: {untagged:?}"
    );
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a2 OK"), "post-auth tagged OK: {ok:?}");
    client
        .write_all(b"a3 LOGOUT\r\n")
        .await
        .expect("logout write");
    let _ = read_line_tok(&mut client).await;
    let _ = read_line_tok(&mut client).await;
}

#[tokio::test]
async fn starttls_upgrade_switches_session_to_tls_semantics() {
    let mock = MockMailstore::new();
    mock.add_account("user@example.test", "acct-11", "pass");
    let server = start_starttls(test_acceptor(), mock, false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let _greeting = read_line_tok(&mut client).await;
    client
        .write_all(b"a1 STARTTLS\r\n")
        .await
        .expect("starttls write");
    let ok = read_line_tok(&mut client).await;
    assert!(
        ok.starts_with("a1 OK") && ok.contains("Begin TLS"),
        "STARTTLS ack: {ok:?}"
    );
    let connector = test_tls_connector();
    let mut tls = connector
        .connect(
            ServerName::try_from("localhost").expect("ServerName from localhost"),
            client,
        )
        .await
        .expect("TLS upgrade handshake");
    // Post-upgrade: no second greeting; CAPABILITY must reflect TLS state.
    tls.write_all(b"a2 CAPABILITY\r\n")
        .await
        .expect("cap write");
    let untagged = read_line_tok(&mut tls).await;
    assert!(
        untagged.starts_with("* CAPABILITY"),
        "post-upgrade caps: {untagged:?}"
    );
    assert!(
        !untagged.contains("STARTTLS"),
        "STARTTLS must not be advertised after the upgrade: {untagged:?}"
    );
    assert!(
        untagged.contains("AUTH=PLAIN"),
        "auth must be permitted after the upgrade: {untagged:?}"
    );
    let ok = read_line_tok(&mut tls).await;
    assert!(ok.starts_with("a2 OK"), "tagged OK: {ok:?}");
    // LOGIN now works over the TLS leg.
    tls.write_all(b"a3 LOGIN user@example.test pass\r\n")
        .await
        .expect("login write");
    let ok = read_line_tok(&mut tls).await;
    assert!(ok.starts_with("a3 OK"), "LOGIN over upgraded TLS: {ok:?}");
    tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout write");
    let _ = read_line_tok(&mut tls).await;
    let _ = read_line_tok(&mut tls).await;
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    assert!(result.is_ok());
}

#[tokio::test]
async fn starttls_upgrade_handshake_failure_ends_the_connection_quietly() {
    let server = start_starttls(test_acceptor(), MockMailstore::new(), false).await;
    let mut client = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let _greeting = read_line_tok(&mut client).await;
    client
        .write_all(b"a1 STARTTLS\r\n")
        .await
        .expect("starttls write");
    let ok = read_line_tok(&mut client).await;
    assert!(ok.starts_with("a1 OK"), "ack: {ok:?}");
    // Garbage instead of a ClientHello: handshake fails; the server ends the
    // connection (Ok(())) rather than looping back to plaintext.
    client
        .write_all(b"this is not a tls client hello\r\n\r\n")
        .await
        .expect("garbage write");
    let result = tokio::time::timeout(Duration::from_secs(10), server.done)
        .await
        .expect("server finishes")
        .expect("join ok");
    assert!(
        result.is_ok(),
        "failed upgrade handshake must end quietly: {result:?}"
    );
}

// ── parse_imap_line ─────────────────────────────────────────────────────────

#[test]
fn parse_imap_line_rejects_a_line_without_a_tag() {
    let err = parse_imap_line("NOOP").expect_err("a single word has no tag/command split");
    assert!(
        format!("{err:#}").contains("No tag in command"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn parse_imap_line_splits_tag_command_and_args() {
    let (tag, cmd, args) = parse_imap_line("a001 FETCH 1:* (FLAGS)").expect("parse");
    assert_eq!(
        (tag.as_str(), cmd.as_str(), args.as_str()),
        ("a001", "FETCH", "1:* (FLAGS)")
    );
    let (tag, cmd, args) = parse_imap_line("a2 NOOP").expect("parse");
    assert_eq!(
        (tag.as_str(), cmd.as_str(), args.as_str()),
        ("a2", "NOOP", "")
    );
}
