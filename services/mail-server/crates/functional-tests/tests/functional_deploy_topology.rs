//! Adversarial deploy-topology tests.
//!
//! These would FAIL if the sales-autopilot wiring regresses: the compose
//! stacks must point the api-server at the `sales-autopilot` SERVICE NAME
//! (never `0.0.0.0`, a bind address no container can dial), and the
//! api-server's config default must stay a routable loopback address.
//!
//! No YAML dependency is used in this crate, so the compose files are
//! asserted on their raw text (audit F01-adjacent hardening).

/// Read a compose file from the repository root.
fn compose_file(name: &str) -> String {
    // services/mail-server/crates/functional-tests → repo root = 4 levels up.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("could not read {}: {error}", path.display());
    })
}

/// Extract `KEY` from the `environment:` map of a 2-space-indented compose
/// service block. Panics when the service or key is absent — deleting the
/// wiring must fail the test, not silently pass it.
fn service_env_value(compose: &str, service: &str, key: &str) -> String {
    let service_header = format!("  {service}:");
    let key_prefix = format!("{key}:");
    let mut in_service = false;

    for line in compose.lines() {
        let trimmed_start = line.len() - line.trim_start().len();
        if trimmed_start == 2 && line.trim_end().ends_with(':') {
            in_service = line.trim_end() == service_header;
            continue;
        }
        if !in_service {
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(&key_prefix) {
            let value = rest.split(" #").next().unwrap_or(rest);
            return value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
        }
    }

    panic!("{service}.{key} is not wired in this compose file");
}

#[test]
fn compose_api_server_points_at_the_sales_autopilot_service_name() {
    for file in ["docker-compose.yml", "docker-compose.prod.yml"] {
        let compose = compose_file(file);
        let value = service_env_value(&compose, "api-server", "SALES_AUTOPILOT_BASE_URL");

        assert!(
            value.contains("${SALES_AUTOPILOT_BASE_URL"),
            "{file}: the value must stay overridable via SALES_AUTOPILOT_BASE_URL, got {value:?}"
        );
        assert!(
            value.contains("sales-autopilot:3010"),
            "{file}: the CP must reach the sales-autopilot SERVICE NAME on its port, got {value:?}"
        );
        assert!(
            !value.contains("0.0.0.0"),
            "{file}: 0.0.0.0 is a bind address, not a routable peer — in-container calls \
             would fail with 503. Got {value:?}"
        );
        // A bare loopback would work on a host but not between containers;
        // the service-name host is the deployment contract.
        assert!(
            !value.contains("127.0.0.1") && !value.contains("localhost"),
            "{file}: inside compose the api-server must not dial itself via loopback, got {value:?}"
        );
    }
}

#[test]
fn compose_declares_the_sales_autopilot_service_itself() {
    for file in ["docker-compose.yml", "docker-compose.prod.yml"] {
        let compose = compose_file(file);
        assert!(
            compose
                .lines()
                .any(|line| line.trim_end() == "  sales-autopilot:"),
            "{file}: the sales-autopilot service the api-server targets must be declared"
        );
    }
}

/// D-5 (live dogfood 2026-10-06): every compose file must pass the
/// api-server the variable its middleware actually READS
/// (`TRUSTED_PROXIES`), not only the legacy `DDOS_TRUSTED_PROXIES` name —
/// the base file wired only the legacy name, so X-Forwarded-For trust was
/// silently ignored and every client behind the proxy shared one limiter
/// bucket. The legacy name must be derived from the same value (or wired
/// independently) so the DDoS crate's own env reader cannot drift from the
/// api-server's.
#[test]
fn compose_api_server_passes_the_trusted_proxy_variable_the_code_reads() {
    for file in ["docker-compose.yml", "docker-compose.prod.yml"] {
        let compose = compose_file(file);
        // Panics (fails) when the key is missing — that IS the regression.
        let trusted = service_env_value(&compose, "api-server", "TRUSTED_PROXIES");
        assert!(
            trusted.contains("${TRUSTED_PROXIES"),
            "{file}: TRUSTED_PROXIES must stay overridable via the documented \
             TRUSTED_PROXIES variable, got {trusted:?}"
        );
        let legacy = service_env_value(&compose, "api-server", "DDOS_TRUSTED_PROXIES");
        assert!(
            legacy.contains("${TRUSTED_PROXIES") || legacy.contains("${DDOS_TRUSTED_PROXIES"),
            "{file}: the legacy DDOS_TRUSTED_PROXIES name must come from \
             TRUSTED_PROXIES (or itself) so the two middlewares cannot drift, \
             got {legacy:?}"
        );
    }
}

/// The api-server config must keep accepting the legacy
/// `DDOS_TRUSTED_PROXIES` name as a fallback (D-5): a deployment that only
/// sets the old name must still trust forwarded headers. Pins the
/// `trusted_proxies_from_env` helper by source text — reverting to a bare
/// `env_or("TRUSTED_PROXIES", "")` fails here.
#[test]
fn api_server_config_accepts_the_legacy_ddos_trusted_proxies_name() {
    const CONFIG_RS: &str = include_str!("../../api-server/src/config.rs");
    assert!(
        CONFIG_RS.contains("fn trusted_proxies_from_env()"),
        "api-server config.rs must keep the two-name trusted-proxy resolver"
    );
    assert!(
        CONFIG_RS.contains("env_or(\"DDOS_TRUSTED_PROXIES\", \"\")"),
        "the legacy DDOS_TRUSTED_PROXIES name must remain a fallback"
    );
}

/// The api-server config default for `SALES_AUTOPILOT_BASE_URL` must be a
/// routable loopback address, never a bind address. The config test module is
/// owned elsewhere, so this pins the exact `env_or` call in `config.rs` by
/// source text — a regression to `http://0.0.0.0:3010` fails here.
#[test]
fn api_server_sales_autopilot_default_is_loopback_not_a_bind_address() {
    const CONFIG_RS: &str = include_str!("../../api-server/src/config.rs");

    let expected = "env_or(\"SALES_AUTOPILOT_BASE_URL\", \"http://127.0.0.1:3010\")";
    assert!(
        CONFIG_RS.contains(expected),
        "api-server config.rs must default SALES_AUTOPILOT_BASE_URL to the loopback \
         address: {expected}"
    );
    assert!(
        !CONFIG_RS.contains("env_or(\"SALES_AUTOPILOT_BASE_URL\", \"http://0.0.0.0"),
        "the SALES_AUTOPILOT_BASE_URL default must never be a bind address"
    );
}
