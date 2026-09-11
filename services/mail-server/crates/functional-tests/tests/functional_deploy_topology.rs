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
