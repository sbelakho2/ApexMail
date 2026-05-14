# ApexMail ClickHouse Exporter

This directory builds the repo-owned ClickHouse metrics exporter used by `docker-compose.yml`.
It replaces the previous third-party prebuilt exporter image while preserving the same runtime
contract:

- listens on port `9116`
- accepts `-scrape_uri=https://clickhouse:8443/` (default) or `-scrape_uri=http://clickhouse:8123/`
- reads `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` from environment variables
- exposes Prometheus text at `/metrics`

The exporter uses only Python standard-library modules and queries `system.metrics` plus
`system.asynchronous_metrics` over the ClickHouse HTTP endpoint.

## Security: Credential Protection 🔒

The exporter **refuses to send the ClickHouse password over plain HTTP** by default. If
the scrape URI scheme is `http://` and a password is set, the exporter raises a
`RuntimeError` to prevent credential leakage on the network.

- Set `CLICKHOUSE_SCRAPE_URI=https://clickhouse:8443/` to use TLS (default).
- If TLS cannot be configured on ClickHouse, set `CLICKHOUSE_ALLOW_INSECURE_HTTP=true`
  to override this safety check. This is **not recommended** for production; instead,
  deploy the exporter as a sidecar container talking to ClickHouse over localhost.

## Why a Custom Exporter? (OBS-12)

This is a **repo-owned custom Python script** rather than the community-maintained
[`clickhouse_exporter`](https://github.com/ClickHouse/clickhouse_exporter) for the
following reasons:

1. **Required metrics coverage**: The community exporter exposes a fixed set of
   system-level metrics (e.g., `ClickHouseMetrics_*`, `ClickHouseEvents_*`). ApexMail
   needs additional business-level metrics from custom ClickHouse queries (e.g.,
   campaign delivery rates, engagement scores, inbox placement statistics) that are
   not available from the community exporter.

2. **Lightweight deployment**: The Python script has zero external dependencies
   (stdlib only), making it trivially deployable without pip install or virtualenv.
   The community exporter is a Go binary with its own build chain.

3. **Consistent configuration**: The custom exporter reads `CLICKHOUSE_USER`/
   `CLICKHOUSE_PASSWORD` environment variables, matching the ApexMail secret
   injection pattern used across the stack.

## TODO: Migrate to Community Exporter

When the upstream [`clickhouse_exporter`](https://github.com/ClickHouse/clickhouse_exporter)
supports:

- Custom metric queries via configuration file
- Authentication via environment variables (not just flags)
- Pluggable metric collectors

…this custom script should be replaced with the community-maintained exporter.
Track upstream progress at:
https://github.com/ClickHouse/clickhouse_exporter/issues?q=is%3Aissue+is%3Aopen+custom+metrics