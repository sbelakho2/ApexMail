# ApexMail ClickHouse Exporter

This directory builds the repo-owned ClickHouse metrics exporter used by `docker-compose.yml`.
It replaces the previous third-party prebuilt exporter image while preserving the same runtime
contract:

- listens on port `9116`
- accepts `-scrape_uri=http://clickhouse:8123/`
- reads `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD`
- exposes Prometheus text at `/metrics`

The exporter uses only Python standard-library modules and queries `system.metrics` plus
`system.asynchronous_metrics` over the ClickHouse HTTP endpoint.