# ApexMail E2E Suite

This is a standalone, fail-first aggressive end-to-end test package.

## Goals

- Test all discovered backend routes and paths
- Test all discovered UI routes and major UX interactions
- Test account lifecycle, billing, webhooks, and service health/auth boundaries
- Probe common bug classes aggressively (auth bypass, malformed payloads, null bytes, traversal, method confusion)

## No Prewritten Test Dependency

All tests in this package are newly authored and self-contained in this folder.
No existing test files are imported.

## Prerequisites

1. Install dependencies from repository root:

```bash
pnpm install
```

2. Start the target stack (API, billing, web UIs, and optional services) with your preferred startup process.

3. Provide environment variables as needed:

```bash
export E2E_API_BASE_URL="http://127.0.0.1:3000"
export E2E_BILLING_BASE_URL="http://127.0.0.1:4100"
export E2E_WEB_BASE_URL="http://127.0.0.1:3000"
export E2E_CONTROL_PLANE_BASE_URL="http://localhost:3000"
export E2E_DEVEX_BASE_URL="http://127.0.0.1:3031"
export E2E_OBSERVABILITY_BASE_URL="http://127.0.0.1:3032"
export E2E_ENTERPRISE_BASE_URL="http://127.0.0.1:3033"

# Optional privileged tokens for deeper authenticated checks
export E2E_API_BEARER_TOKEN="..."
export E2E_BILLING_BEARER_TOKEN="..."
export E2E_INTERNAL_SERVICE_TOKEN="..."
```

The Rust `api-server` now serves both browser surfaces directly. By default, `127.0.0.1` resolves to the web SSR surface and `localhost` resolves to the control-plane SSR surface when both are hosted by the Rust UI layer.

## Run

From repository root:

```bash
pnpm --filter @apexmail/e2e run test:e2e
```

Or by phase:

```bash
pnpm --filter @apexmail/e2e run test:repo
pnpm --filter @apexmail/e2e run test:api
pnpm --filter @apexmail/e2e run test:services
pnpm --filter @apexmail/e2e run test:ui
```

## Fail-First Design Notes

- Coverage guard fails if discovered routes/pages are not exercised.
- Tests prioritize negative/abuse paths first, then expected valid behavior.
- Route sweeps validate that malformed input and unauthorized access do not produce 5xx responses.
