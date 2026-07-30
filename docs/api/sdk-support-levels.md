# SDK Support Levels

> Last updated: 2026-07-29

## Official SDK Registry

| Language | Package Name | Status | Support Level | Module Format |
|----------|-------------|--------|---------------|---------------|
| TypeScript | `@apexmail/node` | Planned | **Officially supported** | ESM + CJS |
| Python | `apexmail-python` | Planned | **Officially supported** | — |
| Go | `github.com/apexmail/apexmail-go` | Planned | **Officially supported** | — |
| Java | `com.apexmail:apexmail-java` | Planned | **Officially supported** | — |
| PHP | `apexmail/apexmail-php` | Planned | **Officially supported** | — |
| Ruby | `apexmail-ruby` | Planned | **Officially supported** | — |
| .NET | `ApexMail.DotNet` | Planned | **Officially supported** | — |
| Rust | Community | Not started | **Community maintained** | — |

## Support Level Definitions

### Officially Supported
- Maintained by ApexMail engineering
- Guaranteed response to issues within published support targets
- Regular release cadence aligned with API changes
- Semantic versioning with documented breaking change policy
- Deprecation announced 6 months in advance
- Covered by ApexMail SLA where applicable

### Community Maintained
- Maintained by the community, not ApexMail engineering
- Best-effort response to issues
- No guaranteed release cadence
- May lag behind API changes
- No SLA coverage

### Beta
- Feature-complete but not yet battle-tested
- API surface may change before stable release
- Suitable for evaluation and non-critical workloads
- Issues tracked but may not meet published support targets

### Experimental
- Early-stage development
- API surface is unstable and may change significantly
- Not recommended for production use
- Limited documentation and examples

### Deprecated
- No longer actively maintained
- Security patches only for critical vulnerabilities
- Users should migrate to a supported SDK
- End-of-life date published at least 6 months in advance

## SDK Requirements Checklist

Every officially supported SDK must provide:

| Requirement | Type | Description |
|-------------|------|-------------|
| Types | Required | TypeScript types / language-native type definitions |
| Configurable Timeout | Required | User-configurable request timeout |
| Configurable Retries | Required | User-configurable retry policy |
| Idempotency | Required | Idempotency-key support for safe retries |
| Abort Signals | Required | AbortController / cancellation token support |
| Structured Errors | Required | Typed error responses with codes |
| Request IDs | Required | Returned and accessible request IDs |
| Pagination | Required | Iterable / cursor-based pagination |
| Webhook Verify | Required | Webhook signature verification utility |
| Custom Base URL | Required | Custom base URL for private deployments |
| Unit Tests | Required | Unit test suite |
| Integration Tests | Required | Integration test suite |
| Repository | Required | Public GitHub repository |
| README | Required | README with install, send, webhook, and error examples |
| Changelog | Required | Maintained changelog |
| Versioning Policy | Required | Documented versioning policy |
| Security Policy | Required | Documented security policy |
| Supported-Runtime Policy | Required | Documented minimum runtime version |
| Browser-Secret Protection | Required | Prevents secret exposure in browser environments |
| Module Format (ESM/CJS) | Optional | ESM and CommonJS support where feasible |

## Compatibility Policy

- Officially supported SDKs target the latest stable API version
- Minor version bumps add features without breaking changes
- Major version bumps indicate breaking API changes
- Deprecated SDKs receive security patches for 6 months after deprecation announcement
- Customers are notified of breaking changes via changelog and email where applicable
