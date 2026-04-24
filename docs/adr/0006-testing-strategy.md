# ADR 0006: Testing Strategy

## Status

Accepted

> **Implementation Note (2026-04):** Backend services and browser surfaces are now Rust-owned. The active test stack is `cargo test` for Rust crates, Playwright for browser validation of Rust-served surfaces, and targeted load and chaos checks under `tools/`.

## Date

2024-01-16

## Context

Email infrastructure requires rigorous testing due to:

1. **Critical Business Impact**: Email delivery failures directly impact customer communications
2. **Complex Integration Points**: MTA, DNS, authentication protocols, and third-party services
3. **Compliance Requirements**: GDPR, HIPAA require verifiable security controls
4. **Multi-tenant Architecture**: Isolation guarantees must be continuously verified

We needed a comprehensive testing strategy that covers:
- Unit testing for business logic
- Integration testing for service interactions
- End-to-end testing for critical user flows
- Performance testing for throughput guarantees
- Chaos testing for resilience verification

## Decision

We adopt a **multi-layered testing pyramid** with the following structure:

### Layer 1: Unit Tests (70% of tests)

**Tools**: Vitest

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

**Coverage Requirements**:
- Minimum 80% line coverage
- Minimum 70% branch coverage
- Critical paths require 100% coverage

### Layer 2: Integration Tests (20% of tests)

**Tools**: Vitest + Testcontainers

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Layer 3: End-to-End Tests (10% of tests)

**Tools**: Playwright

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Layer 4: Performance Tests

**Tools**: k6

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Layer 5: Chaos Tests

**Tools**: Custom chaos testing framework (tools/chaos/)

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Test Data Management

- Use factories for generating test data
- Seed databases with consistent state
- Clean up after test runs
- Isolate tests from external services with mocks

### CI/CD Integration

```yaml
# Example workflow
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: cargo test --manifest-path services/mail-server/Cargo.toml
    - run: cargo test --manifest-path services/mail-server/Cargo.toml -p integration-tests --tests
    - run: cargo test --manifest-path services/mail-server/Cargo.toml -p ui-foundation --no-run
    - run: playwright test
    - run: k6 run tools/load/mail-api.js
    - uses: codecov/codecov-action@v3
```

## Consequences

### Positive

- **High Confidence**: Comprehensive coverage ensures reliable deployments
- **Fast Feedback**: Unit tests run in <10 seconds
- **Documentation**: Tests serve as living documentation
- **Regression Prevention**: Automated tests catch regressions early

### Negative

- **Maintenance Overhead**: Tests require ongoing maintenance
- **Initial Investment**: Significant upfront effort to establish patterns
- **Slow E2E Tests**: Full test suite takes ~15 minutes

### Mitigations

- Use snapshot testing for UI components
- Parallelize test execution
- Run E2E tests only on main branch
- Invest in test infrastructure (Testcontainers, factories)

## References

- [Testing Trophy by Kent C. Dodds](https://kentcdodds.com/blog/write-tests)
- [Vitest Documentation](https://vitest.dev/)
- [Playwright Best Practices](https://playwright.dev/docs/best-practices)
- [k6 Load Testing](https://k6.io/docs/)
