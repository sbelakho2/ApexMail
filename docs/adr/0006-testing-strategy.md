# ADR 0006: Testing Strategy

## Status

Accepted

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

```typescript
// Example: Email validation unit test
describe('EmailValidator', () => {
  it('should reject invalid email formats', () => {
    expect(validateEmail('invalid')).toBe(false);
    expect(validateEmail('test@')).toBe(false);
    expect(validateEmail('@domain.com')).toBe(false);
  });

  it('should accept valid email formats', () => {
    expect(validateEmail('user@domain.com')).toBe(true);
    expect(validateEmail('user+tag@sub.domain.co')).toBe(true);
  });
});
```

**Coverage Requirements**:
- Minimum 80% line coverage
- Minimum 70% branch coverage
- Critical paths require 100% coverage

### Layer 2: Integration Tests (20% of tests)

**Tools**: Vitest + Testcontainers

```typescript
// Example: Database integration test
describe('EmailRepository', () => {
  let container: PostgreSqlContainer;
  let db: Database;

  beforeAll(async () => {
    container = await new PostgreSqlContainer().start();
    db = await createConnection(container.getConnectionUri());
  });

  afterAll(async () => {
    await container.stop();
  });

  it('should persist and retrieve emails', async () => {
    const email = await repo.create({ to: 'test@example.com', subject: 'Test' });
    const retrieved = await repo.findById(email.id);
    expect(retrieved).toMatchObject(email);
  });
});
```

### Layer 3: End-to-End Tests (10% of tests)

**Tools**: Playwright

```typescript
// Example: Email sending E2E test
test('send email flow', async ({ page }) => {
  await page.goto('/dashboard');
  await page.click('text=Send Email');
  await page.fill('[name=to]', 'recipient@example.com');
  await page.fill('[name=subject]', 'Test Email');
  await page.fill('[name=body]', 'Hello World');
  await page.click('text=Send');
  await expect(page.locator('.toast')).toContainText('Email sent');
});
```

### Layer 4: Performance Tests

**Tools**: k6

```javascript
// Example: API load test
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const response = http.post('http://localhost:3000/api/emails', {
    to: 'test@example.com',
    subject: 'Load Test',
    text: 'Testing throughput',
  });
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(0.1);
}
```

### Layer 5: Chaos Tests

**Tools**: Custom chaos testing framework (tools/chaos/)

```typescript
// Example: Network partition simulation
describe('MTA Resilience', () => {
  it('should queue emails during database outage', async () => {
    await chaos.simulateFailure('postgres', { duration: '30s' });
    const result = await api.sendEmail({ to: 'test@example.com', subject: 'Test' });
    expect(result.status).toBe('queued');
    await chaos.restoreService('postgres');
    await waitFor(() => api.getEmail(result.id).status === 'delivered');
  });
});
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
    - run: pnpm install
    - run: pnpm test:unit
    - run: pnpm test:integration
    - run: pnpm test:e2e
    - run: pnpm test:coverage
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
