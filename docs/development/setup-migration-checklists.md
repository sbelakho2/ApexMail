# Setup and Migration Checklists

Checklist patterns for complex feature onboarding and migration-sensitive areas.

## Feature Setup Checklist Template

1. Confirm prerequisites (plan, role, domain/state)
2. Configure required settings
3. Validate test flow
4. Enable production behavior
5. Verify monitoring and rollback path

## Dedicated IP Onboarding Checklist

1. Confirm entitlement (plan + role)
2. Provision IP
3. Validate PTR and warmup state
4. Monitor send limits and reputation
5. Promote to full send when warmup completes

## Billing or Plan Migration Checklist

1. Verify current plan constraints
2. Review target plan capabilities
3. Confirm payment method
4. Execute plan change
5. Verify post-change access and limits

## Security-Sensitive Settings Checklist

1. Review impact summary
2. Confirm actor identity
3. Apply change
4. Verify audit trail entry
5. Confirm user-visible post-change state

## UX Rules

- Every checklist step must include a clear next action.
- Blocked states must include escalation path.
- Completion must be visible in the same workflow context.
