# Pricing Authority and Reconciliation

## Operational authority

ApexMail plan entitlements, prices, limits, and feature gates are operationally
owned by [the billing plan seeds](../services/mail-server/crates/billing-service/src/plans.rs),
the active `plans` database rows, and verified Stripe webhooks. The database
rows also bind approved Stripe price IDs to plan IDs.

A tenant receives paid access only after the verified Stripe subscription
lifecycle reports an entitled status. Contractually executed Enterprise
agreements are the separate, audited exception.

## Public self-service boundary

The public signup and Stripe Checkout paths support these self-service plans:

- `starter`
- `pro`
- `growth`
- `scale`

`free` is always the initial tenant entitlement. `enterprise` is a sales and
contract flow; `payg` is configured through an approved billing setup. Neither
is offered by generic public Checkout.

## Derived and non-authoritative artifacts

The following files are presentation or company-identity artifacts, not
runtime billing configuration:

- [marketing calculator data](../apps/marketing-zola/data/pricing.json)
- [marketing pricing templates](../apps/marketing-zola/templates/partials/pricing/)
- [company/claims snapshot](../apps/marketing-zola/data/canonical.json)
- [company/claims Rust constants](../compliance/src/legal_entity.rs)

The canonical company snapshot deliberately contains no plan catalog. It must
not be used to calculate bills, grant entitlement, or configure Stripe.

## Drift control

[tools/validate_pricing_drift.py](../tools/validate_pricing_drift.py) performs
structured catalog checks across runtime seeds, public data/templates,
documentation, signup/Checkout allow-lists, and generated marketing output.
The pricing workflow rebuilds the Zola site before validating generated HTML.
