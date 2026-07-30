# ApexMail Staging Environment — Equivalence Specification

## Purpose

This document defines the required equivalence between staging and production
environments to ensure meaningful QA. Staging must reproduce production
behavior closely enough that any feature approved in staging behaves
identically in production.

## Required Equivalence

| Dimension                  | Staging Requirement                                        |
|--------------------------- |----------------------------------------------------------- |
| Frontend framework         | Same Zola static-site generator version                    |
| Routing structure          | Identical route map                                        |
| Build system               | Same Zola build pipeline                                   |
| CMS schema                 | Same content structure and frontmatter                     |
| Authentication flow        | Same auth configuration (API gateway, same token format)   |
| Analytics event structure  | Same event schema as production                            |
| Cookie-consent logic       | Same consent banner, same cookie categories                |
| Legal footer               | Same legal entity information (read from legal_entity.rs)  |
| Pricing calculation logic  | Same cost_model.rs and pricing data                        |
| API documentation renderer | Same OpenAPI spec rendering                                 |
| Responsive breakpoints     | Same CSS breakpoints                                       |
| Status-page integration    | Same status endpoint structure                              |
| Form-validation behavior   | Same validation rules (error_contract.rs)                  |

## Prohibited Shortcuts

The staging environment MUST NOT:

- Use placeholder legal information — must read from legal_entity.rs
- Disable validation that exists in production
- Use different pricing formulas
- Exclude mobile navigation rendering
- Skip authentication integrations
- Use dummy routes that do not reflect production
- Hide error states or error pages

## Staging-Production Comparison Tests

| Test                           | Method                                              |
|------------------------------- |---------------------------------------------------- |
| Environment variables          | Diff staging vs production .env (non-secret keys)   |
| Route maps                     | Compare `zola build` output file trees             |
| Rendered page counts           | Count HTML files in staging vs production output   |
| Bundle versions                | Compare dependency hashes                           |
| Critical third-party integ     | Verify same service endpoints                       |
| Automated test suite           | Run identical test suite against both environments  |

## Intentional Differences

Any intentional difference between staging and production must be documented
here with an explicit approval. If this section is empty, no intentional
differences exist.

| Difference               | Reason                          | Approver | Date |
|--------------------------|---------------------------------|----------|------|
| (none documented)        |                                 |          |      |

## Completion Requirements

- [ ] A feature approved in staging behaves identically in production.
- [ ] Any intentional environment difference is documented above.
- [ ] No legal, pricing, authentication or conversion behavior differs
      without explicit approval recorded in this document.
