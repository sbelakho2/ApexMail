//! Built-in enrichment providers.
//!
//! Inventory:
//!
//! | provider id                | fields                                                                 | cost            | source_kind   |
//! |----------------------------|------------------------------------------------------------------------|-----------------|---------------|
//! | `mock`                     | company_name, industry, employee_count, revenue_band                   | €0              | provider_api  |
//! | `http_gateway`             | firmographics, tech stack, ESP, person/email verification, language    | €0.03 default   | provider_api  |
//! | `internal_research`        | language, location, funding/change signals                             | €0              | first_party   |

pub mod http;
pub mod mock;
pub mod research;

pub use http::{HttpEnrichmentProvider, DEFAULT_HTTP_COST_EUR};
pub use mock::MockEnrichmentProvider;
pub use research::ResearchEnrichmentProvider;
