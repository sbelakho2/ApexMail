use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredSection {
    Authentication,
    Scopes,
    RequestFields,
    OptionalFields,
    DataTypes,
    Validation,
    Enums,
    MaxLengths,
    MinValues,
    CompleteExamples,
    ResponseSchemas,
    ErrorSchemas,
    Pagination,
    RateLimitHeaders,
    Idempotency,
    PlanRestrictions,
    BetaLabels,
    DeprecationLabels,
    WebhookSchemas,
}

impl std::fmt::Display for RequiredSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Authentication => "authentication",
            Self::Scopes => "scopes",
            Self::RequestFields => "request_fields",
            Self::OptionalFields => "optional_fields",
            Self::DataTypes => "data_types",
            Self::Validation => "validation",
            Self::Enums => "enums",
            Self::MaxLengths => "max_lengths",
            Self::MinValues => "min_values",
            Self::CompleteExamples => "complete_examples",
            Self::ResponseSchemas => "response_schemas",
            Self::ErrorSchemas => "error_schemas",
            Self::Pagination => "pagination",
            Self::RateLimitHeaders => "rate_limit_headers",
            Self::Idempotency => "idempotency",
            Self::PlanRestrictions => "plan_restrictions",
            Self::BetaLabels => "beta_labels",
            Self::DeprecationLabels => "deprecation_labels",
            Self::WebhookSchemas => "webhook_schemas",
        };
        f.write_str(s)
    }
}

pub fn all_required_sections() -> Vec<RequiredSection> {
    use RequiredSection::*;
    vec![
        Authentication,
        Scopes,
        RequestFields,
        OptionalFields,
        DataTypes,
        Validation,
        Enums,
        MaxLengths,
        MinValues,
        CompleteExamples,
        ResponseSchemas,
        ErrorSchemas,
        Pagination,
        RateLimitHeaders,
        Idempotency,
        PlanRestrictions,
        BetaLabels,
        DeprecationLabels,
        WebhookSchemas,
    ]
}

pub const REQUIRED_SECTION_NAMES: &[&str] = &[
    "authentication",
    "scopes",
    "request_fields",
    "optional_fields",
    "data_types",
    "validation",
    "enums",
    "max_lengths",
    "min_values",
    "complete_examples",
    "response_schemas",
    "error_schemas",
    "pagination",
    "rate_limit_headers",
    "idempotency",
    "plan_restrictions",
    "beta_labels",
    "deprecation_labels",
    "webhook_schemas",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCheck {
    pub path: String,
    pub method: String,
    pub has_authentication: bool,
    pub has_scopes: bool,
    pub has_request_fields: bool,
    pub has_optional_fields: bool,
    pub has_data_types: bool,
    pub has_validation: bool,
    pub has_enums: bool,
    pub has_max_lengths: bool,
    pub has_min_values: bool,
    pub has_complete_examples: bool,
    pub has_response_schemas: bool,
    pub has_error_schemas: bool,
    pub has_pagination: bool,
    pub has_rate_limit_headers: bool,
    pub has_idempotency: bool,
    pub has_plan_restrictions: bool,
    pub has_beta_labels: bool,
    pub has_deprecation_labels: bool,
    pub has_webhook_schemas: bool,
}

impl EndpointCheck {
    pub fn missing_sections(&self) -> Vec<String> {
        let mut missing = Vec::new();

        if !self.has_authentication {
            missing.push("authentication".into());
        }
        if !self.has_scopes {
            missing.push("scopes".into());
        }
        if !self.has_request_fields {
            missing.push("request_fields".into());
        }
        if !self.has_optional_fields {
            missing.push("optional_fields".into());
        }
        if !self.has_data_types {
            missing.push("data_types".into());
        }
        if !self.has_validation {
            missing.push("validation".into());
        }
        if !self.has_enums {
            missing.push("enums".into());
        }
        if !self.has_max_lengths {
            missing.push("max_lengths".into());
        }
        if !self.has_min_values {
            missing.push("min_values".into());
        }
        if !self.has_complete_examples {
            missing.push("complete_examples".into());
        }
        if !self.has_response_schemas {
            missing.push("response_schemas".into());
        }
        if !self.has_error_schemas {
            missing.push("error_schemas".into());
        }
        if !self.has_pagination {
            missing.push("pagination".into());
        }
        if !self.has_rate_limit_headers {
            missing.push("rate_limit_headers".into());
        }
        if !self.has_idempotency {
            missing.push("idempotency".into());
        }
        if !self.has_plan_restrictions {
            missing.push("plan_restrictions".into());
        }
        if !self.has_beta_labels {
            missing.push("beta_labels".into());
        }
        if !self.has_deprecation_labels {
            missing.push("deprecation_labels".into());
        }
        if !self.has_webhook_schemas {
            missing.push("webhook_schemas".into());
        }

        missing
    }

    pub fn is_complete(&self) -> bool {
        self.missing_sections().is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiCompletenessReport {
    pub total_endpoints: usize,
    pub complete_endpoints: usize,
    pub incomplete_endpoints: usize,
    pub results: Vec<EndpointCheck>,
    pub overall_complete: bool,
    pub missing_sections_summary: HashMap<String, usize>,
}

/// Validate that an OpenAPI specification includes all required sections
/// for every public endpoint.
pub fn validate_openapi_completeness(
    endpoints: &[EndpointCheck],
) -> OpenApiCompletenessReport {
    let total = endpoints.len();
    let complete: Vec<&EndpointCheck> = endpoints.iter().filter(|e| e.is_complete()).collect();
    let incomplete: Vec<&EndpointCheck> = endpoints.iter().filter(|e| !e.is_complete()).collect();

    let mut summary: HashMap<String, usize> = HashMap::new();
    for ep in &incomplete {
        for section in ep.missing_sections() {
            *summary.entry(section).or_insert(0) += 1;
        }
    }

    OpenApiCompletenessReport {
        total_endpoints: total,
        complete_endpoints: complete.len(),
        incomplete_endpoints: incomplete.len(),
        results: endpoints.to_vec(),
        overall_complete: incomplete.is_empty(),
        missing_sections_summary: summary,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiValidation {
    pub schema_version: String,
    pub endpoints_count: usize,
    pub schemas_count: usize,
    pub has_security_definitions: bool,
    pub has_published_docs: bool,
    pub has_openapi_json: bool,
    pub has_openapi_yaml: bool,
    pub has_versioned_historical: bool,
    pub ci_breaking_change_check: bool,
    pub ci_compile_examples: bool,
    pub ci_test_sample_requests: bool,
    pub ci_generate_sdk_models: bool,
    pub ci_check_broken_links: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecVersionManifest {
    pub versions: Vec<SpecVersionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecVersionEntry {
    pub version_id: String,
    pub published_at: String,
    pub format: SpecFormat,
    pub url: String,
    pub deprecated: bool,
    pub changelog_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpecFormat {
    Json,
    Yaml,
    Both,
}

impl std::fmt::Display for SpecFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Yaml => f.write_str("yaml"),
            Self::Both => f.write_str("both"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_complete_endpoint(path: &str) -> EndpointCheck {
        EndpointCheck {
            path: path.into(),
            method: "POST".into(),
            has_authentication: true,
            has_scopes: true,
            has_request_fields: true,
            has_optional_fields: true,
            has_data_types: true,
            has_validation: true,
            has_enums: true,
            has_max_lengths: true,
            has_min_values: true,
            has_complete_examples: true,
            has_response_schemas: true,
            has_error_schemas: true,
            has_pagination: true,
            has_rate_limit_headers: true,
            has_idempotency: true,
            has_plan_restrictions: true,
            has_beta_labels: true,
            has_deprecation_labels: true,
            has_webhook_schemas: true,
        }
    }

    #[test]
    fn test_endpoint_complete_when_all_sections_present() {
        let ep = make_complete_endpoint("/v1/messages");
        assert!(ep.is_complete());
        assert!(ep.missing_sections().is_empty());
    }

    #[test]
    fn test_endpoint_incomplete_when_missing_pagination() {
        let mut ep = make_complete_endpoint("/v1/list");
        ep.has_pagination = false;
        assert!(!ep.is_complete());
        assert!(ep.missing_sections().contains(&"pagination".to_string()));
    }

    #[test]
    fn test_validate_openapi_completeness_reports_all() {
        let complete_ep = make_complete_endpoint("/v1/complete");
        let mut incomplete_ep = make_complete_endpoint("/v1/incomplete");
        incomplete_ep.has_idempotency = false;
        incomplete_ep.has_plan_restrictions = false;

        let endpoints = vec![complete_ep, incomplete_ep];
        let report = validate_openapi_completeness(&endpoints);

        assert_eq!(report.total_endpoints, 2);
        assert_eq!(report.complete_endpoints, 1);
        assert_eq!(report.incomplete_endpoints, 1);
        assert!(!report.overall_complete);
        assert_eq!(
            report.missing_sections_summary.get("idempotency").copied().unwrap_or(0),
            1
        );
        assert_eq!(
            report
                .missing_sections_summary
                .get("plan_restrictions")
                .copied()
                .unwrap_or(0),
            1
        );
    }
}
