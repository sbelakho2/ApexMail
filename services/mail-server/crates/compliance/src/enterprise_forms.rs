use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseFormType {
    EnterprisePricing,
    PrivateCloudConsultation,
    SecurityPackageRequest,
    MigrationAssessment,
    DataResidencyInquiry,
    ArchitectureReview,
}

impl EnterpriseFormType {
    pub fn form_id(&self) -> &'static str {
        match self {
            Self::EnterprisePricing => "ENT-FRM-001",
            Self::PrivateCloudConsultation => "ENT-FRM-002",
            Self::SecurityPackageRequest => "ENT-FRM-003",
            Self::MigrationAssessment => "ENT-FRM-004",
            Self::DataResidencyInquiry => "ENT-FRM-005",
            Self::ArchitectureReview => "ENT-FRM-006",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::EnterprisePricing => "Enterprise Pricing",
            Self::PrivateCloudConsultation => "Private Cloud Consultation",
            Self::SecurityPackageRequest => "Security Package Request",
            Self::MigrationAssessment => "Migration Assessment",
            Self::DataResidencyInquiry => "Data Residency Inquiry",
            Self::ArchitectureReview => "Architecture Review",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::EnterprisePricing => "Request custom pricing for Enterprise plan with volume-based quotes and contract options.",
            Self::PrivateCloudConsultation => "Discuss Private Cloud deployment (Dedicated Tenant or BYOC) with an ApexMail engineer.",
            Self::SecurityPackageRequest => "Request security documentation package including penetration test summaries, SOC 2 attestation, and SIG/CAIQ responses.",
            Self::MigrationAssessment => "Get a migration assessment: timeline, cost estimate, and integration plan for moving from your current provider.",
            Self::DataResidencyInquiry => "Inquire about data residency options, regional deployments, and data sovereignty configurations.",
            Self::ArchitectureReview => "Schedule a technical architecture review with ApexMail engineering to validate your integration design.",
        }
    }

    pub fn routing_owner(&self) -> &'static str {
        match self {
            Self::EnterprisePricing => "sales@apexmail.ee",
            Self::PrivateCloudConsultation => "enterprise@apexmail.ee",
            Self::SecurityPackageRequest => "security@apexmail.ee",
            Self::MigrationAssessment => "enterprise@apexmail.ee",
            Self::DataResidencyInquiry => "enterprise@apexmail.ee",
            Self::ArchitectureReview => "enterprise@apexmail.ee",
        }
    }

    pub fn all_form_types() -> Vec<EnterpriseFormDefinition> {
        use EnterpriseFormType::*;
        [
            EnterprisePricing,
            PrivateCloudConsultation,
            SecurityPackageRequest,
            MigrationAssessment,
            DataResidencyInquiry,
            ArchitectureReview,
        ]
        .iter()
        .map(|ft| EnterpriseFormDefinition {
            id: ft.form_id().to_string(),
            display_name: ft.display_name().to_string(),
            description: ft.description().to_string(),
            routing_owner: ft.routing_owner().to_string(),
            required_fields: EnterpriseFormFields::required_fields(),
            optional_fields: EnterpriseFormFields::optional_fields(),
        })
        .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseFormDefinition {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub routing_owner: String,
    pub required_fields: Vec<FormField>,
    pub optional_fields: Vec<FormField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub label: String,
    pub field_type: FormFieldType,
    pub max_length: usize,
    pub validation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFieldType {
    Text,
    Email,
    Number,
    Select,
    Textarea,
}

impl FormFieldType {
    pub fn html_type(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Email => "email",
            Self::Number => "number",
            Self::Select => "select",
            Self::Textarea => "textarea",
        }
    }
}

pub struct EnterpriseFormFields;

impl EnterpriseFormFields {
    pub fn required_fields() -> Vec<FormField> {
        vec![
            FormField {
                name: "full_name".to_string(),
                label: "Full name".to_string(),
                field_type: FormFieldType::Text,
                max_length: 200,
                validation: "Required. 2–200 characters. Must contain at least one space.".to_string(),
            },
            FormField {
                name: "work_email".to_string(),
                label: "Work email".to_string(),
                field_type: FormFieldType::Email,
                max_length: 254,
                validation: "Required. Valid email format. No disposable email domains. RFC 5321/5322 compliant.".to_string(),
            },
            FormField {
                name: "company".to_string(),
                label: "Company".to_string(),
                field_type: FormFieldType::Text,
                max_length: 200,
                validation: "Required. 1–200 characters.".to_string(),
            },
            FormField {
                name: "job_title".to_string(),
                label: "Job title".to_string(),
                field_type: FormFieldType::Text,
                max_length: 150,
                validation: "Required. 1–150 characters.".to_string(),
            },
            FormField {
                name: "country".to_string(),
                label: "Country".to_string(),
                field_type: FormFieldType::Select,
                max_length: 100,
                validation: "Required. Must select a valid country.".to_string(),
            },
            FormField {
                name: "monthly_volume".to_string(),
                label: "Estimated monthly email volume".to_string(),
                field_type: FormFieldType::Number,
                max_length: 20,
                validation: "Required. Must be a positive integer. Minimum 100,000 for enterprise qualification.".to_string(),
            },
            FormField {
                name: "use_case".to_string(),
                label: "Primary use case".to_string(),
                field_type: FormFieldType::Select,
                max_length: 100,
                validation: "Required. Must select from defined options.".to_string(),
            },
        ]
    }

    pub fn optional_fields() -> Vec<FormField> {
        vec![
            FormField {
                name: "current_provider".to_string(),
                label: "Current email provider".to_string(),
                field_type: FormFieldType::Text,
                max_length: 100,
                validation: "Optional. 1–100 characters.".to_string(),
            },
            FormField {
                name: "peak_volume".to_string(),
                label: "Peak daily volume".to_string(),
                field_type: FormFieldType::Number,
                max_length: 20,
                validation: "Optional. Positive integer.".to_string(),
            },
            FormField {
                name: "required_region".to_string(),
                label: "Required deployment region".to_string(),
                field_type: FormFieldType::Select,
                max_length: 100,
                validation: "Optional. Select from available regions.".to_string(),
            },
            FormField {
                name: "compliance_requirement".to_string(),
                label: "Compliance requirements".to_string(),
                field_type: FormFieldType::Select,
                max_length: 200,
                validation: "Optional. Multi-select from defined frameworks.".to_string(),
            },
            FormField {
                name: "deployment_preference".to_string(),
                label: "Deployment preference".to_string(),
                field_type: FormFieldType::Select,
                max_length: 100,
                validation: "Optional. Shared Cloud, Dedicated Tenant, BYOC, or Not sure.".to_string(),
            },
            FormField {
                name: "target_timeline".to_string(),
                label: "Target timeline".to_string(),
                field_type: FormFieldType::Select,
                max_length: 100,
                validation: "Optional. Immediate, 1–3 months, 3–6 months, 6+ months.".to_string(),
            },
            FormField {
                name: "additional_context".to_string(),
                label: "Additional context".to_string(),
                field_type: FormFieldType::Textarea,
                max_length: 5000,
                validation: "Optional. Maximum 5000 characters. No HTML.".to_string(),
            },
        ]
    }

    pub fn all_field_names() -> Vec<String> {
        let required = Self::required_fields();
        let optional = Self::optional_fields();
        let mut names: Vec<String> = required.iter().map(|f| f.name.clone()).collect();
        names.extend(optional.iter().map(|f| f.name.clone()));
        names
    }

    pub fn total_fields() -> usize {
        Self::required_fields().len() + Self::optional_fields().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseFormSubmission {
    pub form_type: EnterpriseFormType,
    pub fields: std::collections::HashMap<String, String>,
    pub consent_given: bool,
    pub submission_timestamp: String,
    pub utm_source: Option<String>,
    pub utm_medium: Option<String>,
    pub utm_campaign: Option<String>,
    pub referrer: Option<String>,
    pub submission_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormValidationResult {
    pub valid: bool,
    pub errors: Vec<FormFieldError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFieldError {
    pub field_name: String,
    pub error_message: String,
}

pub fn validate_enterprise_form(submission: &EnterpriseFormSubmission) -> FormValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let required_fields = EnterpriseFormFields::required_fields();
    let all_valid_fields: std::collections::HashSet<String> = EnterpriseFormFields::all_field_names()
        .into_iter()
        .collect();

    for unknown in submission.fields.keys() {
        if !all_valid_fields.contains(unknown) {
            warnings.push(format!("Unknown field submitted: {unknown}"));
        }
    }

    for field in &required_fields {
        match submission.fields.get(&field.name) {
            None => {
                errors.push(FormFieldError {
                    field_name: field.name.clone(),
                    error_message: format!("{} is required.", field.label),
                });
            }
            Some(value) => {
                if value.trim().is_empty() {
                    errors.push(FormFieldError {
                        field_name: field.name.clone(),
                        error_message: format!("{} cannot be blank.", field.label),
                    });
                }
                if value.len() > field.max_length {
                    errors.push(FormFieldError {
                        field_name: field.name.clone(),
                        error_message: format!(
                            "{} exceeds maximum length of {} characters.",
                            field.label, field.max_length
                        ),
                    });
                }
                if field.field_type == FormFieldType::Email && !value.contains('@') {
                    errors.push(FormFieldError {
                        field_name: field.name.clone(),
                        error_message: format!("{} must be a valid email address.", field.label),
                    });
                }
                if field.field_type == FormFieldType::Number {
                    if let Ok(n) = value.trim().parse::<i64>() {
                        if n <= 0 {
                            errors.push(FormFieldError {
                                field_name: field.name.clone(),
                                error_message: format!("{} must be a positive number.", field.label),
                            });
                        }
                    } else {
                        errors.push(FormFieldError {
                            field_name: field.name.clone(),
                            error_message: format!("{} must be a valid number.", field.label),
                        });
                    }
                }
            }
        }
    }

    if !submission.consent_given {
        warnings.push("Consent disclosure not explicitly confirmed.".to_string());
    }

    FormValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormRoutingResult {
    pub form_type: EnterpriseFormType,
    pub submission_id: String,
    pub crm_record_created: bool,
    pub lead_owner_assigned: String,
    pub internal_notification_sent: bool,
    pub customer_acknowledgment_sent: bool,
    pub referral_source_preserved: bool,
    pub utm_parameters_preserved: bool,
    pub requested_solution_recorded: String,
    pub submission_timestamp: String,
}

pub fn validate_form_coverage() -> EnterpriseFormValidation {
    let types = EnterpriseFormType::all_form_types();
    let expected_count = 6;

    let all_have_required_fields = types.iter().all(|t| !t.required_fields.is_empty());
    let all_have_routing = types.iter().all(|t| !t.routing_owner.is_empty());
    let total_fields = EnterpriseFormFields::total_fields();

    EnterpriseFormValidation {
        total_form_types: types.len(),
        expected_count,
        all_present: types.len() == expected_count,
        all_have_required_fields,
        all_have_routing,
        required_field_count: EnterpriseFormFields::required_fields().len(),
        optional_field_count: EnterpriseFormFields::optional_fields().len(),
        total_fields,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseFormValidation {
    pub total_form_types: usize,
    pub expected_count: usize,
    pub all_present: bool,
    pub all_have_required_fields: bool,
    pub all_have_routing: bool,
    pub required_field_count: usize,
    pub optional_field_count: usize,
    pub total_fields: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_all_6_form_types_defined() {
        let types = EnterpriseFormType::all_form_types();
        assert_eq!(types.len(), 6);
    }

    #[test]
    fn test_all_forms_have_unique_ids() {
        let types = EnterpriseFormType::all_form_types();
        let mut ids = std::collections::HashSet::new();
        for t in &types {
            assert!(ids.insert(t.id.clone()), "Duplicate form ID: {}", t.id);
        }
    }

    #[test]
    fn test_required_fields_present() {
        let required = EnterpriseFormFields::required_fields();
        assert_eq!(required.len(), 7);
        let names: Vec<&str> = required.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"full_name"));
        assert!(names.contains(&"work_email"));
        assert!(names.contains(&"company"));
        assert!(names.contains(&"job_title"));
        assert!(names.contains(&"country"));
        assert!(names.contains(&"monthly_volume"));
        assert!(names.contains(&"use_case"));
    }

    #[test]
    fn test_optional_fields_present() {
        let optional = EnterpriseFormFields::optional_fields();
        assert_eq!(optional.len(), 7);
    }

    #[test]
    fn test_total_fields_14() {
        assert_eq!(EnterpriseFormFields::total_fields(), 14);
    }

    #[test]
    fn test_validate_valid_submission() {
        let mut fields = HashMap::new();
        fields.insert("full_name".to_string(), "Jane Smith".to_string());
        fields.insert("work_email".to_string(), "jane@acmecorp.com".to_string());
        fields.insert("company".to_string(), "Acme Corp".to_string());
        fields.insert("job_title".to_string(), "VP Engineering".to_string());
        fields.insert("country".to_string(), "United Kingdom".to_string());
        fields.insert("monthly_volume".to_string(), "500000".to_string());
        fields.insert("use_case".to_string(), "Transactional email".to_string());

        let submission = EnterpriseFormSubmission {
            form_type: EnterpriseFormType::EnterprisePricing,
            fields,
            consent_given: true,
            submission_timestamp: "2026-07-29T12:00:00Z".to_string(),
            utm_source: None,
            utm_medium: None,
            utm_campaign: None,
            referrer: None,
            submission_id: "sub-test-001".to_string(),
        };

        let result = validate_enterprise_form(&submission);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_missing_required_field() {
        let fields = HashMap::new();
        let submission = EnterpriseFormSubmission {
            form_type: EnterpriseFormType::EnterprisePricing,
            fields,
            consent_given: true,
            submission_timestamp: "2026-07-29T12:00:00Z".to_string(),
            utm_source: None,
            utm_medium: None,
            utm_campaign: None,
            referrer: None,
            submission_id: "sub-test-002".to_string(),
        };

        let result = validate_enterprise_form(&submission);
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 7);
    }

    #[test]
    fn test_validate_invalid_email() {
        let mut fields = HashMap::new();
        fields.insert("full_name".to_string(), "John Doe".to_string());
        fields.insert("work_email".to_string(), "not-an-email".to_string());
        fields.insert("company".to_string(), "Test Inc".to_string());
        fields.insert("job_title".to_string(), "CTO".to_string());
        fields.insert("country".to_string(), "Germany".to_string());
        fields.insert("monthly_volume".to_string(), "200000".to_string());
        fields.insert("use_case".to_string(), "SaaS platform".to_string());

        let submission = EnterpriseFormSubmission {
            form_type: EnterpriseFormType::EnterprisePricing,
            fields,
            consent_given: true,
            submission_timestamp: "2026-07-29T12:00:00Z".to_string(),
            utm_source: None,
            utm_medium: None,
            utm_campaign: None,
            referrer: None,
            submission_id: "sub-test-003".to_string(),
        };

        let result = validate_enterprise_form(&submission);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.field_name == "work_email"));
    }

    #[test]
    fn test_validate_form_coverage() {
        let validation = validate_form_coverage();
        assert!(validation.all_present);
        assert!(validation.all_have_required_fields);
        assert!(validation.all_have_routing);
        assert_eq!(validation.total_fields, 14);
    }

    #[test]
    fn test_form_routing_distinct() {
        let types = EnterpriseFormType::all_form_types();
        let mut routes = std::collections::HashMap::new();
        for t in &types {
            routes.entry(t.routing_owner.clone()).or_insert_with(Vec::new).push(t.id.clone());
        }
        assert!(routes.contains_key("sales@apexmail.ee"));
        assert!(routes.contains_key("enterprise@apexmail.ee"));
        assert!(routes.contains_key("security@apexmail.ee"));
    }
}
