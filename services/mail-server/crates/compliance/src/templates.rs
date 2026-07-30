use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateState {
    Draft,
    Published,
    Archived,
}

impl std::fmt::Display for TemplateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Archived => "archived",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub name: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub description: Option<String>,
    pub safe_escape: bool,
    pub raw_html: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedContent {
    pub locale: String,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVersion {
    pub version_id: String,
    pub template_id: String,
    pub version_number: u32,
    pub name: String,
    pub description: Option<String>,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub subject_template: Option<String>,
    pub variables: Vec<TemplateVariable>,
    pub defaults: HashMap<String, String>,
    pub raw_html: bool,
    pub state: TemplateState,
    pub locale: Option<String>,
    pub localizations: Vec<LocalizedContent>,
    pub layout_template_id: Option<String>,
    pub partial_template_ids: Vec<String>,
    pub max_size_bytes: usize,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
    pub audit_events: Vec<TemplateAuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateAuditEvent {
    pub event_id: String,
    pub action: TemplateAction,
    pub user_id: String,
    pub timestamp: DateTime<Utc>,
    pub detail: String,
    pub previous_state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateAction {
    Created,
    Updated,
    Published,
    Archived,
    RolledBack,
    VariableSchemaChanged,
    LocalizationAdded,
    LocalizationRemoved,
}

impl std::fmt::Display for TemplateAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Published => "published",
            Self::Archived => "archived",
            Self::RolledBack => "rolled_back",
            Self::VariableSchemaChanged => "variable_schema_changed",
            Self::LocalizationAdded => "localization_added",
            Self::LocalizationRemoved => "localization_removed",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub template_id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub use_case: Option<TemplateUseCase>,
    pub versions: Vec<TemplateVersion>,
    pub current_version_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateUseCase {
    Transactional,
    Broadcast,
    Automation,
    SharedLayout,
    Partial,
}

impl std::fmt::Display for TemplateUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Transactional => "transactional",
            Self::Broadcast => "broadcast",
            Self::Automation => "automation",
            Self::SharedLayout => "shared_layout",
            Self::Partial => "partial",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    pub success: bool,
    pub template_id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub rollback_time: DateTime<Utc>,
    pub rollback_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewInput {
    pub template_id: String,
    pub version_id: Option<String>,
    pub variables: HashMap<String, String>,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewOutput {
    pub subject: Option<String>,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub errors: Vec<RenderError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderError {
    pub variable_name: String,
    pub error_type: RenderErrorType,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderErrorType {
    MissingVariable,
    InvalidValue,
    EscapeError,
    SizeExceeded,
    RawHtmlViolation,
}

impl std::fmt::Display for RenderErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MissingVariable => "missing_variable",
            Self::InvalidValue => "invalid_value",
            Self::EscapeError => "escape_error",
            Self::SizeExceeded => "size_exceeded",
            Self::RawHtmlViolation => "raw_html_violation",
        };
        f.write_str(s)
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn has_html_tags(input: &str) -> bool {
    let lower = input.to_lowercase();
    lower.contains("<script")
        || lower.contains("<iframe")
        || lower.contains("<img")
        || lower.contains("<a ")
        || lower.contains("<div")
        || lower.contains("<span")
        || lower.contains("<table")
        || lower.contains("<style")
        || lower.contains("<link")
        || lower.contains("<meta")
}

/// Validate that all required variables are provided and values meet constraints.
/// Returns a list of any errors found (empty = valid).
pub fn validate_template_variables(
    version: &TemplateVersion,
    provided_vars: &HashMap<String, String>,
) -> Vec<RenderError> {
    let mut errors = Vec::new();

    for var in &version.variables {
        match provided_vars.get(&var.name) {
            Some(value) => {
                if var.raw_html && !version.raw_html && has_html_tags(value) {
                    errors.push(RenderError {
                        variable_name: var.name.clone(),
                        error_type: RenderErrorType::RawHtmlViolation,
                        message: format!(
                            "Variable '{}' contains raw HTML but the template does not permit raw HTML",
                            var.name
                        ),
                    });
                }
            }
            None => {
                if var.required && var.default_value.is_none() {
                    errors.push(RenderError {
                        variable_name: var.name.clone(),
                        error_type: RenderErrorType::MissingVariable,
                        message: format!(
                            "Required variable '{}' is missing and has no default value",
                            var.name
                        ),
                    });
                }
            }
        }
    }

    let missing_required: HashSet<&str> = version
        .variables
        .iter()
        .filter(|v| v.required && v.default_value.is_none())
        .map(|v| v.name.as_str())
        .collect();

    let provided_keys: HashSet<&str> = provided_vars.keys().map(|k| k.as_str()).collect();
    for name in missing_required.difference(&provided_keys) {
        if errors.iter().any(|e| e.variable_name == *name) {
            continue;
        }
        errors.push(RenderError {
            variable_name: name.to_string(),
            error_type: RenderErrorType::MissingVariable,
            message: format!("Required variable '{}' is missing", name),
        });
    }

    errors
}

/// Render a preview of the template with the given variable substitutions.
pub fn render_preview(
    version: &TemplateVersion,
    input: &HashMap<String, String>,
    locale: Option<&str>,
) -> PreviewOutput {
    let mut effective = HashMap::new();
    for var in &version.variables {
        let value = input
            .get(&var.name)
            .cloned()
            .or_else(|| var.default_value.clone());

        if let Some(v) = value {
            if var.safe_escape && !var.raw_html {
                effective.insert(var.name.clone(), html_escape(&v));
            } else {
                effective.insert(var.name.clone(), v);
            }
        }
    }

    let validation_errors = validate_template_variables(version, input);

    let mut localized = None;
    if let Some(loc) = locale {
        localized = version
            .localizations
            .iter()
            .find(|l| l.locale.eq_ignore_ascii_case(loc));
    }

    let resolved_html = match (localized.as_ref().and_then(|l| l.html_body.as_ref()), &version.html_body) {
        (Some(body), _) => Some(interpolate_variables(body, &effective)),
        (None, Some(body)) => Some(interpolate_variables(body, &effective)),
        _ => None,
    };

    let resolved_text = match (localized.as_ref().and_then(|l| l.text_body.as_ref()), &version.text_body) {
        (Some(body), _) => Some(interpolate_variables(body, &effective)),
        (None, Some(body)) => Some(interpolate_variables(body, &effective)),
        _ => None,
    };

    let resolved_subject = match (localized.as_ref().and_then(|l| l.subject.as_ref()), &version.subject_template) {
        (Some(subj), _) => Some(interpolate_variables(subj, &effective)),
        (None, Some(subj)) => Some(interpolate_variables(subj, &effective)),
        _ => None,
    };

    let mut warnings = Vec::new();
    for var in &version.variables {
        if !input.contains_key(&var.name) && var.default_value.is_some() {
            warnings.push(format!(
                "Variable '{}' not provided, using default value",
                var.name
            ));
        }
    }

    let rendered_size = resolved_html.as_ref().map(|h| h.len()).unwrap_or(0)
        + resolved_text.as_ref().map(|t| t.len()).unwrap_or(0);

    if rendered_size > version.max_size_bytes {
        warnings.push(format!(
            "Rendered content size {} exceeds limit {} bytes",
            rendered_size, version.max_size_bytes
        ));
    }

    PreviewOutput {
        subject: resolved_subject,
        html_body: resolved_html,
        text_body: resolved_text,
        errors: validation_errors,
        warnings,
    }
}

fn interpolate_variables(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        let placeholder = format!("{{{{{}}}}}", key);
        result = result.replace(&placeholder, value);
    }
    result
}

impl Template {
    pub fn find_version(&self, version_id: &str) -> Option<&TemplateVersion> {
        self.versions.iter().find(|v| v.version_id == version_id)
    }

    pub fn current_version(&self) -> Option<&TemplateVersion> {
        self.versions
            .iter()
            .find(|v| v.version_id == self.current_version_id)
    }

    pub fn version_history(&self) -> Vec<&TemplateVersion> {
        let mut sorted: Vec<&TemplateVersion> = self.versions.iter().collect();
        sorted.sort_by_key(|v| v.version_number);
        sorted.reverse();
        sorted
    }

    pub fn rollback_to_version(
        &mut self,
        version_number: u32,
        user_id: &str,
        reason: Option<&str>,
    ) -> Result<RollbackResult, String> {
        let target = self
            .versions
            .iter()
            .find(|v| v.version_number == version_number)
            .ok_or_else(|| format!("Version {} not found in history", version_number))?;

        let previous_version_number = self
            .current_version()
            .map(|cv| cv.version_number)
            .unwrap_or(0);

        self.current_version_id = target.version_id.clone();

        let new_version_number = self
            .versions
            .iter()
            .map(|v| v.version_number)
            .max()
            .unwrap_or(0)
            + 1;

        let mut restored = target.clone();
        restored.version_id = uuid::Uuid::new_v4().to_string();
        restored.version_number = new_version_number;
        restored.state = TemplateState::Draft;
        restored.created_at = Utc::now();
        restored.updated_at = Utc::now();
        restored.archived_at = None;
        restored.audit_events.push(TemplateAuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            action: TemplateAction::RolledBack,
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            detail: reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| format!("Rolled back from v{} to v{}", previous_version_number, version_number)),
            previous_state: None,
        });

        self.versions.push(restored);

        Ok(RollbackResult {
            success: true,
            template_id: self.template_id.clone(),
            from_version: previous_version_number,
            to_version: new_version_number,
            rollback_time: Utc::now(),
            rollback_by: user_id.to_string(),
            reason: reason.map(|r| r.to_string()),
        })
    }

    pub fn publish_version(&mut self, version_id: &str, user_id: &str) -> Result<(), String> {
        let version = self
            .versions
            .iter_mut()
            .find(|v| v.version_id == version_id)
            .ok_or_else(|| format!("Version {} not found", version_id))?;

        if version.state == TemplateState::Archived {
            return Err("Cannot publish an archived version".to_string());
        }

        if version.html_body.is_none() && version.text_body.is_none() {
            return Err("Template must have at least one body (HTML or text)".to_string());
        }

        if version.subject_template.is_none() {
            return Err("Template must have a subject".to_string());
        }

        version.state = TemplateState::Published;
        version.updated_at = Utc::now();
        self.current_version_id = version_id.to_string();
        version.audit_events.push(TemplateAuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            action: TemplateAction::Published,
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            detail: "Version published".to_string(),
            previous_state: None,
        });

        Ok(())
    }

    pub fn archive_version(&mut self, version_id: &str, user_id: &str) -> Result<(), String> {
        let version = self
            .versions
            .iter_mut()
            .find(|v| v.version_id == version_id)
            .ok_or_else(|| format!("Version {} not found", version_id))?;

        if version_id == self.current_version_id {
            return Err("Cannot archive the current published version".to_string());
        }

        version.state = TemplateState::Archived;
        version.archived_at = Some(Utc::now());
        version.updated_at = Utc::now();
        version.audit_events.push(TemplateAuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            action: TemplateAction::Archived,
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            detail: "Version archived".to_string(),
            previous_state: Some("published".to_string()),
        });

        Ok(())
    }

    pub fn add_localization(
        &mut self,
        version_id: &str,
        content: LocalizedContent,
        user_id: &str,
    ) -> Result<(), String> {
        let version = self
            .versions
            .iter_mut()
            .find(|v| v.version_id == version_id)
            .ok_or_else(|| format!("Version {} not found", version_id))?;

        version
            .localizations
            .retain(|l| l.locale != content.locale);
        version.localizations.push(content);
        version.audit_events.push(TemplateAuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            action: TemplateAction::LocalizationAdded,
            user_id: user_id.to_string(),
            timestamp: Utc::now(),
            detail: format!("Localization added for locale '{}'", version.locale.as_deref().unwrap_or("default")),
            previous_state: None,
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_basic_version() -> TemplateVersion {
        TemplateVersion {
            version_id: "v1".into(),
            template_id: "tmpl_test".into(),
            version_number: 1,
            name: "Welcome Email".into(),
            description: Some("Onboarding template".into()),
            html_body: Some("<h1>Hello {{name}}!</h1><p>{{message}}</p>".into()),
            text_body: Some("Hello {{name}}!\n\n{{message}}".into()),
            subject_template: Some("Welcome, {{name}}!".into()),
            variables: vec![
                TemplateVariable {
                    name: "name".into(),
                    required: true,
                    default_value: None,
                    description: Some("Recipient name".into()),
                    safe_escape: true,
                    raw_html: false,
                },
                TemplateVariable {
                    name: "message".into(),
                    required: true,
                    default_value: Some("Thanks for joining!".into()),
                    description: Some("Welcome message".into()),
                    safe_escape: true,
                    raw_html: false,
                },
            ],
            defaults: HashMap::from([("message".into(), "Thanks for joining!".into())]),
            raw_html: false,
            state: TemplateState::Draft,
            locale: None,
            localizations: vec![],
            layout_template_id: None,
            partial_template_ids: vec![],
            max_size_bytes: 102_400,
            created_at: Utc::now(),
            created_by: "admin".into(),
            updated_at: Utc::now(),
            archived_at: None,
            audit_events: vec![],
        }
    }

    #[test]
    fn test_validate_missing_required_variable() {
        let version = make_basic_version();
        let provided = HashMap::from([("message".into(), "Welcome!".into())]);
        let errors = validate_template_variables(&version, &provided);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].variable_name, "name");
        assert_eq!(errors[0].error_type, RenderErrorType::MissingVariable);
    }

    #[test]
    fn test_validate_all_provided() {
        let version = make_basic_version();
        let provided = HashMap::from([
            ("name".into(), "Alice".into()),
            ("message".into(), "Hello!".into()),
        ]);
        let errors = validate_template_variables(&version, &provided);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_html_escape_safe_variables() {
        let version = make_basic_version();
        let input = HashMap::from([
            ("name".into(), "<script>alert(1)</script> Bob".into()),
            ("message".into(), "Normal text".into()),
        ]);
        let output = render_preview(&version, &input, None);
        assert!(output.html_body.unwrap().contains("&lt;script&gt;"));
        assert!(output.errors.is_empty());
    }

    #[test]
    fn test_rollback_creates_new_version() {
        let old_version = TemplateVersion {
            version_id: "v0".into(),
            version_number: 0,
            html_body: Some("<p>Old</p>".into()),
            text_body: Some("Old".into()),
            subject_template: Some("Old Subject".into()),
            variables: vec![],
            defaults: HashMap::new(),
            localizations: vec![],
            audit_events: vec![],
            ..make_basic_version()
        };

        let mut template = Template {
            template_id: "tmpl_test".into(),
            tenant_id: "tenant_1".into(),
            name: "Test".into(),
            description: None,
            use_case: None,
            versions: vec![old_version.clone(), make_basic_version()],
            current_version_id: "v1".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = template.rollback_to_version(0, "admin", Some("bug fix"));
        assert!(result.is_ok());
        let rollback = result.unwrap();
        assert!(rollback.success);
        assert_eq!(rollback.from_version, 1);
        assert_eq!(rollback.to_version, 2);
    }

    #[test]
    fn test_cannot_publish_without_body() {
        let mut version = make_basic_version();
        version.html_body = None;
        version.text_body = None;

        let mut template = Template {
            template_id: "tmpl_test".into(),
            tenant_id: "tenant_1".into(),
            name: "Test".into(),
            description: None,
            use_case: None,
            versions: vec![version],
            current_version_id: "v1".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = template.publish_version("v1", "admin");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have at least one body"));
    }
}
