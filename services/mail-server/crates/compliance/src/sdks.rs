use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdkLanguage {
    TypeScript,
    Python,
    Go,
    Java,
    Php,
    Ruby,
    DotNet,
    Rust,
}

impl std::fmt::Display for SdkLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::TypeScript => "typescript",
            Self::Python => "python",
            Self::Go => "go",
            Self::Java => "java",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::DotNet => "dotnet",
            Self::Rust => "rust",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdkModuleFormat {
    Esm,
    Cjs,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkRequirement {
    pub id: String,
    pub name: String,
    pub description: String,
    pub required: bool,
}

impl SdkRequirement {
    pub fn new(name: &str, description: &str, required: bool) -> Self {
        Self {
            id: name.to_lowercase().replace(' ', "_"),
            name: name.to_string(),
            description: description.to_string(),
            required,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkEntry {
    pub language: SdkLanguage,
    pub package_name: String,
    pub module_format: Option<SdkModuleFormat>,
    pub requirements_status: HashMap<String, bool>,
    pub repo_url: Option<String>,
    pub readme_url: Option<String>,
    pub changelog_url: Option<String>,
    pub version: Option<String>,
    pub published: bool,
}

impl SdkEntry {
    pub fn readiness_percentage(&self) -> f64 {
        let total = self.requirements_status.len() as f64;
        if total == 0.0 {
            return 0.0;
        }
        let met = self.requirements_status.values().filter(|v| **v).count() as f64;
        (met / total) * 100.0
    }
}

pub fn standard_requirements() -> Vec<SdkRequirement> {
    vec![
        SdkRequirement::new("Types", "TypeScript types / language-native type definitions", true),
        SdkRequirement::new("Module Format (ESM/CJS)", "ESM and CommonJS support where feasible", false),
        SdkRequirement::new("Browser-Secret Protection", "Prevents secret exposure in browser environments", true),
        SdkRequirement::new("Configurable Timeout", "User-configurable request timeout", true),
        SdkRequirement::new("Configurable Retries", "User-configurable retry policy", true),
        SdkRequirement::new("Idempotency", "Idempotency-key support for safe retries", true),
        SdkRequirement::new("Abort Signals", "AbortController / cancellation token support", true),
        SdkRequirement::new("Structured Errors", "Typed error responses with codes", true),
        SdkRequirement::new("Request IDs", "Returned and accessible request IDs", true),
        SdkRequirement::new("Pagination", "Iterable / cursor-based pagination", true),
        SdkRequirement::new("Webhook Verify", "Webhook signature verification utility", true),
        SdkRequirement::new("Custom Base URL", "Custom base URL for private deployments", true),
        SdkRequirement::new("Unit Tests", "Unit test suite", true),
        SdkRequirement::new("Integration Tests", "Integration test suite", true),
        SdkRequirement::new("Repository", "Public GitHub repository", true),
        SdkRequirement::new("README", "README with install, send, webhook, and error examples", true),
        SdkRequirement::new("Changelog", "Maintained changelog", true),
        SdkRequirement::new("Versioning Policy", "Documented versioning policy", true),
        SdkRequirement::new("Security Policy", "Documented security policy", true),
        SdkRequirement::new("Supported-Runtime Policy", "Documented minimum runtime version", true),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkRegistry {
    pub sdks: Vec<SdkEntry>,
    pub requirements: Vec<SdkRequirement>,
}

impl SdkRegistry {
    pub fn new() -> Self {
        let requirements = standard_requirements();
        let req_map: HashMap<String, bool> = requirements.iter().map(|r| (r.id.clone(), false)).collect();

        let sdks = vec![
            SdkEntry {
                language: SdkLanguage::TypeScript,
                package_name: "@apexmail/node".to_string(),
                module_format: Some(SdkModuleFormat::Both),
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::Python,
                package_name: "apexmail-python".to_string(),
                module_format: None,
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::Go,
                package_name: "github.com/apexmail/apexmail-go".to_string(),
                module_format: None,
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::Java,
                package_name: "com.apexmail:apexmail-java".to_string(),
                module_format: None,
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::Php,
                package_name: "apexmail/apexmail-php".to_string(),
                module_format: None,
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::Ruby,
                package_name: "apexmail-ruby".to_string(),
                module_format: None,
                requirements_status: req_map.clone(),
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
            SdkEntry {
                language: SdkLanguage::DotNet,
                package_name: "ApexMail.DotNet".to_string(),
                module_format: None,
                requirements_status: req_map,
                repo_url: None,
                readme_url: None,
                changelog_url: None,
                version: None,
                published: false,
            },
        ];

        Self { sdks, requirements }
    }

    pub fn get_by_language(&self, language: SdkLanguage) -> Option<&SdkEntry> {
        self.sdks.iter().find(|s| s.language == language)
    }

    pub fn get_by_language_mut(&mut self, language: SdkLanguage) -> Option<&mut SdkEntry> {
        self.sdks.iter_mut().find(|s| s.language == language)
    }

    pub fn validate_sdk_readiness(&self, language: SdkLanguage) -> SdkReadinessReport {
        let sdk = self.get_by_language(language);
        let entry = match sdk {
            Some(s) => s,
            None => {
                return SdkReadinessReport {
                    language,
                    overall_ready: false,
                    completion_percentage: 0.0,
                    missing_required: self.requirements.iter().filter(|r| r.required).map(|r| r.name.clone()).collect(),
                    missing_optional: vec![],
                    ready_requirements: vec![],
                };
            }
        };

        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut ready_requirements = Vec::new();

        for req in &self.requirements {
            let met = entry.requirements_status.get(&req.id).copied().unwrap_or(false);
            if met {
                ready_requirements.push(req.name.clone());
            } else if req.required {
                missing_required.push(req.name.clone());
            } else {
                missing_optional.push(req.name.clone());
            }
        }

        let pct = entry.readiness_percentage();
        let overall_ready = missing_required.is_empty() && entry.published;

        SdkReadinessReport {
            language,
            overall_ready,
            completion_percentage: pct,
            missing_required,
            missing_optional,
            ready_requirements,
        }
    }

    pub fn mark_requirement_met(&mut self, language: SdkLanguage, requirement_ids: &[&str]) {
        if let Some(entry) = self.get_by_language_mut(language) {
            for id in requirement_ids {
                entry.requirements_status.insert(id.to_string(), true);
            }
        }
    }
}

impl Default for SdkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkReadinessReport {
    pub language: SdkLanguage,
    pub overall_ready: bool,
    pub completion_percentage: f64,
    pub missing_required: Vec<String>,
    pub missing_optional: Vec<String>,
    pub ready_requirements: Vec<String>,
}

pub fn validate_sdk_readiness(registry: &SdkRegistry, language: SdkLanguage) -> SdkReadinessReport {
    registry.validate_sdk_readiness(language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_seven_official_sdks() {
        let registry = SdkRegistry::new();
        assert_eq!(registry.sdks.len(), 7);
        let languages: Vec<SdkLanguage> = registry.sdks.iter().map(|s| s.language).collect();
        assert!(languages.contains(&SdkLanguage::TypeScript));
        assert!(languages.contains(&SdkLanguage::Python));
        assert!(languages.contains(&SdkLanguage::Go));
        assert!(languages.contains(&SdkLanguage::Java));
        assert!(languages.contains(&SdkLanguage::Php));
        assert!(languages.contains(&SdkLanguage::Ruby));
        assert!(languages.contains(&SdkLanguage::DotNet));
    }

    #[test]
    fn test_validate_sdk_readiness_all_unmet() {
        let registry = SdkRegistry::new();
        let report = validate_sdk_readiness(&registry, SdkLanguage::TypeScript);
        assert!(!report.overall_ready);
        assert_eq!(report.completion_percentage, 0.0);
        assert!(report.missing_required.len() >= 18);
    }

    #[test]
    fn test_validate_sdk_readiness_fully_met() {
        let mut registry = SdkRegistry::new();
        let all_ids: Vec<String> = registry.requirements.iter().map(|r| r.id.clone()).collect();
        let id_refs: Vec<&str> = all_ids.iter().map(|s| s.as_str()).collect();

        registry.mark_requirement_met(SdkLanguage::TypeScript, &id_refs);
        if let Some(entry) = registry.get_by_language_mut(SdkLanguage::TypeScript) {
            entry.published = true;
            entry.version = Some("1.0.0".to_string());
        }

        let report = validate_sdk_readiness(&registry, SdkLanguage::TypeScript);
        assert!(report.overall_ready);
        assert_eq!(report.completion_percentage, 100.0);
        assert!(report.missing_required.is_empty());
    }

    #[test]
    fn test_package_names_correct() {
        let registry = SdkRegistry::new();
        let ts = registry.get_by_language(SdkLanguage::TypeScript).unwrap();
        assert_eq!(ts.package_name, "@apexmail/node");
        let py = registry.get_by_language(SdkLanguage::Python).unwrap();
        assert_eq!(py.package_name, "apexmail-python");
        let go = registry.get_by_language(SdkLanguage::Go).unwrap();
        assert_eq!(go.package_name, "github.com/apexmail/apexmail-go");
        let java = registry.get_by_language(SdkLanguage::Java).unwrap();
        assert_eq!(java.package_name, "com.apexmail:apexmail-java");
        let php = registry.get_by_language(SdkLanguage::Php).unwrap();
        assert_eq!(php.package_name, "apexmail/apexmail-php");
        let ruby = registry.get_by_language(SdkLanguage::Ruby).unwrap();
        assert_eq!(ruby.package_name, "apexmail-ruby");
        let dotnet = registry.get_by_language(SdkLanguage::DotNet).unwrap();
        assert_eq!(dotnet.package_name, "ApexMail.DotNet");
    }
}
