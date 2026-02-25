//! SDK registry — list SDKs, get install commands, validate versions.
//!
//! Mirrors the TypeScript `SdkGeneratorService` (read-only registry portion).

use crate::types::{DevExError, SdkInfo, SdkLanguage};

/// In-memory registry of official ApexMail SDKs.
#[derive(Debug, Clone)]
pub struct SdkManager {
    sdks: Vec<SdkInfo>,
}

impl Default for SdkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SdkManager {
    /// Build the registry with current SDK metadata.
    pub fn new() -> Self {
        let sdks = vec![
            SdkInfo {
                language: SdkLanguage::Go,
                package_name: "github.com/apexmail/apexmail-go".into(),
                latest_version: "1.4.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-go".into(),
                install_command: "go get github.com/apexmail/apexmail-go@v1.4.0".into(),
                min_runtime_version: "1.21".into(),
            },
            SdkInfo {
                language: SdkLanguage::Java,
                package_name: "ee.apexmail:apexmail-java".into(),
                latest_version: "1.3.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-java".into(),
                install_command:
                    "<dependency>\n  <groupId>ee.apexmail</groupId>\n  <artifactId>apexmail-java</artifactId>\n  <version>1.3.0</version>\n</dependency>".into(),
                min_runtime_version: "17".into(),
            },
            SdkInfo {
                language: SdkLanguage::Node,
                package_name: "@apexmail/sdk".into(),
                latest_version: "2.1.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-node".into(),
                install_command: "npm install @apexmail/sdk".into(),
                min_runtime_version: "18.0.0".into(),
            },
            SdkInfo {
                language: SdkLanguage::Php,
                package_name: "apexmail/apexmail-php".into(),
                latest_version: "1.2.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-php".into(),
                install_command: "composer require apexmail/apexmail-php".into(),
                min_runtime_version: "8.1".into(),
            },
            SdkInfo {
                language: SdkLanguage::Python,
                package_name: "apexmail".into(),
                latest_version: "1.5.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-python".into(),
                install_command: "pip install apexmail".into(),
                min_runtime_version: "3.9".into(),
            },
            SdkInfo {
                language: SdkLanguage::Ruby,
                package_name: "apexmail".into(),
                latest_version: "1.1.0".into(),
                api_version: "2024-01".into(),
                repository_url: "https://github.com/apexmail/apexmail-ruby".into(),
                install_command: "gem install apexmail".into(),
                min_runtime_version: "3.1".into(),
            },
        ];
        Self { sdks }
    }

    /// Return all registered SDKs.
    pub fn list_sdks(&self) -> &[SdkInfo] {
        &self.sdks
    }

    /// Get SDK info for a specific language.
    pub fn get_sdk_info(&self, language: SdkLanguage) -> Result<&SdkInfo, DevExError> {
        self.sdks
            .iter()
            .find(|s| s.language == language)
            .ok_or_else(|| DevExError::UnsupportedLanguage(language.to_string()))
    }

    /// Return the canonical install command for a given language.
    pub fn get_install_command(&self, language: SdkLanguage) -> Result<String, DevExError> {
        self.get_sdk_info(language)
            .map(|s| s.install_command.clone())
    }

    /// Validate that a requested SDK version is compatible with the given API version.
    ///
    /// For now, the check is: the SDK must target the requested `api_version` (or later).
    pub fn validate_sdk_version(
        &self,
        language: SdkLanguage,
        requested_api_version: &str,
    ) -> Result<bool, DevExError> {
        let info = self.get_sdk_info(language)?;
        let sdk_version = parse_api_version(&info.api_version).ok_or_else(|| {
            DevExError::Validation(format!("Invalid SDK API version: {}", info.api_version))
        })?;
        let requested_version = parse_api_version(requested_api_version).ok_or_else(|| {
            DevExError::Validation(format!(
                "Invalid requested API version: {}",
                requested_api_version
            ))
        })?;

        Ok(sdk_version >= requested_version)
    }
}

fn parse_api_version(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('-');
    let year: u32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    Some((year, month))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_sdks_has_all_languages() {
        let mgr = SdkManager::new();
        let sdks = mgr.list_sdks();
        assert_eq!(sdks.len(), 6);
        let langs: Vec<SdkLanguage> = sdks.iter().map(|s| s.language).collect();
        assert!(langs.contains(&SdkLanguage::Go));
        assert!(langs.contains(&SdkLanguage::Python));
        assert!(langs.contains(&SdkLanguage::Ruby));
    }

    #[test]
    fn test_get_sdk_info() {
        let mgr = SdkManager::new();
        let info = mgr.get_sdk_info(SdkLanguage::Node).unwrap();
        assert_eq!(info.package_name, "@apexmail/sdk");
        assert_eq!(info.min_runtime_version, "18.0.0");
    }

    #[test]
    fn test_get_install_command() {
        let mgr = SdkManager::new();
        let cmd = mgr.get_install_command(SdkLanguage::Python).unwrap();
        assert_eq!(cmd, "pip install apexmail");
    }

    #[test]
    fn test_validate_sdk_version() {
        let mgr = SdkManager::new();
        // Current SDK targets 2024-01 → requesting 2024-01 is valid.
        assert!(mgr.validate_sdk_version(SdkLanguage::Go, "2024-01").unwrap());
        // Requesting a newer API version than SDK target should fail.
        assert!(!mgr.validate_sdk_version(SdkLanguage::Go, "2025-01").unwrap());
        // Requesting an older version should be valid (SDK is newer).
        assert!(mgr.validate_sdk_version(SdkLanguage::Go, "2023-06").unwrap());
    }
}
