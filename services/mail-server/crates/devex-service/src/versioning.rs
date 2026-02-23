//! API versioning — list, inspect, compare, and deprecation checks.
//!
//! Mirrors the TypeScript `ApiVersioningService` with date-based versions (YYYY-MM).

use chrono::{DateTime, NaiveDate, Utc};

use crate::types::{ApiVersion, ChangelogEntry, ChangelogType, DevExError, VersionStatus};

/// In-memory API version registry.
#[derive(Debug, Clone)]
pub struct VersionRegistry {
    versions: Vec<ApiVersion>,
}

impl Default for VersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionRegistry {
    /// Build the registry with the canonical version history.
    pub fn new() -> Self {
        let versions = vec![
            ApiVersion {
                version: "2024-01".into(),
                release_date: date(2024, 1, 15),
                status: VersionStatus::Current,
                sunset_date: None,
                changelog: vec![
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Batch email sending endpoint".into(),
                        endpoint: Some("POST /v1/emails/batch".into()),
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Email templates with Handlebars support".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Real-time delivery webhooks".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Changed,
                        description: "Rate limits increased to 1000 req/min for paid plans".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Fixed,
                        description: "Timezone handling in scheduled sends".into(),
                        endpoint: None,
                        breaking: false,
                    },
                ],
            },
            ApiVersion {
                version: "2023-10".into(),
                release_date: date(2023, 10, 1),
                status: VersionStatus::Supported,
                sunset_date: Some(date(2025, 1, 1)),
                changelog: vec![
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Webhook signatures with HMAC-SHA256".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Custom tracking domains".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Changed,
                        description: "Error response format standardized".into(),
                        endpoint: None,
                        breaking: true,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Deprecated,
                        description: "Legacy /send endpoint".into(),
                        endpoint: Some("POST /v1/send".into()),
                        breaking: false,
                    },
                ],
            },
            ApiVersion {
                version: "2023-06".into(),
                release_date: date(2023, 6, 15),
                status: VersionStatus::Supported,
                sunset_date: Some(date(2024, 9, 1)),
                changelog: vec![
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Suppression list management".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Email validation endpoint".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Changed,
                        description: "Pagination uses cursor-based pagination".into(),
                        endpoint: None,
                        breaking: true,
                    },
                ],
            },
            ApiVersion {
                version: "2023-01".into(),
                release_date: date(2023, 1, 10),
                status: VersionStatus::Deprecated,
                sunset_date: Some(date(2024, 6, 1)),
                changelog: vec![
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Initial API release".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Email sending".into(),
                        endpoint: None,
                        breaking: false,
                    },
                    ChangelogEntry {
                        change_type: ChangelogType::Added,
                        description: "Basic analytics".into(),
                        endpoint: None,
                        breaking: false,
                    },
                ],
            },
            ApiVersion {
                version: "2022-10".into(),
                release_date: date(2022, 10, 1),
                status: VersionStatus::Sunset,
                sunset_date: Some(date(2023, 12, 1)),
                changelog: vec![ChangelogEntry {
                    change_type: ChangelogType::Added,
                    description: "Beta API release".into(),
                    endpoint: None,
                    breaking: false,
                }],
            },
        ];
        Self { versions }
    }

    /// Return all known versions, newest first.
    pub fn list_versions(&self) -> &[ApiVersion] {
        &self.versions
    }

    /// Look up a specific version by its `YYYY-MM` string.
    pub fn get_version(&self, version: &str) -> Result<&ApiVersion, DevExError> {
        self.versions
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| DevExError::VersionNotFound(version.to_string()))
    }

    /// Check if a version is deprecated or sunset.
    pub fn is_deprecated(&self, version: &str) -> bool {
        self.versions.iter().any(|v| {
            v.version == version
                && matches!(v.status, VersionStatus::Deprecated | VersionStatus::Sunset)
        })
    }

    /// Compare two version strings chronologically.
    ///
    /// Returns `Ordering::Less` if `a` was released before `b`,
    /// `Ordering::Greater` if after, and `Ordering::Equal` if same.
    pub fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
        let parse = |v: &str| -> (i32, u32) {
            let parts: Vec<&str> = v.split('-').collect();
            let year = parts.first().and_then(|p| p.parse::<i32>().ok()).unwrap_or(0);
            let month = parts.get(1).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
            (year, month)
        };
        let va = parse(a);
        let vb = parse(b);
        va.cmp(&vb)
    }
}

/// Helper: build a `DateTime<Utc>` from y/m/d.
fn date(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(year, month, day)
        .expect("valid date")
        .and_hms_opt(0, 0, 0)
        .expect("valid time")
        .and_utc()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_list_versions_returns_all() {
        let reg = VersionRegistry::new();
        let versions = reg.list_versions();
        assert_eq!(versions.len(), 5);
        assert_eq!(versions[0].version, "2024-01");
    }

    #[test]
    fn test_get_version_found_and_not_found() {
        let reg = VersionRegistry::new();
        let v = reg.get_version("2023-10").unwrap();
        assert_eq!(v.status, VersionStatus::Supported);

        assert!(reg.get_version("9999-01").is_err());
    }

    #[test]
    fn test_is_deprecated() {
        let reg = VersionRegistry::new();
        assert!(reg.is_deprecated("2023-01"));
        assert!(reg.is_deprecated("2022-10"));
        assert!(!reg.is_deprecated("2024-01"));
        assert!(!reg.is_deprecated("2023-10"));
    }

    #[test]
    fn test_compare_versions() {
        let reg = VersionRegistry::new();
        assert_eq!(reg.compare_versions("2023-06", "2024-01"), Ordering::Less);
        assert_eq!(reg.compare_versions("2024-01", "2023-10"), Ordering::Greater);
        assert_eq!(reg.compare_versions("2023-10", "2023-10"), Ordering::Equal);
        assert_eq!(reg.compare_versions("2022-10", "2023-01"), Ordering::Less);
    }
}
