//! Behavioral profiling — login pattern analysis
//!
//! Analyzes user behavior patterns to detect anomalies://! - Time-of-day deviation from typical patterns
//! - Login frequency anomalies
//! - Geographic consistency

use crate::session::UserLoginHistory;

/// Behavioral analysis result
#[derive(Debug, Clone)]
pub struct BehaviorScore {
/// Total risk from behavioral analysis (0.0 - 10.0)
    pub score: f64,
/// Individual findings
    pub findings: Vec<BehaviorFinding>,
}

/// A behavioral finding
#[derive(Debug, Clone)]
pub struct BehaviorFinding {
/// Finding ID
    pub id: &'static str,
/// Description
    pub description: String,
/// Risk score
    pub risk: f64,
}

/// Analyze login behavior against user history
pub fn analyze_behavior(
    login_hour: u32,
    history: &UserLoginHistory,
) -> BehaviorScore {
    let mut findings = Vec::new();

// 1. Time-of-day anomaly
    if let Some(typical_hour) = history.typical_login_hour() {
        let hour_diff = hour_distance(login_hour, typical_hour);
        if hour_diff >= 10 {
// Far outside typical hours (e.g. usually logs in at 9am, now at 3am)
            findings.push(BehaviorFinding {
                id: "UNUSUAL_HOUR_HIGH",
                description: format!(
                    "Login at {}:00 is {} hours from typical {}:00",
                    login_hour, hour_diff, typical_hour
                ),
                risk: 3.0,
            });
        } else if hour_diff >= 6 {
            findings.push(BehaviorFinding {
                id: "UNUSUAL_HOUR_MEDIUM",
                description: format!(
                    "Login at {}:00 is {} hours from typical {}:00",
                    login_hour, hour_diff, typical_hour
                ),
                risk: 1.5,
            });
        }
    }

// 2. Very few historical logins (new account or rarely used)
    let successful_logins = history.events.iter().filter(|e| e.success).count();
    if successful_logins < 3 {
        findings.push(BehaviorFinding {
            id: "LOW_HISTORY",
            description: format!("Only {} historical successful logins", successful_logins),
            risk: 1.0,
        });
    }

// 3. Burst login pattern (many logins in short period — could be automated)
    let recent_logins = history.events.iter()
        .filter(|e| {
            let age = chrono::Utc::now().signed_duration_since(e.timestamp);
            age.num_minutes() < 5
        })
        .count();
    if recent_logins > 5 {
        findings.push(BehaviorFinding {
            id: "BURST_LOGINS",
            description: format!("{} logins in last 5 minutes", recent_logins),
            risk: 3.0,
        });
    } else if recent_logins > 3 {
        findings.push(BehaviorFinding {
            id: "FREQUENT_LOGINS",
            description: format!("{} logins in last 5 minutes", recent_logins),
            risk: 1.5,
        });
    }

    let total_score: f64 = findings.iter().map(|f| f.risk).sum::<f64>().min(10.0);
    BehaviorScore {
        score: total_score,
        findings,
    }
}

/// Circular distance between two hours (0-23)
fn hour_distance(a: u32, b: u32) -> u32 {
    let diff = a.abs_diff(b);
    diff.min(24 - diff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{LoginEvent, UserLoginHistory};
    use chrono::Utc;

    fn make_history_at_hours(hours: &[u32]) -> UserLoginHistory {
        let mut history = UserLoginHistory::new(100);
        for &h in hours {
            let ts = Utc::now()
                .date_naive()
                .and_hms_opt(h, 0, 0)
                .map(|naive| chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
                .unwrap_or_else(Utc::now);
            let event = LoginEvent {
                user_id: "test".into(),
                ip_address: "1.2.3.4".into(),
                user_agent: "Test".into(),
                latitude: None,
                longitude: None,
                timestamp: ts,
                success: true,
                tls_fingerprint: None,
            };
            history.record(event);
        }
        history
    }

    #[test]
    fn test_hour_distance() {
        assert_eq!(hour_distance(9, 9), 0);
        assert_eq!(hour_distance(9, 15), 6);
        assert_eq!(hour_distance(23, 1), 2);
        assert_eq!(hour_distance(0, 12), 12);
    }

    #[test]
    fn test_normal_hour() {
        let history = make_history_at_hours(&[9, 10, 9, 8, 10]);
        let result = analyze_behavior(9, &history);
        assert!(
            !result.findings.iter().any(|f| f.id.starts_with("UNUSUAL_HOUR")),
            "Login at typical hour should not be flagged"
        );
    }

    #[test]
    fn test_unusual_hour() {
        let history = make_history_at_hours(&[9, 10, 9, 8, 10, 9, 9]);
// Login at 3am when typical is ~9am
        let result = analyze_behavior(3, &history);
        assert!(
            result.findings.iter().any(|f| f.id.starts_with("UNUSUAL_HOUR")),
            "Login at 3am (typical 9am) should be flagged"
        );
    }

    #[test]
    fn test_low_history() {
        let history = make_history_at_hours(&[9]);
        let result = analyze_behavior(9, &history);
        assert!(result.findings.iter().any(|f| f.id == "LOW_HISTORY"));
    }
}
