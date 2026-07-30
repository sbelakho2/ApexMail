use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationChecklist {
    pub items: Vec<ActivationItem>,
    pub estimated_paid_plan: Option<String>,
    pub remaining_free_usage: Option<i64>,
}

impl ActivationChecklist {
    pub fn new() -> Self {
        Self {
            items: vec![
                ActivationItem {
                    step: 1,
                    name: "Verify email".to_string(),
                    description: "Check your inbox and click the verification link".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/verify-email".to_string()),
                    completed: false,
                    blocked_by: None,
                },
                ActivationItem {
                    step: 2,
                    name: "Add sending domain".to_string(),
                    description: "Add and verify a domain you control for sending".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/domains".to_string()),
                    completed: false,
                    blocked_by: Some(1),
                },
                ActivationItem {
                    step: 3,
                    name: "Publish DKIM".to_string(),
                    description: "Add the DKIM DNS records shown in your domain settings".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/dkim".to_string()),
                    completed: false,
                    blocked_by: Some(2),
                },
                ActivationItem {
                    step: 4,
                    name: "Configure return path".to_string(),
                    description: "Set up a custom return-path domain for bounce processing".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/return-path".to_string()),
                    completed: false,
                    blocked_by: Some(2),
                },
                ActivationItem {
                    step: 5,
                    name: "Check SPF".to_string(),
                    description: "Ensure your SPF record includes ApexMail servers".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/spf".to_string()),
                    completed: false,
                    blocked_by: Some(2),
                },
                ActivationItem {
                    step: 6,
                    name: "Add or review DMARC".to_string(),
                    description: "Configure DMARC policy for your sending domain".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/dmarc".to_string()),
                    completed: false,
                    blocked_by: Some(2),
                },
                ActivationItem {
                    step: 7,
                    name: "Create test key".to_string(),
                    description: "Generate a test API key for sandbox integration".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/api-keys".to_string()),
                    completed: false,
                    blocked_by: Some(1),
                },
                ActivationItem {
                    step: 8,
                    name: "Send test message".to_string(),
                    description: "Send a test email through the sandbox or with your test key".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/test-send".to_string()),
                    completed: false,
                    blocked_by: Some(7),
                },
                ActivationItem {
                    step: 9,
                    name: "Configure webhook".to_string(),
                    description: "Set up a webhook endpoint to receive delivery events".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/webhooks".to_string()),
                    completed: false,
                    blocked_by: None,
                },
                ActivationItem {
                    step: 10,
                    name: "Create production key".to_string(),
                    description: "Generate a production API key (requires domain verification)".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/api-keys".to_string()),
                    completed: false,
                    blocked_by: Some(8),
                },
                ActivationItem {
                    step: 11,
                    name: "Complete production review".to_string(),
                    description: "We review your account before approving production sending".to_string(),
                    documentation_url: Some("https://docs.apexmail.ee/activation/production-review".to_string()),
                    completed: false,
                    blocked_by: Some(10),
                },
            ],
            estimated_paid_plan: None,
            remaining_free_usage: None,
        }
    }

    pub fn mark_completed(&mut self, step: u32) {
        if let Some(item) = self.items.iter_mut().find(|i| i.step == step) {
            item.completed = true;
        }
    }

    pub fn completion_percentage(&self) -> f64 {
        let total = self.items.len() as f64;
        if total == 0.0 {
            return 0.0;
        }
        let completed = self.items.iter().filter(|i| i.completed).count() as f64;
        (completed / total) * 100.0
    }

    pub fn current_blocker(&self) -> Option<&ActivationItem> {
        self.items
            .iter()
            .find(|i| !i.completed && i.blocked_by.is_none())
    }

    pub fn next_unblocked_step(&self) -> Option<&ActivationItem> {
        self.items
            .iter()
            .filter(|i| !i.completed)
            .find(|i| {
                match i.blocked_by {
                    Some(blocker_step) => {
                        self.items.iter().any(|dep| dep.step == blocker_step && dep.completed)
                    }
                    None => true,
                }
            })
    }

    pub fn remaining_free_usage_info(&self) -> Option<String> {
        self.remaining_free_usage.map(|remaining| {
            format!(
                "{} emails remaining in your free tier",
                remaining
            )
        })
    }
}

impl Default for ActivationChecklist {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationItem {
    pub step: u32,
    pub name: String,
    pub description: String,
    pub documentation_url: Option<String>,
    pub completed: bool,
    pub blocked_by: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationProgress {
    pub completion_percentage: f64,
    pub current_blocker: Option<String>,
    pub remediation: Option<String>,
    pub documentation_url: Option<String>,
    pub remaining_free_usage: Option<String>,
    pub estimated_paid_plan: Option<String>,
    pub can_send_test: bool,
    pub can_send_production: bool,
}

pub fn get_activation_progress(checklist: &ActivationChecklist) -> ActivationProgress {
    let pct = checklist.completion_percentage();
    let blocker = checklist.current_blocker();
    let next = checklist.next_unblocked_step();

    let can_send_test = checklist.items.iter().any(|i| i.step == 7 && i.completed);
    let can_send_production = checklist.items.iter().any(|i| i.step == 11 && i.completed);

    let (blocker_name, remediation, doc_url) = if let Some(b) = blocker {
        (
            Some(b.name.clone()),
            Some(b.description.clone()),
            b.documentation_url.clone(),
        )
    } else if let Some(n) = next {
        (
            Some(n.name.clone()),
            Some(n.description.clone()),
            n.documentation_url.clone(),
        )
    } else {
        (None, None, None)
    };

    ActivationProgress {
        completion_percentage: pct,
        current_blocker: blocker_name,
        remediation,
        documentation_url: doc_url,
        remaining_free_usage: checklist.remaining_free_usage_info(),
        estimated_paid_plan: checklist.estimated_paid_plan.clone(),
        can_send_test,
        can_send_production,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activation_checklist_has_11_items() {
        let checklist = ActivationChecklist::new();
        assert_eq!(checklist.items.len(), 11);
        assert_eq!(checklist.completion_percentage(), 0.0);
    }

    #[test]
    fn test_completion_percentage_half_done() {
        let mut checklist = ActivationChecklist::new();
        for i in 1..=5 {
            checklist.mark_completed(i);
        }
        assert!((checklist.completion_percentage() - (5.0 / 11.0 * 100.0)).abs() < 0.01);
    }

    #[test]
    fn test_get_activation_progress_initial() {
        let checklist = ActivationChecklist::new();
        let progress = get_activation_progress(&checklist);
        assert_eq!(progress.completion_percentage, 0.0);
        assert!(progress.current_blocker.is_some());
        assert!(!progress.can_send_test);
        assert!(!progress.can_send_production);
    }

    #[test]
    fn test_get_activation_progress_fully_activated() {
        let mut checklist = ActivationChecklist::new();
        checklist.remaining_free_usage = Some(5000);
        checklist.estimated_paid_plan = Some("Growth".to_string());

        for i in 1..=11 {
            checklist.mark_completed(i);
        }

        let progress = get_activation_progress(&checklist);
        assert_eq!(progress.completion_percentage, 100.0);
        assert!(progress.can_send_test);
        assert!(progress.can_send_production);
        assert_eq!(progress.estimated_paid_plan, Some("Growth".to_string()));
    }
}
