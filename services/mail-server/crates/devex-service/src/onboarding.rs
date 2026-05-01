//! Developer onboarding — quickstart guides, checklists, API key setup instructions.

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A quickstart guide for a specific SDK language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickstartGuide {
    pub language: String,
    pub title: String,
    pub steps: Vec<QuickstartStep>,
    pub estimated_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickstartStep {
    pub order: u32,
    pub title: String,
    pub description: String,
    pub code_snippet: Option<String>,
}

/// Onboarding checklist item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub completed: bool,
    pub order: u32,
    pub required: bool,
}

/// Full onboarding checklist for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingChecklist {
    pub tenant_id: String,
    pub items: Vec<ChecklistItem>,
    pub progress_pct: f32,
}

// ── Service ──────────────────────────────────────────────────────────────────

/// Onboarding service — stateless helpers (state stored externally).
#[derive(Debug, Clone)]
pub struct OnboardingService;

impl Default for OnboardingService {
    fn default() -> Self {
        Self::new()
    }
}

impl OnboardingService {
    pub fn new() -> Self {
        Self
    }

    /// Generate a quickstart guide for the requested language.
    pub fn create_quickstart(&self, language: &str) -> QuickstartGuide {
        let (install_cmd, send_code) = match language {
            "python" => (
                "pip install apexmail",
                r#"from apexmail import ApexMail

client = ApexMail(api_key="am_live_...")

client.emails.send(
    from_email="sender@yourdomain.com",
    to=["user@example.com"],
    subject="Hello from ApexMail!",
    html="<h1>Welcome!</h1>",
)"#,
            ),
            "go" => (
                "go get github.com/apexmail/apexmail-go",
                r#"client := apexmail.New("am_live_...")

_, err := client.Emails.Send(&apexmail.SendEmailParams{
    From:    "sender@yourdomain.com",
    To:      []string{"user@example.com"},
    Subject: "Hello from ApexMail!",
    HTML:    "<h1>Welcome!</h1>",
})"#,
            ),
            "ruby" => (
                "gem install apexmail",
                r#"require 'apexmail'

client = ApexMail::Client.new(api_key: 'am_live_...')

client.emails.send(
  from: 'sender@yourdomain.com',
  to: ['user@example.com'],
  subject: 'Hello from ApexMail!',
  html: '<h1>Welcome!</h1>'
)"#,
            ),
            "php" => (
                "composer require apexmail/apexmail-php",
                r#"$apexmail = new \ApexMail\Client('am_live_...');

$apexmail->emails->send([
    'from' => 'sender@yourdomain.com',
    'to'   => ['user@example.com'],
    'subject' => 'Hello from ApexMail!',
    'html' => '<h1>Welcome!</h1>',
]);"#,
            ),
            "java" => (
                "<! -- Maven -->\n<dependency>\n <groupId>ee.apexmail</groupId>\n <artifactId>apexmail-java</artifactId>\n <version>1.3.0</version>\n</dependency>",
                r#"ApexMailClient client = ApexMailClient.create("am_live_...");

client.emails().send(SendEmailParams.builder()
    .from("sender@yourdomain.com")
    .to(List.of("user@example.com"))
    .subject("Hello from ApexMail!")
    .html("<h1>Welcome!</h1>")
    .build());"#,
            ),
            _ => (
                "# See https://apexmail.ee/docs/sdks for install instructions",
                " // See https://apexmail.ee/docs",
            ),
        };

        QuickstartGuide {
            language: language.to_string(),
            title: format!("ApexMail Quickstart — {}", language),
            estimated_minutes: 5,
            steps: vec![
                QuickstartStep {
                    order: 1,
                    title: "Install the SDK".into(),
                    description: "Add the ApexMail SDK to your project.".into(),
                    code_snippet: Some(install_cmd.to_string()),
                },
                QuickstartStep {
                    order: 2,
                    title: "Get your API key".into(),
                    description:
                        "Copy your API key from the ApexMail dashboard → Settings → API Keys."
                            .into(),
                    code_snippet: None,
                },
                QuickstartStep {
                    order: 3,
                    title: "Send your first email".into(),
                    description: "Use the SDK to send a transactional email.".into(),
                    code_snippet: Some(send_code.to_string()),
                },
                QuickstartStep {
                    order: 4,
                    title: "Verify domain".into(),
                    description:
                        "Add DNS records (SPF, DKIM, DMARC) to authenticate your sending domain."
                            .into(),
                    code_snippet: None,
                },
            ],
        }
    }

    /// Get the default onboarding checklist for a tenant.
    pub fn get_checklist(&self, tenant_id: &str) -> OnboardingChecklist {
        let items = vec![
            ChecklistItem {
                id: "create_account".into(),
                title: "Create an account".into(),
                description: "Sign up for ApexMail.".into(),
                completed: true, // always true if they have a tenant_id
                order: 1,
                required: true,
            },
            ChecklistItem {
                id: "generate_api_key".into(),
                title: "Generate an API key".into(),
                description: "Create an API key in the dashboard.".into(),
                completed: false,
                order: 2,
                required: true,
            },
            ChecklistItem {
                id: "verify_domain".into(),
                title: "Verify a sending domain".into(),
                description: "Add DNS records to authenticate your domain.".into(),
                completed: false,
                order: 3,
                required: true,
            },
            ChecklistItem {
                id: "send_test_email".into(),
                title: "Send a test email".into(),
                description: "Send your first email via the API or sandbox.".into(),
                completed: false,
                order: 4,
                required: true,
            },
            ChecklistItem {
                id: "configure_webhooks".into(),
                title: "Set up webhooks".into(),
                description: "Subscribe to delivery events for real-time notifications.".into(),
                completed: false,
                order: 5,
                required: false,
            },
            ChecklistItem {
                id: "setup_templates".into(),
                title: "Create an email template".into(),
                description: "Build a reusable template with Handlebars.".into(),
                completed: false,
                order: 6,
                required: false,
            },
        ];

        let total = items.len() as f32;
        let done = items.iter().filter(|i| i.completed).count() as f32;

        OnboardingChecklist {
            tenant_id: tenant_id.to_string(),
            items,
            progress_pct: if total > 0.0 {
                (done / total) * 100.0
            } else {
                0.0
            },
        }
    }

    /// Mark a checklist step as complete (returns updated checklist).
    pub fn mark_step_complete(&self, checklist: &mut OnboardingChecklist, step_id: &str) -> bool {
        let mut found = false;
        for item in &mut checklist.items {
            if item.id == step_id {
                item.completed = true;
                found = true;
            }
        }
        // Recalculate progress.
        let total = checklist.items.len() as f32;
        let done = checklist.items.iter().filter(|i| i.completed).count() as f32;
        checklist.progress_pct = if total > 0.0 {
            (done / total) * 100.0
        } else {
            0.0
        };
        found
    }

    /// Generate a short API key management guide.
    pub fn generate_api_key_guide(&self) -> String {
        let guide = r#"# ApexMail API Key Guide

## Creating an API Key
1. Log in to the ApexMail dashboard.
2. Navigate to **Settings → API Keys**.
3. Click **Create API Key**.
4. Give it a descriptive name (e.g. "Production Backend").
5. Select the scopes you need:
   - `messages:write` — Send emails
   - `messages:read` — Read email status
   - `domains:read` — List domains
   - `domains:write` — Manage domains
   - `analytics:read` — View analytics
   - `webhooks:write` — Manage webhooks
   - `templates:write` — Manage templates
6. Click **Create** and copy the key immediately — it won't be shown again.

## Using Your API Key
Include the key in the `Authorization` header:
```
Authorization: Bearer am_live_...
```
Or use the `X-API-Key` header:
```
X-API-Key: am_live_...
```

## Security Best Practices
- **Never commit** API keys to version control.
- Use environment variables: `APEXMAIL_API_KEY`.
- Rotate keys periodically.
- Use the minimum scopes required.
- Set an expiration date for non-production keys.
- Revoke keys immediately if compromised.
"#;
        guide.to_string()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_quickstart_python() {
        let svc = OnboardingService::new();
        let guide = svc.create_quickstart("python");
        assert_eq!(guide.steps.len(), 4);
        assert!(guide.steps[0]
            .code_snippet
            .as_ref()
            .unwrap()
            .contains("pip install"));
        assert_eq!(guide.estimated_minutes, 5);
    }

    #[test]
    fn test_get_checklist_and_progress() {
        let svc = OnboardingService::new();
        let cl = svc.get_checklist("tenant_123");
        assert_eq!(cl.tenant_id, "tenant_123");
        assert_eq!(cl.items.len(), 6);
        // Only "create_account" is pre-completed.
        assert!((cl.progress_pct - (1.0 / 6.0) * 100.0).abs() < 0.1);
    }

    #[test]
    fn test_mark_step_complete() {
        let svc = OnboardingService::new();
        let mut cl = svc.get_checklist("t1");
        assert!(svc.mark_step_complete(&mut cl, "generate_api_key"));
        assert!(
            cl.items
                .iter()
                .find(|i| i.id == "generate_api_key")
                .unwrap()
                .completed
        );
        // Progress should increase.
        assert!((cl.progress_pct - (2.0 / 6.0) * 100.0).abs() < 0.1);
        // Unknown step returns false.
        assert!(!svc.mark_step_complete(&mut cl, "nonexistent"));
    }
}
