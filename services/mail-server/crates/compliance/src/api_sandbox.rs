use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub demo_tenant_id: String,
    pub demo_tenant_name: String,
    pub test_addresses: Vec<String>,
    pub reset_schedule_cron: String,
    pub next_reset_at: DateTime<Utc>,
    pub realistic_ids_enabled: bool,
    pub authenticated_mode_enabled: bool,
    pub sdk_example_languages: Vec<String>,
}

impl SandboxConfig {
    pub fn default_demo() -> Self {
        Self {
            demo_tenant_id: "demo-00000000-0000-0000-0000-000000000001".to_string(),
            demo_tenant_name: "ApexMail Demo Tenant".to_string(),
            test_addresses: vec![
                "success@simulator.amazonses.com".to_string(),
                "bounce@simulator.amazonses.com".to_string(),
                "complaint@simulator.amazonses.com".to_string(),
                "suppression@simulator.amazonses.com".to_string(),
                "delayed@simulator.amazonses.com".to_string(),
            ],
            reset_schedule_cron: "0 */6 * * *".to_string(),
            next_reset_at: Utc::now(),
            realistic_ids_enabled: true,
            authenticated_mode_enabled: false,
            sdk_example_languages: vec![
                "typescript".to_string(),
                "python".to_string(),
                "go".to_string(),
                "java".to_string(),
                "php".to_string(),
                "ruby".to_string(),
                "dotnet".to_string(),
            ],
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self::default_demo()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSandboxSession {
    pub session_id: String,
    pub tenant_id: String,
    pub test_key_prefix: String,
    pub created_at: DateTime<Utc>,
    pub request_log: Vec<SandboxRequestLogEntry>,
    pub test_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRequestLogEntry {
    pub entry_id: String,
    pub method: String,
    pub path: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: serde_json::Value,
    pub response_body: serde_json::Value,
    pub status_code: u16,
    pub latency_ms: u64,
    pub request_id: String,
    pub curl_command: String,
    pub sdk_example: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResponseEntry {
    pub id: String,
    pub request_id: String,
    pub status_code: u16,
    pub body: serde_json::Value,
    pub headers: HashMap<String, String>,
    pub is_test_recipient: bool,
}

pub fn generate_sandbox_response(
    _method: &str,
    path: &str,
    body: &serde_json::Value,
    test_recipient: bool,
) -> SandboxResponseEntry {
    let request_id = format!("sandbox-{}", Uuid::new_v4());
    let path_lower = path.to_lowercase();

    if !test_recipient {
        return SandboxResponseEntry {
            id: Uuid::new_v4().to_string(),
            request_id,
            status_code: 403,
            body: serde_json::json!({
                "error": "test_recipient_required",
                "message": "The sandbox only accepts documented test addresses. See https://docs.apexmail.ee/sandbox for valid test recipients.",
                "sandbox_mode": true
            }),
            headers: headers_with_sandbox(),
            is_test_recipient: false,
        };
    }

    if path_lower.contains("bounce") || body.to_string().to_lowercase().contains("bounce@") {
        return deterministic_outcome(
            &request_id,
            202,
            serde_json::json!({
                "id": format!("msg-{}", Uuid::new_v4()),
                "status": "accepted",
                "event": "bounce",
                "reason": "Hard bounce (simulated)",
                "sandbox": true
            }),
        );
    }

    if path_lower.contains("complaint") || body.to_string().to_lowercase().contains("complaint@") {
        return deterministic_outcome(
            &request_id,
            202,
            serde_json::json!({
                "id": format!("msg-{}", Uuid::new_v4()),
                "status": "accepted",
                "event": "complaint",
                "reason": "Abuse complaint (simulated)",
                "sandbox": true
            }),
        );
    }

    if path_lower.contains("delayed") || body.to_string().to_lowercase().contains("delayed@") {
        return deterministic_outcome(
            &request_id,
            202,
            serde_json::json!({
                "id": format!("msg-{}", Uuid::new_v4()),
                "status": "queued",
                "event": "delayed",
                "reason": "Temporary deferral (simulated)",
                "sandbox": true
            }),
        );
    }

    deterministic_outcome(
        &request_id,
        202,
        serde_json::json!({
            "id": format!("msg-{}", Uuid::new_v4()),
            "status": "accepted",
            "event": "delivered",
            "sandbox": true
        }),
    )
}

fn deterministic_outcome(
    request_id: &str,
    status_code: u16,
    body: serde_json::Value,
) -> SandboxResponseEntry {
    SandboxResponseEntry {
        id: Uuid::new_v4().to_string(),
        request_id: request_id.to_string(),
        status_code,
        body,
        headers: headers_with_sandbox(),
        is_test_recipient: true,
    }
}

fn headers_with_sandbox() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("X-Sandbox-Mode".to_string(), "true".to_string());
    headers.insert("X-Request-ID".to_string(), Uuid::new_v4().to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers
}

pub fn generate_curl_command(method: &str, path: &str, headers: &HashMap<String, String>, body: &serde_json::Value) -> String {
    let mut curl = format!("curl -X {} 'https://sandbox.apexmail.ee{}'", method.to_uppercase(), path);
    for (k, v) in headers {
        curl.push_str(&format!(" \\\n  -H '{}: {}'", k, v));
    }
    if !body.is_null() {
        curl.push_str(&format!(
            " \\\n  -d '{}'",
            serde_json::to_string(body).unwrap_or_default()
        ));
    }
    curl
}

pub fn generate_sdk_example(language: &str, method: &str, path: &str, body: &serde_json::Value) -> String {
    match language {
        "typescript" => {
            format!(
                "import {{ ApexMail }} from '@apexmail/node';\n\nconst client = new ApexMail({{ apiKey: 'test_key' }});\nconst response = await client.{}();\nconsole.log(response);",
                path_to_method_name(path)
            )
        }
        "python" => {
            format!(
                "from apexmail import ApexMail\n\nclient = ApexMail(api_key='test_key')\nresponse = client.{}()\nprint(response)",
                path_to_method_name(path)
            )
        }
        "go" => {
            format!(
                "import \"github.com/apexmail/apexmail-go\"\n\nclient := apexmail.NewClient(\"test_key\")\nresp, err := client.{}(nil)\nfmt.Println(resp)",
                pascal_method_name(path)
            )
        }
        "java" => {
            format!(
                "import com.apexmail.ApexMail;\n\nApexMail client = new ApexMail(\"test_key\");\nvar response = client.{}();\nSystem.out.println(response);",
                path_to_method_name(path)
            )
        }
        _ => {
            format!(
                "// {} example for {} {}\n// with body: {}",
                language, method, path, serde_json::to_string_pretty(body).unwrap_or_default()
            )
        }
    }
}

fn path_to_method_name(path: &str) -> String {
    path.trim_start_matches('/')
        .split('/')
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_lowercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn pascal_method_name(path: &str) -> String {
    path.trim_start_matches('/')
        .split('/')
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSandbox {
    pub config: SandboxConfig,
    pub sessions: HashMap<String, AuthenticatedSandboxSession>,
}

impl AuthenticatedSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, tenant_id: &str, test_key_prefix: &str) -> String {
        let session_id = format!("sandbox-ses-{}", Uuid::new_v4());
        let session = AuthenticatedSandboxSession {
            session_id: session_id.clone(),
            tenant_id: tenant_id.to_string(),
            test_key_prefix: test_key_prefix.to_string(),
            created_at: Utc::now(),
            request_log: Vec::new(),
            test_only: true,
        };
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn log_request(
        &mut self,
        session_id: &str,
        method: &str,
        path: &str,
        request_headers: HashMap<String, String>,
        request_body: serde_json::Value,
        status_code: u16,
        latency_ms: u64,
        response_body: serde_json::Value,
    ) -> Option<&SandboxRequestLogEntry> {
        let session = self.sessions.get_mut(session_id)?;
        let request_id = format!("sandbox-req-{}", Uuid::new_v4());
        let curl_command = generate_curl_command(method, path, &request_headers, &request_body);

        let mut sdk_example = HashMap::new();
        for lang in &self.config.sdk_example_languages {
            sdk_example.insert(
                lang.clone(),
                generate_sdk_example(lang, method, path, &request_body),
            );
        }

        let entry = SandboxRequestLogEntry {
            entry_id: Uuid::new_v4().to_string(),
            method: method.to_string(),
            path: path.to_string(),
            request_headers,
            request_body,
            response_body,
            status_code,
            latency_ms,
            request_id,
            curl_command,
            sdk_example,
            timestamp: Utc::now(),
        };
        session.request_log.push(entry);
        session.request_log.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_defaults() {
        let config = SandboxConfig::default_demo();
        assert_eq!(config.test_addresses.len(), 5);
        assert!(config.test_addresses.iter().any(|a| a.contains("success@")));
        assert!(config.realistic_ids_enabled);
        assert_eq!(config.sdk_example_languages.len(), 7);
    }

    #[test]
    fn test_generate_sandbox_response_non_test_recipient() {
        let resp = generate_sandbox_response("POST", "/v1/send", &serde_json::json!({"to": "real@example.com"}), false);
        assert_eq!(resp.status_code, 403);
        assert!(!resp.is_test_recipient);
        let body_str = resp.body.to_string();
        assert!(body_str.contains("test_recipient_required"));
    }

    #[test]
    fn test_generate_sandbox_response_success() {
        let resp = generate_sandbox_response(
            "POST",
            "/v1/send",
            &serde_json::json!({"to": "success@simulator.amazonses.com"}),
            true,
        );
        assert_eq!(resp.status_code, 202);
        assert!(resp.is_test_recipient);
        assert_eq!(resp.body["event"], "delivered");
        assert_eq!(resp.body["sandbox"], true);
        assert!(resp.headers.contains_key("X-Sandbox-Mode"));
    }

    #[test]
    fn test_generate_sandbox_response_bounce() {
        let resp = generate_sandbox_response(
            "POST",
            "/v1/send",
            &serde_json::json!({"to": "bounce@simulator.amazonses.com"}),
            true,
        );
        assert_eq!(resp.body["event"], "bounce");
        assert_eq!(resp.status_code, 202);
    }

    #[test]
    fn test_generate_curl_and_sdk_example() {
        let headers = HashMap::from([
            ("Authorization".to_string(), "Bearer test_key".to_string()),
        ]);
        let body = serde_json::json!({"from": "test@demo.com"});
        let curl = generate_curl_command("POST", "/v1/send", &headers, &body);
        assert!(curl.contains("curl -X POST"));
        assert!(curl.contains("sandbox.apexmail.ee"));
        assert!(curl.contains("Bearer test_key"));

        let ts_example = generate_sdk_example("typescript", "POST", "/v1/send", &body);
        assert!(ts_example.contains("@apexmail/node"));

        let py_example = generate_sdk_example("python", "POST", "/v1/send", &body);
        assert!(py_example.contains("from apexmail"));

        let go_example = generate_sdk_example("go", "POST", "/v1/send", &body);
        assert!(go_example.contains("apexmail-go"));

        let java_example = generate_sdk_example("java", "POST", "/v1/send", &body);
        assert!(java_example.contains("com.apexmail"));
    }
}
