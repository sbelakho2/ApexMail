//! OpenAPI specification generation — produce an OpenAPI 3.1 JSON document
//! describing the ApexMail REST API.
//!
//! Generates the service OpenAPI document.

use serde::{Deserialize, Serialize};

// ── Public types ─────────────────────────────────────────────────────────────

/// Minimal representation of an OpenAPI 3.1 spec (enough for generation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub servers: Vec<OpenApiServer>,
    pub paths: serde_json::Value,
    pub components: serde_json::Value,
    pub tags: Vec<OpenApiTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<OpenApiContact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<OpenApiLicense>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiContact {
    pub name: String,
    pub url: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiLicense {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiServer {
    pub url: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiTag {
    pub name: String,
    pub description: String,
}

/// Describes a single API endpoint for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub method: String,
    pub path: String,
    pub summary: String,
    pub tag: String,
    pub deprecated: bool,
}

// ── Generator ────────────────────────────────────────────────────────────────

/// Generates OpenAPI specs for the ApexMail API.
#[derive(Debug, Clone)]
pub struct OpenApiGenerator {
    api_version: String,
    base_url: String,
}

impl OpenApiGenerator {
    pub fn new(api_version: &str, base_url: &str) -> Self {
        Self {
            api_version: api_version.to_string(),
            base_url: base_url.to_string(),
        }
    }

/// Generate the full OpenAPI 3.1 spec.
    pub fn generate_spec(&self) -> OpenApiSpec {
        OpenApiSpec {
            openapi: "3.1.0".into(),
            info: OpenApiInfo {
                title: "ApexMail API".into(),
                version: self.api_version.clone(),
                description: "Transactional email API for developers. Send, track, and manage email at scale.".into(),
                contact: Some(OpenApiContact {
                    name: "ApexMail Support".into(),
                    url: "https://apexmail.ee/support".into(),
                    email: "support@apexmail.ee".into(),
                }),
                license: Some(OpenApiLicense {
                    name: "MIT".into(),
                    url: "https://opensource.org/licenses/MIT".into(),
                }),
            },
            servers: vec![
                OpenApiServer {
                    url: self.base_url.clone(),
                    description: "Production".into(),
                },
                OpenApiServer {
                    url: "https://sandbox.api.apexmail.ee".into(),
                    description: "Sandbox".into(),
                },
            ],
            paths: self.build_paths(),
            components: self.build_components(),
            tags: self.build_tags(),
        }
    }

/// List all registered endpoints.
    pub fn list_endpoints(&self) -> Vec<EndpointSummary> {
        vec![
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/emails".into(),
                summary: "Send an email".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/emails/batch".into(),
                summary: "Send batch emails".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/emails/{id}".into(),
                summary: "Get email by ID".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/domains".into(),
                summary: "List domains".into(),
                tag: "Domains".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/domains".into(),
                summary: "Add a domain".into(),
                tag: "Domains".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/domains/{id}/verify".into(),
                summary: "Verify domain DNS".into(),
                tag: "Domains".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/webhooks".into(),
                summary: "List webhooks".into(),
                tag: "Webhooks".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/webhooks".into(),
                summary: "Create a webhook".into(),
                tag: "Webhooks".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/webhooks/{id}/test".into(),
                summary: "Test a webhook".into(),
                tag: "Webhooks".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/analytics".into(),
                summary: "Get email analytics".into(),
                tag: "Analytics".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/templates".into(),
                summary: "List templates".into(),
                tag: "Templates".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/send".into(),
                summary: "Send email (legacy)".into(),
                tag: "Emails".into(),
                deprecated: true,
            },
        ]
    }

/// Get the JSON schema for a specific endpoint.
    pub fn get_endpoint_schema(&self, method: &str, path: &str) -> Option<serde_json::Value> {
        let endpoints = self.list_endpoints();
        let found = endpoints
            .iter()
            .find(|e| e.method.eq_ignore_ascii_case(method) && e.path == path)?;

        Some(serde_json::json!({
            "method": found.method,
            "path": found.path,
            "summary": found.summary,
            "tag": found.tag,
            "deprecated": found.deprecated,
            "parameters": [],
            "responses": {
                "200": { "description": "Success" },
                "400": { "description": "Bad Request" },
                "401": { "description": "Unauthorized" },
                "429": { "description": "Rate Limited" },
                "500": { "description": "Internal Server Error" }
            }
        }))
    }

// ── private builders ─────────────────────────────────────────────────

    fn build_paths(&self) -> serde_json::Value {
        serde_json::json!({
            "/v1/emails": {
                "post": {
                    "operationId": "sendEmail",
                    "summary": "Send an email",
                    "tags": ["Emails"],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/SendEmailRequest" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Email accepted" },
                        "400": { "description": "Validation error" },
                        "401": { "description": "Unauthorized" }
                    }
                }
            },
            "/v1/emails/batch": {
                "post": {
                    "operationId": "sendBatchEmails",
                    "summary": "Send batch emails",
                    "tags": ["Emails"]
                }
            },
            "/v1/emails/{id}": {
                "get": {
                    "operationId": "getEmail",
                    "summary": "Get email by ID",
                    "tags": ["Emails"]
                }
            },
            "/v1/domains": {
                "get": {
                    "operationId": "listDomains",
                    "summary": "List domains",
                    "tags": ["Domains"]
                },
                "post": {
                    "operationId": "addDomain",
                    "summary": "Add a domain",
                    "tags": ["Domains"]
                }
            },
            "/v1/webhooks": {
                "get": {
                    "operationId": "listWebhooks",
                    "summary": "List webhooks",
                    "tags": ["Webhooks"]
                },
                "post": {
                    "operationId": "createWebhook",
                    "summary": "Create a webhook",
                    "tags": ["Webhooks"]
                }
            },
            "/v1/analytics": {
                "get": {
                    "operationId": "getAnalytics",
                    "summary": "Get email analytics",
                    "tags": ["Analytics"]
                }
            },
            "/v1/templates": {
                "get": {
                    "operationId": "listTemplates",
                    "summary": "List templates",
                    "tags": ["Templates"]
                }
            }
        })
    }

    fn build_components(&self) -> serde_json::Value {
        serde_json::json!({
            "securitySchemes": {
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key for authentication"
                },
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API Key"
                }
            },
            "schemas": {
                "SendEmailRequest": {
                    "type": "object",
                    "required": ["from", "to", "subject"],
                    "properties": {
                        "from": { "type": "string", "format": "email" },
                        "to": {
                            "type": "array",
                            "items": { "type": "string", "format": "email" }
                        },
                        "subject": { "type": "string", "maxLength": 998 },
                        "text": { "type": "string" },
                        "html": { "type": "string" },
                        "template_id": { "type": "string" },
                        "template_data": { "type": "object" },
                        "tags": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                },
                "Error": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" }
                    }
                }
            }
        })
    }

    fn build_tags(&self) -> Vec<OpenApiTag> {
        vec![
            OpenApiTag {
                name: "Emails".into(),
                description: "Send and manage transactional emails".into(),
            },
            OpenApiTag {
                name: "Domains".into(),
                description: "Manage sending domains and DNS verification".into(),
            },
            OpenApiTag {
                name: "Webhooks".into(),
                description: "Configure and test webhook endpoints".into(),
            },
            OpenApiTag {
                name: "Analytics".into(),
                description: "Email delivery analytics and metrics".into(),
            },
            OpenApiTag {
                name: "Templates".into(),
                description: "Email template management".into(),
            },
        ]
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gen() -> OpenApiGenerator {
        OpenApiGenerator::new("2024-01", "https://api.apexmail.ee")
    }

    #[test]
    fn test_generate_spec_structure() {
        let spec = gen().generate_spec();
        assert_eq!(spec.openapi, "3.1.0");
        assert_eq!(spec.info.title, "ApexMail API");
        assert_eq!(spec.info.version, "2024-01");
        assert_eq!(spec.servers.len(), 2);
        assert!(spec.tags.len() >= 5);
    }

    #[test]
    fn test_list_endpoints() {
        let endpoints = gen().list_endpoints();
        assert!(endpoints.len() >= 10);
// Should have at least one deprecated endpoint
        assert!(endpoints.iter().any(|e| e.deprecated));
// All should have non-empty method + path
        assert!(endpoints.iter().all(|e| !e.method.is_empty() && !e.path.is_empty()));
    }

    #[test]
    fn test_get_endpoint_schema() {
        let g = gen();
        let schema = g.get_endpoint_schema("POST", "/v1/emails").unwrap();
        assert_eq!(schema["method"], "POST");
        assert_eq!(schema["path"], "/v1/emails");
        assert!(!schema["deprecated"].as_bool().unwrap());

// Unknown endpoint returns None.
        assert!(g.get_endpoint_schema("DELETE", "/v1/foobar").is_none());
    }
}
