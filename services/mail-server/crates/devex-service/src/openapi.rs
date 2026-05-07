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
    /// O-20.1: Declare default security requirements so consumers know
    /// authentication is expected. Null/missing = no default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<serde_json::Value>>,
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
    ///
    /// # O-20.1 — Missing security field
    /// Every endpoint now declares `security: [{"apiKey": []}]` by default so that
    /// API consumers know authentication is required. The security scheme is
    /// defined in `components.securitySchemes` (apiKey + bearerAuth).
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
            security: Some(vec![
                serde_json::json!({"apiKey": []})
            ]),
        }
    }

    /// List all registered endpoints.
    pub fn list_endpoints(&self) -> Vec<EndpointSummary> {
        vec![
            // ── Emails ────────────────────────────────────────────
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/messages".into(),
                summary: "Send a message".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/messages".into(),
                summary: "List messages".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/messages/batch".into(),
                summary: "Send batch messages".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/messages/{id}".into(),
                summary: "Get message by ID".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/messages/{id}/cancel".into(),
                summary: "Cancel a queued or scheduled message".into(),
                tag: "Emails".into(),
                deprecated: false,
            },
            // ── Domains ───────────────────────────────────────────
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
            // ── Templates ─────────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/templates".into(),
                summary: "List templates".into(),
                tag: "Templates".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/templates".into(),
                summary: "Create a template".into(),
                tag: "Templates".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/templates/{id}".into(),
                summary: "Get template by ID".into(),
                tag: "Templates".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/templates/{id}/render".into(),
                summary: "Render a template".into(),
                tag: "Templates".into(),
                deprecated: false,
            },
            // ── Webhooks ──────────────────────────────────────────
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
            // ── Suppressions ──────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/suppressions".into(),
                summary: "List suppressions".into(),
                tag: "Suppressions".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/suppressions".into(),
                summary: "Create a suppression".into(),
                tag: "Suppressions".into(),
                deprecated: false,
            },
            // ── Events ────────────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/events".into(),
                summary: "List events".into(),
                tag: "Events".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/events/stats".into(),
                summary: "Get event statistics".into(),
                tag: "Events".into(),
                deprecated: false,
            },
            // ── Analytics ─────────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/analytics".into(),
                summary: "Get email analytics".into(),
                tag: "Analytics".into(),
                deprecated: false,
            },
            // ── Campaigns ─────────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/campaigns".into(),
                summary: "List campaigns".into(),
                tag: "Campaigns".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/campaigns".into(),
                summary: "Create a campaign".into(),
                tag: "Campaigns".into(),
                deprecated: false,
            },
            // ── Contacts ──────────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/v1/contacts".into(),
                summary: "List contacts".into(),
                tag: "Contacts".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/contacts".into(),
                summary: "Create a contact".into(),
                tag: "Contacts".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/contacts/bulk".into(),
                summary: "Bulk import contacts".into(),
                tag: "Contacts".into(),
                deprecated: false,
            },
            // ── Auth ──────────────────────────────────────────────
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/auth/login".into(),
                summary: "Login".into(),
                tag: "Auth".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/auth/register".into(),
                summary: "Register a new account".into(),
                tag: "Auth".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/auth/forgot-password".into(),
                summary: "Request password reset".into(),
                tag: "Auth".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/v1/auth/reset-password".into(),
                summary: "Reset password with token".into(),
                tag: "Auth".into(),
                deprecated: false,
            },
            // ── Enterprise private cloud ────────────────────────
            EndpointSummary {
                method: "POST".into(),
                path: "/enterprise/v1/deployments".into(),
                summary: "Create an Enterprise private deployment".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/deployments/{id}".into(),
                summary: "Get an Enterprise private deployment".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/deployments/tenant/{tenant_id}".into(),
                summary: "List Enterprise private deployments".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/enterprise/v1/deployments/{id}/provision".into(),
                summary: "Start private deployment provisioning".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/deployments/{id}/health".into(),
                summary: "Check private deployment health".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/enterprise/v1/ips/allocate".into(),
                summary: "Allocate an Enterprise dedicated IP".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/ips/{id}".into(),
                summary: "Get an Enterprise dedicated IP".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/ips/tenant/{tenant_id}".into(),
                summary: "List Enterprise dedicated IPs".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/enterprise/v1/ips/reputation/{ip_address}".into(),
                summary: "Get Enterprise dedicated IP reputation".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/enterprise/v1/ips/byoip".into(),
                summary: "Register a BYOIP range".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/enterprise/v1/ips/byoip/{id}/verify".into(),
                summary: "Verify BYOIP ownership".into(),
                tag: "Enterprise Private Cloud".into(),
                deprecated: false,
            },
            // ── DevEx internal ────────────────────────────────────
            EndpointSummary {
                method: "GET".into(),
                path: "/versions".into(),
                summary: "List API versions".into(),
                tag: "Developer".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/sdks".into(),
                summary: "List available SDKs".into(),
                tag: "Developer".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "POST".into(),
                path: "/webhooks/test".into(),
                summary: "Send a test webhook".into(),
                tag: "Developer".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/openapi.json".into(),
                summary: "Get OpenAPI specification".into(),
                tag: "Developer".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/onboarding/checklist".into(),
                summary: "Get onboarding checklist".into(),
                tag: "Developer".into(),
                deprecated: false,
            },
            EndpointSummary {
                method: "GET".into(),
                path: "/health".into(),
                summary: "Health check".into(),
                tag: "Developer".into(),
                deprecated: false,
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
        let mut paths = serde_json::json!({
            // ── Messages ─────────────────────────────────────────
            "/v1/messages": {
                "get": {
                    "operationId": "listMessages",
                    "summary": "List messages with pagination",
                    "tags": ["Emails"],
                    "parameters": [
                        { "name": "cursor", "in": "query", "schema": { "type": "string" }, "description": "Pagination cursor" },
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 50 } },
                        { "name": "sort", "in": "query", "schema": { "type": "string", "default": "created_at" } }
                    ],
                    "responses": {
                        "200": { "description": "List of messages" },
                        "401": { "description": "Unauthorized" }
                    }
                },
                "post": {
                    "operationId": "sendMessage",
                    "summary": "Send a message",
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
            "/v1/messages/batch": {
                "post": {
                    "operationId": "sendBatchMessages",
                    "summary": "Send batch messages",
                    "tags": ["Emails"]
                }
            },
            "/v1/messages/{id}": {
                "get": {
                    "operationId": "getMessage",
                    "summary": "Get message by ID",
                    "tags": ["Emails"]
                }
            },
            "/v1/messages/{id}/cancel": {
                "post": {
                    "operationId": "cancelMessage",
                    "summary": "Cancel a scheduled message",
                    "tags": ["Emails"]
                }
            },
            // ── Domains ──────────────────────────────────────────
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
            // ── Webhooks ─────────────────────────────────────────
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
            // ── Templates ────────────────────────────────────────
            "/v1/templates": {
                "get": {
                    "operationId": "listTemplates",
                    "summary": "List templates",
                    "tags": ["Templates"]
                },
                "post": {
                    "operationId": "createTemplate",
                    "summary": "Create an email template",
                    "tags": ["Templates"]
                }
            },
            "/v1/templates/{id}": {
                "get": {
                    "operationId": "getTemplate",
                    "summary": "Get template by ID",
                    "tags": ["Templates"]
                }
            },
            "/v1/templates/{id}/render": {
                "post": {
                    "operationId": "renderTemplate",
                    "summary": "Render a template with data",
                    "tags": ["Templates"]
                }
            },
            // ── Suppressions ─────────────────────────────────────
            "/v1/suppressions": {
                "get": {
                    "operationId": "listSuppressions",
                    "summary": "List suppressions",
                    "tags": ["Suppressions"]
                },
                "post": {
                    "operationId": "createSuppression",
                    "summary": "Add a suppression",
                    "tags": ["Suppressions"]
                }
            },
            // ── Events ───────────────────────────────────────────
            "/v1/events": {
                "get": {
                    "operationId": "listEvents",
                    "summary": "List delivery events",
                    "tags": ["Events"]
                }
            },
            "/v1/events/stats": {
                "get": {
                    "operationId": "getEventStats",
                    "summary": "Get event statistics",
                    "tags": ["Events"]
                }
            },
            // ── Analytics ────────────────────────────────────────
            "/v1/analytics": {
                "get": {
                    "operationId": "getAnalytics",
                    "summary": "Get email analytics",
                    "tags": ["Analytics"]
                }
            },
            // ── Campaigns ────────────────────────────────────────
            "/v1/campaigns": {
                "get": {
                    "operationId": "listCampaigns",
                    "summary": "List campaigns",
                    "tags": ["Campaigns"]
                },
                "post": {
                    "operationId": "createCampaign",
                    "summary": "Create a campaign",
                    "tags": ["Campaigns"]
                }
            },
            // ── Contacts ─────────────────────────────────────────
            "/v1/contacts": {
                "get": {
                    "operationId": "listContacts",
                    "summary": "List contacts",
                    "tags": ["Contacts"]
                },
                "post": {
                    "operationId": "createContact",
                    "summary": "Create a contact",
                    "tags": ["Contacts"]
                }
            },
            "/v1/contacts/bulk": {
                "post": {
                    "operationId": "bulkImportContacts",
                    "summary": "Bulk import contacts",
                    "tags": ["Contacts"]
                }
            },
            // ── Auth ─────────────────────────────────────────────
            "/v1/auth/login": {
                "post": {
                    "operationId": "login",
                    "summary": "Login",
                    "tags": ["Auth"]
                }
            },
            "/v1/auth/register": {
                "post": {
                    "operationId": "register",
                    "summary": "Register a new account",
                    "tags": ["Auth"]
                }
            },
            "/v1/auth/forgot-password": {
                "post": {
                    "operationId": "forgotPassword",
                    "summary": "Request password reset",
                    "tags": ["Auth"]
                }
            },
            "/v1/auth/reset-password": {
                "post": {
                    "operationId": "resetPassword",
                    "summary": "Reset password with token",
                    "tags": ["Auth"]
                }
            },
            // ── Developer (DevEx) ────────────────────────────────
            "/versions": {
                "get": {
                    "operationId": "listApiVersions",
                    "summary": "List API versions",
                    "tags": ["Developer"]
                }
            },
            "/sdks": {
                "get": {
                    "operationId": "listSdks",
                    "summary": "List available SDKs",
                    "tags": ["Developer"]
                }
            },
            "/webhooks/test": {
                "post": {
                    "operationId": "testWebhook",
                    "summary": "Send a test webhook",
                    "tags": ["Developer"]
                }
            },
            "/openapi.json": {
                "get": {
                    "operationId": "getOpenApiSpec",
                    "summary": "Get OpenAPI specification",
                    "tags": ["Developer"]
                }
            },
            "/onboarding/checklist": {
                "get": {
                    "operationId": "getOnboardingChecklist",
                    "summary": "Get onboarding checklist",
                    "tags": ["Developer"]
                }
            },
            "/health": {
                "get": {
                    "operationId": "healthCheck",
                    "summary": "Health check",
                    "tags": ["Developer"]
                }
            }
        });

        let enterprise_paths = self.build_enterprise_private_cloud_paths();
        paths
            .as_object_mut()
            .expect("OpenAPI paths builder must produce an object")
            .extend(
                enterprise_paths
                    .as_object()
                    .expect("Enterprise OpenAPI paths builder must produce an object")
                    .clone(),
            );

        paths
    }

    fn build_enterprise_private_cloud_paths(&self) -> serde_json::Value {
        serde_json::json!({
            "/enterprise/v1/deployments": {
                "post": {
                    "operationId": "createEnterprisePrivateDeployment",
                    "summary": "Create an Enterprise private deployment",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["tenant_id", "name", "deployment_type"]}}}},
                    "responses": {"200": {"description": "Deployment created"}, "401": {"description": "Unauthorized"}}
                }
            },
            "/enterprise/v1/deployments/{id}": {
                "get": {
                    "operationId": "getEnterprisePrivateDeployment",
                    "summary": "Get an Enterprise private deployment",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/deployments/tenant/{tenant_id}": {
                "get": {
                    "operationId": "listEnterprisePrivateDeployments",
                    "summary": "List Enterprise private deployments",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/deployments/{id}/provision": {
                "post": {
                    "operationId": "provisionEnterprisePrivateDeployment",
                    "summary": "Start private deployment provisioning",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/deployments/{id}/health": {
                "get": {
                    "operationId": "checkEnterprisePrivateDeploymentHealth",
                    "summary": "Check private deployment health",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/ips/allocate": {
                "post": {
                    "operationId": "allocateEnterpriseDedicatedIp",
                    "summary": "Allocate an Enterprise dedicated IP",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["tenant_id", "ip_address"]}}}},
                    "responses": {"200": {"description": "Dedicated IP allocated"}, "401": {"description": "Unauthorized"}}
                }
            },
            "/enterprise/v1/ips/{id}": {
                "get": {
                    "operationId": "getEnterpriseDedicatedIp",
                    "summary": "Get an Enterprise dedicated IP",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/ips/tenant/{tenant_id}": {
                "get": {
                    "operationId": "listEnterpriseDedicatedIps",
                    "summary": "List Enterprise dedicated IPs",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                    ]
                }
            },
            "/enterprise/v1/ips/reputation/{ip_address}": {
                "get": {
                    "operationId": "getEnterpriseDedicatedIpReputation",
                    "summary": "Get Enterprise dedicated IP reputation",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}]
                }
            },
            "/enterprise/v1/ips/byoip": {
                "post": {
                    "operationId": "registerEnterpriseByoipRange",
                    "summary": "Register a BYOIP range",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["tenant_id", "cidr_block"]}}}},
                    "responses": {"200": {"description": "BYOIP range registered"}, "401": {"description": "Unauthorized"}}
                }
            },
            "/enterprise/v1/ips/byoip/{id}/verify": {
                "post": {
                    "operationId": "verifyEnterpriseByoipRange",
                    "summary": "Verify BYOIP ownership",
                    "tags": ["Enterprise Private Cloud"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["verification_token"]}}}},
                    "responses": {"200": {"description": "BYOIP range verified"}, "401": {"description": "Unauthorized"}}
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
                name: "Templates".into(),
                description: "Email template management".into(),
            },
            OpenApiTag {
                name: "Webhooks".into(),
                description: "Configure and test webhook endpoints".into(),
            },
            OpenApiTag {
                name: "Suppressions".into(),
                description: "Manage email suppression lists".into(),
            },
            OpenApiTag {
                name: "Events".into(),
                description: "Email delivery events and statistics".into(),
            },
            OpenApiTag {
                name: "Analytics".into(),
                description: "Email delivery analytics and metrics".into(),
            },
            OpenApiTag {
                name: "Campaigns".into(),
                description: "Manage email campaigns".into(),
            },
            OpenApiTag {
                name: "Contacts".into(),
                description: "Manage contact lists".into(),
            },
            OpenApiTag {
                name: "Auth".into(),
                description: "Authentication and account management".into(),
            },
            OpenApiTag {
                name: "Enterprise Private Cloud".into(),
                description: "Private deployments, dedicated IP lifecycle, and BYOIP verification"
                    .into(),
            },
            OpenApiTag {
                name: "Developer".into(),
                description: "Developer experience and API tooling".into(),
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
        assert!(spec
            .tags
            .iter()
            .any(|tag| tag.name == "Enterprise Private Cloud"));
        assert!(spec.paths.get("/enterprise/v1/ips/byoip").is_some());
        // O-20.1: top-level security requirement declared
        assert!(
            spec.security.is_some(),
            "spec must declare top-level security requirements"
        );
        let sec = spec.security.as_ref().unwrap();
        assert!(
            sec.iter().any(|s| s.get("apiKey").is_some()),
            "spec must include apiKey security requirement"
        );
    }

    #[test]
    fn test_list_endpoints() {
        let endpoints = gen().list_endpoints();
        assert!(endpoints.len() >= 10);
        // All should have non-empty method + path
        assert!(endpoints
            .iter()
            .all(|e| !e.method.is_empty() && !e.path.is_empty()));
        assert!(endpoints.iter().all(|e| !e.deprecated));
        assert!(endpoints
            .iter()
            .any(|e| e.method == "POST" && e.path == "/enterprise/v1/ips/byoip"));
    }

    #[test]
    fn test_get_endpoint_schema() {
        let g = gen();
        let schema = g.get_endpoint_schema("POST", "/v1/messages").unwrap();
        assert_eq!(schema["method"], "POST");
        assert_eq!(schema["path"], "/v1/messages");
        assert!(!schema["deprecated"].as_bool().unwrap());

        let enterprise_schema = g
            .get_endpoint_schema("POST", "/enterprise/v1/ips/byoip/{id}/verify")
            .unwrap();
        assert_eq!(enterprise_schema["tag"], "Enterprise Private Cloud");

        // Unknown endpoint returns None.
        assert!(g.get_endpoint_schema("DELETE", "/v1/foobar").is_none());
    }
}
