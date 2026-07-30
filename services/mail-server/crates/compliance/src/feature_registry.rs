use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureStatus {
    GA,
    Beta,
    Preview,
    Planned,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeaturePlan {
    Free,
    Developer,
    Pro,
    Growth,
    Business,
    Enterprise,
    DedicatedTenant,
    BYOC,
    AddOn,
}

impl FeaturePlan {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Free => 0,
            Self::Developer => 1,
            Self::Pro => 2,
            Self::Growth => 3,
            Self::Business => 4,
            Self::Enterprise => 5,
            Self::DedicatedTenant => 6,
            Self::BYOC => 7,
            Self::AddOn => 8,
        }
    }

    pub fn available_on(&self, plan: FeaturePlan) -> bool {
        if matches!(self, FeaturePlan::AddOn) {
            return matches!(plan, FeaturePlan::AddOn);
        }
        self.rank() >= plan.rank()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureRecord {
    pub feature_id: String,
    pub public_name: String,
    pub customer_outcome: String,
    pub definition: String,
    pub status: FeatureStatus,
    pub minimum_plan: FeaturePlan,
    pub additional_limits: Option<String>,
    pub api_endpoint: Option<String>,
    pub smtp_behavior: Option<String>,
    pub dashboard_route: Option<String>,
    pub documentation_url: Option<String>,
    pub required_permissions: Vec<String>,
    pub data_processed: Vec<String>,
    pub retention_implications: Option<String>,
    pub screenshot_asset: Option<String>,
    pub product_owner: String,
    pub support_owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct FeatureRegistry {
    features: HashMap<String, FeatureRecord>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
        }
    }

    pub fn register(&mut self, feature: FeatureRecord) {
        self.features.insert(feature.feature_id.clone(), feature);
    }

    pub fn get(&self, id: &str) -> Option<&FeatureRecord> {
        self.features.get(id)
    }

    pub fn all(&self) -> Vec<&FeatureRecord> {
        self.features.values().collect()
    }

    pub fn by_status(&self, status: FeatureStatus) -> Vec<&FeatureRecord> {
        self.features
            .values()
            .filter(|f| f.status == status)
            .collect()
    }

    pub fn by_minimum_plan(&self, plan: FeaturePlan) -> Vec<&FeatureRecord> {
        self.features
            .values()
            .filter(|f| f.minimum_plan.rank() >= plan.rank())
            .collect()
    }

    pub fn available_for_plan(&self, plan: FeaturePlan) -> Vec<&FeatureRecord> {
        self.features
            .values()
            .filter(|f| plan.available_on(f.minimum_plan) && f.status != FeatureStatus::Retired)
            .collect()
    }

    pub fn retired(&self) -> Vec<&FeatureRecord> {
        self.by_status(FeatureStatus::Retired)
    }
}

pub fn seed_feature_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    let now = Utc::now();

    registry.register(FeatureRecord {
        feature_id: "FEAT-001".into(),
        public_name: "REST Sending".into(),
        customer_outcome: "Send transactional or broadcast email through a standard HTTP API.".into(),
        definition: "REST API endpoint accepting JSON payloads with recipients, subject, body, headers, attachments, and metadata.".into(),
        status: FeatureStatus::Beta,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 100/day. Developer: 5,000/day. Pro: 15,000/day.".into()),
        api_endpoint: Some("POST /v1/messages".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/send".into()),
        documentation_url: Some("/docs/sending/rest/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["recipient".into(), "subject".into(), "body".into(), "headers".into(), "attachments".into(), "metadata".into()],
        retention_implications: Some("Content retention per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-002".into(),
        public_name: "SMTP Sending".into(),
        customer_outcome: "Send email through standard SMTP relay for legacy and internal applications.".into(),
        definition: "Authenticated SMTP relay accepting messages from any standards-compliant SMTP client.".into(),
        status: FeatureStatus::Beta,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 1 credential. Developer: 3 credentials.".into()),
        api_endpoint: None,
        smtp_behavior: Some("AUTH LOGIN/PLAIN, STARTTLS required".into()),
        dashboard_route: Some("/dashboard/smtp".into()),
        documentation_url: Some("/docs/sending/smtp/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["recipient".into(), "subject".into(), "body".into(), "headers".into(), "attachments".into()],
        retention_implications: Some("Content retention per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-003".into(),
        public_name: "Batch Sending".into(),
        customer_outcome: "Send to multiple recipients in a single API call for efficiency.".into(),
        definition: "Single API request can address up to the plan batch limit recipients, each receiving the same message content.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Developer,
        additional_limits: Some("Free: 10. Developer: 500. Pro: 1,000. Growth: 5,000. Business: 10,000.".into()),
        api_endpoint: Some("POST /v1/messages (batch mode)".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/send".into()),
        documentation_url: Some("/docs/sending/batch/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["recipients".into()],
        retention_implications: Some("Content retention per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-004".into(),
        public_name: "Scheduled Sending".into(),
        customer_outcome: "Schedule messages for future delivery with cancellation before dispatch.".into(),
        definition: "Accept a send_at timestamp; message is queued and delivered at or after the scheduled time. Cancellable before dispatch.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Developer,
        additional_limits: Some("Scheduling horizon: 30 days".into()),
        api_endpoint: Some("POST /v1/messages (scheduled)".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/scheduled".into()),
        documentation_url: Some("/docs/sending/scheduled/".into()),
        required_permissions: vec!["messages:send".into(), "messages:read".into()],
        data_processed: vec!["scheduled_at".into()],
        retention_implications: Some("Scheduled content stored until dispatch".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-005".into(),
        public_name: "Templates".into(),
        customer_outcome: "Define reusable email layouts with variables for consistent application messages.".into(),
        definition: "Stored HTML and text templates with named variables, default values, versioning, and rollback.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 5 templates. Developer: 25. Pro: 100. Growth: 250. Business/Enterprise: unlimited.".into()),
        api_endpoint: Some("POST /v1/templates".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/templates".into()),
        documentation_url: Some("/docs/templates/".into()),
        required_permissions: vec!["templates:read".into(), "templates:write".into()],
        data_processed: vec!["template_content".into(), "variables".into()],
        retention_implications: Some("Template versions retained indefinitely while published".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-006".into(),
        public_name: "Template Versions".into(),
        customer_outcome: "Publish, version, and roll back templates without affecting in-flight messages.".into(),
        definition: "Templates support draft/published states, version history, and rollback. New publishes do not alter already-queued messages.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Developer,
        additional_limits: None,
        api_endpoint: Some("POST /v1/templates/{id}/versions".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/templates/{id}/versions".into()),
        documentation_url: Some("/docs/templates/versions/".into()),
        required_permissions: vec!["templates:read".into(), "templates:write".into()],
        data_processed: vec!["template_version".into()],
        retention_implications: Some("Historic versions retained for rollback".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-007".into(),
        public_name: "Attachments".into(),
        customer_outcome: "Attach files to email messages with configurable size limits.".into(),
        definition: "Support for MIME attachments with type validation, size enforcement, and inline attachment support.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 5 MB. Dev/Pro: 25 MB. Growth/Business: 50 MB. Enterprise: 100 MB.".into()),
        api_endpoint: Some("Included in POST /v1/messages payload".into()),
        smtp_behavior: Some("Standard MIME attachment encoding".into()),
        dashboard_route: None,
        documentation_url: Some("/docs/sending/attachments/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["attachment_content".into(), "file_type".into()],
        retention_implications: Some("Content retention per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-008".into(),
        public_name: "Tags and Metadata".into(),
        customer_outcome: "Attach custom tags and metadata to messages for filtering, reporting, and automation.".into(),
        definition: "Each message accepts key-value tags and JSON metadata for customer-side classification and webhook routing.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: None,
        api_endpoint: Some("Included in POST /v1/messages payload".into()),
        smtp_behavior: Some("Tags set via X-ApexMail-Tag header".into()),
        dashboard_route: Some("/dashboard/activity".into()),
        documentation_url: Some("/docs/sending/tags/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["tags".into(), "metadata".into()],
        retention_implications: Some("Persisted with message events per retention policy".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-009".into(),
        public_name: "Transactional Streams".into(),
        customer_outcome: "Send critical application email through a dedicated sending pool for higher delivery priority.".into(),
        definition: "Messages classified as transactional use a separate IP pool, skip automatic unsubscribe footers, and receive higher delivery priority.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Pro,
        additional_limits: Some("Separate pool assignment per stream".into()),
        api_endpoint: Some("POST /v1/messages with stream=transactional".into()),
        smtp_behavior: Some("X-ApexMail-Stream header".into()),
        dashboard_route: Some("/dashboard/streams".into()),
        documentation_url: Some("/docs/streams/transactional/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["stream_type".into()],
        retention_implications: None,
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-010".into(),
        public_name: "Broadcast Streams".into(),
        customer_outcome: "Send marketing and broadcast email with required unsubscribe handling and separate reputation management.".into(),
        definition: "Messages classified as broadcast are sent from a separate pool with mandatory unsubscribe (`List-Unsubscribe` and `List-Unsubscribe-Post`), complaint monitoring, and frequency controls.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Pro,
        additional_limits: Some("Unsubscribe configuration required".into()),
        api_endpoint: Some("POST /v1/messages with stream=broadcast".into()),
        smtp_behavior: Some("X-ApexMail-Stream header".into()),
        dashboard_route: Some("/dashboard/streams".into()),
        documentation_url: Some("/docs/streams/broadcast/".into()),
        required_permissions: vec!["messages:send".into()],
        data_processed: vec!["stream_type".into(), "unsubscribe_config".into()],
        retention_implications: None,
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-011".into(),
        public_name: "Webhooks".into(),
        customer_outcome: "Receive real-time push notifications for every message event with HMAC signature verification.".into(),
        definition: "Signed HTTP callbacks delivering `message.*` events (accepted, delivered, bounced, complained, opened, clicked, etc.) with at-least-once delivery and retry.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 1 endpoint. Developer: 3. Pro: 5. Growth: 10. Business: 25. Enterprise: 50.".into()),
        api_endpoint: Some("POST /v1/webhooks".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/webhooks".into()),
        documentation_url: Some("/docs/webhooks/".into()),
        required_permissions: vec!["webhooks:read".into(), "webhooks:write".into()],
        data_processed: vec!["event_payload".into(), "signature".into()],
        retention_implications: Some("Webhook request/response bodies retained per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-012".into(),
        public_name: "Webhook Replay".into(),
        customer_outcome: "Replay failed or missed webhook events manually from the dashboard.".into(),
        definition: "Dashboard and API support for re-sending webhook payloads from a configurable replay window.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Developer,
        additional_limits: Some("Replay window: 7 days".into()),
        api_endpoint: Some("POST /v1/webhooks/{id}/replay".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/webhooks/{id}".into()),
        documentation_url: Some("/docs/webhooks/replay/".into()),
        required_permissions: vec!["webhooks:read".into(), "webhooks:write".into()],
        data_processed: vec!["replay_request".into()],
        retention_implications: Some("Events retained for replay per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-013".into(),
        public_name: "Suppressions".into(),
        customer_outcome: "Prevent delivery to bounced, complained, or opted-out recipients automatically.".into(),
        definition: "Multi-scope suppression system (global, organization, workspace, subaccount, stream, domain) blocking delivery before billing for hard bounces, complaints, unsubscribes, and administrative blocks.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Basic suppressions on Free".into()),
        api_endpoint: Some("GET/POST/DELETE /v1/suppressions".into()),
        smtp_behavior: Some("Automatic suppression enforcement on relay".into()),
        dashboard_route: Some("/dashboard/suppressions".into()),
        documentation_url: Some("/docs/suppressions/".into()),
        required_permissions: vec!["suppressions:read".into(), "suppressions:write".into()],
        data_processed: vec!["recipient".into(), "reason".into(), "scope".into()],
        retention_implications: Some("Suppression records retained indefinitely while active".into()),
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-014".into(),
        public_name: "Inbound Email".into(),
        customer_outcome: "Receive, parse, and process inbound email through signed webhooks.".into(),
        definition: "MX-based inbound email reception with header parsing, body extraction, attachment handling, spam scoring, malware scanning, and signed webhook delivery.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Developer,
        additional_limits: Some("Developer: basic inbound. Full routing on Pro+".into()),
        api_endpoint: Some("Inbound routes configured via /v1/inbound".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/inbound".into()),
        documentation_url: Some("/docs/inbound/".into()),
        required_permissions: vec!["webhooks:read".into(), "webhooks:write".into()],
        data_processed: vec!["inbound_message".into(), "attachments".into(), "sender".into()],
        retention_implications: Some("Inbound content retention configurable per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-015".into(),
        public_name: "Message Activity".into(),
        customer_outcome: "Inspect the complete lifecycle of every message with provider-aware diagnostics.".into(),
        definition: "Searchable timeline showing API acceptance, queueing, DKIM, sending IP, delivery attempts, SMTP responses, enhanced status codes, TLS info, and webhook attempts.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Free,
        additional_limits: Some("Free: 7-day event history. Developer: 30-day. Pro: 90-day. Growth: 90-day. Business: 180-day.".into()),
        api_endpoint: Some("GET /v1/messages/{id}/activity".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/activity".into()),
        documentation_url: Some("/docs/activity/".into()),
        required_permissions: vec!["messages:read".into(), "events:read".into()],
        data_processed: vec!["message_events".into(), "smtp_responses".into(), "tls_info".into()],
        retention_implications: Some("Event retention per plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-016".into(),
        public_name: "Analytics".into(),
        customer_outcome: "Monitor sending performance, engagement, and delivery across domains, streams, and providers.".into(),
        definition: "Dashboard and API analytics covering accepted, delivered, deferred, bounced, complained, opened, clicked metrics with filtering, export, and alert thresholds.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Pro,
        additional_limits: Some("Basic analytics on Pro. Advanced on Growth+.".into()),
        api_endpoint: Some("GET /v1/analytics/**".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/analytics".into()),
        documentation_url: Some("/docs/analytics/".into()),
        required_permissions: vec!["analytics:read".into()],
        data_processed: vec!["aggregated_events".into(), "opens".into(), "clicks".into()],
        retention_implications: Some("Analytics data retention per plan event retention".into()),
        screenshot_asset: None,
        product_owner: "Product".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-017".into(),
        public_name: "Email Grader".into(),
        customer_outcome: "Score email content for authentication, deliverability, and best-practice compliance.".into(),
        definition: "Automated analysis checking SPF/DKIM/DMARC alignment, header quality, HTML structure, link validity, image attributes, blocklist presence, and content heuristics with an actionable score.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Pro,
        additional_limits: Some("Credit-based; 10 free/month on Pro".into()),
        api_endpoint: Some("POST /v1/grader".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/grader".into()),
        documentation_url: Some("/docs/grader/".into()),
        required_permissions: vec!["messages:read".into()],
        data_processed: vec!["email_content".into(), "authentication_state".into()],
        retention_implications: Some("Grading results retained per plan".into()),
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-018".into(),
        public_name: "Inbox Placement".into(),
        customer_outcome: "Test where your email lands across major mailbox providers using seed addresses.".into(),
        definition: "Seed-list based inbox placement testing showing folder categorization (inbox, spam, promotions) across supported providers, with documented limitations.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Pro,
        additional_limits: Some("Pro: 10 tests/month. Growth: 20. Business: 50. Enterprise: negotiated.".into()),
        api_endpoint: Some("POST /v1/inbox-placement".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/inbox-placement".into()),
        documentation_url: Some("/docs/inbox-placement/".into()),
        required_permissions: vec!["messages:send".into(), "messages:read".into()],
        data_processed: vec!["seed_addresses".into(), "test_content".into()],
        retention_implications: Some("Test content retained per plan".into()),
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-019".into(),
        public_name: "Dedicated IP".into(),
        customer_outcome: "Build and manage your own sending reputation on dedicated IP addresses.".into(),
        definition: "Managed dedicated IP assignment with reverse DNS, warm-up schedule, reputation monitoring, blocklist monitoring, feedback loops, and controlled replacement policy. Eligibility review required.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::AddOn,
        additional_limits: Some("€49/mo first IP, €69/mo additional. ~100k monthly volume recommended.".into()),
        api_endpoint: None,
        smtp_behavior: Some("Dedicated IP pool assignment".into()),
        dashboard_route: Some("/dashboard/ips".into()),
        documentation_url: Some("/docs/dedicated-ips/".into()),
        required_permissions: vec!["domains:read".into(), "compliance:read".into()],
        data_processed: vec!["ip_assignment".into(), "warmup_schedule".into()],
        retention_implications: None,
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Deliverability".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-020".into(),
        public_name: "IP Warming".into(),
        customer_outcome: "Gradually establish sending reputation on new dedicated IPs with automated or managed warm-up.".into(),
        definition: "Automated warm-up service with daily volume targets, provider-specific throttling, pause/rollback, shared-pool fallback, and dashboard visibility into warm-up progress.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Growth,
        additional_limits: Some("Managed warm-up on Growth+. Requires dedicated IP.".into()),
        api_endpoint: Some("GET /v1/ips/{id}/warmup".into()),
        smtp_behavior: Some("Volume throttling during warm-up".into()),
        dashboard_route: Some("/dashboard/ips/{id}/warmup".into()),
        documentation_url: Some("/docs/dedicated-ips/warm-up/".into()),
        required_permissions: vec!["domains:read".into()],
        data_processed: vec!["warmup_progress".into(), "daily_volume".into()],
        retention_implications: None,
        screenshot_asset: None,
        product_owner: "Deliverability".into(),
        support_owner: "Deliverability".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-021".into(),
        public_name: "Subaccounts".into(),
        customer_outcome: "Organise sending under separate subaccounts with independent quotas, domains, and API keys.".into(),
        definition: "Hierarchical subaccount model with per-subaccount quotas, domain isolation, API key scoping, and consolidated billing. Subaccount users cannot access other subaccounts.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Growth,
        additional_limits: Some("Growth: 5 subaccounts. Business: 25. Enterprise: 50.".into()),
        api_endpoint: Some("POST /v1/subaccounts".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/subaccounts".into()),
        documentation_url: Some("/docs/subaccounts/".into()),
        required_permissions: vec!["domains:read".into(), "domains:write".into()],
        data_processed: vec!["subaccount_config".into(), "quotas".into()],
        retention_implications: Some("Subaccount data retained per parent plan".into()),
        screenshot_asset: None,
        product_owner: "Engineering".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-022".into(),
        public_name: "Audit Logs".into(),
        customer_outcome: "Track every administrative and security action across your organization.".into(),
        definition: "Immutable, hashed, chained audit log recording all administrative actions, API key operations, permission changes, and security events with export capability.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Growth,
        additional_limits: Some("Growth: basic audit logs. Business: advanced. Enterprise: premium.".into()),
        api_endpoint: Some("GET /v1/audit-logs".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/audit".into()),
        documentation_url: Some("/docs/audit-logs/".into()),
        required_permissions: vec!["compliance:read".into()],
        data_processed: vec!["audit_entries".into()],
        retention_implications: Some("Audit logs retained per plan retention".into()),
        screenshot_asset: None,
        product_owner: "Security".into(),
        support_owner: "Security".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-023".into(),
        public_name: "SSO (SAML)".into(),
        customer_outcome: "Authenticate users through your corporate identity provider using SAML 2.0.".into(),
        definition: "SAML 2.0 SSO integration supporting IdP-initiated and SP-initiated flows, just-in-time provisioning, and role mapping.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Business,
        additional_limits: None,
        api_endpoint: None,
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/settings/sso".into()),
        documentation_url: Some("/docs/security/sso/".into()),
        required_permissions: vec!["compliance:read".into()],
        data_processed: vec!["saml_assertion".into(), "user_attributes".into()],
        retention_implications: Some("SSO configuration retained while active".into()),
        screenshot_asset: None,
        product_owner: "Security".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-024".into(),
        public_name: "SCIM".into(),
        customer_outcome: "Automate user and group provisioning and deprovisioning through SCIM 2.0.".into(),
        definition: "SCIM 2.0 API for programmatic user lifecycle management, group synchronization, and automated deprovisioning.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Enterprise,
        additional_limits: None,
        api_endpoint: Some("/scim/v2/".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/settings/scim".into()),
        documentation_url: Some("/docs/security/scim/".into()),
        required_permissions: vec!["compliance:write".into()],
        data_processed: vec!["user_attributes".into(), "group_membership".into()],
        retention_implications: None,
        screenshot_asset: None,
        product_owner: "Security".into(),
        support_owner: "Support".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-025".into(),
        public_name: "Dedicated Tenancy".into(),
        customer_outcome: "Run on dedicated application and data infrastructure with customer-specific maintenance windows.".into(),
        definition: "Single-tenant deployment with dedicated application servers, optional dedicated database, defined EEA region, private network options, custom backup policy, and enhanced SLA.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::DedicatedTenant,
        additional_limits: Some("From €4,000/mo + setup. 12-month minimum.".into()),
        api_endpoint: Some("Custom base URL for tenant".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/deployment".into()),
        documentation_url: Some("/docs/deployment/dedicated-tenant/".into()),
        required_permissions: vec!["compliance:read".into()],
        data_processed: vec!["infrastructure_config".into(), "backup_policy".into()],
        retention_implications: Some("Custom retention policies available".into()),
        screenshot_asset: None,
        product_owner: "Infrastructure".into(),
        support_owner: "Infrastructure".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-026".into(),
        public_name: "BYOC".into(),
        customer_outcome: "Deploy ApexMail in your own cloud account with full infrastructure control.".into(),
        definition: "Customer-hosted deployment using infrastructure-as-code, with ApexMail providing software license, deployment automation, upgrades, monitoring integration, and operational support.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::BYOC,
        additional_limits: Some("From €6,500/mo + setup. 12-24 month minimum.".into()),
        api_endpoint: Some("Custom base URL in customer account".into()),
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/deployment".into()),
        documentation_url: Some("/docs/deployment/byoc/".into()),
        required_permissions: vec!["compliance:read".into()],
        data_processed: vec!["infrastructure_config".into(), "deployment_state".into()],
        retention_implications: Some("Customer-managed retention".into()),
        screenshot_asset: None,
        product_owner: "Infrastructure".into(),
        support_owner: "Infrastructure".into(),
        created_at: now,
        updated_at: now,
    });

    registry.register(FeatureRecord {
        feature_id: "FEAT-027".into(),
        public_name: "BAA Eligibility".into(),
        customer_outcome: "Enter into a Business Associate Agreement for HIPAA-covered workloads after review.".into(),
        definition: "BAA availability for eligible Enterprise Cloud and Dedicated Tenant customers whose workload, architecture, and configuration pass BAA eligibility review.".into(),
        status: FeatureStatus::Planned,
        minimum_plan: FeaturePlan::Enterprise,
        additional_limits: Some("BAA review required; not automatic".into()),
        api_endpoint: None,
        smtp_behavior: None,
        dashboard_route: Some("/dashboard/compliance".into()),
        documentation_url: Some("/docs/compliance/hipaa/".into()),
        required_permissions: vec!["compliance:read".into()],
        data_processed: vec!["baa_agreement".into()],
        retention_implications: Some("HIPAA retention requirements apply".into()),
        screenshot_asset: None,
        product_owner: "Security".into(),
        support_owner: "Legal".into(),
        created_at: now,
        updated_at: now,
    });

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> FeatureRegistry {
        seed_feature_registry()
    }

    #[test]
    fn test_minimum_27_features() {
        let r = registry();
        assert!(
            r.all().len() >= 27,
            "Expected at least 27 features, got {}",
            r.all().len()
        );
    }

    #[test]
    fn test_all_features_have_unique_ids() {
        let r = registry();
        let mut ids: Vec<&str> = r.all().iter().map(|f| f.feature_id.as_str()).collect();
        ids.sort();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "Duplicate feature IDs found");
    }

    #[test]
    fn test_no_retired_features_yet() {
        let r = registry();
        assert!(
            r.retired().is_empty(),
            "No features should be retired at initial seed"
        );
    }

    #[test]
    fn test_all_features_have_owner() {
        let r = registry();
        for f in r.all() {
            assert!(!f.product_owner.is_empty(), "Feature {} has no product owner", f.feature_id);
            assert!(!f.support_owner.is_empty(), "Feature {} has no support owner", f.feature_id);
        }
    }

    #[test]
    fn test_feature_by_id() {
        let r = registry();
        let feat = r.get("FEAT-001").expect("FEAT-001 should exist");
        assert_eq!(feat.public_name, "REST Sending");
        assert_eq!(feat.minimum_plan, FeaturePlan::Free);
    }

    #[test]
    fn test_plan_availability() {
        let r = registry();
        let free_features = r.available_for_plan(FeaturePlan::Free);
        assert!(!free_features.is_empty(), "Free plan should have features");

        let byoc_features = r.available_for_plan(FeaturePlan::BYOC);
        assert!(byoc_features.len() > free_features.len(), "BYOC should have more features than Free");

        let has_dedicated_tenancy = byoc_features.iter().any(|f| f.feature_id == "FEAT-025");
        assert!(has_dedicated_tenancy, "BYOC should include Dedicated Tenancy");
    }

    #[test]
    fn test_key_features_exist() {
        let r = registry();
        let ids: Vec<&str> = r.all().iter().map(|f| f.feature_id.as_str()).collect();

        let required = [
            "FEAT-001", "FEAT-002", "FEAT-003", "FEAT-004", "FEAT-005",
            "FEAT-007", "FEAT-011", "FEAT-013", "FEAT-014", "FEAT-015",
            "FEAT-016", "FEAT-019", "FEAT-021", "FEAT-022", "FEAT-023", "FEAT-024",
            "FEAT-025", "FEAT-026",
        ];

        for req_id in required {
            assert!(ids.contains(&req_id), "Required feature {} missing from registry", req_id);
        }
    }
}
