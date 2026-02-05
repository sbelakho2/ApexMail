-- Performance indexes to fix PERF-003
-- These indexes improve query performance on high-volume columns

-- Messages table - frequently queried by tenant and status
CREATE INDEX IF NOT EXISTS idx_messages_tenant_status ON messages(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_messages_tenant_created ON messages(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_status_created ON messages(status, created_at);

-- Events table - frequently queried by message_id
CREATE INDEX IF NOT EXISTS idx_events_message_id ON events(message_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_created ON events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant_type ON events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_recipient ON events(recipient_email);

-- Suppressions table - frequently queried by email hash
CREATE INDEX IF NOT EXISTS idx_suppressions_email_hash ON suppressions(email_hash);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant_reason ON suppressions(tenant_id, reason);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant_created ON suppressions(tenant_id, created_at DESC);

-- API keys table - frequently queried by prefix for validation
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_status ON api_keys(tenant_id, is_active);

-- Domains table - frequently queried by tenant and status
CREATE INDEX IF NOT EXISTS idx_domains_tenant_status ON domains(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_domains_domain_name ON domains(domain_name);

-- Templates table - frequently queried by tenant and status
CREATE INDEX IF NOT EXISTS idx_templates_tenant_active ON templates(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_templates_slug ON templates(slug);
CREATE INDEX IF NOT EXISTS idx_templates_tenant_category ON templates(tenant_id, category);

-- Webhooks table - frequently queried by tenant and status
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_enabled ON webhooks(tenant_id, is_enabled);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_events ON webhooks(tenant_id, events);

-- Audit logs table - frequently queried for compliance
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_action ON audit_logs(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Add comments for documentation
COMMENT ON INDEX idx_messages_tenant_status IS 'Performance: List messages by tenant and filter by status';
COMMENT ON INDEX idx_events_message_id IS 'Performance: Fast event lookup for message tracking';
COMMENT ON INDEX idx_suppressions_email_hash IS 'Performance: Fast suppression check during sending';
COMMENT ON INDEX idx_api_keys_prefix IS 'Performance: Fast API key validation by prefix';
