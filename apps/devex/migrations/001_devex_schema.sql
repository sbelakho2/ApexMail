-- DevEx Schema Migration
-- Developer Experience tables for API versioning, webhooks, SDKs, sandbox mode

-- API Versions table
CREATE TABLE IF NOT EXISTS api_versions (
    version VARCHAR(20) PRIMARY KEY,
    status VARCHAR(20) NOT NULL CHECK (status IN ('current', 'supported', 'deprecated', 'sunset')),
    release_date DATE NOT NULL,
    deprecation_date DATE,
    sunset_date DATE,
    changes JSONB NOT NULL DEFAULT '[]',
    breaking_changes JSONB NOT NULL DEFAULT '[]',
    upgrade_guide TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook Endpoints table
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id VARCHAR(50) PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    events TEXT[] NOT NULL,
    secret VARCHAR(100) NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_endpoints_tenant ON webhook_endpoints(tenant_id);
CREATE INDEX idx_webhook_endpoints_enabled ON webhook_endpoints(enabled) WHERE enabled = true;

-- Webhook Delivery Logs table
CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id VARCHAR(50) PRIMARY KEY,
    endpoint_id VARCHAR(50) NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    event_id VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    response_time_ms INTEGER,
    attempt INTEGER NOT NULL DEFAULT 1,
    error TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at TIMESTAMPTZ
);

CREATE INDEX idx_webhook_delivery_logs_endpoint ON webhook_delivery_logs(endpoint_id);
CREATE INDEX idx_webhook_delivery_logs_event ON webhook_delivery_logs(event_id);
CREATE INDEX idx_webhook_delivery_logs_time ON webhook_delivery_logs(delivered_at DESC);
CREATE INDEX idx_webhook_delivery_logs_retry ON webhook_delivery_logs(next_retry_at) WHERE next_retry_at IS NOT NULL;

-- Pending Webhook Events table (for retry queue)
CREATE TABLE IF NOT EXISTS webhook_pending_events (
    id VARCHAR(50) PRIMARY KEY,
    endpoint_id VARCHAR(50) NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 6,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_pending_events_next ON webhook_pending_events(next_attempt_at) WHERE attempt < max_attempts;

-- Sandbox Environments table
CREATE TABLE IF NOT EXISTS sandbox_environments (
    id VARCHAR(50) PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    mode VARCHAR(20) NOT NULL CHECK (mode IN ('capture', 'simulate', 'forward', 'replay')),
    settings JSONB NOT NULL DEFAULT '{}',
    rate_limits JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_sandbox_environments_tenant ON sandbox_environments(tenant_id);
CREATE INDEX idx_sandbox_environments_expires ON sandbox_environments(expires_at) WHERE expires_at IS NOT NULL;

-- Sandbox Captured Emails table
CREATE TABLE IF NOT EXISTS sandbox_captured_emails (
    id VARCHAR(50) PRIMARY KEY,
    sandbox_id VARCHAR(50) NOT NULL REFERENCES sandbox_environments(id) ON DELETE CASCADE,
    from_address VARCHAR(255) NOT NULL,
    to_addresses TEXT[] NOT NULL,
    cc_addresses TEXT[] NOT NULL DEFAULT '{}',
    bcc_addresses TEXT[] NOT NULL DEFAULT '{}',
    subject TEXT NOT NULL,
    text_content TEXT,
    html_content TEXT,
    headers JSONB NOT NULL DEFAULT '{}',
    attachments JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    simulated_events JSONB NOT NULL DEFAULT '[]',
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sandbox_captured_emails_sandbox ON sandbox_captured_emails(sandbox_id);
CREATE INDEX idx_sandbox_captured_emails_from ON sandbox_captured_emails(from_address);
CREATE INDEX idx_sandbox_captured_emails_time ON sandbox_captured_emails(captured_at DESC);

-- Sandbox Test Inboxes table
CREATE TABLE IF NOT EXISTS sandbox_test_inboxes (
    id VARCHAR(50) PRIMARY KEY,
    sandbox_id VARCHAR(50) NOT NULL REFERENCES sandbox_environments(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sandbox_test_inboxes_sandbox ON sandbox_test_inboxes(sandbox_id);
CREATE INDEX idx_sandbox_test_inboxes_email ON sandbox_test_inboxes(email);

-- Sandbox API Keys table
CREATE TABLE IF NOT EXISTS sandbox_api_keys (
    id VARCHAR(50) PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    sandbox_id VARCHAR(50) NOT NULL REFERENCES sandbox_environments(id) ON DELETE CASCADE,
    key_prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_sandbox_api_keys_prefix ON sandbox_api_keys(key_prefix);
CREATE INDEX idx_sandbox_api_keys_tenant ON sandbox_api_keys(tenant_id);

-- SDK Downloads tracking table
CREATE TABLE IF NOT EXISTS sdk_downloads (
    id SERIAL PRIMARY KEY,
    language VARCHAR(20) NOT NULL,
    version VARCHAR(20) NOT NULL,
    tenant_id VARCHAR(50),
    ip_address INET,
    user_agent TEXT,
    downloaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sdk_downloads_language ON sdk_downloads(language);
CREATE INDEX idx_sdk_downloads_time ON sdk_downloads(downloaded_at DESC);

-- API Usage Metrics table
CREATE TABLE IF NOT EXISTS api_usage_metrics (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    api_version VARCHAR(20) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_usage_metrics_tenant ON api_usage_metrics(tenant_id);
CREATE INDEX idx_api_usage_metrics_time ON api_usage_metrics(timestamp DESC);
CREATE INDEX idx_api_usage_metrics_endpoint ON api_usage_metrics(endpoint);

-- Partitioning for api_usage_metrics (by month)
-- In production, you'd create partitions dynamically

-- API Version Deprecation Notices table
CREATE TABLE IF NOT EXISTS api_deprecation_notices (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    api_version VARCHAR(20) NOT NULL,
    notice_type VARCHAR(20) NOT NULL CHECK (notice_type IN ('deprecation', 'sunset', 'upgrade_available')),
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    email_sent BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_api_deprecation_notices_tenant ON api_deprecation_notices(tenant_id);

-- Feature Flags table (for gradual rollout)
CREATE TABLE IF NOT EXISTS devex_feature_flags (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT false,
    percentage INTEGER NOT NULL DEFAULT 0 CHECK (percentage >= 0 AND percentage <= 100),
    tenant_allowlist TEXT[] NOT NULL DEFAULT '{}',
    tenant_blocklist TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CLI Configuration table
CREATE TABLE IF NOT EXISTS cli_configurations (
    id VARCHAR(50) PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    profile_name VARCHAR(50) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, profile_name)
);

CREATE INDEX idx_cli_configurations_tenant ON cli_configurations(tenant_id);

-- Insert default API versions
INSERT INTO api_versions (version, status, release_date, changes) VALUES
    ('2024-01', 'current', '2024-01-15', '[
        {"type": "feature", "description": "Added batch sending with up to 1000 emails"},
        {"type": "feature", "description": "Added email scheduling"},
        {"type": "feature", "description": "Improved template variable syntax"},
        {"type": "improvement", "description": "Better error messages with field-level details"}
    ]'::jsonb),
    ('2023-10', 'supported', '2023-10-01', '[
        {"type": "feature", "description": "Added webhook retry with exponential backoff"},
        {"type": "feature", "description": "Added suppression list management"},
        {"type": "improvement", "description": "Increased attachment size limit to 25MB"}
    ]'::jsonb),
    ('2023-06', 'supported', '2023-06-15', '[
        {"type": "feature", "description": "Added analytics API"},
        {"type": "feature", "description": "Added template versioning"},
        {"type": "improvement", "description": "Added pagination to list endpoints"}
    ]'::jsonb),
    ('2023-01', 'deprecated', '2023-01-10', '[
        {"type": "feature", "description": "Initial stable release"},
        {"type": "feature", "description": "Email sending, templates, webhooks"}
    ]'::jsonb),
    ('2022-10', 'sunset', '2022-10-01', '[
        {"type": "feature", "description": "Beta release"}
    ]'::jsonb)
ON CONFLICT (version) DO UPDATE SET
    status = EXCLUDED.status,
    changes = EXCLUDED.changes,
    updated_at = NOW();

-- Set deprecation/sunset dates for older versions
UPDATE api_versions SET 
    deprecation_date = '2024-01-15',
    sunset_date = '2024-07-15'
WHERE version = '2023-01';

UPDATE api_versions SET 
    deprecation_date = '2023-06-01',
    sunset_date = '2024-01-01'
WHERE version = '2022-10';

-- Insert default feature flags
INSERT INTO devex_feature_flags (id, name, description, enabled, percentage) VALUES
    ('ff_sandbox_mode', 'Sandbox Mode', 'Enable sandbox mode for testing', true, 100),
    ('ff_sdk_generation', 'SDK Generation', 'Enable SDK generation endpoint', true, 100),
    ('ff_webhooks_v2', 'Webhooks V2', 'Enable new webhook delivery system', true, 100),
    ('ff_api_versioning', 'API Versioning', 'Enable date-based API versioning', true, 100),
    ('ff_cli_download', 'CLI Download', 'Enable CLI source download', true, 100)
ON CONFLICT (id) DO NOTHING;

-- Create function to clean up expired sandboxes
CREATE OR REPLACE FUNCTION cleanup_expired_sandboxes() RETURNS void AS $$
BEGIN
    -- Delete captured emails for expired sandboxes
    DELETE FROM sandbox_captured_emails 
    WHERE sandbox_id IN (
        SELECT id FROM sandbox_environments WHERE expires_at < NOW()
    );
    
    -- Delete test inboxes for expired sandboxes
    DELETE FROM sandbox_test_inboxes
    WHERE sandbox_id IN (
        SELECT id FROM sandbox_environments WHERE expires_at < NOW()
    );
    
    -- Delete API keys for expired sandboxes
    DELETE FROM sandbox_api_keys
    WHERE sandbox_id IN (
        SELECT id FROM sandbox_environments WHERE expires_at < NOW()
    );
    
    -- Delete expired sandboxes
    DELETE FROM sandbox_environments WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up old webhook logs
CREATE OR REPLACE FUNCTION cleanup_old_webhook_logs(retention_days INTEGER DEFAULT 30) RETURNS void AS $$
BEGIN
    DELETE FROM webhook_delivery_logs 
    WHERE delivered_at < NOW() - (retention_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up old API metrics
CREATE OR REPLACE FUNCTION cleanup_old_api_metrics(retention_days INTEGER DEFAULT 90) RETURNS void AS $$
BEGIN
    DELETE FROM api_usage_metrics 
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

-- Create aggregated metrics view
CREATE OR REPLACE VIEW v_api_metrics_daily AS
SELECT 
    tenant_id,
    api_version,
    endpoint,
    DATE(timestamp) as date,
    COUNT(*) as request_count,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) as success_count,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) as client_error_count,
    COUNT(*) FILTER (WHERE status_code >= 500) as server_error_count,
    AVG(response_time_ms)::INTEGER as avg_response_time_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms)::INTEGER as p95_response_time_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY response_time_ms)::INTEGER as p99_response_time_ms
FROM api_usage_metrics
GROUP BY tenant_id, api_version, endpoint, DATE(timestamp);

-- Create webhook stats view
CREATE OR REPLACE VIEW v_webhook_stats AS
SELECT 
    e.id as endpoint_id,
    e.tenant_id,
    e.url,
    e.enabled,
    COUNT(l.id) as total_deliveries,
    COUNT(l.id) FILTER (WHERE l.response_status >= 200 AND l.response_status < 300) as successful_deliveries,
    COUNT(l.id) FILTER (WHERE l.response_status >= 400 OR l.error IS NOT NULL) as failed_deliveries,
    AVG(l.response_time_ms) FILTER (WHERE l.response_time_ms IS NOT NULL)::INTEGER as avg_response_time_ms,
    MAX(l.delivered_at) as last_delivery_at
FROM webhook_endpoints e
LEFT JOIN webhook_delivery_logs l ON e.id = l.endpoint_id
GROUP BY e.id, e.tenant_id, e.url, e.enabled;

-- Create sandbox stats view
CREATE OR REPLACE VIEW v_sandbox_stats AS
SELECT 
    s.id as sandbox_id,
    s.tenant_id,
    s.name,
    s.mode,
    s.expires_at,
    COUNT(e.id) as emails_captured,
    COUNT(i.id) as test_inboxes,
    COUNT(k.id) as api_keys
FROM sandbox_environments s
LEFT JOIN sandbox_captured_emails e ON s.id = e.sandbox_id
LEFT JOIN sandbox_test_inboxes i ON s.id = i.sandbox_id
LEFT JOIN sandbox_api_keys k ON s.id = k.sandbox_id
GROUP BY s.id, s.tenant_id, s.name, s.mode, s.expires_at;

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_webhook_endpoints_updated_at
    BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sandbox_environments_updated_at
    BEFORE UPDATE ON sandbox_environments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_versions_updated_at
    BEFORE UPDATE ON api_versions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devex_feature_flags_updated_at
    BEFORE UPDATE ON devex_feature_flags
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cli_configurations_updated_at
    BEFORE UPDATE ON cli_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE api_versions IS 'Stores API version information for date-based versioning';
COMMENT ON TABLE webhook_endpoints IS 'Webhook endpoint configurations per tenant';
COMMENT ON TABLE webhook_delivery_logs IS 'Log of all webhook delivery attempts';
COMMENT ON TABLE webhook_pending_events IS 'Queue for webhook events pending delivery/retry';
COMMENT ON TABLE sandbox_environments IS 'Sandbox environments for testing';
COMMENT ON TABLE sandbox_captured_emails IS 'Emails captured in sandbox mode';
COMMENT ON TABLE sandbox_test_inboxes IS 'Test inboxes created within sandboxes';
COMMENT ON TABLE sandbox_api_keys IS 'API keys scoped to sandbox environments';
COMMENT ON TABLE sdk_downloads IS 'Tracking SDK downloads by language';
COMMENT ON TABLE api_usage_metrics IS 'Detailed API usage metrics for analytics';
COMMENT ON TABLE api_deprecation_notices IS 'Tracking of deprecation notices sent to tenants';
COMMENT ON TABLE devex_feature_flags IS 'Feature flags for gradual rollout';
COMMENT ON TABLE cli_configurations IS 'CLI configurations per tenant profile';
