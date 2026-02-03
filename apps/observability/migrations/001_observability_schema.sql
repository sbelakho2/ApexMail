-- Observability Schema Migration
-- ApexMail Observability & Tracing Database Schema

-- ============================================
-- Trace Storage Tables
-- ============================================

-- Traces table - stores complete trace information
CREATE TABLE IF NOT EXISTS obs_traces (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    service_name VARCHAR(128) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    duration_ms BIGINT,
    status VARCHAR(32) DEFAULT 'OK',
    status_message TEXT,
    attributes JSONB DEFAULT '{}',
    resource JSONB DEFAULT '{}',
    span_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_traces_service ON obs_traces(service_name);
CREATE INDEX idx_obs_traces_start_time ON obs_traces(start_time);
CREATE INDEX idx_obs_traces_status ON obs_traces(status);
CREATE INDEX idx_obs_traces_attributes ON obs_traces USING gin(attributes);

-- Spans table - stores individual spans
CREATE TABLE IF NOT EXISTS obs_spans (
    id VARCHAR(64) PRIMARY KEY,
    trace_id VARCHAR(64) NOT NULL REFERENCES obs_traces(id) ON DELETE CASCADE,
    parent_span_id VARCHAR(64),
    name VARCHAR(255) NOT NULL,
    kind VARCHAR(32) DEFAULT 'INTERNAL',
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    duration_ms BIGINT,
    status VARCHAR(32) DEFAULT 'OK',
    status_message TEXT,
    attributes JSONB DEFAULT '{}',
    events JSONB DEFAULT '[]',
    links JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_spans_trace_id ON obs_spans(trace_id);
CREATE INDEX idx_obs_spans_parent ON obs_spans(parent_span_id);
CREATE INDEX idx_obs_spans_name ON obs_spans(name);
CREATE INDEX idx_obs_spans_start_time ON obs_spans(start_time);
CREATE INDEX idx_obs_spans_attributes ON obs_spans USING gin(attributes);

-- ============================================
-- Metrics Storage Tables
-- ============================================

-- Metrics table - time series data
CREATE TABLE IF NOT EXISTS obs_metrics (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL,
    workspace_id VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_metrics_name ON obs_metrics(name);
CREATE INDEX idx_obs_metrics_recorded_at ON obs_metrics(recorded_at);
CREATE INDEX idx_obs_metrics_labels ON obs_metrics USING gin(labels);
CREATE INDEX idx_obs_metrics_workspace ON obs_metrics(workspace_id);

-- Partitioning for metrics (daily partitions)
-- In production, would use pg_partman or similar

-- Metrics metadata - stores metric definitions
CREATE TABLE IF NOT EXISTS obs_metrics_metadata (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL,
    description TEXT,
    unit VARCHAR(64),
    labels_schema JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- Logging Tables
-- ============================================

-- Log entries table
CREATE TABLE IF NOT EXISTS obs_logs (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    level VARCHAR(16) NOT NULL,
    message TEXT NOT NULL,
    service VARCHAR(128),
    trace_id VARCHAR(64),
    span_id VARCHAR(64),
    context JSONB DEFAULT '{}',
    workspace_id VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_logs_timestamp ON obs_logs(timestamp);
CREATE INDEX idx_obs_logs_level ON obs_logs(level);
CREATE INDEX idx_obs_logs_service ON obs_logs(service);
CREATE INDEX idx_obs_logs_trace_id ON obs_logs(trace_id);
CREATE INDEX idx_obs_logs_workspace ON obs_logs(workspace_id);
CREATE INDEX idx_obs_logs_message_search ON obs_logs USING gin(to_tsvector('english', message));
CREATE INDEX idx_obs_logs_context ON obs_logs USING gin(context);

-- ============================================
-- Alerting Tables
-- ============================================

-- Alert rules table
CREATE TABLE IF NOT EXISTS obs_alert_rules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    expression TEXT NOT NULL,
    duration INTEGER DEFAULT 300,
    severity VARCHAR(32) DEFAULT 'warning',
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    notification_channels JSONB DEFAULT '[]',
    runbook TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_alert_rules_enabled ON obs_alert_rules(enabled);
CREATE INDEX idx_obs_alert_rules_severity ON obs_alert_rules(severity);

-- Alerts table - alert instances
CREATE TABLE IF NOT EXISTS obs_alerts (
    id VARCHAR(64) PRIMARY KEY,
    rule_id VARCHAR(64) REFERENCES obs_alert_rules(id) ON DELETE SET NULL,
    rule_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    summary TEXT NOT NULL,
    description TEXT,
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    value DOUBLE PRECISION,
    threshold DOUBLE PRECISION,
    fired_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by VARCHAR(64),
    silenced_until TIMESTAMPTZ,
    notifications_sent INTEGER DEFAULT 0,
    last_notification_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_alerts_status ON obs_alerts(status);
CREATE INDEX idx_obs_alerts_severity ON obs_alerts(severity);
CREATE INDEX idx_obs_alerts_rule_id ON obs_alerts(rule_id);
CREATE INDEX idx_obs_alerts_fired_at ON obs_alerts(fired_at);
CREATE INDEX idx_obs_alerts_labels ON obs_alerts USING gin(labels);

-- Notification channels table
CREATE TABLE IF NOT EXISTS obs_notification_channels (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_notification_channels_type ON obs_notification_channels(type);
CREATE INDEX idx_obs_notification_channels_enabled ON obs_notification_channels(enabled);

-- Silences table
CREATE TABLE IF NOT EXISTS obs_silences (
    id VARCHAR(64) PRIMARY KEY,
    matchers JSONB NOT NULL DEFAULT '[]',
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_silences_ends_at ON obs_silences(ends_at);
CREATE INDEX idx_obs_silences_matchers ON obs_silences USING gin(matchers);

-- Escalation policies table
CREATE TABLE IF NOT EXISTS obs_escalation_policies (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    steps JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- Dashboard Tables
-- ============================================

-- Dashboards table
CREATE TABLE IF NOT EXISTS obs_dashboards (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id VARCHAR(64) NOT NULL,
    is_public BOOLEAN DEFAULT false,
    tags JSONB DEFAULT '[]',
    layout JSONB NOT NULL DEFAULT '{"rows": []}',
    variables JSONB DEFAULT '[]',
    time_range JSONB DEFAULT '{"from": "now-6h", "to": "now", "raw": {"from": "now-6h", "to": "now"}}',
    refresh_interval INTEGER DEFAULT 30,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_dashboards_owner ON obs_dashboards(owner_id);
CREATE INDEX idx_obs_dashboards_public ON obs_dashboards(is_public);
CREATE INDEX idx_obs_dashboards_tags ON obs_dashboards USING gin(tags);

-- Dashboard snapshots table
CREATE TABLE IF NOT EXISTS obs_dashboard_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    dashboard_id VARCHAR(64) REFERENCES obs_dashboards(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    key VARCHAR(64) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_dashboard_snapshots_key ON obs_dashboard_snapshots(key);
CREATE INDEX idx_obs_dashboard_snapshots_expires ON obs_dashboard_snapshots(expires_at);

-- Dashboard permissions table
CREATE TABLE IF NOT EXISTS obs_dashboard_permissions (
    id BIGSERIAL PRIMARY KEY,
    dashboard_id VARCHAR(64) NOT NULL REFERENCES obs_dashboards(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    team_id VARCHAR(64),
    permission VARCHAR(32) NOT NULL DEFAULT 'view',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_dashboard_user UNIQUE (dashboard_id, user_id),
    CONSTRAINT unique_dashboard_team UNIQUE (dashboard_id, team_id)
);

CREATE INDEX idx_obs_dashboard_permissions_dashboard ON obs_dashboard_permissions(dashboard_id);
CREATE INDEX idx_obs_dashboard_permissions_user ON obs_dashboard_permissions(user_id);
CREATE INDEX idx_obs_dashboard_permissions_team ON obs_dashboard_permissions(team_id);

-- ============================================
-- Service Level Objectives (SLO) Tables
-- ============================================

-- SLO definitions table
CREATE TABLE IF NOT EXISTS obs_slos (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    service VARCHAR(128) NOT NULL,
    sli_type VARCHAR(32) NOT NULL,
    sli_query TEXT NOT NULL,
    target_percentage DECIMAL(5,2) NOT NULL,
    window_days INTEGER DEFAULT 30,
    burn_rate_threshold DECIMAL(5,2) DEFAULT 14.4,
    enabled BOOLEAN DEFAULT true,
    labels JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_slos_service ON obs_slos(service);
CREATE INDEX idx_obs_slos_enabled ON obs_slos(enabled);

-- SLO error budget tracking
CREATE TABLE IF NOT EXISTS obs_slo_error_budgets (
    id BIGSERIAL PRIMARY KEY,
    slo_id VARCHAR(64) NOT NULL REFERENCES obs_slos(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    total_events BIGINT NOT NULL,
    good_events BIGINT NOT NULL,
    error_budget_remaining DECIMAL(7,4),
    burn_rate DECIMAL(7,4),
    calculated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obs_slo_error_budgets_slo ON obs_slo_error_budgets(slo_id);
CREATE INDEX idx_obs_slo_error_budgets_window ON obs_slo_error_budgets(window_start, window_end);

-- ============================================
-- Views and Aggregations
-- ============================================

-- Active alerts view
CREATE OR REPLACE VIEW obs_active_alerts AS
SELECT 
    a.*,
    r.name as rule_display_name,
    r.runbook
FROM obs_alerts a
LEFT JOIN obs_alert_rules r ON a.rule_id = r.id
WHERE a.status IN ('pending', 'firing', 'acknowledged');

-- Metrics summary view (last hour)
CREATE OR REPLACE VIEW obs_metrics_summary AS
SELECT 
    name,
    AVG(value) as avg_value,
    MIN(value) as min_value,
    MAX(value) as max_value,
    COUNT(*) as sample_count
FROM obs_metrics
WHERE recorded_at > NOW() - INTERVAL '1 hour'
GROUP BY name;

-- Service health view
CREATE OR REPLACE VIEW obs_service_health AS
SELECT 
    service_name,
    COUNT(*) as total_traces,
    COUNT(*) FILTER (WHERE status = 'ERROR') as error_traces,
    AVG(duration_ms) as avg_duration_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95_duration_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99_duration_ms
FROM obs_traces
WHERE start_time > NOW() - INTERVAL '1 hour'
GROUP BY service_name;

-- Log error summary view
CREATE OR REPLACE VIEW obs_log_error_summary AS
SELECT 
    service,
    level,
    DATE_TRUNC('hour', timestamp) as hour,
    COUNT(*) as count
FROM obs_logs
WHERE level IN ('error', 'fatal')
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY service, level, DATE_TRUNC('hour', timestamp);

-- ============================================
-- Functions
-- ============================================

-- Function to clean old metrics data
CREATE OR REPLACE FUNCTION obs_cleanup_old_metrics(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM obs_metrics
    WHERE recorded_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean old logs
CREATE OR REPLACE FUNCTION obs_cleanup_old_logs(retention_days INTEGER DEFAULT 14)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM obs_logs
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean old traces
CREATE OR REPLACE FUNCTION obs_cleanup_old_traces(retention_days INTEGER DEFAULT 7)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM obs_traces
    WHERE start_time < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate SLO error budget
CREATE OR REPLACE FUNCTION obs_calculate_error_budget(
    p_slo_id VARCHAR(64),
    p_window_start TIMESTAMPTZ,
    p_window_end TIMESTAMPTZ
)
RETURNS TABLE(
    total_events BIGINT,
    good_events BIGINT,
    error_budget_remaining DECIMAL,
    burn_rate DECIMAL
) AS $$
DECLARE
    v_slo RECORD;
    v_total BIGINT;
    v_good BIGINT;
    v_error_budget DECIMAL;
    v_burn DECIMAL;
BEGIN
    SELECT * INTO v_slo FROM obs_slos WHERE id = p_slo_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SLO not found: %', p_slo_id;
    END IF;
    
    -- Execute SLI query (simplified - would need dynamic SQL in real implementation)
    SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'OK')
    INTO v_total, v_good
    FROM obs_traces
    WHERE service_name = v_slo.service
      AND start_time BETWEEN p_window_start AND p_window_end;
    
    IF v_total > 0 THEN
        v_error_budget := 100.0 - (v_good::DECIMAL / v_total * 100.0);
        v_error_budget := (100.0 - v_slo.target_percentage) - v_error_budget;
        v_burn := (v_total - v_good)::DECIMAL / ((v_slo.window_days * 24 * 60) * (100.0 - v_slo.target_percentage) / 100.0);
    ELSE
        v_error_budget := 100.0 - v_slo.target_percentage;
        v_burn := 0;
    END IF;
    
    RETURN QUERY SELECT v_total, v_good, v_error_budget, v_burn;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Triggers
-- ============================================

-- Trigger to update trace statistics when spans are added
CREATE OR REPLACE FUNCTION obs_update_trace_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE obs_traces
    SET 
        span_count = (SELECT COUNT(*) FROM obs_spans WHERE trace_id = NEW.trace_id),
        error_count = (SELECT COUNT(*) FROM obs_spans WHERE trace_id = NEW.trace_id AND status = 'ERROR'),
        end_time = (SELECT MAX(end_time) FROM obs_spans WHERE trace_id = NEW.trace_id),
        duration_ms = EXTRACT(EPOCH FROM (
            (SELECT MAX(end_time) FROM obs_spans WHERE trace_id = NEW.trace_id) - 
            (SELECT MIN(start_time) FROM obs_spans WHERE trace_id = NEW.trace_id)
        )) * 1000
    WHERE id = NEW.trace_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_obs_span_stats
AFTER INSERT OR UPDATE ON obs_spans
FOR EACH ROW
EXECUTE FUNCTION obs_update_trace_stats();

-- Trigger to auto-resolve old firing alerts
CREATE OR REPLACE FUNCTION obs_auto_resolve_stale_alerts()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE obs_alerts
    SET 
        status = 'resolved',
        resolved_at = NOW()
    WHERE status = 'firing'
      AND fired_at < NOW() - INTERVAL '24 hours'
      AND resolved_at IS NULL;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Initial Data - Default Notification Channels
-- ============================================

INSERT INTO obs_notification_channels (id, name, type, config, enabled) VALUES
('channel_default_email', 'Default Email', 'email', '{"recipients": ["alerts@apexmail.ee"]}', true),
('channel_default_slack', 'Default Slack', 'slack', '{"channel": "#alerts"}', false)
ON CONFLICT (id) DO NOTHING;

-- ============================================
-- Initial Data - Default Alert Rules
-- ============================================

INSERT INTO obs_alert_rules (id, name, description, expression, duration, severity, notification_channels, runbook) VALUES
('rule_high_error_rate', 'High Error Rate', 'Error rate exceeds 5%', 'avg(apexmail_error_rate) > 0.05', 300, 'critical', '["channel_default_email"]', 'https://docs.apexmail.ee/runbooks/high-error-rate'),
('rule_high_latency', 'High Latency', 'P99 latency exceeds 5 seconds', 'histogram_quantile(0.99, apexmail_request_duration_bucket) > 5', 300, 'warning', '["channel_default_email"]', 'https://docs.apexmail.ee/runbooks/high-latency'),
('rule_low_delivery_rate', 'Low Delivery Rate', 'Email delivery rate below 95%', 'avg(apexmail_delivery_rate) < 0.95', 600, 'warning', '["channel_default_email"]', 'https://docs.apexmail.ee/runbooks/low-delivery'),
('rule_queue_backup', 'Queue Backup', 'Queue depth exceeds 10000', 'apexmail_queue_depth > 10000', 300, 'critical', '["channel_default_email"]', 'https://docs.apexmail.ee/runbooks/queue-backup')
ON CONFLICT (id) DO NOTHING;

-- ============================================
-- Initial Data - Default SLOs
-- ============================================

INSERT INTO obs_slos (id, name, description, service, sli_type, sli_query, target_percentage, window_days) VALUES
('slo_api_availability', 'API Availability', '99.9% availability for API requests', 'api', 'availability', 'sum(rate(apexmail_requests_total{status!~"5.."}[5m])) / sum(rate(apexmail_requests_total[5m]))', 99.9, 30),
('slo_email_delivery', 'Email Delivery', '99% of emails delivered within 5 minutes', 'mta', 'latency', 'histogram_quantile(0.99, rate(apexmail_delivery_latency_bucket[5m])) < 300', 99.0, 30),
('slo_webhook_delivery', 'Webhook Delivery', '99.5% webhook delivery success rate', 'webhooks', 'availability', 'sum(rate(apexmail_webhook_success_total[5m])) / sum(rate(apexmail_webhook_total[5m]))', 99.5, 30)
ON CONFLICT (id) DO NOTHING;

-- Comments for documentation
COMMENT ON TABLE obs_traces IS 'Distributed tracing data storage';
COMMENT ON TABLE obs_spans IS 'Individual spans within traces';
COMMENT ON TABLE obs_metrics IS 'Time series metrics data';
COMMENT ON TABLE obs_logs IS 'Centralized log storage';
COMMENT ON TABLE obs_alerts IS 'Alert instances and history';
COMMENT ON TABLE obs_alert_rules IS 'Alert rule definitions';
COMMENT ON TABLE obs_dashboards IS 'Dashboard definitions';
COMMENT ON TABLE obs_slos IS 'Service Level Objective definitions';
