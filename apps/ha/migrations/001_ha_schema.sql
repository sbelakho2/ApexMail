-- HA Service Database Schema
-- High Availability and Disaster Recovery tables

-- ===== Backup Tables =====

CREATE TABLE IF NOT EXISTS ha_backups (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL CHECK (type IN ('full', 'incremental', 'wal', 'snapshot')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'verified', 'expired')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    size_bytes BIGINT DEFAULT 0,
    compressed_size_bytes BIGINT DEFAULT 0,
    checksum VARCHAR(128),
    location TEXT,
    encryption_key_id VARCHAR(255),
    base_backup_id VARCHAR(255) REFERENCES ha_backups(id),
    wal_start VARCHAR(50),
    wal_end VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_backups_type ON ha_backups(type);
CREATE INDEX idx_ha_backups_status ON ha_backups(status);
CREATE INDEX idx_ha_backups_completed_at ON ha_backups(completed_at);
CREATE INDEX idx_ha_backups_base_backup_id ON ha_backups(base_backup_id);

-- ===== Failover Tables =====

CREATE TABLE IF NOT EXISTS ha_failover_events (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL CHECK (type IN ('automatic', 'manual', 'scheduled')),
    state VARCHAR(50) NOT NULL,
    source_host VARCHAR(255),
    target_host VARCHAR(255),
    reason TEXT,
    initiated_by VARCHAR(255),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    success BOOLEAN,
    error_message TEXT,
    metrics JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_failover_events_type ON ha_failover_events(type);
CREATE INDEX idx_ha_failover_events_state ON ha_failover_events(state);
CREATE INDEX idx_ha_failover_events_started_at ON ha_failover_events(started_at);

-- ===== Replication Tables =====

CREATE TABLE IF NOT EXISTS ha_replication_slots (
    slot_name VARCHAR(255) PRIMARY KEY,
    slot_type VARCHAR(50) NOT NULL CHECK (slot_type IN ('physical', 'logical')),
    database_name VARCHAR(255),
    plugin VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT FALSE,
    restart_lsn VARCHAR(50),
    confirmed_flush_lsn VARCHAR(50),
    wal_status VARCHAR(50),
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS ha_replication_lag_history (
    id BIGSERIAL PRIMARY KEY,
    replica_id VARCHAR(255) NOT NULL,
    lag_bytes BIGINT,
    lag_ms DOUBLE PRECISION,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_replication_lag_replica_id ON ha_replication_lag_history(replica_id);
CREATE INDEX idx_ha_replication_lag_recorded_at ON ha_replication_lag_history(recorded_at);

-- ===== Multi-Region Tables =====

CREATE TABLE IF NOT EXISTS ha_regions (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    endpoint TEXT NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('primary', 'secondary', 'standby', 'observer')),
    status VARCHAR(50) NOT NULL DEFAULT 'healthy' CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'maintenance', 'offline')),
    weight INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ha_region_status_history (
    id BIGSERIAL PRIMARY KEY,
    region_id VARCHAR(100) NOT NULL REFERENCES ha_regions(id),
    status VARCHAR(50) NOT NULL,
    previous_status VARCHAR(50),
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_region_status_history_region_id ON ha_region_status_history(region_id);
CREATE INDEX idx_ha_region_status_history_changed_at ON ha_region_status_history(changed_at);

CREATE TABLE IF NOT EXISTS ha_region_role_history (
    id BIGSERIAL PRIMARY KEY,
    region_id VARCHAR(100) NOT NULL REFERENCES ha_regions(id),
    role VARCHAR(50) NOT NULL,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_region_role_history_region_id ON ha_region_role_history(region_id);

CREATE TABLE IF NOT EXISTS ha_region_failovers (
    id BIGSERIAL PRIMARY KEY,
    source_region VARCHAR(100) NOT NULL,
    target_region VARCHAR(100) NOT NULL,
    reason TEXT,
    initiated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    success BOOLEAN,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_ha_region_failovers_initiated_at ON ha_region_failovers(initiated_at);

CREATE TABLE IF NOT EXISTS ha_geo_routing_rules (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    source_countries JSONB DEFAULT '[]',
    source_continent VARCHAR(50),
    target_region VARCHAR(100) NOT NULL REFERENCES ha_regions(id),
    priority INTEGER DEFAULT 100,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_geo_routing_rules_enabled ON ha_geo_routing_rules(enabled);
CREATE INDEX idx_ha_geo_routing_rules_priority ON ha_geo_routing_rules(priority);

CREATE TABLE IF NOT EXISTS ha_request_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(255),
    region VARCHAR(100) NOT NULL,
    endpoint TEXT,
    method VARCHAR(10),
    status_code INTEGER,
    latency_ms INTEGER,
    client_ip INET,
    country VARCHAR(10),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_request_logs_region ON ha_request_logs(region);
CREATE INDEX idx_ha_request_logs_created_at ON ha_request_logs(created_at);

-- Partition by time for large tables
-- Note: In production, use native PostgreSQL partitioning

-- ===== Chaos Engineering Tables =====

CREATE TABLE IF NOT EXISTS ha_chaos_experiments (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN (
        'latency', 'failure', 'resource_exhaustion', 'network_partition',
        'dns_failure', 'disk_full', 'memory_pressure', 'cpu_stress'
    )),
    config JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'aborted', 'failed'
    )),
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    started_by VARCHAR(255),
    results JSONB,
    abort_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_chaos_experiments_status ON ha_chaos_experiments(status);
CREATE INDEX idx_ha_chaos_experiments_type ON ha_chaos_experiments(type);
CREATE INDEX idx_ha_chaos_experiments_created_at ON ha_chaos_experiments(created_at);

-- ===== Health Check Tables =====

CREATE TABLE IF NOT EXISTS ha_health_checks (
    id BIGSERIAL PRIMARY KEY,
    component VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('healthy', 'degraded', 'unhealthy')),
    latency_ms INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_health_checks_component ON ha_health_checks(component);
CREATE INDEX idx_ha_health_checks_status ON ha_health_checks(status);
CREATE INDEX idx_ha_health_checks_checked_at ON ha_health_checks(checked_at);

-- ===== Service Metrics Tables =====

CREATE TABLE IF NOT EXISTS ha_service_metrics (
    id BIGSERIAL PRIMARY KEY,
    service VARCHAR(100) NOT NULL,
    endpoint TEXT,
    request_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    error_rate DOUBLE PRECISION DEFAULT 0,
    latency_ms INTEGER,
    availability DOUBLE PRECISION DEFAULT 100,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_service_metrics_service ON ha_service_metrics(service);
CREATE INDEX idx_ha_service_metrics_recorded_at ON ha_service_metrics(recorded_at);

-- ===== Circuit Breaker Tables =====

CREATE TABLE IF NOT EXISTS ha_circuit_breaker_events (
    id BIGSERIAL PRIMARY KEY,
    circuit_name VARCHAR(255) NOT NULL,
    old_state VARCHAR(50),
    new_state VARCHAR(50) NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_circuit_breaker_events_circuit_name ON ha_circuit_breaker_events(circuit_name);
CREATE INDEX idx_ha_circuit_breaker_events_created_at ON ha_circuit_breaker_events(created_at);

-- ===== Alert Tables =====

CREATE TABLE IF NOT EXISTS ha_alerts (
    id BIGSERIAL PRIMARY KEY,
    severity VARCHAR(50) NOT NULL CHECK (severity IN ('info', 'warning', 'critical', 'emergency')),
    component VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_alerts_severity ON ha_alerts(severity);
CREATE INDEX idx_ha_alerts_component ON ha_alerts(component);
CREATE INDEX idx_ha_alerts_acknowledged ON ha_alerts(acknowledged);
CREATE INDEX idx_ha_alerts_resolved ON ha_alerts(resolved);
CREATE INDEX idx_ha_alerts_created_at ON ha_alerts(created_at);

-- ===== Scheduled Tasks Tables =====

CREATE TABLE IF NOT EXISTS ha_scheduled_tasks (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    task_type VARCHAR(100) NOT NULL,
    cron_expression VARCHAR(100),
    next_run TIMESTAMPTZ,
    last_run TIMESTAMPTZ,
    last_status VARCHAR(50),
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ha_scheduled_tasks_enabled ON ha_scheduled_tasks(enabled);
CREATE INDEX idx_ha_scheduled_tasks_next_run ON ha_scheduled_tasks(next_run);

-- ===== Functions and Triggers =====

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_ha_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to tables with updated_at
CREATE TRIGGER trigger_ha_backups_updated_at
    BEFORE UPDATE ON ha_backups
    FOR EACH ROW EXECUTE FUNCTION update_ha_updated_at();

CREATE TRIGGER trigger_ha_regions_updated_at
    BEFORE UPDATE ON ha_regions
    FOR EACH ROW EXECUTE FUNCTION update_ha_updated_at();

CREATE TRIGGER trigger_ha_geo_routing_rules_updated_at
    BEFORE UPDATE ON ha_geo_routing_rules
    FOR EACH ROW EXECUTE FUNCTION update_ha_updated_at();

CREATE TRIGGER trigger_ha_scheduled_tasks_updated_at
    BEFORE UPDATE ON ha_scheduled_tasks
    FOR EACH ROW EXECUTE FUNCTION update_ha_updated_at();

-- ===== Initial Data =====

-- Insert default regions
INSERT INTO ha_regions (id, name, endpoint, role, status) VALUES
    ('us-east-1', 'US East (N. Virginia)', 'https://us-east-1.ha.apexmail.ee', 'primary', 'healthy'),
    ('us-west-2', 'US West (Oregon)', 'https://us-west-2.ha.apexmail.ee', 'secondary', 'healthy'),
    ('eu-west-1', 'EU (Ireland)', 'https://eu-west-1.ha.apexmail.ee', 'secondary', 'healthy'),
    ('ap-northeast-1', 'Asia Pacific (Tokyo)', 'https://ap-northeast-1.ha.apexmail.ee', 'standby', 'healthy')
ON CONFLICT (id) DO NOTHING;

-- Insert default geo-routing rules
INSERT INTO ha_geo_routing_rules (id, name, source_countries, source_continent, target_region, priority, enabled) VALUES
    ('geo_us', 'US Traffic', '["US", "CA", "MX"]', 'NA', 'us-east-1', 10, true),
    ('geo_eu', 'EU Traffic', '["GB", "DE", "FR", "IT", "ES", "NL", "BE", "PL", "SE", "AT", "CH"]', 'EU', 'eu-west-1', 10, true),
    ('geo_apac', 'APAC Traffic', '["JP", "KR", "AU", "SG", "HK", "TW"]', 'AS', 'ap-northeast-1', 10, true)
ON CONFLICT (id) DO NOTHING;

-- Insert default scheduled tasks
INSERT INTO ha_scheduled_tasks (id, name, task_type, cron_expression, enabled, config) VALUES
    ('full_backup', 'Full Database Backup', 'backup', '0 0 * * 0', true, '{"type": "full"}'),
    ('incremental_backup', 'Incremental Backup', 'backup', '0 0 * * *', true, '{"type": "incremental"}'),
    ('retention_cleanup', 'Backup Retention Cleanup', 'maintenance', '0 3 * * *', true, '{}'),
    ('health_check_report', 'Health Check Report', 'report', '*/5 * * * *', true, '{}')
ON CONFLICT (id) DO NOTHING;

-- ===== Views =====

-- Current system health view
CREATE OR REPLACE VIEW ha_current_health AS
SELECT 
    component,
    status,
    latency_ms,
    error_message,
    checked_at
FROM ha_health_checks hc1
WHERE checked_at = (
    SELECT MAX(checked_at) 
    FROM ha_health_checks hc2 
    WHERE hc2.component = hc1.component
);

-- Active alerts view
CREATE OR REPLACE VIEW ha_active_alerts AS
SELECT *
FROM ha_alerts
WHERE resolved = FALSE
ORDER BY 
    CASE severity 
        WHEN 'emergency' THEN 1 
        WHEN 'critical' THEN 2 
        WHEN 'warning' THEN 3 
        ELSE 4 
    END,
    created_at DESC;

-- Region overview view
CREATE OR REPLACE VIEW ha_region_overview AS
SELECT 
    r.id,
    r.name,
    r.endpoint,
    r.role,
    r.status,
    r.weight,
    (SELECT COUNT(*) FROM ha_request_logs rl 
     WHERE rl.region = r.id 
     AND rl.created_at > NOW() - INTERVAL '1 hour') as requests_last_hour,
    (SELECT AVG(latency_ms) FROM ha_request_logs rl 
     WHERE rl.region = r.id 
     AND rl.created_at > NOW() - INTERVAL '1 hour') as avg_latency_last_hour
FROM ha_regions r;

-- Backup summary view
CREATE OR REPLACE VIEW ha_backup_summary AS
SELECT 
    type,
    status,
    COUNT(*) as count,
    SUM(compressed_size_bytes) as total_size_bytes,
    MAX(completed_at) as last_completed
FROM ha_backups
GROUP BY type, status;

COMMENT ON TABLE ha_backups IS 'Database backup records';
COMMENT ON TABLE ha_failover_events IS 'Failover event history';
COMMENT ON TABLE ha_regions IS 'Multi-region configuration';
COMMENT ON TABLE ha_chaos_experiments IS 'Chaos engineering experiments';
COMMENT ON TABLE ha_health_checks IS 'Component health check results';
COMMENT ON TABLE ha_alerts IS 'System alerts and notifications';
