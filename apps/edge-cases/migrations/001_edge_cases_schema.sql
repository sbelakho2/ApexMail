-- Edge Cases Schema Migration
-- Version: 001
-- Description: Tables for edge case handling (EAI, attachments, calendar, delivery)

BEGIN;

-- Enable UUID extension if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==================== Domain Capabilities ====================

CREATE TABLE edge_domain_capabilities (
    domain VARCHAR(255) PRIMARY KEY,
    supports_smtputf8 BOOLEAN NOT NULL DEFAULT false,
    supports_starttls BOOLEAN NOT NULL DEFAULT true,
    supports_8bitmime BOOLEAN NOT NULL DEFAULT true,
    supports_pipelining BOOLEAN NOT NULL DEFAULT true,
    max_message_size INTEGER,
    primary_mx VARCHAR(255),
    mx_count INTEGER,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    check_count INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Domain capabilities indexes
CREATE INDEX idx_edge_domain_caps_checked ON edge_domain_capabilities(checked_at DESC);
CREATE INDEX idx_edge_domain_caps_smtputf8 ON edge_domain_capabilities(supports_smtputf8);

-- ==================== Attachment Scans ====================

CREATE TABLE edge_attachment_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    filename VARCHAR(500) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    file_size BIGINT,
    is_valid BOOLEAN NOT NULL,
    virus_scanned BOOLEAN NOT NULL DEFAULT false,
    virus_detected BOOLEAN NOT NULL DEFAULT false,
    virus_name VARCHAR(255),
    errors JSONB NOT NULL DEFAULT '[]',
    warnings JSONB NOT NULL DEFAULT '[]',
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attachment scan indexes
CREATE INDEX idx_edge_attachment_scans_message ON edge_attachment_scans(message_id);
CREATE INDEX idx_edge_attachment_scans_date ON edge_attachment_scans(scanned_at DESC);
CREATE INDEX idx_edge_attachment_scans_virus ON edge_attachment_scans(virus_detected) WHERE virus_detected = true;

-- ==================== Calendar Events ====================

CREATE TABLE edge_calendar_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    uid VARCHAR(500) NOT NULL,
    summary VARCHAR(1000) NOT NULL,
    organizer_email VARCHAR(255) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    location VARCHAR(1000),
    method VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    attendee_count INTEGER NOT NULL DEFAULT 0,
    is_recurring BOOLEAN NOT NULL DEFAULT false,
    recurrence_rule TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Calendar event indexes
CREATE INDEX idx_edge_calendar_events_message ON edge_calendar_events(message_id);
CREATE INDEX idx_edge_calendar_events_uid ON edge_calendar_events(uid);
CREATE INDEX idx_edge_calendar_events_organizer ON edge_calendar_events(organizer_email);
CREATE INDEX idx_edge_calendar_events_time ON edge_calendar_events(start_time, end_time);

-- ==================== Delivery Attempts ====================

CREATE TABLE edge_delivery_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    attempt_number INTEGER NOT NULL,
    mx_host VARCHAR(255) NOT NULL,
    mx_priority INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    response_message TEXT NOT NULL,
    response_type VARCHAR(50) NOT NULL,
    enhanced_status VARCHAR(20),
    is_greylist BOOLEAN NOT NULL DEFAULT false,
    attempt_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms INTEGER
);

-- Delivery attempt indexes
CREATE INDEX idx_edge_delivery_attempts_message ON edge_delivery_attempts(message_id);
CREATE INDEX idx_edge_delivery_attempts_mx ON edge_delivery_attempts(mx_host);
CREATE INDEX idx_edge_delivery_attempts_type ON edge_delivery_attempts(response_type);
CREATE INDEX idx_edge_delivery_attempts_greylist ON edge_delivery_attempts(is_greylist) WHERE is_greylist = true;
CREATE INDEX idx_edge_delivery_attempts_time ON edge_delivery_attempts(attempt_time DESC);

-- ==================== Auto-Responder Detections ====================

CREATE TABLE edge_autoresponder_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    from_address VARCHAR(255) NOT NULL,
    is_autoresponder BOOLEAN NOT NULL,
    autoresponder_type VARCHAR(50),
    confidence INTEGER NOT NULL,
    indicators JSONB NOT NULL DEFAULT '[]',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auto-responder indexes
CREATE INDEX idx_edge_autoresponder_message ON edge_autoresponder_detections(message_id);
CREATE INDEX idx_edge_autoresponder_from ON edge_autoresponder_detections(from_address);
CREATE INDEX idx_edge_autoresponder_type ON edge_autoresponder_detections(autoresponder_type);

-- ==================== Loop Detections ====================

CREATE TABLE edge_loop_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    hop_count INTEGER NOT NULL,
    max_hops INTEGER NOT NULL,
    is_loop BOOLEAN NOT NULL,
    loop_path JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Loop detection indexes
CREATE INDEX idx_edge_loop_detections_message ON edge_loop_detections(message_id);
CREATE INDEX idx_edge_loop_detections_loop ON edge_loop_detections(is_loop) WHERE is_loop = true;

-- ==================== Email Validation Results ====================

CREATE TABLE edge_email_validations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_address VARCHAR(320) NOT NULL,
    normalized_address VARCHAR(320) NOT NULL,
    is_valid BOOLEAN NOT NULL,
    requires_smtputf8 BOOLEAN NOT NULL DEFAULT false,
    has_mx BOOLEAN,
    errors JSONB NOT NULL DEFAULT '[]',
    warnings JSONB NOT NULL DEFAULT '[]',
    validated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Email validation indexes
CREATE INDEX idx_edge_email_validations_email ON edge_email_validations(email_address);
CREATE INDEX idx_edge_email_validations_valid ON edge_email_validations(is_valid);
CREATE INDEX idx_edge_email_validations_smtputf8 ON edge_email_validations(requires_smtputf8);

-- ==================== Greylist Tracking ====================

CREATE TABLE edge_greylist_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    triplet_key VARCHAR(500) NOT NULL UNIQUE, -- from_ip:from_email:to_email
    from_ip INET NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry_count INTEGER NOT NULL DEFAULT 0,
    passed BOOLEAN NOT NULL DEFAULT false,
    passed_at TIMESTAMPTZ
);

-- Greylist tracking indexes
CREATE INDEX idx_edge_greylist_triplet ON edge_greylist_tracking(triplet_key);
CREATE INDEX idx_edge_greylist_from_ip ON edge_greylist_tracking(from_ip);
CREATE INDEX idx_edge_greylist_passed ON edge_greylist_tracking(passed);

-- ==================== MX Resolution Cache ====================

CREATE TABLE edge_mx_cache (
    domain VARCHAR(255) PRIMARY KEY,
    mx_records JSONB NOT NULL DEFAULT '[]',
    ttl INTEGER,
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    resolution_time_ms INTEGER
);

-- MX cache indexes
CREATE INDEX idx_edge_mx_cache_expires ON edge_mx_cache(expires_at);

-- ==================== Functions ====================

-- Function to update domain capability timestamps
CREATE OR REPLACE FUNCTION edge_update_domain_capability()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.check_count = OLD.check_count + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to clean old delivery attempts
CREATE OR REPLACE FUNCTION edge_clean_old_delivery_attempts(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM edge_delivery_attempts
        WHERE attempt_time < NOW() - (retention_days || ' days')::INTERVAL
        RETURNING 1
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get delivery statistics by MX
CREATE OR REPLACE FUNCTION edge_get_mx_stats(p_mx_host VARCHAR, p_days INTEGER DEFAULT 7)
RETURNS TABLE (
    mx_host VARCHAR,
    total_attempts BIGINT,
    success_count BIGINT,
    greylist_count BIGINT,
    temp_failure_count BIGINT,
    perm_failure_count BIGINT,
    avg_duration_ms NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.mx_host::VARCHAR,
        COUNT(*)::BIGINT as total_attempts,
        COUNT(*) FILTER (WHERE a.response_type = 'success')::BIGINT as success_count,
        COUNT(*) FILTER (WHERE a.is_greylist = true)::BIGINT as greylist_count,
        COUNT(*) FILTER (WHERE a.response_type = 'temporary_failure')::BIGINT as temp_failure_count,
        COUNT(*) FILTER (WHERE a.response_type = 'permanent_failure')::BIGINT as perm_failure_count,
        ROUND(AVG(a.duration_ms), 2) as avg_duration_ms
    FROM edge_delivery_attempts a
    WHERE a.mx_host = p_mx_host
    AND a.attempt_time >= NOW() - (p_days || ' days')::INTERVAL
    GROUP BY a.mx_host;
END;
$$ LANGUAGE plpgsql;

-- Function to check if triplet should pass greylist
CREATE OR REPLACE FUNCTION edge_check_greylist_pass(
    p_from_ip INET,
    p_from_email VARCHAR,
    p_to_email VARCHAR,
    p_min_delay_seconds INTEGER DEFAULT 300
)
RETURNS BOOLEAN AS $$
DECLARE
    v_record edge_greylist_tracking%ROWTYPE;
    v_triplet_key VARCHAR;
BEGIN
    v_triplet_key := p_from_ip::TEXT || ':' || p_from_email || ':' || p_to_email;
    
    SELECT * INTO v_record
    FROM edge_greylist_tracking
    WHERE triplet_key = v_triplet_key;
    
    IF NOT FOUND THEN
        -- First time seeing this triplet, create record
        INSERT INTO edge_greylist_tracking (triplet_key, from_ip, from_email, to_email)
        VALUES (v_triplet_key, p_from_ip, p_from_email, p_to_email);
        RETURN FALSE;
    END IF;
    
    IF v_record.passed THEN
        -- Already passed, update last_seen
        UPDATE edge_greylist_tracking
        SET last_seen = NOW(), retry_count = retry_count + 1
        WHERE triplet_key = v_triplet_key;
        RETURN TRUE;
    END IF;
    
    -- Check if enough time has passed
    IF v_record.first_seen + (p_min_delay_seconds || ' seconds')::INTERVAL <= NOW() THEN
        -- Mark as passed
        UPDATE edge_greylist_tracking
        SET passed = TRUE, passed_at = NOW(), last_seen = NOW(), retry_count = retry_count + 1
        WHERE triplet_key = v_triplet_key;
        RETURN TRUE;
    END IF;
    
    -- Update retry count
    UPDATE edge_greylist_tracking
    SET last_seen = NOW(), retry_count = retry_count + 1
    WHERE triplet_key = v_triplet_key;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- ==================== Triggers ====================

-- Domain capability update trigger
CREATE TRIGGER edge_domain_capability_update
    BEFORE UPDATE ON edge_domain_capabilities
    FOR EACH ROW
    EXECUTE FUNCTION edge_update_domain_capability();

-- ==================== Views ====================

-- Recent delivery failures view
CREATE VIEW edge_recent_delivery_failures AS
SELECT 
    message_id,
    mx_host,
    response_code,
    response_message,
    response_type,
    is_greylist,
    attempt_time
FROM edge_delivery_attempts
WHERE response_type IN ('temporary_failure', 'permanent_failure', 'greylist')
AND attempt_time >= NOW() - INTERVAL '24 hours'
ORDER BY attempt_time DESC;

-- Domain delivery stats view
CREATE VIEW edge_domain_delivery_stats AS
SELECT 
    SUBSTRING(mx_host FROM '@(.+)$') as domain,
    COUNT(*) as total_attempts,
    COUNT(*) FILTER (WHERE response_type = 'success') as success_count,
    COUNT(*) FILTER (WHERE is_greylist = true) as greylist_count,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE response_type = 'success') / NULLIF(COUNT(*), 0),
        2
    ) as success_rate
FROM edge_delivery_attempts
WHERE attempt_time >= NOW() - INTERVAL '7 days'
GROUP BY SUBSTRING(mx_host FROM '@(.+)$')
ORDER BY total_attempts DESC;

-- Virus detection summary view
CREATE VIEW edge_virus_detection_summary AS
SELECT 
    DATE_TRUNC('day', scanned_at) as scan_date,
    COUNT(*) as total_scanned,
    COUNT(*) FILTER (WHERE virus_detected = true) as viruses_found,
    array_agg(DISTINCT virus_name) FILTER (WHERE virus_name IS NOT NULL) as virus_names
FROM edge_attachment_scans
WHERE scanned_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', scanned_at)
ORDER BY scan_date DESC;

-- Auto-responder statistics view
CREATE VIEW edge_autoresponder_stats AS
SELECT 
    autoresponder_type,
    COUNT(*) as detection_count,
    ROUND(AVG(confidence), 1) as avg_confidence
FROM edge_autoresponder_detections
WHERE detected_at >= NOW() - INTERVAL '30 days'
GROUP BY autoresponder_type
ORDER BY detection_count DESC;

COMMIT;
