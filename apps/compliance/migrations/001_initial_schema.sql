-- Compliance initial schema

-- Risk profiles table
CREATE TABLE IF NOT EXISTS risk_profiles (
    tenant_id VARCHAR(36) PRIMARY KEY,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    factors JSONB NOT NULL,
    limits JSONB NOT NULL,
    flags JSONB NOT NULL DEFAULT '[]',
    last_assessed_at TIMESTAMP NOT NULL,
    next_assessment_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    message_id VARCHAR(255) NOT NULL,
    scanned_at TIMESTAMP NOT NULL,
    results JSONB NOT NULL,
    overall_verdict VARCHAR(20) NOT NULL,
    actions JSONB NOT NULL,
    spam_detected BOOLEAN DEFAULT FALSE,
    phishing_detected BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_scan_results_tenant ON scan_results(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_message ON scan_results(message_id);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36),
    user_id VARCHAR(36),
    session_id VARCHAR(36),
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    outcome VARCHAR(20) NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMP NOT NULL,
    hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64),
    signature VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Audit logs archive
CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);

-- Audit webhooks
CREATE TABLE IF NOT EXISTS audit_webhooks (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    url TEXT NOT NULL,
    events JSONB NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Secrets table
CREATE TABLE IF NOT EXISTS secrets (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    encrypted_value TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    rotation_schedule JSONB,
    last_rotated_at TIMESTAMP,
    next_rotation_at TIMESTAMP,
    created_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_secrets_tenant ON secrets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_secrets_rotation ON secrets(next_rotation_at);

-- Secret versions history
CREATE TABLE IF NOT EXISTS secret_versions (
    id SERIAL PRIMARY KEY,
    secret_id VARCHAR(36) NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    encrypted_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(secret_id, version)
);

-- Secret access grants
CREATE TABLE IF NOT EXISTS secret_access (
    id VARCHAR(36) PRIMARY KEY,
    secret_id VARCHAR(36) NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id VARCHAR(36) NOT NULL,
    access_type VARCHAR(20) NOT NULL,
    granted_by VARCHAR(36) NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    UNIQUE(secret_id, user_id)
);

-- Secret access log
CREATE TABLE IF NOT EXISTS secret_access_log (
    id SERIAL PRIMARY KEY,
    secret_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Secrets archive
CREATE TABLE IF NOT EXISTS secrets_archive (LIKE secrets INCLUDING ALL);

-- Data subject requests
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    request_type VARCHAR(50) NOT NULL,
    email VARCHAR(255) NOT NULL,
    verification_token VARCHAR(64) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    status VARCHAR(50) NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    processed_at TIMESTAMP,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    result JSONB
);

CREATE INDEX IF NOT EXISTS idx_dsr_tenant ON data_subject_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dsr_email ON data_subject_requests(email);

-- Consent records
CREATE TABLE IF NOT EXISTS consent_records (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    subscriber_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    consent_type VARCHAR(50) NOT NULL,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMP,
    revoked_at TIMESTAMP,
    source VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    proof_document TEXT,
    expires_at TIMESTAMP,
    metadata JSONB DEFAULT '{}',
    UNIQUE(tenant_id, subscriber_id, consent_type)
);

CREATE INDEX IF NOT EXISTS idx_consent_tenant ON consent_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_consent_email ON consent_records(email);

-- Consent changelog
CREATE TABLE IF NOT EXISTS consent_changelog (
    id SERIAL PRIMARY KEY,
    consent_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    consent_type VARCHAR(50) NOT NULL,
    granted BOOLEAN NOT NULL,
    changed_at TIMESTAMP DEFAULT NOW()
);

-- Double opt-in tokens
CREATE TABLE IF NOT EXISTS double_optin_tokens (
    token VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    subscriber_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    consent_types JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP
);

-- GDPR exports
CREATE TABLE IF NOT EXISTS gdpr_exports (
    request_id VARCHAR(36) PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    data JSONB NOT NULL,
    access_token_hash VARCHAR(64),
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- GDPR deletion log
CREATE TABLE IF NOT EXISTS gdpr_deletion_log (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    records_deleted INTEGER NOT NULL,
    deleted_at TIMESTAMP DEFAULT NOW()
);

-- Processing objections
CREATE TABLE IF NOT EXISTS processing_objections (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    request_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Content policies
CREATE TABLE IF NOT EXISTS content_policies (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    rules JSONB NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Flag resolutions
CREATE TABLE IF NOT EXISTS flag_resolutions (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    flag_type VARCHAR(50) NOT NULL,
    resolution TEXT NOT NULL,
    resolved_at TIMESTAMP DEFAULT NOW()
);
