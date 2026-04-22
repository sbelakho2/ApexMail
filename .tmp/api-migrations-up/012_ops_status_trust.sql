-- -500-155:Status Page tables
-- -500-156:Trust Center tables

-- =============================================================================
-- STATUS PAGE (#155)
-- =============================================================================

CREATE TABLE IF NOT EXISTS status_page_components (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    status          VARCHAR(30) NOT NULL DEFAULT 'operational',
    group_id        VARCHAR(64),
    sort_order      INTEGER NOT NULL DEFAULT 0,
    visible         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS status_page_groups (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    status          VARCHAR(30) NOT NULL DEFAULT 'operational',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS status_page_incidents (
    id              VARCHAR(64) PRIMARY KEY,
    title           VARCHAR(500) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'investigating',
    impact          VARCHAR(30) NOT NULL DEFAULT 'none',
    affected_components TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS status_page_incident_updates (
    id              VARCHAR(64) PRIMARY KEY,
    incident_id     VARCHAR(64) NOT NULL REFERENCES status_page_incidents(id) ON DELETE CASCADE,
    status          VARCHAR(30) NOT NULL,
    body            TEXT NOT NULL,
    author          VARCHAR(200) NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_updates_incident ON status_page_incident_updates(incident_id);

CREATE TABLE IF NOT EXISTS status_page_maintenance (
    id              VARCHAR(64) PRIMARY KEY,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    scheduled_start TIMESTAMPTZ NOT NULL,
    scheduled_end   TIMESTAMPTZ NOT NULL,
    actual_start    TIMESTAMPTZ,
    actual_end      TIMESTAMPTZ,
    status          VARCHAR(30) NOT NULL DEFAULT 'scheduled',
    affected_components TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS status_page_subscribers (
    id              VARCHAR(64) PRIMARY KEY,
    email           VARCHAR(300) NOT NULL,
    components      TEXT[] NOT NULL DEFAULT '{}',
    confirmed       BOOLEAN NOT NULL DEFAULT false,
    subscribed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_subscribers_email ON status_page_subscribers(email);

-- =============================================================================
-- TRUST CENTER (#156)
-- =============================================================================

CREATE TABLE IF NOT EXISTS trust_certifications (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    issuer          VARCHAR(200),
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    status          VARCHAR(30) NOT NULL DEFAULT 'valid',
    document_url    VARCHAR(500),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_documents (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    type            VARCHAR(50) NOT NULL,
    url             VARCHAR(500) NOT NULL,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version         VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS trust_security_controls (
    id              VARCHAR(64) PRIMARY KEY,
    category        VARCHAR(100) NOT NULL,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    status          VARCHAR(30) NOT NULL DEFAULT 'implemented',
    evidence        TEXT,
    last_verified   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_security_controls_category ON trust_security_controls(category);

CREATE TABLE IF NOT EXISTS trust_sub_processors (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    purpose         TEXT,
    location        VARCHAR(200),
    data_categories TEXT[] NOT NULL DEFAULT '{}',
    website         VARCHAR(500),
    dpa_url         VARCHAR(500),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_data_practices (
    id              VARCHAR(64) PRIMARY KEY,
    category        VARCHAR(100) NOT NULL,
    practice        VARCHAR(200) NOT NULL,
    description     TEXT
);

CREATE TABLE IF NOT EXISTS trust_faq (
    id              SERIAL PRIMARY KEY,
    category        VARCHAR(100) NOT NULL,
    question        TEXT NOT NULL,
    answer          TEXT NOT NULL,
    sort_order      INTEGER NOT NULL DEFAULT 0
);
