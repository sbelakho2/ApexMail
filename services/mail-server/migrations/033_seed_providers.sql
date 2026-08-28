-- Seed providers for inbox placement testing
CREATE TABLE IF NOT EXISTS seed_providers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    inbox_types TEXT[] NOT NULL DEFAULT '{"inbox","promotions","spam"}',
    icon_url    VARCHAR(512),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed known providers
INSERT INTO seed_providers (name, display_name, inbox_types) VALUES
    ('gmail', 'Gmail', '{inbox,promotions,spam}'),
    ('outlook', 'Outlook.com', '{inbox,spam}'),
    ('yahoo', 'Yahoo Mail', '{inbox,spam}'),
    ('icloud', 'iCloud Mail', '{inbox,spam}'),
    ('aol', 'AOL Mail', '{inbox,spam}'),
    ('zoho', 'Zoho Mail', '{inbox,spam}')
ON CONFLICT (name) DO NOTHING;
