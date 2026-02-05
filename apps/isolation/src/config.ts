/**
 * Isolation Service Configuration
 */

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  maxConnections: number;
}

export interface RedisConfig {
  host: string;
  port: number;
  password: string | null;
  db: number;
}

export interface TenantConfig {
  maxWorkspacesPerOrg: number;
  maxUsersPerWorkspace: number;
  defaultQuota: QuotaConfig;
  isolationLevels: IsolationLevel[];
}

export interface QuotaConfig {
  emailsPerMonth: number;
  storageBytes: number;
  apiRequestsPerMinute: number;
  webhooksPerMonth: number;
  contactsLimit: number;
  templatesLimit: number;
  domainsLimit: number;
}

export interface SecurityConfig {
  encryptionKey: string;
  dataKeyRotationDays: number;
  auditRetentionDays: number;
  sessionTimeoutMinutes: number;
}

export enum IsolationLevel {
  SHARED = 'shared',
  DEDICATED_SCHEMA = 'dedicated_schema',
  DEDICATED_DATABASE = 'dedicated_database',
  DEDICATED_INSTANCE = 'dedicated_instance',
}

export interface Config {
  port: number;
  environment: string;
  database: DatabaseConfig;
  redis: RedisConfig;
  tenant: TenantConfig;
  security: SecurityConfig;
  cors: {
    origins: string[];
  };
}

function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key] || defaultValue;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export const config: Config = {
  port: parseInt(getEnv('PORT', '4500')),
  environment: getEnv('NODE_ENV', 'development'),

  database: {
    host: getEnv('DATABASE_HOST', 'localhost'),
    port: parseInt(getEnv('DATABASE_PORT', '5432')),
    database: getEnv('DATABASE_NAME', 'apexmail_isolation'),
    user: getEnv('DATABASE_USER', 'postgres'),
    password: getEnv('DATABASE_PASSWORD', ''),
    maxConnections: parseInt(getEnv('DATABASE_MAX_CONNECTIONS', '20')),
  },

  redis: {
    host: getEnv('REDIS_HOST', 'localhost'),
    port: parseInt(getEnv('REDIS_PORT', '6379')),
    password: process.env.REDIS_PASSWORD || null,
    db: parseInt(getEnv('REDIS_DB', '0')),
  },

  tenant: {
    maxWorkspacesPerOrg: parseInt(getEnv('MAX_WORKSPACES_PER_ORG', '100')),
    maxUsersPerWorkspace: parseInt(getEnv('MAX_USERS_PER_WORKSPACE', '500')),
    defaultQuota: {
      emailsPerMonth: parseInt(getEnv('DEFAULT_EMAILS_PER_MONTH', '10000')),
      storageBytes: parseInt(getEnv('DEFAULT_STORAGE_BYTES', '1073741824')), // 1GB
      apiRequestsPerMinute: parseInt(getEnv('DEFAULT_API_REQUESTS_PER_MINUTE', '1000')),
      webhooksPerMonth: parseInt(getEnv('DEFAULT_WEBHOOKS_PER_MONTH', '100000')),
      contactsLimit: parseInt(getEnv('DEFAULT_CONTACTS_LIMIT', '10000')),
      templatesLimit: parseInt(getEnv('DEFAULT_TEMPLATES_LIMIT', '100')),
      domainsLimit: parseInt(getEnv('DEFAULT_DOMAINS_LIMIT', '10')),
    },
    isolationLevels: [
      IsolationLevel.SHARED,
      IsolationLevel.DEDICATED_SCHEMA,
      IsolationLevel.DEDICATED_DATABASE,
    ],
  },

  security: {
    encryptionKey: (() => {
      const key = getEnv('TENANT_ENCRYPTION_KEY', 'dev-encryption-key-32chars!!');
      if (key === 'dev-encryption-key-32chars!!' && process.env.NODE_ENV === 'production') {
        throw new Error('TENANT_ENCRYPTION_KEY must be set in production');
      }
      return key;
    })(),
    dataKeyRotationDays: parseInt(getEnv('DATA_KEY_ROTATION_DAYS', '90')),
    auditRetentionDays: parseInt(getEnv('AUDIT_RETENTION_DAYS', '365')),
    // SOC2-001 FIX: Changed from 60 to 30 minutes for SOC2 compliance
    sessionTimeoutMinutes: parseInt(getEnv('SESSION_TIMEOUT_MINUTES', '30')),
  },

  cors: {
    origins: getEnv('CORS_ORIGINS', '*').split(','),
  },
};
