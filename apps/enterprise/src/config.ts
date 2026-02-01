/**
 * Enterprise Configuration
 */

export interface SSOConfig {
  saml: {
    enabled: boolean;
    entityId: string;
    assertionConsumerServiceUrl: string;
    singleLogoutServiceUrl: string;
    certificate: string;
    privateKey: string;
  };
  oidc: {
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    issuer: string;
    redirectUri: string;
    scopes: string[];
  };
}

export interface WhiteLabelConfig {
  enabled: boolean;
  customDomainPrefix: string;
  defaultBranding: {
    logoUrl: string;
    primaryColor: string;
    companyName: string;
  };
}

export interface SubAccountConfig {
  maxSubAccounts: number;
  inheritParentSettings: boolean;
  volumeAllocationMode: 'fixed' | 'shared' | 'burst';
}

export interface ComplianceConfig {
  hipaaEnabled: boolean;
  zeroRetentionEnabled: boolean;
  dataResidencyRegions: string[];
  auditRetentionDays: number;
}

export interface LogStreamConfig {
  bufferSize: number;
  flushInterval: number;
  compressionEnabled: boolean;
  maxRetries: number;
}

export interface EnterpriseConfig {
  sso: SSOConfig;
  whiteLabel: WhiteLabelConfig;
  subAccounts: SubAccountConfig;
  compliance: ComplianceConfig;
  logStream: LogStreamConfig;
  database: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    ssl: boolean;
  };
  redis: {
    host: string;
    port: number;
    password?: string;
    db: number;
  };
  cors: {
    origins: string[];
  };
}

export const config: EnterpriseConfig = {
  sso: {
    saml: {
      enabled: process.env.SAML_ENABLED === 'true',
      entityId: process.env.SAML_ENTITY_ID || 'https://apexmail.ee',
      assertionConsumerServiceUrl: process.env.SAML_ACS_URL || 'https://apexmail.ee/api/v1/sso/saml/acs',
      singleLogoutServiceUrl: process.env.SAML_SLO_URL || 'https://apexmail.ee/api/v1/sso/saml/slo',
      certificate: process.env.SAML_CERTIFICATE || '',
      privateKey: process.env.SAML_PRIVATE_KEY || '',
    },
    oidc: {
      enabled: process.env.OIDC_ENABLED === 'true',
      clientId: process.env.OIDC_CLIENT_ID || '',
      clientSecret: process.env.OIDC_CLIENT_SECRET || '',
      issuer: process.env.OIDC_ISSUER || '',
      redirectUri: process.env.OIDC_REDIRECT_URI || 'https://apexmail.ee/api/v1/sso/oidc/callback',
      scopes: (process.env.OIDC_SCOPES || 'openid,profile,email').split(','),
    },
  },
  whiteLabel: {
    enabled: process.env.WHITE_LABEL_ENABLED === 'true',
    customDomainPrefix: process.env.CUSTOM_DOMAIN_PREFIX || 'mail',
    defaultBranding: {
      logoUrl: process.env.DEFAULT_LOGO_URL || '/logo.svg',
      primaryColor: process.env.DEFAULT_PRIMARY_COLOR || '#0066FF',
      companyName: process.env.DEFAULT_COMPANY_NAME || 'ApexMail',
    },
  },
  subAccounts: {
    maxSubAccounts: parseInt(process.env.MAX_SUB_ACCOUNTS || '100', 10),
    inheritParentSettings: process.env.INHERIT_PARENT_SETTINGS !== 'false',
    volumeAllocationMode: (process.env.VOLUME_ALLOCATION_MODE || 'shared') as SubAccountConfig['volumeAllocationMode'],
  },
  compliance: {
    hipaaEnabled: process.env.HIPAA_ENABLED === 'true',
    zeroRetentionEnabled: process.env.ZERO_RETENTION_ENABLED === 'true',
    dataResidencyRegions: (process.env.DATA_RESIDENCY_REGIONS || 'eu-west-1,us-east-1').split(','),
    auditRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '2555', 10), // 7 years default
  },
  logStream: {
    bufferSize: parseInt(process.env.LOG_STREAM_BUFFER_SIZE || '1000', 10),
    flushInterval: parseInt(process.env.LOG_STREAM_FLUSH_INTERVAL || '60000', 10),
    compressionEnabled: process.env.LOG_STREAM_COMPRESSION !== 'false',
    maxRetries: parseInt(process.env.LOG_STREAM_MAX_RETRIES || '3', 10),
  },
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'apexmail',
    user: process.env.DB_USER || 'apexmail',
    password: process.env.DB_PASSWORD || '',
    ssl: process.env.DB_SSL === 'true',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0', 10),
  },
  cors: {
    origins: (process.env.CORS_ORIGINS || '*').split(','),
  },
};

// Enterprise plan tiers
export enum EnterprisePlan {
  SCALE = 'scale',
  ENTERPRISE = 'enterprise',
  PRIVATE = 'private',
}

// SSO provider types
export enum SSOProvider {
  SAML = 'saml',
  OIDC = 'oidc',
  OKTA = 'okta',
  AZURE_AD = 'azure_ad',
  GOOGLE = 'google',
}

// Template approval status
export enum TemplateApprovalStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  DRAFT = 'draft',
}

// Support ticket priority
export enum TicketPriority {
  P1 = 'p1', // Critical - 1hr response, 4hr resolution
  P2 = 'p2', // High - 4hr response, 24hr resolution
  P3 = 'p3', // Normal - 24hr response, 72hr resolution
  P4 = 'p4', // Low - 72hr response, 1 week resolution
}
