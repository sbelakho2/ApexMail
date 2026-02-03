/**
 * MTA Configuration
 */

export interface MTAConfig {
  nodeEnv: string;
  mtaId: string;
  
  database: {
    connectionString: string;
    maxConnections: number;
  };
  
  redis: {
    url: string;
    keyPrefix: string;
  };
  
  inbound: {
    enabled: boolean;
    host: string;
    port: number;
    securePort: number;
    hostname: string;
    maxMessageSize: number;
    maxRecipients: number;
    authRequired: boolean;
    tls: {
      enabled: boolean;
      keyPath?: string;
      certPath?: string;
    };
  };
  
  bounce: {
    enabled: boolean;
    host: string;
    port: number;
    hostname: string;
    verpDomain: string;
  };
  
  feedback: {
    enabled: boolean;
    host: string;
    port: number;
    hostname: string;
  };
  
  dkim: {
    selector: string;
    defaultKeyPath?: string;
  };
  
  spf: {
    strictMode: boolean;
  };
  
  dmarc: {
    reportEmail: string;
    reportDomain: string;
  };
  
  rateLimit: {
    enabled: boolean;
    maxConnectionsPerIP: number;
    maxMessagesPerConnection: number;
    maxRecipientsPerMessage: number;
  };
  
  emailAuth: {
    requireSPF: boolean;
    requireDKIM: boolean;
    enforceDMARC: boolean;
    allowSoftFail: boolean;
    trustedRelays: string[];
  };
  
  metrics: {
    enabled: boolean;
    port: number;
  };
  
  /** HTTP port for health check endpoints (Kubernetes liveness/readiness probes) */
  healthPort: number;
  
  gracefulShutdownTimeout: number;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parseNumber(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

export function loadConfig(): MTAConfig {
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  
  return {
    nodeEnv,
    mtaId: process.env.MTA_ID ?? `mta-${process.pid}`,
    
    database: {
      connectionString: requireEnv('DATABASE_URL'),
      maxConnections: parseNumber(process.env.DATABASE_MAX_CONNECTIONS, 10),
    },
    
    redis: {
      url: process.env.REDIS_URL ?? 'redis://localhost:6379',
      keyPrefix: process.env.REDIS_KEY_PREFIX ?? 'apexmail:',
    },
    
    inbound: {
      enabled: parseBoolean(process.env.INBOUND_ENABLED, true),
      host: process.env.INBOUND_HOST ?? '0.0.0.0',
      port: parseNumber(process.env.INBOUND_PORT, 25),
      securePort: parseNumber(process.env.INBOUND_SECURE_PORT, 465),
      hostname: process.env.INBOUND_HOSTNAME ?? 'mx.example.com',
      maxMessageSize: parseNumber(process.env.INBOUND_MAX_MESSAGE_SIZE, 25 * 1024 * 1024), // 25MB
      maxRecipients: parseNumber(process.env.INBOUND_MAX_RECIPIENTS, 100),
      authRequired: parseBoolean(process.env.INBOUND_AUTH_REQUIRED, false),
      tls: {
        enabled: parseBoolean(process.env.INBOUND_TLS_ENABLED, true),
        keyPath: process.env.INBOUND_TLS_KEY_PATH,
        certPath: process.env.INBOUND_TLS_CERT_PATH,
      },
    },
    
    bounce: {
      enabled: parseBoolean(process.env.BOUNCE_ENABLED, true),
      host: process.env.BOUNCE_HOST ?? '0.0.0.0',
      port: parseNumber(process.env.BOUNCE_PORT, 2525),
      hostname: process.env.BOUNCE_HOSTNAME ?? 'bounce.example.com',
      verpDomain: process.env.VERP_DOMAIN ?? 'bounce.example.com',
    },
    
    feedback: {
      enabled: parseBoolean(process.env.FEEDBACK_ENABLED, true),
      host: process.env.FEEDBACK_HOST ?? '0.0.0.0',
      port: parseNumber(process.env.FEEDBACK_PORT, 2526),
      hostname: process.env.FEEDBACK_HOSTNAME ?? 'feedback.example.com',
    },
    
    dkim: {
      selector: process.env.DKIM_SELECTOR ?? 'apexmail',
      defaultKeyPath: process.env.DKIM_DEFAULT_KEY_PATH,
    },
    
    spf: {
      strictMode: parseBoolean(process.env.SPF_STRICT_MODE, false),
    },
    
    dmarc: {
      reportEmail: process.env.DMARC_REPORT_EMAIL ?? 'dmarc@example.com',
      reportDomain: process.env.DMARC_REPORT_DOMAIN ?? 'example.com',
    },
    
    rateLimit: {
      enabled: parseBoolean(process.env.RATE_LIMIT_ENABLED, true),
      maxConnectionsPerIP: parseNumber(process.env.RATE_LIMIT_MAX_CONNECTIONS_PER_IP, 10),
      maxMessagesPerConnection: parseNumber(process.env.RATE_LIMIT_MAX_MESSAGES_PER_CONNECTION, 100),
      maxRecipientsPerMessage: parseNumber(process.env.RATE_LIMIT_MAX_RECIPIENTS_PER_MESSAGE, 100),
    },
    
    emailAuth: {
      requireSPF: parseBoolean(process.env.EMAIL_AUTH_REQUIRE_SPF, true),
      requireDKIM: parseBoolean(process.env.EMAIL_AUTH_REQUIRE_DKIM, true),
      enforceDMARC: parseBoolean(process.env.EMAIL_AUTH_ENFORCE_DMARC, true),
      allowSoftFail: parseBoolean(process.env.EMAIL_AUTH_ALLOW_SOFTFAIL, true),
      trustedRelays: (process.env.EMAIL_AUTH_TRUSTED_RELAYS ?? '').split(',').filter(Boolean),
    },
    
    metrics: {
      enabled: parseBoolean(process.env.METRICS_ENABLED, true),
      port: parseNumber(process.env.METRICS_PORT, 9091),
    },
    
    healthPort: parseNumber(process.env.HEALTH_PORT, 9092),
    
    gracefulShutdownTimeout: parseNumber(process.env.GRACEFUL_SHUTDOWN_TIMEOUT, 30000),
  };
}
