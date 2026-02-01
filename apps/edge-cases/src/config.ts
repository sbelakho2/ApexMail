/**
 * Edge Cases Configuration
 */

export interface AttachmentLimits {
  maxSingleAttachmentSize: number; // bytes
  maxTotalMessageSize: number;     // bytes
  maxAttachmentCount: number;
  blockedExtensions: string[];
  blockedMimeTypes: string[];
}

export interface RetryConfig {
  maxRetries: number;
  initialDelay: number;    // ms
  maxDelay: number;        // ms
  backoffMultiplier: number;
  greylistRetryDelay: number; // ms
}

export interface LoopDetectionConfig {
  maxHops: number;
  maxReceivedHeaders: number;
}

export interface AutoResponderConfig {
  patterns: string[];
  headerIndicators: string[];
  subjectPatterns: string[];
}

export interface ClamAVConfig {
  host: string;
  port: number;
  timeout: number;
  enabled: boolean;
}

export interface EdgeCasesConfig {
  attachments: AttachmentLimits;
  retry: RetryConfig;
  loopDetection: LoopDetectionConfig;
  autoResponder: AutoResponderConfig;
  clamav: ClamAVConfig;
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

export const config: EdgeCasesConfig = {
  attachments: {
    maxSingleAttachmentSize: parseInt(process.env.MAX_ATTACHMENT_SIZE || '26214400', 10), // 25MB
    maxTotalMessageSize: parseInt(process.env.MAX_MESSAGE_SIZE || '36700160', 10), // 35MB
    maxAttachmentCount: parseInt(process.env.MAX_ATTACHMENT_COUNT || '20', 10),
    blockedExtensions: (process.env.BLOCKED_EXTENSIONS || '.exe,.bat,.cmd,.com,.dll,.scr,.pif,.vbs,.js,.jar,.msi,.ps1,.sh').split(','),
    blockedMimeTypes: (process.env.BLOCKED_MIME_TYPES || 'application/x-msdownload,application/x-executable,application/x-dosexec').split(','),
  },
  retry: {
    maxRetries: parseInt(process.env.MAX_RETRIES || '3', 10),
    initialDelay: parseInt(process.env.INITIAL_RETRY_DELAY || '1000', 10),
    maxDelay: parseInt(process.env.MAX_RETRY_DELAY || '300000', 10), // 5 minutes
    backoffMultiplier: parseFloat(process.env.BACKOFF_MULTIPLIER || '2'),
    greylistRetryDelay: parseInt(process.env.GREYLIST_RETRY_DELAY || '300000', 10), // 5 minutes
  },
  loopDetection: {
    maxHops: parseInt(process.env.MAX_HOPS || '25', 10),
    maxReceivedHeaders: parseInt(process.env.MAX_RECEIVED_HEADERS || '30', 10),
  },
  autoResponder: {
    patterns: [
      'auto-reply',
      'autoresponder',
      'auto.reply',
      'out of office',
      'out-of-office',
      'on vacation',
      'away from office',
      'automatic reply',
    ],
    headerIndicators: [
      'X-Auto-Response-Suppress',
      'X-Autorespond',
      'X-Autoreply',
      'Auto-Submitted',
      'Precedence',
    ],
    subjectPatterns: [
      /^(re:|fw:|fwd:)?\s*out of office/i,
      /^(re:|fw:|fwd:)?\s*automatic reply/i,
      /^(re:|fw:|fwd:)?\s*auto:/i,
      /^(re:|fw:|fwd:)?\s*ooo:/i,
      /^(re:|fw:|fwd:)?\s*vacation/i,
      /^(re:|fw:|fwd:)?\s*away/i,
    ].map(r => r.source),
  },
  clamav: {
    host: process.env.CLAMAV_HOST || 'localhost',
    port: parseInt(process.env.CLAMAV_PORT || '3310', 10),
    timeout: parseInt(process.env.CLAMAV_TIMEOUT || '30000', 10),
    enabled: process.env.CLAMAV_ENABLED !== 'false',
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

// Unicode normalization form
export const UNICODE_NORMALIZATION = 'NFC';

// Email size estimation multiplier for base64 encoding
export const BASE64_OVERHEAD = 1.37;

// SMTPUTF8 extension identifier
export const SMTPUTF8_EXTENSION = 'SMTPUTF8';

// Calendar content types
export const CALENDAR_CONTENT_TYPES = [
  'text/calendar',
  'application/ics',
];

// Common greylist response codes
export const GREYLIST_CODES = [
  '450',
  '451',
  '452',
  '421',
];

// Auto-submitted header values
export const AUTO_SUBMITTED_VALUES = [
  'auto-generated',
  'auto-replied',
  'auto-notified',
];
