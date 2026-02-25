/**
 * Logger Wrapper - Thin Interface over Pino
 * 
 * Provides structured logging with:
 * - Request correlation IDs
 * - Automatic context propagation
 * - Sensitive data redaction
 * - JSON and pretty output modes
 */

import { pino as createPino, type Logger as PinoLogger, type LoggerOptions, type Level } from 'pino';

export interface LogContext {
  requestId?: string;
  tenantId?: string;
  userId?: string;
  traceId?: string;
  spanId?: string;
  [key: string]: unknown;
}

export interface Logger {
  trace(msg: string, context?: LogContext): void;
  debug(msg: string, context?: LogContext): void;
  info(msg: string, context?: LogContext): void;
  warn(msg: string, context?: LogContext): void;
  error(msg: string, context?: LogContext): void;
  fatal(msg: string, context?: LogContext): void;
  child(context: LogContext): Logger;
  flush(): Promise<void>;
}

// Paths to redact from logs (sensitive data protection)
// AUDIT-002 FIX: Extended list to cover more sensitive fields
const REDACT_PATHS = [
  // Direct matches
  'password',
  'apiKey',
  'api_key',
  'apikey',
  'secret',
  'token',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'idToken',
  'id_token',
  'jwt',
  'sessionId',
  'session_id',
  'authorization',
  'cookie',
  'creditCard',
  'credit_card',
  'cardNumber',
  'card_number',
  'cvv',
  'cvc',
  'ssn',
  'socialSecurity',
  'privateKey',
  'private_key',
  'encryptionKey',
  'encryption_key',
  'signingKey',
  'signing_key',
  // Nested paths with wildcard
  '*.password',
  '*.apiKey',
  '*.api_key',
  '*.apikey',
  '*.secret',
  '*.token',
  '*.accessToken',
  '*.access_token',
  '*.refreshToken',
  '*.refresh_token',
  '*.jwt',
  '*.privateKey',
  '*.private_key',
  '*.encryptionKey',
  '*.encryption_key',
  // HTTP header paths (use bracket notation for hyphenated keys)
  'headers.authorization',
  'headers.cookie',
  'headers["x-api-key"]',
  'headers["x-auth-token"]',
  // Request body paths
  'body.password',
  'body.api_key',
  'body.apiKey',
  'body.secret',
  'body.token',
  'body.creditCard',
  'body.cardNumber',
  // Database/connection string paths
  '*.connectionString',
  '*.databaseUrl',
  '*.database_url',
  '*.redisUrl',
  '*.redis_url',
];

class PinoLoggerWrapper implements Logger {
  private readonly pino: PinoLogger;

  constructor(options: LoggerOptions = {}, pinoInstance?: PinoLogger) {
    if (pinoInstance) {
      this.pino = pinoInstance;
      return;
    }

    const nodeEnv = process.env['NODE_ENV'];
    const isPretty = nodeEnv !== 'production' && nodeEnv !== 'test';
    
    this.pino = createPino({
      level: process.env['LOG_LEVEL'] ?? (nodeEnv === 'test' ? 'silent' : 'info'),
      redact: {
        paths: REDACT_PATHS,
        censor: '[REDACTED]',
      },
      formatters: {
        level: (label: string) => ({ level: label }),
        bindings: (bindings: Record<string, unknown>) => ({
          pid: bindings['pid'],
          host: bindings['hostname'],
          service: process.env['SERVICE_NAME'] ?? 'apexmail',
        }),
      },
      transport: isPretty
        ? {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'SYS:standard',
              ignore: 'pid,hostname',
            },
          }
        : undefined,
      ...options,
    });
  }

  private log(level: Level, msg: string, context?: LogContext): void {
    if (context) {
      (this.pino[level] as (obj: unknown, msg: string) => void)(context, msg);
    } else {
      (this.pino[level] as (msg: string) => void)(msg);
    }
  }

  trace(msg: string, context?: LogContext): void {
    this.log('trace', msg, context);
  }

  debug(msg: string, context?: LogContext): void {
    this.log('debug', msg, context);
  }

  info(msg: string, context?: LogContext): void {
    this.log('info', msg, context);
  }

  warn(msg: string, context?: LogContext): void {
    this.log('warn', msg, context);
  }

  error(msg: string, context?: LogContext): void {
    this.log('error', msg, context);
  }

  fatal(msg: string, context?: LogContext): void {
    this.log('fatal', msg, context);
  }

  child(context: LogContext): Logger {
    const childPino = this.pino.child(context);
    return new PinoLoggerWrapper(undefined, childPino);
  }

  async flush(): Promise<void> {
    return new Promise((resolve) => {
      this.pino.flush(() => resolve());
    });
  }
}

// Singleton logger instance
let globalLogger: Logger | null = null;

export function getLogger(options?: LoggerOptions): Logger {
  if (!globalLogger) {
    globalLogger = new PinoLoggerWrapper(options);
  } else if (options) {
    // FIX-500-379: Warn when singleton is requested with different options
    globalLogger.warn('getLogger() called with options but singleton already exists; options ignored');
  }
  return globalLogger;
}

export function createLogger(options?: LoggerOptions): Logger {
  return new PinoLoggerWrapper(options);
}

// Re-export for convenience
export { type LoggerOptions };
