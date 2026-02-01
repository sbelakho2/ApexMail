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
const REDACT_PATHS = [
  'password',
  'apiKey',
  'api_key',
  'secret',
  'token',
  'authorization',
  'cookie',
  'creditCard',
  'credit_card',
  'ssn',
  'privateKey',
  'private_key',
  '*.password',
  '*.apiKey',
  '*.api_key',
  '*.secret',
  '*.token',
  'headers.authorization',
  'headers.cookie',
  'body.password',
  'body.api_key',
];

class PinoLoggerWrapper implements Logger {
  private readonly pino: PinoLogger;

  constructor(options: LoggerOptions = {}) {
    const isPretty = process.env['NODE_ENV'] !== 'production';
    
    this.pino = createPino({
      level: process.env['LOG_LEVEL'] ?? 'info',
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
    const wrapper = new PinoLoggerWrapper();
    Object.defineProperty(wrapper, 'pino', { value: childPino, writable: false });
    return wrapper;
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
  }
  return globalLogger;
}

export function createLogger(options?: LoggerOptions): Logger {
  return new PinoLoggerWrapper(options);
}

// Re-export for convenience
export { type LoggerOptions };
