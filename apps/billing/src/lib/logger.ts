/**
 * Structured logger for the billing service.
 *
 * Emits JSON lines to stdout/stderr matching the 12-factor logging pattern.
 * In production, a log collector (e.g. Vector, Fluentd) ingests these lines.
 * 
 * Includes PII redaction utilities for consistent sensitive data handling.
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
    level: LogLevel;
    msg: string;
    timestamp: string;
    service: 'billing';
    [key: string]: unknown;
}

/**
 * Redact sensitive fields from objects before logging.
 * List of field names that should be redacted in logs.
 */
const SENSITIVE_FIELDS = new Set([
    'password',
    'secret',
    'token',
    'apiKey',
    'api_key',
    'authorization',
    'credit_card',
    'creditCard',
    'cardNumber',
    'card_number',
    'cvv',
    'ssn',
    'iban',
]);

/**
 * Redact sensitive data from log entries.
 * @param data - Object to redact
 * @returns Redacted copy of the object
 */
export function redactSensitive(data: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
        if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
            result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            result[key] = redactSensitive(value as Record<string, unknown>);
        } else {
            result[key] = value;
        }
    }
    return result;
}

/**
 * Safely extract error info for logging.
 * Prevents stack traces from leaking in production.
 */
export function safeError(error: unknown): Record<string, unknown> {
    if (error instanceof Error) {
        return {
            message: error.message,
            name: error.name,
            // Only include stack in development
            ...(process.env.NODE_ENV !== 'production' && { stack: error.stack }),
        };
    }
    return { message: String(error) };
}

function emit(level: LogLevel, msg: string, extra?: Record<string, unknown>): void {
    const entry: LogEntry = {
        level,
        msg,
        timestamp: new Date().toISOString(),
        service: 'billing',
        // Automatically redact sensitive fields
        ...(extra ? redactSensitive(extra) : {}),
    };

    const line = JSON.stringify(entry);

    if (level === 'error' || level === 'warn') {
        process.stderr.write(line + '\n');
    } else {
        process.stdout.write(line + '\n');
    }
}

export const logger = {
    debug(msg: string, extra?: Record<string, unknown>): void {
        if (process.env.NODE_ENV !== 'production') {
            emit('debug', msg, extra);
        }
    },
    info(msg: string, extra?: Record<string, unknown>): void {
        emit('info', msg, extra);
    },
    warn(msg: string, extra?: Record<string, unknown>): void {
        emit('warn', msg, extra);
    },
    error(msg: string, extra?: Record<string, unknown>): void {
        emit('error', msg, extra);
    },
};
