type LogLevel = 'audit' | 'security' | 'error';

function emitStructuredLog(level: LogLevel, event: string, payload: Record<string, unknown>): void {
    const entry = {
        level,
        event,
        timestamp: new Date().toISOString(),
        ...payload,
    };

    if (level === 'error') {
        console.error(JSON.stringify(entry));
        return;
    }

    console.info(JSON.stringify(entry));
}

export function logAuditEvent(event: string, payload: Record<string, unknown>): void {
    emitStructuredLog('audit', event, payload);
}

export function logSecurityEvent(event: string, payload: Record<string, unknown>): void {
    emitStructuredLog('security', event, payload);
}

export function logErrorEvent(event: string, payload: Record<string, unknown>): void {
    emitStructuredLog('error', event, payload);
}
