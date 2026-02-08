import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

/**
 * FIX-500-096: Cache Intl formatters at module level.
 * Creating new Intl.DateTimeFormat / NumberFormat per call is expensive
 * because the constructor parses locale data and options each time.
 */
const dateFormatter = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
});

const numberFormatter = new Intl.NumberFormat('en-US');

/** Cache keyed by currency code — FIX-500-443: capped at 50 entries to prevent unbounded growth */
const MAX_CURRENCY_FORMATTERS = 50;
const currencyFormatters = new Map<string, Intl.NumberFormat>();

function getCurrencyFormatter(currency: string): Intl.NumberFormat {
    let fmt = currencyFormatters.get(currency);
    if (!fmt) {
        // FIX-500-443: Evict oldest entry if at capacity
        if (currencyFormatters.size >= MAX_CURRENCY_FORMATTERS) {
            const oldest = currencyFormatters.keys().next().value;
            if (oldest !== undefined) currencyFormatters.delete(oldest);
        }
        fmt = new Intl.NumberFormat('en-US', { style: 'currency', currency });
        currencyFormatters.set(currency, fmt);
    }
    return fmt;
}

export function formatDate(date: string | Date): string {
    return dateFormatter.format(new Date(date));
}

export function formatCurrency(amount: number, currency = 'EUR'): string {
    return getCurrencyFormatter(currency).format(amount);
}

export function formatNumber(num: number): string {
    return numberFormatter.format(num);
}

export function formatPercentage(value: number): string {
    return `${(value * 100).toFixed(1)}%`;
}

export function getRiskColor(level: 'low' | 'medium' | 'high' | 'critical'): string {
    const colors = {
        low: 'text-emerald-600 bg-emerald-500/10 border border-emerald-500/20',
        medium: 'text-amber-600 bg-amber-500/10 border border-amber-500/20',
        high: 'text-orange-600 bg-orange-500/10 border border-orange-500/20',
        critical: 'text-destructive bg-destructive/10 border border-destructive/20',
    };
    return colors[level];
}

export function getStatusColor(status: string): string {
    const colors: Record<string, string> = {
        active: 'text-success bg-success/10 border border-success/20',
        paused: 'text-amber-600 bg-amber-500/10 border border-amber-500/20',
        completed: 'text-info bg-info/10 border border-info/20',
        draft: 'text-muted-foreground bg-muted border border-border',
        pending: 'text-amber-600 bg-amber-500/10 border border-amber-500/20',
        processing: 'text-info bg-info/10 border border-info/20',
        success: 'text-success bg-success/10 border border-success/20',
        failed: 'text-destructive bg-destructive/10 border border-destructive/20',
    };
    return colors[status] || 'text-muted-foreground bg-muted border border-border';
}

export function truncate(str: string, length: number): string {
    if (str.length <= length) return str;
    return str.slice(0, length) + '...';
}

export function timeAgo(date: string | Date): string {
    const now = new Date();
    const then = new Date(date);
    const seconds = Math.floor((now.getTime() - then.getTime()) / 1000);

    const intervals = [
        { label: 'year', seconds: 31536000 },
        { label: 'month', seconds: 2592000 },
        { label: 'week', seconds: 604800 },
        { label: 'day', seconds: 86400 },
        { label: 'hour', seconds: 3600 },
        { label: 'minute', seconds: 60 },
    ];

    for (const interval of intervals) {
        const count = Math.floor(seconds / interval.seconds);
        if (count >= 1) {
            return `${count} ${interval.label}${count !== 1 ? 's' : ''} ago`;
        }
    }

    return 'just now';
}
