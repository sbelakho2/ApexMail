import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merge Tailwind CSS classes with proper precedence
 */
export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

/**
 * Format a number with thousands separators
 */
export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
    return new Intl.NumberFormat('en-US', options).format(value);
}

/**
 * Format a number as currency
 */
export function formatCurrency(value: number, currency = 'USD'): string {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency,
    }).format(value);
}

/**
 * Format a number as a percentage
 */
export function formatPercent(value: number, decimals = 1): string {
    return `${value.toFixed(decimals)}%`;
}

/**
 * Format a date relative to now
 */
export function formatRelativeTime(date: Date | string): string {
    const now = new Date();
    const target = new Date(date);
    const diffInSeconds = Math.floor((now.getTime() - target.getTime()) / 1000);

    if (diffInSeconds < 60) {
        return 'just now';
    }

    const diffInMinutes = Math.floor(diffInSeconds / 60);
    if (diffInMinutes < 60) {
        return `${diffInMinutes}m ago`;
    }

    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) {
        return `${diffInHours}h ago`;
    }

    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) {
        return `${diffInDays}d ago`;
    }

    const diffInWeeks = Math.floor(diffInDays / 7);
    if (diffInWeeks < 4) {
        return `${diffInWeeks}w ago`;
    }

    const diffInMonths = Math.floor(diffInDays / 30);
    if (diffInMonths < 12) {
        return `${diffInMonths}mo ago`;
    }

    const diffInYears = Math.floor(diffInDays / 365);
    return `${diffInYears}y ago`;
}

/**
 * Format a date
 */
export function formatDate(date: Date | string, options?: Intl.DateTimeFormatOptions): string {
    return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        ...options,
    }).format(new Date(date));
}

/**
 * Format a date and time
 */
export function formatDateTime(date: Date | string): string {
    return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
    }).format(new Date(date));
}

/**
 * Format a short date (e.g. Jan 15)
 */
export function formatShortDate(date: Date | string): string {
    return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
    }).format(new Date(date));
}

/**
 * Format a time-only value
 */
export function formatTime(date: Date | string, options?: Intl.DateTimeFormatOptions): string {
    return new Intl.DateTimeFormat('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        ...options,
    }).format(new Date(date));
}

/**
 * Get the user's local timezone identifier
 */
export function getLocalTimeZone(): string {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/**
 * Format bytes to human readable format
 */
export function formatBytes(bytes: number, decimals = 2): string {
    if (!Number.isFinite(bytes)) return '0 Bytes';

    const sign = bytes < 0 ? '-' : '';
    const absoluteBytes = Math.abs(bytes);
    if (absoluteBytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(Math.floor(Math.log(absoluteBytes) / Math.log(k)), sizes.length - 1);
    const value = absoluteBytes / Math.pow(k, i);

    return `${sign}${parseFloat(value.toFixed(decimals))} ${sizes[i]}`;
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, length: number): string {
    if (text.length <= length) return text;
    return `${text.slice(0, length)}...`;
}

/**
 * Capitalize first letter
 */
export function capitalize(text: string): string {
    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
}

/**
 * Convert string to title case
 */
export function titleCase(text: string): string {
    return text
        .split(' ')
        .map((word) => capitalize(word))
        .join(' ');
}

/**
 * Generate initials from name
 */
export function getInitials(name: string, maxLength = 2): string {
    return name
        .split(' ')
        .map((word) => word[0])
        .join('')
        .toUpperCase()
        .slice(0, maxLength);
}

/**
 * Slugify a string
 */
export function slugify(text: string): string {
    return text
        .toLowerCase()
        .trim()
        .replace(/[^\w\s-]/g, '')
        .replace(/[\s_-]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

/**
 * Debounce a function
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: NodeJS.Timeout | null = null;

    return (...args: Parameters<T>) => {
        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

/**
 * Throttle a function
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle = false;

    return (...args: Parameters<T>) => {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => (inThrottle = false), limit);
        }
    };
}

/**
 * Sleep for a given duration
 */
export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Check if value is empty
 */
export function isEmpty(value: unknown): boolean {
    if (value === null || value === undefined) return true;
    if (typeof value === 'string') return value.trim() === '';
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === 'object') return Object.keys(value).length === 0;
    return false;
}

/**
 * Generate a random color
 */
export function randomColor(): string {
    const colors = [
        '#2563eb', // brand-500
        '#16a34a', // success
        '#d97706', // warning
        '#dc2626', // danger
        '#0891b2', // info
        '#8b5cf6', // violet
        '#1742b4', // brand-700
        '#64748b', // surface-500
    ];
    return colors[Math.floor(Math.random() * colors.length)];
}

/**
 * Get contrast color (black or white) for a given background color
 */
export function getContrastColor(hexColor: string): string {
    const hex = hexColor.replace('#', '');
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    return luminance > 0.5 ? '#000000' : '#ffffff';
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

/**
 * Download data as file
 */
let downloadAnchor: HTMLAnchorElement | null = null;

export function downloadFile(data: string | Blob, filename: string, type = 'text/plain'): void {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);

    if (!downloadAnchor) {
        downloadAnchor = document.createElement('a');
        downloadAnchor.style.display = 'none';
        document.body.appendChild(downloadAnchor);
    }

    const link = downloadAnchor;
    link.href = url;
    link.download = filename;
    link.click();

    // Ensure object URL stays alive for click handling before cleanup.
    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 0);
}

/**
 * Generate UUID v4
 */
export function uuid(): string {
    return crypto.randomUUID();
}

/**
 * Parse query string to object
 */
export function parseQueryString(queryString: string): Record<string, string> {
    const params = new URLSearchParams(queryString);
    const result: Record<string, string> = {};
    params.forEach((value, key) => {
        result[key] = value;
    });
    return result;
}

/**
 * Build query string from object
 */
export function buildQueryString(params: Record<string, string | number | boolean | undefined>): string {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
            searchParams.append(key, String(value));
        }
    });
    return searchParams.toString();
}

/**
 * Check if running in browser
 */
export function isBrowser(): boolean {
    return typeof window !== 'undefined';
}

/**
 * Check if running on mobile device
 */
export function isMobile(): boolean {
    if (!isBrowser()) return false;

    const hasTouchPoints = (navigator.maxTouchPoints ?? 0) > 0;
    const coarsePointer = typeof window.matchMedia === 'function'
        ? window.matchMedia('(pointer: coarse)').matches
        : false;
    const narrowViewport = window.innerWidth <= 768;

    return narrowViewport && (hasTouchPoints || coarsePointer);
}

/**
 * Check if dark mode is preferred
 */
export function prefersDarkMode(): boolean {
    if (!isBrowser()) return false;
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
}
