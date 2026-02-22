/**
 * Template Engine - MJML + Handlebars Support
 * 
 * Supports:
 * - MJML for responsive email layouts
 * - Handlebars for variable interpolation
 * - Plain HTML passthrough
 * - Safe rendering with XSS prevention
 * 
 * SECURITY: All user-provided attributes are sanitized to prevent XSS
 */

import Handlebars from 'handlebars';

// ============================================================================
// XSS Prevention Utilities
// ============================================================================

/**
 * SECURITY: Escape HTML special characters to prevent XSS
 */
function escapeHtml(str: string): string {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * SECURITY: Sanitize URL to prevent javascript: and data: XSS attacks
 * Only allows http, https, mailto, and tel protocols
 */
function sanitizeUrl(url: string): string {
    if (!url || typeof url !== 'string') return '#';
    
    const trimmed = url.trim().toLowerCase();
    
    // Block dangerous protocols
    const dangerousProtocols = [
        'javascript:',
        'data:',
        'vbscript:',
        'file:',
        'about:',
        'blob:',
    ];
    
    for (const protocol of dangerousProtocols) {
        if (trimmed.startsWith(protocol)) {
            return '#';
        }
    }
    
    // Allow safe protocols
    const safeProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
    
    // Check if it's a relative URL or has a safe protocol
    if (!trimmed.includes(':') || safeProtocols.some(p => trimmed.startsWith(p))) {
        // Escape HTML entities in the URL (but preserve URL encoding)
        return url
            .replace(/"/g, '%22')
            .replace(/'/g, '%27')
            .replace(/</g, '%3C')
            .replace(/>/g, '%3E');
    }
    
    // Unknown protocol, block it
    return '#';
}

/**
 * SECURITY: Sanitize attribute value for safe HTML insertion
 */
function sanitizeAttr(value: string): string {
    if (!value || typeof value !== 'string') return '';
    return escapeHtml(value);
}

// ============================================================================
// Types
// ============================================================================

export interface TemplateContext {
    [key: string]: unknown;
}

export interface TemplateRenderOptions {
    /** Template format: 'mjml' | 'handlebars' | 'html' */
    format?: 'mjml' | 'handlebars' | 'html';
    // FIX-500-380: Note: Use 'format', not 'type'. If callers pass a 'type' property
    // it will be silently ignored. TypeScript catches this at compile time, but
    // dynamic callers (e.g., API payloads spread into options) should validate.
    /** Enable strict mode - throw on missing variables */
    strict?: boolean;
    /** Custom helpers for Handlebars */
    helpers?: Record<string, Handlebars.HelperDelegate>;
    /** Partials for Handlebars */
    partials?: Record<string, string>;
}

export interface TemplateRenderResult {
    html: string;
    text?: string;
    errors?: string[];
}

export interface ExtractedVariable {
    name: string;
    path: string;
    defaultValue?: string;
}

// ============================================================================
// MJML Components (Simplified - core structure)
// ============================================================================

/**
 * Simple MJML to HTML converter
 * Handles the most common MJML tags without external dependencies
 */
function mjmlToHtml(mjml: string): { html: string; errors: string[] } {
    const errors: string[] = [];
    
    // Extract body content
    const bodyMatch = mjml.match(/<mj-body[^>]*>([\s\S]*?)<\/mj-body>/i);
    if (!bodyMatch) {
        errors.push('Missing <mj-body> tag');
        return { html: mjml, errors };
    }
    
    let content = bodyMatch[1] || '';
    
    // Convert MJML sections to table rows
    // SECURITY: Use (?:[^">]|"[^"]*")* instead of [^>]* to handle > inside quoted attributes
    content = content.replace(
        /<mj-section((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-section>/gi,
        (_match, attrs, inner) => {
            const bgColor = extractAttr(attrs, 'background-color') || '#ffffff';
            const padding = extractAttr(attrs, 'padding') || '20px';
            return `<tr><td style="background-color:${bgColor};padding:${padding}"><table width="100%" cellpadding="0" cellspacing="0">${inner}</table></td></tr>`;
        }
    );
    
    // Convert MJML columns to table cells
    content = content.replace(
        /<mj-column((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-column>/gi,
        (_match, attrs, inner) => {
            const width = extractAttr(attrs, 'width') || '100%';
            const padding = extractAttr(attrs, 'padding') || '0';
            return `<td style="width:${width};padding:${padding};vertical-align:top">${inner}</td>`;
        }
    );
    
    // Convert MJML text to paragraphs
    content = content.replace(
        /<mj-text((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-text>/gi,
        (_match, attrs, inner) => {
            const color = extractAttr(attrs, 'color') || '#000000';
            const fontSize = extractAttr(attrs, 'font-size') || '14px';
            const lineHeight = extractAttr(attrs, 'line-height') || '1.5';
            const fontFamily = extractAttr(attrs, 'font-family') || 'Arial, sans-serif';
            const align = extractAttr(attrs, 'align') || 'left';
            return `<div style="color:${color};font-size:${fontSize};line-height:${lineHeight};font-family:${fontFamily};text-align:${align}">${inner}</div>`;
        }
    );
    
    // Convert MJML buttons
    // SECURITY: Sanitize href to prevent javascript: XSS
    content = content.replace(
        /<mj-button((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-button>/gi,
        (_match, attrs, inner) => {
            const href = sanitizeUrl(extractAttr(attrs, 'href') || '#');
            const bgColor = sanitizeAttr(extractAttr(attrs, 'background-color') || '#007bff');
            const color = sanitizeAttr(extractAttr(attrs, 'color') || '#ffffff');
            const borderRadius = sanitizeAttr(extractAttr(attrs, 'border-radius') || '4px');
            const padding = sanitizeAttr(extractAttr(attrs, 'inner-padding') || '12px 24px');
            const fontSize = sanitizeAttr(extractAttr(attrs, 'font-size') || '14px');
            // Inner content is typically user-provided button text - escape it
            const safeInner = escapeHtml(inner);
            return `<table cellpadding="0" cellspacing="0" style="margin:10px 0"><tr><td style="background-color:${bgColor};border-radius:${borderRadius};padding:${padding}"><a href="${href}" style="color:${color};text-decoration:none;font-size:${fontSize};font-weight:bold;display:inline-block">${safeInner}</a></td></tr></table>`;
        }
    );
    
    // Convert MJML images
    // SECURITY: Sanitize src and href to prevent XSS, escape alt text
    content = content.replace(
        /<mj-image((?:[^">]|"[^"]*")*)\/?>/gi,
        (_match, attrs) => {
            const src = sanitizeUrl(extractAttr(attrs, 'src') || '');
            const alt = sanitizeAttr(extractAttr(attrs, 'alt') || '');
            const width = sanitizeAttr(extractAttr(attrs, 'width') || 'auto');
            const align = sanitizeAttr(extractAttr(attrs, 'align') || 'center');
            const href = extractAttr(attrs, 'href');
            const img = `<img src="${src}" alt="${alt}" style="max-width:${width};width:100%;display:block;margin:0 auto" />`;
            if (href) {
                const safeHref = sanitizeUrl(href);
                return `<div style="text-align:${align}"><a href="${safeHref}">${img}</a></div>`;
            }
            return `<div style="text-align:${align}">${img}</div>`;
        }
    );
    
    // Convert MJML dividers
    content = content.replace(
        /<mj-divider((?:[^">]|"[^"]*")*)\/?>/gi,
        (_match, attrs) => {
            const borderColor = extractAttr(attrs, 'border-color') || '#e0e0e0';
            const borderWidth = extractAttr(attrs, 'border-width') || '1px';
            const padding = extractAttr(attrs, 'padding') || '10px 0';
            return `<div style="padding:${padding}"><hr style="border:0;border-top:${borderWidth} solid ${borderColor};margin:0" /></div>`;
        }
    );
    
    // Convert MJML spacers
    content = content.replace(
        /<mj-spacer((?:[^">]|"[^"]*")*)\/?>/gi,
        (_match, attrs) => {
            const height = sanitizeAttr(extractAttr(attrs, 'height') || '20px');
            return `<div style="height:${height}"></div>`;
        }
    );
    
    // Convert MJML social elements
    content = content.replace(
        /<mj-social((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-social>/gi,
        (_match, _attrs, inner) => {
            return `<div style="text-align:center;padding:10px 0">${inner}</div>`;
        }
    );
    
    // SECURITY: Sanitize social element URLs and text
    content = content.replace(
        /<mj-social-element((?:[^">]|"[^"]*")*)>([\s\S]*?)<\/mj-social-element>/gi,
        (_match, attrs, inner) => {
            const href = sanitizeUrl(extractAttr(attrs, 'href') || '#');
            const src = extractAttr(attrs, 'src') || '';
            const name = sanitizeAttr(extractAttr(attrs, 'name') || '');
            const iconSize = sanitizeAttr(extractAttr(attrs, 'icon-size') || '24px');
            
            // Use inline SVG icons for common social networks
            // SECURITY: getSocialIcon returns safe, predefined URLs
            const icon = src ? sanitizeUrl(src) : getSocialIcon(name);
            const safeAlt = sanitizeAttr(inner || name);
            return `<a href="${href}" style="display:inline-block;margin:0 8px;text-decoration:none"><img src="${icon}" alt="${safeAlt}" style="width:${iconSize};height:${iconSize}" /></a>`;
        }
    );
    
    // Build responsive HTML template
    const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Email</title>
    <style>
        body { margin: 0; padding: 0; width: 100%; }
        table { border-collapse: collapse; }
        img { border: 0; display: block; }
        @media only screen and (max-width: 600px) {
            .container { width: 100% !important; }
            td { padding: 10px !important; }
        }
    </style>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f4">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f4">
        <tr>
            <td align="center" style="padding:20px 0">
                <table class="container" width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff">
                    ${content}
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;
    
    // FIX-500-378: Warn about unrecognized MJML tags that were not converted
    const unrecongnizedMjTags = content.match(/<mj-(?!body|section|column|text|button|image|divider|spacer|social|social-element)[a-z-]+/gi);
    if (unrecongnizedMjTags) {
        const uniqueTags = [...new Set(unrecongnizedMjTags.map(t => t.toLowerCase()))];
        for (const tag of uniqueTags) {
            errors.push(`Warning: unrecognized MJML tag '${tag}>' was not converted and may not render correctly`);
        }
    }

    return { html, errors };
}

function extractAttr(attrs: string, name: string): string | undefined {
    const match = attrs.match(new RegExp(`${name}="([^"]*)"`, 'i'));
    return match?.[1];
}

function getSocialIcon(name: string): string {
    // Return embedded SVG data URIs for common social networks
    const icons: Record<string, string> = {
        'facebook': 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563EB"><path d="M22 12a10 10 0 1 0-11.56 9.87v-6.98H7.9V12h2.54V9.8c0-2.5 1.49-3.88 3.78-3.88 1.1 0 2.25.2 2.25.2v2.47h-1.27c-1.25 0-1.64.78-1.64 1.58V12h2.8l-.45 2.89h-2.35v6.98A10 10 0 0 0 22 12z"/></svg>',
        'twitter': 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563EB"><path d="M18.9 2H22l-6.77 7.74L23.2 22h-6.24l-4.9-6.5L6.4 22H3.3l7.24-8.28L.8 2H7.2l4.43 5.88L18.9 2z"/></svg>',
        'linkedin': 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563EB"><path d="M4.98 3.5C4.98 4.88 3.86 6 2.49 6S0 4.88 0 3.5 1.12 1 2.49 1s2.49 1.12 2.49 2.5zM.5 8h4V23h-4V8zm7 0h3.8v2h.05c.53-1 1.83-2.05 3.77-2.05C19 7.95 21 10.1 21 14.1V23h-4v-7.7c0-1.84-.03-4.2-2.56-4.2-2.56 0-2.95 2-2.95 4.07V23h-4V8z"/></svg>',
        'instagram': 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563EB"><path d="M7.75 2h8.5A5.75 5.75 0 0 1 22 7.75v8.5A5.75 5.75 0 0 1 16.25 22h-8.5A5.75 5.75 0 0 1 2 16.25v-8.5A5.75 5.75 0 0 1 7.75 2zm8.3 1.5h-8.1A4.45 4.45 0 0 0 3.5 7.95v8.1a4.45 4.45 0 0 0 4.45 4.45h8.1a4.45 4.45 0 0 0 4.45-4.45v-8.1a4.45 4.45 0 0 0-4.45-4.45zM12 7a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 1.5A3.5 3.5 0 1 0 12 15.5 3.5 3.5 0 0 0 12 8.5zm5.2-2.3a1.2 1.2 0 1 1 0 2.4 1.2 1.2 0 0 1 0-2.4z"/></svg>',
        'youtube': 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%232563EB"><path d="M23.5 7.2a3 3 0 0 0-2.1-2.1C19.4 4.5 12 4.5 12 4.5s-7.4 0-9.4.6A3 3 0 0 0 .5 7.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 4.8 3 3 0 0 0 2.1 2.1c2 .6 9.4.6 9.4.6s7.4 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-4.8zM9.75 15.5v-7L16 12l-6.25 3.5z"/></svg>',
    };
    return icons[name.toLowerCase()] || icons.facebook;
}

// ============================================================================
// Handlebars Setup
// ============================================================================

/**
 * Create a configured Handlebars instance with safe defaults
 */
function createHandlebarsInstance(options?: TemplateRenderOptions): typeof Handlebars {
    const hbs = Handlebars.create();

    /**
     * F-240: Prototype pollution prevention.
     *
     * Handlebars by default allows templates to access `__proto__`,
     * `constructor`, and other prototype properties on the context
     * object. An attacker who controls template content could use
     * {{__proto__.polluted}} or {{constructor.constructor}} to
     * access or enumerate internal JS engine details.
     *
     * We register a hook that silently blocks any property lookup
     * that would traverse the prototype chain.
     */
    const BLOCKED_PROPERTIES = new Set([
        '__proto__',
        'constructor',
        'prototype',
        '__defineGetter__',
        '__defineSetter__',
        '__lookupGetter__',
        '__lookupSetter__',
    ]);

    // Override lookupProperty on the Handlebars runtime so that any
    // property traversal through blocked names (even nested paths like
    // {{a.__proto__.b}}) returns undefined.
    const originalLookup = (hbs.Utils as any).lookupProperty;
    if (typeof originalLookup === 'function') {
        (hbs.Utils as any).lookupProperty = function (parent: any, propertyName: string) {
            if (BLOCKED_PROPERTIES.has(propertyName)) {
                return undefined;
            }
            return originalLookup(parent, propertyName);
        };
    }
    
    // Register default helpers
    registerDefaultHelpers(hbs);
    
    // Register custom helpers
    if (options?.helpers) {
        for (const [name, helper] of Object.entries(options.helpers)) {
            hbs.registerHelper(name, helper);
        }
    }
    
    // Register partials
    if (options?.partials) {
        for (const [name, partial] of Object.entries(options.partials)) {
            hbs.registerPartial(name, partial);
        }
    }
    
    return hbs;
}

/**
 * Register default Handlebars helpers
 */
function registerDefaultHelpers(hbs: typeof Handlebars): void {
    // Conditional helpers
    hbs.registerHelper('eq', (a: unknown, b: unknown) => a === b);
    hbs.registerHelper('ne', (a: unknown, b: unknown) => a !== b);
    hbs.registerHelper('lt', (a: number, b: number) => a < b);
    hbs.registerHelper('gt', (a: number, b: number) => a > b);
    hbs.registerHelper('lte', (a: number, b: number) => a <= b);
    hbs.registerHelper('gte', (a: number, b: number) => a >= b);
    hbs.registerHelper('and', (...args: unknown[]) => args.slice(0, -1).every(Boolean));
    hbs.registerHelper('or', (...args: unknown[]) => args.slice(0, -1).some(Boolean));
    hbs.registerHelper('not', (a: unknown) => !a);
    
    // String helpers
    hbs.registerHelper('uppercase', (str: string) => String(str || '').toUpperCase());
    hbs.registerHelper('lowercase', (str: string) => String(str || '').toLowerCase());
    hbs.registerHelper('capitalize', (str: string) => {
        const s = String(str || '');
        return s.charAt(0).toUpperCase() + s.slice(1);
    });
    hbs.registerHelper('truncate', (str: string, len: number) => {
        const s = String(str || '');
        return s.length > len ? s.slice(0, len) + '...' : s;
    });
    
    // Date helpers
    hbs.registerHelper('formatDate', (date: Date | string | number, format: string) => {
        const d = new Date(date);
        if (isNaN(d.getTime())) return '';
        
        const formats: Record<string, string> = {
            'short': d.toLocaleDateString(),
            'long': d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
            'iso': d.toISOString(),
            'time': d.toLocaleTimeString(),
        };
        return formats[format] || d.toLocaleDateString();
    });
    
    // Number helpers
    hbs.registerHelper('formatNumber', (num: number, decimals = 0) => {
        return Number(num).toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
    });
    
    hbs.registerHelper('formatCurrency', (num: number, currency = 'USD') => {
        return Number(num).toLocaleString(undefined, { style: 'currency', currency });
    });
    
    // Array helpers
    hbs.registerHelper('first', (arr: unknown[]) => Array.isArray(arr) ? arr[0] : undefined);
    hbs.registerHelper('last', (arr: unknown[]) => Array.isArray(arr) ? arr[arr.length - 1] : undefined);
    hbs.registerHelper('length', (arr: unknown[]) => Array.isArray(arr) ? arr.length : 0);
    
    // Object helpers
    hbs.registerHelper('json', (obj: unknown) => JSON.stringify(obj, null, 2));
    
    /**
     * E-179: Default / fallback value helper.
     *
     * When a template variable is missing from the context Handlebars renders
     * it as an empty string (non-strict mode) or throws (strict mode).
     *
     * To provide an explicit fallback use:
     *   {{default name "Valued Customer"}}    → uses name if present, else "Valued Customer"
     *   {{default user.company "Your Company"}} → nested path with fallback
     *
     * This is the recommended pattern for user-facing merge tags where a
     * blank output would look broken.
     */
    hbs.registerHelper('default', (value: unknown, defaultValue: unknown) => value ?? defaultValue);
}

// ============================================================================
// Template Engine Class
// ============================================================================

export class TemplateEngine {
    private handlebars: typeof Handlebars;
    private options: TemplateRenderOptions;

    /**
     * C-072: LRU-style cache for compiled Handlebars templates.
     * Avoids re-parsing and re-compiling the same template string on every
     * render call.  Keyed by the raw template source; capped at 200 entries
     * to bound memory.
     */
    private compiledCache = new Map<string, Handlebars.TemplateDelegate>();
    private static readonly MAX_CACHE_SIZE = 200;

    /** C-102: Maximum time (ms) allowed for template rendering */
    private static readonly RENDER_TIMEOUT_MS = 5_000;
    
    constructor(options?: TemplateRenderOptions) {
        this.options = options || {};
        this.handlebars = createHandlebarsInstance(options);
    }

    /**
     * C-102: Render a template with a timeout guard.
     * Uses Promise.race to abort rendering that exceeds RENDER_TIMEOUT_MS,
     * preventing malicious or broken templates from blocking the event loop.
     */
    async renderWithTimeout(
        template: string,
        context: TemplateContext = {},
        options?: TemplateRenderOptions,
    ): Promise<TemplateRenderResult> {
        return Promise.race([
            Promise.resolve(this.render(template, context, options)),
            new Promise<never>((_, reject) =>
                setTimeout(
                    () => reject(new Error('Template rendering timed out')),
                    TemplateEngine.RENDER_TIMEOUT_MS,
                ),
            ),
        ]);
    }
    
    /**
     * Render a template with context data.
     *
     * E-179: Missing variable behaviour:
     * - **Non-strict mode** (default): Missing variables render as empty
     *   strings, which is safe for user-facing emails. Use the {{default}}
     *   helper to supply a fallback, e.g. {{default name "Friend"}}.
     * - **Strict mode** (`strict: true`): Throws an error if a referenced
     *   variable is not present in `context`, useful for validation.
     *
     * The engine never emits the literal text "undefined" for missing vars.
     */
    render(template: string, context: TemplateContext = {}, options?: TemplateRenderOptions): TemplateRenderResult {
        const opts = { ...this.options, ...options };
        const format = opts.format || this.detectFormat(template);
        const errors: string[] = [];
        
        let html = template;
        
        // Step 1: Process MJML if needed
        if (format === 'mjml') {
            const mjmlResult = mjmlToHtml(template);
            html = mjmlResult.html;
            errors.push(...mjmlResult.errors);
        }
        
        // Step 2: Process Handlebars variables (C-072: cached compilation)
        try {
            // Include strict flag in cache key so strict vs non-strict compile differently
            const cacheKey = `${opts.strict ? '1' : '0'}:${html}`;
            let compiled = this.compiledCache.get(cacheKey);
            if (!compiled) {
                compiled = this.handlebars.compile(html, {
                    strict: opts.strict,
                    noEscape: false, // HTML escape by default for security
                });
                // Evict oldest entry when cache is full
                if (this.compiledCache.size >= TemplateEngine.MAX_CACHE_SIZE) {
                    const firstKey = this.compiledCache.keys().next().value;
                    if (firstKey !== undefined) this.compiledCache.delete(firstKey);
                }
                this.compiledCache.set(cacheKey, compiled);
            }
            html = compiled(context);
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Template compilation failed';
            errors.push(message);
            if (opts.strict) {
                throw new Error(`Template rendering failed: ${message}`);
            }
        }
        
        // Step 3: Generate plain text version
        const text = this.htmlToText(html);
        
        return { html, text, errors: errors.length > 0 ? errors : undefined };
    }
    
    /**
     * Detect template format from content
     */
    private detectFormat(template: string): 'mjml' | 'handlebars' | 'html' {
        if (template.includes('<mjml') || template.includes('<mj-')) {
            return 'mjml';
        }
        if (template.includes('{{') && template.includes('}}')) {
            return 'handlebars';
        }
        return 'html';
    }
    
    /**
     * Convert HTML to plain text
     */
    private htmlToText(html: string): string {
        return html
            // Remove style and script tags with content
            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
            .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
            // Convert links to text with URL
            .replace(/<a[^>]*href="([^"]*)"[^>]*>([^<]*)<\/a>/gi, '$2 ($1)')
            // Convert line breaks
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<\/p>/gi, '\n\n')
            .replace(/<\/div>/gi, '\n')
            .replace(/<\/tr>/gi, '\n')
            .replace(/<\/li>/gi, '\n')
            // Remove remaining HTML tags
            .replace(/<[^>]+>/g, '')
            // Decode HTML entities
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'")
            // Clean up whitespace
            .replace(/\n\s*\n\s*\n/g, '\n\n')
            .trim();
    }
    
    /**
     * Extract variables from a template
     */
    extractVariables(template: string): ExtractedVariable[] {
        const variables: ExtractedVariable[] = [];
        const seen = new Set<string>();
        
        // Match Handlebars expressions: {{variable}}, {{#if variable}}, {{object.property}}
        const regex = /\{\{[#/]?([^}]+)\}\}/g;
        let match;
        
        while ((match = regex.exec(template)) !== null) {
            const expr = match[1]?.trim() || '';
            
            // Skip helpers and block keywords
            if (expr.startsWith('else') || expr.startsWith('!') || expr === '') continue;
            
            // Extract variable name (first word before space)
            const parts = expr.split(/\s+/);
            const varName = parts[0] || '';
            
            // Skip common helpers
            const helpers = ['if', 'unless', 'each', 'with', 'lookup', 'log', 'eq', 'ne', 'lt', 'gt', 'and', 'or'];
            if (helpers.includes(varName)) {
                // Get the actual variable from the helper expression
                if (parts[1] && !helpers.includes(parts[1])) {
                    const actualVar = parts[1];
                    if (!seen.has(actualVar)) {
                        seen.add(actualVar);
                        variables.push({
                            name: actualVar.split('.')[0] || actualVar,
                            path: actualVar,
                        });
                    }
                }
                continue;
            }
            
            if (!seen.has(varName)) {
                seen.add(varName);
                variables.push({
                    name: varName.split('.')[0] || varName,
                    path: varName,
                });
            }
        }
        
        return variables;
    }
    
    /**
     * Validate a template
     */
    validate(template: string): { valid: boolean; errors: string[] } {
        const errors: string[] = [];
        
        // Check for unmatched Handlebars blocks
        const openBlocks = (template.match(/\{\{#(\w+)/g) || []).map(m => m.replace('{{#', ''));
        const closeBlocks = (template.match(/\{\{\/(\w+)/g) || []).map(m => m.replace('{{/', ''));
        
        for (const block of openBlocks) {
            const openCount = openBlocks.filter(b => b === block).length;
            const closeCount = closeBlocks.filter(b => b === block).length;
            if (openCount !== closeCount) {
                errors.push(`Unmatched block: {{#${block}}}`);
            }
        }
        
        // Check for MJML structure if MJML
        if (template.includes('<mjml') || template.includes('<mj-')) {
            if (!template.includes('<mj-body')) {
                errors.push('MJML template missing <mj-body> tag');
            }
        }
        
        // Try to compile
        try {
            this.handlebars.compile(template);
        } catch (err) {
            errors.push(`Compilation error: ${err instanceof Error ? err.message : 'Unknown error'}`);
        }
        
        return { valid: errors.length === 0, errors };
    }
    
    /**
     * Register a custom helper
     */
    registerHelper(name: string, helper: Handlebars.HelperDelegate): void {
        this.handlebars.registerHelper(name, helper);
    }
    
    /**
     * Register a partial template
     */
    registerPartial(name: string, partial: string): void {
        this.handlebars.registerPartial(name, partial);
    }
}

// ============================================================================
// Factory function
// ============================================================================

/**
 * Create a new template engine instance
 */
export function createTemplateEngine(options?: TemplateRenderOptions): TemplateEngine {
    return new TemplateEngine(options);
}

// Default instance
export const templateEngine = createTemplateEngine();

// ============================================================================
// Quick render function
// ============================================================================

/**
 * Quick render a template without creating an instance
 */
export function renderTemplate(
    template: string,
    context: TemplateContext = {},
    options?: TemplateRenderOptions
): TemplateRenderResult {
    return templateEngine.render(template, context, options);
}
