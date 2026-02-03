/**
 * Template Engine - MJML + Handlebars Support
 * 
 * Supports:
 * - MJML for responsive email layouts
 * - Handlebars for variable interpolation
 * - Plain HTML passthrough
 * - Safe rendering with XSS prevention
 */

import Handlebars from 'handlebars';

// ============================================================================
// Types
// ============================================================================

export interface TemplateContext {
    [key: string]: unknown;
}

export interface TemplateRenderOptions {
    /** Template format: 'mjml' | 'handlebars' | 'html' */
    format?: 'mjml' | 'handlebars' | 'html';
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
    content = content.replace(
        /<mj-section([^>]*)>([\s\S]*?)<\/mj-section>/gi,
        (_match, attrs, inner) => {
            const bgColor = extractAttr(attrs, 'background-color') || '#ffffff';
            const padding = extractAttr(attrs, 'padding') || '20px';
            return `<tr><td style="background-color:${bgColor};padding:${padding}"><table width="100%" cellpadding="0" cellspacing="0">${inner}</table></td></tr>`;
        }
    );
    
    // Convert MJML columns to table cells
    content = content.replace(
        /<mj-column([^>]*)>([\s\S]*?)<\/mj-column>/gi,
        (_match, attrs, inner) => {
            const width = extractAttr(attrs, 'width') || '100%';
            const padding = extractAttr(attrs, 'padding') || '0';
            return `<td style="width:${width};padding:${padding};vertical-align:top">${inner}</td>`;
        }
    );
    
    // Convert MJML text to paragraphs
    content = content.replace(
        /<mj-text([^>]*)>([\s\S]*?)<\/mj-text>/gi,
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
    content = content.replace(
        /<mj-button([^>]*)>([\s\S]*?)<\/mj-button>/gi,
        (_match, attrs, inner) => {
            const href = extractAttr(attrs, 'href') || '#';
            const bgColor = extractAttr(attrs, 'background-color') || '#007bff';
            const color = extractAttr(attrs, 'color') || '#ffffff';
            const borderRadius = extractAttr(attrs, 'border-radius') || '4px';
            const padding = extractAttr(attrs, 'inner-padding') || '12px 24px';
            const fontSize = extractAttr(attrs, 'font-size') || '14px';
            return `<table cellpadding="0" cellspacing="0" style="margin:10px 0"><tr><td style="background-color:${bgColor};border-radius:${borderRadius};padding:${padding}"><a href="${href}" style="color:${color};text-decoration:none;font-size:${fontSize};font-weight:bold;display:inline-block">${inner}</a></td></tr></table>`;
        }
    );
    
    // Convert MJML images
    content = content.replace(
        /<mj-image([^>]*)\/?>/gi,
        (_match, attrs) => {
            const src = extractAttr(attrs, 'src') || '';
            const alt = extractAttr(attrs, 'alt') || '';
            const width = extractAttr(attrs, 'width') || 'auto';
            const align = extractAttr(attrs, 'align') || 'center';
            const href = extractAttr(attrs, 'href');
            const img = `<img src="${src}" alt="${alt}" style="max-width:${width};width:100%;display:block;margin:0 auto" />`;
            if (href) {
                return `<div style="text-align:${align}"><a href="${href}">${img}</a></div>`;
            }
            return `<div style="text-align:${align}">${img}</div>`;
        }
    );
    
    // Convert MJML dividers
    content = content.replace(
        /<mj-divider([^>]*)\/?>/gi,
        (_match, attrs) => {
            const borderColor = extractAttr(attrs, 'border-color') || '#e0e0e0';
            const borderWidth = extractAttr(attrs, 'border-width') || '1px';
            const padding = extractAttr(attrs, 'padding') || '10px 0';
            return `<div style="padding:${padding}"><hr style="border:0;border-top:${borderWidth} solid ${borderColor};margin:0" /></div>`;
        }
    );
    
    // Convert MJML spacers
    content = content.replace(
        /<mj-spacer([^>]*)\/?>/gi,
        (_match, attrs) => {
            const height = extractAttr(attrs, 'height') || '20px';
            return `<div style="height:${height}"></div>`;
        }
    );
    
    // Convert MJML social elements
    content = content.replace(
        /<mj-social([^>]*)>([\s\S]*?)<\/mj-social>/gi,
        (_match, _attrs, inner) => {
            return `<div style="text-align:center;padding:10px 0">${inner}</div>`;
        }
    );
    
    content = content.replace(
        /<mj-social-element([^>]*)>([\s\S]*?)<\/mj-social-element>/gi,
        (_match, attrs, inner) => {
            const href = extractAttr(attrs, 'href') || '#';
            const src = extractAttr(attrs, 'src') || '';
            const name = extractAttr(attrs, 'name') || '';
            const iconSize = extractAttr(attrs, 'icon-size') || '24px';
            
            // Use inline SVG icons for common social networks
            const icon = src || getSocialIcon(name);
            return `<a href="${href}" style="display:inline-block;margin:0 8px;text-decoration:none"><img src="${icon}" alt="${inner || name}" style="width:${iconSize};height:${iconSize}" /></a>`;
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
    
    return { html, errors };
}

function extractAttr(attrs: string, name: string): string | undefined {
    const match = attrs.match(new RegExp(`${name}="([^"]*)"`, 'i'));
    return match?.[1];
}

function getSocialIcon(name: string): string {
    // Return placeholder data URIs for common social networks
    const icons: Record<string, string> = {
        'facebook': 'https://cdn.jsdelivr.net/npm/simple-icons@v9/icons/facebook.svg',
        'twitter': 'https://cdn.jsdelivr.net/npm/simple-icons@v9/icons/twitter.svg',
        'linkedin': 'https://cdn.jsdelivr.net/npm/simple-icons@v9/icons/linkedin.svg',
        'instagram': 'https://cdn.jsdelivr.net/npm/simple-icons@v9/icons/instagram.svg',
        'youtube': 'https://cdn.jsdelivr.net/npm/simple-icons@v9/icons/youtube.svg',
    };
    return icons[name.toLowerCase()] || '';
}

// ============================================================================
// Handlebars Setup
// ============================================================================

/**
 * Create a configured Handlebars instance with safe defaults
 */
function createHandlebarsInstance(options?: TemplateRenderOptions): typeof Handlebars {
    const hbs = Handlebars.create();
    
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
    
    // Default value helper
    hbs.registerHelper('default', (value: unknown, defaultValue: unknown) => value ?? defaultValue);
}

// ============================================================================
// Template Engine Class
// ============================================================================

export class TemplateEngine {
    private handlebars: typeof Handlebars;
    private options: TemplateRenderOptions;
    
    constructor(options?: TemplateRenderOptions) {
        this.options = options || {};
        this.handlebars = createHandlebarsInstance(options);
    }
    
    /**
     * Render a template with context data
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
        
        // Step 2: Process Handlebars variables
        try {
            const compiled = this.handlebars.compile(html, {
                strict: opts.strict,
                noEscape: false, // HTML escape by default for security
            });
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
