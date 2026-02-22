/**
 * Lead Verification Service
 * Rigorously validates and verifies company information before storage
 *
 * Validates:
 * - Company names (format, length, suspicious patterns)
 * - Email addresses (format, MX verification, disposable detection)
 * - Websites (URL format, accessibility, domain extraction)
 * - Domains (DNS existence, parked domain detection)
 */

import { Resolver } from 'node:dns/promises';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'lead-verifier', level: 'info' });

const resolver = new Resolver();
resolver.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface VerificationResult {
    isValid: boolean;
    confidence: number; // 0-100
    issues: string[];
    sanitized: {
        companyName: string | null;
        domain: string | null;
        website: string | null;
        email: string | null;
    };
    checks: {
        companyName: CheckResult;
        domain: CheckResult;
        website: CheckResult;
        email: CheckResult;
    };
}

export interface CheckResult {
    passed: boolean;
    score: number; // 0-100
    issues: string[];
    details?: Record<string, unknown>;
}

export interface CompanyData {
    name?: string | null;
    domain?: string | null;
    website?: string | null;
    email?: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Disposable/Temporary Email Domains
// ─────────────────────────────────────────────────────────────────────────────

const DISPOSABLE_EMAIL_DOMAINS = new Set([
    '10minutemail.com', 'guerrillamail.com', 'guerrillamail.org', 'tempmail.com',
    'temp-mail.org', 'throwaway.email', 'mailinator.com', 'yopmail.com',
    'fakeinbox.com', 'trashmail.com', 'sharklasers.com', 'spam4.me',
    'dispostable.com', 'getairmail.com', 'mailnesia.com', 'tempinbox.com',
    'getnada.com', 'burnermail.io', 'maildrop.cc', 'mohmal.com',
    'emailondeck.com', 'tempmailaddress.com', 'crazymailing.com',
    'tmail.ws', 'harakirimail.com', 'mintemail.com', 'mailcatch.com',
]);

// ─────────────────────────────────────────────────────────────────────────────
// Suspicious Company Name Patterns
// ─────────────────────────────────────────────────────────────────────────────

const SUSPICIOUS_NAME_PATTERNS = [
    /^test\s*company/i,
    /^demo\s/i,
    /^example\s/i,
    /^sample\s/i,
    /^fake\s/i,
    /^placeholder/i,
    /^\d+$/, // All numbers
    /^[a-z]$/i, // Single letter
    /lorem\s*ipsum/i,
    /asdf|qwerty/i,
    /^xxx+$/i,
    /^n\/a$|^na$|^none$/i,
    /^unknown$/i,
    /^company\s*name$/i,
    /^your\s*company$/i,
];

// ─────────────────────────────────────────────────────────────────────────────
// Parked Domain Indicators
// ─────────────────────────────────────────────────────────────────────────────

const PARKED_DOMAIN_PATTERNS = [
    'sedoparking.com',
    'parkingcrew.net',
    'domainmarket.com',
    'afternic.com',
    'godaddy.com/domain',
    'hugedomains.com',
    'dan.com',
    'undeveloped.com',
    'parked-content.godaddy.com',
    'bodis.com',
];

// ─────────────────────────────────────────────────────────────────────────────
// Company Name Verification
// ─────────────────────────────────────────────────────────────────────────────

export function verifyCompanyName(name?: string | null): CheckResult {
    const issues: string[] = [];
    let score = 100;

    if (!name || typeof name !== 'string') {
        return {
            passed: false,
            score: 0,
            issues: ['Company name is missing'],
        };
    }

    const trimmed = name.trim();

    // Length checks
    if (trimmed.length < 2) {
        issues.push('Company name too short (min 2 characters)');
        score -= 50;
    }
    if (trimmed.length > 200) {
        issues.push('Company name too long (max 200 characters)');
        score -= 20;
    }

    // Suspicious pattern checks
    for (const pattern of SUSPICIOUS_NAME_PATTERNS) {
        if (pattern.test(trimmed)) {
            issues.push(`Suspicious pattern detected: ${pattern.source}`);
            score -= 40;
            break;
        }
    }

    // Check for excessive special characters
    const specialCharRatio = (trimmed.match(/[^a-zA-Z0-9\s&.,'-]/g) || []).length / trimmed.length;
    if (specialCharRatio > 0.3) {
        issues.push('Excessive special characters in company name');
        score -= 30;
    }

    // Check for all caps (might be acronym or placeholder)
    if (trimmed.length > 5 && trimmed === trimmed.toUpperCase() && !/\s/.test(trimmed)) {
        issues.push('All uppercase name may be placeholder');
        score -= 10;
    }

    // Check for repeated characters
    if (/(.)\1{4,}/.test(trimmed)) {
        issues.push('Repeated characters detected');
        score -= 40;
    }

    return {
        passed: score >= 50,
        score: Math.max(0, score),
        issues,
        details: {
            original: name,
            sanitized: sanitizeCompanyName(trimmed),
            length: trimmed.length,
        },
    };
}

function sanitizeCompanyName(name: string): string {
    return name
        .replace(/\s+/g, ' ') // Normalize whitespace
        .replace(/[^\w\s&.,'-]/g, '') // Remove unusual characters
        .trim()
        .slice(0, 200); // Enforce max length
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Verification
// ─────────────────────────────────────────────────────────────────────────────

export async function verifyDomain(domain?: string | null): Promise<CheckResult> {
    const issues: string[] = [];
    let score = 100;

    if (!domain || typeof domain !== 'string') {
        return {
            passed: false,
            score: 0,
            issues: ['Domain is missing'],
        };
    }

    const sanitized = sanitizeDomain(domain);

    // Format validation
    const domainRegex = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z]{2,})+$/;
    if (!domainRegex.test(sanitized)) {
        issues.push('Invalid domain format');
        score -= 50;
    }

    // Check for localhost/test domains
    const testDomains = ['localhost', 'example.com', 'test.com', 'invalid.', '.local', '.test', '.invalid'];
    for (const testDomain of testDomains) {
        if (sanitized.includes(testDomain)) {
            issues.push(`Test/invalid domain detected: ${testDomain}`);
            score -= 60;
        }
    }

    // DNS existence check
    if (score >= 50) {
        try {
            // Check if domain has any DNS records
            const [hasA, hasMx] = await Promise.all([
                checkDnsRecord(sanitized, 'A'),
                checkDnsRecord(sanitized, 'MX'),
            ]);

            if (!hasA && !hasMx) {
                issues.push('Domain has no DNS records (may not exist)');
                score -= 40;
            } else if (!hasA) {
                issues.push('Domain has no A record (website may not exist)');
                score -= 10;
            }

            // Check for parked domain (via nameservers)
            const isParked = await checkIfDomainParked(sanitized);
            if (isParked) {
                issues.push('Domain appears to be parked/for sale');
                score -= 30;
            }
        } catch (error) {
            issues.push(`DNS lookup failed: ${(error as Error).message}`);
            score -= 20;
        }
    }

    return {
        passed: score >= 50,
        score: Math.max(0, score),
        issues,
        details: {
            original: domain,
            sanitized,
        },
    };
}

function sanitizeDomain(domain: string): string {
    return domain
        .toLowerCase()
        .trim()
        .replace(/^(https?:\/\/)?(www\.)?/, '') // Remove protocol and www
        .replace(/\/.*$/, '') // Remove path
        .replace(/[^a-z0-9.-]/g, ''); // Remove invalid characters
}

async function checkDnsRecord(domain: string, type: 'A' | 'MX' | 'TXT' | 'NS'): Promise<boolean> {
    try {
        switch (type) {
            case 'A':
                await resolver.resolve4(domain);
                return true;
            case 'MX':
                await resolver.resolveMx(domain);
                return true;
            case 'TXT':
                await resolver.resolveTxt(domain);
                return true;
            case 'NS':
                await resolver.resolveNs(domain);
                return true;
            default:
                return false;
        }
    } catch {
        return false;
    }
}

async function checkIfDomainParked(domain: string): Promise<boolean> {
    try {
        const nsRecords = await resolver.resolveNs(domain);
        const nsString = nsRecords.join(' ').toLowerCase();

        for (const pattern of PARKED_DOMAIN_PATTERNS) {
            if (nsString.includes(pattern)) {
                return true;
            }
        }

        // Additional check: CNAME to parking services
        try {
            const cname = await resolver.resolveCname(domain);
            const cnameString = cname.join(' ').toLowerCase();
            for (const pattern of PARKED_DOMAIN_PATTERNS) {
                if (cnameString.includes(pattern)) {
                    return true;
                }
            }
        } catch {
            // No CNAME is fine
        }

        return false;
    } catch {
        return false; // Can't determine, assume not parked
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Website Verification
// ─────────────────────────────────────────────────────────────────────────────

export async function verifyWebsite(website?: string | null): Promise<CheckResult> {
    const issues: string[] = [];
    let score = 100;

    if (!website || typeof website !== 'string') {
        return {
            passed: false,
            score: 0,
            issues: ['Website URL is missing'],
        };
    }

    const sanitized = sanitizeWebsiteUrl(website);

    // URL format validation
    try {
        const url = new URL(sanitized);

        // Check protocol
        if (!['http:', 'https:'].includes(url.protocol)) {
            issues.push(`Invalid protocol: ${url.protocol}`);
            score -= 40;
        }

        // Check for localhost/test URLs
        if (['localhost', '127.0.0.1', '0.0.0.0'].includes(url.hostname)) {
            issues.push('Localhost URL detected');
            score -= 60;
        }

        // Check for IP address URLs (less trustworthy)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) {
            issues.push('IP address URL (less trustworthy)');
            score -= 20;
        }

        // HTTP accessibility check (with timeout)
        if (score >= 50) {
            const isAccessible = await checkWebsiteAccessibility(sanitized);
            if (!isAccessible) {
                issues.push('Website not accessible (may be down or blocked)');
                score -= 15; // Don't penalize too heavily, could be temporary
            }
        }
    } catch {
        issues.push('Invalid URL format');
        score -= 50;
    }

    return {
        passed: score >= 50,
        score: Math.max(0, score),
        issues,
        details: {
            original: website,
            sanitized,
        },
    };
}

function sanitizeWebsiteUrl(url: string): string {
    let sanitized = url.trim();

    // Add protocol if missing
    if (!sanitized.match(/^https?:\/\//i)) {
        sanitized = `https://${sanitized}`;
    }

    // Normalize protocol to lowercase
    sanitized = sanitized.replace(/^HTTP/i, 'http');

    return sanitized;
}

async function checkWebsiteAccessibility(url: string): Promise<boolean> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(url, {
            method: 'HEAD',
            signal: controller.signal,
            redirect: 'follow',
            headers: {
                'User-Agent': 'ApexMail-LeadVerifier/1.0',
            },
        });

        clearTimeout(timeoutId);

        // Accept 2xx and 3xx status codes
        return response.status >= 200 && response.status < 400;
    } catch {
        return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Verification
// ─────────────────────────────────────────────────────────────────────────────

export async function verifyEmail(email?: string | null): Promise<CheckResult> {
    const issues: string[] = [];
    let score = 100;

    if (!email || typeof email !== 'string') {
        return {
            passed: true, // Email is optional
            score: 0,
            issues: ['Email is missing (optional field)'],
        };
    }

    const sanitized = email.trim().toLowerCase();

    // Format validation (RFC 5322 simplified)
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!emailRegex.test(sanitized)) {
        issues.push('Invalid email format');
        return {
            passed: false,
            score: 0,
            issues,
        };
    }

    const parts = sanitized.split('@');
    const localPart = parts[0] ?? '';
    const domain = parts[1] ?? '';

    if (!localPart || !domain) {
        issues.push('Invalid email structure');
        return {
            passed: false,
            score: 0,
            issues,
        };
    }

    // Local part checks
    if (localPart.length > 64) {
        issues.push('Local part too long (max 64 characters)');
        score -= 30;
    }

    // Check for common placeholder emails
    const placeholderPatterns = [
        /^test@/i, /^demo@/i, /^example@/i, /^sample@/i,
        /^admin@example/i, /^user@example/i, /^noreply/i,
        /^no-reply/i, /^donotreply/i, /^fake@/i,
    ];
    for (const pattern of placeholderPatterns) {
        if (pattern.test(sanitized)) {
            issues.push('Placeholder/test email detected');
            score -= 40;
            break;
        }
    }

    // Check for disposable email domains
    if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
        issues.push('Disposable/temporary email domain');
        score -= 50;
    }

    // Check for common role-based emails (less valuable for outreach)
    const roleBasedPrefixes = [
        'info', 'contact', 'support', 'sales', 'hello', 'help',
        'admin', 'webmaster', 'postmaster', 'hostmaster',
    ];
    if (roleBasedPrefixes.some((prefix) => localPart === prefix || localPart.startsWith(`${prefix}.`))) {
        issues.push('Role-based email (may have lower response rate)');
        score -= 10; // Minor penalty, still useful
    }

    // MX record verification for email domain
    if (score >= 50) {
        try {
            const hasMx = await checkDnsRecord(domain, 'MX');
            if (!hasMx) {
                issues.push('Email domain has no MX records');
                score -= 40;
            }
        } catch {
            issues.push('Could not verify email domain MX records');
            score -= 10;
        }
    }

    return {
        passed: score >= 50,
        score: Math.max(0, score),
        issues,
        details: {
            original: email,
            sanitized,
            localPart,
            domain,
            isRoleBased: roleBasedPrefixes.some((p) => localPart === p),
            isDisposable: DISPOSABLE_EMAIL_DOMAINS.has(domain),
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Full Company Verification
// ─────────────────────────────────────────────────────────────────────────────

export async function verifyCompanyData(data: CompanyData): Promise<VerificationResult> {
    logger.debug('Verifying company data', { domain: data.domain, name: data.name });

    const [companyNameResult, domainResult, websiteResult, emailResult] = await Promise.all([
        Promise.resolve(verifyCompanyName(data.name)),
        verifyDomain(data.domain),
        verifyWebsite(data.website),
        verifyEmail(data.email),
    ]);

    const allIssues = [
        ...companyNameResult.issues.map((i) => `[Name] ${i}`),
        ...domainResult.issues.map((i) => `[Domain] ${i}`),
        ...websiteResult.issues.map((i) => `[Website] ${i}`),
        ...emailResult.issues.map((i) => `[Email] ${i}`),
    ];

    // Calculate overall confidence (weighted average)
    const weights = { companyName: 0.25, domain: 0.35, website: 0.25, email: 0.15 };
    const confidence = Math.round(
        companyNameResult.score * weights.companyName +
        domainResult.score * weights.domain +
        websiteResult.score * weights.website +
        emailResult.score * weights.email
    );

    // Overall validity requires at least company name and domain to pass
    const isValid = companyNameResult.passed && domainResult.passed && confidence >= 50;

    const result: VerificationResult = {
        isValid,
        confidence,
        issues: allIssues,
        sanitized: {
            companyName: companyNameResult.details?.sanitized as string ?? null,
            domain: domainResult.details?.sanitized as string ?? null,
            website: websiteResult.details?.sanitized as string ?? null,
            email: emailResult.details?.sanitized as string ?? null,
        },
        checks: {
            companyName: companyNameResult,
            domain: domainResult,
            website: websiteResult,
            email: emailResult,
        },
    };

    logger.info('Company verification complete', {
        domain: data.domain,
        isValid,
        confidence,
        issueCount: allIssues.length,
    });

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch Verification
// ─────────────────────────────────────────────────────────────────────────────

export async function verifyCompanyBatch(
    companies: CompanyData[],
    options: { concurrency?: number; minConfidence?: number } = {}
): Promise<{
    verified: Array<CompanyData & { verification: VerificationResult }>;
    rejected: Array<CompanyData & { verification: VerificationResult }>;
    stats: {
        total: number;
        passed: number;
        rejected: number;
        averageConfidence: number;
        issueBreakdown: Record<string, number>;
    };
}> {
    const concurrency = options.concurrency ?? 5;
    const minConfidence = options.minConfidence ?? 50;

    const verified: Array<CompanyData & { verification: VerificationResult }> = [];
    const rejected: Array<CompanyData & { verification: VerificationResult }> = [];
    const issueBreakdown: Record<string, number> = {};
    let totalConfidence = 0;

    // Process in batches for concurrency control
    for (let i = 0; i < companies.length; i += concurrency) {
        const batch = companies.slice(i, i + concurrency);
        const results = await Promise.all(batch.map((c) => verifyCompanyData(c)));

        for (let j = 0; j < batch.length; j++) {
            const company = batch[j];
            const verification = results[j];

            // Skip if somehow undefined (shouldn't happen)
            if (!company || !verification) continue;

            totalConfidence += verification.confidence;

            // Track issues
            for (const issue of verification.issues) {
                issueBreakdown[issue] = (issueBreakdown[issue] || 0) + 1;
            }

            if (verification.isValid && verification.confidence >= minConfidence) {
                verified.push({ ...company, verification });
            } else {
                rejected.push({ ...company, verification });
            }
        }
    }

    return {
        verified,
        rejected,
        stats: {
            total: companies.length,
            passed: verified.length,
            rejected: rejected.length,
            averageConfidence: companies.length > 0 ? Math.round(totalConfidence / companies.length) : 0,
            issueBreakdown,
        },
    };
}
