/**
 * Sales Automation System Tests
 * 
 * Tests for the automated sales system:
 * - DNS-based email provider detection
 * - SaaS directory scraping
 * - Campaign template creation
 * - Lead scoring and filtering
 */

import { describe, it, expect, vi } from 'vitest';

// Mock DNS resolver
vi.mock('node:dns/promises', () => ({
    Resolver: vi.fn().mockImplementation(() => ({
        setServers: vi.fn(),
        resolveMx: vi.fn().mockResolvedValue([
            { exchange: 'mx.sendgrid.net', priority: 10 },
        ]),
        resolveTxt: vi.fn().mockResolvedValue([['v=spf1 include:sendgrid.net ~all']]),
    })),
}));

describe('DNS Provider Detection', () => {
    it('should identify SendGrid from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'mx.sendgrid.net', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('SendGrid');
    });

    it('should identify Mailgun from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'mxa.mailgun.org', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Mailgun');
    });

    it('should identify Resend from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'feedback-smtp.resend.dev', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Resend');
    });

    it('should identify Postmark from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'inbound.mtasv.net', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Postmark');
    });

    it('should identify SparkPost from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'mx.sparkpostmail.com', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('SparkPost');
    });

    it('should identify Google Workspace from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'aspmx.l.google.com', priority: 1 },
            { exchange: 'alt1.aspmx.l.google.com', priority: 5 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Google Workspace');
    });

    it('should identify Microsoft 365 from MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'company-com.mail.protection.outlook.com', priority: 0 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Microsoft 365');
    });

    it('should identify self-hosted from generic MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const mxRecords = [
            { exchange: 'mail.company.com', priority: 10 },
        ];
        
        const provider = identifyEmailProvider(mxRecords);
        expect(provider).toBe('Self-Hosted');
    });

    it('should return null for empty MX records', async () => {
        const { identifyEmailProvider } = await import('../scrapers/dns-resolver.js');
        
        const provider = identifyEmailProvider([]);
        expect(provider).toBeNull();
    });
});

describe('Campaign Templates', () => {
    it('should have competitor migration template', async () => {
        const { getTemplate } = await import('../campaigns/templates.js');
        
        const migrationTemplate = getTemplate('tmpl_competitor_migration');
        
        expect(migrationTemplate).not.toBeNull();
        expect(migrationTemplate?.name).toContain('Migration');
        expect(migrationTemplate?.sequence.length).toBeGreaterThanOrEqual(4);
    });

    it('should include deliverability audit offer in migration template', async () => {
        const { getTemplate } = await import('../campaigns/templates.js');
        
        const template = getTemplate('tmpl_competitor_migration');
        
        expect(template).not.toBeNull();
        
        // First touch should be about deliverability audit
        const firstStep = template?.sequence[0];
        expect(firstStep?.content.htmlBody).toContain('audit');
    });

    it('should include webhook migration guide in migration template', async () => {
        const { getTemplate } = await import('../campaigns/templates.js');
        
        const template = getTemplate('tmpl_competitor_migration');
        
        expect(template).not.toBeNull();
        
        // Second touch should be about webhook migration
        const secondStep = template?.sequence[1];
        expect(secondStep?.content.htmlBody).toContain('webhook');
    });

    it('should include free migration support offer', async () => {
        const { getTemplate } = await import('../campaigns/templates.js');
        
        const template = getTemplate('tmpl_competitor_migration');
        
        expect(template).not.toBeNull();
        
        // Last touch should offer free migration support
        const lastStep = template?.sequence[template.sequence.length - 1];
        expect(lastStep?.content.htmlBody).toContain('free migration support');
    });

    it('should have all required template variables', async () => {
        const { getTemplate } = await import('../campaigns/templates.js');
        
        const template = getTemplate('tmpl_competitor_migration');
        
        expect(template).not.toBeNull();
        
        const variableNames = template?.variables.map(v => v.name) || [];
        expect(variableNames).toContain('current_provider');
        expect(variableNames).toContain('audit_link');
        expect(variableNames).toContain('migration_guide_link');
        expect(variableNames).toContain('webhook_guide_link');
    });

    it('should clone template with new IDs', async () => {
        const { cloneTemplate, getTemplate } = await import('../campaigns/templates.js');
        
        const original = getTemplate('tmpl_competitor_migration');
        const cloned = cloneTemplate('tmpl_competitor_migration');
        
        expect(cloned).not.toBeNull();
        expect(cloned?.id).not.toBe(original?.id);
        expect(cloned?.sequence[0]?.id).not.toBe(original?.sequence[0]?.id);
    });
});

describe('Lead Scoring Model', () => {
    it('should calculate lead score', async () => {
        const { calculateLeadScore } = await import('../scrapers/saas-hunter.js');
        
        const company = {
            name: 'Test SaaS Company',
            domain: 'testsaas.io',
            website: 'https://testsaas.io',
            description: 'Email marketing platform',
            category: 'Email Marketing',
            tags: ['saas', 'email'],
            sourceUrl: 'https://producthunt.com',
            source: 'product_hunt' as const,
        };
        
        const score = calculateLeadScore(company, null);
        
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
    });
});

describe('Migration Providers', () => {
    it('should have SendGrid migration data', async () => {
        const { MIGRATION_PROVIDERS } = await import('../campaigns/migration-hub.js');
        
        const sendgrid = MIGRATION_PROVIDERS.find(p => p.slug === 'sendgrid');
        
        expect(sendgrid).toBeDefined();
        expect(sendgrid?.apiMappings.length).toBeGreaterThan(0);
        expect(sendgrid?.codeSnippets.length).toBeGreaterThan(0);
        expect(sendgrid?.gotchas.length).toBeGreaterThan(0);
    });

    it('should have Resend migration data', async () => {
        const { MIGRATION_PROVIDERS } = await import('../campaigns/migration-hub.js');
        
        const resend = MIGRATION_PROVIDERS.find(p => p.slug === 'resend');
        
        expect(resend).toBeDefined();
    });
});

describe('Lead Verification', () => {
    it('should validate company names', async () => {
        const { verifyCompanyName } = await import('../scrapers/lead-verifier.js');
        
        // Valid names
        expect(verifyCompanyName('Stripe').passed).toBe(true);
        expect(verifyCompanyName('Linear').passed).toBe(true);
        expect(verifyCompanyName('Vercel Inc.').passed).toBe(true);
        
        // Invalid names
        expect(verifyCompanyName('').passed).toBe(false);
        expect(verifyCompanyName('A').passed).toBe(false);
        expect(verifyCompanyName('xxxxxxxxx').passed).toBe(false);
    });

    it('should detect disposable emails', async () => {
        const { verifyEmail } = await import('../scrapers/lead-verifier.js');
        
        // Valid emails
        const validResult = await verifyEmail('ceo@stripe.com');
        expect(validResult.passed).toBe(true);
        expect(validResult.score).toBeGreaterThanOrEqual(90);
        
        // Disposable email should be penalized heavily
        const disposableResult = await verifyEmail('user@10minutemail.com');
        expect(disposableResult.score).toBeLessThanOrEqual(50);
        expect(disposableResult.issues.some(i => i.includes('Disposable'))).toBe(true);
    });

    it('should detect invalid domain formats', async () => {
        const { verifyDomain } = await import('../scrapers/lead-verifier.js');
        
        // Valid domains
        const validResult = await verifyDomain('stripe.com');
        expect(validResult.passed).toBe(true);
        
        // Test/invalid domains should fail
        const testResult = await verifyDomain('example.com');
        expect(testResult.passed).toBe(false);
        
        const localhostResult = await verifyDomain('localhost');
        expect(localhostResult.passed).toBe(false);
    });

    it('should verify full company data', async () => {
        const { verifyCompanyData } = await import('../scrapers/lead-verifier.js');
        
        // Valid company
        const validResult = await verifyCompanyData({
            name: 'Stripe',
            domain: 'stripe.com',
            website: 'https://stripe.com',
            email: 'hello@stripe.com',
        });
        
        expect(validResult.isValid).toBe(true);
        expect(validResult.confidence).toBeGreaterThanOrEqual(80);
        expect(validResult.sanitized.companyName).toBe('Stripe');
        expect(validResult.sanitized.domain).toBe('stripe.com');
    });

    it('should reject suspicious company data', async () => {
        const { verifyCompanyData } = await import('../scrapers/lead-verifier.js');
        
        // Invalid company with multiple issues
        const invalidResult = await verifyCompanyData({
            name: 'Test Company',
            domain: 'example.com',
            website: 'http://localhost',
            email: 'test@10minutemail.com',
        });
        
        expect(invalidResult.isValid).toBe(false);
        expect(invalidResult.confidence).toBeLessThan(50);
        expect(invalidResult.issues.length).toBeGreaterThan(0);
    });

    it('should sanitize company data', async () => {
        const { verifyCompanyData } = await import('../scrapers/lead-verifier.js');
        
        const result = await verifyCompanyData({
            name: '  Acme Corp  ',
            domain: 'HTTPS://WWW.ACME.COM/about',
            website: 'acme.com',
        });
        
        // Sanitized values should be cleaned
        expect(result.sanitized.companyName).toBe('Acme Corp');
        expect(result.sanitized.domain).toBe('acme.com');
        expect(result.sanitized.website).toBe('https://acme.com');
    });
});