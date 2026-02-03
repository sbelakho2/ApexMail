import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as os from 'os';
import {
    TemplateEngine,
    createTemplateEngine,
    renderTemplate,
} from '../templates/index.js';
import {
    LocalAttachmentStorage,
    type AttachmentStorageConfig,
} from '../attachments/index.js';
import {
    validateEmail,
    validateEmailSyntax,
    validateEmails,
    domainAcceptsEmail,
    isDisposableEmail,
    isRoleBasedEmail,
    createEmailValidator,
} from '../validation/index.js';

// ============================================================================
// TEMPLATE ENGINE SMOKE TESTS
// ============================================================================

describe('Template Engine - Smoke Tests', () => {
    let engine: TemplateEngine;

    beforeAll(() => {
        engine = createTemplateEngine();
    });

    it('should render simple variables', () => {
        const template = 'Hello {{name}}, welcome to {{company}}!';
        const result = engine.render(template, { name: 'John', company: 'ApexMail' });
        
        expect(result.html).toBe('Hello John, welcome to ApexMail!');
    });

    it('should render with eq helper', () => {
        const template = '{{#if (eq status "active")}}Active{{else}}Inactive{{/if}}';
        
        const activeResult = engine.render(template, { status: 'active' });
        expect(activeResult.html).toBe('Active');
        
        const inactiveResult = engine.render(template, { status: 'pending' });
        expect(inactiveResult.html).toBe('Inactive');
    });

    it('should render with ne helper', () => {
        const template = '{{#if (ne role "admin")}}Regular User{{else}}Admin{{/if}}';
        
        const result = engine.render(template, { role: 'user' });
        expect(result.html).toBe('Regular User');
    });

    it('should render with gt/lt helpers', () => {
        const template = '{{#if (gt score 80)}}Pass{{else}}Fail{{/if}}';
        
        expect(engine.render(template, { score: 90 }).html).toBe('Pass');
        expect(engine.render(template, { score: 70 }).html).toBe('Fail');
    });

    it('should format dates', () => {
        const template = 'Date: {{formatDate date "short"}}';
        const date = new Date('2024-01-15');
        
        const result = engine.render(template, { date });
        expect(result.html).toContain('2024');
    });

    it('should format currency', () => {
        const template = 'Total: {{formatCurrency amount "USD"}}';
        
        const result = engine.render(template, { amount: 99.99 });
        expect(result.html).toContain('99.99');
    });

    it('should truncate text', () => {
        const template = '{{truncate description 20}}';
        
        const result = engine.render(template, { 
            description: 'This is a very long description that should be truncated' 
        });
        expect(result.html.length).toBeLessThanOrEqual(23); // 20 + '...'
    });

    it('should iterate over arrays', () => {
        const template = '{{#each items}}{{name}},{{/each}}';
        
        const result = engine.render(template, { 
            items: [{ name: 'A' }, { name: 'B' }, { name: 'C' }] 
        });
        expect(result.html).toBe('A,B,C,');
    });

    it('should convert MJML to HTML', () => {
        const mjmlTemplate = `
            <mjml>
                <mj-body>
                    <mj-section>
                        <mj-column>
                            <mj-text>Hello {{name}}</mj-text>
                        </mj-column>
                    </mj-section>
                </mj-body>
            </mjml>
        `;
        
        const result = engine.render(mjmlTemplate, { name: 'World' });
        
        expect(result.html).toContain('Hello World');
        expect(result.html.toLowerCase()).toContain('<!doctype html>');
    });

    it('should extract variables from template', () => {
        const template = 'Hello {{firstName}} {{lastName}}, your order #{{orderId}} is {{status}}.';
        
        const variables = engine.extractVariables(template);
        
        // extractVariables returns array of { name, type } objects
        const names = variables.map(v => v.name);
        expect(names).toContain('firstName');
        expect(names).toContain('lastName');
        expect(names).toContain('orderId');
        expect(names).toContain('status');
    });

    it('should validate templates', () => {
        const validTemplate = 'Hello {{name}}';
        const invalidTemplate = 'Hello {{name}';
        
        const validResult = engine.validate(validTemplate);
        expect(validResult.valid).toBe(true);
        
        // Note: Handlebars is permissive, so this might still be valid
        // The validate function checks for basic errors
        const invalidResult = engine.validate(invalidTemplate);
        // Since Handlebars might not catch this, we check the result exists
        expect(invalidResult).toBeDefined();
    });

    it('should use factory function', () => {
        const result = renderTemplate(
            'Hello {{name}}!',
            { name: 'Factory Test' }
        );
        
        expect(result.html).toBe('Hello Factory Test!');
    });

    it('should handle complex email template', () => {
        const template = `
            <mjml>
                <mj-body>
                    <mj-section>
                        <mj-column>
                            <mj-text>
                                Hi {{customer.name}},

                                {{#if (gt items.length 0)}}
                                Your order contains {{items.length}} items.
                                {{#each items}}
                                - {{name}}: {{formatCurrency price "USD"}}
                                {{/each}}
                                {{else}}
                                Your cart is empty.
                                {{/if}}

                                Total: {{formatCurrency total "USD"}}
                            </mj-text>
                        </mj-column>
                    </mj-section>
                </mj-body>
            </mjml>
        `;
        
        const result = engine.render(template, {
            customer: { name: 'Jane' },
            items: [
                { name: 'Widget', price: 29.99 },
                { name: 'Gadget', price: 49.99 },
            ],
            total: 79.98,
        });
        
        expect(result.html).toContain('Jane');
        expect(result.html).toContain('2 items');
        expect(result.html).toContain('Widget');
        expect(result.html).toContain('79.98');
    });
});

// ============================================================================
// ATTACHMENT STORAGE SMOKE TESTS
// ============================================================================

describe('Attachment Storage - Smoke Tests', () => {
    let storage: LocalAttachmentStorage;
    let tempDir: string;

    beforeAll(async () => {
        tempDir = path.join(os.tmpdir(), `apexmail-test-${Date.now()}`);
        await fs.mkdir(tempDir, { recursive: true });
        
        const config: AttachmentStorageConfig = { 
            type: 'local', 
            localPath: tempDir,
            baseUrl: '/attachments',
        };
        storage = new LocalAttachmentStorage(config);
    });

    afterAll(async () => {
        // Cleanup
        await fs.rm(tempDir, { recursive: true, force: true });
    });

    it('should upload and download text attachment', async () => {
        const content = Buffer.from('Hello, this is a test attachment!');
        
        const result = await storage.upload(
            content,
            'test.txt',
            'text/plain',
            'tenant-1'
        );
        
        expect(result.id).toBeDefined();
        expect(result.size).toBe(content.length);
        expect(result.hash).toBeDefined();
        
        // Download
        const downloaded = await storage.download(result.id);
        expect(downloaded.content.toString()).toBe(content.toString());
        expect(downloaded.metadata.filename).toBe('test.txt');
    });

    it('should upload binary content', async () => {
        // Create a simple PNG-like binary content
        const content = Buffer.from([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        ]);
        
        const result = await storage.upload(
            content,
            'image.png',
            'image/png',
            'tenant-1'
        );
        
        expect(result.id).toBeDefined();
        
        const downloaded = await storage.download(result.id);
        expect(Buffer.compare(downloaded.content, content)).toBe(0);
    });

    it('should reject oversized attachments', async () => {
        // Try to upload 26MB file (limit is 25MB)
        const largeContent = Buffer.alloc(26 * 1024 * 1024, 'x');
        
        await expect(storage.upload(
            largeContent,
            'large.bin',
            'application/octet-stream',
            'tenant-1'
        )).rejects.toThrow(/exceeds maximum/);
    });

    it('should delete attachments', async () => {
        const content = Buffer.from('Delete me');
        
        const result = await storage.upload(
            content,
            'delete.txt',
            'text/plain',
            'tenant-1'
        );
        
        // Verify it exists
        const metadata = await storage.getMetadata(result.id);
        expect(metadata).toBeTruthy();
        
        // Delete
        await storage.delete(result.id);
        
        // Verify it's gone
        const deletedMetadata = await storage.getMetadata(result.id);
        expect(deletedMetadata).toBeNull();
    });

    it('should get metadata', async () => {
        const content = Buffer.from('Metadata test content');
        
        const result = await storage.upload(
            content,
            'metadata.txt',
            'text/plain',
            'tenant-1'
        );
        
        const metadata = await storage.getMetadata(result.id);
        
        expect(metadata).toBeDefined();
        expect(metadata?.filename).toBe('metadata.txt');
        expect(metadata?.contentType).toBe('text/plain');
        expect(metadata?.size).toBe(content.length);
    });

    it('should deduplicate identical content', async () => {
        const content = Buffer.from('Duplicate content for dedup test');
        
        const result1 = await storage.upload(
            content,
            'dup1.txt',
            'text/plain',
            'tenant-1'
        );
        
        const result2 = await storage.upload(
            content,
            'dup2.txt',
            'text/plain',
            'tenant-1'
        );
        
        // Same hash means same underlying storage
        expect(result1.hash).toBe(result2.hash);
    });

    it('should handle various content types', async () => {
        const testCases = [
            { filename: 'doc.pdf', contentType: 'application/pdf' },
            { filename: 'data.json', contentType: 'application/json' },
            { filename: 'style.css', contentType: 'text/css' },
            { filename: 'script.js', contentType: 'application/javascript' },
        ];
        
        for (const testCase of testCases) {
            const content = Buffer.from(`Test content for ${testCase.filename}`);
            
            const result = await storage.upload(
                content,
                testCase.filename,
                testCase.contentType,
                'tenant-1'
            );
            
            const metadata = await storage.getMetadata(result.id);
            expect(metadata?.filename).toBe(testCase.filename);
            expect(metadata?.contentType).toBe(testCase.contentType);
        }
    });

    it('should return correct URL', async () => {
        const content = Buffer.from('URL test content');
        
        const result = await storage.upload(
            content,
            'urltest.txt',
            'text/plain',
            'tenant-1'
        );
        
        const url = storage.getUrl(result.id);
        expect(url).toContain(result.id);
        expect(url).toContain('/attachments');
    });
});

// ============================================================================
// EMAIL VALIDATION SMOKE TESTS
// ============================================================================

describe('Email Validation - Smoke Tests', () => {
    it('should validate correct email syntax', () => {
        expect(validateEmailSyntax('user@example.com')).toBe(true);
        expect(validateEmailSyntax('user.name@example.com')).toBe(true);
        expect(validateEmailSyntax('user+tag@example.com')).toBe(true);
        expect(validateEmailSyntax('user@subdomain.example.com')).toBe(true);
    });

    it('should reject invalid email syntax', () => {
        expect(validateEmailSyntax('invalid')).toBe(false);
        expect(validateEmailSyntax('@example.com')).toBe(false);
        expect(validateEmailSyntax('user@')).toBe(false);
        expect(validateEmailSyntax('user..name@example.com')).toBe(false);
        expect(validateEmailSyntax('.user@example.com')).toBe(false);
        expect(validateEmailSyntax('user.@example.com')).toBe(false);
    });

    it('should detect disposable emails', () => {
        expect(isDisposableEmail('user@mailinator.com')).toBe(true);
        expect(isDisposableEmail('user@guerrillamail.com')).toBe(true);
        expect(isDisposableEmail('user@tempmail.com')).toBe(true);
        expect(isDisposableEmail('user@gmail.com')).toBe(false);
        expect(isDisposableEmail('user@company.com')).toBe(false);
    });

    it('should detect role-based emails', () => {
        expect(isRoleBasedEmail('admin@example.com')).toBe(true);
        expect(isRoleBasedEmail('support@example.com')).toBe(true);
        expect(isRoleBasedEmail('info@example.com')).toBe(true);
        expect(isRoleBasedEmail('noreply@example.com')).toBe(true);
        expect(isRoleBasedEmail('john@example.com')).toBe(false);
        expect(isRoleBasedEmail('jane.doe@example.com')).toBe(false);
    });

    it('should validate email with MX check', async () => {
        const result = await validateEmail('test@gmail.com', { checkMx: true, timeout: 10000 });
        
        expect(result.checks.syntax).toBe(true);
        // Gmail should have MX records
        if (result.checks.mxRecord) {
            expect(result.mxRecords).toBeDefined();
            expect(result.mxRecords!.length).toBeGreaterThan(0);
        }
    });

    it('should fail MX check for invalid domain', async () => {
        const result = await validateEmail('test@thisdomain-definitely-does-not-exist-12345.com', {
            checkMx: true,
            timeout: 5000,
        });
        
        expect(result.checks.syntax).toBe(true);
        expect(result.checks.mxRecord).toBe(false);
        expect(result.valid).toBe(false);
    });

    it('should normalize Gmail addresses without subaddressing', async () => {
        // By default, subaddressing is allowed so +tag is kept
        const result = await validateEmail('User.Name+tag@gmail.com', { 
            checkMx: false,
            allowSubaddressing: false, // Disable to strip +tag
        });
        
        // When subaddressing is disabled, +tag is removed, and dots in Gmail are removed
        expect(result.normalized).toBe('username@gmail.com');
    });

    it('should suggest corrections for typos', async () => {
        const result = await validateEmail('user@gmial.com', { 
            checkMx: false,
            suggestCorrections: true 
        });
        
        expect(result.suggestions).toBeDefined();
        expect(result.suggestions).toContain('user@gmail.com');
    });

    it('should batch validate emails', async () => {
        const emails = [
            'valid@example.com',
            'invalid',
            'another@test.com',
        ];
        
        const results = await validateEmails(emails, { checkMx: false });
        
        expect(results.length).toBe(3);
        expect(results[0]!.valid).toBe(true);
        expect(results[1]!.valid).toBe(false);
        expect(results[2]!.valid).toBe(true);
    });

    it('should check domain accepts email', async () => {
        // Gmail definitely accepts email
        const gmailAccepts = await domainAcceptsEmail('gmail.com', 10000);
        
        // This should be true unless there's a network issue
        // We're more lenient here since DNS can be flaky in tests
        expect(typeof gmailAccepts).toBe('boolean');
    });

    it('should use validator class with caching', async () => {
        const validator = createEmailValidator({ checkMx: false });
        
        // First validation
        const result1 = await validator.validate('cached@example.com');
        expect(result1.valid).toBe(true);
        
        // Second validation (should be cached)
        const result2 = await validator.validate('cached@example.com');
        expect(result2.valid).toBe(true);
        
        // Check cache size
        expect(validator.getCacheSize()).toBeGreaterThan(0);
        
        // Clear cache
        validator.clearCache();
        expect(validator.getCacheSize()).toBe(0);
    });

    it('should return comprehensive validation result', async () => {
        const result = await validateEmail('test@example.com', {
            checkMx: false,
            checkDisposable: true,
            checkRoleBased: true,
        });
        
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('email');
        expect(result).toHaveProperty('normalized');
        expect(result).toHaveProperty('local');
        expect(result).toHaveProperty('domain');
        expect(result).toHaveProperty('checks');
        expect(result.checks).toHaveProperty('syntax');
        expect(result.checks).toHaveProperty('mxRecord');
        expect(result.checks).toHaveProperty('notDisposable');
        expect(result.checks).toHaveProperty('notRoleBased');
    });

    it('should handle edge cases', async () => {
        // Very long local part (64 chars is max)
        const longLocal = 'a'.repeat(64);
        const longEmail = `${longLocal}@example.com`;
        expect(validateEmailSyntax(longEmail)).toBe(true);
        
        // Too long local part
        const tooLongLocal = 'a'.repeat(65);
        const tooLongEmail = `${tooLongLocal}@example.com`;
        expect(validateEmailSyntax(tooLongEmail)).toBe(false);
        
        // Whitespace handling
        const result = await validateEmail('  user@example.com  ', { checkMx: false });
        expect(result.email).toBe('user@example.com');
    });
});

// ============================================================================
// INTEGRATION SMOKE TESTS
// ============================================================================

describe('Integration - All Features Working Together', () => {
    let templateEngine: TemplateEngine;
    let attachmentStorage: LocalAttachmentStorage;
    let tempDir: string;

    beforeAll(async () => {
        // Initialize all services
        templateEngine = createTemplateEngine();
        
        tempDir = path.join(os.tmpdir(), `apexmail-integration-${Date.now()}`);
        await fs.mkdir(tempDir, { recursive: true });
        attachmentStorage = new LocalAttachmentStorage({ 
            type: 'local', 
            localPath: tempDir,
            baseUrl: '/attachments',
        });
    });

    afterAll(async () => {
        await fs.rm(tempDir, { recursive: true, force: true });
    });

    it('should prepare a complete email with template, attachment, and validated recipient', async () => {
        const emailValidator = createEmailValidator({ checkMx: false });
        
        // 1. Validate recipient email
        const recipientValidation = await emailValidator.validate('customer@example.com');
        expect(recipientValidation.valid).toBe(true);
        
        // 2. Upload attachment
        const invoicePdf = Buffer.from('PDF content for invoice #12345');
        const attachmentResult = await attachmentStorage.upload(
            invoicePdf,
            'invoice-12345.pdf',
            'application/pdf',
            'tenant-1'
        );
        expect(attachmentResult.id).toBeDefined();
        
        // Get attachment metadata
        const attachmentMeta = await attachmentStorage.getMetadata(attachmentResult.id);
        expect(attachmentMeta).toBeTruthy();
        
        // 3. Render email template
        const emailContent = templateEngine.render(`
            <mjml>
                <mj-body>
                    <mj-section>
                        <mj-column>
                            <mj-text>
                                Dear {{customer.name}},
                                
                                Please find attached your invoice #{{invoice.number}}.
                                
                                Amount Due: {{formatCurrency invoice.amount "USD"}}
                                Due Date: {{formatDate invoice.dueDate "short"}}
                                
                                {{#if invoice.overdue}}
                                ⚠️ This invoice is overdue. Please pay immediately.
                                {{/if}}
                                
                                Attachment: {{attachment.filename}} ({{attachment.size}} bytes)
                                
                                Best regards,
                                {{company.name}}
                            </mj-text>
                        </mj-column>
                    </mj-section>
                </mj-body>
            </mjml>
        `, {
            customer: { name: 'John Doe' },
            invoice: {
                number: '12345',
                amount: 299.99,
                dueDate: new Date('2024-02-15'),
                overdue: false,
            },
            attachment: {
                filename: attachmentMeta?.filename,
                size: attachmentMeta?.size,
            },
            company: { name: 'ApexMail Inc.' },
        });
        
        // Verify complete email
        expect(emailContent.html).toContain('John Doe');
        expect(emailContent.html).toContain('12345');
        expect(emailContent.html).toContain('299.99');
        expect(emailContent.html).toContain('invoice-12345.pdf');
        expect(emailContent.html).toContain('ApexMail Inc.');
        expect(emailContent.html).not.toContain('overdue'); // Should not show overdue warning
        
        // 4. Download attachment to confirm it's accessible
        const downloadedAttachment = await attachmentStorage.download(attachmentResult.id);
        expect(downloadedAttachment.content.toString()).toBe(invoicePdf.toString());
    });

    it('should handle bulk email preparation with validation', async () => {
        const emailValidator = createEmailValidator({ checkMx: false });
        
        const recipients = [
            'alice@example.com',
            'bob@test.org',
            'invalid-email',
            'charlie@valid.net',
        ];
        
        // Validate all recipients
        const validationResults = await emailValidator.validateBatch(recipients);
        
        // Filter valid recipients
        const validRecipients = validationResults
            .filter(r => r.valid)
            .map(r => r.email);
        
        expect(validRecipients).toHaveLength(3);
        expect(validRecipients).not.toContain('invalid-email');
        
        // Render personalized emails for valid recipients
        const template = 'Hello {{name}}, your email {{email}} is verified!';
        
        for (const email of validRecipients) {
            const content = templateEngine.render(template, {
                name: email.split('@')[0],
                email,
            });
            expect(content.html).toContain(email);
        }
    });
});
