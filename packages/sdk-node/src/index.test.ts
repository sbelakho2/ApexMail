import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApexMail, ValidationError, AuthenticationError, RateLimitError, ApexMailError, NotFoundError, ForbiddenError, ConflictError } from './index.js';

// Mock fetch
const mockFetch = vi.fn();

// Valid test API key (32+ alphanumeric chars after am_test_)
const VALID_TEST_KEY = 'am_test_abcdefghij1234567890abcdefghij1234567890';

describe('ApexMail SDK', () => {
    let client: ApexMail;

    beforeEach(() => {
        mockFetch.mockReset();
        client = new ApexMail({
            apiKey: VALID_TEST_KEY,
            fetch: mockFetch as unknown as typeof fetch,
        });
    });

    describe('Constructor', () => {
        it('should accept API key string', () => {
            const sdk = new ApexMail(VALID_TEST_KEY);
            expect(sdk).toBeInstanceOf(ApexMail);
        });

        it('should accept config object', () => {
            const sdk = new ApexMail({
                apiKey: VALID_TEST_KEY,
                baseUrl: 'https://custom.api.com',
                timeout: 5000,
            });
            expect(sdk).toBeInstanceOf(ApexMail);
        });

        it('should throw on missing API key', () => {
            expect(() => new ApexMail({ apiKey: '' })).toThrow(ValidationError);
        });

        it('should throw on invalid API key format', () => {
            expect(() => new ApexMail('invalid_key')).toThrow(ValidationError);
        });

        it('should expose all resource APIs', () => {
            const sdk = new ApexMail(VALID_TEST_KEY);
            expect(sdk.emails).toBeDefined();
            expect(sdk.domains).toBeDefined();
            expect(sdk.apiKeys).toBeDefined();
            expect(sdk.webhooks).toBeDefined();
            expect(sdk.analytics).toBeDefined();
        });
    });

    describe('Emails API', () => {
        it('should send email with minimal options', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'email_123', status: 'queued' }),
            });

            const result = await client.emails.send({
                from: 'hello@example.com',
                to: 'user@example.com',
                subject: 'Test',
                html: '<p>Hello</p>',
            });

            expect(result.id).toBe('email_123');
            expect(result.status).toBe('queued');
            expect(mockFetch).toHaveBeenCalledWith(
                'https://api.apexmail.ee/v1/emails',
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Authorization': `Bearer ${VALID_TEST_KEY}`,
                        'Content-Type': 'application/json',
                    }),
                })
            );
        });

        it('should send email with full options', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'email_456', status: 'queued' }),
            });

            const result = await client.emails.send({
                from: { email: 'hello@example.com', name: 'Hello' },
                to: [
                    { email: 'user1@example.com', name: 'User 1' },
                    'user2@example.com',
                ],
                cc: 'cc@example.com',
                bcc: 'bcc@example.com',
                replyTo: 'reply@example.com',
                subject: 'Test Email',
                html: '<h1>Hello</h1>',
                text: 'Hello',
                attachments: [
                    {
                        filename: 'test.txt',
                        content: 'SGVsbG8gV29ybGQ=', // base64
                        contentType: 'text/plain',
                    },
                ],
                headers: { 'X-Custom': 'value' },
                tags: [{ name: 'category', value: 'test' }],
                scheduledAt: new Date('2024-01-15T10:00:00Z'),
            });

            expect(result.id).toBe('email_456');
        });

        it('should send batch emails', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    ids: ['email_1', 'email_2'],
                    successCount: 2,
                    failureCount: 0,
                }),
            });

            const result = await client.emails.batch({
                emails: [
                    { from: 'a@example.com', to: 'b@example.com', subject: 'Test 1', html: '<p>1</p>' },
                    { from: 'a@example.com', to: 'c@example.com', subject: 'Test 2', html: '<p>2</p>' },
                ],
            });

            expect(result.ids).toHaveLength(2);
            expect(result.successCount).toBe(2);
        });

        it('should reject batch over 1000 emails', async () => {
            const emails = Array.from({ length: 1001 }, (_, i) => ({
                from: 'a@example.com',
                to: `user${i}@example.com`,
                subject: 'Test',
                html: '<p>Hi</p>',
            }));

            await expect(client.emails.batch({ emails })).rejects.toThrow(ValidationError);
        });

        it('should get email by ID', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'email_123',
                    status: 'delivered',
                    from: { email: 'hello@example.com' },
                    to: [{ email: 'user@example.com' }],
                    subject: 'Test',
                    createdAt: '2024-01-01T00:00:00Z',
                }),
            });

            const email = await client.emails.get('email_123');

            expect(email.id).toBe('email_123');
            expect(email.status).toBe('delivered');
        });

        it('should list emails with filters', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    data: [{ id: 'email_1' }, { id: 'email_2' }],
                    hasMore: true,
                    cursor: 'cursor_abc',
                }),
            });

            const result = await client.emails.list({
                status: 'delivered',
                limit: 50,
                tag: 'welcome',
            });

            expect(result.data).toHaveLength(2);
            expect(result.hasMore).toBe(true);
            expect(mockFetch).toHaveBeenCalledWith(
                expect.stringContaining('status=delivered'),
                expect.anything()
            );
        });

        it('should cancel scheduled email', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({}),
            });

            await client.emails.cancel('email_123');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://api.apexmail.ee/v1/emails/email_123/cancel',
                expect.objectContaining({ method: 'POST' })
            );
        });
    });

    describe('Domains API', () => {
        it('should create domain', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'domain_123',
                    domain: 'example.com',
                    status: 'pending',
                    dnsRecords: [],
                }),
            });

            const domain = await client.domains.create({ domain: 'example.com' });

            expect(domain.id).toBe('domain_123');
            expect(domain.domain).toBe('example.com');
        });

        it('should verify domain', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'domain_123',
                    status: 'verified',
                }),
            });

            const domain = await client.domains.verify('domain_123');

            expect(domain.status).toBe('verified');
        });

        it('should list domains', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    data: [{ id: 'domain_1' }, { id: 'domain_2' }],
                }),
            });

            const { data } = await client.domains.list();

            expect(data).toHaveLength(2);
        });
    });

    describe('Webhooks API', () => {
        it('should create webhook', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'webhook_123',
                    url: 'https://example.com/webhook',
                    events: ['email.delivered'],
                    active: true,
                    secret: 'whsec_xxx',
                }),
            });

            const webhook = await client.webhooks.create({
                url: 'https://example.com/webhook',
                events: ['email.delivered'],
            });

            expect(webhook.id).toBe('webhook_123');
            expect(webhook.secret).toBeDefined();
        });

        it('should update webhook', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'webhook_123',
                    events: ['email.bounced'],
                }),
            });

            const webhook = await client.webhooks.update('webhook_123', {
                events: ['email.bounced'],
            });

            expect(webhook.events).toContain('email.bounced');
        });
    });

    describe('Analytics API', () => {
        it('should get analytics', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    sent: 1000,
                    delivered: 980,
                    opened: 500,
                    clicked: 100,
                    bounced: 20,
                    complained: 5,
                    deliveryRate: 0.98,
                    openRate: 0.51,
                    clickRate: 0.102,
                    bounceRate: 0.02,
                }),
            });

            const analytics = await client.analytics.get({
                from: '2024-01-01',
                to: '2024-01-31',
                groupBy: 'day',
            });

            expect(analytics.sent).toBe(1000);
            expect(analytics.deliveryRate).toBe(0.98);
        });
    });

    describe('Error Handling', () => {
        it('should throw ValidationError on 400', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 400,
                json: async () => ({
                    message: 'Invalid email format',
                    code: 'VALIDATION_ERROR',
                    details: { field: 'to' },
                }),
            });

            await expect(client.emails.send({
                from: 'a@example.com',
                to: 'invalid',
                subject: 'Test',
                html: '<p>Hi</p>',
            })).rejects.toThrow(ValidationError);
        });

        it('should throw AuthenticationError on 401', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                json: async () => ({ message: 'Invalid API key' }),
            });

            await expect(client.emails.send({
                from: 'a@example.com',
                to: 'b@example.com',
                subject: 'Test',
                html: '<p>Hi</p>',
            })).rejects.toThrow(AuthenticationError);
        });

        it('should throw ForbiddenError on 403', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 403,
                json: async () => ({ message: 'Forbidden' }),
            });

            await expect(client.emails.send({
                from: 'a@example.com',
                to: 'b@example.com',
                subject: 'Test',
                html: '<p>Hi</p>',
            })).rejects.toThrow(ForbiddenError);
        });

        it('should throw NotFoundError on 404', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 404,
                json: async () => ({ message: 'Not found' }),
            });

            await expect(client.emails.get('nonexistent')).rejects.toThrow(NotFoundError);
        });

        it('should throw ConflictError on 409', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 409,
                json: async () => ({ message: 'Conflict' }),
            });

            await expect(client.domains.create({ domain: 'existing.com' })).rejects.toThrow(ConflictError);
        });

        it('should throw RateLimitError on 429 with retryAfter', async () => {
            // Mock 4 responses (initial + 3 retries) since SDK has retry logic
            const mockResponse = {
                ok: false,
                status: 429,
                headers: { get: (name: string) => name === 'Retry-After' ? '1' : null },
                json: async () => ({ message: 'Rate limited' }),
            };
            mockFetch
                .mockResolvedValueOnce(mockResponse)
                .mockResolvedValueOnce(mockResponse)
                .mockResolvedValueOnce(mockResponse)
                .mockResolvedValueOnce(mockResponse);

            try {
                await client.emails.send({
                    from: 'a@example.com',
                    to: 'b@example.com',
                    subject: 'Test',
                    html: '<p>Hi</p>',
                });
                expect.fail('Expected RateLimitError to be thrown');
            } catch (error) {
                expect(error).toBeInstanceOf(RateLimitError);
                expect((error as RateLimitError).retryAfter).toBe(1);
            }
        }, 15000); // Increase timeout for retries

        it('should throw ApexMailError on other errors', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
                json: async () => ({ message: 'Internal server error', code: 'SERVER_ERROR' }),
            });

            await expect(client.emails.send({
                from: 'a@example.com',
                to: 'b@example.com',
                subject: 'Test',
                html: '<p>Hi</p>',
            })).rejects.toThrow(ApexMailError);
        });
    });
});
