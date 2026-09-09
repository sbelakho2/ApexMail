<?php

declare(strict_types=1);

namespace ApexMail\Tests;

use ApexMail\Client;
use PHPUnit\Framework\TestCase;

/**
 * Payload contract tests: the wire bodies the SDKs emit must match the
 * server DTOs in api-server/src/routes/*.rs exactly (most of them use
 * serde(deny_unknown_fields), so any extra key is a 422).
 *
 * Ground truth fixtures mirror:
 *  - messages.rs   SendMessageRequest
 *  - webhooks.rs   CreateWebhookRequest / UpdateWebhookRequest
 *  - templates.rs  CreateTemplateRequest / UpdateTemplateRequest
 *  - suppressions.rs CreateSuppressionRequest
 *  - domains.rs    CreateDomainRequest
 *  - auth.rs       CreateApiKeyRequest
 */
final class PayloadContractTest extends TestCase
{
    /**
     * Records requests instead of performing HTTP. Public API surface of
     * Client is reused verbatim so the resource classes serialize exactly
     * what production would send.
     */
    private function recordingClient(): RecordingClient
    {
        return new RecordingClient('am_live_1234567890abcdef');
    }

    public function testSendPayloadMatchesSendMessageRequest(): void
    {
        $client = $this->recordingClient();

        $client->emails->send([
            'from'          => 'hello@example.com',
            'to'            => ['user@example.com', ['email' => 'second@example.com', 'name' => 'Second']],
            'cc'            => ['cc@example.com'],
            'bcc'           => 'bcc@example.com',
            'subject'       => 'Hello!',
            'html'          => '<h1>Hello World</h1>',
            'tags'          => ['welcome', ['name' => 'campaign', 'value' => 'spring']],
            'scheduled_at'  => '2026-09-01T09:00:00Z',
            'metadata'      => ['source' => 'php-sdk-test'],
            // F48: every accepted option must reach the wire.
            'reply_to'      => ['email' => 'reply@example.com', 'name' => 'Replies'],
            'template_id'   => 'tpl_1',
            'template_data' => ['a' => 1],
            'attachments'   => [['filename' => 'a.txt', 'content' => 'eHg=']],
            'priority'      => 'high',
            'headers'       => ['X-Custom' => 'yes'],
        ]);

        $request = $client->requests[0];
        $this->assertSame('POST', $request['method']);
        $this->assertSame('/v1/messages', $request['path']);

        $expected = [
            'from'         => 'hello@example.com',
            'to'           => ['user@example.com', 'Second <second@example.com>'],
            'cc'           => ['cc@example.com'],
            'bcc'          => ['bcc@example.com'],
            'reply_to'     => 'Replies <reply@example.com>',
            'subject'      => 'Hello!',
            'html'         => '<h1>Hello World</h1>',
            'attachments'  => [['filename' => 'a.txt', 'content' => 'eHg=']],
            'headers'      => ['X-Custom' => 'yes'],
            'priority'     => 'high',
            'template_id'  => 'tpl_1',
            'template_data' => ['a' => 1],
            'tags'         => ['welcome', 'campaign=spring'],
            'scheduled_at' => '2026-09-01T09:00:00Z',
            'metadata'     => ['source' => 'php-sdk-test'],
        ];
        $this->assertEqualsCanonicalizing($expected, $request['body']);

        foreach (['replyTo', 'templateId', 'templateData', 'scheduledAt', 'name'] as $rejected) {
            $this->assertArrayNotHasKey($rejected, $request['body'], "{$rejected} must not be serialized");
        }
    }

    public function testSendFromNameObjectKeepsDisplayName(): void
    {
        $client = $this->recordingClient();

        $client->emails->send([
            'from'    => ['email' => 'named@example.com', 'name' => 'Named Sender'],
            'to'      => 'user@example.com',
            'subject' => 'Hi',
            'text'    => 'Hello',
        ]);

        $body = $client->requests[0]['body'];
        // F48: display names survive as "Name <addr>" forms.
        $this->assertSame('Named Sender <named@example.com>', $body['from']);
        $this->assertSame(['user@example.com'], $body['to']);
        $this->assertArrayNotHasKey('name', $body);
    }

    public function testBatchNormalizesEachMessageLikeSend(): void
    {
        $client = $this->recordingClient();

        $client->emails->batch([
            [
                'from'    => 'hello@example.com',
                'to'      => 'user@example.com',
                'subject' => 'Hi',
                'text'    => 'Hello',
                'tags'    => ['batch'],
                'priority' => 'high',
                'reply_to' => 'reply@example.com',
            ],
        ]);

        $request = $client->requests[0];
        $this->assertSame('/v1/messages/batch', $request['path']);
        $this->assertSame([
            'messages' => [
                [
                    'from'     => 'hello@example.com',
                    'to'       => ['user@example.com'],
                    'reply_to' => 'reply@example.com',
                    'subject'  => 'Hi',
                    'text'     => 'Hello',
                    'priority' => 'high',
                    'tags'     => ['batch'],
                ],
            ],
        ], $request['body']);
    }

    public function testWebhookCreateSendsExactlyUrlAndEvents(): void
    {
        $client = $this->recordingClient();

        $client->webhooks->create([
            'url'     => 'https://example.com/hook',
            'events'  => ['message.delivered', 'email.bounced', '*'],
            // Legacy inputs the API rejects — must NOT be sent:
            'name'    => 'my hook',
            'secret'  => 'whsec_legacy',
            'enabled' => true,
        ]);

        $request = $client->requests[0];
        $this->assertSame('/v1/webhooks', $request['path']);
        $this->assertSame([
            'url'    => 'https://example.com/hook',
            'events' => ['message.delivered', 'email.bounced', '*'],
        ], $request['body']);
    }

    public function testWebhookUpdateMapsActiveBooleanToStatus(): void
    {
        $client = $this->recordingClient();

        $client->webhooks->update('wh_1', [
            'url'    => 'https://example.com/hook2',
            'events' => ['message.opened'],
            'active' => false,
        ]);

        $request = $client->requests[0];
        $this->assertSame('PUT', $request['method']);
        $this->assertSame([
            'url'    => 'https://example.com/hook2',
            'events' => ['message.opened'],
            'status' => 'paused',
        ], $request['body']);
    }

    public function testWebhookEventConstantsMatchServerKnownEvents(): void
    {
        // webhooks.rs KNOWN_WEBHOOK_EVENTS
        $expected = [
            'email.delivered', 'email.bounced', 'email.complained',
            'message.sent', 'message.delivered', 'message.bounced',
            'message.complained', 'message.opened', 'message.clicked',
            'recipient.unsubscribed', 'placement_test.completed',
            'bounce', 'complaint', 'inbound', '*',
        ];
        $this->assertSame($expected, \ApexMail\Resources\Webhooks::EVENTS);
    }

    public function testTemplateCreateMapsHtmlAndTextToBodyFields(): void
    {
        $client = $this->recordingClient();

        $client->templates->create([
            'name'    => 'welcome',
            'subject' => 'Welcome!',
            'html'    => '<p>Hi</p>',
            'text'    => 'Hi',
            'slug'    => 'welcome-v1',   // not accepted by the API
            'engine'  => 'handlebars',   // not accepted by the API
        ]);

        $request = $client->requests[0];
        $this->assertSame('/v1/templates', $request['path']);
        $this->assertSame([
            'name'      => 'welcome',
            'subject'   => 'Welcome!',
            'html_body' => '<p>Hi</p>',
            'text_body' => 'Hi',
        ], $request['body']);
    }

    public function testTemplateUpdateSendsOnlyServerFields(): void
    {
        $client = $this->recordingClient();

        $client->templates->update('tpl_1', [
            'subject' => 'New subject',
            'html'    => '<p>New</p>',
            'schema'  => ['type' => 'object'], // not accepted by the API
        ]);

        $request = $client->requests[0];
        $this->assertSame('PUT', $request['method']);
        $this->assertSame([
            'subject'   => 'New subject',
            'html_body' => '<p>New</p>',
        ], $request['body']);
    }

    public function testSuppressionAddSendsSingleEmailBody(): void
    {
        $client = $this->recordingClient();

        $client->suppressions->add('blocked@example.com', 'bounce', ['source' => 'import']);

        $request = $client->requests[0];
        $this->assertSame('/v1/suppressions', $request['path']);
        $this->assertSame([
            'email'  => 'blocked@example.com',
            'reason' => 'bounce',
            'source' => 'import',
        ], $request['body']);
    }

    public function testSuppressionAddArrayOfEmailsPostsOneRequestPerAddress(): void
    {
        $client = $this->recordingClient();

        $result = $client->suppressions->add(
            ['a@example.com', 'b@example.com'],
            'unsubscribe',
        );

        $this->assertCount(2, $client->requests);
        $this->assertCount(2, $result);
        $this->assertSame(['email' => 'a@example.com', 'reason' => 'unsubscribe'], $client->requests[0]['body']);
        $this->assertSame(['email' => 'b@example.com', 'reason' => 'unsubscribe'], $client->requests[1]['body']);
    }

    public function testDomainCreateSendsNameNotDomain(): void
    {
        $client = $this->recordingClient();

        $client->domains->create('mail.example.com', ['region' => 'eu-west-1']);

        $request = $client->requests[0];
        $this->assertSame('/v1/domains', $request['path']);
        $this->assertSame(['name' => 'mail.example.com'], $request['body']);
    }

    public function testApiKeyCreateSendsScopesAndExpiresInDays(): void
    {
        $client = $this->recordingClient();

        $client->apiKeys->create([
            'name'             => 'deploy',
            'scopes'           => ['messages:send'],
            'expires_in_days'  => 30,
            'expiresAt'        => '2030-01-01T00:00:00Z', // legacy, must not be sent
        ]);

        $request = $client->requests[0];
        $this->assertSame('/v1/auth/api-keys', $request['path']);
        $this->assertSame([
            'name'            => 'deploy',
            'scopes'          => ['messages:send'],
            'expires_in_days' => 30,
        ], $request['body']);
    }

    public function testApiKeyCreateAlwaysIncludesScopes(): void
    {
        $client = $this->recordingClient();

        $client->apiKeys->create(['name' => 'minimal']);

        $this->assertSame([
            'name'   => 'minimal',
            'scopes' => [],
        ], $client->requests[0]['body']);
    }

    public function testAnalyticsTypedMethodsHitRealSubpaths(): void
    {
        $client = $this->recordingClient();

        $client->analytics->dashboard('2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z');
        $client->analytics->volume(null, null, 'week');
        $client->analytics->engagement();
        $client->analytics->deliverability();
        $client->analytics->analyzeSubjectLine('Open me');

        $paths = array_map(static fn ($r) => $r['method'] . ' ' . $r['path'], $client->requests);
        $this->assertSame([
            'GET /v1/analytics/dashboard?from=2026-01-01T00%3A00%3A00Z&to=2026-02-01T00%3A00%3A00Z',
            'GET /v1/analytics/volume?interval=week',
            'GET /v1/analytics/engagement',
            'GET /v1/analytics/deliverability',
            'POST /v1/analytics/subject-line',
        ], $paths);

        $this->assertSame(['subject' => 'Open me'], $client->requests[4]['body']);
    }

    public function testDomainHealthHitsGetByIdNotHealth(): void
    {
        $client = $this->recordingClient();

        $client->domains->health('dom_1');

        $request = $client->requests[0];
        $this->assertSame('GET', $request['method']);
        $this->assertSame('/v1/domains/dom_1', $request['path']);
    }
}

/**
 * Internal test double: reuses the real Client constructor (validation
 * included) but records requests instead of performing HTTP.
 */
final class RecordingClient extends Client
{
    /** @var list<array{method: string, path: string, body: array|null, idempotencyKey: string|null}> */
    public array $requests = [];

    public function request(
        string $method,
        string $path,
        ?array $body = null,
        ?string $idempotencyKey = null,
    ): array {
        $this->requests[] = [
            'method'         => $method,
            'path'           => $path,
            'body'           => $body,
            'idempotencyKey' => $idempotencyKey,
        ];

        // Canonical server responses for the exercised endpoints.
        return match ($path) {
            '/v1/messages' => ['id' => 'msg_1', 'status' => 'queued', 'created_at' => '2026-08-29T00:00:00Z'],
            '/v1/messages/batch' => ['accepted' => 1, 'rejected' => 0, 'results' => [
                ['index' => 0, 'id' => 'msg_1', 'status' => 'queued'],
            ]],
            '/v1/suppressions' => ['id' => 'sup_1', 'email' => 'x@example.com', 'reason' => 'manual', 'source' => 'manual', 'created_at' => '2026-08-29T00:00:00Z'],
            default => ['ok' => true],
        };
    }
}
