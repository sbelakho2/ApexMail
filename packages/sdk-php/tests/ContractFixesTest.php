<?php

declare(strict_types=1);

namespace ApexMail\Tests;

use ApexMail\Client;
use ApexMail\Exceptions\ValidationException;
use PHPUnit\Framework\TestCase;

/**
 * Live-contract regression tests for the 2026-10-06 dogfood SDK fixes.
 *
 * Every expectation here was verified against the running api-server
 * (127.0.0.1:8080): the events/query-parameter shapes, the reject-unknown
 * query structs, the camelCase pagination meta, and the 422 error contract
 * (docs/audit/dogfood-2026-10-06/fix-sdks.md).
 */
final class ContractFixesTest extends TestCase
{
    private function client(): RecordingContractClient
    {
        return new RecordingContractClient('am_test_contractfix000001');
    }

    // ── Events: server param names (ListEventsQuery, deny_unknown_fields) ──

    public function testEventsListMapsLegacyAliasesToServerFieldNames(): void
    {
        $client = $this->client();
        $client->events->list([
            'type' => 'message.delivered',
            'message_id' => 'msg_1',
            'limit' => 5,
            'offset' => 0,
        ]);

        $path = $client->requests[0]['path'];
        $this->assertStringContainsString('event_type=message.delivered', $path);
        $this->assertStringContainsString('message_id=msg_1', $path);
        $this->assertStringNotContainsString('messageId', $path);
        $this->assertStringNotContainsString('?type=', $path);
    }

    public function testEventsListRejectsUnsupportedFilters(): void
    {
        $client = $this->client();
        $this->expectException(\InvalidArgumentException::class);
        $client->events->list(['cursor' => 'abc']);
    }

    public function testEventsListRejectsStartEndDomainFilters(): void
    {
        $client = $this->client();
        $this->expectException(\InvalidArgumentException::class);
        $client->events->list(['start' => '2026-01-01T00:00:00Z']);
    }

    public function testEventsGetByMessageUsesSnakeCaseMessageId(): void
    {
        $client = $this->client();
        $client->events->getByMessage('msg_abc');

        $this->assertSame('/v1/events?message_id=msg_abc&limit=100', $client->requests[0]['path']);
    }

    public function testEventsStatsMapsStartEndToFromToAndRejectsType(): void
    {
        $client = $this->client();
        $client->events->stats(['start' => '2026-01-01T00:00:00Z', 'end' => '2026-01-02T00:00:00Z']);
        $path = $client->requests[0]['path'];
        $this->assertStringContainsString('from=2026-01-01T00%3A00%3A00Z', $path);
        $this->assertStringContainsString('to=2026-01-02T00%3A00%3A00Z', $path);

        $this->expectException(\InvalidArgumentException::class);
        $client->events->stats(['type' => 'message.delivered']);
    }

    // ── Unsupported cursor parameters (server 400s on unknown fields) ──────

    public function testTemplatesListRejectsCursor(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->templates->list(['cursor' => 'abc']);
    }

    public function testSuppressionsListRejectsCursor(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->suppressions->list(['cursor' => 'abc']);
    }

    public function testApiKeysListRejectsCursor(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->apiKeys->list(['cursor' => 'abc']);
    }

    public function testSupportedListsSendOnlyLimitAndOffset(): void
    {
        $client = $this->client();
        $client->templates->list(['limit' => 10, 'offset' => 5]);
        $this->assertSame('/v1/templates?limit=10&offset=5', $client->requests[0]['path']);
    }

    // ── Template create: html_body is required and non-empty server-side ──

    public function testTemplateCreateRejectsMissingHtmlBody(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->templates->create(['name' => 'n', 'subject' => 's', 'text' => 'only text']);
    }

    public function testTemplateCreateSendsNameSubjectHtmlBody(): void
    {
        $client = $this->client();
        $client->templates->create(['name' => 'n', 'subject' => 's', 'html' => '<p>x</p>']);
        $this->assertSame(
            ['name' => 'n', 'subject' => 's', 'html_body' => '<p>x</p>'],
            $client->requests[0]['body']
        );
    }

    // ── Error typing: 422 → ValidationException ────────────────────────────

    public function testThrowApiErrorMaps422ToValidationException(): void
    {
        $client = $this->client();
        $method = new \ReflectionMethod(Client::class, 'throwApiError');

        try {
            $method->invoke($client, 422, ['error' => ['code' => 'VALIDATION_ERROR', 'message' => 'missing field']], null);
            $this->fail('expected ValidationException');
        } catch (ValidationException $e) {
            $this->assertSame(422, $e->getStatusCode());
            $this->assertSame('VALIDATION_ERROR', $e->getApiCode());
        }
    }

    // ── Pagination meta: camelCase keys, cleared when absent ───────────────

    public function testDecodeResponseBodyCapturesCamelCaseMeta(): void
    {
        $client = $this->client();
        $method = new \ReflectionMethod(Client::class, 'decodeResponseBody');

        $data = $method->invoke(
            $client,
            '{"data":[{"id":"m1"}],"meta":{"hasMore":true,"nextCursor":"cur_123"}}'
        );
        $this->assertSame([['id' => 'm1']], $data);
        $this->assertSame('cur_123', $client->getNextCursor());
        $this->assertTrue($client->getHasMore());

        // A response without an envelope clears the stale meta.
        $method->invoke($client, '[]');
        $this->assertNull($client->getNextCursor());
        $this->assertFalse($client->getHasMore());

        // Snake_case (older/self-hosted) is still accepted.
        $method->invoke($client, '{"data":[],"meta":{"has_more":true,"next_cursor":"cur_legacy"}}');
        $this->assertSame('cur_legacy', $client->getNextCursor());
        $this->assertTrue($client->getHasMore());
    }
}

/**
 * Test double reusing the real Client constructor (validation included)
 * while recording resource calls instead of performing HTTP.
 */
final class RecordingContractClient extends Client
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
            'method' => $method,
            'path' => $path,
            'body' => $body,
            'idempotencyKey' => $idempotencyKey,
        ];

        return ['ok' => true];
    }
}
