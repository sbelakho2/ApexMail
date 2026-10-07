<?php

declare(strict_types=1);

namespace ApexMail\Tests;

use ApexMail\Client;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the live-envelope unwrap and the resource methods
 * added by the 2026-10-06 dogfood SDK fixes.
 *
 * The live api-server always serialises the `error` key (null on success):
 * {"data": ..., "error": null}. `isset($decoded['error'])` is FALSE for
 * JSON null, so the historical guard left every single-object response
 * (send/get/cancel/batch, analytics dashboard, ...) wrapped in its
 * envelope — the PHP test double only emitted a bare {"data": ...}, which
 * is why the suite stayed green while the live contract broke.
 */
final class EnvelopeAndSurfaceTest extends TestCase
{
    private function client(): RecordingSurfaceClient
    {
        return new RecordingSurfaceClient('am_test_envelope00000001');
    }

    private function decode(Client $client, string $body): array
    {
        $method = new \ReflectionMethod(Client::class, 'decodeResponseBody');

        /** @var array $decoded */
        $decoded = $method->invoke($client, $body);

        return $decoded;
    }

    // ── Envelope unwrap (SDK-PHP-1) ───────────────────────────────────────

    public function testUnwrapsLiveSuccessEnvelopeWithNullError(): void
    {
        $client = $this->client();
        $decoded = $this->decode(
            $client,
            '{"data":{"id":"msg_1","status":"queued","created_at":"2026-10-07T10:00:00Z"},"error":null}'
        );

        $this->assertSame(
            ['id' => 'msg_1', 'status' => 'queued', 'created_at' => '2026-10-07T10:00:00Z'],
            $decoded
        );
    }

    public function testUnwrapsAnalyticsEnvelopeWithNullError(): void
    {
        $client = $this->client();
        $decoded = $this->decode($client, '{"data":{"total_sent":3},"error":null}');

        $this->assertSame(['total_sent' => 3], $decoded);
    }

    public function testUnwrapsArrayDataEnvelopeWithNullError(): void
    {
        $client = $this->client();
        $decoded = $this->decode($client, '{"data":[{"id":"m1"}],"error":null}');

        $this->assertSame([['id' => 'm1']], $decoded);
    }

    public function testCapturesMetaFromEnvelopeWithNullError(): void
    {
        $client = $this->client();
        $decoded = $this->decode(
            $client,
            '{"data":[],"error":null,"meta":{"hasMore":true,"nextCursor":"cur_1"}}'
        );

        $this->assertSame([], $decoded);
        $this->assertSame('cur_1', $client->getNextCursor());
        $this->assertTrue($client->getHasMore());
    }

    public function testErrorEnvelopeIsKeptWholeForThrowApiError(): void
    {
        $client = $this->client();
        $decoded = $this->decode(
            $client,
            '{"data":null,"error":{"code":"NOT_FOUND","message":"message not found"}}'
        );

        // The error body must survive decoding so throwApiError() can read
        // the code/message off it.
        $this->assertArrayHasKey('error', $decoded);
        $this->assertSame('NOT_FOUND', $decoded['error']['code']);
    }

    public function testEmptyDataEnvelopeDecodesToEmptyArray(): void
    {
        $client = $this->client();
        $this->assertSame([], $this->decode($client, '{"data":null,"error":null}'));
    }

    public function testPlainArrayPayloadIsNotTreatedAsEnvelope(): void
    {
        $client = $this->client();
        $this->assertSame([['id' => 'd1']], $this->decode($client, '[{"id":"d1"}]'));
        $this->assertNull($client->getNextCursor());
    }

    // ── Added resource methods (SDK-PHP-2 / SDK-PHP-3) ────────────────────

    public function testEmailsCancelPostsToTheCancelRoute(): void
    {
        $client = $this->client();
        $client->emails->cancel('msg_abc');

        $this->assertSame('POST', $client->requests[0]['method']);
        $this->assertSame('/v1/messages/msg_abc/cancel', $client->requests[0]['path']);
        $this->assertNull($client->requests[0]['body']);
    }

    public function testWebhooksRotateSecretPostsToTheRotateRoute(): void
    {
        $client = $this->client();
        $client->webhooks->rotateSecret('wh_abc');

        $this->assertSame('POST', $client->requests[0]['method']);
        $this->assertSame('/v1/webhooks/wh_abc/rotate-secret', $client->requests[0]['path']);
    }
}

/**
 * Test double reusing the real Client constructor (validation included)
 * while recording resource calls instead of performing HTTP.
 */
final class RecordingSurfaceClient extends Client
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
