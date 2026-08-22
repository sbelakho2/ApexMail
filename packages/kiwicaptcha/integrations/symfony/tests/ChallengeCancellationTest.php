<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The bounded cancellation endpoint, the server side of the
 * exhaustion->debt feedback break: a widget that abandons a challenge tells
 * the server to retire the record (pending -> cancelled) and release the
 * deployment-wide live-outstanding slot. The endpoint is idempotent (an
 * unknown, expired or already-cancelled nonce answers the same success; a
 * consumed/finalized record is never cancelled), never returns record
 * contents, and is POST-only, bounded, origin-checked and per-source
 * rate-limited like the challenge endpoint.
 */
final class ChallengeCancellationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function controller(?OutstandingChallenges $outstanding = null, ?StorageInterface $storage = null): ChallengeController
    {
        $storage ??= new ArrayStorage();

        return new ChallengeController(
            new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage),
            null,
            false,
            null,
            null,
            null,
            $outstanding,
            [],
            false,
            $storage,
        );
    }

    private function issue(ChallengeController $controller, string $ip = '198.51.100.7'): string
    {
        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => $ip], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode(), sprintf('challenge issuance must succeed: %s', (string) $response->getContent()));
        $data = json_decode((string) $response->getContent(), true);
        self::assertIsString($data['nonce'] ?? null, 'the issuance response carries the nonce');

        return $data['nonce'];
    }

    private function cancel(ChallengeController $controller, string $nonce, string $ip = '198.51.100.7'): \Symfony\Component\HttpFoundation\JsonResponse
    {
        return $controller->cancel(JsonRequest::create(
            '/challenge/cancel',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => $ip],
            json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR),
        ));
    }

    private function outstanding(string $prefix = '{kiwi:cancel-test}:outstanding:'): OutstandingChallenges
    {
        return new OutstandingChallenges(new FakePredisClient(), $prefix, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
    }

    public function testPendingNonceIsCancelledAndRemovedFromTheLiveMembership(): void
    {
        $storage = new ArrayStorage();
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:cancel-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, $storage);

        $nonce = $this->issue($controller);
        $liveKey = '{kiwi:cancel-test}:outstanding:global:live';
        self::assertArrayHasKey($liveKey, $client->zsets, 'the issuance must place the nonce in the live-outstanding membership');
        self::assertArrayHasKey($nonce, $client->zsets[$liveKey], 'the issued nonce is a live member');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), sprintf('cancelling a pending nonce must succeed: %s', (string) $response->getContent()));
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true), 'the response acknowledges the cancellation and nothing else');

        $records = (new \ReflectionObject($storage))->getProperty('records')->getValue($storage);
        self::assertTrue($records[$nonce]['cancelled'], 'the pending record flips to the terminal cancelled state');
        self::assertFalse($records[$nonce]['consumed'], 'a cancellation is not a consume');
        self::assertArrayNotHasKey($nonce, $client->zsets[$liveKey] ?? [], 'the cancelled nonce leaves the live-outstanding membership');
    }

    public function testConsumedNonceIsIdempotentSuccessWithoutAStateChange(): void
    {
        $storage = new ArrayStorage();
        $controller = $this->controller($this->outstanding(), $storage);

        $nonce = $this->issue($controller);
        self::assertNotNull($storage->consume($nonce), 'the challenge is consumed before the cancellation attempt');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), sprintf('cancelling a consumed nonce must answer the same idempotent success: %s', (string) $response->getContent()));
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));

        $records = (new \ReflectionObject($storage))->getProperty('records')->getValue($storage);
        self::assertTrue($records[$nonce]['consumed'], 'a consumed/finalized record stays consumed');
        self::assertFalse($records[$nonce]['cancelled'] ?? false, 'a consumed/finalized record is never cancelled');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives the cancellation attempt');
    }

    public function testAlreadyCancelledNonceIsIdempotentSuccess(): void
    {
        $storage = new ArrayStorage();
        $controller = $this->controller($this->outstanding(), $storage);

        $nonce = $this->issue($controller);
        self::assertSame(200, $this->cancel($controller, $nonce)->getStatusCode());

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), 'an already-cancelled nonce answers the same success');
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));
    }

    public function testUnknownNonceIsIdempotentSuccess(): void
    {
        $storage = new ArrayStorage();
        $controller = $this->controller($this->outstanding(), $storage);

        // A well-formed but never-issued nonce: idempotent success, no
        // record contents, no state written.
        $response = $this->cancel($controller, 'A'.str_repeat('a', 43));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));
        self::assertSame(0, \count((new \ReflectionObject($storage))->getProperty('records')->getValue($storage)), 'no state is written for an unknown nonce');
    }

    public function testMalformedCancellationBodiesAre422(): void
    {
        $controller = $this->controller();

        $malformed = [
            '{"nonce":"'.str_repeat('a', 65).'"}',
            '{"nonce":"bad nonce!"}',
            '{"nonce":"a|b"}',
            '{"nonce":"abc"} extra',
            '{"nonce":123}',
            '{}',
            '{"nonce":"abc","extra":1}',
            '{"nonce":"abc","nonce":"def"}',
            'not json',
            '[1,2]',
        ];
        foreach ($malformed as $body) {
            $response = $controller->cancel(JsonRequest::create('/challenge/cancel', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], $body));
            self::assertSame(422, $response->getStatusCode(), 'malformed body must be 422: '.$body);
        }
    }

    public function testCancelledRecordFailsVerificationClosed(): void
    {
        $storage = new ArrayStorage();
        $controller = $this->controller($this->outstanding(), $storage);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $challenge = json_decode((string) $response->getContent(), true);
        $this->cancel($controller, $challenge['nonce']);

        // Mine a genuinely valid solution for the cancelled record: the
        // verifier must still refuse it — the cancelled marker makes the
        // record dead (reported missing), never redeemable.
        $saltBytes = base64_decode($challenge['salt'], true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge['prefix'].$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge['targetBits']);
        --$counter;
        // The server-measured minimum-duration floor: wait it out so the
        // proof itself is not rejected as TooFast (the cancelled-marker
        // behavior is what this test pins).
        usleep(((int) $challenge['minDurationMs'] + 10) * 1000);
        $token = \KiwiCaptcha\SolutionToken::create($challenge['nonce'], $counter, 5000, [])->encode();

        $outcome = (new Verifier($storage))->verify($token, self::SECRET, 'login', '198.51.100.7');
        self::assertFalse($outcome->isOk(), 'a cancelled challenge must never verify');
        self::assertSame(VerifyError::RecordNotFound, $outcome->error, 'the cancelled record fails verification closed (reported missing, never consumable)');
    }

    public function testCancellationIsPostOnly(): void
    {
        $controller = $this->controller();

        foreach (['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'] as $method) {
            $response = $controller->cancel(JsonRequest::create('/challenge/cancel', $method, [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"nonce":"abc"}'));
            self::assertSame(405, $response->getStatusCode(), $method.' must stay 405');
            self::assertSame('POST', $response->headers->get('Allow'), '405 must advertise Allow: POST');
            self::assertSame('METHOD_NOT_ALLOWED', json_decode((string) $response->getContent(), true)['error']['code']);
        }
    }

    public function testCrossOriginCancellationIsForbidden(): void
    {
        $controller = new ChallengeController(
            new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), new ArrayStorage()),
            null,
            true,
        );

        $response = $controller->cancel(JsonRequest::create(
            '/challenge/cancel',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_ORIGIN' => 'https://evil.example'],
            '{"nonce":"abc"}',
        ));
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('CROSS_ORIGIN_DENIED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    public function testCancellationIsRateLimitedPerSource(): void
    {
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, '{kiwi:cancel-test}:outstanding:', RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, new ArrayStorage());

        for ($i = 0; $i < OutstandingChallenges::CANCELLATION_PER_IP_CAP; $i++) {
            $response = $this->cancel($controller, 'A'.str_pad((string) $i, 43, 'a'));
            self::assertSame(200, $response->getStatusCode(), 'cancellation '.$i.' within the per-source window must pass');
        }

        $response = $this->cancel($controller, 'B'.str_pad('x', 43, 'a'));
        self::assertSame(429, $response->getStatusCode(), 'the N+1st cancellation within the window is refused');
        self::assertSame('CANCELLATION_RATE_LIMITED', json_decode((string) $response->getContent(), true)['error']['code']);
    }

    public function testCancellationResponseIsPrivateAndNeverCached(): void
    {
        $controller = $this->controller();
        $response = $this->cancel($controller, 'A'.str_repeat('a', 43));

        self::assertSame('max-age=0, no-store, private', $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }
}
