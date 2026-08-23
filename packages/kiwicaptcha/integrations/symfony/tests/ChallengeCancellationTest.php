<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\Psr6Storage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The bounded cancellation endpoint, the server side of the
 * exhaustion->debt feedback break: a widget that abandons a challenge tells
 * the server to retire the record (pending -> cancelled) and release the
 * deployment-wide live-outstanding slot. The endpoint is idempotent (an
 * unknown, expired or already-cancelled nonce answers the same success; a
 * consumed/finalized record is never cancelled), never returns record
 * contents, and is POST-only, bounded, origin-checked and per-source
 * rate-limited like the challenge endpoint.
 *
 * The record transition runs against the real bundled storages. The
 * atomic pending->cancelled flip of {@see ArrayStorage} and
 * {@see RedisStorage} (both implement
 * {@see \KiwiCaptcha\CancellableStorageInterface}) decides the outcome
 * in one storage operation. The deployment-wide slot is released only
 * for a record the storage actually cancelled: a fresh flip or an
 * already-cancelled record. A consumed or missing nonce answers the same
 * idempotent success without freeing anything. A storage that cannot
 * establish the cancellation (e.g. {@see Psr6Storage}, which cannot
 * express the atomic flip) fails closed with the retryable 503 and frees
 * nothing. Freeing the global gate while the record stays pending and
 * redeemable would be an anti-stockpiling bypass.
 */
final class ChallengeCancellationTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const OUTSTANDING_PREFIX = '{kiwi:cancel-test}:outstanding:';

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

    private function outstanding(string $prefix = self::OUTSTANDING_PREFIX): OutstandingChallenges
    {
        return new OutstandingChallenges(new FakePredisClient(), $prefix, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
    }

    /**
     * The full risk-enabled stack with the in-memory fake state store:
     * issuance records PreIssue + ChallengeIssued, a fresh cancellation
     * records ChallengeCancelled against the same identities.
     *
     * @return array{controller: ChallengeController, store: FakeRiskStateStore, storage: ArrayStorage}
     */
    private function riskStack(): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $keys = RiskKeys::fromMaster(self::SECRET);
        $identityFactory = new RiskIdentityFactory($keys);
        $classifier = new CidrNetworkClassifier([]);
        $scorer = new RiskScorer();
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => [],
            'scopes' => [
                1 => ['base_risk' => 100, 'minimum' => 'allow', 'post_solve_check' => false, 'degraded' => 'allow'],
            ],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, $identityFactory, $scorer, $policy, $keys);
        $resolver = new RiskProfileResolver(PoWAlgorithm::Sha256, 8);
        $gateway = new RiskGateway($engine, $classifier, $resolver, ['login' => 1], policy: $policy);
        $controller = new ChallengeController($issuer, null, false, $gateway, new ContinuityCookie(), null, null, [], false, $storage);

        return ['controller' => $controller, 'store' => $store, 'storage' => $storage];
    }

    /** The continuity session cookie value the issuance response minted. */
    private function issuedSession(JsonResponse $response): string
    {
        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        self::assertSame('__Host-kiwi-session', $cookies[0]->getName());

        return $cookies[0]->getValue();
    }

    private function liveKey(): string
    {
        return self::OUTSTANDING_PREFIX.'global:live';
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
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, self::OUTSTANDING_PREFIX, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, $storage);

        $nonce = $this->issue($controller);
        self::assertNotNull($storage->consume($nonce), 'the challenge is consumed before the cancellation attempt');
        self::assertArrayHasKey($nonce, $client->zsets[$this->liveKey()], 'the issued nonce is a live member');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), sprintf('cancelling a consumed nonce must answer the same idempotent success: %s', (string) $response->getContent()));
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));

        $records = (new \ReflectionObject($storage))->getProperty('records')->getValue($storage);
        self::assertTrue($records[$nonce]['consumed'], 'a consumed/finalized record stays consumed');
        self::assertFalse($records[$nonce]['cancelled'] ?? false, 'a consumed/finalized record is never cancelled');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives the cancellation attempt');
        self::assertArrayHasKey($nonce, $client->zsets[$this->liveKey()], 'a consumed record performs no cancellation — the live-outstanding slot is NOT freed');
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

    public function testRedisStoragePendingNonceIsCancelledAndFreesTheLiveMembership(): void
    {
        // The same contract against the real bundled Redis storage: the
        // atomic Lua flip retires the record (state=cancelled in the
        // stored envelope, retained until its TTL). The endpoint frees
        // the deployment-wide live-outstanding slot.
        $client = new FakePredisClient();
        $storage = new RedisStorage($client, 'kiwicaptcha:');
        $outstanding = new OutstandingChallenges($client, self::OUTSTANDING_PREFIX, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, $storage);

        $nonce = $this->issue($controller);
        $liveKey = $this->liveKey();
        self::assertArrayHasKey($liveKey, $client->zsets, 'the issuance must place the nonce in the live-outstanding membership');
        self::assertArrayHasKey($nonce, $client->zsets[$liveKey], 'the issued nonce is a live member');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), sprintf('cancelling a pending nonce must succeed: %s', (string) $response->getContent()));
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));

        $data = json_decode((string) $client->strings['kiwicaptcha:'.$nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('cancelled', $data['state'], 'the atomic Lua flip persists state=cancelled in the stored envelope');
        self::assertArrayNotHasKey($nonce, $client->zsets[$liveKey] ?? [], 'the cancelled nonce leaves the live-outstanding membership');
        self::assertNotNull($storage->find($nonce), 'the cancelled record is retained until its TTL');
    }

    public function testRedisStorageConsumedNonceIsIdempotentWithoutFreeingTheSlot(): void
    {
        // The Redis consumed branch: a finalized record is never
        // cancelled — the endpoint answers the idempotent success, the
        // envelope stays consumed and the live-outstanding slot is NOT
        // freed.
        $client = new FakePredisClient();
        $storage = new RedisStorage($client, 'kiwicaptcha:');
        $outstanding = new OutstandingChallenges($client, self::OUTSTANDING_PREFIX, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, $storage);

        $nonce = $this->issue($controller);
        self::assertNotNull($storage->consume($nonce), 'the challenge is consumed before the cancellation attempt');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(200, $response->getStatusCode(), sprintf('cancelling a consumed nonce must answer the same idempotent success: %s', (string) $response->getContent()));
        self::assertSame(['cancelled' => true], json_decode((string) $response->getContent(), true));

        $data = json_decode((string) $client->strings['kiwicaptcha:'.$nonce], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('consumed', $data['state'], 'a consumed/finalized record stays consumed');
        self::assertArrayHasKey($nonce, $client->zsets[$this->liveKey()], 'a consumed record performs no cancellation — the live-outstanding slot is NOT freed');
        self::assertNotNull($storage->consumedState($nonce), 'the consumed evidence survives the cancellation attempt');
    }

    public function testRedisStorageCancelledRecordFailsVerificationClosed(): void
    {
        // A genuinely valid solution for the cancelled record must fail
        // closed: the cancelled marker makes the record dead — the
        // consume transition reports it missing (RecordNotFound), never
        // redeemable.
        $client = new FakePredisClient();
        $storage = new RedisStorage($client, 'kiwicaptcha:');
        $controller = $this->controller($this->outstanding(), $storage);

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $challenge = json_decode((string) $response->getContent(), true);
        $this->cancel($controller, $challenge['nonce']);

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

    public function testNonCancellableStorageFailsClosedAndNeverFreesTheSlot(): void
    {
        // The operator's storage cannot establish the cancellation: a
        // PSR-6 pool has no atomic pending->cancelled transition, so the
        // endpoint MUST fail closed with the retryable 503 — freeing the
        // deployment-wide live-outstanding slot while the record stays
        // pending and redeemable would be an anti-stockpiling bypass.
        $storage = new Psr6Storage(new ArrayAdapter());
        $client = new FakePredisClient();
        $outstanding = new OutstandingChallenges($client, self::OUTSTANDING_PREFIX, RiskKeys::fromMaster(self::SECRET), 5, 100, 0);
        $controller = $this->controller($outstanding, $storage);

        $nonce = $this->issue($controller);
        $liveKey = $this->liveKey();
        self::assertArrayHasKey($nonce, $client->zsets[$liveKey], 'the issued nonce is a live member');

        $response = $this->cancel($controller, $nonce);
        self::assertSame(503, $response->getStatusCode(), 'a non-cancellable storage must fail closed with the retryable 503');
        self::assertSame('SERVICE_UNAVAILABLE', json_decode((string) $response->getContent(), true)['error']['code']);
        self::assertArrayHasKey($nonce, $client->zsets[$liveKey], 'the live-outstanding slot is NEVER freed for a cancellation that could not be established');
        self::assertNotNull($storage->find($nonce), 'the record stays in the pool, untouched by the refused cancellation');
        self::assertNull($storage->inspectConsumedEnvelope($nonce), 'the record was never consumed either — it stays pending');
    }

    public function testFreshCancellationRecordsChallengeCancelledOnceWithNonceDerivedIdempotency(): void
    {
        // The ChallengeCancelled risk event (the issue-debt restoration)
        // fires exactly once, on the first fresh pending->cancelled
        // transition, against the same identities the issuance recorded
        // (the continuity session rides the cancellation request), with an
        // event id derived from the nonce — the idempotency identity that
        // makes a repeated cancellation unable to re-subtract the debt.
        $stack = $this->riskStack();
        $controller = $stack['controller'];
        $store = $stack['store'];

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}'));
        self::assertSame(200, $response->getStatusCode());
        $nonce = json_decode((string) $response->getContent(), true)['nonce'];
        $session = $this->issuedSession($response);
        $issued = array_values(array_filter($store->observations, static fn ($o): bool => $o->event === RiskEventKind::ChallengeIssued));
        self::assertCount(1, $issued, 'the issuance must record the ChallengeIssued event');

        $cancelResponse = $controller->cancel(JsonRequest::create(
            '/challenge/cancel',
            'POST',
            [],
            ['__Host-kiwi-session' => $session],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR),
        ));
        self::assertSame(200, $cancelResponse->getStatusCode());

        $cancelled = array_values(array_filter($store->observations, static fn ($o): bool => $o->event === RiskEventKind::ChallengeCancelled));
        self::assertCount(1, $cancelled, 'a fresh pending->cancelled transition records the event exactly once');
        $event = $cancelled[0];
        self::assertSame($issued[0]->sourceId, $event->sourceId, 'the cancellation event restores the same source identity\'s debt');
        self::assertSame($issued[0]->sessionId, $event->sessionId, 'the cancellation event restores the same session identity\'s debt');
        self::assertSame($issued[0]->scope, $event->scope, 'the cancellation event rides the issued scope');
        $expectedId = hash_hmac('sha256', pack('N', $issued[0]->scope).chr(RiskEventKind::ChallengeCancelled->value).$nonce, RiskKeys::fromMaster(self::SECRET)->event);
        self::assertSame($expectedId, $event->eventId, 'the event id is the nonce-derived idempotency identity (scope and event domain separated)');

        // Repeated idempotent cancellation requests (already-cancelled
        // outcomes) never record the event again: the debt can never be
        // re-subtracted by a replay.
        $repeat = JsonRequest::create(
            '/challenge/cancel',
            'POST',
            [],
            ['__Host-kiwi-session' => $session],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            json_encode(['nonce' => $nonce], JSON_THROW_ON_ERROR),
        );
        self::assertSame(200, $controller->cancel($repeat)->getStatusCode());
        self::assertSame(200, $controller->cancel($repeat)->getStatusCode());
        $after = array_values(array_filter($store->observations, static fn ($o): bool => $o->event === RiskEventKind::ChallengeCancelled));
        self::assertCount(1, $after, 'repeated idempotent cancellations never record the event again');
    }

    public function testConsumedAndUnknownCancellationsRecordNoRiskEvent(): void
    {
        // The event fires only for the fresh pending->cancelled transition:
        // a consumed (finalized) record and a never-issued nonce perform no
        // cancellation and must never subtract the debt.
        $stack = $this->riskStack();
        $controller = $stack['controller'];
        $store = $stack['store'];

        $nonce = $this->issue($controller);
        self::assertNotNull($stack['storage']->consume($nonce), 'the challenge is consumed before the cancellation attempt');
        self::assertSame(200, $this->cancel($controller, $nonce)->getStatusCode());
        self::assertSame(200, $this->cancel($controller, 'A'.str_repeat('a', 43))->getStatusCode());

        $cancelled = array_values(array_filter($store->observations, static fn ($o): bool => $o->event === RiskEventKind::ChallengeCancelled));
        self::assertSame([], $cancelled, 'consumed and unknown nonces never record the ChallengeCancelled event');
    }
}
