<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallenge;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpChallengeKind;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The Redis step-up store over the emulated Predis client: the exact
 * command surface (SET EX NX records, GETDEL consumption, the attempt
 * and window and replay-guard scripts) with real key shapes under the
 * deployment namespace family.
 */
final class RedisStepUpChallengeStoreTest extends TestCase
{
    private const PRINCIPAL = '00112233445566778899aabbccddeeff';

    private FakePredisClient $redis;

    private RedisStepUpChallengeStore $store;

    protected function setUp(): void
    {
        $this->redis = new FakePredisClient();
        $this->store = new RedisStepUpChallengeStore($this->redis, '{kiwi:test-ns}:stepup:');
    }

    public function testThePrefixMustBeAHashTaggedFamily(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RedisStepUpChallengeStore($this->redis, 'stepup:');
    }

    public function testRecordsAreSingleUse(): void
    {
        $challenge = $this->challenge('aaaaaaaaaaaaaaaaaaaaaaa');
        $this->store->create($challenge, 300);
        $key = '{kiwi:test-ns}:stepup:challenge:aaaaaaaaaaaaaaaaaaaaaaa';
        self::assertArrayHasKey($key, $this->redis->strings);
        self::assertStringContainsString('"principal":"'.self::PRINCIPAL.'"', $this->redis->strings[$key]);
        self::assertArrayHasKey($key, $this->redis->expirations, 'the record carries its TTL');

        self::assertNotNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertNotNull($consumed = $this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'));
        self::assertSame(self::PRINCIPAL, $consumed->principalPseudonym);
        self::assertNull($this->store->read('aaaaaaaaaaaaaaaaaaaaaaa'), 'the consumed record is gone');
        self::assertNull($this->store->consume('aaaaaaaaaaaaaaaaaaaaaaa'), 'a second consumption answers null');
    }

    public function testTheAttemptScriptCountsAndRemovesAtTheCap(): void
    {
        $id = 'bbbbbbbbbbbbbbbbbbbbbbb';
        $this->store->create($this->challenge($id), 300);
        self::assertSame(1, $this->store->recordFailure($id, 3));
        self::assertSame(2, $this->store->recordFailure($id, 3));
        self::assertSame(0, $this->store->recordFailure($id, 3), 'the cap removes the record');
        self::assertSame(-1, $this->store->recordFailure($id, 3), 'a missing record answers -1');
    }

    public function testTheBeginWindowCountsPerPrincipal(): void
    {
        self::assertSame(1, $this->store->countBegin(self::PRINCIPAL, 900));
        self::assertSame(2, $this->store->countBegin(self::PRINCIPAL, 900));
        $other = 'ffffffffffffffffffffffffffffffff';
        self::assertSame(1, $this->store->countBegin($other, 900));
        self::assertArrayHasKey('{kiwi:test-ns}:stepup:begins:'.self::PRINCIPAL, $this->redis->counters);
    }

    public function testTheTotpStateIsDurableAndReplayGuarded(): void
    {
        $this->store->saveTotpSecret(self::PRINCIPAL, 'secret-bytes');
        self::assertSame('secret-bytes', $this->store->findTotpSecret(self::PRINCIPAL));
        self::assertNull($this->store->findTotpSecret('ffffffffffffffffffffffffffffffff'));
        self::assertArrayNotHasKey('{kiwi:test-ns}:stepup:totp:secret:'.self::PRINCIPAL, $this->redis->expirations, 'the enrollment carries no TTL');

        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1000, 90));
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 1000, 90), 'the same step is a replay');
        self::assertFalse($this->store->markTotpStep(self::PRINCIPAL, 999, 90), 'an earlier step is a replay');
        self::assertTrue($this->store->markTotpStep(self::PRINCIPAL, 1001, 90), 'a strictly newer step wins');
    }

    private function challenge(string $id): StepUpChallenge
    {
        return StepUpChallenge::begin(
            $id,
            StepUpChallengeKind::EmailOtp,
            self::PRINCIPAL,
            null,
            'login',
            null,
            'post_solve_step_up_required',
            1700000000,
            300,
            5,
            str_repeat('a', 64),
        );
    }
}
