<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\AuthorityGuardedPredisClient;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\RedisSecurityCommandExecutor;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;

/**
 * The pinned-primary authority guard (docs/ha-authority.md): the
 * production runtime never auto-pins, so an operator records the
 * initial authority pin through the `kiwicaptcha:ha-initialize`
 * command, documented on {@see PinnedPrimaryAuthorityGuard::initializePin()}.
 * Every subsequent use refuses when the authority changed. The pin is
 * write-once (`SET NX`) in the same Redis namespace, one pin per
 * distinct authority (`{kiwi:<ns>}:authority:pin:<suffix>`). A pin
 * that disappears after it was established is a refusal, never a
 * silent re-pin; an unverifiable authority is a refusal. The
 * verification result is cached per connection object for the
 * reverify window, and a security-final transition bypasses the cache
 * entirely (zero stale).
 *
 * These fake-based tests run without a server and exercise the exact
 * refusal semantics; the real promotion simulation (a restarted
 * primary with a new run_id, and a pointed-at replica) lives in
 * PinnedPrimaryAuthorityPromotionTest, gated on the shared real-Redis
 * environment.
 */
final class PinnedPrimaryAuthorityGuardTest extends TestCase
{
    private const NS = 'pinned-test';
    private const RUN_ID_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const RUN_ID_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private function fake(): FakePredisClient
    {
        $fake = new FakePredisClient();
        $fake->infoReplication = ['role' => 'master', 'run_id' => self::RUN_ID_A];
        $fake->infoServer = ['run_id' => self::RUN_ID_A];

        return $fake;
    }

    private function pinKey(string $suffix = ''): string
    {
        return '{kiwi:'.self::NS.'}:authority:pin'.($suffix !== '' ? ':'.$suffix : '');
    }

    private function infoCalls(FakePredisClient $fake): int
    {
        return \count(array_filter($fake->calls, static fn (array $call): bool => $call[0] === 'INFO'));
    }

    public function testInitializeRecordsThePinAndVerifiesPass(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);

        $pin = $guard->initializePin();
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $pin,
            'the initialize command records the serving identity as the pin',
        );
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $fake->strings[$this->pinKey()] ?? null,
            'the pin is written once (SET NX) in the same Redis namespace',
        );
        $state = $guard->state();
        self::assertTrue($state['armed'], 'after the initialization the guard is armed');
        self::assertSame('master|'.self::RUN_ID_A, $state['pinned'], 'the state reports the pinned identity');

        $guard->assertServeEligible($fake);
        $guard->assertServeEligible($fake);
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $fake->strings[$this->pinKey()] ?? null,
            'the pin is write-once: a stable authority never rewrites it',
        );
    }

    public function testAnUninitializedGuardRefusesAndNamesTheInitializeCommand(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);

        try {
            $guard->assertServeEligible($fake);
            self::fail('an uninitialized guard must refuse: the production runtime never auto-pins');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the deployment is not bootstrapped', $e->getMessage());
            self::assertStringContainsString('never auto-pins', $e->getMessage(), 'the refusal states the no-auto-pin contract');
            self::assertStringContainsString('kiwicaptcha:ha-initialize', $e->getMessage(), 'the refusal names the explicit bootstrap command');
            self::assertStringContainsString($this->pinKey(), $e->getMessage());
        }
        self::assertArrayNotHasKey($this->pinKey(), $fake->strings, 'the guard must not have auto-pinned');
    }

    public function testInitializeRefusesAnExistingPinWithoutForce(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();

        try {
            $guard->initializePin();
            self::fail('re-initializing an existing pin must refuse without --force');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('a pin already exists', $e->getMessage());
            self::assertStringContainsString('--force', $e->getMessage(), 'the refusal names the deliberate re-pin option');
            self::assertStringContainsString('quiesce', $e->getMessage());
        }
    }

    public function testInitializeWithForceOverwritesThePin(): void
    {
        $fake = $this->fake();
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();

        $pin = $guard->initializePin(true);
        self::assertSame('master|'.self::RUN_ID_B, $pin, '--force records the new serving identity');
        self::assertSame('master|'.self::RUN_ID_B, $fake->strings[$this->pinKey()] ?? null);
    }

    public function testThePerAuthorityPinSuffixIsBakedIntoTheKey(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage');
        self::assertSame(
            '{kiwi:'.self::NS.'}:authority:pin:storage',
            $guard->pinKey(),
            'one pin per distinct Redis authority: the storage authority pins its own key',
        );

        $riskGuard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'risk');
        self::assertSame(
            '{kiwi:'.self::NS.'}:authority:pin:risk',
            $riskGuard->pinKey(),
            'a distinct risk authority pins its own key',
        );
    }

    public function testTheExpectedIdentityReplacesThePinComparison(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, '', 'master|'.self::RUN_ID_A);

        // No pin key at all: the operator-provisioned expected identity
        // is the comparison target, so the guard serves.
        $guard->assertServeEligible($fake);
        self::assertSame('master|'.self::RUN_ID_A, $guard->expectedIdentity(), 'the expected identity is the operator contract');
        self::assertNull($fake->strings[$this->pinKey()] ?? null, 'the expected identity path never requires a pin key');

        // The serving authority changed: refused against the expected
        // identity, exactly like a pin mismatch.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('pinned master|'.self::RUN_ID_A);
        $this->expectExceptionMessage('observed master|'.self::RUN_ID_B);

        $guard->assertServeEligible($fake);
    }

    public function testInitializeWritesThePinToMatchTheExpectedIdentity(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0, 'storage', 'master|'.self::RUN_ID_A);

        self::assertSame('master|'.self::RUN_ID_A, $guard->initializePin());
        self::assertSame(
            'master|'.self::RUN_ID_A,
            $fake->strings['{kiwi:'.self::NS.'}:authority:pin:storage'] ?? null,
            'the initialize command records the operator-provisioned identity as the pin',
        );
    }

    public function testTheVerificationIsCachedWithinTheWindow(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();

        $guard->assertServeEligible($fake);
        $infoAfterFirst = $this->infoCalls($fake);
        self::assertGreaterThan(0, $infoAfterFirst, 'the first check reads the serving identity');

        $guard->assertServeEligible($fake);
        $guard->assertServeEligible($fake);
        self::assertSame(
            $infoAfterFirst,
            $this->infoCalls($fake),
            'within the reverify window the check serves from the cache without an INFO round trip',
        );
    }

    public function testASecurityFinalCheckBypassesTheVerificationWindow(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();

        $guard->assertServeEligible($fake);
        $infoAfterOrdinary = $this->infoCalls($fake);

        $guard->assertServeEligible($fake, true);
        self::assertGreaterThan(
            $infoAfterOrdinary,
            $this->infoCalls($fake),
            'a security-final transition re-verifies the authority even inside the window: zero stale',
        );
    }

    public function testAChangedRunIdIsRefusedWithTheExactMessage(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();

        // The stale-promotion detection: the serving authority changed.
        // A restarted primary (new run_id) or a promoted stale replica
        // presents exactly this identity change.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;

        try {
            $guard->assertServeEligible($fake);
            self::fail('the guard must refuse when the serving run_id changed');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage(), 'the refusal names the identity change');
            self::assertStringContainsString('pinned master|'.self::RUN_ID_A, $e->getMessage(), 'the refusal names the PINNED identity');
            self::assertStringContainsString('observed master|'.self::RUN_ID_B, $e->getMessage(), 'the refusal names the OBSERVED identity');
            self::assertStringContainsString($this->pinKey(), $e->getMessage(), 'the refusal names the pin key for the re-pin');
            self::assertStringContainsString('kiwicaptcha:ha-initialize', $e->getMessage(), 'the refusal names the re-pin command');
            self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $e->getMessage(), 'the refusal names the remediation');
            self::assertSame('master|'.self::RUN_ID_A, $e->pinnedIdentity());
            self::assertSame('master|'.self::RUN_ID_B, $e->observedIdentity());
        }
    }

    public function testAChangedRoleIsRefused(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();

        // Pointed at a replica: the serving role is no longer the
        // pinned role, so the guard refuses.
        $fake->infoReplication['role'] = 'slave';

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('pinned master|'.self::RUN_ID_A);
        $this->expectExceptionMessage('observed slave|'.self::RUN_ID_A);

        $guard->assertServeEligible($fake);
    }

    public function testAPinThatDisappearsAfterEstablishmentIsRefusedNeverRePinned(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();
        self::assertNotNull($fake->strings[$this->pinKey()] ?? null);

        // A failover to a node that never received the pin presents
        // exactly this state: the key is gone. The guard must refuse,
        // never silently re-pin to the new authority.
        unset($fake->strings[$this->pinKey()]);

        try {
            $guard->assertServeEligible($fake);
            self::fail('a pin that disappears after establishment must be a refusal, never a silent re-pin');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the pinned identity is missing', $e->getMessage());
            self::assertStringContainsString('was pinned to master|'.self::RUN_ID_A, $e->getMessage());
            self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $e->getMessage());
        }
        self::assertArrayNotHasKey($this->pinKey(), $fake->strings, 'the guard must not have re-pinned');
    }

    public function testAnUnverifiableIdentityIsRefused(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);

        // The `INFO` read cannot succeed (Redis down): an unverifiable
        // authority is stale, never passed — the guard refuses instead
        // of pinning.
        $fake->failCommand = 'INFO';

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('the serving authority cannot be verified');

        $guard->initializePin();
    }

    public function testAConcurrentInitializeComparesAgainstTheWinningPin(): void
    {
        $fake = $this->fake();
        // The pin already exists (a concurrent process initialized
        // first) and the observed identity matches it: the guard
        // serves.
        $fake->strings[$this->pinKey()] = 'master|'.self::RUN_ID_A;
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->assertServeEligible($fake);

        // The observed identity differs from the existing pin: refused.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('pinned master|'.self::RUN_ID_A);
        $this->expectExceptionMessage('observed master|'.self::RUN_ID_B);

        $guard->assertServeEligible($fake);
    }

    public function testARetryEnabledDirectClientIsRefusedAtConstruction(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $retryEnabled = new \Predis\Client([
            'host' => '127.0.0.1',
            'retry' => new \Predis\Retry\Retry(new \Predis\Retry\Strategy\ExponentialBackoff(), 3),
        ]);

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('retry-enabled');

        new PinnedPrimaryAuthorityGuard($retryEnabled, self::NS, 0);
    }

    public function testAnUnknownClientIsRefusedAtConstruction(): void
    {
        $opaque = new FakePredisClient();
        $opaque->connectionOverride = null;

        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('cannot be classified as a single-node direct connection');

        new PinnedPrimaryAuthorityGuard($opaque, self::NS, 0);
    }

    public function testTheGuardedClientWrapperDelegatesAndRefuses(): void
    {
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 0);
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);

        // The command goes through the guard to the inner client.
        $wrapped->set('probe', '1');
        self::assertSame('1', $fake->strings['probe'], 'the guarded wrapper delegates commands to the inner client');

        // The authority changed: the next command refuses with the
        // pinned-vs-observed refusal, so a durability-critical
        // transition can never execute on the changed authority.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;
        $this->expectException(PinnedAuthorityRefusalException::class);
        $this->expectExceptionMessage('the serving authority changed');

        $wrapped->set('probe', '2');
    }

    // ── The guarded Lua seam (RedisSecurityCommandExecutor) ──────────────

    public function testAPlainEvalOutsideTheSeamIsSecurityFinalByDefault(): void
    {
        // An EVAL the wrapper cannot prove non-final (no seam lane, no
        // recorded sha) is an unknown mutating script: fail closed with
        // the zero-stale lane — immediate revalidation, never a window
        // pass.
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);

        $wrapped->eval('-- a bare script nobody declared', 1, 'k', 'v');
        $infoAfterEval = $this->infoCalls($fake);
        self::assertGreaterThan(0, $infoAfterEval, 'the first EVAL verifies the authority');

        // Within the window the ordinary lane serves from the cache...
        $wrapped->get('probe');
        $infoAfterOrdinary = $this->infoCalls($fake);
        self::assertSame($infoAfterEval, $infoAfterOrdinary, 'an ordinary command serves from the cached verification');

        // ...but a second bare EVAL re-verifies anyway: unknown mutating
        // EVAL is security-final by default.
        $wrapped->eval('-- a bare script nobody declared', 1, 'k', 'v');
        self::assertGreaterThan(
            $infoAfterOrdinary,
            $this->infoCalls($fake),
            'a bare EVAL is security-final by default: it bypasses the verification window',
        );
    }

    public function testTheSeamOrdinaryLaneServesWithinTheWindow(): void
    {
        // The seam's declared ordinary lane (executeRead /
        // executeMutation) relaxes the eval default: a known
        // non-final script serves within the verification window.
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);
        $seam = new RedisSecurityCommandExecutor($wrapped);

        $seam->executeRead('-- Chain live read: read-only', 'k', ['arg']);
        $seam->executeMutation('-- a known non-final mutation', 'k', ['v']);
        $infoAfterSeam = $this->infoCalls($fake);

        $seam->executeRead('-- Chain live read: read-only', 'k', ['arg']);
        $seam->executeMutation('-- a known non-final mutation', 'k', ['v']);
        self::assertSame(
            $infoAfterSeam,
            $this->infoCalls($fake),
            'the seam\'s ordinary lanes serve within the verification window without re-verifying',
        );
    }

    public function testTheSeamSecurityFinalLaneForcesRevalidationForEveryShape(): void
    {
        // The seam's security-final lane forces the zero-stale
        // revalidation even inside the window, regardless of the
        // command shape (`eval` here; `evalsha` rides the same
        // forced lane through the wrapper).
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);
        $seam = new RedisSecurityCommandExecutor($wrapped);

        $seam->executeSecurityFinal('-- Chain verification: terminal', 'k', ['v']);
        $infoAfterFinal = $this->infoCalls($fake);
        self::assertGreaterThan(0, $infoAfterFinal, 'the security-final lane verifies the authority');

        // An ordinary command serves from the cache inside the window...
        $wrapped->get('probe');
        $infoAfterOrdinary = $this->infoCalls($fake);
        self::assertSame($infoAfterFinal, $infoAfterOrdinary, 'the ordinary lane still serves from the cache');

        // ...and the next security-final transition re-verifies anyway.
        $seam->executeSecurityFinal('-- Chain verification: terminal', 'k', ['v']);
        self::assertGreaterThan(
            $infoAfterOrdinary,
            $this->infoCalls($fake),
            'the seam\'s security-final lane bypasses the window for every command shape',
        );
    }

    public function testTheSeamSecurityFinalLaneRefusesImmediatelyOnAChangedAuthority(): void
    {
        // The zero-stale refusal through the seam: a changed authority
        // inside the window refuses the security-final write before the
        // mutation reaches Redis (the guard runs first, the script never
        // executes).
        $fake = $this->fake();
        $guard = new PinnedPrimaryAuthorityGuard($fake, self::NS, 5);
        $guard->initializePin();
        $wrapped = new AuthorityGuardedPredisClient($guard, $fake);
        $seam = new RedisSecurityCommandExecutor($wrapped);

        $seam->executeSecurityFinal('-- Chain verification: terminal', 'k', ['v']);

        // The authority changed; the window has NOT expired.
        $fake->infoReplication['run_id'] = self::RUN_ID_B;
        $fake->infoServer['run_id'] = self::RUN_ID_B;

        $evalCallsBefore = \count(array_filter($fake->calls, static fn (array $call): bool => $call[0] === 'EVAL'));
        try {
            $seam->executeSecurityFinal('-- Chain verification: terminal', 'k', ['v']);
            self::fail('a security-final transition must refuse immediately after the authority changed, inside the window');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('pinned master|'.self::RUN_ID_A, $e->getMessage());
            self::assertStringContainsString('observed master|'.self::RUN_ID_B, $e->getMessage());
        }
        self::assertSame(
            $evalCallsBefore,
            \count(array_filter($fake->calls, static fn (array $call): bool => $call[0] === 'EVAL')),
            'the refused security-final write never reaches the client: the guard refuses before the mutation',
        );
    }
}
