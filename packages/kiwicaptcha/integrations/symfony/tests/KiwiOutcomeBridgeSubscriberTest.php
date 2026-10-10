<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\MetricsCounterStore;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeTrustGateInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\Outcomes\Outcome;
use KiwiCaptcha\Risk\Outcomes\OutcomeHandleDimension;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

(require_once __DIR__.'/Fixtures/security-event-shims.php') || true;

/**
 * The Symfony security auto-bridge of the outcomes plane. The three
 * security events translate into typed outcome reports on derived
 * pseudonyms; the idempotency key is the HMAC of the request id. The
 * success-trust gate decides the session credit, and no listener
 * failure ever propagates into the authentication flow.
 */
final class KiwiOutcomeBridgeSubscriberTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const CANARY_USERNAME = 'canary-username-9f31aa';

    private SpyOutcomeReporter $reporter;

    private MetricsCounterStore $counters;

    private RiskIdentityFactory $identity;

    private \ArrayObject $debugs;

    protected function setUp(): void
    {
        $this->reporter = new SpyOutcomeReporter();
        $this->counters = new MetricsCounterStore('bridge-test');
        $this->identity = new RiskIdentityFactory(RiskKeys::fromMaster(self::SECRET));
        $this->debugs = new \ArrayObject();
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function subscriber(
        bool $targetFieldConfigured = true,
        ?OutcomeTrustGateInterface $trustGate = null,
        array $overrides = [],
        bool $trustRequestIdHeader = false,
        ?\BelConsulting\KiwiCaptchaBundle\Risk\AuthOutcomeWindowInterface $authWindow = null,
    ): KiwiOutcomeBridgeSubscriber {
        return new KiwiOutcomeBridgeSubscriber(
            $this->reporter,
            $this->identity,
            10,
            self::SECRET,
            new CidrNetworkClassifier([]),
            new ContinuityCookie('__Host-kiwi-session'),
            new ClientIpResolver('direct'),
            $targetFieldConfigured,
            $trustGate,
            $this->counters,
            $this->debugLogger(),
            $trustRequestIdHeader,
            $authWindow,
        );
    }

    private function debugLogger(): LoggerInterface
    {
        $debugs = $this->debugs;

        return new class ($debugs) implements LoggerInterface {
            public function __construct(private readonly \ArrayObject $debugs)
            {
            }

            public function debug(string|\Stringable $message, array $context = []): void
            {
                $this->debugs[] = (string) $message.' '.json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
            }

            public function emergency(string|\Stringable $message, array $context = []): void
            {
            }

            public function alert(string|\Stringable $message, array $context = []): void
            {
            }

            public function critical(string|\Stringable $message, array $context = []): void
            {
            }

            public function error(string|\Stringable $message, array $context = []): void
            {
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
            }

            public function notice(string|\Stringable $message, array $context = []): void
            {
            }

            public function info(string|\Stringable $message, array $context = []): void
            {
            }

            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
            }
        };
    }

    /**
     * @param array<string, mixed> $server
     */
    public function testARepeatedRequestIdHeaderNeverCollapsesDistinctAttempts(): void
    {
        // The header is client-controlled: without a declared edge that
        // overwrites it, two attempts on different connections must get
        // distinct idempotency ids even when they send one shared value.
        $subscriber = $this->subscriber();
        $dispatcher = $this->dispatcher($subscriber);
        $server = ['REMOTE_ADDR' => '203.0.113.9', 'REMOTE_PORT' => '54321', 'REQUEST_TIME_FLOAT' => 1700000000.5, 'HTTP_X_REQUEST_ID' => 'attacker-chosen-value'];
        $attributes = ['_security.last_username' => self::CANARY_USERNAME];
        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $this->request($server, [], $attributes)), LoginFailureEvent::class);
        $server['REMOTE_PORT'] = '54322';
        $server['REQUEST_TIME_FLOAT'] = 1700000000.9;
        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $this->request($server, [], $attributes)), LoginFailureEvent::class);

        self::assertCount(2, $this->reporter->reports);
        $first = $this->reporter->reports[0]['idempotencyKey'];
        $second = $this->reporter->reports[1]['idempotencyKey'];
        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertNotSame($first, $second, 'one repeated header value must never collapse distinct attempt events');

        // With the trusted-edge knob the header is honored: one value
        // means one logical event, exactly what a rewriting proxy gives.
        $this->reporter->reports = [];
        $trusting = $this->subscriber(trustRequestIdHeader: true);
        $trustingDispatcher = $this->dispatcher($trusting);
        $server['REMOTE_PORT'] = '54323';
        $trustingDispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $this->request($server, [], $attributes)), LoginFailureEvent::class);
        $server['REMOTE_PORT'] = '54324';
        $server['REQUEST_TIME_FLOAT'] = 1700000001.5;
        $trustingDispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $this->request($server, [], $attributes)), LoginFailureEvent::class);
        self::assertCount(2, $this->reporter->reports);
        self::assertSame(
            $this->reporter->reports[0]['idempotencyKey'],
            $this->reporter->reports[1]['idempotencyKey'],
            'a rewriting edge makes one header value one logical event'
        );
    }

    private function request(array $server = [], array $cookies = [], array $attributes = []): Request
    {
        $request = Request::create('https://example.com/login', 'POST', [], $cookies, [], $server);
        foreach ($attributes as $name => $value) {
            $request->attributes->set($name, $value);
        }

        return $request;
    }

    private function dispatcher(KiwiOutcomeBridgeSubscriber $subscriber): EventDispatcher
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($subscriber);

        return $dispatcher;
    }

    private function user(string $identifier): object
    {
        return new class ($identifier) {
            public function __construct(private readonly string $identifier)
            {
            }

            public function getUserIdentifier(): string
            {
                return $this->identifier;
            }
        };
    }

    private function sessionCookie(): string
    {
        return bin2hex(random_bytes(16));
    }

    public function testLoginSuccessReportsAuthenticationSuccessOnPrincipalPseudonymWithHmacIdempotencyKey(): void
    {
        $request = $this->request([
            'REQUEST_TIME_FLOAT' => 1234567890.5,
            'REMOTE_ADDR' => '198.51.100.7',
            'REMOTE_PORT' => '54321',
        ]);
        $subscriber = $this->subscriber();
        $dispatcher = $this->dispatcher($subscriber);

        $dispatcher->dispatch(new LoginSuccessEvent($request, $this->user('user-42')), LoginSuccessEvent::class);

        self::assertCount(1, $this->reporter->reports, 'exactly one report for one login success');
        $report = $this->reporter->reports[0];
        self::assertSame(Outcome::AuthenticationSuccess, $report['outcome']);
        self::assertSame(OutcomeHandleDimension::Principal, $report['handle']->dimension);
        self::assertSame($this->identity->principalId('user-42'), $report['handle']->id, 'the principal handle carries the engine pseudonym, never the raw identifier');
        $expectedKey = hash_hmac(
            'sha256',
            '1234567890.5|198.51.100.7|54321',
            KiwiOutcomeBridgeSubscriber::deriveIdempotencyKey(self::SECRET),
        );
        self::assertSame($expectedKey, $report['idempotencyKey'], 'the idempotency key is the HMAC of the request id under the derived purpose key');
        self::assertNotNull($report['context']);
        self::assertSame(10, $report['context']->scope);
        self::assertSame('198.51.100.7', $report['context']->sourceIp);
        self::assertNull($report['context']->sessionId, 'the fail-closed default gate carries no session on a success');
        self::assertNull($report['context']->principalId, 'the principal rides the handle pseudonym, never the context raw value');
    }

    public function testReplayedLoginSuccessReplaysTheSameIdempotencyKey(): void
    {
        $request = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.5, 'REMOTE_PORT' => '54321']);
        $dispatcher = $this->dispatcher($this->subscriber());
        $event = new LoginSuccessEvent($request, $this->user('user-42'));

        $dispatcher->dispatch($event, LoginSuccessEvent::class);
        $dispatcher->dispatch($event, LoginSuccessEvent::class);

        self::assertCount(2, $this->reporter->reports, 'the listener runs per dispatch');
        self::assertSame(
            $this->reporter->reports[0]['idempotencyKey'],
            $this->reporter->reports[1]['idempotencyKey'],
            'a replayed event carries the same idempotency key, so the engine books it exactly once',
        );
    }

    public function testTheStoreBackedGateCreditsACleanSessionAndRefusesAFailureHeavyOne(): void
    {
        $window = new \BelConsulting\KiwiCaptchaBundle\Risk\MemoryAuthOutcomeWindow();
        $gate = new \BelConsulting\KiwiCaptchaBundle\Risk\StoreBackedOutcomeTrustGate($window, null, 0.05);
        $session = $this->sessionCookie();
        $request = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.5, 'REMOTE_PORT' => '54321'], ['__Host-kiwi-session' => $session]);
        $dispatcher = $this->dispatcher($this->subscriber(trustGate: $gate, authWindow: $window));

        // A brand-new session earns nothing from the first success.
        $dispatcher->dispatch(new LoginSuccessEvent($request, $this->user('user-42')), LoginSuccessEvent::class);
        self::assertCount(1, $this->reporter->reports);
        self::assertNull($this->reporter->reports[0]['context']?->sessionId, 'a brand-new session earns no credit from one success');

        // After a clean history the same session earns the credit.
        $this->reporter->reports = [];
        $seeded = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.0, 'REMOTE_PORT' => '54320'], ['__Host-kiwi-session' => $session]);
        $dispatcher->dispatch(new LoginSuccessEvent($seeded, $this->user('user-42')), LoginSuccessEvent::class);
        self::assertCount(1, $this->reporter->reports);
        self::assertNotNull($this->reporter->reports[0]['context']?->sessionId, 'a clean session earns the session credit');

        // Three failures against one success put the ratio above the
        // ceiling: the next success keeps the principal credit but the
        // session rides no report context.
        $this->reporter->reports = [];
        for ($i = 0; $i < 3; ++$i) {
            $failureRequest = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.5 + $i, 'REMOTE_PORT' => (string) (54322 + $i)], ['__Host-kiwi-session' => $session], ['_security.last_username' => self::CANARY_USERNAME]);
            $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $failureRequest), LoginFailureEvent::class);
        }
        $this->reporter->reports = [];
        $successRequest = $this->request(['REQUEST_TIME_FLOAT' => 1234567891.5, 'REMOTE_PORT' => '54330'], ['__Host-kiwi-session' => $session]);
        $dispatcher->dispatch(new LoginSuccessEvent($successRequest, $this->user('user-42')), LoginSuccessEvent::class);
        self::assertCount(1, $this->reporter->reports, 'the principal credit is unconditional');
        self::assertNull($this->reporter->reports[0]['context']?->sessionId, 'a failure-heavy session earns no session credit');
    }

    public function testTrustGateAllowsSessionCreditWhenOpen(): void
    {
        $session = $this->sessionCookie();
        $request = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.5, 'REMOTE_PORT' => '54321'], ['__Host-kiwi-session' => $session]);
        $gate = new class implements OutcomeTrustGateInterface {
            public function allowsSessionSourceCredit(string $principalPseudonym, ?string $sessionPseudonym, ?string $targetPseudonym): bool
            {
                return true;
            }
        };
        $dispatcher = $this->dispatcher($this->subscriber(trustGate: $gate));

        $dispatcher->dispatch(new LoginSuccessEvent($request, $this->user('user-42')), LoginSuccessEvent::class);

        self::assertCount(1, $this->reporter->reports);
        $context = $this->reporter->reports[0]['context'];
        self::assertNotNull($context);
        self::assertSame($session, $context->sessionId, 'an open gate rides the raw continuity value for the engine to pseudonymize');
    }

    public function testLoginFailureWithConfiguredTargetFieldCarriesTheTargetPseudonym(): void
    {
        $request = $this->request([], [], ['_security.last_username' => self::CANARY_USERNAME]);
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: true));

        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $request), LoginFailureEvent::class);

        self::assertCount(1, $this->reporter->reports);
        $report = $this->reporter->reports[0];
        self::assertSame(Outcome::AuthenticationFailure, $report['outcome']);
        self::assertSame(OutcomeHandleDimension::Target, $report['handle']->dimension);
        $derived = $this->identity->targetId(TargetIdentifierNormalizer::normalize(self::CANARY_USERNAME));
        self::assertTrue(
            $report['handle']->id === $derived || $report['handle']->id === substr($derived, 0, 32),
            'the target handle carries the derived pseudonym (full digest or the 128-bit family shape), never the raw claimed identifier',
        );
        self::assertMatchesRegularExpression('/^[0-9a-f]{32,64}$/', $report['handle']->id);
        self::assertNotNull($report['idempotencyKey']);
    }

    public function testLoginFailureWithoutTargetFieldFallsBackToTheSessionHandle(): void
    {
        $session = $this->sessionCookie();
        $request = $this->request([], ['__Host-kiwi-session' => $session], ['_security.last_username' => self::CANARY_USERNAME]);
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: false));

        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $request), LoginFailureEvent::class);

        self::assertCount(1, $this->reporter->reports);
        $report = $this->reporter->reports[0];
        self::assertSame(OutcomeHandleDimension::Session, $report['handle']->dimension, 'an unconfigured target field reports the failure without a target handle');
        self::assertSame($this->identity->sessionId($session), $report['handle']->id);
    }

    public function testLoginFailureWithoutTargetOrSessionSkipsTheReportAndCountsTheSkip(): void
    {
        $request = $this->request([], [], ['_security.last_username' => self::CANARY_USERNAME]);
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: false));

        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $request), LoginFailureEvent::class);

        self::assertCount(0, $this->reporter->reports, 'no attributable identity handle means no typed report');
        self::assertSame(1, $this->counters->all()['outcome_skips:no_attributable_handle'] ?? 0);
    }

    public function testCheckPassportErrorReportsAuthenticationFailure(): void
    {
        $request = $this->request([], [], []);
        $badge = new UserBadge(self::CANARY_USERNAME, static function (string $identifier): object {
            throw new UsernameNotFoundException();
        });
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: true));

        $dispatcher->dispatch(new CheckPassportEvent(new Passport([UserBadge::class => $badge]), $request), CheckPassportEvent::class);

        self::assertCount(1, $this->reporter->reports);
        $report = $this->reporter->reports[0];
        self::assertSame(Outcome::AuthenticationFailure, $report['outcome']);
        self::assertSame(OutcomeHandleDimension::Target, $report['handle']->dimension);
        self::assertSame(self::CANARY_USERNAME, (string) $request->attributes->get('_kiwi_outcome_target'), 'the observed claimed identifier is handed to the request\'s failure lane');
    }

    public function testCheckPassportResolutionSuccessStashesTheTargetAndReportsNothing(): void
    {
        $request = $this->request([], [], []);
        $badge = new UserBadge('resolved-user', static fn (string $identifier): object => new class {
            public function getUserIdentifier(): string
            {
                return 'resolved-user';
            }
        });
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: true));

        $dispatcher->dispatch(new CheckPassportEvent(new Passport([UserBadge::class => $badge]), $request), CheckPassportEvent::class);

        self::assertCount(0, $this->reporter->reports, 'a resolving passport is the success event\'s business, not a failure report');
        self::assertSame('resolved-user', (string) $request->attributes->get('_kiwi_outcome_target'));
    }

    public function testAReportingFailureNeverPropagatesIntoTheAuthenticationFlow(): void
    {
        $request = $this->request(['REQUEST_TIME_FLOAT' => 1234567890.5, 'REMOTE_PORT' => '54321']);
        $this->reporter->throwOnReport = new \RuntimeException('store down');
        $dispatcher = $this->dispatcher($this->subscriber());

        $dispatcher->dispatch(new LoginSuccessEvent($request, $this->user('user-42')), LoginSuccessEvent::class);

        self::assertCount(0, $this->reporter->reports);
        self::assertSame(1, $this->counters->all()['outcome_skips:report_failed'] ?? 0, 'the failed report is counted, never propagated');
        self::assertNotEmpty($this->debugs->getArrayCopy(), 'the failure is logged at debug');
    }

    public function testRawUsernamesNeverReachAHandleOrAContext(): void
    {
        $request = $this->request(
            ['REQUEST_TIME_FLOAT' => 1234567890.5, 'REMOTE_PORT' => '54321'],
            [],
            ['_security.last_username' => self::CANARY_USERNAME],
        );
        $dispatcher = $this->dispatcher($this->subscriber(targetFieldConfigured: true));

        $dispatcher->dispatch(new LoginSuccessEvent($request, $this->user(self::CANARY_USERNAME)), LoginSuccessEvent::class);
        $dispatcher->dispatch(new LoginFailureEvent(new UsernameNotFoundException(), $request), LoginFailureEvent::class);
        $badge = new UserBadge(self::CANARY_USERNAME, static function (): object {
            throw new UsernameNotFoundException();
        });
        $dispatcher->dispatch(new CheckPassportEvent(new Passport([UserBadge::class => $badge]), $request), CheckPassportEvent::class);

        self::assertGreaterThanOrEqual(2, \count($this->reporter->reports));
        $serialized = serialize($this->reporter->reports);
        self::assertStringNotContainsString(self::CANARY_USERNAME, $serialized, 'the raw claimed identifier never reaches a report');
        self::assertStringNotContainsString(bin2hex(self::CANARY_USERNAME), $serialized, 'nor its hex encoding');
        foreach ($this->reporter->reports as $report) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32,64}$/', $report['handle']->id, 'every handle id is a derived pseudonym shape');
            $context = $report['context'];
            if ($context !== null) {
                self::assertTrue(
                    $context->sessionId === null || preg_match('/^[0-9a-f]{32}$/D', $context->sessionId) === 1,
                    'a context session is the validated cookie value or absent',
                );
                self::assertNull($context->principalId);
            }
        }
    }
}
