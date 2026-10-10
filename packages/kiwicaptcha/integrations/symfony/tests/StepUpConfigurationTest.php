<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\StepUpController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\StepUpControllerResolverPass;
use BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\ArrayStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\EmailOtpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\KiwiStepUpHandlerRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\LoggingStepUpCodeSender;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\RedisStepUpChallengeStore;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpCompletionCredit;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpTicket;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\TotpStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Security\StepUp\WebAuthnStepUpHandler;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePrincipalResolver;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SpyOutcomeReporter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The step-up configuration contract: the knob bounds and cross-field
 * rules of the tree, and the extension's handler registry wiring. The
 * wiring covers the kill-switch, the derived default, the custom
 * handler map and the sender seam, the deliberately throwing WebAuthn
 * placeholder, and the resolver pass of the controller.
 */
final class StepUpConfigurationTest extends TestCase
{
    private const MASTER = '0123456789abcdef0123456789abcdef';

    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * @return array<string, mixed>
     */
    private function stepUpDefaults(array $stepUp = []): array
    {
        return [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'namespace' => 'stepup-test',
            'scopes' => ['login' => ['id' => 10]],
            'step_up' => [
                'enabled' => true,
                'scope' => 'login',
                'default_handler' => 'email_otp',
                'handlers' => ['email_otp' => ['enabled' => true]],
                ...$stepUp,
            ],
        ];
    }

    private function load(array $risk, ?\Closure $register = null): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        if ($register !== null) {
            $register($container);
        }
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'risk' => $risk,
        ]], $container);

        return $container;
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function invalidTrees(): array
    {
        $base = [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'scopes' => ['login' => ['id' => 10]],
        ];

        return [
            'no scope when enabled' => [
                ['step_up' => ['enabled' => true]] + $base,
                'risk.step_up.scope is required',
            ],
            'default handler names nothing' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'default_handler' => 'sms', 'handlers' => ['email_otp' => ['enabled' => true]]]] + $base,
                'default_handler must name an enabled handler',
            ],
            'digits outside 6 or 8' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'handlers' => ['email_otp' => ['enabled' => true, 'digits' => 7]]]] + $base,
                'digits must be 6 or 8',
            ],
            'totp window out of bounds' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'handlers' => ['totp' => ['enabled' => true, 'window' => 3]]]] + $base,
                'too big for path "kiwi_captcha.risk.step_up.handlers.totp.window"',
            ],
            'short master secret' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'hmac_secret' => 'short']] + $base,
                'hmac_secret must be a string of at least 32 bytes',
            ],
            'relative complete path' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'complete_path' => 'step-up/complete']] + $base,
                'complete_path must be an absolute path',
            ],
            'begin rate below one' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'rate_limit' => ['max_begins' => 0]]] + $base,
                'too small for path "kiwi_captcha.risk.step_up.rate_limit.max_begins"',
            ],
            'ttl below the floor' => [
                ['step_up' => ['enabled' => true, 'scope' => 'login', 'challenge_ttl_secs' => 10]] + $base,
                'too small for path "kiwi_captcha.risk.step_up.challenge_ttl_secs"',
            ],
        ];
    }

    /**
     * @dataProvider invalidTrees
     *
     * @param array<string, mixed> $risk
     */
    public function testTheTreeRefusesInvalidKnobs(array $risk, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/'.preg_quote($message, '/').'/');
        $this->load($risk);
    }

    public function testStepUpWithoutTheRiskEngineIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/risk.step_up.enabled requires risk.enabled/');
        $this->load([
            'enabled' => false,
            'redis_service' => 'fake_redis',
            'scopes' => ['login' => ['id' => 10]],
            'step_up' => ['enabled' => true, 'scope' => 'login'],
        ]);
    }

    public function testTheKillSwitchRegistersNothing(): void
    {
        $container = $this->load([
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'scopes' => ['login' => ['id' => 10]],
            'step_up' => ['enabled' => false],
        ]);
        self::assertFalse($container->hasDefinition(KiwiStepUpHandlerRegistry::class));
        self::assertFalse($container->hasDefinition(EmailOtpStepUpHandler::class));
        self::assertFalse($container->hasDefinition(StepUpController::class));
        // The reporter seam itself is NOT governed by the step-up
        // kill switch: the engine's composed marks stage arms the typed
        // outcomes facade (the long-memory mark writer) on its own, so
        // the application's own abuse confirmations keep a reporter even
        // with the bridge and the plane off. The plane's own services
        // above stay absent.
        self::assertTrue($container->hasDefinition(OutcomeReporterInterface::class), 'the reporter seam rides the composed marks stage, not the step-up plane');
    }

    public function testThePlaneRegistersTheStoreTheSeamsAndTheController(): void
    {
        $container = $this->load($this->stepUpDefaults());
        self::assertTrue($container->hasDefinition('kiwi_captcha.step_up.store'));
        $store = $container->getDefinition('kiwi_captcha.step_up.store');
        self::assertSame(RedisStepUpChallengeStore::class, $store->getClass());
        self::assertSame('{kiwi:stepup-test}:stepup:', $store->getArgument(1), 'the keys live under the deployment namespace family');

        self::assertTrue($container->hasDefinition(StepUpTicket::class));
        self::assertTrue($container->hasDefinition(StepUpCompletionCredit::class));
        self::assertTrue($container->hasDefinition(OutcomeReporterInterface::class), 'the plane alone arms the outcomes reporter seam');

        $handler = $container->getDefinition(EmailOtpStepUpHandler::class);
        $sender = $handler->getArgument(3);
        if ($sender instanceof Reference) {
            $sender = $container->getDefinition((string) $sender);
        }
        self::assertInstanceOf(\Symfony\Component\DependencyInjection\Definition::class, $sender);
        self::assertSame(LoggingStepUpCodeSender::class, $sender->getClass(), 'the unbound sender knob wires the logging dev sender');

        $registry = $container->getDefinition(KiwiStepUpHandlerRegistry::class);
        self::assertSame(['email_otp'], array_keys($registry->getArgument(0)));
        self::assertSame('email_otp', $registry->getArgument(1));
    }

    public function testTheDefaultHandlerIsDerivedFromTheFirstRegisteredHandler(): void
    {
        $container = $this->load($this->stepUpDefaults([
            'default_handler' => null,
            'handlers' => [
                'email_otp' => ['enabled' => true],
                'totp' => ['enabled' => true],
            ],
        ]));
        $registry = $container->getDefinition(KiwiStepUpHandlerRegistry::class);
        self::assertSame(['email_otp', 'totp'], array_keys($registry->getArgument(0)));
        self::assertSame('email_otp', $registry->getArgument(1));
    }

    public function testACustomHandlerServiceJoinsTheRegistry(): void
    {
        $container = $this->load($this->stepUpDefaults([
            'default_handler' => 'app_sms',
            'handlers' => [
                'custom' => ['app_sms' => 'app.step_up.sms'],
            ],
        ]));
        $registry = $container->getDefinition(KiwiStepUpHandlerRegistry::class);
        $handlers = $registry->getArgument(0);
        self::assertArrayHasKey('app_sms', $handlers);
        self::assertSame('app.step_up.sms', (string) $handlers['app_sms']);
        self::assertSame('app_sms', $registry->getArgument(1));
    }

    public function testTheWebAuthnKnobRegistersTheLibBackedHandlerBehindTheInstallCheck(): void
    {
        $container = $this->load($this->stepUpDefaults([
            'default_handler' => 'webauthn',
            'handlers' => [
                'email_otp' => ['enabled' => true],
                'webauthn' => ['enabled' => true, 'rp_id' => 'login.example.com', 'allowed_origins' => ['https://login.example.com']],
            ],
        ]));
        self::assertTrue($container->hasDefinition(WebAuthnStepUpHandler::class));

        // The one installation-gated piece: constructing the handler
        // without the web-auth/webauthn-lib package fails with the
        // documented actionable message, and the registry keeps the
        // handler position either way (activation is one composer
        // require).
        try {
            new WebAuthnStepUpHandler(
                new ArrayStepUpChallengeStore(static fn (): int => 0),
                new StepUpTicket(self::MASTER),
                new StepUpCompletionCredit(new SpyOutcomeReporter(), self::MASTER),
                null,
                self::MASTER,
                300, 5, 3, 900, '/kiwi/step-up/complete', null, false,
            );
            self::fail('the WebAuthn handler must refuse construction without its library');
        } catch (\LogicException $e) {
            self::assertSame(WebAuthnStepUpHandler::NOT_IMPLEMENTED_MESSAGE, $e->getMessage());
            self::assertStringContainsString('web-auth/webauthn-lib', $e->getMessage());
            self::assertStringContainsString('composer require', $e->getMessage());
        }
    }

    public function testEnabledWithoutAnyHandlerIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/names no handler/');
        $this->load($this->stepUpDefaults(['default_handler' => null, 'handlers' => []]));
    }

    public function testAnUnknownScopeIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/is not a configured risk scope/');
        $this->load($this->stepUpDefaults(['scope' => 'financial_action']));
    }

    public function testTheResolverPassBindsAnApplicationResolver(): void
    {
        $container = $this->load($this->stepUpDefaults(), static function (ContainerBuilder $container): void {
            $container->register(PrincipalResolverInterface::class, FakePrincipalResolver::class);
        });
        (new StepUpControllerResolverPass())->process($container);
        $controller = $container->getDefinition(StepUpController::class);
        self::assertInstanceOf(Reference::class, $controller->getArgument('$principalResolver'));
        self::assertSame(PrincipalResolverInterface::class, (string) $controller->getArgument('$principalResolver'));
    }

    public function testTheResolverPassLeavesTheControllerNullWithoutAResolver(): void
    {
        $container = $this->load($this->stepUpDefaults());
        (new StepUpControllerResolverPass())->process($container);
        self::assertNull($container->getDefinition(StepUpController::class)->getArgument('$principalResolver'));
    }
}
