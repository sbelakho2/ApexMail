<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Risk\DecoyEscalationScriptRunner;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\Evidence\AutofillQualificationGate;
use KiwiCaptcha\Risk\Evidence\DecoyEscalationStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The evidence-plane wiring at the definition level (extension load, no
 * container compile). The widget telemetry arm follows the stage
 * composition: the profile matrix plus the risk.evidence.telemetry
 * knob. The decoy-escalation store rides the engine's reader argument
 * and the gateway's record call wherever the server-side stage pipeline
 * is composed and a risk Redis client exists.
 */
final class EvidenceStageWiringTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function load(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
        ], $config)], $container);

        return $container;
    }

    private function riskDefaults(): array
    {
        return [
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'namespace' => 'evidence-wiring',
                'scopes' => ['login' => ['id' => 10]],
            ],
        ];
    }

    public function testTheWidgetTelemetryArmResolvesPerProfile(): void
    {
        // Profile-less (the neutral balanced posture): minimal.
        self::assertSame('minimal', $this->load($this->riskDefaults())
            ->getDefinition(KiwiCaptchaRuntime::class)->getArgument(3));

        // The abuse postures arm the full telemetry.
        foreach (['abuse_first', 'high_abuse'] as $profile) {
            self::assertSame('full', $this->load(array_merge(
                $this->riskDefaults(),
                ['protection_profile' => $profile],
            ))->getDefinition(KiwiCaptchaRuntime::class)->getArgument(3), "$profile arms the full telemetry");
        }

        // Compatibility stays minimal (the arm default everywhere).
        self::assertSame('minimal', $this->load(array_merge(
            $this->riskDefaults(),
            ['protection_profile' => 'compatibility'],
        ))->getDefinition(KiwiCaptchaRuntime::class)->getArgument(3));
    }

    public function testTheTelemetryKnobOverridesTheProfileMatrix(): void
    {
        $off = $this->load(array_merge($this->riskDefaults(), [
            'protection_profile' => 'abuse_first',
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'namespace' => 'evidence-wiring',
                'scopes' => ['login' => ['id' => 10]],
                'evidence' => ['telemetry' => 'off'],
            ],
        ]));
        self::assertSame('off', $off->getDefinition(KiwiCaptchaRuntime::class)->getArgument(3), 'an explicit off wins over the abuse matrix');

        $full = $this->load(array_merge($this->riskDefaults(), [
            'risk' => [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'namespace' => 'evidence-wiring',
                'scopes' => ['login' => ['id' => 10]],
                'evidence' => ['telemetry' => 'full'],
            ],
        ]));
        self::assertSame('full', $full->getDefinition(KiwiCaptchaRuntime::class)->getArgument(3), 'an explicit full widens the neutral posture');
    }

    public function testTheFormTypeCarriesTheSameTelemetryArm(): void
    {
        self::assertSame('minimal', $this->load($this->riskDefaults())
            ->getDefinition(KiwiCaptchaType::class)->getArgument(2));

        $abuse = $this->load(array_merge($this->riskDefaults(), ['protection_profile' => 'abuse_first']));
        self::assertSame('full', $abuse->getDefinition(KiwiCaptchaType::class)->getArgument(2));
    }

    public function testAbuseFirstWiresTheDecoyEscalationPlane(): void
    {
        $container = $this->load(array_merge($this->riskDefaults(), ['protection_profile' => 'abuse_first']));

        // The store: the bundle's script runner over the risk client, the
        // canonical committed qualification gate and the deployment
        // namespace.
        self::assertTrue($container->hasDefinition('kiwi_captcha.risk.decoy_escalation'));
        $store = $container->getDefinition('kiwi_captcha.risk.decoy_escalation');
        self::assertSame(DecoyEscalationStore::class, $store->getClass());
        $args = $store->getArguments();
        self::assertInstanceOf(Reference::class, $args[0]);
        self::assertSame('kiwi_captcha.risk.decoy_script_runner', (string) $args[0]);
        self::assertInstanceOf(Reference::class, $args[1]);
        self::assertSame('kiwi_captcha.risk.autofill_gate', (string) $args[1]);
        self::assertSame('evidence-wiring', $args[2], 'the store namespace is the derived deployment namespace');
        $gate = $container->getDefinition('kiwi_captcha.risk.autofill_gate');
        self::assertSame([AutofillQualificationGate::class, 'fromConfiguration'], $gate->getFactory());
        self::assertSame(
            [false, null, null],
            $gate->getArguments(),
            'the default gate is the fail-closed matrix path (armed false, committed asset pair)',
        );
        $runner = $container->getDefinition('kiwi_captcha.risk.decoy_script_runner');
        self::assertSame(DecoyEscalationScriptRunner::class, $runner->getClass());

        // The engine holds the reader seam; the gateway holds the write
        // side and the identity factory that derives the keyed pseudonym.
        $engine = $container->getDefinition('kiwi_captcha.risk.engine');
        $reader = $engine->getArgument('$decoyEscalationReader');
        self::assertInstanceOf(Reference::class, $reader);
        self::assertSame('kiwi_captcha.risk.decoy_escalation', (string) $reader);
        $gateway = $container->getDefinition(\BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway::class);
        self::assertInstanceOf(Reference::class, $gateway->getArgument('$decoyEscalation'));
        self::assertSame('kiwi_captcha.risk.identity_factory', (string) $gateway->getArgument('$identityFactory'));
    }

    public function testCompatibilityKeepsThePlainPipelineWithoutTheDecoyPlane(): void
    {
        $container = $this->load(array_merge($this->riskDefaults(), ['protection_profile' => 'compatibility']));

        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.decoy_escalation'));
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.autofill_gate'));
        self::assertFalse($container->hasDefinition('kiwi_captcha.risk.decoy_script_runner'));
        self::assertNull($container->getDefinition('kiwi_captcha.risk.engine')->getArgument('$decoyEscalationReader'));
    }
}
