<?php

declare(strict_types=1);

namespace BelConsulting\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\BucketTrustPriceContext;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use BelConsulting\KiwiCaptchaBundle\Tests\Kernel\RiskStageMatrixTestKernel;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Marks\StoreMarksReader;
use KiwiCaptcha\Risk\Trust\ContextBoundTrust;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The stage-composition wiring matrix (change.md Part 5): per protection
 * profile, the composed engine arguments on a real compiled container.
 * The engine carries every decision stage as an optional constructor
 * argument, so the matrix reflects on the actual composed object: null
 * means the stage is absent and the plain pipeline runs untouched, an
 * instance means the profile composed it.
 *
 * The matrix:
 *  - abuse_first / high_abuse compose everything (marks, pricing, trust,
 *    the target resolver, the explanation surface) — the abuse posture
 *    may carry no opt-in stage that no default turns on.
 *  - balanced (and the profile-less neutral default, and its ha_safe /
 *    privacy_strict mirrors) compose the server-side memory stages
 *    (marks, pricing, trust) without requiring the ASN dataset, and keep
 *    the explanation surface off (balanced promises byte-identical
 *    behavior).
 *  - compatibility keeps today's minimal set: no decision stage rides
 *    the engine.
 *  - An explicit stage knob always wins over the profile matrix, in
 *    both directions (widen compatibility, narrow abuse_first).
 */
final class RiskStageWiringMatrixTest extends TestCase
{
    private const STAGE_PROPERTIES = ['targetResolver', 'marksReader', 'priceContext'];

    public function testAbuseFirstComposesEveryStage(): void
    {
        $container = $this->boot('abuse_first');

        $this->assertStageInstance($container, 'marksReader', StoreMarksReader::class);
        $this->assertStageInstance($container, 'priceContext', BucketTrustPriceContext::class);
        $this->assertStageInstance($container, 'targetResolver', \KiwiCaptcha\Risk\FormFieldTargetResolver::class);
        self::assertTrue($this->gatewayFlag($container, 'explain'), 'abuse_first surfaces the names-only explanation');
        self::assertTrue($container->has('kiwi_captcha.risk.asn'), 'the configured dataset is wired under abuse_first');
        self::assertTrue($container->has('kiwi_captcha.risk.trust'), 'the bucket-trust facade rides the dataset');
        self::assertTrue($container->has('kiwi_captcha.risk.outcomes'), 'the marks stage arms the outcomes facade (the mark writer)');
    }

    public function testHighAbuseIsTheSameCompositionUnderItsIntegrationName(): void
    {
        $container = $this->boot('high_abuse');

        foreach (self::STAGE_PROPERTIES as $stage) {
            self::assertNotNull($this->stage($container, $stage), "high_abuse composes $stage");
        }
        self::assertTrue($this->gatewayFlag($container, 'explain'));
        self::assertTrue($container->has('kiwi_captcha.risk.trust'));
    }

    public function testBalancedComposesTheMemoryStagesWithoutExplaining(): void
    {
        $container = $this->boot('balanced');

        self::assertNotNull($this->stage($container, 'marksReader'), 'balanced composes the marks stage');
        self::assertNotNull($this->stage($container, 'priceContext'), 'balanced composes the pricing stage');
        self::assertTrue($container->has('kiwi_captcha.risk.trust'), 'the dataset is configured, so the trust plane engages');
        self::assertFalse($this->gatewayFlag($container, 'explain'), 'balanced keeps the byte-identical behavior surface');
    }

    public function testProfilelessDeploymentFollowsTheNeutralMatrix(): void
    {
        $container = $this->boot(null);

        self::assertNotNull($this->stage($container, 'marksReader'));
        self::assertNotNull($this->stage($container, 'priceContext'));
        self::assertFalse($this->gatewayFlag($container, 'explain'));
    }

    public function testCompatibilityKeepsTheMinimalSet(): void
    {
        $container = $this->boot('compatibility');

        self::assertNull($this->stage($container, 'marksReader'), 'compatibility keeps the plain pipeline');
        self::assertNull($this->stage($container, 'priceContext'));
        self::assertFalse($container->has('kiwi_captcha.risk.trust'), 'no pricing stage, no trust plane');
        self::assertFalse($this->gatewayFlag($container, 'explain'));
        // The dataset is data, not a stage flag: a configured path is
        // wired under every profile even where nothing consumes it yet
        // (compatibility), so an operator's dataset never silently
        // disappears per profile.
        self::assertTrue($container->has('kiwi_captcha.risk.asn'));
        // The outcomes facade rides the marks stage only: without it the
        // kill-switch posture has no mark writer and no reporter seam.
        self::assertFalse($container->has('kiwi_captcha.risk.outcomes'));
    }

    public function testExplicitKnobsWinOverTheProfileMatrix(): void
    {
        // Widening: compatibility with the stages explicitly enabled.
        $container = $this->boot('compatibility', ['marks' => ['enabled' => true], 'pricing' => ['enabled' => true]]);
        self::assertNotNull($this->stage($container, 'marksReader'), 'an explicit marks knob widens compatibility');
        self::assertNotNull($this->stage($container, 'priceContext'));
        self::assertTrue($container->has('kiwi_captcha.risk.trust'));

        // Narrowing: abuse_first with the marks stage explicitly off; the
        // pricing stage (and the trust plane under the configured
        // dataset) stay composed.
        $container = $this->boot('abuse_first', ['marks' => ['enabled' => false]]);
        self::assertNull($this->stage($container, 'marksReader'), 'an explicit marks knob narrows abuse_first');
        self::assertNotNull($this->stage($container, 'priceContext'));
        self::assertTrue($container->has('kiwi_captcha.risk.trust'));
        self::assertTrue($this->gatewayFlag($container, 'explain'), 'the explanation knob is independent of the marks knob');
    }

    public function testExplainKnobOverridesTheProfile(): void
    {
        $container = $this->boot('balanced', ['explain' => true]);
        self::assertTrue($this->gatewayFlag($container, 'explain'));

        $container = $this->boot('abuse_first', ['explain' => false]);
        self::assertFalse($this->gatewayFlag($container, 'explain'));
    }

    public function testNoDatasetMeansNoAsnDimensionButEveryOtherStage(): void
    {
        $container = $this->boot('abuse_first', [], withAsnDataset: false);

        self::assertNotNull($this->stage($container, 'marksReader'), 'the marks stage survives without a dataset');
        self::assertNotNull($this->stage($container, 'priceContext'), 'the pricing stage survives without a dataset');
        self::assertFalse($container->has('kiwi_captcha.risk.asn'));
        self::assertFalse($container->has('kiwi_captcha.risk.trust'), 'no dataset, no bucket resolution, no trust facade');
    }

    private function boot(?string $profile, array $overrides = [], bool $withAsnDataset = true): ContainerInterface
    {
        $kernel = new RiskStageMatrixTestKernel('test', true, $profile, $overrides, $withAsnDataset);
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    /** One composed engine stage by constructor property reflection. */
    private function stage(ContainerInterface $container, string $property): ?object
    {
        $engine = $container->get('kiwi_captcha.risk.engine');
        self::assertInstanceOf(AdaptiveRiskEngine::class, $engine);
        $prop = new \ReflectionProperty(AdaptiveRiskEngine::class, $property);

        return $prop->getValue($engine);
    }

    private function assertStageInstance(ContainerInterface $container, string $property, string $class): void
    {
        $stage = $this->stage($container, $property);
        self::assertNotNull($stage, "$property must be composed");
        self::assertInstanceOf($class, $stage);
    }

    /** One gateway flag by constructor property reflection. */
    private function gatewayFlag(ContainerInterface $container, string $property): bool
    {
        $gateway = $container->get(RiskGateway::class);
        $prop = new \ReflectionProperty(RiskGateway::class, $property);
        $value = $prop->getValue($gateway);
        self::assertIsBool($value);

        return $value;
    }
}
