<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\RiskStageComposition;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * The stage-composition configuration surface (change.md Part 5): the
 * new knobs validate in the config tree, the abuse_first name is the
 * accepted alias of high_abuse, and the profile resolution derives the
 * per-profile matrix while an explicit knob always wins.
 */
final class RiskStageCompositionConfigTest extends TestCase
{
    private function process(array $overrides = []): array
    {
        $config = array_merge(['secret_key' => str_repeat('a', 32)], $overrides);
        $processed = (new Processor())->processConfiguration(
            new Configuration(),
            ProtectionProfileDefaults::stack([$config]),
        );

        return ProtectionProfileDefaults::finalize($processed, [$config]);
    }

    public function testAbuseFirstIsAnAcceptedAliasOfHighAbuse(): void
    {
        $abuseFirst = $this->process(['protection_profile' => 'abuse_first']);
        $highAbuse = $this->process(['protection_profile' => 'high_abuse']);

        // The visible profile field is the one deliberate difference: it
        // reports the name the operator wrote. Every derived knob is
        // byte-identical between the two spellings.
        unset($abuseFirst['protection_profile'], $highAbuse['protection_profile']);
        self::assertSame($highAbuse, $abuseFirst, 'the abuse_first alias derives the byte-identical matrix of high_abuse');
        self::assertTrue($abuseFirst['risk']['enabled']);
    }

    public function testAnUnknownProfileNameIsStillRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be one of "balanced"/');
        $this->process(['protection_profile' => 'abuse_secondly']);
    }

    public function testStageKnobsDefaultToNullEverywhere(): void
    {
        $processed = $this->process();

        self::assertNull($processed['risk']['marks']['enabled']);
        self::assertNull($processed['risk']['pricing']['enabled']);
        self::assertNull($processed['risk']['asn']['dataset_path']);
        self::assertNull($processed['risk']['explain']);
        self::assertNull($processed['risk']['evidence']['telemetry']);
        self::assertSame('standard', $processed['risk']['scopes']['login']['value_class']);
    }

    public function testStageKnobsRejectNonBooleans(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/risk\.marks\.enabled must be a boolean or null/');
        $this->process(['risk' => ['marks' => ['enabled' => 'yes']]]);
    }

    public function testPricingKnobRejectsNonBooleans(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/risk\.pricing\.enabled must be a boolean or null/');
        $this->process(['risk' => ['pricing' => ['enabled' => 1]]]);
    }

    public function testExplainKnobRejectsNonBooleans(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/risk\.explain must be a boolean or null/');
        $this->process(['risk' => ['explain' => 'true']]);
    }

    public function testValueClassRejectsUnknownClasses(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/value_class/');
        $this->process(['risk' => ['scopes' => ['login' => ['value_class' => 'priceless']]]]);
    }

    public function testTheProfileMatrixResolvesTheStages(): void
    {
        $risk = ['asn' => ['dataset_path' => '/tmp/asn.tsv']];

        foreach (['abuse_first', 'high_abuse'] as $profile) {
            $plan = RiskStageComposition::resolve($profile, $risk);
            self::assertTrue($plan['marks'], "$profile composes the marks stage");
            self::assertTrue($plan['pricing'], "$profile composes the pricing stage");
            self::assertTrue($plan['trust'], "$profile composes the trust plane");
            self::assertTrue($plan['asn'], "$profile engages the configured dataset");
            self::assertTrue($plan['explain'], "$profile surfaces the explanation");
        }

        foreach (['balanced', 'ha_safe', 'privacy_strict', null] as $profile) {
            $plan = RiskStageComposition::resolve($profile, $risk);
            self::assertTrue($plan['marks'], "$profile composes the server-side memory stages");
            self::assertTrue($plan['pricing']);
            self::assertTrue($plan['trust']);
            self::assertFalse($plan['explain'], "$profile keeps the behavior surface byte-identical");
        }

        $plan = RiskStageComposition::resolve('compatibility', $risk);
        self::assertFalse($plan['marks'], 'compatibility keeps the minimal set');
        self::assertFalse($plan['pricing']);
        self::assertFalse($plan['trust']);
        self::assertFalse($plan['explain']);
        self::assertTrue($plan['asn'], 'the dataset is data, not a stage flag');
    }

    public function testExplicitKnobsWinOverTheMatrix(): void
    {
        $plan = RiskStageComposition::resolve('compatibility', [
            'marks' => ['enabled' => true],
            'pricing' => ['enabled' => true],
        ]);
        self::assertTrue($plan['marks']);
        self::assertTrue($plan['pricing']);
        self::assertTrue($plan['trust'], 'the trust plane follows the pricing stage');

        $plan = RiskStageComposition::resolve('abuse_first', [
            'marks' => ['enabled' => false],
            'explain' => false,
        ]);
        self::assertFalse($plan['marks']);
        self::assertTrue($plan['pricing']);
        self::assertFalse($plan['explain']);
    }

    public function testAnEmptyDatasetPathIsNoDataset(): void
    {
        self::assertFalse(RiskStageComposition::resolve('abuse_first', ['asn' => ['dataset_path' => '']])['asn']);
        self::assertFalse(RiskStageComposition::resolve('abuse_first', [])['asn']);
    }

    public function testEvidenceTelemetryKnobValidatesTheVocabulary(): void
    {
        foreach (['minimal', 'full', 'off'] as $mode) {
            self::assertSame($mode, $this->process(['risk' => ['evidence' => ['telemetry' => $mode]]])['risk']['evidence']['telemetry']);
        }

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/telemetry/');
        $this->process(['risk' => ['evidence' => ['telemetry' => 'sometimes']]]);
    }

    public function testTheTelemetryArmResolvesPerProfile(): void
    {
        foreach (['abuse_first', 'high_abuse'] as $profile) {
            self::assertSame('full', RiskStageComposition::resolve($profile, [])['telemetry'], "$profile arms the full telemetry by default");
        }
        foreach (['balanced', 'ha_safe', 'privacy_strict', 'compatibility', null] as $profile) {
            self::assertSame('minimal', RiskStageComposition::resolve($profile, [])['telemetry'], "$profile arms the minimal telemetry by default");
        }
    }

    public function testAnExplicitTelemetryKnobWinsOverTheMatrix(): void
    {
        self::assertSame('off', RiskStageComposition::resolve('abuse_first', ['evidence' => ['telemetry' => 'off']])['telemetry']);
        self::assertSame('full', RiskStageComposition::resolve('compatibility', ['evidence' => ['telemetry' => 'full']])['telemetry']);
        self::assertSame('minimal', RiskStageComposition::resolve('abuse_first', ['evidence' => ['telemetry' => 'minimal']])['telemetry']);
    }

    public function testTheDecoyReaderFollowsTheServerSideStages(): void
    {
        foreach (['abuse_first', 'high_abuse', 'balanced', 'ha_safe', 'privacy_strict', null] as $profile) {
            self::assertTrue(RiskStageComposition::resolve($profile, [])['decoy'], "$profile wires the decoy-escalation reader");
        }
        self::assertFalse(RiskStageComposition::resolve('compatibility', [])['decoy'], 'compatibility keeps the plain pipeline');
    }
}
