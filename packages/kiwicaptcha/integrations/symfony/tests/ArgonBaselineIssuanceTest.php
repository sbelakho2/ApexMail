<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ChallengeStrength;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use KiwiCaptcha\ChallengeProfile;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Storage\ArrayStorage;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakeRiskStateStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The application's configured strength is the floor of every adaptive
 * decision. These are the controller-level regressions for the
 * complete-profile strength authority. An Argon-configured deployment
 * must never issue less work than its configured baseline because risk
 * decided a lower action. The strength comparison must also use the
 * full memory/time/parallelism/target envelope, not target bits alone.
 */
final class ArgonBaselineIssuanceTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /**
     * @return array{gateway: RiskGateway, resolver: RiskProfileResolver}
     */
    private function gatewayForMinimum(string $minimum, RiskProfileResolver $resolver): array
    {
        $keys = RiskKeys::fromMaster(self::SECRET);
        $classifier = new CidrNetworkClassifier([]);
        $policy = RiskPolicy::fromConfig([
            'version' => RiskPolicy::CONTRACT_VERSION,
            'global_floors' => [0 => 'allow', 1 => 'allow', 2 => 'allow', 3 => 'allow', 4 => 'allow'],
            'weights' => [],
            'scopes' => [1 => ['base_risk' => 100, 'minimum' => $minimum, 'post_solve_check' => false, 'degraded' => 'allow']],
        ]);
        $store = new FakeRiskStateStore();
        $engine = new AdaptiveRiskEngine($store, $classifier, new RiskIdentityFactory($keys), new RiskScorer(), $policy, $keys);

        return ['gateway' => new RiskGateway($engine, $classifier, $resolver, ['login' => 1], policy: $policy), 'resolver' => $resolver];
    }

    private function argonResolver(): RiskProfileResolver
    {
        // An Argon deployment at 16 MiB, t=3, p=1, target 4 (the config
        // defaults an operator gets with algorithm argon2id and the
        // documented argon2_difficulty_bits).
        return new RiskProfileResolver(
            PoWAlgorithm::Argon2id,
            difficultyBits: 4,
            argonMKib: 16384,
            argonT: 3,
            argonP: 1,
            argon2DifficultyBits: 4,
            argonEnvelopeMemoryKib: 16384,
            argonTargetBits: [1, 2, 4],
        );
    }

    public function testAnArgon16DecisionNeverWeakensTheConfiguredArgonBaseline(): void
    {
        // Finding 1, controller level: the pre-issue decision is Argon16
        // (the scope minimum) while the application is configured at
        // target 4. profileFor(Argon16) must be a no-op — the issued
        // challenge keeps the configured target and the full baseline.
        $resolver = $this->argonResolver();
        self::assertNull($resolver->profileFor(\KiwiCaptcha\Risk\RiskAction::Argon16), 'Argon16 never downgrades the configured target 4');

        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(
            secretKey: self::SECRET,
            algorithm: PoWAlgorithm::Argon2id,
            mKib: 16384,
            t: 3,
            p: 1,
            argon2TargetBits: 4,
            ttlSecs: 120,
        ), $storage);
        $risk = $this->gatewayForMinimum('argon16', $resolver);
        $controller = new ChallengeController(
            $issuer,
            null,
            false,
            $risk['gateway'],
            null,
            storage: $storage,
            policyVersion: 1,
        );

        $response = $controller->challenge(JsonRequest::create(
            '/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        ));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('argon2id', $data['algorithm']);
        self::assertSame(16384, $data['mKib'], 'the configured memory baseline is preserved');
        self::assertSame(3, $data['t'], 'the configured iteration baseline is preserved');
        self::assertSame(1, $data['p']);
        self::assertGreaterThanOrEqual(4, $data['targetBits'], 'an Argon16 decision never issues below the configured target 4');

        // The issued challenge satisfies every action at or below the
        // baseline, including the cross-family SHA rungs (finding 8): the
        // configured memory-hard baseline dominates them, so a fresh SHA
        // requirement can never open a chain against it.
        $strength = new ChallengeStrength(PoWAlgorithm::Argon2id, (int) $data['mKib'], (int) $data['t'], (int) $data['p'], (int) $data['targetBits']);
        self::assertTrue($resolver->strengthSatisfies($strength, \KiwiCaptcha\Risk\RiskAction::Argon16));
        self::assertTrue($resolver->strengthSatisfies($strength, \KiwiCaptcha\Risk\RiskAction::Sha18), 'the Argon baseline dominates a SHA rung');
        $raised = new RiskProfileResolver(PoWAlgorithm::Argon2id, 4, 16384, 3, 1, 4, 16384, [1, 2, 6]);
        self::assertFalse(
            $raised->strengthSatisfies($strength, \KiwiCaptcha\Risk\RiskAction::Argon64),
            'a higher rung still requires more search space',
        );
    }

    public function testAStrongerArgonDecisionRaisesOnlyTheSearchSpace(): void
    {
        // A stronger rung (Argon64 at target 4, the configured ladder's
        // top) rewrites only the target bits of the baseline envelope.
        $resolver = $this->argonResolver();
        $required = $resolver->requiredStrength(\KiwiCaptcha\Risk\RiskAction::Argon64);
        self::assertSame(16384, $required?->mKib);
        self::assertSame(3, $required?->t);
        self::assertSame(1, $required?->p);
        self::assertSame(4, $required?->targetBits);
        self::assertNull($resolver->profileFor(\KiwiCaptcha\Risk\RiskAction::Argon64), 'the top rung equals the configured target: no rewrite');

        // With a weaker configured baseline (target 1), Argon32 raises the
        // target to the rung while preserving the memory envelope.
        $weaker = new RiskProfileResolver(PoWAlgorithm::Argon2id, 1, 16384, 3, 1, 1, 16384, [1, 2, 4]);
        $profile = $weaker->profileFor(\KiwiCaptcha\Risk\RiskAction::Argon32);
        self::assertInstanceOf(ChallengeProfile::class, $profile);
        self::assertSame(2, $profile->targetBits);
        self::assertSame(16384, $profile->mKib);
        self::assertSame(3, $profile->t);
        self::assertSame(1, $profile->p);
    }

    public function testTheMemoryEnvelopeIsPartOfTheStrengthComparison(): void
    {
        // Finding 2: an 8 KiB Argon target-4 proof must NOT satisfy an
        // Argon32 requirement whose required envelope is 16 MiB target 2.
        $resolver = new RiskProfileResolver(PoWAlgorithm::Argon2id, 4, 8, 3, 1, 4, 16384, [1, 2, 4]);
        $required = $resolver->requiredStrength(\KiwiCaptcha\Risk\RiskAction::Argon32);
        self::assertSame(16384, $required?->mKib);
        self::assertSame(3, $required?->t);
        self::assertSame(1, $required?->p);
        self::assertSame(4, $required?->targetBits, 'the baseline target 4 is preserved');

        $smallProof = new ChallengeStrength(PoWAlgorithm::Argon2id, 8, 3, 1, 4);
        self::assertFalse(
            $resolver->strengthSatisfies($smallProof, \KiwiCaptcha\Risk\RiskAction::Argon32),
            'an 8 KiB proof can never satisfy a 16 MiB requirement, however high its target bits',
        );
        self::assertTrue(
            $resolver->strengthSatisfies($smallProof, \KiwiCaptcha\Risk\RiskAction::Sha18),
            'the SHA rung stays dominated by the configured Argon baseline',
        );

        $fullProof = new ChallengeStrength(PoWAlgorithm::Argon2id, 16384, 3, 1, 4);
        self::assertTrue($resolver->strengthSatisfies($fullProof, \KiwiCaptcha\Risk\RiskAction::Argon32));
        self::assertFalse(
            $resolver->strengthSatisfies(new ChallengeStrength(PoWAlgorithm::Argon2id, 16384, 2, 1, 4), \KiwiCaptcha\Risk\RiskAction::Argon32),
            'fewer iterations at the same memory is not at least as strong',
        );
        self::assertFalse(
            $resolver->strengthSatisfies(new ChallengeStrength(PoWAlgorithm::Sha256, 0, 0, 1, 64), \KiwiCaptcha\Risk\RiskAction::Sha18),
            'a foreign family never dominates the required family',
        );
    }

    public function testDormantCoreArgonKnobsNeverLeakIntoAdaptiveProfiles(): void
    {
        // A sha256 deployment may carry inert argon_m_kib/argon_t/argon_p
        // values (the core validates them only for argon2id): the adaptive
        // profile must come entirely from risk.argon_verification_memory_kib
        // at t=3, p=1. Borrowing the dormant knobs would either build an
        // invalid profile (argon_p: 2, which ChallengeProfile::validate
        // rejects with p === 1) or silently raise the server verification
        // cost the adaptive envelope explicitly bounds.
        $matrices = [
            ['mKib' => 65536],
            ['t' => 6],
            ['p' => 2],
            ['mKib' => 65536, 't' => 6, 'p' => 2],
        ];
        $actions = [
            [\KiwiCaptcha\Risk\RiskAction::Argon16, 1],
            [\KiwiCaptcha\Risk\RiskAction::Argon32, 2],
            [\KiwiCaptcha\Risk\RiskAction::Argon64, 4],
        ];
        foreach ($matrices as $dormant) {
            $resolver = new RiskProfileResolver(
                PoWAlgorithm::Sha256,
                difficultyBits: 8,
                argonMKib: $dormant['mKib'] ?? 16384,
                argonT: $dormant['t'] ?? 3,
                argonP: $dormant['p'] ?? 1,
                argon2DifficultyBits: 9,
                argonEnvelopeMemoryKib: 16384,
                argonTargetBits: [1, 2, 4],
            );
            foreach ($actions as [$action, $rung]) {
                $profile = $resolver->profileFor($action);
                self::assertInstanceOf(ChallengeProfile::class, $profile, $action->value.' must map to a profile');
                $profile->validate();
                self::assertSame(PoWAlgorithm::Argon2id, $profile->algorithm);
                self::assertSame(16384, $profile->mKib, $action->value.': the adaptive envelope, never the dormant core knob');
                self::assertSame(3, $profile->t, $action->value.': the adaptive iteration count');
                self::assertSame(1, $profile->p, $action->value.': p === 1, the only interoperable profile');
                self::assertSame($rung, $profile->targetBits);
                $required = $resolver->requiredStrength($action);
                self::assertSame(16384, $required?->mKib);
                self::assertSame(3, $required?->t);
                self::assertSame(1, $required?->p);
            }
        }
    }

    public function testAShaDeploymentWithADormantArgonPStillIssuesAValidAdaptiveChallenge(): void
    {
        // The reachable production failure: algorithm sha256 with
        // argon_p: 2 (accepted by the config tree because p is validated
        // only for argon2id) used to mint an invalid Argon profile on the
        // first high-risk decision, surfacing as a 422 invalid-scope (the wire code spelling) for
        // a perfectly valid scope. The issued challenge is the adaptive
        // envelope with p === 1.
        $resolver = new RiskProfileResolver(
            PoWAlgorithm::Sha256,
            difficultyBits: 8,
            argonMKib: 65536,
            argonT: 6,
            argonP: 2,
            argon2DifficultyBits: 9,
            argonEnvelopeMemoryKib: 16384,
            argonTargetBits: [1, 2, 4],
        );
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage);
        $risk = $this->gatewayForMinimum('argon16', $resolver);
        $controller = new ChallengeController(
            $issuer,
            null,
            false,
            $risk['gateway'],
            null,
            storage: $storage,
            policyVersion: 1,
        );

        $response = $controller->challenge(JsonRequest::create(
            '/challenge',
            'POST',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '198.51.100.7'],
            '{"scope":"login"}',
        ));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $data = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('argon2id', $data['algorithm'], 'the high-risk decision escalates into the adaptive Argon envelope');
        self::assertSame(16384, $data['mKib'], 'the dormant argon_m_kib never leaks into the profile');
        self::assertSame(3, $data['t'], 'the dormant argon_t never leaks into the profile');
        self::assertSame(1, $data['p'], 'p === 1, the only interoperable profile');
        self::assertSame(1, $data['targetBits'], 'the adaptive rung');
    }

    public function testRswCannotBeCombinedWithAdaptiveRisk(): void
    {
        // Finding 8: RSW has no adaptive-risk ordering. The bundle refuses
        // the combination at configuration time rather than treating RSW
        // as both "strong enough" and "not strong enough" depending on
        // the method.
        $container = new \Symfony\Component\DependencyInjection\ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', '/tmp/kiwi-rsw-risk');
        $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class);
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/rsw.*risk|risk.*rsw/');
        (new \BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'difficulty_bits' => 8,
            'algorithm' => 'rsw',
            'rsw_modulus_n' => \KiwiCaptcha\Tests\Support\RswFixture::MODULUS_N_B64,
            'rsw_lambda' => \KiwiCaptcha\Tests\Support\RswFixture::LAMBDA_B64,
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'namespace' => 'rsw-risk-test'],
        ]], $container);
    }
}
