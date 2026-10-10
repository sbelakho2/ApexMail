<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\ConstraintViolationListInterface;

/**
 * The Plane-2 evidence stage over the full bundle (change.md 3.2.1).
 * A verified token whose telemetry segment carries an agent-cadence
 * payload produces a post-solve assessment that reflects the evidence
 * stage: the action rises to the first band rung, and the solved 8-bit
 * challenge cannot satisfy it. The disposition is the terminal
 * step-up. The human-cadence payload from the same shared corpus and
 * the absent payload stay the neutral pass. The widget markup carries
 * the profile's telemetry arm and the files tier's telemetry asset
 * attributes.
 *
 * Gated on KC_REDIS_URL like every real-Redis test (the evidence stage
 * composes inside the engine's canonical pipeline, and the fake client
 * cannot serve the risk Lua).
 */
final class EvidenceStageKernelTest extends TestCase
{
    private static ?EvidenceCompositionTestKernel $kernel = null;
    private static ContainerInterface $container;

    private const COOKIE = '__Host-kiwi-session';

    public static function setUpBeforeClass(): void
    {
        if (EvidenceCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set — the evidence-stage proof needs the real risk Lua');
        }
        self::$kernel = new EvidenceCompositionTestKernel('test', true);
        self::$kernel->boot();
        self::$container = self::$kernel->getContainer()->get('test.service_container');
    }

    protected function setUp(): void
    {
        if (EvidenceCompositionTestKernel::redisUrl() === null) {
            self::markTestSkipped('KC_REDIS_URL not set');
        }
        // Each leg starts from a quiet store: the aggregate channels are
        // namespace-global, so a previous leg's pressure must never leak
        // into the next leg's plain posture.
        self::redis()->flushdb();
    }

    private static function redis(): \Predis\Client
    {
        return self::$container->get('kiwi_e2e_redis');
    }

    /**
     * One payload from the shared evidence corpus (the risk cores'
     * evidence vectors), by name.
     *
     * @return array<string, mixed>
     */
    private static function corpusPayload(string $name): array
    {
        $path = dirname(__DIR__, 6).'/protocol/telemetry-v1/evidence-vectors.json';
        self::assertFileExists($path, 'the shared evidence corpus must ship with the repository');
        $corpus = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        foreach ($corpus['interaction_vectors'] as $vector) {
            if ($vector['name'] === $name) {
                return $vector['payload'];
            }
        }

        throw new \RuntimeException(sprintf('vector "%s" missing from the shared corpus', $name));
    }

    private static function solveToken(Challenge $challenge, array $telemetry = []): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, $telemetry)->encode();
    }

    private static function issue(string $ip): Challenge
    {
        return self::$container->get('kiwi_captcha.issuer')->issue('login', $ip);
    }

    private static function validate(string $token, string $ip, string $session): ConstraintViolationListInterface
    {
        $request = Request::create('https://captcha.example.com/login', 'POST', ['kiwi__token' => $token], [self::COOKIE => $session], [], [
            'REMOTE_ADDR' => $ip,
        ]);
        self::$container->get('request_stack')->push($request);
        $dto = new class {
            #[KiwiCaptcha(scope: 'login')]
            public ?string $kiwiToken = null;
        };
        $dto->kiwiToken = $token;
        $violations = self::$container->get('validator')->validate($dto);
        self::$container->get('request_stack')->pop();

        return $violations;
    }

    private static function violationCodes(ConstraintViolationListInterface $violations): array
    {
        $codes = [];
        foreach ($violations as $violation) {
            $codes[] = $violation->getCode();
        }

        return $codes;
    }

    public function testWidgetMarkupCarriesTheProfileTelemetryArmAndTheAssetAttributes(): void
    {
        $runtime = self::$container->get(KiwiCaptchaRuntime::class);
        $runtime->reset();
        $html = $runtime->renderWidget(self::$container->get('twig'), ['endpoint' => '/kiwi-captcha/challenge']);
        self::assertStringContainsString('data-kiwi-telemetry="full"', $html, 'the abuse profile arms the full evidence telemetry');
        self::assertStringContainsString('data-kiwi-telemetry-src="/kiwi-captcha/assets/telemetry.', $html, 'the files tier carries the versioned telemetry asset URL');
        self::assertStringContainsString('data-kiwi-telemetry-integrity="sha256-', $html, 'the telemetry asset URL carries its SRI digest');
    }

    public function testAgentCadencePayloadEscalatesThePostSolveAssessment(): void
    {
        // One address per leg: the profile's nonce-ip binding signs the
        // issuance address, so the solve must redeem where it was minted.
        $session = bin2hex(random_bytes(16));
        $token = self::solveToken(self::issue('10.60.0.1'), self::corpusPayload('agent-metronomic-typing'));

        $violations = self::validate($token, '10.60.0.1', $session);

        // The evidence stage raises the composed action to the first band
        // rung; the solved 8-bit challenge cannot satisfy it and chaining
        // is unavailable, so the disposition is the terminal step-up.
        self::assertContains(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED, self::violationCodes($violations), (string) json_encode(self::violationCodes($violations)));
    }

    public function testHumanCadencePayloadStaysTheNeutralPass(): void
    {
        $session = bin2hex(random_bytes(16));
        $token = self::solveToken(self::issue('10.60.1.1'), self::corpusPayload('human-mixed-cadence'));

        $violations = self::validate($token, '10.60.1.1', $session);

        self::assertCount(0, $violations, (string) json_encode(self::violationCodes($violations)));
    }

    public function testAbsentPayloadStaysTheNeutralPass(): void
    {
        $session = bin2hex(random_bytes(16));
        $token = self::solveToken(self::issue('10.60.2.1'));

        $violations = self::validate($token, '10.60.2.1', $session);

        self::assertCount(0, $violations, (string) json_encode(self::violationCodes($violations)));
    }

    public function testAnOverBoundTelemetrySegmentIsTheNeutralState(): void
    {
        $session = bin2hex(random_bytes(16));
        // A segment over the contract bound never reaches the engine as
        // an assessment input (the gateway bounds it): the solve passes.
        $token = self::solveToken(self::issue('10.60.3.1'), ['pad' => str_repeat('a', 600)]);

        $violations = self::validate($token, '10.60.3.1', $session);

        self::assertCount(0, $violations, (string) json_encode(self::violationCodes($violations)));
    }

    public function testTheRungMapperNamesThePublishedClientPerformanceRungs(): void
    {
        $record = static fn (PoWAlgorithm $algorithm, int $targetBits, int $t): ChallengeRecord => new ChallengeRecord(
            nonce: 'n',
            scope: 'login',
            bindingTag: '',
            issuedAt: 0,
            expiresAt: 1,
            algorithm: $algorithm,
            mKib: 0,
            t: $t,
            p: 1,
            targetBits: $targetBits,
            salt: '',
            prefix: '',
            challenge: '',
            minDurationMs: 0,
        );
        // The well-known rungs of the published per-rung reference table.
        self::assertSame('sha16', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Sha256, 16, 1)));
        self::assertSame('sha18', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Sha256, 18, 1)));
        self::assertSame('sha20', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Sha256, 20, 1)));
        self::assertSame('argon16', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Argon2id, 16, 3)));
        self::assertSame('argon32', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Argon2id, 32, 3)));
        self::assertSame('argon64', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Argon2id, 64, 3)));
        self::assertSame('rsw75k', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Rsw, 1, 75_000)));
        self::assertSame('rsw150k', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Rsw, 1, 150_000)));
        self::assertSame('rsw300k', RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Rsw, 1, 300_000)));
        // Every other profile stays neutral: an unmapped rung must never
        // fabricate evidence (the ordinary 8-bit test difficulty here).
        self::assertNull(RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Sha256, 8, 1)));
        self::assertNull(RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Argon2id, 4, 3)));
        self::assertNull(RiskGateway::solveRungOfRecord($record(PoWAlgorithm::Rsw, 1, 90_000)));
    }
}
