<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;

/**
 * ExecutionChallengeV1 bundle wiring: the execution_key config node, the
 * risk.execution_challenge gate, the protection-profile matrix
 * (privacy_strict forces off, high_abuse arms, balanced default off),
 * the compile-time gate-without-key refusal, and the end-to-end armed
 * issuance + verification through the real controller.
 *
 * The dimension is supplementary evidence only, never the sole
 * acceptance boundary: the PoW proof and the record state machinery
 * always gate.
 */
final class ExecutionChallengeDimensionTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const EXECUTION_KEY = 'fedcba9876543210fedcba9876543210';

    /**
     * @param array<int, array<string, mixed>> $layers
     */
    private function load(array $layers): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $container->register('fake_redis', FakePredisClient::class);
        // The request stack is required when the risk engine is wired
        // (the request-scope admission gate); the fixture registers a
        // minimal stand-in.
        $container->register('request_stack', \Symfony\Component\HttpFoundation\RequestStack::class);
        (new KiwiCaptchaExtension())->load($layers, $container);

        return $container;
    }

    private function baseConfig(): array
    {
        return [
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'off'],
        ];
    }

    public function testBalancedProfileDefaultsTheGateOff(): void
    {
        $container = $this->load([[
            'protection_profile' => 'balanced',
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
        ]]);

        self::assertFalse(
            $container->getDefinition(ChallengeController::class)->getArgument('$executionGate'),
            'balanced must leave the execution gate off by default',
        );
        self::assertSame(
            self::EXECUTION_KEY,
            $container->getDefinition('kiwi_captcha.config')->getArgument('$executionKey'),
        );
    }

    public function testHighAbuseProfileArmsTheGate(): void
    {
        $container = $this->load([[
            'protection_profile' => 'high_abuse',
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            // high_abuse enables the risk engine, which requires a
            // Predis client (the fixture stands in for it).
            'risk' => ['redis_service' => 'fake_redis'],
        ]]);

        self::assertTrue(
            $container->getDefinition(ChallengeController::class)->getArgument('$executionGate'),
            'high_abuse must arm the execution gate by default',
        );
    }

    public function testPrivacyStrictProfileForcesTheGateOffEvenAgainstAnExplicitOverride(): void
    {
        $container = $this->load([[
            'protection_profile' => 'privacy_strict',
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            // An explicit override in ANY layer must not re-arm the
            // dimension under the strongest privacy posture.
            'risk' => ['enabled' => false, 'execution_challenge' => 'on'],
        ]]);

        self::assertFalse(
            $container->getDefinition(ChallengeController::class)->getArgument('$executionGate'),
            'privacy_strict must force the execution gate off regardless of explicit overrides',
        );
    }

    public function testGateOnWithoutExecutionKeyIsInertNotABreakage(): void
    {
        // The gate on without a key never arms (the dimension is
        // supplementary evidence only — an inert gate is never a
        // security hole), so an existing high_abuse deployment without
        // the key keeps issuing byte-identically.
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => null,
            'risk' => ['enabled' => false, 'execution_challenge' => 'on'],
        ]]);

        self::assertTrue(
            $container->getDefinition(ChallengeController::class)->getArgument('$executionGate'),
            'the gate itself is on',
        );
        self::assertNull(
            $container->getDefinition('kiwi_captcha.config')->getArgument('$executionKey'),
        );
    }

    public function testShortExecutionKeyIsRefusedAtConfigTime(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => 'short',
            'risk' => ['execution_challenge' => 'on'],
        ]]);
    }

    public function testArmedIssuanceAndVerificationThroughTheController(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);
        self::assertTrue($container->getDefinition(ChallengeController::class)->getArgument('$executionGate'));

        // Without the risk engine deciding, the gate itself is the
        // trigger: every issuance is armed.
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
        ], '{"scope":"login","action":"login-action"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);

        self::assertArrayHasKey('execution_program', $payload, 'an armed issuance must carry the execution program');
        self::assertTrue(ExecutionChallengeGenerator::isValidProgram($payload['execution_program']));

        // The stored record carries the same program.
        $storage = $container->get('kiwi_captcha.storage.array');
        self::assertInstanceOf(ArrayStorage::class, $storage);
        $record = $storage->find($payload['nonce']);
        self::assertNotNull($record);
        self::assertSame($payload['execution_program'], $record->executionProgram);

        // Verify: correct digest -> valid; wrong digest -> the
        // deterministic execution_mismatch; missing digest -> mismatch.
        $expected = ExecutionChallengeGenerator::expectedDigest($payload['execution_program'], $payload['nonce']);
        self::assertNotNull($expected);

        // The risk engine escalates the issued difficulty above the
        // configured floor, so the solver must match the bits the
        // response actually carries; the winning counter is a pure
        // function of the challenge, so it is computed once and reused
        // for every token.
        $counter = $this->winningCounter($payload);

        $verifier = new Verifier($storage, now: static fn (): int => time());

        $good = SolutionToken::create($payload['nonce'], $counter, 5000, [], $expected)->encode();
        self::assertTrue($verifier->verify($good, self::SECRET, 'login', '127.0.0.1')->isOk());

        $wrong = SolutionToken::create($payload['nonce'], $counter, 5000, [], str_repeat('0', 64))->encode();
        self::assertSame(VerifyError::ExecutionMismatch, $verifier->verify($wrong, self::SECRET, 'login', '127.0.0.1')->error);

        $missing = SolutionToken::create($payload['nonce'], $counter, 5000, [])->encode();
        self::assertSame(VerifyError::ExecutionMismatch, $verifier->verify($missing, self::SECRET, 'login', '127.0.0.1')->error);
    }

    public function testGateOffIssuanceIsByteIdenticalLegacy(): void
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'off'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);

        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
        ], '{"scope":"login"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayNotHasKey('execution_program', $payload, 'the gate off must not arm the dimension');
    }

    /**
     * Brute-force a counter whose SHA-256(prefix || counter || salt)
     * meets the issued target bits — the same derivation the browser
     * solver performs. Unbounded like the repository's other solver
     * helpers: the risk engine may escalate the issued difficulty, so
     * the search matches the response's bits and terminates with
     * probability 1.
     *
     * @param array<string, mixed> $challenge
     */
    private function winningCounter(array $challenge): int
    {
        $salt = base64_decode($challenge['salt'], true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge['prefix'].$counter.$salt, true);
            $counter++;
        } while (\KiwiCaptcha\Verifier::leadingZeroBits($hash) < $challenge['targetBits']);

        return $counter - 1;
    }
}
