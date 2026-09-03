<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Config;
use KiwiCaptcha\ExecutionChallengeGenerator;
use KiwiCaptcha\TestSupport\ExecutionTraceFixture;
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
            // The storage/limiter Redis: the SecurityEpochMonitor's
            // central security-policy read rides this client, so the
            // test can seed the v4 floor.
            'redis_service' => 'fake_redis',
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);
        self::assertTrue($container->getDefinition(ChallengeController::class)->getArgument('$executionGate'));

        // The two-phase protocol-v4 rollout gate: execution arming
        // requires the confirmed central floor >= 4, so the fake
        // security Redis is seeded with the v4 floor first.
        $redis = $container->get('fake_redis');
        $monitor = $container->get(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        $redis->hset($monitor->policyKey(), 'min_protocol_version', 4);

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

        // Verify: correct digest+trace -> valid; wrong digest -> the
        // deterministic execution_mismatch; missing digest -> mismatch.
        $program = ExecutionChallengeGenerator::decode($payload['execution_program']);
        self::assertNotNull($program);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $expected = ExecutionChallengeGenerator::digestOverTrace($payload['execution_program'], $payload['nonce'], $trace);
        self::assertNotNull($expected);

        // The risk engine escalates the issued difficulty above the
        // configured floor, so the solver must match the bits the
        // response actually carries; the winning counter is a pure
        // function of the challenge, so it is computed once and reused
        // for every token.
        $counter = $this->winningCounter($payload);

        $verifier = new Verifier($storage, now: static fn (): int => time());

        $good = SolutionToken::create($payload['nonce'], $counter, 5000, [], $expected, base64_encode($trace))->encode();
        self::assertTrue($verifier->verify($good, self::SECRET, 'login', '127.0.0.1')->isOk());

        $wrong = SolutionToken::create($payload['nonce'], $counter, 5000, [], str_repeat('0', 64))->encode();
        self::assertSame(VerifyError::ExecutionMismatch, $verifier->verify($wrong, self::SECRET, 'login', '127.0.0.1')->error);

        $missing = SolutionToken::create($payload['nonce'], $counter, 5000, [])->encode();
        self::assertSame(VerifyError::ExecutionMismatch, $verifier->verify($missing, self::SECRET, 'login', '127.0.0.1')->error);
    }

    /**
     * Seed the fake security Redis with the confirmed central policy the
     * two-phase gates require: the protocol-v4 floor (arming) and the
     * execution-grammar floor (version 2 emission), plus the epoch.
     */
    private function seedExecutionPolicy(\BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient $redis, \BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor $monitor, int $protocolFloor = 4, ?int $executionFloor = 2): void
    {
        $redis->hset($monitor->policyKey(), 'min_policy_epoch', '1');
        $redis->hset($monitor->policyKey(), 'min_protocol_version', (string) $protocolFloor);
        if ($executionFloor !== null) {
            $redis->hset($monitor->policyKey(), 'min_execution_version', (string) $executionFloor);
        }
    }

    /**
     * The grammar version byte of a program blob (the byte after the
     * length-prefixed scope and action, before the op count).
     */
    private function programVersion(string $programB64): int
    {
        $blob = base64_decode($programB64, true);
        $pos = 1;
        $pos += 1 + \ord($blob[$pos]);
        $pos += 1 + \ord($blob[$pos]);

        return \ord($blob[$pos]);
    }

    /**
     * A full armed-issuance controller request (the container wiring of
     * {@see self::testArmedIssuanceAndVerificationThroughTheController()},
     * with the node's execution_version cap raised to 2 and the central
     * execution floor seeded). The capability advertisement rides the
     * `Kiwi-Execution-Max-Version` request header exactly like the
     * widget driver sends it; passing null means the request carries no
     * header (an older client that never advertises). Returns the
     * response and the shared in-memory challenge storage.
     *
     * @return array{0: \Symfony\Component\HttpFoundation\Response, 1: \KiwiCaptcha\Storage\ArrayStorage}
     */
    private function armedIssuance(string $json, ?string $capabilityHeader = null, int $requiredVersion = 1): array
    {
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'execution_version' => 2,
            'execution_required_version' => $requiredVersion,
            'redis_service' => 'fake_redis',
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);
        $redis = $container->get('fake_redis');
        $monitor = $container->get(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        $this->seedExecutionPolicy($redis, $monitor);

        $server = [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
        ];
        if ($capabilityHeader !== null) {
            $server['HTTP_Kiwi_Execution_Max_Version'] = $capabilityHeader;
        }
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], $server, $json);
        $response = $controller->challenge($request);

        return [$response, $container->get('kiwi_captcha.storage.array')];
    }

    /** Verify a solved token against the stored record (the core path). */
    private function verifyWithRecord(\KiwiCaptcha\Storage\ArrayStorage $storage, string $nonce, string $token): bool
    {
        $record = $storage->find($nonce);
        self::assertNotNull($record, 'the stored record must exist for the solve to verify');
        $verifier = new Verifier($storage, now: static fn (): int => time());

        return $verifier->verify($token, self::SECRET, 'login', '127.0.0.1')->isOk();
    }

    public function testVersion2GrammarIsIssuedOnlyWhenClientConfigAndFloorAllConfirm(): void
    {
        // The three-way execution-versioning gate: the causal observe
        // grammar (version 2) is issued only when the client advertised
        // the Kiwi-Execution-Max-Version header with a value >= 2 AND
        // the node's execution_version cap is >= 2 AND the confirmed
        // central min_execution_version floor is >= 2. All three hold
        // here; the request body is the bare closed field set, so the
        // header alone carries the capability.
        [$response, $storage] = $this->armedIssuance('{"scope":"login","action":"login-action"}', '2');
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayHasKey('execution_program', $payload, 'an armed issuance must carry the execution program');
        self::assertSame(2, $this->programVersion($payload['execution_program']), 'the version-2 causal grammar is issued to a capable client');
        // The client-facing surface never carries the stored-record
        // canonical fields.
        self::assertArrayNotHasKey('execution_version', $payload, 'execution_version never appears on the client-facing surface');
        self::assertArrayNotHasKey('execution_commitment', $payload, 'execution_commitment never appears on the client-facing surface');
        // The stored record carries the same program the response carries.
        $record = $storage->find($payload['nonce']);
        self::assertNotNull($record);
        self::assertSame($payload['execution_program'], $record->executionProgram, 'the response program is the stored program');
        self::assertSame(2, $record->executionVersion, 'the stored record stamps the emitted grammar version');

        // The program's deterministic trace carries the causal observe
        // entry, and the full solve verifies end to end.
        $program = ExecutionChallengeGenerator::decode($payload['execution_program']);
        self::assertNotNull($program);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        self::assertStringContainsString('obs(', $trace, 'the version-2 grammar writes the causal observe entry');
        $expected = ExecutionChallengeGenerator::digestOverTrace($payload['execution_program'], $payload['nonce'], $trace);
        self::assertNotNull($expected);
        $counter = $this->winningCounter($payload);
        $token = SolutionToken::create($payload['nonce'], $counter, 5000, [], $expected, base64_encode($trace))->encode();
        self::assertTrue($this->verifyWithRecord($storage, $payload['nonce'], $token), 'the version-2 solve must verify');
    }

    public function testRequiredExecutionVersionTwoRefusesIncapableClientsNeverDowngrades(): void
    {
        // The server-owned required tier: with execution_required_version
        // 2, a client that does not advertise execution version 2 must
        // be refused with the deterministic client-unsupported code
        // below — never issued the weaker version-1 grammar, never
        // issued an unarmed challenge. The client capability
        // declaration is never an authority over the grammar a hostile
        // solver must solve.
        foreach ([null, '1', 'abc', '0', '-1'] as $capability) {
            [$response, $storage] = $this->armedIssuance('{"scope":"login","action":"login-action"}', $capability, 2);
            self::assertSame(422, $response->getStatusCode(), 'the incapable client must be refused');
            $body = json_decode((string) $response->getContent(), true);
            self::assertSame('CLIENT_EXECUTION_VERSION_UNSUPPORTED', $body['error']['code'] ?? null, 'the refusal code is deterministic');
            self::assertArrayNotHasKey('execution_program', $body, 'no weaker grammar is ever handed out');
            self::assertArrayNotHasKey('challenge', $body, 'no challenge is handed out');
        }
    }

    public function testRequiredExecutionVersionTwoIssuesVersionTwoToCapableClients(): void
    {
        // A capable client under the required tier still receives the
        // version-2 grammar and the full solve verifies end to end.
        [$response, $storage] = $this->armedIssuance('{"scope":"login","action":"login-action"}', '2', 2);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertArrayHasKey('execution_program', $payload);
        self::assertSame(2, $this->programVersion($payload['execution_program']), 'the required tier issues version 2 to a capable client');
        $program = ExecutionChallengeGenerator::decode($payload['execution_program']);
        self::assertNotNull($program);
        $trace = ExecutionTraceFixture::executedTraceFor($program);
        $expected = ExecutionChallengeGenerator::digestOverTrace($payload['execution_program'], $payload['nonce'], $trace);
        self::assertNotNull($expected);
        $counter = $this->winningCounter($payload);
        $token = SolutionToken::create($payload['nonce'], $counter, 5000, [], $expected, base64_encode($trace))->encode();
        self::assertTrue($this->verifyWithRecord($storage, $payload['nonce'], $token), 'the required-tier version-2 solve must verify');
    }

    public function testRequiredExecutionVersionDefaultOneKeepsTheTransitionBehavior(): void
    {
        // The safe transition default: required tier 1 keeps the
        // capability-negotiated behavior — a headerless request still
        // receives version 1 (stale clients keep working until the
        // operator raises the required tier fleet-wide).
        [$response, $storage] = $this->armedIssuance('{"scope":"login","action":"login-action"}', null, 1);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertSame(1, $this->programVersion($payload['execution_program']), 'default tier 1 emits version 1 to a headerless client');
    }

    public function testClientWithoutTheCapabilityHeaderReceivesVersion1(): void
    {
        // No Kiwi-Execution-Max-Version header on the request: an older
        // client (a driver generation that never advertises, or a widget
        // without the execution tier). The body is the same bare closed
        // field set as the header-2 case above, so the header is what
        // the controller reads. The node cap and the central floor are
        // both at 2, but the client gate alone keeps the issuance at
        // version 1.
        [$response, $storage] = $this->armedIssuance('{"scope":"login"}');
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayHasKey('execution_program', $payload, 'the dimension is still armed (the protocol-v4 floor holds)');
        self::assertSame(1, $this->programVersion($payload['execution_program']), 'a client that never advertised the capability receives version 1');
        $record = $storage->find($payload['nonce']);
        self::assertNotNull($record);
        self::assertSame(1, $record->executionVersion, 'the stored record stamps version 1 for an older client');
    }

    public function testNodeCapBelowTwoKeepsEveryIssuanceAtVersion1(): void
    {
        // The node cap (kiwi_captcha.execution_version) defaults to 1:
        // even a capable client on a confirmed floor-2 fleet receives
        // version 1 until the operator raises the node cap.
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'redis_service' => 'fake_redis',
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);
        self::assertSame(1, $container->getDefinition(ChallengeController::class)->getArgument('$executionVersionCap'), 'the execution_version knob defaults to 1');
        $redis = $container->get('fake_redis');
        $monitor = $container->get(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        $this->seedExecutionPolicy($redis, $monitor);
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
            'HTTP_Kiwi_Execution_Max_Version' => '2',
        ], '{"scope":"login"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertSame(1, $this->programVersion($payload['execution_program']), 'the node cap below 2 keeps issuance at version 1');
    }

    public function testPolicyWithoutTheExecutionFloorKeyKeepsVersion1(): void
    {
        // A confirmed policy with min_protocol_version 4 but no
        // min_execution_version key: the fleet floor is not declared at
        // 2, so a capable client on a cap-2 node still receives version 1
        // (the permissive read 0 is below 2 — version 2 is never emitted
        // until the operator explicitly declares the floor).
        $container = $this->load([[
            'secret_key' => self::SECRET,
            'execution_key' => self::EXECUTION_KEY,
            'execution_version' => 2,
            'redis_service' => 'fake_redis',
            'risk' => ['enabled' => true, 'redis_service' => 'fake_redis', 'execution_challenge' => 'on'],
            'storage' => 'kiwi_captcha.storage.array',
            'difficulty_bits' => 8,
        ]]);
        $controller = $container->get(ChallengeController::class);
        $redis = $container->get('fake_redis');
        $monitor = $container->get(\BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor::class);
        $this->seedExecutionPolicy($redis, $monitor, protocolFloor: 4, executionFloor: null);
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ORIGIN' => 'http://localhost',
            'HTTP_Kiwi_Execution_Max_Version' => '2',
        ], '{"scope":"login"}');
        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertSame(1, $this->programVersion($payload['execution_program']), 'no declared execution floor on the confirmed policy keeps version 1');
    }

    public function testMalformedOrNonPositiveCapabilityHeaderValuesDegradeToVersion1AndNever422(): void
    {
        // The header is a capability claim, never a gate: a value that
        // is empty, garbage or below 2 must degrade to version 1 with a
        // 200 response, exactly like the absent header. Only integer
        // strings parse (2 and above are capped at the node ceiling);
        // a header never produces a 422.
        foreach (['', 'abc', '-1', '0', '1', ' 2', '2.0', '007'] as $value) {
            [$response] = $this->armedIssuance('{"scope":"login"}', $value);
            self::assertSame(200, $response->getStatusCode(), 'header value '.var_export($value, true).' must never 422: '.(string) $response->getContent());
            $payload = json_decode((string) $response->getContent(), true);
            self::assertSame(1, $this->programVersion($payload['execution_program']), 'header value '.var_export($value, true).' degrades to version 1');
        }
        // The negative control: the same wiring issues version 2 for a
        // well-formed header value, so the matrix above is not a broken
        // fixture arm.
        [$response] = $this->armedIssuance('{"scope":"login"}', '2');
        self::assertSame(200, $response->getStatusCode());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertSame(2, $this->programVersion($payload['execution_program']), 'the wiring control: a header value 2 still issues version 2');
    }

    public function testBodyCarryingExecutionMaxVersionIs422UnknownFieldsPreservingTheClosedContract(): void
    {
        // The closed challenge-body field set never grew: a request
        // whose JSON body carries execution_max_version is refused with
        // 422 `UNKNOWN_FIELDS`, with or without the capability header.
        // That is exactly why the capability moved out of the body: a
        // new widget that never sends the field keeps working against a
        // server generation that validates bodies against the closed
        // set.
        [$response] = $this->armedIssuance('{"scope":"login","execution_max_version":2}');
        self::assertSame(422, $response->getStatusCode(), (string) $response->getContent());
        self::assertSame('UNKNOWN_FIELDS', json_decode((string) $response->getContent(), true)['error']['code']);

        [$response] = $this->armedIssuance('{"scope":"login","execution_max_version":2}', '2');
        self::assertSame(422, $response->getStatusCode(), 'a body field is refused before any capability read, even with the header: '.(string) $response->getContent());
        self::assertSame('UNKNOWN_FIELDS', json_decode((string) $response->getContent(), true)['error']['code']);
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
