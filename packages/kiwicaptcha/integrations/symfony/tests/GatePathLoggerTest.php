<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Symfony\Component\HttpFoundation\Request;

/**
 * The gate-path diagnostic channel: backend exception details reach the
 * injected PSR-3 logger (structured context), never the response. The
 * guarded paths log through the logger, so the diagnostics are
 * observable wherever the application routes its logs.
 */
final class GatePathLoggerTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    public function testTheBindingAuthorityFailureDetailReachesTheInjectedLoggerNotTheResponse(): void
    {
        $logger = new class() extends AbstractLogger {
            /** @var list<string> */
            public array $messages = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->messages[] = (string) $message.'|'.json_encode($context, JSON_THROW_ON_ERROR);
            }
        };

        $authority = new class() implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                throw new \RuntimeException('authority backend on fire');
            }
        };

        $storage = new ArrayStorage();
        $controller = new ChallengeController(
            new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage),
            null,
            false,
            null,
            null,
            null,
            null,
            [],
            false,
            $storage,
            bindingAuthority: $authority,
            logger: $logger,
        );

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"txn-1"}'));

        // The response is the structured 503 with no backend detail; the
        // detail rides the injected logger's warning with structured
        // context.
        self::assertSame(503, $response->getStatusCode());
        self::assertStringNotContainsString('on fire', (string) $response->getContent(), 'the backend exception detail never reaches the response');
        self::assertCount(1, $logger->messages, 'exactly one gate-path diagnostic is logged');
        self::assertStringContainsString('kiwicaptcha: request binding authority unavailable', $logger->messages[0]);
        self::assertStringContainsString('authority backend on fire', $logger->messages[0], 'the backend exception message travels in the log record');
        self::assertStringContainsString('"message":"authority backend on fire"', $logger->messages[0], 'the detail is structured PSR-3 context');
    }

    public function testARaisingLoggerNeverTurnsTheGuardedFailureIntoA500(): void
    {
        $logger = new class() extends AbstractLogger {
            public function log($level, string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger itself is broken');
            }
        };
        $authority = new class() implements RequestBindingAuthorityInterface {
            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                throw new \RuntimeException('authority backend on fire');
            }
        };
        $storage = new ArrayStorage();
        $controller = new ChallengeController(
            new Issuer(new Config(secretKey: self::SECRET, algorithm: PoWAlgorithm::Sha256, targetBits: 8, ttlSecs: 120), $storage),
            null,
            false,
            null,
            null,
            null,
            null,
            [],
            false,
            $storage,
            bindingAuthority: $authority,
            logger: $logger,
        );

        $response = $controller->challenge(JsonRequest::create('/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login","request_binding":"txn-1"}'));
        self::assertSame(503, $response->getStatusCode(), 'a raising logger must never change the guarded answer');
    }
}
