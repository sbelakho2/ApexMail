<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The bounded-read fallback contract of the challenge and cancellation
 * endpoints: when Symfony hands back no stream resource from
 * getContent(true), the reader returns the empty string instead of the
 * unbounded buffered content. The strict decoders therefore refuse the
 * request and an oversized buffered body is never materialized.
 */
final class BoundedBodyReadFallbackTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function controller(): ChallengeController
    {
        $storage = new ArrayStorage();

        return new ChallengeController(
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
        );
    }

    /**
     * A Request whose getContent(true) hands back no resource and whose
     * buffered getContent() would be a megabyte: the fallback must never
     * read it.
     */
    private function streamlessRequest(string $uri): Request
    {
        return new class($uri) extends Request {
            public int $bufferedReads = 0;

            public function __construct(string $uri)
            {
                parent::__construct([], [], [], [], [], [
                    'REQUEST_METHOD' => 'POST',
                    'CONTENT_TYPE' => 'application/json',
                    'REQUEST_URI' => $uri,
                ]);
            }

            public function getContent(bool $asResource = false): string|false
            {
                if ($asResource) {
                    return false;
                }
                $this->bufferedReads++;

                return str_repeat('A', 1024 * 1024);
            }
        };
    }

    public function testTheChallengeEndpointRefusesAStreamlessBodyWithoutMaterializingIt(): void
    {
        $request = $this->streamlessRequest('/challenge');
        $response = $this->controller()->challenge($request);

        self::assertNotSame(500, $response->getStatusCode(), 'a streamless request is refused by the strict decoder, never a 500');
        $body = (string) $response->getContent();
        self::assertStringNotContainsString('AAAA', $body, 'the oversized buffered content never reaches the response');
        self::assertSame(0, $request->bufferedReads, 'the unbounded buffered content is never materialized');
    }

    public function testTheCancellationEndpointRefusesAStreamlessBodyWithoutMaterializingIt(): void
    {
        $request = $this->streamlessRequest('/challenge/cancel');
        $response = $this->controller()->cancel($request);

        self::assertNotSame(500, $response->getStatusCode(), 'a streamless request is refused by the strict decoder, never a 500');
        self::assertStringNotContainsString('AAAA', (string) $response->getContent());
        self::assertSame(0, $request->bufferedReads, 'the unbounded buffered content is never materialized');
    }
}
