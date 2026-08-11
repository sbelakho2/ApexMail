<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Symfony\Kernel;

use KiwiCaptcha\Challenge;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Symfony\Controller\ChallengeController;
use KiwiCaptcha\Symfony\Form\KiwiCaptchaType;
use KiwiCaptcha\Symfony\Validator\KiwiCaptcha;
use KiwiCaptcha\Symfony\Validator\KiwiCaptchaValidator;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintViolationListInterface;

/**
 * Boots a real Symfony kernel and exercises the bundle's actual service
 * wiring: configured secret, widget markup, challenge endpoint JSON, and
 * end-to-end validation through the container's validator/form services.
 */
final class KernelIntegrationTest extends TestCase
{
    private static ?TestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new TestKernel('test', true);
        self::$kernel->boot();
        $this->container()->get('request_stack')->push(
            Request::create('/login', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']),
        );
    }

    private function container(): ContainerInterface
    {
        return self::$kernel->getContainer()->get('test.service_container');
    }

    private function twig(): \Twig\Environment
    {
        return $this->container()->get('twig');
    }

    private function solveToken(Challenge $challenge): string
    {
        $counter = 0;
        $saltBytes = base64_decode($challenge->salt, true);
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();
    }

    /**
     * The core enforces the minimum solve duration with a server-measured
     * clock; tests issue and verify in the same process, so wait out the
     * floor before submitting.
     */
    private function waitOutMinDuration(Challenge $challenge): void
    {
        usleep(($challenge->minDurationMs + 10) * 1000);
    }

    public function testValidatorIsWiredWithConfiguredSecret(): void
    {
        $validator = $this->container()->get(KiwiCaptchaValidator::class);
        $property = new \ReflectionProperty(KiwiCaptchaValidator::class, 'configuredSecretKey');
        self::assertSame(TestKernel::SECRET, $property->getValue($validator));

        $config = $this->container()->get('kiwicaptcha.config');
        self::assertSame(TestKernel::SECRET, $config->secretKey);
    }

    public function testFormRendersTokenInput(): void
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'expected_scope' => 'login',
        ]);

        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);

        self::assertStringContainsString('name="captcha[kiwi__token]"', $html);
    }

    public function testWidgetFunctionEmitsNonceWhenProvided(): void
    {
        $html = $this->twig()->render('@Test/widget-function.html.twig', ['nonce' => 'n-csp-abc123']);

        self::assertStringContainsString('<style nonce="n-csp-abc123">', $html);
        self::assertSame(2, substr_count($html, '<script nonce="n-csp-abc123">'));
        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
        self::assertStringContainsString('name="kiwi__token"', $html);
    }

    public function testWidgetFunctionOmitsNonceAttributeWhenAbsent(): void
    {
        $html = $this->twig()->render('@Test/widget-function.html.twig');

        self::assertStringContainsString('<style>', $html);
        self::assertSame(2, substr_count($html, '<script>'));
    }

    public function testChallengeControllerReturnsJsonShape(): void
    {
        $controller = $this->container()->get(ChallengeController::class);
        $request = Request::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

        $response = $controller->challenge($request);
        self::assertSame(200, $response->getStatusCode());

        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('sha256', $data['algorithm']);
        self::assertSame(8, $data['targetBits']);
        self::assertNotEmpty($data['nonce']);
        self::assertNotEmpty($data['salt']);
        self::assertNotEmpty($data['challenge']);
        self::assertNotEmpty($data['prefix']);
        self::assertStringContainsString($data['challenge'], $data['prefix']);
        self::assertArrayHasKey('ttlSecs', $data);
        self::assertArrayHasKey('minDurationMs', $data);
        // The signed challenge payload embeds the issued scope.
        $payload = base64_decode((string) strtok($data['challenge'], '.'), true);
        self::assertIsString($payload);
        self::assertStringContainsString('|login|', $payload);
    }

    public function testEndToEndValidationThroughValidatorService(): void
    {
        $issuer = $this->container()->get('kiwicaptcha.issuer');
        $challenge = $issuer->issue('login', '198.51.100.7');
        $this->waitOutMinDuration($challenge);

        $dto = new class {
            #[KiwiCaptcha(scope: 'login')]
            public ?string $kiwiToken = null;
        };
        $dto->kiwiToken = $this->solveToken($challenge);

        $validator = $this->container()->get('validator');
        $violations = $validator->validate($dto);
        self::assertCount(0, $violations, $this->describe($violations));

        // Single-use: replaying the same token must now fail.
        $violations = $validator->validate($dto);
        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
    }

    public function testEndToEndValidationThroughForm(): void
    {
        $issuer = $this->container()->get('kiwicaptcha.issuer');
        $challenge = $issuer->issue('login', '198.51.100.7');
        $this->waitOutMinDuration($challenge);
        $token = $this->solveToken($challenge);

        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'expected_scope' => 'login',
        ]);
        $form->submit(['kiwi__token' => $token]);
        self::assertTrue($form->isValid());

        // Replay: same token on a fresh form must fail.
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'expected_scope' => 'login',
        ]);
        $form->submit(['kiwi__token' => $token]);
        self::assertFalse($form->isValid());
    }

    private function describe(ConstraintViolationListInterface $violations): string
    {
        $messages = [];
        foreach ($violations as $violation) {
            $messages[] = $violation->getMessage();
        }

        return implode('; ', $messages);
    }
}
