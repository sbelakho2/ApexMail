<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Challenge;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\ConstraintViolationListInterface;

/**
 * Boots a real Symfony kernel and exercises the bundle's actual service
 * wiring: configured secret, widget markup (incl. CSP nonce), challenge
 * endpoint JSON, and end-to-end validation through the container's
 * validator/form services.
 */
final class KernelIntegrationTest extends TestCase
{
    private static ?TestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new TestKernel('test', true);
        self::$kernel->boot();
        $this->container()->get('request_stack')->push(
            JsonRequest::create('/login', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']),
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
        $property = new \ReflectionProperty(KiwiCaptchaValidator::class, 'secretKey');
        self::assertSame(TestKernel::SECRET, $property->getValue($validator));

        self::assertSame(TestKernel::SECRET, $this->container()->getParameter('kiwi_captcha.secret_key'));

        $config = $this->container()->get('kiwi_captcha.config');
        self::assertSame(TestKernel::SECRET, $config->secretKey);
    }

    public function testFormRendersWidgetMarkupWithNonce(): void
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'nonce' => 'n-csp-abc123',
        ]);

        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);

        self::assertStringContainsString('<style nonce="n-csp-abc123">', $html);
        self::assertSame(2, substr_count($html, '<script nonce="n-csp-abc123">'));
        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
        self::assertStringContainsString('data-kiwi-telemetry="off"', $html, 'default strict privacy mode renders telemetry off');
        self::assertStringContainsString('name="captcha"', $html);
        self::assertStringContainsString('data-kiwi-token', $html);
        // The inlined assets are present in the form-rendered markup.
        self::assertStringContainsString('.kiwi-container', $html);
        self::assertStringContainsString('KIWI_WASM_B64', $html);
        self::assertStringContainsString('window.KiwiCaptcha = {', $html);
        self::assertStringContainsString('render: kiwiRender', $html);
    }

    public function testFormRendersWidgetMarkupWithoutNonce(): void
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);

        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);

        self::assertStringContainsString('<style>', $html);
        self::assertSame(2, substr_count($html, '<script>'));
    }

    public function testStandaloneWidgetFunctionEmitsNonce(): void
    {
        $html = $this->twig()->render('@Test/widget-function.html.twig', ['nonce' => 'n-csp-xyz']);

        self::assertStringContainsString('<style nonce="n-csp-xyz">', $html);
        self::assertSame(2, substr_count($html, '<script nonce="n-csp-xyz">'));
        self::assertStringContainsString('data-kiwi-endpoint="/kiwi-captcha/challenge"', $html);
        self::assertStringContainsString('data-kiwi-scope="login"', $html);
        self::assertStringContainsString('name="kiwi__token"', $html);
    }

    public function testFormTelemetryOptionOverridesConfigDefault(): void
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'telemetry' => 'minimal',
        ]);

        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringContainsString('data-kiwi-telemetry="minimal"', $html);

        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'telemetry' => 'full',
        ]);
        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringContainsString('data-kiwi-telemetry="full"', $html);

        // Invalid telemetry values are rejected by the options resolver.
        $this->expectException(\Symfony\Component\OptionsResolver\Exception\InvalidOptionsException::class);
        $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['telemetry' => 'bogus']);
    }

    public function testFormRequestBindingOptionRendersTheWidgetAttribute(): void
    {
        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, [
            'scope' => 'login',
            'request_binding' => 'txn-abc',
        ]);

        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);
        self::assertStringContainsString('data-kiwi-request-binding="txn-abc"', $html, 'the form-level transaction binding must render on the widget container');

        // Without the option the attribute is absent (the static config
        // default is null in the test kernel).
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $html = $this->twig()->render('@Test/form.html.twig', ['form' => $form->createView()]);
        // The driver script always mentions the attribute; the container
        // must not carry it when no binding is configured.
        self::assertStringContainsString('data-kiwi-telemetry="off">', $html, 'without the option the widget container must not render data-kiwi-request-binding');
    }

    public function testStandaloneWidgetRequestBindingContext(): void
    {
        $html = $this->twig()->render('@Test/widget-function.html.twig', ['nonce' => 'n-csp-xyz', 'request_binding' => 'standalone-txn']);
        self::assertStringContainsString('data-kiwi-request-binding="standalone-txn"', $html);
    }

    public function testChallengeControllerReturnsJsonShape(): void
    {
        $controller = $this->container()->get(ChallengeController::class);
        $request = JsonRequest::create('/kiwi-captcha/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'], '{"scope":"login"}');

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

    public function testEndToEndValidationThroughForm(): void
    {
        $issuer = $this->container()->get('kiwi_captcha.issuer');
        $challenge = $issuer->issue('login', '198.51.100.7');
        $this->waitOutMinDuration($challenge);

        $factory = $this->container()->get('form.factory');
        // The retry legs below model the explicitly identified idempotent
        // retry (the same kiwi_operation_id re-presented with the token).
        $this->container()->get('request_stack')->getMainRequest()?->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-kernel-test');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $form->submit($this->solveToken($challenge));
        self::assertTrue($form->isValid(), $this->describe($form->getErrors(true)));

        // Retry semantics: an identical replay in the same
        // context returns the same stored result without a second
        // derivation — deterministic retry safety, not reuse of a second
        // operation. A replay under a different binding is rejected.
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $form->submit($this->solveToken($challenge));
        self::assertTrue($form->isValid(), 'same-context retry must return the same stored result');
    }

    public function testEndToEndValidationThroughValidatorService(): void
    {
        $issuer = $this->container()->get('kiwi_captcha.issuer');
        $challenge = $issuer->issue('login', '198.51.100.7');
        $this->waitOutMinDuration($challenge);

        $dto = new class {
            #[KiwiCaptcha(scope: 'login')]
            public ?string $kiwiToken = null;
        };
        $dto->kiwiToken = $this->solveToken($challenge);

        $validator = $this->container()->get('validator');
        // The retry leg below models the explicitly identified idempotent
        // retry (the same kiwi_operation_id re-presented with the token).
        $this->container()->get('request_stack')->getMainRequest()?->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, 'op-kernel-test');
        $violations = $validator->validate($dto);
        self::assertCount(0, $violations, $this->describeViolations($violations));

        // Retry semantics: the same token in the same context
        // returns the same stored result (idempotent), never a second
        // derivation.
        $violations = $validator->validate($dto);
        self::assertCount(0, $violations, 'same-context retry must return the same stored result');
    }

    /**
     * Scope/expected_scope consistency: the form's scope option drives the
     * constraint's expected scope, so a token minted for a 'signup' challenge
     * must be rejected by a form that declares scope 'login' (and vice versa).
     */
    public function testFormScopeIsEnforcedAgainstChallengeScope(): void
    {
        $issuer = $this->container()->get('kiwi_captcha.issuer');
        $challenge = $issuer->issue('signup', '198.51.100.7');
        $this->waitOutMinDuration($challenge);

        $factory = $this->container()->get('form.factory');
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $form->submit($this->solveToken($challenge));

        self::assertFalse($form->isValid(), 'a signup-scoped token must not satisfy a login-scoped form');
        $errors = $this->describe($form->getErrors(true));
        self::assertStringContainsString('security check failed', $errors);

        // The matching scope still passes (the rejection above is scope-driven,
        // not token corruption).
        $challenge = $issuer->issue('login', '198.51.100.7');
        $this->waitOutMinDuration($challenge);
        $form = $factory->createNamed('captcha', KiwiCaptchaType::class, null, ['scope' => 'login']);
        $form->submit($this->solveToken($challenge));
        self::assertTrue($form->isValid(), $this->describe($form->getErrors(true)));
    }

    private function describe(\Traversable $errors): string
    {
        $messages = [];
        foreach ($errors as $error) {
            $messages[] = $error->getMessage();
        }

        return implode('; ', $messages);
    }

    private function describeViolations(ConstraintViolationListInterface $violations): string
    {
        $messages = [];
        foreach ($violations as $violation) {
            $messages[] = $violation->getMessage();
        }

        return implode('; ', $messages);
    }

    /**
     * The real bundle routes must serve the compatibility
     * loader — the browser fixture hid the missing Request
     * import (the controller's type declarations resolved to a
     * nonexistent namespace-local class and the production routes could
     * not dispatch).
     */
    public function testApiJsRouteServesTheLoaderWithEtagRevalidation(): void
    {
        $kernel = self::$kernel;

        $response = $kernel->handle(Request::create('/kiwi-captcha/api.js?compat=recaptcha', 'GET'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/javascript; charset=UTF-8', $response->headers->get('Content-Type'));
        self::assertNotNull($response->headers->get('ETag'), 'the mutable stable URL must carry an ETag for revalidation');
        $body = (string) $response->getContent();
        self::assertStringContainsString('/*KIWI_COMPAT_SPLIT*/', $body);
        self::assertStringContainsString('solver_protocol_version', $body);
        self::assertStringContainsString('compat', $body);

        // Revalidation: the same ETag -> 304, no body.
        $second = $kernel->handle(Request::create(
            '/kiwi-captcha/api.js?compat=recaptcha',
            'GET',
            [],
            [],
            [],
            ['HTTP_IF_NONE_MATCH' => $response->headers->get('ETag')],
        ));
        self::assertSame(304, $second->getStatusCode());
        self::assertSame('', (string) $second->getContent());
    }

    public function testWidgetCssRouteIsServed(): void
    {
        $kernel = self::$kernel;

        $response = $kernel->handle(Request::create('/kiwi-captcha/widget.css', 'GET'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/css; charset=UTF-8', $response->headers->get('Content-Type'));
        self::assertStringContainsString('.kiwi-widget', (string) $response->getContent());
        self::assertNotNull($response->headers->get('ETag'));
    }
}
