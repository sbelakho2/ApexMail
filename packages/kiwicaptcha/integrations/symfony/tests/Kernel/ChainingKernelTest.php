<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The chaining config options compile and reach the REAL wired services:
 * the kernel boots with risk.chaining enabled, the ticket service + Redis
 * state store exist, and BOTH the challenge controller and the validator
 * carry the injected chain service + the configured TLS header.
 */
final class ChainingKernelTest extends TestCase
{
    private static ?ChainingTestKernel $kernel = null;

    protected function setUp(): void
    {
        self::$kernel ??= new ChainingTestKernel('test', true);
        self::$kernel->boot();
    }

    private function container(): ContainerInterface
    {
        return self::$kernel->getContainer()->get('test.service_container');
    }

    private function property(object $object, string $name): mixed
    {
        $prop = new \ReflectionProperty($object, $name);

        return $prop->getValue($object);
    }

    public function testChainingServicesAreWiredAndInjected(): void
    {
        $service = $this->container()->get(ChainedChallengeTicketService::class);
        self::assertInstanceOf(ChainedChallengeTicketService::class, $service);
        self::assertTrue($this->container()->has(RedisChainedChallengeStateStore::class));

        $controller = $this->container()->get(ChallengeController::class);
        self::assertSame($service, $this->property($controller, 'chainTickets'), 'the controller carries the wired chain ticket service');
        self::assertSame('X-Tls-Class', $this->property($controller, 'trustedTlsHeader'), 'the configured TLS header reaches the controller');
        self::assertSame(1, $this->property($controller, 'policyVersion'));
        $authority = $this->property($controller, 'bindingAuthority');
        self::assertInstanceOf(ChainingBindingAuthority::class, $authority, 'the authoritative transaction-binding resolver reaches the controller');
        self::assertSame($this->container()->get('fake_binding_authority'), $authority, 'the controller carries the SAME wired authority service');

        $validator = $this->container()->get(KiwiCaptchaValidator::class);
        self::assertSame($service, $this->property($validator, 'chainTickets'), 'the validator carries the wired chain ticket service');
        self::assertSame(1, $this->property($validator, 'policyVersion'));
        $resolver = $this->property($validator, 'riskResolver');
        self::assertNotNull($resolver, 'the validator carries the wired risk profile resolver (the stage-strength comparison)');
        self::assertSame($this->container()->get('kiwi_captcha.risk.resolver'), $resolver, 'the resolver is the SAME service the risk gateway maps actions with');
        self::assertSame($authority, $this->property($validator, 'bindingAuthority'), 'the validator carries the SAME wired authority service');

        // The controller carries the SAME post-solve disposition store the
        // validator finalizes: a consumed-valid stage-2 challenge is never
        // terminal from the core's consumed result alone.
        $disposition = $this->property($controller, 'postSolveDispositionStore');
        self::assertNotNull($disposition, 'the controller receives the wired post-solve disposition store');
        self::assertSame($this->property($validator, 'dispositionStore'), $disposition, 'the controller and the validator share the SAME disposition store');
    }
}
