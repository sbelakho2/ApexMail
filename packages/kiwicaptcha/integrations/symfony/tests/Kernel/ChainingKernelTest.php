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

        $validator = $this->container()->get(KiwiCaptchaValidator::class);
        self::assertSame($service, $this->property($validator, 'chainTickets'), 'the validator carries the wired chain ticket service');
        self::assertSame(1, $this->property($validator, 'policyVersion'));
    }
}
