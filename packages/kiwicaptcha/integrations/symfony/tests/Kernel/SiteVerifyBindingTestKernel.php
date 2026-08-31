<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use KiwiCaptcha\AtomicDeleteIfPendingInterface;
use KiwiCaptcha\AtomicStorageInterface;
use KiwiCaptcha\CancellableStorageInterface;
use KiwiCaptcha\CancellationResult;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedRecord;
use KiwiCaptcha\ConsumedStateReadableInterface;
use KiwiCaptcha\DeleteIfPendingResult;
use KiwiCaptcha\OperationIdentityAwareStorageInterface;
use KiwiCaptcha\Storage\ArrayStorage;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;

/**
 * A counting storage used by the Siteverify DI-binding tests: every
 * pending→consumed transition increments a public counter, so a test can
 * prove a rejection happened before any consume.
 */
final class CountingStorage implements AtomicStorageInterface, ConsumedStateReadableInterface, OperationIdentityAwareStorageInterface, AtomicDeleteIfPendingInterface, CancellableStorageInterface
{
    public int $consumes = 0;

    public function __construct(private readonly ArrayStorage $inner = new ArrayStorage())
    {
    }

    public function store(ChallengeRecord $record): void
    {
        $this->inner->store($record);
    }

    public function find(string $nonce): ?ChallengeRecord
    {
        return $this->inner->find($nonce);
    }

    public function consume(string $nonce): ?ConsumedRecord
    {
        ++$this->consumes;

        return $this->inner->consume($nonce);
    }

    public function consumeWithOperationIdentity(string $nonce, ?string $operationIdentity): ?ConsumedRecord
    {
        ++$this->consumes;

        return $this->inner->consumeWithOperationIdentity($nonce, $operationIdentity);
    }

    public function commitResult(string $nonce, bool $valid, ?string $binding): bool
    {
        return $this->inner->commitResult($nonce, $valid, $binding);
    }

    public function delete(string $nonce): void
    {
        $this->inner->delete($nonce);
    }

    public function consumedState(string $nonce): ?ConsumedRecord
    {
        return $this->inner->consumedState($nonce);
    }

    public function deleteIfPending(string $nonce): DeleteIfPendingResult
    {
        return $this->inner->deleteIfPending($nonce);
    }

    public function cancel(string $nonce): ?CancellationResult
    {
        return $this->inner->cancel($nonce);
    }
}

/**
 * The fake authoritative transaction-binding resolver of the mandatory
 * regression: every invocation increments a public counter and resolves
 * the txn-A transaction.
 */
final class AuthorityStub implements RequestBindingAuthorityInterface
{
    public int $calls = 0;

    public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
    {
        ++$this->calls;

        return 'txn-A';
    }
}

/**
 * The mandatory regression kernel: risk.request_binding_authority +
 * risk.siteverify_secrets wired through the real container, so the test
 * proves the SiteVerifyController receives the authority via DI (a
 * unit-constructed controller can never catch a wiring hole).
 */
final class SiteVerifyBindingTestKernel extends TestKernel
{
    public const SITEVERIFY_SECRET = '0123456789abcdef0123456789abcdef';

    protected function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                foreach (['kiwi_captcha.issuer', SiteVerifyController::class, 'test.binding_authority', 'kiwi_captcha.storage.array'] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    } elseif ($container->hasAlias($id)) {
                        $container->getAlias($id)->setPublic(true);
                    }
                }
            }
        });
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->register('test.binding_authority', AuthorityStub::class);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            $container->loadFromExtension('twig', [
                'form_themes' => ['@KiwiCaptcha/form_div_layout.html.twig'],
                'paths' => [
                    __DIR__.'/templates' => 'Test',
                ],
            ]);
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => [
                    'enabled' => false,
                    'redis' => ['ttl_margin_secs' => 90],
                    'request_binding_authority' => 'test.binding_authority',
                    'siteverify_secrets' => [self::SITEVERIFY_SECRET => 'payment'],
                    'policy_version' => 1,
                ],
            ]);
        });
    }
}
