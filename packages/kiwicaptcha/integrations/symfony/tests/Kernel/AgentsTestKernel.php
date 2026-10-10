<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;

/**
 * Kernel with the risk engine and one configured verified agent
 * (RFC 9421 plane): the fake Predis client serves the nonce ledger
 * and the quota windows. The key-set variants model the rotation
 * window: "both" configures the current and the retired key,
 * "current" only the current key (the rebuild that revokes the
 * retired key), "none" leaves the agents plane unconfigured.
 */
class AgentsTestKernel extends TestKernel
{
    public const AGENT_NAME = 'acme-bot';
    public const AGENT_KEY_ID = 'acme-bot-2026q4';

    public const KEY_BOTH = 'both';
    public const KEY_CURRENT = 'current';
    public const KEY_NONE = 'none';

    public function __construct(
        string $environment,
        bool $debug,
        private readonly string $keySet = self::KEY_BOTH,
    ) {
        parent::__construct($environment, $debug);
    }

    /** The deterministic public key of the test agent (base64, raw 32 bytes). */
    public static function agentPublicKeyBase64(): string
    {
        return (new AgentSigner(AgentSigner::seed('kernel-agent')))->publicKeyBase64();
    }

    /** The deterministic public key the revocation rebuild removes. */
    public static function retiredPublicKeyBase64(): string
    {
        return (new AgentSigner(AgentSigner::seed('kernel-retired')))->publicKeyBase64();
    }

    /**
     * The cache dir carries the key-set variant, so the revocation
     * rebuild really recompiles its own container instead of reusing
     * the cached one of the sibling variant (the environment stays
     * "test" for the in-memory storage guard).
     */
    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/kiwicaptcha-symfony-kernel-'.md5(static::class.$this->keySet).'-'.getmypid().'/'.$this->environment;
    }

    protected function build(\Symfony\Component\DependencyInjection\ContainerBuilder $container): void
    {
        $container->addCompilerPass(new class implements \Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface {
            public function process(\Symfony\Component\DependencyInjection\ContainerBuilder $container): void
            {
                foreach ([
                    \BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController::class,
                    \BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentsVerifier::class,
                    'kiwi_captcha.agents.registry',
                    'kiwi_captcha.agents.signature_verifier',
                    'kiwi_captcha.agents.nonce_store',
                    'kiwi_captcha.agents.quota',
                    \BelConsulting\KiwiCaptchaBundle\Risk\OutcomeReporterInterface::class,
                ] as $id) {
                    if ($container->hasDefinition($id)) {
                        $container->getDefinition($id)->setPublic(true);
                    }
                }
            }
        });
    }

    public function registerContainerConfiguration(\Symfony\Component\Config\Loader\LoaderInterface $loader): void
    {
        $keySet = $this->keySet;
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container) use ($keySet): void {
            $container->register('fake_redis', \BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient::class)
                ->setPublic(true);
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
            $risk = [
                'enabled' => true,
                'redis_service' => 'fake_redis',
                'scopes' => [
                    'login' => ['id' => 10],
                ],
            ];
            if ($keySet !== self::KEY_NONE) {
                $publicKeys = [self::agentPublicKeyBase64()];
                if ($keySet === self::KEY_BOTH) {
                    $publicKeys[] = self::retiredPublicKeyBase64();
                }
                $risk['agents'] = [
                    self::AGENT_NAME => [
                        'key_id' => self::AGENT_KEY_ID,
                        'public_keys' => $publicKeys,
                        'allowed_scopes' => ['login'],
                        'per_minute' => 60,
                        'per_day' => 1000,
                        'price_tier' => 'standard',
                        'contact' => 'ops@acme.example',
                    ],
                ];
            }
            $container->loadFromExtension('kiwi_captcha', [
                'secret_key' => self::SECRET,
                'difficulty_bits' => 8,
                'public_base_url' => 'https://captcha.example.com',
                'risk' => $risk,
            ]);
        });
    }
}
