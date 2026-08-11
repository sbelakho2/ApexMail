<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader;
use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaExtension as TwigExtension;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Reference;

final class KiwiCaptchaExtension extends Extension implements PrependExtensionInterface
{
    private const ARRAY_STORAGE_ID = 'kiwi_captcha.storage.array';

    public function getAlias(): string
    {
        return 'kiwi_captcha';
    }

    /**
     * Auto-register the bundle's challenge route so POST /kiwi-captcha/challenge
     * works out of the box.
     *
     * Bundle controllers are never scanned for #[Route] attributes (the
     * framework only scans the application's src/Controller), so the bundle
     * must contribute its own routing resource. The framework.router.resource
     * option is a single value owned by the application: this prepend only
     * sets it when the application has NOT configured the router at all (a
     * fresh app). Applications that configure framework.router themselves must
     * import the bundle's routes file manually:
     *
     *     # config/routes.yaml
     *     kiwi_captcha:
     *         resource: '@KiwiCaptchaBundle/Resources/config/routes.php'
     */
    public function prepend(ContainerBuilder $container): void
    {
        if (!$container->hasExtension('framework')) {
            return;
        }
        foreach ($container->getExtensionConfig('framework') as $config) {
            if (isset($config['router'])) {
                // The app configures the router itself (own resource or
                // explicitly disabled) — never touch it.
                return;
            }
        }

        $container->prependExtensionConfig('framework', [
            'router' => ['resource' => __DIR__.'/../Resources/config/routes.php'],
        ]);
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // ── Privacy posture enforcement ──────────────────────────────────
        // 'strict' (default) forces the privacy-sensitive options OFF/true:
        //   - telemetry: 'off'      (no client signal fields at all)
        //   - enforce_telemetry: false (an off widget sends EMPTY telemetry;
        //                            enforcing it would reject every user)
        //   - same_origin_only: true (cross-origin POSTs rejected)
        //   - min_duration_ms: 0    (the server-side solve-timing floor is a
        //                            timing heuristic and is disabled)
        // binding_mode is NOT forced: IP binding is a relay mitigation and
        // the stored tag is nonce-bound (never a stable IP identifier), so an
        // operator may still disable it under strict. rate_limit /
        // rate_limit_global already default to nonzero.
        if ($config['privacy_mode'] === 'strict') {
            $config['telemetry'] = 'off';
            $config['enforce_telemetry'] = false;
            $config['same_origin_only'] = true;
            $config['min_duration_ms'] = 0;
        } elseif ($config['enforce_telemetry'] && $config['telemetry'] === 'off') {
            // Impossible combination outside strict mode: enforcement rejects
            // clients whose telemetry is EMPTY (which is exactly what an off
            // widget sends), so every legitimate solve would fail. Refuse the
            // configuration instead of accepting a production trap.
            throw new \InvalidArgumentException(
                'kiwi_captcha.enforce_telemetry cannot be true while telemetry is "off": '.
                'an off widget sends empty telemetry and enforcement rejects it. '.
                'Set telemetry to "minimal"/"full", or disable enforcement.'
            );
        }

        $container->setParameter('kiwi_captcha.secret_key', $config['secret_key']);
        $container->setParameter('kiwi_captcha.route_prefix', $config['route_prefix']);
        $container->setParameter('kiwi_captcha.privacy_mode', $config['privacy_mode']);
        $container->setParameter('kiwi_captcha.telemetry', $config['telemetry']);
        $container->setParameter('kiwi_captcha.binding_mode', $config['binding_mode']);
        $container->setParameter('kiwi_captcha.same_origin_only', $config['same_origin_only']);
        $container->setParameter('kiwi_captcha.rate_limit', $config['rate_limit']);
        $container->setParameter('kiwi_captcha.rate_limit_global', $config['rate_limit_global']);
        $container->setParameter('kiwi_captcha.rate_limit_window_secs', $config['rate_limit_window_secs']);
        $container->setParameter('kiwi_captcha.argon2_semaphore_namespace', $config['argon2_semaphore_namespace']);
        $container->setParameter('kiwi_captcha.enforce_telemetry', $config['enforce_telemetry']);
        $container->setParameter('kiwi_captcha.min_duration_ms', $config['min_duration_ms']);

        $storageRef = $this->resolveStorage($config['storage'], $this->environment($container), $container);
        $redisRef = $this->resolveRedisClient((string) $storageRef, $config['redis_service'], $container);

        // ── Verified core (kiwicaptcha/kiwicaptcha-php): Config, Issuer, Verifier ──
        $configDef = (new Definition(Config::class, [
            $config['secret_key'],
            PoWAlgorithm::from($config['algorithm']),
            $config['argon_m_kib'],
            $config['argon_t'],
            $config['argon_p'],
            $config['difficulty_bits'],
            $config['argon2_difficulty_bits'],
            $config['challenge_ttl_secs'],
            // null = derive the floor from difficulty (standard mode);
            // 0 = timing heuristic off (strict mode / explicit operator choice).
            $config['min_duration_ms'],
            // 10th arg: solver cap (informational, matches the widget).
            5_000_000,
        ]))
            ->setArgument('$bindingMode', $config['binding_mode'] === 'none'
                ? BindingMode::None
                : BindingMode::Bound)
            ->setPublic(true);
        $container->setDefinition('kiwi_captcha.config', $configDef);

        $container->setDefinition('kiwi_captcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwi_captcha.config'),
            $storageRef,
        ]))->setPublic(true));

        // Verifier: the core now takes the Argon2id admission gate natively
        // (VerificationAdmissionGate — consulted only when the STORED record
        // is Argon2id, only after the cheap checks). Admission is enforced
        // against Redis (across all PHP-FPM workers, tokenized leases) when a
        // Redis client is available — either from the 'redis_service' config
        // option or from the RedisStorage storage definition — and falls back
        // to the in-process token-set gate (per-process only).
        // The gate is created whenever the concurrency cap is > 0 —
        // REGARDLESS of the locally configured issuance algorithm. The core
        // verifier consults the gate based on the STORED record's algorithm,
        // and the project supports Rust/PHP interoperable records in shared
        // storage: a Symfony service issuing SHA challenges may still receive
        // a solution for an Argon record written by a Rust service. There is
        // no cost for SHA verifications — the gate is never consulted unless
        // the record actually says Argon2id.
        $gateRef = null;
        if ($config['argon2_max_concurrent_verifications'] > 0) {
            if ($redisRef !== null) {
                $container->setDefinition(
                    'kiwi_captcha.argon2_redis_semaphore',
                    (new Definition(RedisAdmissionSemaphore::class, [
                        $redisRef,
                        $config['argon2_max_concurrent_verifications'],
                        $config['argon2_semaphore_namespace'],
                        $config['argon2_lease_ms'],
                    ]))->setPublic(true),
                );
                $gateRef = new Reference('kiwi_captcha.argon2_redis_semaphore');
            } else {
                $container->setDefinition('kiwi_captcha.argon2_inprocess_gate', (new Definition(InProcessArgonGate::class, [
                    $config['argon2_max_concurrent_verifications'],
                ]))->setPublic(true));
                $gateRef = new Reference('kiwi_captcha.argon2_inprocess_gate');
            }
        }
        $container->setDefinition('kiwi_captcha.verifier', (new Definition(Verifier::class, [
            $storageRef,
            $gateRef,
        ]))->setPublic(true));
        $container->setAlias(StorageInterface::class, (string) $storageRef);

        // ── Challenge endpoint controller (+ issuance rate limiter) ──
        // The limiter is wired whenever either limit is nonzero (defaults are
        // 10 per-client / 500 global). With a Redis client the ATOMIC
        // sliding-window backend enforces both caps across all workers;
        // without one it falls back to the shared PSR-6 pool (rate_limit_cache)
        // or the in-memory window (best-effort, single worker).
        $rateLimiterRef = null;
        if ($config['rate_limit'] > 0 || $config['rate_limit_global'] > 0) {
            $poolRef = $config['rate_limit_cache'] !== null ? new Reference($config['rate_limit_cache']) : null;
            $container->setDefinition('kiwi_captcha.rate_limiter', (new Definition(IssuanceRateLimiter::class, [
                $config['rate_limit'],
                $config['rate_limit_window_secs'],
                $poolRef,
                null,
                // Pepper for the per-IP rate-limit HMAC keys: raw IPs are
                // never stored (defaults to the bundle secret).
                $config['rate_limit_pepper'] ?? $config['secret_key'],
                $redisRef,
                $config['rate_limit_global'],
                $config['argon2_semaphore_namespace'],
                $config['rate_limit_rotation_secs'],
            ]))->setPublic(true));
            $rateLimiterRef = new Reference('kiwi_captcha.rate_limiter');
        }
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
            $rateLimiterRef,
            $config['same_origin_only'],
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // ── Challenge route (configured prefix; see KiwiCaptchaRouteLoader) ──
        $container->setDefinition(KiwiCaptchaRouteLoader::class, (new Definition(KiwiCaptchaRouteLoader::class, [
            '%kiwi_captcha.route_prefix%',
        ]))->addTag('routing.loader'));

        // ── Form type (renders the widget through the form theme) ──
        // The route prefix is injected so the default 'endpoint' option
        // follows the ACTUAL registered route (the standalone Twig widget
        // derives its endpoint from the same prefix); the telemetry mode
        // follows the (strict-enforced) config.
        $container->setDefinition(KiwiCaptchaType::class, (new Definition(KiwiCaptchaType::class, [
            new Reference(KiwiCaptchaRuntime::class),
            '%kiwi_captcha.route_prefix%',
            $config['telemetry'],
        ]))->addTag('form.type'));

        // ── Validator (local verification, no external calls) ──
        $container->setDefinition(KiwiCaptchaValidator::class, (new Definition(KiwiCaptchaValidator::class, [
            new Reference('kiwi_captcha.verifier'),
            new Reference('request_stack'),
            $config['secret_key'],
            $config['enforce_telemetry'],
        ]))->addTag('validator.constraint_validator'));

        // ── Twig widget runtime + twig function (embeds the shared widget assets) ──
        $container->setDefinition(KiwiCaptchaRuntime::class, (new Definition(KiwiCaptchaRuntime::class, [
            $config['route_prefix'],
            null,
            KiwiCaptchaRuntime::DEFAULT_TEMPLATE,
            $config['telemetry'],
        ]))->addTag('twig.runtime'));
        $container->setDefinition(TwigExtension::class, (new Definition(TwigExtension::class))
            ->addTag('twig.extension'));
    }

    /**
     * ArrayStorage is an in-memory, single-process store. A challenge issued
     * in request A is verified in request B, which runs in a different PHP
     * process under PHP-FPM — the record would be lost. Fail hard outside
     * test/dev environments instead of silently breaking every visitor.
     *
     * @throws \LogicException when the in-memory storage is selected for a
     *                         non-test, non-dev environment
     */
    private function resolveStorage(string $storageId, string $environment, ContainerBuilder $container): Reference
    {
        if ($storageId === self::ARRAY_STORAGE_ID) {
            if (!\in_array($environment, ['test', 'dev'], true)) {
                throw new \LogicException(sprintf(
                    'KiwiCaptcha is configured with the in-memory ArrayStorage ("%s"), which cannot persist challenges between requests (challenges are issued in one request and verified in the next; PHP-FPM processes share no memory). This is only allowed in test/dev environments. Configure a shared storage for the "%s" environment, e.g. "storage: kiwicaptcha.storage.redis" using KiwiCaptcha\Storage\RedisStorage (Redis 6.2+, predis or phpredis) or "storage: kiwicaptcha.storage.psr6" backed by a Redis PSR-6 pool (KiwiCaptcha\Storage\Psr6Storage) — or any service implementing KiwiCaptcha\StorageInterface.',
                    self::ARRAY_STORAGE_ID,
                    $environment,
                ));
            }
            $container->setDefinition(self::ARRAY_STORAGE_ID, new Definition(ArrayStorage::class));

            return new Reference(self::ARRAY_STORAGE_ID);
        }

        return new Reference($storageId);
    }

    /**
     * Find the Redis client to use for the Argon2 admission gate and the
     * atomic rate limiter.
     *
     * Priority:
     *  1. the `redis_service` config option (explicit client service id);
     *  2. the storage service when it is a KiwiCaptcha\Storage\RedisStorage
     *     definition (its first constructor argument is the client) —
     *     aliases to the storage id are followed;
     *  3. null — the caller falls back to the in-process gate / best-effort
     *     rate limiting.
     */
    private function resolveRedisClient(string $storageId, ?string $redisService, ContainerBuilder $container): ?Reference
    {
        if ($redisService !== null) {
            return new Reference($redisService);
        }

        $id = $storageId;
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return null;
        }
        $definition = $container->getDefinition($id);
        $class = $definition->getClass();
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return null;
        }
        $client = $definition->getArgument(0);

        return $client instanceof Reference ? $client : null;
    }

    private function environment(ContainerBuilder $container): string
    {
        if ($container->hasParameter('kernel.environment')) {
            return (string) $container->getParameter('kernel.environment');
        }
        if (isset($_SERVER['APP_ENV'])) {
            return (string) $_SERVER['APP_ENV'];
        }

        return 'dev';
    }
}
