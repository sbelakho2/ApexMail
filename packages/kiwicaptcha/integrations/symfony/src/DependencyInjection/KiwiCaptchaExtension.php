<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
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
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\LocalEmergencyLimiter;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
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

        // Cross-option invariants (validated here, after the config tree):
        // - a rotation shorter than the sliding window would drop live hits
        //   from epochs older than (current - 1) from the two-epoch
        //   accounting (the limiter constructor enforces the same rule)
        // - a min_duration_ms at or above the TTL leaves no acceptable
        //   submission time (TooFast before expiry, Expired after) — the
        //   core Config validates the same relation.
        if ($config['rate_limit_rotation_secs'] > 0 && $config['rate_limit_rotation_secs'] < $config['rate_limit_window_secs']) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.rate_limit_rotation_secs must be 0 or >= rate_limit_window_secs — '.
                'a rotation shorter than the window would drop live hits from older epochs'
            );
        }
        if ($config['min_duration_ms'] !== null && $config['min_duration_ms'] >= $config['challenge_ttl_secs'] * 1000) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.min_duration_ms must be < challenge_ttl_secs * 1000 — '.
                'a floor at or above the TTL leaves no acceptable submission time'
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

        // ── Adaptive risk engine (kiwicaptcha/kiwicaptcha-risk-php) ────────
        // Off by default. When enabled, a Predis\Client is REQUIRED for the
        // canonical risk-v1 state script (risk.redis_service, or the bundle's
        // own Redis client when it is a Predis client) — fail fast at compile
        // time otherwise. The engine runs PRE-ISSUE (decide difficulty or
        // deny), records issuances, and receives POST-SOLVE outcome feedback
        // from the validator.
        $riskConfig = $config['risk'];
        $riskGatewayRef = null;
        $riskCookieRef = null;
        if ($riskConfig['enabled']) {
            [$policyConfig, $scopeIds] = $this->buildRiskPolicy($riskConfig);
            $riskRedis = $this->resolveRiskRedisClient($riskConfig, $redisRef, $container);
            $namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';

            $riskMaster = $riskConfig['master_secret'] ?? $config['secret_key'];
            $container->setDefinition('kiwi_captcha.risk.keys', (new Definition(RiskKeys::class))
                ->setFactory([RiskKeys::class, 'fromMaster'])
                ->setArguments([$riskMaster])
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.identity_factory', new Definition(RiskIdentityFactory::class, [
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['subnet_ipv4_prefix'],
                $riskConfig['subnet_ipv6_prefix'],
            ]));
            if ($riskConfig['network_classifier_file'] !== null) {
                $container->setDefinition('kiwi_captcha.risk.classifier', (new Definition(CidrNetworkClassifier::class))
                    ->setFactory([CidrNetworkClassifier::class, 'fromFile'])
                    ->setArguments([$riskConfig['network_classifier_file']]));
            } else {
                $container->setDefinition('kiwi_captcha.risk.classifier', new Definition(CidrNetworkClassifier::class, [[]]));
            }
            $container->setDefinition('kiwi_captcha.risk.scorer', new Definition(RiskScorer::class));
            $container->setDefinition('kiwi_captcha.risk.policy', (new Definition(RiskPolicy::class))
                ->setFactory([RiskPolicy::class, 'fromConfig'])
                ->setArguments([$policyConfig])
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.store', new Definition(RedisRiskStateStore::class, [
                $riskRedis,
                $namespace,
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['state_ttl_secs'],
                $riskConfig['principal_ttl_secs'],
                $riskConfig['dedupe_ttl_secs'],
                $riskConfig['hysteresis_ms'],
                $riskConfig['saturations'],
            ]));
            $container->setDefinition('kiwi_captcha.risk.metrics', new Definition(RiskMetrics::class));

            // In-process emergency limiter (cheap admission BEFORE the risk
            // engine): a fixed per-process window from hard_limits.
            $container->setDefinition('kiwi_captcha.risk.emergency_limiter', new Definition(LocalEmergencyLimiter::class, [
                max(1, $riskConfig['hard_limits']['source_per_second']),
            ]));

            // Bounded automatic calibration (aggregate score buckets, no
            // identity): adjusts only the per-scope bias.
            $calibrationRef = null;
            if ($riskConfig['calibration']['enabled']) {
                $container->setDefinition('kiwi_captcha.risk.calibration', new Definition(AggregateCalibrator::class, [
                    null, // default clock
                    $riskConfig['calibration']['retention_secs'],
                    $riskConfig['calibration']['min_samples'],
                    $riskConfig['calibration']['max_adjustment'],
                    $riskConfig['calibration']['max_change_per_minute'],
                ]));
                $calibrationRef = new Reference('kiwi_captcha.risk.calibration');
            }

            // The engine is public so applications can read risk metrics
            // (RiskGateway::metricsSnapshot) or record their own
            // confirmed-legitimate/abuse signals.
            $container->setDefinition('kiwi_captcha.risk.engine', (new Definition(AdaptiveRiskEngine::class, [
                new Reference('kiwi_captcha.risk.store'),
                new Reference('kiwi_captcha.risk.classifier'),
                new Reference('kiwi_captcha.risk.identity_factory'),
                new Reference('kiwi_captcha.risk.scorer'),
                new Reference('kiwi_captcha.risk.policy'),
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['state_ttl_secs'],
                $riskConfig['principal_ttl_secs'],
                $riskConfig['dedupe_ttl_secs'],
                $riskConfig['saturations'],
                new Definition(CircuitBreaker::class),
                new Reference('kiwi_captcha.risk.emergency_limiter'),
                new Reference('kiwi_captcha.risk.metrics'),
                $calibrationRef,
            ]))->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.resolver', new Definition(RiskProfileResolver::class, [
                PoWAlgorithm::from($config['algorithm']),
                $config['difficulty_bits'],
                $config['argon2_difficulty_bits'],
            ]));
            $loggerRef = $container->hasDefinition('logger') || $container->hasAlias('logger')
                ? new Reference('logger')
                : null;
            $container->setDefinition(RiskGateway::class, (new Definition(RiskGateway::class, [
                new Reference('kiwi_captcha.risk.engine'),
                new Reference('kiwi_captcha.risk.classifier'),
                new Reference('kiwi_captcha.risk.resolver'),
                $scopeIds,
                $loggerRef,
            ]))->setPublic(true));
            $cookie = $riskConfig['continuity_cookie'];
            $container->setDefinition(ContinuityCookie::class, (new Definition(ContinuityCookie::class, [
                $cookie['name'],
                $cookie['ttl_secs'],
                $cookie['path'],
                $cookie['secure'],
                $cookie['samesite'],
                $cookie['http_only'],
            ]))->setPublic(true));
            $riskGatewayRef = new Reference(RiskGateway::class);
            $riskCookieRef = new Reference(ContinuityCookie::class);
        }
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
            $rateLimiterRef,
            $config['same_origin_only'],
            $riskGatewayRef,
            $riskCookieRef,
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
            $riskGatewayRef,
            $riskCookieRef,
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

    /**
     * Build the risk-v1 policy config (int-keyed scopes) and the
     * scope-name => int-id map from the bundle's string-keyed scopes node.
     *
     * Scope ids must be unique and stable across deploys: an explicit `id`
     * wins, otherwise the id is crc32(scope name) & 0x7fffffff. Two scopes
     * with the same id would silently share risk state — refuse the config.
     *
     * @return array{0: array<string, mixed>, 1: array<string, int>}
     */
    private function buildRiskPolicy(array $riskConfig): array
    {
        $policyConfig = [
            'version' => $riskConfig['policy_version'],
            'weights' => $riskConfig['weights'],
            'scopes' => [],
            'global_floors' => $riskConfig['global_floors'],
        ];
        $scopeIds = [];
        foreach ($riskConfig['scopes'] as $name => $spec) {
            $id = $spec['id'] ?? (crc32($name) & 0x7fffffff);
            if ($id < 1) {
                throw new \InvalidArgumentException(sprintf(
                    'kiwi_captcha.risk.scopes[%s].id must be >= 1 (got %d)',
                    $name,
                    $id,
                ));
            }
            if (isset($scopeIds[$name]) || \in_array($id, $scopeIds, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'kiwi_captcha.risk.scopes[%s]: risk scope id %d collides with another scope — set explicit, unique "id" values',
                    $name,
                    $id,
                ));
            }
            $scopeIds[$name] = $id;
            $policyConfig['scopes'][$id] = [
                'base_risk' => $spec['base_risk'],
                'minimum' => $spec['minimum'],
                'post_solve_check' => $spec['post_solve_check'],
                'degraded' => $spec['degraded'],
            ];
        }
        ksort($policyConfig['scopes']);

        return [$policyConfig, $scopeIds];
    }

    /**
     * Resolve the Predis\Client for the risk state store.
     *
     * Priority: the explicit risk.redis_service, then the bundle's own Redis
     * client (redis_service / RedisStorage) when it is a Predis client. A
     * phpredis (\Redis) client cannot drive the risk-v1 EVALSHA store (its
     * constructor is typed Predis\Client) — refuse with an actionable
     * message instead of failing at request time.
     *
     * @throws \LogicException when risk is enabled but no Predis client is
     *                         resolvable
     */
    private function resolveRiskRedisClient(array $riskConfig, ?Reference $bundleRedis, ContainerBuilder $container): Reference
    {
        if ($riskConfig['redis_service'] !== null) {
            $ref = new Reference($riskConfig['redis_service']);
            $class = $this->definitionClass((string) $ref, $container);
            if ($class !== null && !is_a($class, \Predis\Client::class, true)) {
                throw new \LogicException(sprintf(
                    'kiwi_captcha.risk.redis_service ("%s", class %s) must be a Predis\Client — '.
                    'the risk-v1 state store is typed Predis\Client (phpredis \Redis is not supported by the risk engine)',
                    $riskConfig['redis_service'],
                    $class,
                ));
            }

            return $ref;
        }

        if ($bundleRedis !== null) {
            $class = $this->definitionClass((string) $bundleRedis, $container);
            if ($class === null) {
                throw new \LogicException(
                    'kiwi_captcha.risk.enabled cannot reuse the bundle Redis client: its service class is not visible to the '.
                    'extension. Set risk.redis_service explicitly to a Predis\Client service id.'
                );
            }
            if (is_a($class, \Predis\Client::class, true)) {
                return $bundleRedis;
            }
            throw new \LogicException(sprintf(
                'kiwi_captcha.risk.enabled requires a Predis\Client, but the bundle Redis client (%s) is %s — '.
                'the risk-v1 state store is typed Predis\Client (phpredis \Redis is not supported by the risk engine). '.
                'Configure risk.redis_service with a Predis\Client service id.',
                (string) $bundleRedis,
                $class,
            ));
        }

        throw new \LogicException(
            'kiwi_captcha.risk.enabled requires a Redis client for the canonical risk-v1 state script. '.
            'Set risk.redis_service to a Predis\Client service id (or configure redis_service / RedisStorage '.
            'with a Predis\Client so the extension can reuse it).'
        );
    }

    /** The class of a service id (following aliases), or null when invisible. */
    private function definitionClass(string $id, ContainerBuilder $container): ?string
    {
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return null;
        }

        return $container->getDefinition($id)->getClass();
    }
}
