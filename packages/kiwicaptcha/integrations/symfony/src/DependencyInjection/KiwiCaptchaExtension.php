<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\DependencyInjection;

use BelConsulting\KiwiCaptchaBundle\Controller\ApiJsController;
use BelConsulting\KiwiCaptchaBundle\Controller\ChallengeController;
use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\ArraySiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\Form\Type\KiwiCaptchaType;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\PrincipalResolverInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisRiskHealthProvider;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader;
use BelConsulting\KiwiCaptchaBundle\Security\InProcessArgonGate;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\RedisAdmissionSemaphore;
use BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate;
use BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaExtension as TwigExtension;
use BelConsulting\KiwiCaptchaBundle\Twig\KiwiCaptchaRuntime;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\BindingMode;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\PoWAlgorithm;
use KiwiCaptcha\Risk\AdaptiveRiskEngine;
use KiwiCaptcha\Risk\Network\CidrNetworkClassifier;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskPolicy;
use KiwiCaptcha\Risk\Breaker\CircuitBreaker;
use KiwiCaptcha\Risk\Calibration\AggregateCalibrator;
use KiwiCaptcha\Risk\Metrics\RiskMetrics;
use KiwiCaptcha\Risk\RiskScorer;
use KiwiCaptcha\Risk\Storage\ProcessEmergencyCap;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\AtomicStorageInterface;
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
        // A STATIC transaction binding must satisfy the same
        // shape rule the controller enforces per request (1..128
        // bytes of [A-Za-z0-9._:-]) — refuse a broken static value at
        // compile time instead of 422-ing every challenge request.
        $staticBinding = $config['risk']['request_binding'];
        if ($staticBinding !== null && !preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $staticBinding)) {
            throw new \InvalidArgumentException(
                'kiwi_captcha.risk.request_binding must be 1-128 characters of [A-Za-z0-9._:-]'
            );
        }

        // The optional Ed25519 receipt-signing seed must be a
        // base64 32-byte Ed25519 seed — refuse a broken value at compile
        // time instead of failing on the first valid verification.
        $receiptSeed = $config['risk']['result_receipt_signing_key'];
        if ($receiptSeed !== null && $receiptSeed !== '') {
            $decodedSeed = base64_decode($receiptSeed, true);
            if ($decodedSeed === false || \strlen($decodedSeed) !== 32) {
                throw new \InvalidArgumentException(
                    'kiwi_captcha.risk.result_receipt_signing_key must be a base64-encoded 32-byte Ed25519 seed'
                );
            }
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

        // Production NEVER derives the expected origin
        // from an arbitrary Host header. When same_origin_only (the
        // default) is active in a production environment, public_base_url
        // is REQUIRED and validated at container compile time — the
        // config trap (falling back to request Host) becomes a boot error.
        $environment = $this->environment($container);
        if (\in_array($environment, ['test', 'dev'], true) === false
            && ($config['same_origin_only'] || $config['risk']['enforce_origin'] || ($config['risk']['siteverify_secrets'] ?? []) !== [])
        ) {
            $this->requireProductionPublicBaseUrl($config['public_base_url'], $config['same_origin_only'], $environment);
        }

        $storageRef = $this->resolveStorage($config['storage'], $this->environment($container), $container);
        $this->requireAtomicStorageWhenNeeded(
            $storageRef,
            $config['storage'],
            $this->environment($container),
            (bool) ($config['allow_best_effort_storage'] ?? false),
            $config['risk']['siteverify_secrets'] ?? [],
            $container,
        );
        $redisRef = $this->resolveRedisClient((string) $storageRef, $config['redis_service'], $container);

        // The risk.redis knobs (wait_replicas /
        // wait_timeout_ms / ttl_margin_secs) harden the CHALLENGE storage
        // when it is a KiwiCaptcha\Storage\RedisStorage definition: WAIT for
        // replica acknowledgment after storing a challenge (async-replication
        // failover can otherwise lose the record and let a re-solved token
        // replay against a "fresh" record after failback), and extra
        // retention on challenge/replay-security state beyond token validity.
        // Applied ONLY when the knobs are non-default, so deployments on
        // older cores (or without a RedisStorage definition) are untouched.
        $this->applyRedisStorageHardening($storageRef, $config['risk']['redis'], $container);

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
            // The security-policy epoch (risk.policy_version) is
            // stamped into every issued challenge record.
            ->setArgument('$policyVersion', $config['risk']['policy_version'])
            // Deployment issuer + signing key id are first-class
            // bundle options (HMAC-key rotation control) — the core's
            // strongest identity/key controls are reachable without
            // replacing services.
            ->setArgument('$issuer', $config['issuer'])
            ->setArgument('$kid', $config['kid'])
            ->setPublic(true);
        $container->setDefinition('kiwi_captcha.config', $configDef);

        $container->setDefinition('kiwi_captcha.issuer', (new Definition(Issuer::class, [
            new Reference('kiwi_captcha.config'),
            $storageRef,
        ]))->setPublic(true));

        // risk.region is baked into
        // every issued challenge record and enforced at verification — a
        // result token issued in one region is never redeemable elsewhere.
        // Set ONLY when configured (the core's $region param is optional),
        // so deployments without the parameter are untouched.
        if ($config['risk']['region'] !== null) {
            $container->getDefinition('kiwi_captcha.issuer')
                ->setArgument('$region', $config['risk']['region']);
        }

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
                        $config['argon2_max_waiters'],
                        // Per-scope budget (argon2_max_per_tenant)
                        // — the semaphore checks the scope's own lease set in
                        // addition to the global cap.
                        $config['argon2_max_per_tenant'],
                    ]))->setPublic(true),
                );
                // The VERIFIER consumes the gate through the
                // request-scope-aware wrapper: the validator
                // stamps the constraint scope into the request and the
                // wrapper forwards it into acquire(), so the per-scope
                // budget engages on top of the global cap. The raw
                // semaphore stays public for the resource-pressure provider
                // (usage is global either way).
                $container->setDefinition('kiwi_captcha.argon2_scope_gate', (new Definition(RequestScopeAdmissionGate::class, [
                    new Reference('kiwi_captcha.argon2_redis_semaphore'),
                    new Reference('request_stack'),
                ]))->setPublic(true));
                $gateRef = new Reference('kiwi_captcha.argon2_scope_gate');
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
        ]))
            // The verifier's expected security-policy epoch — a
            // record issued under any other epoch is rejected
            // (WrongPolicyVersion) so bumping risk.policy_version invalidates
            // outstanding challenges immediately.
            ->setArgument('$expectedPolicyVersion', $config['risk']['policy_version'])
            // HMAC-key rotation (secretsByKid) + emergency
            // revocation (revokedKids) + expected issuer are first-class
            // bundle options.
            ->setArgument('$expectedIssuer', $config['issuer'])
            ->setArgument('$secretsByKid', $config['secrets_by_kid'])
            ->setArgument('$revokedKids', $config['revoked_kids'])
            ->setPublic(true));
        if ($config['risk']['region'] !== null) {
            $container->getDefinition('kiwi_captcha.verifier')
                ->setArgument('$region', $config['risk']['region']);
        }
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
        // A logger (when the app has one) receives the risk gateway's
        // internal diagnostics and the validator's collapsed-verification
        // detail — resolved once, used by both.
        $loggerRef = $container->hasDefinition('logger') || $container->hasAlias('logger')
            ? new Reference('logger')
            : null;
        $riskConfig = $config['risk'];
        $riskGatewayRef = null;
        $riskCookieRef = null;
        $issuanceCounterRef = null;
        $outstandingRef = null;
        $riskRedis = null;
        if ($riskConfig['enabled']) {
            [$policyConfig, $scopeIds, $postSolveScopes, $unknownScopeId] = $this->buildRiskPolicy($riskConfig);
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
            // The risk state store is self-contained in the package (the
            // canonical risk-v1 Lua ships at resources/risk-v1.lua). The
            // session TTL comes from the continuity-cookie lifetime: a
            // session signal must never outlive the cookie that carries it.
            $container->setDefinition('kiwi_captcha.risk.store', (new Definition(RedisRiskStateStore::class, [
                $riskRedis,
                $namespace,
                $riskConfig['source_epoch_secs'],
                $riskConfig['subnet_epoch_secs'],
                $riskConfig['state_ttl_secs'],
            ]))
                ->setArgument('$principalTtlSecs', $riskConfig['principal_ttl_secs'])
                ->setArgument('$sessionTtlSecs', $riskConfig['continuity_cookie']['ttl_secs'])
                ->setArgument('$dedupeTtlSecs', $riskConfig['dedupe_ttl_secs'])
                ->setArgument('$hysteresisMs', $riskConfig['hysteresis_ms'])
                ->setArgument('$saturations', $riskConfig['saturations'])
                ->setArgument('$outcomeTtlSecs', $riskConfig['calibration']['outcome_receipt_ttl_secs']));
            $container->setDefinition('kiwi_captcha.risk.metrics', new Definition(RiskMetrics::class));

            // In-process emergency limiter (cheap admission BEFORE the risk
            // engine): ONE honest per-process window from hard_limits —
            // process_per_second (assessPreIssue() checks the single cap
            // once before any state backend; per-source throttling belongs
            // to the distributed keyed layer). The CONTROLLER also consults
            // it via the gateway BEFORE the Redis issuance
            // limiter — non-consuming, so the engine stays the single
            // budget consumer.
            $container->setDefinition('kiwi_captcha.risk.emergency_limiter', new Definition(ProcessEmergencyCap::class, [
                $riskConfig['hard_limits']['process_per_second'],
            ]));

            // Redis-backed aggregate calibration (score-bucket statistics,
            // no identity): adjusts only the per-scope bias, bounded by the
            // configured min_samples / max_adjustment / max_change_per_minute
            // knobs, with the outcome/calibration receipt + outcome-ledger
            // lifetime passed through (outcome_receipt_ttl_secs — also the
            // lifetime of the store's outcome ledger; the short-lived
            // nonce->decision handles use risk.nonce_to_decision_ttl_secs
            // instead) and the LABEL-SELECTION contract
            // (calibration.mode + sampling_probability_ppm) passed to the
            // calibrator's sampling knobs. Receipts are keyed on decision
            // ids, so the same Predis client + namespace as the risk state
            // store keeps every calibration key in one hash-tag family.
            $calibrationRef = null;
            if ($riskConfig['calibration']['enabled']) {
                $container->setDefinition('kiwi_captcha.risk.calibration', (new Definition(AggregateCalibrator::class, [
                    $riskRedis,
                    $namespace,
                    $riskConfig['calibration']['min_samples'],
                    $riskConfig['calibration']['max_adjustment'],
                    $riskConfig['calibration']['max_change_per_minute'],
                    $riskConfig['calibration']['outcome_receipt_ttl_secs'],
                ]))
                    ->setArgument('$samplingMode', $riskConfig['calibration']['mode'])
                    ->setArgument('$samplingProbabilityPpm', $riskConfig['calibration']['sampling_probability_ppm'])
                    ->setArgument('$minimumResolutionRatio', $riskConfig['calibration']['minimum_resolution_ratio'])
                    ->setArgument('$falsePositiveCost', $riskConfig['calibration']['false_positive_cost'])
                    ->setArgument('$falseNegativeCost', $riskConfig['calibration']['false_negative_cost'])
                    ->setArgument('$outcomeTtlSecs', $riskConfig['calibration']['outcome_receipt_ttl_secs'])
                    ->setArgument('$scopeHmacKey', AggregateCalibrator::deriveScopeHmacKey($riskMaster)));
                $calibrationRef = new Reference('kiwi_captcha.risk.calibration');
            }

            // Shared circuit breaker: the engine records every store
            // success/failure on it and consumes its state for the DEGRADED
            // mode (backend unavailable -> the policy's degraded action) —
            // no per-request PING, the breaker state IS the last-operation
            // result.
            $container->setDefinition('kiwi_captcha.risk.breaker', new Definition(CircuitBreaker::class));

            // The engine is public so applications can read risk metrics
            // (RiskGateway::metricsSnapshot) or record their own
            // confirmed-legitimate/abuse signals. The trailing parameters
            // are passed BY NAME against the final package contract
            // (principalTtlSecs, saturations, calibration) so their position
            // in the constructor cannot drift from this wiring. The session
            // TTL lives on the state store, the per-process emergency cap on
            // the limiter — both wired above.
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
            ]))
                ->setArgument('$principalTtlSecs', $riskConfig['principal_ttl_secs'])
                ->setArgument('$dedupeTtlSecs', $riskConfig['dedupe_ttl_secs'])
                ->setArgument('$saturations', $riskConfig['saturations'])
                ->setArgument('$breaker', new Reference('kiwi_captcha.risk.breaker'))
                ->setArgument('$limiter', new Reference('kiwi_captcha.risk.emergency_limiter'))
                ->setArgument('$metrics', new Reference('kiwi_captcha.risk.metrics'))
                ->setArgument('$calibration', $calibrationRef)
                ->setArgument('$enableGlobalPressure', $riskConfig['global_pressure']['enabled'])
                ->setPublic(true));
            $container->setDefinition('kiwi_captcha.risk.resolver', new Definition(RiskProfileResolver::class, [
                PoWAlgorithm::from($config['algorithm']),
                $config['difficulty_bits'],
                // The FIXED Argon2id verification-memory envelope
                // (risk.argon_verification_memory_kib) and the target-bits
                // escalation ladder — risk escalates the expected nonce
                // search space, never the server verification cost.
                $riskConfig['argon_verification_memory_kib'],
                $riskConfig['argon_escalation_target_bits'],
            ]));

            // Atomic issuance-rate signal: the controller increments
            // {kiwi:<ns>}:issuance:<second> (INCR + EXPIRE 1) on every minted
            // challenge; the resource-pressure provider reads it for the
            // real issuanceCapacity headroom.
            $issuanceKeyPrefix = sprintf('{kiwi:%s}:issuance:', $namespace);
            $container->setDefinition('kiwi_captcha.risk.issuance_counter', new Definition(IssuanceCounter::class, [
                $riskRedis,
                $issuanceKeyPrefix,
            ]));
            $issuanceCounterRef = new Reference('kiwi_captcha.risk.issuance_counter');

            // Anti-stockpiling: bounded outstanding UNSOLVED
            // challenges per source + deployment-wide. One atomic Lua checks
            // BOTH caps before incrementing ({kiwi:<ns>}:outstanding:<hex>
            // — the source identity is HMAC(canonical ip, RiskKeys::event),
            // the raw IP never appears in Redis — and
            // {kiwi:<ns>}:outstanding:global), EXPIRE = challenge lifetime +
            // risk.redis.ttl_margin_secs. The controller refuses issuance
            // with the 429 risk-denied response when a cap is reached; a
            // valid verification decrements the per-source counter.
            $container->setDefinition('kiwi_captcha.risk.outstanding', new Definition(OutstandingChallenges::class, [
                $riskRedis,
                sprintf('{kiwi:%s}:outstanding:', $namespace),
                new Reference('kiwi_captcha.risk.keys'),
                $riskConfig['max_outstanding_challenges'],
                $riskConfig['max_outstanding_challenges_global'],
                $riskConfig['redis']['ttl_margin_secs'],
            ]));
            $outstandingRef = new Reference('kiwi_captcha.risk.outstanding');

            // Live resource pressure: remaining Redis admission-semaphore
            // slots (argon_capacity.enabled gate) and real per-second
            // issuance headroom as the remaining FRACTION of the
            // deployment-wide resource_capacity.issuance_per_second
            // (fixed-point 0..1000). hard_limits.process_per_second is NOT
            // the denominator — it stays exclusively on the per-process
            // emergency limiter above. Risk backend health is NOT a snapshot
            // field anymore — the engine's degraded mode consumes the shared
            // circuit breaker directly. Unobservable sources stay nominal
            // (1000) for issuance, conservative 0 for the argon gate.
            $container->setDefinition('kiwi_captcha.risk.resource_pressure', new Definition(RedisRiskHealthProvider::class, [
                $riskConfig['argon_capacity']['enabled']
                    ? ($container->hasDefinition('kiwi_captcha.argon2_redis_semaphore')
                        ? new Reference('kiwi_captcha.argon2_redis_semaphore')
                        : null)
                    : null,
                $riskRedis,
                $issuanceKeyPrefix,
                $config['resource_capacity']['issuance_per_second'],
            ]));
            $container->setDefinition(RiskGateway::class, (new Definition(RiskGateway::class, [
                new Reference('kiwi_captcha.risk.engine'),
                new Reference('kiwi_captcha.risk.classifier'),
                new Reference('kiwi_captcha.risk.resolver'),
                $scopeIds,
            ]))
                ->setArgument('$logger', $loggerRef)
                ->setArgument('$resources', new Reference('kiwi_captcha.risk.resource_pressure'))
                ->setArgument('$postSolveScopes', $postSolveScopes)
                ->setArgument('$unknownScopeMode', $riskConfig['unknown_scope']['mode'])
                ->setArgument('$unknownScopeId', $unknownScopeId)
                ->setArgument('$requestStack', new Reference('request_stack'))
                ->setArgument('$decisionRedis', $riskRedis)
                ->setArgument('$decisionKeyPrefix', sprintf('{kiwi:%s}:decision:', $namespace))
                ->setArgument('$decisionTtlSecs', $riskConfig['nonce_to_decision_ttl_secs'])
                ->setArgument('$calibration', $calibrationRef)
                ->setArgument('$policy', new Reference('kiwi_captcha.risk.policy'))
                // The controller's cheap local admission step
                // (RiskGateway::emergencyCapSaturated) — the process-local
                // window checked BEFORE any Redis issuance limiter.
                ->setArgument('$emergencyCap', new Reference('kiwi_captcha.risk.emergency_limiter'))
                ->setPublic(true));
            if ($container->has(PrincipalResolverInterface::class)) {
                // An application-registered principal resolver is OPT-IN:
                // when a service for the interface exists, the raw principal
                // of each request flows into every engine context (the
                // engine HMAC-pseudonymizes it before Redis storage).
                $container->getDefinition(RiskGateway::class)
                    ->setArgument('$principalResolver', new Reference(PrincipalResolverInterface::class));
            }
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
        // ── Trusted client-IP policy ──────────────────────────────────────
        // Wired UNCONDITIONALLY (not gated on risk.enabled): the canonical
        // client IP feeds the challenge binding tag, the rate-limit identity
        // and the risk source pseudonym — the controller and the validator
        // must agree on it in every deployment mode.
        $container->setDefinition(ClientIpResolver::class, (new Definition(ClientIpResolver::class, [
            $config['risk']['client_ip_mode'],
            $config['risk']['trusted_proxies'],
            $config['risk']['reject_ambiguous_forwarding'],
        ]))
            ->setArgument('$logger', $loggerRef)
            ->setPublic(true));

        // ── Security-epoch monitor ────────────────────────────────────────
        // Wired UNCONDITIONALLY (not gated on risk.enabled — the central
        // security-policy state exists independently of the adaptive
        // engine): reads `{kiwi:<ns>}:security-policy`'s min_policy_epoch
        // with a SHORT cache (risk.security_epoch_cache_secs), keeps a
        // MONOTONIC in-process max (a regressed central value is ignored)
        // and serves the last-observed max when Redis is unavailable. The
        // effective epoch is applied to the SHARED verifier (rotating its
        // expected policy version — always re-applying the configured
        // region/issuer expectations), so every verification enforces the
        // CURRENT epoch and a central policy bump revokes outstanding
        // challenges within one cache window. Without a Redis client the
        // monitor serves the configured risk.policy_version (no central
        // state to read).
        $namespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';
        $container->setDefinition(SecurityEpochMonitor::class, (new Definition(SecurityEpochMonitor::class, [
            new Reference('kiwi_captcha.verifier'),
            $redisRef,
            $namespace,
            $config['risk']['policy_version'],
            $riskConfig['security_epoch_cache_secs'],
        ]))
            ->setArgument('$region', $config['risk']['region'])
            ->setArgument('$issuer', null)
            // The max-stale fail-closed window — past
            // last_success + max_stale the validator fails verification
            // closed (temporary_unavailable) and the controller refuses
            // issuance with 503 SERVICE_UNAVAILABLE.
            ->setArgument('$maxStaleSecs', $riskConfig['security_epoch_max_stale_secs'])
            ->setPublic(true));

        // ── Optional Ed25519 result-receipt signer ────────────────────────
        // The result verification stays CENTRAL-ONLY (the HMAC secret never
        // leaves the server); this signer only enables EXPORTED
        // verification receipts verified with the public key. Null seed =
        // disabled (the validator's receipt accessors stay null).
        $container->setDefinition(ResultReceiptSigner::class, new Definition(ResultReceiptSigner::class, [
            $receiptSeed,
        ]));

        // ── Per-scope issuance cap ────────────────────────────────────────
        // risk.max_challenges_per_scope_per_minute > 0 requires a Redis
        // client for the atomic fixed-window counter — refuse the config at
        // compile time instead of silently minting unbilled challenges. The
        // window key carries hex(hmac_sha256(scope, K_scope)) — the RAW
        // scope string is never a Redis key component; K_scope
        // is derived from the risk master with
        // hash_hkdf info 'kiwi/v2/scope-rate' (the same derivation the risk
        // package uses for its calibration scope keys).
        $scopeCapRef = null;
        if ($riskConfig['max_challenges_per_scope_per_minute'] > 0) {
            $scopeCapRedis = $riskRedis ?? $redisRef;
            if ($scopeCapRedis === null) {
                throw new \LogicException(
                    'kiwi_captcha.risk.max_challenges_per_scope_per_minute requires a Redis client for the atomic '.
                    'fixed-window counter ({kiwi:<ns>}:issuance:<scopeIdentity>:<minute>). Configure '.
                    'redis_service / risk.redis_service (or a RedisStorage client) or set the cap to 0 (unlimited).'
                );
            }
            $scopeHmacKey = ScopeIssuanceCap::deriveScopeHmacKey($riskConfig['master_secret'] ?? $config['secret_key']);
            $container->setDefinition('kiwi_captcha.risk.scope_issuance_cap', new Definition(ScopeIssuanceCap::class, [
                $scopeCapRedis,
                sprintf('{kiwi:%s}:issuance:', $namespace),
                $riskConfig['max_challenges_per_scope_per_minute'],
                $scopeHmacKey,
            ]));
            $scopeCapRef = new Reference('kiwi_captcha.risk.scope_issuance_cap');
        }

        // Server-side provider-compatibility stores — the
        // metadata sidecar (action/cData bound at challenge issuance) and
        // the atomic idempotency store (provider-style idempotency_key).
        // Redis-backed whenever the challenge storage is RedisStorage (the
        // same client), in-memory otherwise (test/dev semantics — the
        // stores are only wired into the controllers; production
        // deployments with Siteverify use the Redis variants).
        $metadataStoreRef = null;
        $idempotencyStoreRef = null;
        if ($redisRef !== null) {
            $redisNamespace = $riskConfig['redis']['namespace'] ?? 'kiwicaptcha';
            $container->setDefinition(RedisSiteVerifyMetadataStore::class, new Definition(RedisSiteVerifyMetadataStore::class, [$redisRef, $redisNamespace]));
            $container->setDefinition(RedisSiteVerifyIdempotencyStore::class, new Definition(RedisSiteVerifyIdempotencyStore::class, [$redisRef, $redisNamespace]));
            $metadataStoreRef = new Reference(RedisSiteVerifyMetadataStore::class);
            $idempotencyStoreRef = new Reference(RedisSiteVerifyIdempotencyStore::class);
        } else {
            $container->setDefinition(ArraySiteVerifyMetadataStore::class, new Definition(ArraySiteVerifyMetadataStore::class, []));
            $container->setDefinition(ArraySiteVerifyIdempotencyStore::class, new Definition(ArraySiteVerifyIdempotencyStore::class, []));
            $metadataStoreRef = new Reference(ArraySiteVerifyMetadataStore::class);
            $idempotencyStoreRef = new Reference(ArraySiteVerifyIdempotencyStore::class);
        }

        // The core binds issuance by the GLOBAL binding_mode only: the
        // per-sitekey map carries no binding dimension. The global
        // server-owned mode is the only binding control.
        $sitekeyPolicy = $riskConfig['sitekeys'] ?? [];
        $container->setDefinition(ChallengeController::class, (new Definition(ChallengeController::class, [
            new Reference('kiwi_captcha.issuer'),
            $rateLimiterRef,
            $config['same_origin_only'],
            $riskGatewayRef,
            $riskCookieRef,
            $issuanceCounterRef,
            $outstandingRef,
            $config['risk']['challenge_origin_allowlist'],
            $config['risk']['enforce_fetch_metadata'],
            $storageRef,
            // Static transaction-binding fallback — the widget
            // sends its own request_binding field when it carries one; this
            // default applies when the request does not.
            $config['risk']['request_binding'],
            // When enforced, a challenge POST without a usable
            // Origin header is rejected with 403 origin_rejected.
            $config['risk']['enforce_origin'],
        ]))
            // The trusted client-IP policy drives the controller's
            // canonical IP (binding tag / rate-limit identity / risk source).
            ->setArgument('$clientIpResolver', new Reference(ClientIpResolver::class))
            // The same-origin expected origin comes from SERVER
            // CONFIG, never the Host header.
            ->setArgument('$publicBaseUrl', $config['public_base_url'])
            // The per-scope issuance cap (fixed-window Redis
            // counter; null when disabled).
            ->setArgument('$scopeIssuanceCap', $scopeCapRef)
            // The SERVER-OWNED scope allowlist — when
            // non-empty, issuance outside it is refused (422
            // SCOPE_NOT_ALLOWED) before risk/quota, making the per-scope
            // quota namespace server-bounded.
            ->setArgument('$allowedScopes', $riskConfig['allowed_scopes'])
            // Migration sitekey -> scope alias map (server-owned).
            ->setArgument('$sitekeyAllowlist', $riskConfig['sitekey_allowlist'])
            // The provider-metadata sidecar (action/cData
            // bound to the nonce at issuance).
            ->setArgument('$metadataStore', $metadataStoreRef)
            // Server-owned (sitekey, action) -> scope
            // policy map.
            ->setArgument('$sitekeyPolicy', $sitekeyPolicy)
            // The security-epoch monitor drives the issuance-side
            // max-stale fail-closed check — a stale central policy read
            // refuses issuance with 503 SERVICE_UNAVAILABLE.
            ->setArgument('$epochMonitor', new Reference(SecurityEpochMonitor::class))
            // The configured challenge TTL lets the anti-
            // stockpiling admission run BEFORE the challenge state is
            // created (the quota checks all precede the storage write).
            ->setArgument('$challengeTtlSecs', $config['challenge_ttl_secs'])
            ->addTag('controller.service_arguments')->setPublic(true));

        // ── Challenge route (configured prefix; see KiwiCaptchaRouteLoader) ──
        $container->setDefinition(KiwiCaptchaRouteLoader::class, (new Definition(KiwiCaptchaRouteLoader::class, [
            '%kiwi_captcha.route_prefix%',
            // The /health/live + /health/ready routes follow
            // risk.health.enabled (default true).
            $config['risk']['health']['enabled'],
        ]))->addTag('routing.loader'));

        // ── Provider-compatible Siteverify ──
        // Disabled unless siteverify_secret is configured; calls the SAME
        // atomic verifier service (kiwi_captcha.verifier). The storage is
        // injected so the deterministic consumed-result's record metadata
        // (issued_at, hostname) is available for the provider-shaped JSON.
        $container->setDefinition(SiteVerifyController::class, (new Definition(SiteVerifyController::class, [
            new Reference('kiwi_captcha.verifier'),
            $config['secret_key'],
            // Map of siteverify secret -> expected scope; empty
            // disables the endpoint.
            $riskConfig['siteverify_secrets'],
            // The one-success provider contract REQUIRES an
            // atomic backend — requireAtomicStorageWhenNeeded() refuses any
            // non-atomic combination (Psr6Storage included) at compile time.
            $riskConfig['siteverify_secrets'] !== [] ? new Reference(StorageInterface::class) : null,
            null, // logger (autowired position — kept explicit for stability)
            $riskConfig['siteverify_secrets'] !== [] ? $metadataStoreRef : null,
            $riskConfig['siteverify_secrets'] !== [] ? $idempotencyStoreRef : null,
            // The shared Redis log gate for
            // invalid-secret flood suppression (null = suppressed detail).
            $riskConfig['siteverify_secrets'] !== [] ? $redisRef : null,
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // ── Migration compatibility loader ──
        // GET {prefix}/api.js[?compat=...]: the canonical glue + driver as
        // one same-origin immutable external script.
        $assetsDir = \dirname(__DIR__, 2).'/Resources/public';
        $container->setDefinition(ApiJsController::class, (new Definition(ApiJsController::class, [
            $assetsDir,
        ]))->addTag('controller.service_arguments')->setPublic(true));

        // ── Health endpoints ──
        // /health/live: always 200 while the process runs. /health/ready:
        // 200 only when the signing keys are configured, the security Redis
        // answers a (cached) PING and the CENTRAL security-policy state is
        // compatible ({kiwi:<ns>}:security-policy: min_protocol_version <= 2
        // AND min_policy_epoch <= risk.policy_version; key absent = the
        // binary's own config is authoritative). Argon queue fullness and
        // transient probe timeouts never fail readiness.
        $healthNamespace = preg_replace('/[^A-Za-z0-9_.-]/', '_', (string) $riskConfig['namespace']) ?: 'kiwi';
        $container->setDefinition(KiwiHealthController::class, (new Definition(KiwiHealthController::class, [
            $config['secret_key'],
            $redisRef,
            $healthNamespace,
            $config['risk']['policy_version'],
        ]))
            // The memory-budget readiness invariant
            // (concurrency x max adaptive profile + headroom <=
            // container_memory_mib). The max adaptive profile
            // memory is the FIXED verification envelope
            // (risk.argon_verification_memory_kib) — risk never escalates
            // the server verification cost, so the worst case is the
            // envelope.
            ->setArgument('$argonConcurrency', $config['argon2_max_concurrent_verifications'])
            ->setArgument('$containerMemoryMib', $config['risk']['container_memory_mib'])
            ->setArgument('$argonEnvelopeMemoryKib', $riskConfig['argon_verification_memory_kib'])
            ->addTag('controller.service_arguments')->setPublic(true));

        // ── Form type (renders the widget through the form theme) ──
        // The route prefix is injected so the default 'endpoint' option
        // follows the ACTUAL registered route (the standalone Twig widget
        // derives its endpoint from the same prefix); the telemetry mode
        // follows the (strict-enforced) config; the request_binding option
        // follows the static risk.request_binding default.
        $container->setDefinition(KiwiCaptchaType::class, (new Definition(KiwiCaptchaType::class, [
            new Reference(KiwiCaptchaRuntime::class),
            '%kiwi_captcha.route_prefix%',
            $config['telemetry'],
            $config['risk']['request_binding'],
        ]))->addTag('form.type'));

        // ── Validator (local verification, no external calls) ──
        // The logger receives the INTERNAL verification detail on failures —
        // the public violation code is collapsed
        // (invalid_or_expired / rate_limited / temporary_unavailable), the
        // precise core reason stays in the logs.
        $container->setDefinition(KiwiCaptchaValidator::class, (new Definition(KiwiCaptchaValidator::class, [
            new Reference('kiwi_captcha.verifier'),
            new Reference('request_stack'),
            $config['secret_key'],
            $config['enforce_telemetry'],
            $riskGatewayRef,
            $riskCookieRef,
            $outstandingRef,
        ]))
            ->setArgument('$logger', $loggerRef)
            // The challenge storage resolves ambiguous-consume
            // outcomes from the consumed record (state + consumed_result).
            ->setArgument('$storage', $storageRef)
            // The SAME canonical client IP the controller bound
            // the challenge to (trusted client-IP policy).
            ->setArgument('$clientIpResolver', new Reference(ClientIpResolver::class))
            // The security-epoch monitor feeds the verifier's
            // expected policy epoch per verification (bounded revocation
            // latency + monotonic max).
            ->setArgument('$epochMonitor', new Reference(SecurityEpochMonitor::class))
            // The optional Ed25519 result-receipt signer for
            // exported verification results (null = disabled).
            ->setArgument('$receiptSigner', new Reference(ResultReceiptSigner::class))
            ->addTag('validator.constraint_validator'));

        // ── Twig widget runtime + twig function (embeds the shared widget assets) ──
        $container->setDefinition(KiwiCaptchaRuntime::class, (new Definition(KiwiCaptchaRuntime::class, [
            $config['route_prefix'],
            null,
            KiwiCaptchaRuntime::DEFAULT_TEMPLATE,
            $config['telemetry'],
            // The static transaction binding is the standalone
            // widget's data-kiwi-request-binding default.
            $config['risk']['request_binding'],
            // The widget page's frame-ancestors CSP helper —
            // the space-separated allowlisted origins.
            $config['risk']['challenge_origin_allowlist'],
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
     * The production origin invariant. The challenge
     * controller's same-origin check must compare against SERVER CONFIG
     * (public_base_url), never the request's own scheme+host — otherwise a
     * forged Host header defines the security boundary. Fail closed at
     * boot: prod + same-origin enforcement + missing/invalid
     * public_base_url is a configuration error.
     */
    private function requireProductionPublicBaseUrl(mixed $publicBaseUrl, bool $sameOriginOnly, string $environment): void
    {
        if (!\is_string($publicBaseUrl) || $publicBaseUrl === '') {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: production (environment "%s") with same-origin enforcement (or Siteverify configured) REQUIRES public_base_url — the expected origin must come from server config, never the request Host header. Set e.g. public_base_url: "https://captcha.example.com".',
                $environment,
            ));
        }
        $parts = parse_url($publicBaseUrl);
        $scheme = $parts['scheme'] ?? null;
        $host = $parts['host'] ?? null;
        $isHttps = $scheme === 'https';
        if (!$isHttps) {
            throw new \LogicException('KiwiCaptcha: public_base_url must be an absolute https:// URL in production (got "'.$publicBaseUrl.'").');
        }
        if ($host === null || (isset($parts['user']) || isset($parts['pass']))) {
            throw new \LogicException('KiwiCaptcha: public_base_url must carry a hostname and NO username/password (got "'.$publicBaseUrl.'").');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new \LogicException('KiwiCaptcha: public_base_url must not carry a query or fragment (got "'.$publicBaseUrl.'").');
        }
        $path = $parts['path'] ?? '';
        if ($path !== '' && $path !== '/') {
            throw new \LogicException('KiwiCaptcha: public_base_url must have an empty path or "/" (got "'.$publicBaseUrl.'").');
        }
    }

    /**
     * Strict single-use requires an ATOMIC storage backend.
     * In production (not test/dev):
     *  - unless allow_best_effort_storage is explicitly true, the resolved
     *    storage must implement KiwiCaptcha\AtomicStorageInterface — a
     *    non-atomic backend (e.g. Psr6Storage) lets two racing requests
     *    both observe pending and both win verification (the documented
     *    PSR-6 race semantics);
     *  - when siteverify_secrets is configured, an atomic backend is
     *    REQUIRED REGARDLESS of the override — the provider one-success
     *    contract cannot exist on a non-atomic backend, so the container
     *    refuses the combination.
     * Fails closed at container compile time (a LogicException names the
     * exact misconfiguration).
     *
     * @param array<string, string> $siteverifySecrets
     */
    private function requireAtomicStorageWhenNeeded(Reference $storageRef, string $storageId, string $environment, bool $allowBestEffort, array $siteverifySecrets, ContainerBuilder $container): void
    {
        $siteverifyEnabled = $siteverifySecrets !== [];
        $production = !\in_array($environment, ['test', 'dev'], true);
        if (!$production && !$siteverifyEnabled) {
            return;
        }
        if ($siteverifyEnabled && $allowBestEffort) {
            throw new \LogicException('KiwiCaptcha: siteverify_secrets requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface) — the provider one-success contract is impossible on a non-atomic backend, and allow_best_effort_storage cannot override this combination.');
        }

        $id = $storageId;
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        $class = null;
        if ($container->hasDefinition($id)) {
            $class = $container->getDefinition($id)->getClass();
            if ($class !== null && str_starts_with($class, '%') && $container->hasParameter(trim($class, '%'))) {
                $class = $container->getParameter(trim($class, '%'));
            }
        }
        $isAtomic = $class !== null && \is_string($class) && \is_a($class, AtomicStorageInterface::class, true);
        if ($isAtomic) {
            return;
        }
        if ($siteverifyEnabled) {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: siteverify_secrets requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface) — the provider one-success contract is impossible on a non-atomic backend. Configure "storage: kiwicaptcha.storage.redis" (RedisStorage) or any service implementing AtomicStorageInterface (resolved class %s).',
                $class === null ? '(unresolvable)' : $class,
            ));
        }
        if ($allowBestEffort) {
            return;
        }
        if ($production) {
            throw new \LogicException(sprintf(
                'KiwiCaptcha: production verification requires an ATOMIC storage backend (KiwiCaptcha\AtomicStorageInterface — e.g. RedisStorage, whose Lua pending→consumed transition guarantees exactly one winner). The configured storage %s resolves to %s. Set the explicitly-named "allow_best_effort_storage: true" only if you deliberately accept weaker concurrency semantics.',
                $storageId,
                $class === null ? '(unresolvable class)' : $class,
            ));
        }
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
     * Apply the risk.redis hardening knobs (wait_replicas /
     * wait_timeout_ms / ttl_margin_secs) to the challenge storage
     * definition when it is a KiwiCaptcha\Storage\RedisStorage.
     *
     * The knobs are only set when they differ from the storage's built-in
     * defaults (wait_replicas > 0 or ttl_margin_secs > 0): a deployment
     * that never opts in keeps byte-identical behavior and stays compatible
     * with cores predating the parameters.
     *
     * @param array{wait_replicas: int, wait_timeout_ms: int, ttl_margin_secs: int} $redisConfig
     */
    private function applyRedisStorageHardening(Reference $storageRef, array $redisConfig, ContainerBuilder $container): void
    {
        $waitReplicas = $redisConfig['wait_replicas'];
        $ttlMarginSecs = $redisConfig['ttl_margin_secs'];
        if ($waitReplicas <= 0 && $ttlMarginSecs <= 0) {
            return;
        }

        $id = (string) $storageRef;
        if ($container->hasAlias($id)) {
            $id = (string) $container->getAlias($id);
        }
        if (!$container->hasDefinition($id)) {
            return;
        }
        $definition = $container->getDefinition($id);
        $class = $definition->getClass();
        if ($class === null || !is_a($class, RedisStorage::class, true)) {
            return;
        }

        $definition->setArgument('$waitReplicas', $waitReplicas);
        $definition->setArgument('$waitTimeoutMs', $redisConfig['wait_timeout_ms']);
        $definition->setArgument('$ttlMarginSecs', $ttlMarginSecs);
    }

    /**
     * Build the risk-v1 policy config (int-keyed scopes) and the
     * scope-name => int-id map from the bundle's string-keyed scopes node.
     *
     * Scope ids must be unique and stable across deploys: an explicit `id`
     * wins, otherwise the id is crc32(scope name) & 0x7fffffff. Two scopes
     * with the same id would silently share risk state — refuse the config.
     *
     * Contract invariants for the policy handed to RiskPolicy::fromConfig:
     *  - global_floors is an array of FIVE entries with index 0 = Allow
     *    (level 0 is the idle level). When global_pressure.enabled is false
     *    every floor is Allow — the global controller is off.
     *  - unknown_scope.mode "minimum" adds a synthetic scope entry
     *    (base_risk 100, minimum/degraded sha20) under a reserved id
     *    (1..u32::MAX, never colliding with a configured id); "reject" and
     *    "baseline" leave the policy without it and the gateway declines
     *    unknown scopes with UnknownScopeException (the controller turns
     *    "reject" into the risk-denied 429 and "baseline" into the default
     *    challenge).
     *
     * @return array{0: array<string, mixed>, 1: array<string, int>, 2: array<string, bool>, 3: ?int}
     *         [policy config, scope-name => scope-id, scope-name => post_solve_check, synthetic unknown-scope id]
     */
    private function buildRiskPolicy(array $riskConfig): array
    {
        // The risk-v1 policy contract version is internal to the risk
        // package (RiskPolicy::CONTRACT_VERSION): the policy handed to the
        // engine always carries it. The operator's risk.policy_version knob
        // is the CHALLENGE security-policy epoch — stamped
        // into issued records and enforced at verification — completely
        // independent of the risk-v1 contract.
        $policyConfig = [
            'version' => RiskPolicy::CONTRACT_VERSION,
            'weights' => $riskConfig['weights'],
            'scopes' => [],
            'global_floors' => $riskConfig['global_pressure']['enabled']
                ? [0 => RiskAction::Allow->value] + $riskConfig['global_floors']
                : array_fill(0, 5, RiskAction::Allow->value),
        ];
        $scopeIds = [];
        $postSolveScopes = [];
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
            $postSolveScopes[$name] = $spec['post_solve_check'];
            $policyConfig['scopes'][$id] = [
                'base_risk' => $spec['base_risk'],
                'minimum' => $spec['minimum'],
                'post_solve_check' => $spec['post_solve_check'],
                'degraded' => $spec['degraded'],
            ];
        }
        ksort($policyConfig['scopes']);

        $unknownScopeId = null;
        if ($riskConfig['unknown_scope']['mode'] === 'minimum') {
            $unknownScopeId = $this->reserveUnknownScopeId($scopeIds);
            $policyConfig['scopes'][$unknownScopeId] = [
                'base_risk' => 100,
                'minimum' => RiskAction::Sha20->value,
                'post_solve_check' => false,
                'degraded' => RiskAction::Sha20->value,
            ];
        }

        return [$policyConfig, $scopeIds, $postSolveScopes, $unknownScopeId];
    }

    /**
     * A stable synthetic scope id for unknown scopes in 'minimum' mode:
     * starts at u32::MAX and walks down until it collides with no
     * configured scope id (the risk-v1 contract allows ids 1..u32::MAX).
     *
     * @param array<string, int> $scopeIds
     */
    private function reserveUnknownScopeId(array $scopeIds): int
    {
        $used = array_values($scopeIds);
        for ($id = 0xFFFFFFFF; $id >= 1; --$id) {
            if (!\in_array($id, $used, true)) {
                return $id;
            }
        }
        throw new \InvalidArgumentException('Cannot reserve a synthetic scope id for unknown_scope.mode=minimum: every id 1..u32::MAX is taken by a configured scope');
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
