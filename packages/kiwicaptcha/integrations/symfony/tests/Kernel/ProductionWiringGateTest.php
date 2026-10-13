<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests\Kernel;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\FirstAttemptLoginGuard;
use BelConsulting\KiwiCaptchaBundle\EventSubscriber\KiwiOutcomeBridgeSubscriber;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\TrustedDeviceCookie;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\HttpKernel\Kernel;

/**
 * The production wiring gate (F14): the kernel is booted under every
 * protection profile and every service of the KIWI_SERVICES contract is
 * actually constructed and reflected — the shape the earlier gate tests
 * could not fail. A source scan cannot see a definition built with one
 * argument too few (the F15 outcomes facade silently carried a null
 * store), and a constant-vs-constant comparison cannot see a store
 * wired without the configured cookie lifetimes (F7). Only a live
 * container can.
 *
 * Three gates, in one place:
 *
 *  1. every KIWI_SERVICES entry resolves on a booted kernel under every
 *     profile, and every property typed to a KiwiCaptcha\ or
 *     BelConsulting\ class holds a real instance — a null there is a
 *     silently disabled defense, never a seam;
 *  2. FirstAttemptLoginGuard carries the login scope's configured
 *     target field, so the first-attempt decision books the target
 *     dimension exactly like the outcome bridge does;
 *  3. the principal-network tag store receives the configured cookie
 *     lifetimes (2x the continuity cookie, the trusted-device TTL
 *     verbatim) and the config tree bounds both so the derived TTLs
 *     stay inside the canonical Lua class ranges.
 */
final class ProductionWiringGateTest extends TestCase
{
    /** Every protection profile the bundle documents. */
    private const PROFILES = ['balanced', 'privacy_strict', 'high_abuse', 'abuse_first', 'compatibility', 'ha_safe'];

    /**
     * The KIWI_SERVICES contract: service ids every profile's booted
     * container must expose once the risk plane is on. The composition
     * differences between profiles (compatibility keeps the plain
     * pipeline) are asserted by RiskStageWiringMatrixTest; this gate
     * only demands the always-present plane.
     */
    private const KIWI_SERVICES = [
        'kiwi_captcha.config',
        'kiwi_captcha.issuer',
        'kiwi_captcha.verifier',
        'kiwi_captcha.risk.engine',
        'kiwi_captcha.risk.store',
        'kiwi_captcha.risk.keys',
        'kiwi_captcha.risk.identity_factory',
        'kiwi_captcha.risk.scorer',
        'kiwi_captcha.risk.policy',
        'kiwi_captcha.risk.classifier',
        'kiwi_captcha.risk.breaker',
        'kiwi_captcha.risk.metrics',
        'kiwi_captcha.risk.emergency_limiter',
        'kiwi_captcha.risk.resolver',
        'kiwi_captcha.risk.principal_networks',
        'kiwi_captcha.risk.outcomes',
        'kiwi_captcha.risk.outstanding',
        'kiwi_captcha.risk.issuance_counter',
        'kiwi_captcha.risk.resource_pressure',
        'kiwi_captcha.risk.v2_weights',
        'kiwi_captcha.risk.asn',
        'kiwi_captcha.risk.target_resolver',
        RiskGateway::class,
        ContinuityCookie::class,
        TrustedDeviceCookie::class,
        FirstAttemptLoginGuard::class,
        KiwiOutcomeBridgeSubscriber::class,
    ];

    /**
     * The services only the armed (marks/pricing/decoy) composition
     * defines: the abuse postures compose every stage, so their boots
     * must expose the whole plane.
     */
    private const ARMED_PROFILE_SERVICES = [
        'kiwi_captcha.risk.marks_reader',
        'kiwi_captcha.risk.price_context',
        'kiwi_captcha.risk.trust',
        'kiwi_captcha.risk.autofill_gate',
        'kiwi_captcha.risk.decoy_escalation',
        'kiwi_captcha.risk.decoy_script_runner',
    ];

    /**
     * Seams legitimately allowed to resolve null on a fully armed
     * container, keyed service id => property => the one-line reason.
     * Every other KiwiCaptcha\/BelConsulting\-typed property must hold
     * an instance: a null there silently disables the defense it feeds.
     */
    private const NULLABLE_SEAM_ALLOW_LIST = [
        'kiwi_captcha.verifier' => [
            // The rsw time-lock verifier rides the rsw algorithm choice:
            // a sha256/argon2id deployment (every profile default)
            // never consults it, and the core verifier refuses an rsw
            // record rather than mis-verifying when the implementation
            // is absent.
            'rsw' => 'wired only when the deployment selects the rsw algorithm',
        ],
        'kiwi_captcha.risk.engine' => [
            // The aggregate score-bucket calibration is an explicit
            // operator opt-in (risk.calibration.enabled, default off).
            'calibration' => 'calibration is an opt-in stage (risk.calibration.enabled)',
        ],
        'kiwi_captcha.risk.outstanding' => [
            // A lazily memoized internal (??= on first mutation), not a
            // wiring seam: the executor is always constructible from
            // the already-injected client.
            'luaSeam' => 'lazily memoized on first mutation from the injected client',
        ],
        'kiwi_captcha.risk.issuance_counter' => [
            // The same lazy memo pattern as the outstanding service.
            'luaSeam' => 'lazily memoized on first mutation from the injected client',
        ],
        'kiwi_captcha.risk.resource_pressure' => [
            // The 100 ms in-process snapshot memo: empty until the
            // first snapshot(), recomputed from the live clients.
            'cached' => 'in-process snapshot memo, filled on first snapshot()',
            // The argon-capacity dimension is opt-in
            // (argon_capacity.enabled, default off): unwired reads
            // nominal 1000 (idle) by documented contract.
            'semaphore' => 'the argon-capacity read is opt-in (argon_capacity.enabled); unwired stays nominal',
        ],
        RiskGateway::class => [
            // The principal resolver is an application-registered
            // opt-in: without the interface service there is no app
            // principal to feed the engine.
            'principalResolver' => 'the application registers a principal resolver service to opt in',
            // The aggregate calibration store rides the same opt-in
            // stage as the engine's calibrator (risk.calibration.enabled).
            'calibration' => 'calibration is an opt-in stage (risk.calibration.enabled)',
        ],
        FirstAttemptLoginGuard::class => [
            // Both are log-and-continue surfaces: the guard degrades to
            // the pending token without them, never to a granted
            // session.
            'logger' => 'the gate is log-and-continue; a deployment without a logger stays silent',
        ],
        KiwiOutcomeBridgeSubscriber::class => [
            // Same log-and-continue posture as the guard.
            'logger' => 'the bridge never breaks authentication; without a logger it stays silent',
            // Wired only when the trust gate runs in store mode AND a
            // risk Redis client exists; otherwise the fail-closed gate
            // serves and the window is unreachable by design.
            'authWindow' => 'the store-backed window rides the store gate mode; the fail-closed default needs no window',
        ],
    ];

    /**
     * Profile-scoped additions to the allow-list: seams that are null
     * by one profile's documented composition contract. The
     * compatibility posture keeps the byte-identical plain decision
     * pipeline — its stage arguments are absent on purpose
     * (RiskStageComposition::MATRICES), while the other profiles must
     * compose them.
     */
    private const PROFILE_NULLABLE_SEAM_ALLOW_LIST = [
        'compatibility' => [
            'kiwi_captcha.risk.engine' => [
                'marksReader' => 'the compatibility posture composes no marks stage (documented minimal set)',
                'priceContext' => 'the compatibility posture composes no pricing stage (documented minimal set)',
                'decoyEscalationReader' => 'the compatibility posture composes no decoy-escalation reader (documented minimal set)',
            ],
            RiskGateway::class => [
                'decoyEscalation' => 'the compatibility posture composes no decoy-escalation surface (documented minimal set)',
            ],
        ],
    ];

    public function testEveryProfileBootsAndWiresTheWholePlane(): void
    {
        foreach (self::PROFILES as $profile) {
            $container = $this->boot($profile);
            $armed = \in_array($profile, ['high_abuse', 'abuse_first'], true);
            foreach (array_merge(self::KIWI_SERVICES, $armed ? self::ARMED_PROFILE_SERVICES : []) as $id) {
                self::assertTrue($container->has($id), sprintf('profile %s must define %s', $profile, $id));
                $service = $container->get($id);
                self::assertNotNull($service, sprintf('profile %s must resolve %s to an instance', $profile, $id));
                $this->assertKiwiTypedPropertiesAreWired($profile, $id, $service);
            }
        }
    }

    public function testTheFirstAttemptGuardCarriesTheConfiguredTargetField(): void
    {
        $container = $this->boot('abuse_first');
        $guard = $container->get(FirstAttemptLoginGuard::class);
        $targetFieldsByScope = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'targetFieldsByScope'))->getValue($guard);
        self::assertSame(
            ['login' => ['username']],
            $targetFieldsByScope,
            'the login scope declares target_field username, so the guard must carry it under the resolved scope (F14)',
        );

        // The negative: a scope without a target field leaves the
        // guard's entry empty (the assessment then carries no target
        // dimension), and the wiring must not invent a field name.
        $container = $this->boot('abuse_first', 'no-target-field', withTargetField: false);
        $guard = $container->get(FirstAttemptLoginGuard::class);
        $targetFieldsByScope = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'targetFieldsByScope'))->getValue($guard);
        self::assertSame(['login' => []], $targetFieldsByScope, 'a scope without target_field wires an empty list');
    }

    /**
     * The H1 regression: a minimal abuse_first install (no outcomes
     * scope, no explicit login_scopes) must still arm the guard, and
     * the profile-derived map must resolve the conventional main
     * firewall to the login scope. The gate follows risk.login_scopes,
     * never the outcomes bridge. The reporting lane rides the same
     * inference: exactly one mapped login scope infers the outcome
     * scope, so the bridge arms too (the H1 outcome-bridge half).
     */
    public function testMinimalAbuseFirstInstallArmsTheGuard(): void
    {
        $container = $this->boot('abuse_first', 'minimal');
        self::assertTrue($container->has(FirstAttemptLoginGuard::class), 'the minimal abuse_first install must arm the first-attempt guard');
        /** @var FirstAttemptLoginGuard $guard */
        $guard = $container->get(FirstAttemptLoginGuard::class);
        $loginScopes = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'loginScopes'))->getValue($guard);
        self::assertSame(['main' => 'login'], $loginScopes, 'the profile defaults the main firewall to the login scope');

        self::assertTrue($container->has(KiwiOutcomeBridgeSubscriber::class), 'the single mapped login scope infers the outcome scope, so the outcome bridge arms without risk.outcomes.scope');
        $bridge = $container->get(KiwiOutcomeBridgeSubscriber::class);
        $scopeId = (new \ReflectionProperty(KiwiOutcomeBridgeSubscriber::class, 'scopeId'))->getValue($bridge);
        self::assertSame(crc32('login') & 0x7fffffff, $scopeId, 'the bridge books under the inferred login scope id (the profile row derives its id from the name)');

        // The per-event resolution is live: an event whose firewall has
        // no entry is outside the gate's mandate, so the token stays
        // intact and the skip is counted (the enforcing posture must
        // see how many logins bypass the gate).
        $counters = $container->get('kiwi_captcha.metrics_counters');
        $server = ['REMOTE_ADDR' => '203.0.113.10'];
        $request = \Symfony\Component\HttpFoundation\Request::create('https://app.example.com/sso', 'POST', [], [], [], $server);
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.sso');
        $stack = $container->get('request_stack');
        $stack->push($request);
        $event = new class ($this->wiredToken()) {
            public function __construct(private object $token)
            {
            }

            public function getAuthenticatedToken(): object
            {
                return $this->token;
            }

            public function setAuthenticatedToken(object $token): void
            {
                $this->token = $token;
            }
        };
        $guard->onTokenCreated($event);
        self::assertNotInstanceOf(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken::class, $event->getAuthenticatedToken(), 'an unmapped firewall is skipped, not withheld');
        self::assertSame(1, $counters->all()['kiwi_login_guard_unmapped_total'] ?? 0, 'the unmapped skip is counted');
    }

    /**
     * The inference at the extension level: exactly one distinct mapped
     * login scope names the outcome scope, so the bridge arms without
     * risk.outcomes.scope; several differing scopes leave no single
     * target and the bridge stays unregistered until the knob is
     * explicit.
     */
    public function testTheOutcomeScopeIsInferredFromASingleLoginScope(): void
    {
        $container = $this->load(['risk' => [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'namespace' => 'bridge-infer',
            'scopes' => ['login' => ['id' => 10]],
            'login_scopes' => ['main' => 'login', 'second' => 'login'],
            'outcomes' => ['auto_bridge' => true],
        ]]);
        self::assertTrue($container->hasDefinition(KiwiOutcomeBridgeSubscriber::class), 'two firewalls on one login scope still resolve one outcome scope');
        $bridge = $container->getDefinition(KiwiOutcomeBridgeSubscriber::class);
        self::assertSame(10, $bridge->getArgument(2), 'the inferred scope is the login scope id the auth events book under');

        $container = $this->load(['risk' => [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'namespace' => 'bridge-multi',
            'scopes' => ['login' => ['id' => 10], 'admin_login' => ['id' => 30]],
            'login_scopes' => ['main' => 'login', 'admin' => 'admin_login'],
            'outcomes' => ['auto_bridge' => true],
        ]]);
        self::assertFalse($container->hasDefinition(KiwiOutcomeBridgeSubscriber::class), 'several differing login scopes leave no inferable outcome scope; the bridge needs the explicit risk.outcomes.scope');

        $container = $this->load(['risk' => [
            'enabled' => true,
            'redis_service' => 'fake_redis',
            'namespace' => 'bridge-explicit',
            'scopes' => ['login' => ['id' => 10], 'admin_login' => ['id' => 30]],
            'login_scopes' => ['main' => 'login', 'admin' => 'admin_login'],
            'outcomes' => ['scope' => 'login'],
        ]]);
        self::assertTrue($container->hasDefinition(KiwiOutcomeBridgeSubscriber::class), 'an explicit risk.outcomes.scope wins over the multi-scope absence');
        $bridge = $container->getDefinition(KiwiOutcomeBridgeSubscriber::class);
        self::assertSame(10, $bridge->getArgument(2), 'the explicit scope decides the booking scope');
    }

    /**
     * Two firewalls, two policies. The admin firewall resolves its
     * own scope, and the always mode withholds its session on every
     * login. The user firewall stays risk-gated: its Allow decisions
     * grant the session, and its scope booking carries the standard
     * value class.
     */
    public function testTwoFirewallsResolveTheirOwnScopes(): void
    {
        $container = $this->boot('abuse_first', 'two-firewalls');
        /** @var FirstAttemptLoginGuard $guard */
        $guard = $container->get(FirstAttemptLoginGuard::class);
        $loginScopes = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'loginScopes'))->getValue($guard);
        self::assertSame(['main' => 'login', 'admin' => 'admin_login'], $loginScopes, 'each firewall maps to its own scope');
        $modes = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'loginStepUpByScope'))->getValue($guard);
        self::assertSame('always', $modes['admin_login'] ?? 'risk', 'the admin scope configures login_step_up always');
        self::assertSame('risk', $modes['login'] ?? 'risk', 'the user scope stays risk-gated');
        $fields = (new \ReflectionProperty(FirstAttemptLoginGuard::class, 'targetFieldsByScope'))->getValue($guard);
        self::assertSame(['username'], $fields['login'] ?? [], 'the user scope carries the target field under its own key');
        self::assertSame([], $fields['admin_login'] ?? null, 'the admin scope declares no target field');

        // Behavior: the admin firewall's login is withheld (always,
        // whatever the engine decided) and the pending token stamps the
        // admin scope, so the step-up flow books under it.
        $stack = $container->get('request_stack');
        $adminServer = ['REMOTE_ADDR' => '203.0.113.10'];
        $adminRequest = \Symfony\Component\HttpFoundation\Request::create('https://app.example.com/admin/login', 'POST', [], [], [], $adminServer);
        $adminRequest->attributes->set('_firewall_context', 'security.firewall.map.context.admin');
        $stack->push($adminRequest);
        $event = new class ($this->wiredToken()) {
            public function __construct(private object $token)
            {
            }

            public function getAuthenticatedToken(): object
            {
                return $this->token;
            }

            public function setAuthenticatedToken(object $token): void
            {
                $this->token = $token;
            }
        };
        $guard->onTokenCreated($event);
        $pending = $event->getAuthenticatedToken();
        self::assertInstanceOf(\BelConsulting\KiwiCaptchaBundle\Security\StepUp\StepUpPendingToken::class, $pending, 'the admin firewall withholds the session under the always mode');
        self::assertSame('admin_login', $pending->scope(), 'the admin login books the step-up under the admin scope');
    }

    /** A real token shape the guard can unwrap an identifier from. */
    private function wiredToken(): \Symfony\Component\Security\Core\Authentication\Token\TokenInterface
    {
        return new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
            new \Symfony\Component\Security\Core\User\InMemoryUser('wired-user', null, ['ROLE_USER']),
            'main',
            ['ROLE_USER'],
        );
    }

    /**
     * The F7 DoD: the store is built with the configured cookie
     * lifetimes. continuity_cookie.ttl_secs 1200 derives a 2x session
     * tag TTL of 2400000 ms; trusted_device.ttl 2592000 passes through
     * verbatim as 2592000000 ms.
     */
    public function testTheTagStoreIsBuiltWithTheConfiguredCookieLifetimes(): void
    {
        $store = $this->storeDefinition([
            'continuity_cookie' => ['ttl_secs' => 1200],
            'trusted_device' => ['ttl' => 2_592_000],
        ]);
        self::assertSame(2_400_000, $store->getArgument('$sessionTtlMs'), 'session tags live 2x the configured continuity cookie');
        self::assertSame(2_592_000_000, $store->getArgument('$deviceTtlMs'), 'device tags live exactly the configured device cookie TTL');
    }

    /**
     * The lifetime contract, against the real wiring (the defaults):
     * the session tag TTL outlasts the continuity cookie it protects,
     * the device tag TTL matches the device cookie, and the network tag
     * TTL outlasts both.
     */
    public function testSessionTagsOutlastTheCookieAndDeviceTagsMatchIt(): void
    {
        $container = $this->load(['risk' => ['enabled' => true, 'redis_service' => 'fake_redis']]);
        $store = $container->getDefinition('kiwi_captcha.risk.principal_networks');
        $cookie = $container->getDefinition(ContinuityCookie::class);
        $device = $container->getDefinition(TrustedDeviceCookie::class);

        $sessionTtlMs = $store->getArgument('$sessionTtlMs');
        $deviceTtlMs = $store->getArgument('$deviceTtlMs');
        $cookieTtlMs = $cookie->getArgument(1) * 1000;
        $deviceCookieTtlMs = $device->getArgument(1) * 1000;

        self::assertGreaterThanOrEqual($cookieTtlMs, $sessionTtlMs, 'session tag TTL must outlast the continuity cookie');
        self::assertSame($deviceCookieTtlMs, $deviceTtlMs, 'device tag TTL must match the device cookie so the binding expires with it');
        self::assertGreaterThan($sessionTtlMs, RedisPrincipalNetworkTagStore::DEFAULT_NET_TTL_MS, 'network tags outlast session tags');
        self::assertGreaterThan($deviceTtlMs, RedisPrincipalNetworkTagStore::DEFAULT_NET_TTL_MS, 'network tags outlast device tags');
        self::assertGreaterThan(0, $sessionTtlMs, 'a zero cookie TTL still wires a positive session tag TTL (the Lua session floor)');
    }

    /**
     * The config bounds keep the derived TTLs inside the canonical Lua
     * class ranges. 2x continuity_cookie.ttl_secs must not exceed the
     * 24 h session ceiling, hence the 12 h config max.
     * trusted_device.ttl must stay in [60, 365 d]; 0 is forbidden,
     * because a disabled device cookie is an operator decision, never a
     * degenerate TTL that would wire a zero tag lifetime.
     */
    public function testTheConfigBoundsKeepTheDerivedTtlsInTheLuaClassRanges(): void
    {
        // Accepted at the boundaries.
        $store = $this->storeDefinition(['continuity_cookie' => ['ttl_secs' => 43_200]]);
        self::assertSame(86_400_000, $store->getArgument('$sessionTtlMs'), '2x a 12 h cookie is exactly the session class ceiling');
        $store = $this->storeDefinition(['trusted_device' => ['ttl' => 31_536_000]]);
        self::assertSame(31_536_000_000, $store->getArgument('$deviceTtlMs'), 'a 365 d device cookie is exactly the device class ceiling');

        // Refused past the ceilings.
        try {
            $this->storeDefinition(['continuity_cookie' => ['ttl_secs' => 43_201]]);
            self::fail('continuity_cookie.ttl_secs above 43200 must be refused (2x would exceed the session class ceiling)');
        } catch (\Throwable $e) {
            self::assertStringContainsString('ttl_secs', $e->getMessage());
        }
        try {
            $this->storeDefinition(['trusted_device' => ['ttl' => 31_536_001]]);
            self::fail('trusted_device.ttl above 31536000 must be refused (it would exceed the device class ceiling)');
        } catch (\Throwable $e) {
            self::assertStringContainsString('ttl', $e->getMessage());
        }

        // The degenerate lifetimes are refused: a zero or sub-minute
        // device cookie would wire a tag lifetime the Lua class range
        // refuses, and 0 must never become a zero server-side TTL.
        foreach ([0, 59] as $ttl) {
            try {
                $this->storeDefinition(['trusted_device' => ['ttl' => $ttl]]);
                self::fail(sprintf('trusted_device.ttl %d must be refused', $ttl));
            } catch (\Throwable $e) {
                self::assertStringContainsString('ttl', $e->getMessage());
            }
        }
    }

    /**
     * Every property of a resolved service whose declared type names a
     * KiwiCaptcha\ or BelConsulting\ class (through a plain nullable or
     * a union) must hold an instance on a fully armed container —
     * unless the seam is allow-listed with a reason.
     */
    private function assertKiwiTypedPropertiesAreWired(string $profile, string $serviceId, object $service): void
    {
        $allowList = array_merge(
            self::NULLABLE_SEAM_ALLOW_LIST[$serviceId] ?? [],
            self::PROFILE_NULLABLE_SEAM_ALLOW_LIST[$profile][$serviceId] ?? [],
        );
        $ref = new \ReflectionClass($service);
        foreach ($ref->getProperties() as $prop) {
            if ($prop->isStatic()) {
                continue;
            }
            $kiwiTypes = self::kiwiClassTypeNames($prop->getType());
            if ($kiwiTypes === []) {
                continue;
            }
            try {
                $value = $prop->getValue($service);
            } catch (\Error) {
                self::fail(sprintf(
                    'profile %s: %s::$%s is typed %s but uninitialized after construction',
                    $profile,
                    $serviceId,
                    $prop->getName(),
                    implode('|', $kiwiTypes),
                ));
            }
            if ($value !== null) {
                continue;
            }
            if (\array_key_exists($prop->getName(), $allowList)) {
                self::addToAssertionCount(1);

                continue;
            }
            self::fail(sprintf(
                'profile %s: %s::$%s is typed %s and resolved null on a fully armed container — a silently disabled defense. Make it a hard reference or allow-list it with a reason (%s).',
                $profile,
                $serviceId,
                $prop->getName(),
                implode('|', $kiwiTypes),
                'ProductionWiringGateTest::NULLABLE_SEAM_ALLOW_LIST',
            ));
        }
    }

    /** The KiwiCaptcha\/BelConsulting\ class names a property type declares. */
    private static function kiwiClassTypeNames(?\ReflectionType $type): array
    {
        if ($type === null) {
            return [];
        }
        $names = [];
        foreach ($type instanceof \ReflectionUnionType || $type instanceof \ReflectionIntersectionType ? $type->getTypes() : [$type] as $member) {
            if (!$member instanceof \ReflectionNamedType || $member->isBuiltin()) {
                continue;
            }
            if (str_starts_with($member->getName(), 'KiwiCaptcha\\') || str_starts_with($member->getName(), 'BelConsulting\\')) {
                $names[] = $member->getName();
            }
        }

        return $names;
    }

    /** Boots one profile's kernel and returns the test container. */
    private function boot(?string $profile, string $variant = 'default', bool $withTargetField = true): ContainerInterface
    {
        $kernel = new ProductionWiringGateKernel('test', true, $profile, $variant, $withTargetField);
        $kernel->boot();

        return $kernel->getContainer()->get('test.service_container');
    }

    /**
     * Loads the extension once and returns the principal-network store
     * definition, the exact compile surface the F7 wiring runs on.
     *
     * @param array<string, mixed> $riskExtra
     */
    private function storeDefinition(array $riskExtra): Definition
    {
        return $this->load(['risk' => array_merge([
            'enabled' => true,
            'redis_service' => 'fake_redis',
        ], $riskExtra)])->getDefinition('kiwi_captcha.risk.principal_networks');
    }

    /**
     * Loads the extension into a fresh container with one registered
     * fake Redis client and returns it (the extension-load compile the
     * wiring tests use; no kernel boot, no Redis traffic).
     *
     * @param array<string, mixed> $config
     */
    private function load(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->register('fake_redis', FakePredisClient::class);
        (new KiwiCaptchaExtension())->load([array_merge([
            'secret_key' => '0123456789abcdef0123456789abcdef',
            'difficulty_bits' => 8,
        ], $config)], $container);

        return $container;
    }
}

/**
 * The wiring-gate kernel: one protection profile per instance, the risk
 * plane armed over the fake Redis client, a login scope (optionally
 * carrying the target field), the outcomes auto-bridge scoped to it and
 * the shared ASN dataset fixture. Nothing touches the network: the gate
 * reflects on constructed services only.
 */
final class ProductionWiringGateKernel extends Kernel
{
    public function __construct(
        string $environment,
        bool $debug,
        private readonly ?string $profile = null,
        private readonly string $variant = 'default',
        private readonly bool $withTargetField = true,
    ) {
        parent::__construct($environment, $debug);
    }

    public function registerBundles(): iterable
    {
        yield new \Symfony\Bundle\FrameworkBundle\FrameworkBundle();
        yield new \Symfony\Bundle\TwigBundle\TwigBundle();
        yield new \BelConsulting\KiwiCaptchaBundle\KiwiCaptchaBundle();
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/kiwicaptcha-wiring-gate-'.md5(static::class.$this->profile.$this->variant.($this->withTargetField ? 't' : 'n')).'/'.$this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/kiwicaptcha-wiring-gate-logs/'.md5(static::class.$this->profile.$this->variant);
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $profile = $this->profile;
        $withTargetField = $this->withTargetField;
        $variant = $this->variant;
        $loader->load(function (ContainerBuilder $container) use ($profile, $withTargetField, $variant): void {
            $container->register('fake_redis', FakePredisClient::class)->setPublic(true);
            $container->loadFromExtension('framework', [
                'secret' => 'test-secret',
                'test' => true,
            ]);
            // The minimal variant is the H1 regression surface: the
            // profile alone (no outcomes scope, no explicit login map,
            // no explicit risk.enabled) must arm the whole first-attempt
            // defense.
            if ($variant === 'minimal') {
                $container->loadFromExtension('kiwi_captcha', [
                    'secret_key' => '0123456789abcdef0123456789abcdef',
                    'protection_profile' => $profile,
                    'risk' => [
                        'redis_service' => 'fake_redis',
                        'asn' => ['dataset_path' => RiskStageMatrixTestKernel::asnFixturePath()],
                    ],
                ]);

                return;
            }
            // The two-firewall variant: a user login and an admin login
            // resolve their own scopes (the admin scope carries the
            // always mode, the user scope stays risk-gated).
            if ($variant === 'two-firewalls') {
                $container->loadFromExtension('kiwi_captcha', [
                    'secret_key' => '0123456789abcdef0123456789abcdef',
                    'protection_profile' => $profile,
                    'risk' => [
                        'enabled' => true,
                        'redis_service' => 'fake_redis',
                        'namespace' => 'wiring-gate-two',
                        'scopes' => [
                            'login' => ['id' => 10, 'target_field' => 'username'],
                            'admin_login' => ['id' => 30, 'value_class' => 'critical', 'login_step_up' => 'always'],
                        ],
                        'login_scopes' => ['main' => 'login', 'admin' => 'admin_login'],
                        'asn' => ['dataset_path' => RiskStageMatrixTestKernel::asnFixturePath()],
                        'outcomes' => ['scope' => 'login'],
                    ],
                ]);

                return;
            }
            $scope = ['id' => 10, 'value_class' => 'critical'];
            if ($withTargetField) {
                $scope['target_field'] = 'username';
            }
            // The ha_safe posture pins the serving authority of the
            // security Redis: the top-level client IS the pinned
            // authority, so this profile wires it at the top level, and
            // the risk plane names the same client explicitly (the
            // checked wrapper's class is not resolvable for the reuse
            // decision, so risk always names its own client).
            $haSafe = $profile === 'ha_safe';
            $container->loadFromExtension('kiwi_captcha', array_filter([
                'secret_key' => '0123456789abcdef0123456789abcdef',
                'difficulty_bits' => 8,
                'protection_profile' => $profile,
                'redis_service' => $haSafe ? 'fake_redis' : null,
                'risk' => [
                    'enabled' => true,
                    'redis_service' => 'fake_redis',
                    'namespace' => 'wiring-gate',
                    'scopes' => ['login' => $scope],
                    'login_scopes' => ['main' => 'login'],
                    'asn' => ['dataset_path' => RiskStageMatrixTestKernel::asnFixturePath()],
                    'outcomes' => ['scope' => 'login'],
                ],
            ], static fn ($v): bool => $v !== null));
        });
    }
}
