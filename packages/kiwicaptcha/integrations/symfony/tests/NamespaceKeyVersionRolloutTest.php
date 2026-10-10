<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Controller\KiwiHealthController;
use BelConsulting\KiwiCaptchaBundle\Controller\SiteVerifyController;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\KiwiCaptchaExtension;
use BelConsulting\KiwiCaptchaBundle\RedisNamespace;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException;
use BelConsulting\KiwiCaptchaBundle\Risk\RedisChainedChallengeStateStore;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyIdempotencyStore;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\RedisSiteVerifyMetadataStore;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\ChainRedisFake;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\SiteVerifyStoreAssert;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The namespace-key-version rollout: switching an existing deployment
 * to the digest derivation is an explicit, acknowledged migration, and
 * the state that can revoke or block something is never abandoned by
 * the cutover.
 *
 * The scenario is the deployment the migration exists for. The legacy
 * namespace holds the emergency revocation
 * (`{kiwi:<legacy>}:security-policy` with min_policy_epoch 7) and an
 * open chain obligation, while the new namespace is empty. The
 * application is still configured with policy_version 6 and boots on
 * namespace_key_version 2 with the drained-migration acknowledgment.
 *
 * The test proves the three properties the rollout must have:
 * readiness never admits the epoch-6 node, verification never falls
 * back to epoch 6, and ticketless issuance can never restart stage 1
 * while the legacy obligation is open.
 */
final class NamespaceKeyVersionRolloutTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    /** The raw configured discriminator both key versions derive from. */
    private const RAW = '/srv/kiwi-prod';

    /** The application's risk.policy_version at the cutover. */
    private const CONFIGURED_EPOCH = 6;

    /** The central emergency revocation that must survive. */
    private const CENTRAL_EPOCH = 7;

    private static function legacyNamespace(): string
    {
        return RedisNamespace::derive(self::RAW, RedisNamespace::VERSION_LEGACY);
    }

    private static function digestNamespace(): string
    {
        return RedisNamespace::derive(self::RAW, RedisNamespace::VERSION_DIGEST);
    }

    public function testTheTwoDerivationsOfTheDeploymentDiffer(): void
    {
        // The cutover is real: the digest namespace is not the legacy
        // segment, so the state written before the migration lives under
        // a different key family and the dual-read is what carries it.
        self::assertSame('_srv_kiwi-prod', self::legacyNamespace(), 'the legacy derivation sanitizes the separator bytes');
        self::assertNotSame(self::legacyNamespace(), self::digestNamespace());
    }

    public function testTheDigestKeyVersionRequiresTheDrainedMigrationAcknowledgment(): void
    {
        // The digest version changes every key family at once, so the
        // bundle refuses it without the explicit acknowledgment.
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::RAW);
        $container->register('fake_redis', FakePredisClient::class);
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/namespace_migration/');
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_DIGEST,
            'risk' => ['namespace' => self::RAW],
        ]], $container);
    }

    public function testTheDigestRolloutWiresTheRawNamespaceAndVersionIntoEveryConsumer(): void
    {
        $container = $this->loadContainer([
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_DIGEST,
            'namespace_migration' => 'migrating_v2',
            'risk' => [
                'namespace' => self::RAW,
                'chaining' => ['enabled' => true],
                'request_binding_authority' => 'binding.authority',
            ],
            'ha_authority' => 'pinned_primary',
        ]);

        // The security-epoch monitor: raw namespace + configured version
        // (the monitor derives the digest key and dual-reads the legacy
        // segment internally).
        $monitor = $container->getDefinition(SecurityEpochMonitor::class)->getArguments();
        self::assertSame(self::RAW, $monitor[2], 'the monitor receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $monitor['$namespaceKeyVersion'] ?? null, 'the monitor receives the configured key version');

        // The readiness probe: same raw namespace + version.
        $health = $container->getDefinition(KiwiHealthController::class)->getArguments();
        self::assertSame(self::RAW, $health[2], 'the readiness probe receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $health['$namespaceKeyVersion'] ?? null, 'the readiness probe receives the configured key version');

        // The chain store: raw namespace + version (it derives the
        // primary tag and dual-reads the legacy segment for obligations
        // and chain records).
        $chain = $container->getDefinition(RedisChainedChallengeStateStore::class)->getArguments();
        self::assertSame(self::RAW, $chain[1], 'the chain store receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $chain[4] ?? null, 'the chain store receives the configured key version');

        // The authority pin: the guard is the single derivation boundary
        // and receives the raw namespace + version (never a derived
        // value).
        $guard = $container->getDefinition('kiwi_captcha.ha_authority_guard.storage')->getArguments();
        self::assertSame(self::RAW, $guard[1], 'the guard receives the raw namespace');
        self::assertSame(RedisNamespace::VERSION_DIGEST, $guard[5] ?? null, 'the guard receives the configured key version');
        $direct = new PinnedPrimaryAuthorityGuard(new FakePredisClient(), self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame(
            '{kiwi:'.self::digestNamespace().'}:authority:pin:storage',
            $direct->pinKey(),
            'the digest pin key is derived exactly once from the raw namespace',
        );
    }

    public function testTheLegacySecurityPolicyRevocationSurvivesTheNamespaceCutover(): void
    {
        // Old namespace: the emergency revocation. New namespace: empty.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => (string) self::CENTRAL_EPOCH,
        ];
        self::assertArrayNotHasKey('{kiwi:'.self::digestNamespace().'}:security-policy', $client->hashes, 'the new namespace starts empty');

        // Verification: the effective epoch is the merged floor (7), never
        // the freshly started process's configured epoch (6). A node that
        // read only the digest key would serve max(6, 0) = 6 and accept
        // the revoked epoch-6 challenges.
        $monitor = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            self::CONFIGURED_EPOCH,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertSame(
            [
                '{kiwi:'.self::digestNamespace().'}:security-policy',
                '{kiwi:'.self::legacyNamespace().'}:security-policy',
            ],
            $monitor->policyKeys(),
            'the digest rollout consults the digest key first, then the legacy segment',
        );
        self::assertSame(self::CENTRAL_EPOCH, $monitor->currentEpoch(), 'the legacy revocation raises the effective epoch to 7');
        self::assertSame(self::CENTRAL_EPOCH, $monitor->observedMax(), 'the observed max carries the legacy revocation');

        // Readiness: the epoch-6 node stays in the pool. The legacy
        // revocation raises the effective epoch to 7, which issuance
        // stamps and the verifier enforces, so the node follows the
        // legacy floor instead of leaving the pool; a node that read only
        // the digest key would serve max(6, 0) = 6 and accept the revoked
        // epoch-6 challenges. The readiness lag is a log warning.
        $controller = new KiwiHealthController(
            self::SECRET,
            $client,
            self::RAW,
            self::CONFIGURED_EPOCH,
            null,
            0,
            null,
            16384,
            [],
            null,
            false,
            1,
            1,
            RedisNamespace::VERSION_DIGEST,
        );
        $response = $controller->ready();
        self::assertSame(200, $response->getStatusCode(), 'the epoch-6 node follows the effective epoch 7 and stays ready');
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('ready', $body['status'] ?? '', 'the effective-epoch follow keeps the node ready');
    }

    public function testThePolicyFloorsMergeConservativelyAcrossBothNamespaces(): void
    {
        // A mixed state: the legacy policy declares the strongest
        // protocol and execution floors, the digest policy the strongest
        // epoch. The merged read takes the maximum of every floor — an
        // absent field in one namespace never weakens the other's.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => '3',
            SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD => '4',
            SecurityEpochMonitor::MIN_EXECUTION_VERSION_FIELD => '2',
        ];
        $client->hashes['{kiwi:'.self::digestNamespace().'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => '5',
            SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD => '2',
        ];

        $monitor = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertSame(5, $monitor->currentEpoch(), 'the strongest epoch wins');
        self::assertSame(4, $monitor->minProtocolVersion(), 'the strongest protocol floor wins');
        self::assertSame(2, $monitor->minExecutionVersion(), 'the strongest execution floor wins');

        // A corrupt field in either namespace leaves the combined read
        // unconfirmed: the protocol/execution floors are never armed off
        // a possibly-weaker read.
        $client->hashes['{kiwi:'.self::legacyNamespace().'}:security-policy'][SecurityEpochMonitor::MIN_PROTOCOL_VERSION_FIELD] = '4x';
        $corrupt = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            self::RAW,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
        );
        self::assertNull($corrupt->minProtocolVersion(), 'a corrupt legacy floor keeps the merged protocol floor unconfirmed');
        self::assertSame(5, $corrupt->currentEpoch(), 'the confirmed epoch fields still merge');
    }

    public function testTheOpenChainObligationSurvivesTheNamespaceCutover(): void
    {
        // Old namespace: an open chain obligation (a stage-2 obligation
        // already issued before the cutover). New namespace: empty.
        $fake = new ChainRedisFake();
        $legacyStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_LEGACY);
        $legacyService = new ChainedChallengeTicketService($legacyStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $requirement = $legacyService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );
        $obligationId = $legacyService->obligationIdFor('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        self::assertSame($requirement->chainId, $legacyStore->obligationChainId($obligationId), 'the legacy obligation is open before the cutover');
        foreach (array_keys($fake->strings) as $key) {
            self::assertStringNotContainsString('{kiwi:'.self::digestNamespace().'}', (string) $key, 'the new namespace starts empty');
        }

        // Boot the upgraded node: the digest store consults the digest
        // namespace first and the legacy segment second.
        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        self::assertSame($requirement->chainId, $digestStore->obligationChainId($obligationId), 'the obligation written before the cutover stays visible');
        self::assertNotNull($digestStore->read($requirement->chainId), 'the chain record written before the cutover stays readable');

        $digestService = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $found = $digestService->findOpenRequirement('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        self::assertNotNull($found, 'a ticketless request must see the open obligation, never restart stage 1');
        self::assertSame($requirement->chainId, $found->chainId);

        // The transition on the legacy-only record fails closed: the
        // reservation answers missing, so the controller cannot issue a
        // fresh unchained stage-1 challenge behind the open obligation.
        self::assertSame(
            ChainReservationResult::Missing,
            $digestService->reserveStage2($requirement->chainId, bin2hex(random_bytes(16))),
            'a transition on the legacy record fails closed instead of restarting the transaction',
        );
    }

    public function testTheLegacyAuthorityPinIsMigratedInsteadOfOrphaned(): void
    {
        $client = new FakePredisClient();
        $legacyKey = '{kiwi:'.self::legacyNamespace().'}:authority:pin:storage';
        $digestKey = '{kiwi:'.self::digestNamespace().'}:authority:pin:storage';
        $client->strings[$legacyKey] = 'primary|run-42';

        $guard = new PinnedPrimaryAuthorityGuard($client, self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame('primary|run-42', $guard->state()['pinned'], 'the legacy pin is adopted by the digest-version guard');
        self::assertSame('primary|run-42', $client->strings[$digestKey] ?? null, 'the legacy pin is explicitly migrated to the digest pin key');
        self::assertSame('primary|run-42', $client->strings[$legacyKey] ?? null, 'the legacy pin is left in place, never destroyed');

        // An existing digest pin always wins: the migration only adopts a
        // legacy pin when the primary pin is absent.
        $client->strings[$digestKey] = 'primary|run-43';
        $guard2 = new PinnedPrimaryAuthorityGuard($client, self::RAW, 5, 'storage', null, RedisNamespace::VERSION_DIGEST);
        self::assertSame('primary|run-43', $guard2->state()['pinned'], 'an existing digest pin is authoritative');
        self::assertSame('primary|run-43', $client->strings[$digestKey]);
    }

    public function testTheFreshMigrationModeSelectsTheDigestDerivationForANewInstall(): void
    {
        // A brand-new install with no pre-cutover state selects the
        // digest derivation without declaring itself "drained".
        $container = $this->loadContainer([
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_migration' => 'fresh',
            'risk' => ['namespace' => self::RAW],
        ]);
        $monitor = $container->getDefinition(SecurityEpochMonitor::class)->getArguments();
        self::assertSame(self::RAW, $monitor[2], 'the raw discriminator is still the identity');
        self::assertSame(
            RedisNamespace::VERSION_DIGEST,
            $monitor['$namespaceKeyVersion'] ?? null,
            'fresh selects the digest derivation without the drained acknowledgment',
        );
    }

    public function testAFreshMigrationContradictingAnExplicitLegacyVersionIsRejected(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::RAW);
        $container->register('fake_redis', FakePredisClient::class);
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/migrating_v2\\/drained\\/fresh select the digest/');
        (new KiwiCaptchaExtension())->load([[
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_LEGACY,
            'namespace_migration' => 'fresh',
            'risk' => ['namespace' => self::RAW],
        ]], $container);
    }

    public function testTheOmittedKeyVersionKeepsTheLegacyShapeAndEmitsTheAdvisory(): void
    {
        // An existing deployment that upgrades without choosing a version
        // keeps its key space, and the bundle says so conspicuously.
        $container = $this->loadContainer([
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'risk' => ['namespace' => self::RAW],
        ]);
        $monitor = $container->getDefinition(SecurityEpochMonitor::class)->getArguments();
        self::assertSame(
            RedisNamespace::VERSION_LEGACY,
            $monitor['$namespaceKeyVersion'] ?? null,
            'an omitted version keeps the legacy sanitized derivation',
        );
        $messages = array_map(
            static fn ($entry): string => \is_array($entry) ? (string) ($entry['message'] ?? '') : (string) $entry,
            $container->getCompiler()->getLog(),
        );
        self::assertNotEmpty(
            array_filter($messages, static fn (string $message): bool => str_contains($message, 'namespace_key_version is not configured')),
            'the omitted version is called out with a configuration advisory',
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideCorruptChainStates(): iterable
    {
        foreach (['available', 'reserved', 'issued', 'denied', 'step_up_required'] as $state) {
            yield $state.' (primary)' => [$state, 'primary'];
            yield $state.' (legacy)' => [$state, 'legacy'];
        }
    }

    /**
     * @dataProvider provideCorruptChainStates
     */
    public function testACorruptChainIsNeverHealedIntoAFreshChain(string $state, string $namespace): void
    {
        // Corrupt retained state must fail closed exactly like every other
        // persisted security boundary: the pointed-at record is preserved
        // byte for byte, the obligation mapping survives, and no fresh
        // chain is ever created in its place. Only a genuinely missing or
        // signed-expired record is stale state that may be repaired.
        $fake = new ChainRedisFake();
        $storeNamespace = $namespace === 'legacy'
            ? RedisNamespace::VERSION_LEGACY
            : RedisNamespace::VERSION_DIGEST;
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, $storeNamespace);
        [$chainId, $obligationId] = $this->buildChainInState($store, $fake, $state);

        $tag = $namespace === 'legacy' ? self::legacyNamespace() : self::digestNamespace();
        $chainKey = '{kiwi:'.$tag.'}:chain:'.$chainId;
        $obligationKey = '{kiwi:'.$tag.'}:chain-obligation:'.$obligationId;
        $record = json_decode((string) $fake->strings[$chainKey], true, flags: JSON_THROW_ON_ERROR);
        // Corrupt a persisted field: the state is no longer one of the
        // contract's states.
        $record['state'] = 'quantum';
        $corrupt = (string) json_encode($record, JSON_THROW_ON_ERROR);
        $fake->strings[$chainKey] = $corrupt;
        $beforeKeys = array_keys($fake->strings);

        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);

        try {
            $digestStore->createOrGetObligation(
                $obligationId,
                str_pad('f', 64, '0'),
                base64_encode(random_bytes(32)),
                'login',
                '',
                'sha20',
                RiskAction::Sha20->rank(),
                self::CONFIGURED_EPOCH,
                $fake->clockSecs() + 300,
                300,
            );
            self::fail(sprintf('a corrupt %s chain in the %s namespace must fail closed, never heal', $state, $namespace));
        } catch (MalformedChainedChallengeStateException) {
            // expected: the retryable/fail-closed 503 path
        }

        self::assertSame($corrupt, $fake->strings[$chainKey], 'the corrupt bytes are preserved');
        self::assertSame($chainId, $fake->strings[$obligationKey] ?? null, 'the obligation mapping is preserved');
        self::assertSame($beforeKeys, array_keys($fake->strings), 'no key is created or deleted by the refused create-or-get');
    }

    public function testALegacyChainRecordWithoutTheGenerationFieldsKeepsWorking(): void
    {
        // A chain record written before the generation fields existed is
        // the legacy shape: it decodes as generation 1, the read serves
        // it, and the first transition heals it (the write carries the
        // fields), so an in-flight chain survives the upgrade.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        [$chainId, $obligationId] = $this->buildChainInState($store, $fake, 'available');
        $chainKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$chainId;
        $legacy = json_decode((string) $fake->strings[$chainKey], true, flags: JSON_THROW_ON_ERROR);
        unset($legacy['requirementGeneration'], $legacy['reservedRequirementGeneration']);
        $fake->strings[$chainKey] = (string) json_encode($legacy, JSON_THROW_ON_ERROR);

        $read = $store->read($chainId);
        self::assertSame(1, $read['requirementGeneration'], 'the legacy record decodes as generation 1');

        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        self::assertSame(ChainReservationResult::Available, $service->reserveStage2($chainId, 'owner-a'));
        $healed = json_decode((string) $fake->strings[$chainKey], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(1, $healed['requirementGeneration'], 'the first transition writes the generation');
        self::assertSame(1, $healed['reservedRequirementGeneration']);
        self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($chainId, 'owner-a', base64_encode(random_bytes(32))));
    }

    public function testALegacyReservationCannotBeIssuedOrCompletedAfterAStrongerRaise(): void
    {
        // A pre-upgrade reservation has no generation snapshot (logically
        // generation 1). A stronger reassessment raises the chain to
        // generation 2; the legacy reservation must then fail both the
        // issuance CAS and the deprecated complete() CAS, so the weaker
        // challenge can never be installed.
        foreach (['markIssued', 'complete'] as $transition) {
            $fake = new ChainRedisFake();
            $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
            [$chainId, $obligationId] = $this->buildChainInState($store, $fake, 'reserved');
            $chainKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$chainId;
            $legacy = json_decode((string) $fake->strings[$chainKey], true, flags: JSON_THROW_ON_ERROR);
            unset($legacy['requirementGeneration'], $legacy['reservedRequirementGeneration']);
            $fake->strings[$chainKey] = (string) json_encode($legacy, JSON_THROW_ON_ERROR);

            // The raise materializes the canonical fields (it used to
            // crash the Lua script on tonumber(nil) + 1).
            $raised = $store->createOrGetObligation(
                $obligationId,
                str_pad('c', 64, '0'),
                base64_encode(random_bytes(32)),
                'login',
                'txn-rollout',
                'argon32',
                RiskAction::Argon32->rank(),
                self::CONFIGURED_EPOCH,
                $fake->clockSecs() + 300,
                300,
            );
            self::assertSame($chainId, $raised);
            $record = $store->read($chainId);
            self::assertSame(2, $record['requirementGeneration'], $transition.': the legacy record materialized and raised to generation 2');
            self::assertSame('reserved', $record['state'], $transition.': the in-flight reservation survives the raise');

            if ($transition === 'markIssued') {
                self::assertSame(
                    'stale_requirement',
                    $store->markIssued($chainId, 'owner-a', base64_encode(random_bytes(32))),
                    'the legacy reservation (logical generation 1) can never install after the raise',
                );
            } else {
                self::assertNull(
                    $store->complete($chainId, 'owner-a', base64_encode(random_bytes(32))),
                    'the deprecated complete() applies the same reservation CAS',
                );
            }
            $after = $store->read($chainId);
            self::assertSame('reserved', $after['state'], $transition.': the refused transition installs nothing');
        }
    }

    public function testAnExplicitNullGenerationIsCorruptNotLegacy(): void
    {
        // The field absent is the legacy shape; an explicit JSON null is
        // not (the canonical writer never emits it): it fails closed
        // instead of being read as generation 1.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        [$chainId] = $this->buildChainInState($store, $fake, 'available');
        $chainKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$chainId;
        $record = json_decode((string) $fake->strings[$chainKey], true, flags: JSON_THROW_ON_ERROR);
        $record['requirementGeneration'] = null;
        $fake->strings[$chainKey] = (string) json_encode($record, JSON_THROW_ON_ERROR);

        $this->expectException(MalformedChainedChallengeStateException::class);
        $store->read($chainId);
    }

    public function testACrossTransactionObligationMappingFailsClosedEverywhere(): void
    {
        // The obligation mapping is not authenticated: corruption can
        // point transaction A's obligation at transaction B's perfectly
        // valid chain. The binding invariant (mapping[oid] = chainId AND
        // chain[chainId].obligationId = oid, with scope/binding/policy
        // equal) must fail closed on every path, with zero writes to
        // either chain.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());

        $a = $service->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-a', self::CONFIGURED_EPOCH, RiskAction::Sha18, $fake->clockSecs() + 300);
        $b = $service->requireStage2(base64_encode(random_bytes(32)), 'login', 'txn-b', self::CONFIGURED_EPOCH, RiskAction::Sha18, $fake->clockSecs() + 300);
        self::assertNotSame($a->chainId, $b->chainId);
        $obligationA = $service->obligationIdFor('login', 'txn-a', self::CONFIGURED_EPOCH);
        $chainAKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$a->chainId;
        $chainBKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$b->chainId;
        $obligationAKey = '{kiwi:'.self::digestNamespace().'}:chain-obligation:'.$obligationA;
        $beforeA = $fake->strings[$chainAKey];
        $beforeB = $fake->strings[$chainBKey];

        // Corrupt only A's mapping: point it at B's valid chain.
        $fake->strings[$obligationAKey] = $b->chainId;
        self::assertSame($b->chainId, $store->obligationChainId($obligationA), 'the plain mapping read resolves the corrupted pointer');

        // Ticketless resumption: the resolved record belongs to another
        // transaction, so no requirement is constructed.
        try {
            $service->findOpenRequirement('login', 'txn-a', self::CONFIGURED_EPOCH);
            self::fail('the cross-transaction mapping must never resume another transaction\'s chain');
        } catch (MalformedChainedChallengeStateException) {
            // expected
        }

        // Create-or-get (the Lua binding invariant) refuses for an equal
        // requirement AND for a stronger reassessment (which must never
        // raise a foreign chain).
        $template = json_decode($beforeA, true, flags: JSON_THROW_ON_ERROR);
        foreach ([RiskAction::Sha18, RiskAction::Argon32] as $action) {
            try {
                $store->createOrGetObligation(
                    $obligationA,
                    bin2hex(random_bytes(16)),
                    base64_encode(random_bytes(32)),
                    'login',
                    'txn-a',
                    $action->value,
                    $action->rank(),
                    self::CONFIGURED_EPOCH,
                    $fake->clockSecs() + 300,
                    300,
                );
                self::fail($action->value.': the cross-transaction mapping must fail closed');
            } catch (MalformedChainedChallengeStateException) {
                // expected
            }
        }

        // Neither chain was touched, and the corrupted mapping is
        // preserved byte for byte (zero writes).
        self::assertSame($beforeA, $fake->strings[$chainAKey], 'chain A is untouched');
        self::assertSame($beforeB, $fake->strings[$chainBKey], 'chain B is untouched');
        self::assertSame($b->chainId, $fake->strings[$obligationAKey], 'the corrupted mapping is preserved');
        self::assertSame(
            1,
            (int) (json_decode($beforeB, true, flags: JSON_THROW_ON_ERROR)['requirementGeneration'] ?? 0),
            'a stronger reassessment never raised the foreign chain\'s generation',
        );

        // Transaction B's own mapping still resolves to B's chain.
        self::assertSame(
            $b->chainId,
            $service->findOpenRequirement('login', 'txn-b', self::CONFIGURED_EPOCH)?->chainId,
        );
    }

    public function testACorruptPrimaryChainNeverFallsBackToTheLegacyRecord(): void
    {
        // During migrating_v2 the dual-read falls back only on genuine
        // primary absence. A primary record whose key lifetime was
        // stripped is corrupt at the primary authority: read() must fail
        // closed and must never serve a valid legacy record for the same
        // chain id.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        [$chainId] = $this->buildChainInState($store, $fake, 'available');
        $primaryKey = '{kiwi:'.self::digestNamespace().'}:chain:'.$chainId;
        $legacyKey = '{kiwi:'.self::legacyNamespace().'}:chain:'.$chainId;

        // A valid legacy record for the same chain id, byte-for-byte.
        $fake->strings[$legacyKey] = $fake->strings[$primaryKey];
        $fake->expirations[$legacyKey] = $fake->expirations[$primaryKey] ?? ((int) $fake->clockSecs() + 300) * 1000;
        // Strip the primary key's TTL: present but lifetime-less = corrupt.
        unset($fake->expirations[$primaryKey]);

        try {
            $store->read($chainId);
            self::fail('a lifetime-less primary chain must fail closed, never fall back to the legacy record');
        } catch (MalformedChainedChallengeStateException) {
            // expected
        }
        try {
            $store->obligationChainId('does-not-matter');
            // no obligation: fine; the read path above is the regression
        } catch (\Throwable) {
            self::fail('the unrelated lookup must not throw');
        }
        self::assertArrayHasKey($primaryKey, $fake->strings, 'the corrupt primary record is preserved');
        self::assertArrayHasKey($legacyKey, $fake->strings, 'the legacy record is never served as a fallback');
    }

    public function testAMissingOrExpiredChainStillHeals(): void
    {
        // The counterpart of the corruption rule: a genuinely missing or
        // signed-expired pointed-at record is stale, so the mapping is
        // compare-deleted and a fresh chain is created.
        foreach (['missing', 'expired'] as $kind) {
            $fake = new ChainRedisFake();
            $legacyStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_LEGACY);
            [$chainId, $obligationId] = $this->buildChainInState($legacyStore, $fake, 'available');
            $legacyChainKey = '{kiwi:'.self::legacyNamespace().'}:chain:'.$chainId;
            if ($kind === 'missing') {
                unset($fake->strings[$legacyChainKey]);
            } else {
                $record = json_decode((string) $fake->strings[$legacyChainKey], true, flags: JSON_THROW_ON_ERROR);
                $record['expiresAt'] = $fake->clockSecs() - 1;
                $fake->strings[$legacyChainKey] = (string) json_encode($record, JSON_THROW_ON_ERROR);
            }

            $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
            $service = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
            $requirement = $service->requireStage2(
                base64_encode(random_bytes(32)),
                'login',
                'txn-rollout',
                self::CONFIGURED_EPOCH,
                RiskAction::Sha20,
                $fake->clockSecs() + 300,
            );

            self::assertNotSame($chainId, $requirement->chainId, $kind.': the stale pointer is replaced');
            self::assertArrayNotHasKey(
                '{kiwi:'.self::legacyNamespace().'}:chain-obligation:'.$obligationId,
                $fake->strings,
                $kind.': the stale legacy mapping is cleared',
            );
            self::assertSame($requirement->chainId, $digestStore->obligationChainId($obligationId));
        }
    }

    public function testARaisedRequirementMakesTheOldStage2NonceUnredeemable(): void
    {
        // Stage 2 was minted for sha18; a second stage-1 solve raises the
        // same chain to Argon32. The stale nonce can never be upgraded in
        // place, so the chain fails closed to the terminal step-up state:
        // the stored nonce is no longer redeemable (markVerified only
        // accepts `issued`) and the controller refuses to recover it.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        [$chainId, $obligationId] = $this->buildChainInState($store, $fake, 'issued');

        $raised = $store->createOrGetObligation(
            $obligationId,
            str_pad('e', 64, '0'),
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            'argon32',
            RiskAction::Argon32->rank(),
            self::CONFIGURED_EPOCH,
            $fake->clockSecs() + 300,
            300,
        );
        self::assertSame($chainId, $raised, 'the raise resolves the same chain');

        $requirement = $store->read($chainId);
        self::assertSame('step_up_required', $requirement['state'], 'the issued chain fails closed to step_up_required');
        self::assertSame('argon32', $requirement['requiredAction'], 'the strengthened floor is recorded');
        self::assertSame(2, (int) $requirement['requirementGeneration'], 'the raise bumped the generation');

        self::assertSame(
            'conflict',
            $store->markVerified($chainId, (string) $this->storedNonce($fake, $chainId)),
            'the weaker issued nonce is no longer redeemable',
        );
    }

    public function testAMintedChallengeCannotBeInstalledAfterTheRequirementRose(): void
    {
        // The reservation race: a challenge is reserved for sha18, a
        // concurrent solve raises the chain to Argon32, and the first
        // mint tries to install its sha18 challenge. The reservation CAS
        // refuses it, so the stale-strength challenge is never installed.
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        [$chainId, $obligationId] = $this->buildChainInState($store, $fake, 'available');

        self::assertSame('available', $store->reserve($chainId, 'owner-a', 15));
        $raised = $store->createOrGetObligation(
            $obligationId,
            str_pad('d', 64, '0'),
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            'argon32',
            RiskAction::Argon32->rank(),
            self::CONFIGURED_EPOCH,
            $fake->clockSecs() + 300,
            300,
        );
        self::assertSame($chainId, $raised);
        self::assertSame('reserved', $store->read($chainId)['state'], 'the raise keeps the in-flight reservation');

        self::assertSame(
            'stale_requirement',
            $store->markIssued($chainId, 'owner-a', base64_encode(random_bytes(32))),
            'the sha18 challenge minted for the earlier generation is refused',
        );
        self::assertSame('reserved', $store->read($chainId)['state'], 'the refused issuance installs nothing');
        self::assertSame('argon32', $store->read($chainId)['requiredAction'], 'the raised floor is untouched');
    }

    public function testADrainedDeploymentIsV2OnlyAndNeverReadsTheLegacyNamespace(): void
    {
        // A completed migration (namespace_migration: drained) derives
        // digest keys and reads NO legacy segment: the transitional dual
        // read exists only while migrating_v2 is in effect. This is the
        // isolation the digest namespace exists for — a deployment whose
        // raw namespace used to collide with this one under v1 can never
        // couple to it again.
        $raw = 'tenant/a';
        $unrelatedRaw = 'tenant:a';
        $legacyNamespace = RedisNamespace::derive($unrelatedRaw, RedisNamespace::VERSION_LEGACY);
        $digestNamespace = RedisNamespace::derive($raw, RedisNamespace::VERSION_DIGEST);
        self::assertSame('tenant_a', $legacyNamespace);

        $container = $this->loadContainer([
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'namespace_key_version' => RedisNamespace::VERSION_DIGEST,
            'namespace_migration' => 'drained',
            'risk' => [
                'namespace' => $raw,
                'chaining' => ['enabled' => true],
                'request_binding_authority' => 'binding.authority',
            ],
            'ha_authority' => 'pinned_primary',
        ]);
        $monitor = $container->getDefinition(SecurityEpochMonitor::class)->getArguments();
        self::assertSame(RedisNamespace::VERSION_DIGEST, $monitor['$namespaceKeyVersion'] ?? null);
        self::assertFalse($monitor['$readLegacyFallback'] ?? true, 'a drained migration is v2-only');
        $health = $container->getDefinition(KiwiHealthController::class)->getArguments();
        self::assertFalse($health['$readLegacyFallback'] ?? true, 'the readiness probe is v2-only');
        $chain = $container->getDefinition(RedisChainedChallengeStateStore::class)->getArguments();
        self::assertSame(RedisNamespace::VERSION_DIGEST, $chain[4] ?? null, 'the chain store derives digest keys');
        self::assertFalse($chain[5] ?? true, 'the chain store is v2-only');
        $guard = $container->getDefinition('kiwi_captcha.ha_authority_guard.storage')->getArguments();
        self::assertFalse($guard[6] ?? true, 'the authority pin is v2-only');

        // Functional: an unrelated legacy policy, pin and obligation are
        // invisible to the drained deployment.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.$legacyNamespace.'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => (string) self::CENTRAL_EPOCH,
        ];
        $client->strings['{kiwi:'.$legacyNamespace.'}:authority:pin'] = 'master|unrelated-run';
        $monitorReal = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            $raw,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
            false,
        );
        self::assertSame(['{kiwi:'.$digestNamespace.'}:security-policy'], $monitorReal->policyKeys());
        self::assertSame(1, $monitorReal->currentEpoch(), 'the legacy revocation is invisible after the migration completes');
        $guardReal = new PinnedPrimaryAuthorityGuard($client, $raw, 0, '', null, RedisNamespace::VERSION_DIGEST, false);
        self::assertNull($guardReal->state()['pinned'], 'the legacy pin is never adopted after the migration completes');
    }

    public function testAFreshDeploymentNeverAdoptsAnUnrelatedLegacyNamespace(): void
    {
        // A fresh install (namespace_migration: fresh) with raw namespace
        // `tenant/a` derives the digest keys and reads NO legacy segment.
        // An unrelated drained deployment with the colliding legacy
        // namespace (`tenant:a` -> tenant_a) pre-populates a policy, a
        // pin and a chain obligation there; none of it may surface in the
        // fresh deployment.
        $freshRaw = 'tenant/a';
        $unrelatedRaw = 'tenant:a';
        $legacyNamespace = RedisNamespace::derive($unrelatedRaw, RedisNamespace::VERSION_LEGACY);
        $digestNamespace = RedisNamespace::derive($freshRaw, RedisNamespace::VERSION_DIGEST);
        self::assertSame('tenant_a', $legacyNamespace, 'the unrelated raw namespace folds onto tenant_a in v1');
        self::assertNotSame($legacyNamespace, $digestNamespace);

        // Unrelated legacy state: a revocation policy, an authority pin
        // and a chain obligation.
        $client = new FakePredisClient();
        $client->hashes['{kiwi:'.$legacyNamespace.'}:security-policy'] = [
            SecurityEpochMonitor::MIN_POLICY_EPOCH_FIELD => (string) self::CENTRAL_EPOCH,
        ];
        $client->strings['{kiwi:'.$legacyNamespace.'}:authority:pin'] = 'master|unrelated-run';

        $fake = new ChainRedisFake();
        $legacyStore = new RedisChainedChallengeStateStore($fake, $unrelatedRaw, 0, 100, RedisNamespace::VERSION_LEGACY);
        $legacyService = new ChainedChallengeTicketService($legacyStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $legacyRequirement = $legacyService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-unrelated',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );
        $legacyObligationKey = '{kiwi:'.$legacyNamespace.'}:chain-obligation:'.$legacyService->obligationIdFor('login', 'txn-unrelated', self::CONFIGURED_EPOCH);
        self::assertArrayHasKey($legacyObligationKey, $fake->strings, 'the unrelated deployment owns a legacy obligation');

        // The fresh deployment: no legacy fallback anywhere.
        $monitor = new SecurityEpochMonitor(
            new Verifier(new ArrayStorage()),
            $client,
            $freshRaw,
            1,
            1,
            null,
            60,
            RedisNamespace::VERSION_DIGEST,
            false,
        );
        self::assertSame(['{kiwi:'.$digestNamespace.'}:security-policy'], $monitor->policyKeys(), 'the fresh reader consults only its own digest key');
        self::assertSame(1, $monitor->currentEpoch(), 'the unrelated revocation is invisible');

        $controller = new KiwiHealthController(
            self::SECRET,
            $client,
            $freshRaw,
            1,
            null,
            0,
            null,
            16384,
            [],
            null,
            false,
            1,
            1,
            RedisNamespace::VERSION_DIGEST,
            false,
        );
        self::assertSame(200, $controller->ready()->getStatusCode(), 'the unrelated policy never blocks the fresh deployment');

        $guard = new PinnedPrimaryAuthorityGuard($client, $freshRaw, 0, '', null, RedisNamespace::VERSION_DIGEST, false);
        self::assertNull($guard->state()['pinned'], 'the unrelated legacy pin is never adopted');
        self::assertArrayNotHasKey('{kiwi:'.$digestNamespace.'}:authority:pin', $client->strings, 'no pin is migrated into the fresh deployment');

        $freshStore = new RedisChainedChallengeStateStore($fake, $freshRaw, 0, 100, RedisNamespace::VERSION_DIGEST, false);
        $freshService = new ChainedChallengeTicketService($freshStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $freshRequirement = $freshService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-unrelated',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );
        self::assertNotSame($legacyRequirement->chainId, $freshRequirement->chainId, 'the unrelated obligation is invisible');
        self::assertSame($legacyRequirement->chainId, $fake->strings[$legacyObligationKey], 'the unrelated mapping is untouched');
    }

    /**
     * Build a live chain in the requested state; returns [chainId, obligationId].
     *
     * @return array{0: string, 1: string}
     */
    private function buildChainInState(RedisChainedChallengeStateStore $store, ChainRedisFake $fake, string $state): array
    {
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $requirement = $service->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Sha18,
            $fake->clockSecs() + 300,
        );
        $obligationId = $service->obligationIdFor('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        if ($state !== 'available') {
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, 'owner-a'));
            if ($state !== 'reserved') {
                $nonce = base64_encode(random_bytes(32));
                self::assertSame(ChainIssuedResult::IssuedNew, $service->markIssued($requirement->chainId, 'owner-a', $nonce));
                if ($state === 'denied') {
                    self::assertSame(ChainVerifiedResult::DeniedNew, $service->markDenied($requirement->chainId, $nonce));
                } elseif ($state === 'step_up_required') {
                    self::assertSame(ChainVerifiedResult::StepUpRequiredNew, $service->markStepUpRequired($requirement->chainId, $nonce));
                }
            }
        }

        return [$requirement->chainId, $obligationId];
    }

    private function storedNonce(ChainRedisFake $fake, string $chainId): ?string
    {
        $record = json_decode((string) $fake->strings['{kiwi:'.self::digestNamespace().'}:chain:'.$chainId], true, flags: JSON_THROW_ON_ERROR);

        return \is_string($record['stage2Nonce'] ?? null) ? $record['stage2Nonce'] : null;
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function provideLegacyStates(): iterable
    {
        yield 'available' => ['available'];
        yield 'reserved' => ['reserved'];
        yield 'issued' => ['issued'];
        yield 'denied' => ['denied'];
        yield 'step_up_required' => ['step_up_required'];
    }

    /**
     * @dataProvider provideLegacyStates
     */
    public function testALiveLegacyObligationIsNeverShadowedByAPrimaryOne(string $state): void
    {
        // Old namespace: a live obligation in the given state. New
        // namespace: empty. requireStage2() on the upgraded node must
        // resolve the legacy chain and write nothing in the primary
        // namespace — a fresh primary obligation would shadow a retained
        // denied/step-up requirement.
        [$fake, $legacyService, $legacyChainId, $obligationId] = $this->buildLegacyChain($state);

        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        $digestService = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());

        $requirement = $digestService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );

        self::assertSame($legacyChainId, $requirement->chainId, 'the live legacy chain is resolved, never replaced');
        self::assertSame(
            $state === 'issued' ? 'issued' : $state,
            $requirement->state,
            'the retained legacy state is preserved',
        );
        $this->assertNoDigestChainState($fake);
        self::assertSame(
            $legacyChainId,
            $digestStore->obligationChainId($obligationId),
            'the legacy obligation mapping still resolves through the dual-read',
        );
    }

    public function testAStrongerReassessmentOnALegacyObligationFailsClosed(): void
    {
        [$fake, $legacyService, $legacyChainId] = $this->buildLegacyChain('available');

        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        $digestService = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());

        try {
            $digestService->requireStage2(
                base64_encode(random_bytes(32)),
                'login',
                'txn-rollout',
                self::CONFIGURED_EPOCH,
                RiskAction::Argon64,
                $fake->clockSecs() + 300,
            );
            self::fail('a stronger reassessment on a live legacy obligation must fail closed');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('predates the namespace cutover', $e->getMessage());
        }
        $this->assertNoDigestChainState($fake);
    }

    public function testAStaleLegacyObligationIsClearedBeforeThePrimaryCreate(): void
    {
        // The legacy mapping points at a chain whose record is gone: the
        // mapping is stale, so the create-or-get clears it (compare
        // delete in the legacy namespace) and creates the primary chain
        // instead of blocking forever on a dead pointer.
        [$fake, $legacyService, $legacyChainId, $obligationId] = $this->buildLegacyChain('available');
        $legacyChainKey = '{kiwi:'.self::legacyNamespace().'}:chain:'.$legacyChainId;
        unset($fake->strings[$legacyChainKey]);

        $digestStore = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_DIGEST);
        $digestService = new ChainedChallengeTicketService($digestStore, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $requirement = $digestService->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );

        self::assertNotSame($legacyChainId, $requirement->chainId, 'the dead legacy pointer is replaced by a primary chain');
        self::assertArrayNotHasKey(
            '{kiwi:'.self::legacyNamespace().'}:chain-obligation:'.$obligationId,
            $fake->strings,
            'the stale legacy mapping is cleared',
        );
        self::assertSame(
            $requirement->chainId,
            $digestStore->obligationChainId($obligationId),
            'the primary mapping is authoritative after the heal',
        );
    }

    /**
     * Build a legacy-namespace chain in the requested state and return
     * the fake, the legacy ticket service, the chain id and the
     * obligation id.
     *
     * @return array{0: ChainRedisFake, 1: ChainedChallengeTicketService, 2: string, 3: string}
     */
    private function buildLegacyChain(string $state): array
    {
        $fake = new ChainRedisFake();
        $store = new RedisChainedChallengeStateStore($fake, self::RAW, 0, 100, RedisNamespace::VERSION_LEGACY);
        $service = new ChainedChallengeTicketService($store, self::SECRET, 300, 15, null, fn (): int => $fake->clockSecs());
        $requirement = $service->requireStage2(
            base64_encode(random_bytes(32)),
            'login',
            'txn-rollout',
            self::CONFIGURED_EPOCH,
            RiskAction::Argon32,
            $fake->clockSecs() + 300,
        );
        $obligationId = $service->obligationIdFor('login', 'txn-rollout', self::CONFIGURED_EPOCH);
        $stage2Nonce = base64_encode(random_bytes(32));
        if ($state !== 'available') {
            $owner = bin2hex(random_bytes(16));
            self::assertSame(ChainReservationResult::Available, $service->reserveStage2($requirement->chainId, $owner));
            if ($state !== 'reserved') {
                $service->markIssued($requirement->chainId, $owner, $stage2Nonce);
                if ($state === 'denied') {
                    $service->markDenied($requirement->chainId, $stage2Nonce);
                } elseif ($state === 'step_up_required') {
                    $service->markStepUpRequired($requirement->chainId, $stage2Nonce);
                }
            }
        }

        return [$fake, $service, $requirement->chainId, $obligationId];
    }

    private function assertNoDigestChainState(ChainRedisFake $fake): void
    {
        foreach (array_keys($fake->strings) as $key) {
            self::assertStringNotContainsString(
                '{kiwi:'.self::digestNamespace().'}',
                (string) $key,
                'no primary-namespace chain state may be created while the legacy obligation is live',
            );
        }
    }

    public function testTwoDeploymentsSharingOneRedisNeverShareSiteverifyState(): void
    {
        // Two containers, identical secrets and security context, one
        // Redis, different risk.namespace. The Siteverify stores and the
        // invalid-secret log gate must derive from the deployment
        // namespace authority like every other key family.
        $containerA = $this->loadContainer($this->siteverifyConfig('/srv/prod-a'));
        $containerB = $this->loadContainer($this->siteverifyConfig('/srv/prod-b'));
        $idemA = $containerA->getDefinition(RedisSiteVerifyIdempotencyStore::class)->getArguments();
        $idemB = $containerB->getDefinition(RedisSiteVerifyIdempotencyStore::class)->getArguments();
        self::assertSame('/srv/prod-a', $idemA[1], 'the idempotency store receives the raw discriminator');
        self::assertSame('/srv/prod-b', $idemB[1], 'the other deployment receives its own raw discriminator');
        $metaA = $containerA->getDefinition(RedisSiteVerifyMetadataStore::class)->getArguments();
        self::assertSame('/srv/prod-a', $metaA[1], 'the metadata store receives the raw discriminator');
        $controllerArgs = $containerA->getDefinition(SiteVerifyController::class)->getArguments();
        self::assertSame('/srv/prod-a', $controllerArgs['$logGateNamespace'] ?? null, 'the log gate is namespaced');
        self::assertNotSame(
            RedisNamespace::derive('/srv/prod-a'),
            RedisNamespace::derive('/srv/prod-b'),
            'the two deployments derive disjoint key segments',
        );

        // Functional proof on one shared Redis: A completes, B receives
        // the identical backend id and idempotency UUID and must not see
        // (or replay) A's completed result.
        $url = getenv('KC_REDIS_URL');
        if (!\is_string($url) || $url === '') {
            $flag = getenv('KIWI_REQUIRE_REAL_REDIS_TESTS');
            if (\is_string($flag) && $flag !== '' && $flag !== '0') {
                self::fail('KIWI_REQUIRE_REAL_REDIS_TESTS is set but KC_REDIS_URL is absent');
            }
            self::markTestSkipped('KC_REDIS_URL is not set');
        }
        $client = new \Predis\Client([
            'host' => parse_url($url, PHP_URL_HOST) ?: '127.0.0.1',
            'port' => parse_url($url, PHP_URL_PORT) ?: 6379,
        ]);
        $storeA = new RedisSiteVerifyIdempotencyStore($client, '/srv/prod-a');
        $storeB = new RedisSiteVerifyIdempotencyStore($client, '/srv/prod-b');
        $backendId = hash_hmac('sha256', 'login|'.self::CONFIGURED_EPOCH.'|shared-context-digest', 'shared-secret');
        $uuid = 'rollout-shared-'.bin2hex(random_bytes(8));
        $responseHash = hash('sha256', 'canonical-response');
        $keyA = '{kiwi:'.RedisNamespace::derive('/srv/prod-a').'}:siteverify-idem:'.$backendId.':'.$uuid;
        $keyB = '{kiwi:'.RedisNamespace::derive('/srv/prod-b').'}:siteverify-idem:'.$backendId.':'.$uuid;
        $client->del([$keyA, $keyB]);

        try {
            [$claimA, $ownerA] = $storeA->claim($backendId, $uuid, $responseHash, 300, hash('sha256', 'ip-fingerprint'));
            self::assertSame(\BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::Claimed, $claimA);
            self::assertNotNull($ownerA);
            self::assertTrue($storeA->finalize($backendId, $uuid, $responseHash, $ownerA, [
                'success' => true,
                'challenge_ts' => null,
                'hostname' => null,
            ]));
            self::assertNotNull(
                SiteVerifyStoreAssert::completed($storeA->storedForOperation($backendId, $uuid, $responseHash, hash('sha256', 'ip-fingerprint'), '')),
                'A reads back its completed result',
            );
            self::assertNull(
                SiteVerifyStoreAssert::completed($storeB->storedForOperation($backendId, $uuid, $responseHash, hash('sha256', 'ip-fingerprint'), '')),
                'B must never replay a result completed under another deployment namespace',
            );
            [$claimB, $ownerB] = $storeB->claim($backendId, $uuid, $responseHash, 300, hash('sha256', 'ip-fingerprint'));
            self::assertSame(
                \BelConsulting\KiwiCaptchaBundle\SiteVerify\IdempotencyClaim::Claimed,
                $claimB,
                'B claims the identical UUID independently of A',
            );
            self::assertNotNull($ownerB);
            self::assertNotSame($ownerA, $ownerB);
        } finally {
            $client->del([$keyA, $keyB]);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function siteverifyConfig(string $namespace): array
    {
        return [
            'secret_key' => self::SECRET,
            'redis_service' => 'fake_redis',
            'risk' => [
                'namespace' => $namespace,
                // The provider-compatible surface requires a scope whose
                // post-solve check is disabled.
                'scopes' => ['siteverify' => ['post_solve_check' => false]],
                'siteverify_secrets' => ['siteverify-secret-0123456789abcdef' => 'siteverify'],
                'redis' => ['ttl_margin_secs' => 2],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function loadContainer(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.project_dir', self::RAW);
        $container->register('fake_redis', FakePredisClient::class);
        $container->register('binding.authority', \stdClass::class);
        (new KiwiCaptchaExtension())->load([$config], $container);

        return $container;
    }
}
