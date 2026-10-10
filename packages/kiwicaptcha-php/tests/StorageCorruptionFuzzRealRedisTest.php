<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRuntimeStateKind;
use KiwiCaptcha\Config;
use KiwiCaptcha\ConsumedOutcomeRecovery;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\RedisStorage;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\Tests\Fixtures\RealRedisTestEnv;
use KiwiCaptcha\Tests\Fixtures\ServerState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The deterministic storage-corruption fuzz over the real-Redis
 * envelope. Every stored record state is corrupted field by field:
 * pending, consumed-resultless, committed-valid, committed-invalid,
 * cancelled and claimed. Fixed-seed random byte flips and truncations
 * are applied too.
 *
 * Every corruption must resolve to a typed fail-closed outcome. The
 * verifier never throws (no 500), never hangs (every derivation is the
 * bounded sha256 of the genuine 8-bit challenge), and never returns a
 * fabricated authorization. The store boundaries (find, runtimeState,
 * consumedState, deleteIfPending, cancel, claim, commit, release)
 * resolve typed outcomes only.
 *
 * The corrupted envelope never decodes to a record that verifies, with
 * the documented raw-write surfaces pinned by dedicated tests. The
 * runtime envelope fields (state, consumed_result, operation_identity)
 * are storage-layer additions outside the challenge HMAC, so a raw
 * write that rewrites them coherently can bypass the one-shot and
 * identity gates. The consume transition now refuses a pending envelope
 * that carries terminal or claim fields (the pending-envelope guard: a
 * pending record must not contain consumed_result / operation_identity
 * / resume_owner / resume_until; only the consume transition may
 * introduce them). The state-flip resurrection of a consumed
 * (resultless, committed-valid, committed-invalid) record and the
 * coherent result-plus-identity forgery therefore fail closed. The
 * server metadata (`issued_at_ns`, `hostname`) carries the
 * record-metadata MAC, and every stored result carries the
 * consumed-result MAC. A direct write onto an already-consumed record
 * therefore fails closed. That covers a forged result, a re-targeted
 * identity, a transplanted genuine result and any metadata rewrite. One surface remains and is pinned:
 * rollback to older genuine state. A cancelled record carries only the
 * null markers, so flipping its state marker produces bytes
 * byte-identical to a genuine pending envelope, and no MAC over state
 * can tell an old genuine value from the current one. Every
 * single-field canonical tamper stays fail-closed.
 *
 * Runs in the real-Redis CI lane; skips without the published Redis
 * env, fails instead of skipping when KIWI_REQUIRE_REAL_REDIS_TESTS is
 * set and the env is missing.
 */
final class StorageCorruptionFuzzRealRedisTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private const CLIENT_IP = '198.51.100.7';

    /** The operation identity every consumed-state preparation records. */
    private const IDENTITY = 'op-recorded';

    /** A foreign operation identity of the same shape. */
    private const FOREIGN_IDENTITY = 'op-forged';

    /** A foreign 32-hex lease owner token. */
    private const FOREIGN_OWNER = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private \Predis\Client $client;

    private string $prefix = '';

    protected function setUp(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        $url = RealRedisTestEnv::requireRedis('the storage-corruption fuzz must run in the dedicated real-Redis CI lane');
        if ($url === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the CI Redis-service job');
        }
        $this->client = new \Predis\Client($url, ['timeout' => 10.0, 'read_write_timeout' => 10.0]);
        try {
            $this->client->ping();
        } catch (\Throwable $e) {
            RealRedisTestEnv::failWhenRequired('Redis is unreachable at the published URL: '.$e->getMessage(), 'the storage-corruption fuzz');
            self::markTestSkipped('no Redis at the configured KC_REDIS_URL/TEST_REDIS_URL');
        }
        $this->client->flushdb();
        $this->prefix = 'corruption-fuzz-'.bin2hex(random_bytes(4)).'-';
    }

    // ── the tamper corpus ───────────────────────────────────────────────

    /**
     * The single-field canonical tamper set. Every closure mutates the
     * decoded envelope array in place, one field at a time.
     *
     * @return array<string, \Closure>
     */
    private static function canonicalTampers(): array
    {
        return [
            'nonce foreign' => static function (array &$d): void {
                $d['nonce'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
            },
            'scope foreign' => static function (array &$d): void {
                $d['scope'] = 'admin';
            },
            'binding_tag foreign' => static function (array &$d): void {
                $d['binding_tag'] = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
            },
            'issued_at shifted to the past' => static function (array &$d): void {
                $d['issued_at'] = $d['issued_at'] - 1000;
            },
            'expires_at before issued_at' => static function (array &$d): void {
                $d['expires_at'] = $d['issued_at'] - 1;
            },
            'expires_at rewritten inside the lifetime' => static function (array &$d): void {
                $d['expires_at'] = $d['issued_at'] + 50;
            },
            'algorithm flipped' => static function (array &$d): void {
                $d['algorithm'] = $d['algorithm'] === 'sha256' ? 'argon2id' : 'sha256';
            },
            'm_kib raised to one' => static function (array &$d): void {
                $d['m_kib'] = 1;
            },
            't lowered to one' => static function (array &$d): void {
                $d['t'] = 1;
            },
            'p raised to two' => static function (array &$d): void {
                $d['p'] = 2;
            },
            'target_bits beyond the ceiling' => static function (array &$d): void {
                $d['target_bits'] = 21;
            },
            'target_bits raised' => static function (array &$d): void {
                $d['target_bits'] = 12;
            },
            'salt foreign' => static function (array &$d): void {
                $d['salt'] = 'AAAAAAAAAAAAAAAAAAAAAA==';
            },
            'prefix foreign' => static function (array &$d): void {
                $d['prefix'] = 'corrupt-prefix';
            },
            'challenge foreign' => static function (array &$d): void {
                $d['challenge'] = 'corrupt-challenge';
            },
            'min_duration_ms raised to one' => static function (array &$d): void {
                $d['min_duration_ms'] = 1;
            },
            'issued_at_ns zeroed' => static function (array &$d): void {
                $d['issued_at_ns'] = 0;
            },
            'protocol_version to v1' => static function (array &$d): void {
                $d['protocol_version'] = 1;
            },
            'protocol_version to v3' => static function (array &$d): void {
                $d['protocol_version'] = 3;
            },
            'region foreign' => static function (array &$d): void {
                $d['region'] = 'us';
            },
            'policy_version foreign' => static function (array &$d): void {
                $d['policy_version'] = 2;
            },
            'request_binding foreign' => static function (array &$d): void {
                $d['request_binding'] = 'txn-other';
            },
            'issuer foreign' => static function (array &$d): void {
                $d['issuer'] = 'other';
            },
            'kid foreign' => static function (array &$d): void {
                $d['kid'] = 2;
            },
            'decoy_field armed on a v2 record' => static function (array &$d): void {
                $d['decoy_field'] = 'armed';
            },
            'scope key dropped' => static function (array &$d): void {
                unset($d['scope']);
            },
            'hostname foreign' => static function (array &$d): void {
                $d['hostname'] = 'evil.example.com';
            },
            'issued_at_ns within the skew window' => static function (array &$d): void {
                $d['issued_at_ns'] = ((int) $d['issued_at'] + 100) * 1_000_000 - 1000;
            },
            'issued_at_ns backdated one microsecond' => static function (array &$d): void {
                $d['issued_at_ns'] = (int) $d['issued_at_ns'] - 1;
            },
            'server_mac foreign hex' => static function (array &$d): void {
                $d['server_mac'] = str_repeat('ab', 32);
            },
            'server_mac upper-cased' => static function (array &$d): void {
                $d['server_mac'] = strtoupper((string) $d['server_mac']);
            },
            'server_mac truncated' => static function (array &$d): void {
                $d['server_mac'] = substr((string) $d['server_mac'], 0, 63);
            },
            'server_mac stripped' => static function (array &$d): void {
                unset($d['server_mac']);
            },
            'hostname injected with the mac stripped' => static function (array &$d): void {
                $d['hostname'] = 'evil.example.com';
                unset($d['server_mac']);
            },
        ];
    }

    /**
     * The single-field runtime-envelope tamper set: state, consumed
     * result, operation identity and the claim lease fields.
     *
     * @return array<string, \Closure>
     */
    private static function runtimeTampers(): array
    {
        return [
            'state marker to consumed' => static function (array &$d): void {
                $d['state'] = 'consumed';
            },
            'state marker to cancelled' => static function (array &$d): void {
                $d['state'] = 'cancelled';
            },
            'state marker to bogus' => static function (array &$d): void {
                $d['state'] = 'bogus';
            },
            'consumed_result forged valid' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => true, 'binding' => null];
            },
            'consumed_result forged invalid' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => false, 'binding' => null];
            },
            'consumed_result forged valid with a random mac' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => true, 'binding' => null, 'mac' => bin2hex(random_bytes(32))];
            },
            'consumed_result mac stripped' => static function (array &$d): void {
                if (\is_array($d['consumed_result'] ?? null)) {
                    unset($d['consumed_result']['mac']);
                }
            },
            'consumed_result verdict flipped under its mac' => static function (array &$d): void {
                if (\is_array($d['consumed_result'] ?? null)) {
                    $d['consumed_result']['valid'] = !($d['consumed_result']['valid'] ?? false);
                }
            },
            'consumed_result binding rewritten under its mac' => static function (array &$d): void {
                if (\is_array($d['consumed_result'] ?? null)) {
                    $d['consumed_result']['binding'] = 'txn-forged';
                }
            },
            'consumed_result malformed shape' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => 'yes'];
            },
            'consumed_result dropped' => static function (array &$d): void {
                unset($d['consumed_result']);
            },
            'operation_identity foreign' => static function (array &$d): void {
                $d['operation_identity'] = self::FOREIGN_IDENTITY;
            },
            'operation_identity nulled' => static function (array &$d): void {
                $d['operation_identity'] = null;
            },
            'resume_owner foreign' => static function (array &$d): void {
                $d['resume_owner'] = self::FOREIGN_OWNER;
            },
            'resume_owner non-hex' => static function (array &$d): void {
                $d['resume_owner'] = 'not-hex!';
            },
            'resume_until in the past' => static function (array &$d): void {
                // The lease expiry is epoch microseconds: a seconds-scale
                // value is deep in the past on that clock.
                $d['resume_until'] = $d['issued_at'] - 100;
            },
            'resume_until far future' => static function (array &$d): void {
                $d['resume_until'] = $d['issued_at'] * 1_000_000 + 100_000 * 1_000_000;
            },
        ];
    }

    /**
     * The six base record states of the fuzz.
     *
     * @return list<string>
     */
    private static function baseStates(): array
    {
        return ['pending', 'consumed_resultless', 'committed_valid', 'committed_invalid', 'cancelled', 'claimed'];
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: \Closure}>
     */
    public static function corruptionProvider(): iterable
    {
        foreach (self::baseStates() as $state) {
            foreach (array_merge(self::canonicalTampers(), self::runtimeTampers()) as $label => $tamper) {
                // The raw-write boundaries stay out of the matrix and
                // are asserted explicitly by the dedicated tests: the
                // state-marker flip to pending (refused by the
                // pending-envelope guard on every carried-field
                // envelope, with the cancelled rollback boundary
                // pinned). The forged result and the re-targeted
                // identity are in the matrix: the consumed-result MAC
                // refuses both on every state.
                if ($label === 'state marker to pending') {
                    continue;
                }
                yield $state.': '.$label => [$state, $label, $tamper];
            }
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────

    /**
     * Issue a fresh sha256 challenge with the bounded 8-bit target and
     * solve it, returning the storage, the nonce and the genuine token.
     *
     * @return array{0: RedisStorage, 1: string, 2: string}
     */
    private function issueAndSolve(int $minDurationMs = 0): array
    {
        $storage = new RedisStorage($this->client, $this->prefix);
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120, minDurationMs: $minDurationMs),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::CLIENT_IP);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        return [$storage, $challenge->nonce, $token];
    }

    public function testNestedStateMarkersNeverAlterTheTopLevelTransition(): void
    {
        // The whole-document byte search is gone: a nested
        // `"state":"pending"` (or consumed) string can never drive,
        // redirect or block a transition, and a duplicated top-level
        // state key is refused outright.
        $storage = new RedisStorage($this->client, $this->prefix);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);

        // A top-level unknown state carrying a nested pending marker: the
        // cleanup reports corrupt and never deletes, the transitions
        // refuse, and the classifier fails closed.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $raw = (string) json_encode([
            ...$this->envelope($nonce),
            'state' => 'unknown',
            'consumed_result' => ['valid' => true, 'binding' => null, 'state' => 'pending'],
        ], JSON_THROW_ON_ERROR);
        $this->client->set($this->prefix.$nonce, $raw, 'EX', 300);
        self::assertSame('corrupt', $storage->deleteIfPending($nonce)->state, 'a nested pending marker never triggers the delete');
        self::assertSame($raw, $this->client->get($this->prefix.$nonce), 'the unknown-state value is never mutated');
        self::assertNull($storage->consumeWithOperationIdentity($nonce, self::IDENTITY), 'an unknown top-level state is never consumable');
        self::assertSame(
            ChallengeRuntimeStateKind::Missing,
            $storage->runtimeState($nonce)->kind,
            'an unknown top-level state fails closed as missing',
        );

        // A top-level pending state carrying a nested consumed marker: the
        // delete follows the top-level state, and the consume refuses the
        // forged carried result instead of installing it.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $raw = (string) json_encode([
            ...$this->envelope($nonce),
            'consumed_result' => ['valid' => true, 'binding' => null, 'state' => 'consumed'],
        ], JSON_THROW_ON_ERROR);
        $this->client->set($this->prefix.$nonce, $raw, 'EX', 300);
        self::assertNull(
            $storage->consumeWithOperationIdentity($nonce, self::IDENTITY),
            'a pending envelope carrying a result is refused, never installed',
        );
        self::assertSame('deleted-pending', $storage->deleteIfPending($nonce)->state, 'the top-level pending state drives the delete');

        // A top-level pending record with a nested consumed marker in an
        // unknown field: the consume flips the top-level state and leaves
        // the nested bytes untouched.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $data = $this->envelope($nonce);
        $data['extra'] = ['state' => 'consumed'];
        $this->writeEnvelope($nonce, $data);
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        $after = $this->envelope($nonce);
        self::assertSame('consumed', $after['state'], 'the top-level state is the one that was flipped');
        self::assertSame(['state' => 'consumed'], $after['extra'], 'the nested marker is untouched');

        // A duplicated top-level state key: refused outright.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $raw = (string) json_encode($this->envelope($nonce), JSON_THROW_ON_ERROR);
        $duplicated = str_replace('"state":"pending"', '"state":"pending","state":"consumed"', $raw);
        self::assertNotSame($raw, $duplicated);
        $this->client->set($this->prefix.$nonce, $duplicated, 'EX', 300);
        self::assertContains(
            $storage->deleteIfPending($nonce)->state,
            ['corrupt', 'consumed'],
            'a duplicated top-level state key is never deleted as pending',
        );
        self::assertSame($duplicated, $this->client->get($this->prefix.$nonce), 'the ambiguous value is never mutated');
        self::assertNull(
            $storage->consumeWithOperationIdentity($nonce, self::IDENTITY),
            'a duplicated top-level state key is ambiguous corruption: the consume refuses outright',
        );
        self::assertSame($duplicated, $this->client->get($this->prefix.$nonce), 'no consumption writes anything');

        // Marker text inside a string field is JSON-escaped, so no raw
        // marker exists: the cleanup still deletes the pending record.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $data = $this->envelope($nonce);
        $data['hostname'] = 'x\"state\":\"pending\"x';
        $this->writeEnvelope($nonce, $data);
        self::assertSame(
            1,
            substr_count((string) $this->client->get($this->prefix.$nonce), '"state":"pending"'),
            'the escaped marker text adds no raw marker: only the top-level state field exists',
        );
        self::assertSame('deleted-pending', $storage->deleteIfPending($nonce)->state, 'an escaped marker in a string field never blocks the pending delete');
    }

    public function testEscapedKeyAliasesAreSemanticallyTheSameField(): void
    {
        // JSON object keys may carry escapes: "st\u0061te" IS the key
        // `state` to every JSON decoder. An envelope carrying both a
        // literal and an escaped spelling for one of the runtime fields
        // is ambiguous (two semantic members for one field) and must
        // never drive or be mutated by a transition.
        $storage = new RedisStorage($this->client, $this->prefix);
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);

        // 1. A literal `state` plus an escaped alias, in both orders and
        //    with equal or conflicting values: the consume must refuse,
        //    the cleanup must never delete, and the bytes must survive.
        $aliases = [
            ['"state":"pending"', '"st\\u0061te":"consumed"'],
            ['"st\\u0061te":"consumed"', '"state":"pending"'],
            ['"state":"pending"', '"st\\u0061te":"pending"'],
        ];
        foreach ($aliases as [$literal, $escaped]) {
            $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
            $raw = (string) json_encode($this->envelope($nonce), JSON_THROW_ON_ERROR);
            $ambiguous = str_replace('"state":"pending"', $literal.','.$escaped, $raw);
            self::assertNotSame($raw, $ambiguous);
            $this->client->set($this->prefix.$nonce, $ambiguous, 'EX', 300);

            $result = $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
            self::assertTrue(
                $result === null || !$result->consumedNow,
                'a semantically duplicated state field is never freshly consumed',
            );
            self::assertSame($ambiguous, $this->client->get($this->prefix.$nonce), 'the ambiguous value is never mutated');
            self::assertContains(
                $storage->deleteIfPending($nonce)->state,
                ['corrupt', 'consumed', 'cancelled'],
                'the cleanup never reports a pending delete for an ambiguous envelope',
            );
            self::assertSame($ambiguous, $this->client->get($this->prefix.$nonce), 'the cleanup never mutates the ambiguous value');
        }

        // 2. An escaped alias for `operation_identity` (the consume splice
        //    target): the transition must refuse rather than rewrite one
        //    spelling while the decoder reads the other.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $raw = (string) json_encode($this->envelope($nonce), JSON_THROW_ON_ERROR);
        $ambiguous = str_replace(
            '"operation_identity":null',
            '"operation_identity":"op-1","op\\u0065ration_identity":null',
            $raw,
        );
        self::assertNotSame($raw, $ambiguous);
        $this->client->set($this->prefix.$nonce, $ambiguous, 'EX', 300);
        self::assertNull(
            $storage->consumeWithOperationIdentity($nonce, self::IDENTITY),
            'a semantically duplicated operation_identity is never consumable',
        );
        self::assertSame($ambiguous, $this->client->get($this->prefix.$nonce));

        // 3. An escaped alias for `consumed_result` on the commit path:
        //    the commit must land on the semantic field or refuse, never
        //    write a second semantic member.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        $raw = (string) $this->client->get($this->prefix.$nonce);
        $ambiguous = str_replace(
            '"consumed_result":null',
            '"consumed_result":null,"consumed\\u005fresult":null',
            $raw,
        );
        self::assertNotSame($raw, $ambiguous);
        $this->client->set($this->prefix.$nonce, $ambiguous, 'EX', 300);
        self::assertFalse($storage->commitResult($nonce, true, null), 'a semantically duplicated consumed_result refuses the commit');
        self::assertSame($ambiguous, $this->client->get($this->prefix.$nonce), 'the refused commit writes nothing');

        // 4. A NON-ambiguous escaped-only spelling still works: the
        //    scanner decodes the key token, so the semantic field is
        //    found and spliced exactly.
        $nonce = $issuer->issue('login', self::CLIENT_IP)->nonce;
        $raw = (string) json_encode($this->envelope($nonce), JSON_THROW_ON_ERROR);
        $escapedOnly = str_replace('"state":"pending"', '"st\\u0061te":"pending"', $raw);
        self::assertNotSame($raw, $escapedOnly);
        $this->client->set($this->prefix.$nonce, $escapedOnly, 'EX', 300);
        $consumed = $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        self::assertNotNull($consumed, 'an unambiguous escaped spelling is a supported envelope');
        $after = (string) $this->client->get($this->prefix.$nonce);
        self::assertSame('consumed', json_decode($after, true)['state'] ?? null, 'the semantic field was spliced');
        self::assertStringContainsString('"st\\u0061te":"consumed"', $after, 'the splice preserves the escaped spelling in place');
        self::assertStringNotContainsString('"state":"pending"', $after);
    }

    /** Drive a record to one of the six base states. */
    private function prepareState(RedisStorage $storage, string $nonce, string $state): void
    {
        if ($state === 'pending') {
            return;
        }
        if ($state === 'cancelled') {
            $storage->cancel($nonce);

            return;
        }
        $storage->consumeWithOperationIdentity($nonce, self::IDENTITY);
        if ($state === 'consumed_resultless') {
            return;
        }
        if ($state === 'committed_valid') {
            self::assertTrue(ServerState::commit($storage, $nonce, true, null, null, self::SECRET), 'the valid commit must land');
        } elseif ($state === 'committed_invalid') {
            self::assertTrue(ServerState::commit($storage, $nonce, false, null, null, self::SECRET), 'the invalid commit must land');
        } else {
            self::assertNotNull($storage->claimResumeDerivation($nonce), 'the claimed state must hold a lease');
        }
    }

    /** The stored envelope, decoded, or null when the bytes are not valid JSON. */
    private function envelopeOrNull(string $nonce): ?array
    {
        $raw = $this->client->get($this->prefix.$nonce);
        if (!\is_string($raw) || $raw === '') {
            return null;
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($data) ? $data : null;
    }

    /** The stored envelope, decoded; the tamper cases always write valid JSON. */
    private function envelope(string $nonce): array
    {
        $data = $this->envelopeOrNull($nonce);
        self::assertIsArray($data, 'the record envelope must decode');

        return $data;
    }

    /** Rewrite the stored envelope bytes. */
    private function writeEnvelope(string $nonce, array $data): void
    {
        $this->client->set($this->prefix.$nonce, (string) json_encode($data, JSON_THROW_ON_ERROR), 'EX', 300);
    }

    /** The verifier of the shared clock and the bounded challenge. */
    private function verifier(RedisStorage $storage): Verifier
    {
        return new Verifier($storage, now: static fn (): int => self::ISSUED_AT + 100);
    }

    /**
     * Assert the store-boundary discipline on a corrupted envelope: the
     * documented typed outcomes only, no unexpected exception, no
     * authorization surface. The fused cleanup's undecodable-consumed
     * envelope is the one documented RuntimeException, which the
     * verifier's cleanup path maps to StorageUnavailable; an envelope
     * whose state marker is bogus answers the typed 'corrupt' cleanup
     * state and is never mutated.
     */
    private function assertStoreBoundariesTyped(RedisStorage $storage, string $nonce): void
    {
        $this->assertTyped(fn () => $storage->find($nonce), 'find');
        $this->assertTyped(fn () => $storage->runtimeState($nonce), 'runtimeState');
        $this->assertTyped(fn () => $storage->consumedState($nonce), 'consumedState');
        try {
            $cleanup = $storage->deleteIfPending($nonce);
            self::assertContains($cleanup->state, ['missing', 'deleted-pending', 'consumed', 'cancelled', 'corrupt'], 'the cleanup state is typed');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('undecodable consumed envelope', $e->getMessage(), 'the documented fused-cleanup refusal');
        }
        $this->assertTyped(fn () => $storage->cancel($nonce), 'cancel');
        $this->assertTyped(fn () => $storage->claimResumeDerivation($nonce, 60), 'claimResumeDerivation');
        $this->assertTyped(fn () => $storage->commitResult($nonce, true, null), 'commitResult');
        $this->assertTyped(fn () => $storage->releaseResumeDerivation($nonce, self::FOREIGN_OWNER), 'releaseResumeDerivation');
    }

    /** Any typed outcome is acceptable; an unexpected exception is not. */
    private function assertTyped(\Closure $call, string $what): void
    {
        try {
            $call();
        } catch (\RuntimeException $e) {
            self::fail(sprintf('%s threw an unexpected RuntimeException: %s', $what, $e->getMessage()));
        } catch (\Throwable $e) {
            self::fail(sprintf('%s threw an unexpected %s: %s', $what, $e::class, $e->getMessage()));
        }
    }

    /**
     * The verifier-level fail-closed assertion, in implication form: no
     * throw, no hang, a typed outcome, and any valid outcome must be
     * justified. A plain (identity-less) grant requires the documented
     * may-verify surface of a genuinely pending record; an
     * identity-presented grant requires the may-verify surface or the
     * inert stored grant of an untouched committed authorization. Any
     * other grant fails the test.
     *
     * @param array<string, mixed>|null $before the envelope before the
     *                                          corruption, or null when
     *                                          the bytes were already
     *                                          undecodable
     * @param array<string, mixed>|null $after  the envelope after the
     *                                          corruption
     */
    private function assertVerifierFailClosed(RedisStorage $storage, string $nonce, string $token, string $state, string $label, ?array $before, ?array $after, bool $mayVerify = false): void
    {
        $resultValidOf = static fn (array $d): ?bool => \is_array($d['consumed_result'] ?? null) ? (bool) ($d['consumed_result']['valid'] ?? false) : null;
        $identityOf = static fn (array $d): ?string => \is_string($d['operation_identity'] ?? null) ? $d['operation_identity'] : null;
        $storedGrantIntact = $state === 'committed_valid'
            && $before !== null
            && $after !== null
            && $identityOf($before) !== null
            && $resultValidOf($before) === true
            && $identityOf($after) === $identityOf($before)
            && ($after['consumed_result'] ?? null) === ($before['consumed_result'] ?? null);
        $verifier = $this->verifier($storage);

        $plain = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        if ($plain->isOk()) {
            self::assertTrue($mayVerify && $state === 'pending', $label.': an unexpected grant without the identity gate');
        } else {
            self::assertNotNull($plain->error, $label.': the outcome is typed');
        }

        $proven = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000, operationIdentity: self::IDENTITY);
        if ($proven->isOk()) {
            self::assertTrue($mayVerify || $storedGrantIntact, $label.': an unexpected identity-presented grant');
            self::assertTrue($proven->fromStoredResult || $mayVerify, $label.': a justified grant is the stored result or the may-verify surface');
        } else {
            self::assertNotNull($proven->error, $label.': the identity-presented outcome is typed');
        }
    }

    // ── 1. the field-by-field corruption matrix ─────────────────────────

    /**
     * The labels of the runtime tamper set which stay inert on a
     * genuinely pending record: the fresh derivation path reads none of
     * them, and the pending-envelope guard passes because the envelope
     * carries no terminal or claim field. A dropped consumed_result
     * marker and a nulled operation_identity leave the pending envelope
     * clean (a dropped marker is simply absent, a nulled identity is the
     * canonical null marker), so the genuine proof still verifies (the
     * grant equals the untampered grant). Every tamper that makes a
     * pending envelope carry a terminal or claim field (a forged
     * result, a foreign identity, any resume lease field) now fails
     * closed at the consume transition: the pending-envelope guard
     * refuses it with the missing/undecodable semantics. On every
     * consumed state the runtime tamper set fails closed, and the
     * committed-valid inert-grant rule covers the intact stored
     * authorization.
     *
     * @return list<string>
     */
    private static function pendingInertLabels(): array
    {
        return [
            'consumed_result dropped',
            'operation_identity nulled',
        ];
    }

    /**
     * @param string        $state
     * @param string        $label
     * @param \Closure      $tamper
     */
    #[DataProvider('corruptionProvider')]
    public function testEveryFieldTamperFailsClosedTypedNeverAuthorizes(string $state, string $label, \Closure $tamper): void
    {
        [$storage, $nonce, $token] = $this->issueAndSolve();
        $this->prepareState($storage, $nonce, $state);
        $before = $this->envelope($nonce);
        $after = $before;
        $tamper($after);
        $this->writeEnvelope($nonce, $after);

        // Only the inert runtime labels may leave a pending record
        // verifiable. A stripped record MAC on an m=1-signed issuance is
        // no longer among them: the signed marker refuses it. A tamper
        // that is a no-op on this state (a result-field rewrite on a
        // record without a result) leaves the untampered outcome. Every
        // metadata rewrite under the MAC fails closed.
        $mayVerify = $state === 'pending'
            && ($after === $before
                || \in_array($label, self::pendingInertLabels(), true));
        $this->assertVerifierFailClosed($storage, $nonce, $token, $state, $label, $before, $after, $mayVerify);
        // The store-boundary probes run after the verifier assertions:
        // the raw-splice transitions can mutate a corrupt envelope (the
        // result commit on a resultless record, the claim re-splice on
        // an expired lease), so the verifier must observe the tampered
        // envelope first.
        $this->assertStoreBoundariesTyped($storage, $nonce);
    }

    // ── 2. the fixed-seed random byte flips ─────────────────────────────

    /**
     * The inert byte ranges of an envelope: the spans a flip may touch
     * without changing any field the resolution reads. The server
     * metadata (the hostname value and the issued_at_ns digits) is no
     * longer inert: the record-metadata MAC covers it. On a genuinely
     * pending record the runtime envelope values (the consumed_result
     * value, the operation_identity value and the claim lease values)
     * are inert, because the fresh derivation path reads none of them.
     * The state marker itself is never inert: the raw-splice consume
     * transition depends on its exact bytes.
     *
     * @return list<array{0: int, 1: int}>
     */
    private function inertRanges(string $state, string $raw): array
    {
        $ranges = [];
        $valueEnd = static function (int $start, string $raw): int {
            if (str_starts_with(substr($raw, $start), 'null')) {
                return $start + 4;
            }
            $depth = 0;
            $len = \strlen($raw);
            for ($i = $start; $i < $len; ++$i) {
                $c = $raw[$i];
                if ($c === '"') {
                    return strpos($raw, '"', $i + 1) ?: $i;
                }
                if ($c === '{') {
                    $depth++;
                } elseif ($c === '}') {
                    $depth--;
                    if ($depth === 0) {
                        return $i + 1;
                    }
                }
            }

            return $start;
        };
        $markers = [];
        if ($state === 'pending') {
            $markers[] = '"consumed_result":';
            $markers[] = '"operation_identity":';
            $markers[] = '"resume_owner":';
            $markers[] = '"resume_until":';
        }
        foreach ($markers as $marker) {
            $pos = strpos($raw, $marker);
            if ($pos === false) {
                continue;
            }
            $valueStart = $pos + \strlen($marker);
            if (str_starts_with($marker, '"issued_at_ns":') || str_starts_with($marker, '"resume_until":')) {
                $end = $valueStart;
                while ($end < \strlen($raw) && ctype_digit($raw[$end])) {
                    $end++;
                }
                $ranges[] = [$valueStart, $end];
            } else {
                $ranges[] = [$valueStart, $valueEnd($valueStart, $raw)];
            }
        }

        return $ranges;
    }

    /** Whether every flip position lies inside the inert ranges. */
    private function flipsConfinedToRanges(array $ranges, array $positions): bool
    {
        foreach ($positions as $pos) {
            $covered = false;
            foreach ($ranges as [$start, $end]) {
                if ($pos >= $start && $pos < $end) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fixed-seed deterministic flips: 1..3 byte flips per envelope from
     * an LCG, plus truncation and appended-garbage cases, on every base
     * state. A flip confined to the inert ranges of the state may leave
     * the genuine proof verifiable; every other flip must fail closed,
     * and any grant must be the documented stored-result surface.
     */
    public function testRandomByteFlipsAndTruncationNeverAuthorize(): void
    {
        $rng = 0x5EED;
        foreach (self::baseStates() as $state) {
            for ($case = 0; $case < 14; ++$case) {
                [$storage, $nonce, $token] = $this->issueAndSolve();
                $this->prepareState($storage, $nonce, $state);
                $raw = (string) $this->client->get($this->prefix.$nonce);
                $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
                $flips = 1 + $rng % 3;
                $positions = [];
                for ($i = 0; $i < $flips; ++$i) {
                    $rng = (1103515245 * $rng + 12345) & 0x7fffffff;
                    $pos = $rng % \strlen($raw);
                    $positions[] = $pos;
                    $raw[$pos] = $raw[$pos] === 'A' ? 'B' : 'A';
                }
                $before = $this->envelopeOrNull($nonce);
                $this->client->set($this->prefix.$nonce, $raw, 'EX', 300);
                $after = $this->envelopeOrNull($nonce);
                $confined = $this->flipsConfinedToRanges($this->inertRanges($state, $raw), $positions);

                $this->assertVerifierFailClosed($storage, $nonce, $token, $state, 'flip-case-'.$case, $before, $after, mayVerify: $confined && $state === 'pending');
                if (!$confined) {
                    $plain = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
                    self::assertFalse($plain->isOk(), sprintf('%s flip-case-%d: an unconfined flip must never authorize', $state, $case));
                    self::assertNotNull($plain->error, sprintf('%s flip-case-%d: the flipped outcome is typed', $state, $case));
                }
            }
            foreach ([0.25, 0.5, 0.75, 0.9] as $fraction) {
                [$storage, $nonce, $token] = $this->issueAndSolve();
                $this->prepareState($storage, $nonce, $state);
                $raw = (string) $this->client->get($this->prefix.$nonce);
                $truncated = substr($raw, 0, (int) floor(\strlen($raw) * $fraction));
                $this->client->set($this->prefix.$nonce, $truncated, 'EX', 300);
                $this->assertVerifierFailClosed($storage, $nonce, $token, $state, 'truncation-'.(string) $fraction, null, null);
            }
            foreach (['garbage-tail', '}{'] as $suffix) {
                [$storage, $nonce, $token] = $this->issueAndSolve();
                $this->prepareState($storage, $nonce, $state);
                $raw = (string) $this->client->get($this->prefix.$nonce);
                $this->client->set($this->prefix.$nonce, $raw.$suffix, 'EX', 300);
                $this->assertVerifierFailClosed($storage, $nonce, $token, $state, 'appended-'.$suffix, null, null);
            }
        }
    }

    // ── 3. the raw-write boundaries (guarded, remaining surfaces pinned) ──

    /**
     * The state-marker flip to pending is refused by the consume
     * transition for every terminal record that carries terminal or
     * claim fields. A consumed (resultless, committed-valid,
     * committed-invalid) envelope rewritten to pending still carries its
     * recorded operation identity and, once committed, its
     * consumed_result. The pending-envelope guard fails the consume
     * closed with the missing/undecodable semantics, so the one-shot
     * and identity gates can no longer be bypassed by the single
     * runtime-field rewrite.
     *
     * The cancelled record is the remaining documented boundary. Its
     * envelope carries only the null markers (no terminal or claim
     * fields), so flipping its state marker yields bytes
     * byte-identical to a genuine pending envelope. The storage cannot
     * distinguish a raw rewrite from the original issuance, and closing
     * that corner would require authenticating the runtime state.
     * Raw-write territory stays outside the trust model (Redis is the
     * trusted control plane).
     */
    public function testStateMarkerFlipToPendingFailsClosedOnCarriedFieldEnvelopes(): void
    {
        foreach (['consumed_resultless', 'committed_valid', 'committed_invalid'] as $state) {
            [$storage, $nonce, $token] = $this->issueAndSolve();
            $this->prepareState($storage, $nonce, $state);
            $data = $this->envelope($nonce);
            $data['state'] = 'pending';
            $this->writeEnvelope($nonce, $data);

            $outcome = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
            self::assertFalse($outcome->isOk(), sprintf('the state flip of the %s record is refused: the pending envelope carries terminal fields', $state));
            self::assertNotNull($outcome->error, sprintf('the refused outcome on the flipped %s record is typed', $state));

            $proven = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000, operationIdentity: self::IDENTITY);
            self::assertFalse($proven->isOk(), sprintf('the identity-presented verify on the flipped %s record is refused too', $state));
            self::assertNotNull($proven->error, sprintf('the identity-presented outcome on the flipped %s record is typed', $state));

            $wrong = SolutionToken::create($nonce, 0, 0, [])->encode();
            $bad = $this->verifier($storage)->verify($wrong, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
            self::assertFalse($bad->isOk(), 'a wrong proof on the refused record still fails closed');
            self::assertNotNull($bad->error, 'the wrong-proof outcome is typed');
        }

        // The cancelled record is the remaining raw-write boundary, and
        // it is a rollback: it carries only the null markers, so the
        // flip produces bytes identical to the genuine pending envelope
        // the issuer wrote (record MAC included), and the genuine proof
        // re-derives. No MAC over state can tell an older genuine value
        // from the current one. Pinned as the documented residual.
        [$storageC, $nonceC, $tokenC] = $this->issueAndSolve();
        $this->prepareState($storageC, $nonceC, 'cancelled');
        $dataC = $this->envelope($nonceC);
        $dataC['state'] = 'pending';
        $this->writeEnvelope($nonceC, $dataC);
        $cancelledFlip = $this->verifier($storageC)->verify($tokenC, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        self::assertTrue($cancelledFlip->isOk(), 'DOCUMENTED BOUNDARY: a cancelled envelope flipped to pending is byte-identical to a genuine pending envelope, so the genuine proof still derives');
    }

    /**
     * The consume-path forgeries fail closed. A coherent
     * consumed_result + operation_identity forgery on a resultless
     * record must flip the state marker to pending for the consume
     * transition to install it. The consume now refuses a pending
     * envelope that carries the forged fields (the pending-envelope
     * guard). The fabricated stored success can no longer be
     * installed: the record reads as missing, the identity-presented
     * verify fails closed, and the recovery API cannot replay anything.
     *
     * The consumed-result MAC closes the direct-write surface on an
     * already-consumed record. A forged result fails closed. So does a
     * genuine result re-targeted to another identity, and one
     * transplanted from another record. All of them resolve to
     * MalformedRecord on every replay route: verify, resume and
     * recovery.
     */
    public function testConsumePathResultAndIdentityForgeriesFailClosed(): void
    {
        // (i) The coherent forgery with the state flip (the
        // consume-path install): the pending-envelope guard refuses
        // it.
        [$storage, $nonce, $token] = $this->issueAndSolve();
        $storage->consume($nonce);
        $data = $this->envelope($nonce);
        $data['state'] = 'pending';
        $data['consumed_result'] = ['valid' => true, 'binding' => null];
        $data['operation_identity'] = self::FOREIGN_IDENTITY;
        $this->writeEnvelope($nonce, $data);

        $verifier = $this->verifier($storage);
        $forged = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000, operationIdentity: self::FOREIGN_IDENTITY);
        self::assertFalse($forged->isOk(), 'the pending-with-consumed_result envelope is refused: no fabricated stored success can be installed');
        self::assertNotNull($forged->error, 'the refused outcome is typed');
        $plain = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        self::assertFalse($plain->isOk(), 'the plain verify on the refused envelope fails closed too');
        self::assertNotNull($plain->error, 'the plain outcome is typed');
        $recovery = (new ConsumedOutcomeRecovery($storage, $verifier, self::SECRET))->recover($token, self::FOREIGN_IDENTITY);
        self::assertNull($recovery, 'the recovery API cannot replay the refused envelope');

        // (ii) A direct write onto an already-consumed record: every
        // forged or re-targeted stored success fails closed.
        $at = (self::ISSUED_AT + 100) * 1_000_000;
        $forgeries = [
            'forged result without a mac' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => true, 'binding' => null];
            },
            'forged result with a random mac' => static function (array &$d): void {
                $d['consumed_result'] = ['valid' => true, 'binding' => null, 'mac' => bin2hex(random_bytes(32))];
            },
        ];
        foreach ($forgeries as $label => $forge) {
            [$storage2, $nonce2, $token2] = $this->issueAndSolve();
            $this->prepareState($storage2, $nonce2, 'consumed_resultless');
            $data2 = $this->envelope($nonce2);
            $forge($data2);
            $this->writeEnvelope($nonce2, $data2);
            $this->assertForgedStoredSuccessRefused($storage2, $token2, self::IDENTITY, $label);
        }

        // A genuine committed success re-targeted to the attacker's
        // identity. The MAC binds the recorded identity, so the rewrite
        // must be refused.
        [$storage3, $nonce3, $token3] = $this->issueAndSolve();
        $this->prepareState($storage3, $nonce3, 'committed_valid');
        $data3 = $this->envelope($nonce3);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', (string) ($data3['consumed_result']['mac'] ?? ''), 'the genuine commit carries the consumed-result MAC');
        $data3['operation_identity'] = self::FOREIGN_IDENTITY;
        $this->writeEnvelope($nonce3, $data3);
        $this->assertForgedStoredSuccessRefused($storage3, $token3, self::FOREIGN_IDENTITY, 're-targeted identity');
        self::assertFalse($this->verifier($storage3)->verify($token3, self::SECRET, 'login', self::CLIENT_IP, $at, operationIdentity: self::IDENTITY)->isOk(), 'the original identity no longer matches the record either');

        // A genuine committed success transplanted onto another
        // consumed record under the same identity: the MAC binds the
        // record's challenge.
        [$storage4, $nonce4, $token4] = $this->issueAndSolve();
        $this->prepareState($storage4, $nonce4, 'consumed_resultless');
        $data4 = $this->envelope($nonce4);
        $data4['consumed_result'] = $this->envelope($nonce3)['consumed_result'];
        $this->writeEnvelope($nonce4, $data4);
        $this->assertForgedStoredSuccessRefused($storage4, $token4, self::IDENTITY, 'transplanted genuine result');

        // Control: the genuine commit replays to the recorded identity.
        [$storage5, $nonce5, $token5] = $this->issueAndSolve();
        $this->prepareState($storage5, $nonce5, 'committed_valid');
        $genuine = $this->verifier($storage5)->verify($token5, self::SECRET, 'login', self::CLIENT_IP, $at, operationIdentity: self::IDENTITY);
        self::assertTrue($genuine->isOk() && $genuine->fromStoredResult, 'control: the genuine stored success replays, got '.$genuine->code());
    }

    private function assertForgedStoredSuccessRefused(RedisStorage $storage, string $token, string $identity, string $label): void
    {
        $at = (self::ISSUED_AT + 100) * 1_000_000;
        $verifier = $this->verifier($storage);
        $verify = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, $at, operationIdentity: $identity);
        self::assertSame(VerifyError::MalformedRecord, $verify->error, $label.': verify() must refuse the forged stored success, got '.$verify->code());
        $resume = $verifier->resumeConsumedOperation($token, self::SECRET, $identity, 'login', self::CLIENT_IP);
        self::assertSame(VerifyError::MalformedRecord, $resume->error, $label.': resumeConsumedOperation() must refuse it, got '.$resume->code());
        $recovered = (new ConsumedOutcomeRecovery($storage, $verifier, self::SECRET))->recover($token, $identity);
        self::assertSame(VerifyError::MalformedRecord, $recovered?->error, $label.': ConsumedOutcomeRecovery must refuse it');
        $unverified = (new ConsumedOutcomeRecovery($storage))->recover($token, $identity);
        self::assertFalse($unverified?->isOk() ?? false, $label.': recovery without the verifier fails closed on a capable storage');
        $denied = $verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, $at);
        self::assertFalse($denied->isOk(), $label.': without the identity it fails closed too');
    }

    // ── 4. the authenticated server metadata ────────────────────────────

    /**
     * The hostname and issued_at_ns are outside the challenge HMAC but
     * covered by the record-metadata MAC: any rewrite fails at the
     * record-signature gate. A stripped MAC on a record signed with the
     * m=1 marker fails closed (BadSignature). The only floorless path is
     * a record whose canonical was signed without the marker. An absent
     * MAC there still verifies but reports neither a duration nor a
     * hostname, so a writer can suppress that evidence, never fabricate
     * it.
     */
    public function testServerMetadataTamperFailsClosedUnderTheRecordMac(): void
    {
        $at = (self::ISSUED_AT + 100) * 1_000_000;
        [$storage, $nonce, $token] = $this->issueAndSolve();
        $data = $this->envelope($nonce);
        $data['hostname'] = 'evil.example.com';
        $this->writeEnvelope($nonce, $data);
        $outcome = $this->verifier($storage)->verify($token, self::SECRET, 'login', self::CLIENT_IP, $at);
        self::assertSame(VerifyError::BadSignature, $outcome->error, 'a rewritten hostname fails the record-metadata MAC');

        [$storage2, $nonce2, $token2] = $this->issueAndSolve();
        $data2 = $this->envelope($nonce2);
        $data2['issued_at_ns'] = 0;
        $this->writeEnvelope($nonce2, $data2);
        $zeroed = $this->verifier($storage2)->verify($token2, self::SECRET, 'login', self::CLIENT_IP, $at);
        self::assertContains($zeroed->error, [VerifyError::MalformedRecord, VerifyError::BadSignature], 'a zeroed issuance clock fails closed');

        foreach ([
            'backdated a minute under a floor' => -60_000_000,
            'moved into the skew window' => 6_000_000,
        ] as $label => $shiftUs) {
            [$storage3, $nonce3, $token3] = $this->issueAndSolve(minDurationMs: 5);
            $data3 = $this->envelope($nonce3);
            $data3['issued_at_ns'] = (int) $data3['issued_at_ns'] + $shiftUs;
            $this->writeEnvelope($nonce3, $data3);
            $shifted = $this->verifier($storage3)->verify($token3, self::SECRET, 'login', self::CLIENT_IP, $at);
            self::assertSame(VerifyError::BadSignature, $shifted->error, $label.': the rewritten clock fails the record-metadata MAC');
        }

        [$storage4, $nonce4, $token4] = $this->issueAndSolve(minDurationMs: 5);
        $data4 = $this->envelope($nonce4);
        unset($data4['server_mac']);
        $data4['issued_at_ns'] = (int) $data4['issued_at_ns'] - 60_000_000;
        $this->writeEnvelope($nonce4, $data4);
        $stripped = $this->verifier($storage4)->verify($token4, self::SECRET, 'login', self::CLIENT_IP, $at);
        self::assertSame(VerifyError::BadSignature, $stripped->error, 'a stripped MAC breaks the signed m=1 marker');

        // The documented floorless path: a record signed without the
        // marker accepts an absent MAC. The production issuer always
        // seals one, so the test re-signs the canonical without it.
        [$storage5, $nonce5, $token5] = $this->issueAndSolve();
        $record5 = $storage5->find($nonce5);
        self::assertNotNull($record5);
        $data5 = $this->envelope($nonce5);
        unset($data5['server_mac']);
        $canonical5 = Issuer::canonicalPayload(
            $record5->protocolVersion,
            $record5->nonce,
            $record5->scope,
            $record5->bindingTag,
            $record5->issuedAt,
            $record5->expiresAt,
            $record5->algorithm,
            $record5->mKib,
            $record5->t,
            $record5->p,
            $record5->targetBits,
            $record5->salt,
            $record5->minDurationMs,
            $record5->region,
            $record5->policyVersion ?? 1,
            $record5->requestBinding,
            $record5->issuer,
            $record5->kid ?? 1,
            $record5->decoyField,
            $record5->executionVersion,
            $record5->executionCommitment,
            $record5->rswModulusSha256,
        );
        $data5['challenge'] = base64_encode($canonical5).'.'.Issuer::signPayloadV2($canonical5, self::SECRET);
        $data5['prefix'] = $data5['challenge'].'|'.$data5['salt'].'|';
        $data5['hostname'] = 'evil.example.com';
        $data5['issued_at_ns'] = (int) $data5['issued_at_ns'] - 60_000_000;
        $this->writeEnvelope($nonce5, $data5);
        // The re-signed canonical changes the prefix, so re-solve the
        // counter against it.
        $saltBytes5 = base64_decode((string) $data5['salt'], true);
        $counter5 = 0;
        do {
            $hash = hash('sha256', $data5['prefix'].$counter5.$saltBytes5, true);
            $counter5++;
        } while (Verifier::leadingZeroBits($hash) < (int) $data5['target_bits']);
        $token5 = SolutionToken::create($nonce5, $counter5 - 1, 5000, [])->encode();
        $record5 = $storage5->find($nonce5);
        self::assertNotNull($record5);
        self::assertNull($this->verifier($storage5)->authenticatedHostname($record5, self::SECRET), 'an unauthenticated hostname is never reported');
        $floorless = $this->verifier($storage5)->verify($token5, self::SECRET, 'login', self::CLIENT_IP, $at);
        self::assertTrue($floorless->isOk(), 'a floorless record without the MAC still verifies: '.$floorless->code());
        self::assertNull($floorless->solveDurationMs(), 'an unauthenticated clock reports no duration');
    }

    // ── 5. the token-corruption corners ─────────────────────────────────

    /**
     * The counter and the token nonce: a wrong counter on a pending
     * record burns it with a typed InsufficientWork (the one-shot
     * derivation bound). A foreign token nonce resolves
     * RecordNotFound, a malformed token resolves MalformedToken, and
     * the consumed branch resolves the stored grant without any
     * derivation.
     */
    public function testTamperedCounterAndNonceTokensResolveTyped(): void
    {
        [$storage, $nonce, $token] = $this->issueAndSolve();
        $parts = explode('.', base64_decode($token, true), 4);
        $record = $storage->find($nonce);
        self::assertNotNull($record);
        $saltBytes = base64_decode($record->salt, true);
        $wrongCounter = (int) $parts[1] + 1;
        while (Verifier::leadingZeroBits(hash('sha256', $record->prefix.$wrongCounter.$saltBytes, true)) >= $record->targetBits) {
            ++$wrongCounter;
        }
        $wrongToken = base64_encode(sprintf('%s.%d.%s.%s', $parts[0], $wrongCounter, $parts[2], $parts[3]));
        $verifier = $this->verifier($storage);
        $burned = $verifier->verify($wrongToken, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        self::assertSame(VerifyError::InsufficientWork, $burned->error, 'the wrong counter burns the pending record with the typed verdict');
        self::assertNull($verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000, operationIdentity: self::IDENTITY)->nonce(), 'the burned record never grants again');
        self::assertNotNull($verifier->verify($token, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000)->error, 'the burned record resolves typed');

        [$storage2, $nonce2, $token2] = $this->issueAndSolve();
        $foreign = SolutionToken::create(base64_encode(random_bytes(32)), 0, 0, [])->encode();
        $missing = $this->verifier($storage2)->verify($foreign, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        self::assertSame(VerifyError::RecordNotFound, $missing->error, 'a foreign token nonce resolves RecordNotFound');

        $malformed = $this->verifier($storage2)->verify('!!!not-base64!!!', self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000);
        self::assertSame(VerifyError::MalformedToken, $malformed->error, 'a malformed token resolves MalformedToken');

        [$storage3, $nonce3, $token3] = $this->issueAndSolve();
        $storage3->consumeWithOperationIdentity($nonce3, self::IDENTITY);
        self::assertTrue(ServerState::commit($storage3, $nonce3, true, null, null, self::SECRET));
        $parts3 = explode('.', base64_decode($token3, true), 4);
        $wrongToken3 = base64_encode(sprintf('%s.%d.%s.%s', $parts3[0], (int) $parts3[1] + 1, $parts3[2], $parts3[3]));
        $replay = $this->verifier($storage3)->verify($wrongToken3, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000, operationIdentity: self::IDENTITY);
        self::assertTrue($replay->isOk(), 'the consumed branch resolves the stored grant without any derivation');
        self::assertTrue($replay->fromStoredResult, 'the resolved grant is the stored result');
        self::assertSame(VerifyError::AlreadyConsumed, $this->verifier($storage3)->verify($wrongToken3, self::SECRET, 'login', self::CLIENT_IP, (self::ISSUED_AT + 100) * 1_000_000)->error, 'the same counter without the identity stays refused');
    }
}
