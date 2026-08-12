<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Network\NetworkFlags;
use KiwiCaptcha\Risk\ResourcePressure;
use KiwiCaptcha\Risk\RiskContext;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\RiskObservation;
use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use Predis\Client;
use PHPUnit\Framework\TestCase;

/**
 * Redis privacy guarantees (real Redis, skipped unless RISK_REDIS_URL):
 * issuing observations derived from a single IP, a User-Agent string, a
 * principal id and an email must leave NO raw personal data in Redis —
 * keys, hash values and metadata contain only HMAC pseudonyms and numeric
 * counters.
 *
 * The scan pattern is namespace-scoped ({kiwi:<ns>}:*): the contract's
 * hash-tagged keys do not start with a bare `kiwi:` prefix, so the literal
 * MATCH 'kiwi:*' glob matches nothing; the namespace-scoped pattern is the
 * strict equivalent and stays isolated from parallel test processes.
 *
 * Session/principal state IS persisted when the observation carries them
 * (has_session/has_principal = 1) — under their keyed HMAC pseudonyms, so
 * the raw principal id / UA / email exist nowhere in any form.
 */
final class PrivacyScanTest extends TestCase
{
    private const T0 = 1_700_000_000_000; // fixed ms clock: no decay between same-ts events

    private const IP = '203.0.113.77';
    private const UA = 'Mozilla/5.0 (X11; Linux x86_64) KiwiBrowser/125.0';
    private const PRINCIPAL = 'customer_2847812';
    private const EMAIL = 'customer_2847812@example.com';

    private ?Client $client = null;

    protected function setUp(): void
    {
        $url = getenv('RISK_REDIS_URL');
        if (!is_string($url) || $url === '') {
            self::markTestSkipped('RISK_REDIS_URL not set; start redis with: docker run -d -p 6399:6379 redis:7-alpine');
        }
        $this->client = RedisRiskStateStore::createClient($url);
    }

    public function testNoRawPiiAnywhereInRedis(): void
    {
        $store = new RedisRiskStateStore($this->client, namespace: 'privacy' . bin2hex(random_bytes(4)));
        $ns = $store->namespace();

        // Real observations derived from the raw values under test.
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster(str_repeat("\x42", 32)));
        $nowSecs = intdiv(self::T0, 1000);
        $srcEpoch = intdiv($nowSecs, 900);
        $netEpoch = intdiv($nowSecs, 900);
        $ctx = new RiskContext(
            scope: 1,
            sourceIp: self::IP,
            sessionId: null,
            principalId: null,
            event: RiskEventKind::PreIssue,
            networkFlags: new NetworkFlags(),
            resources: new ResourcePressure(1000, 1000, 1000),
        );
        $sourceId = $factory->sourceIdForEpoch($ctx, $srcEpoch);
        $sourceIdPrev = $factory->sourceIdForEpoch($ctx, $srcEpoch - 1);
        $sourceIdNext = $factory->sourceIdForEpoch($ctx, $srcEpoch + 1);
        $subnetId = $factory->subnetIdForEpoch($ctx, $netEpoch);
        $subnetIdPrev = $factory->subnetIdForEpoch($ctx, $netEpoch - 1);
        $subnetIdNext = $factory->subnetIdForEpoch($ctx, $netEpoch + 1);
        $principalId = $factory->principalId(self::PRINCIPAL);
        $sessionUa = $factory->sessionId(self::UA);
        $sessionEmail = $factory->sessionId(self::EMAIL);

        $observations = [
            new RiskObservation(event: RiskEventKind::PreIssue, scope: 1, sourceEpoch: $srcEpoch, sourceIdPrev: $sourceIdPrev, sourceId: $sourceId, sourceIdNext: $sourceIdNext, subnetEpoch: $netEpoch, subnetIdPrev: $subnetIdPrev, subnetId: $subnetId, subnetIdNext: $subnetIdNext, sessionId: $sessionUa, principalId: $principalId, eventId: RiskObservation::newEventId(), networkRisk: 0, nowMs: self::T0),
            new RiskObservation(event: RiskEventKind::ProtectedActionFailure, scope: 1, sourceEpoch: $srcEpoch, sourceIdPrev: $sourceIdPrev, sourceId: $sourceId, sourceIdNext: $sourceIdNext, subnetEpoch: $netEpoch, subnetIdPrev: $subnetIdPrev, subnetId: $subnetId, subnetIdNext: $subnetIdNext, sessionId: $sessionEmail, principalId: $principalId, eventId: RiskObservation::newEventId(), networkRisk: 0, nowMs: self::T0),
            new RiskObservation(event: RiskEventKind::ConfirmedAbuse, scope: 1, sourceEpoch: $srcEpoch, sourceIdPrev: $sourceIdPrev, sourceId: $sourceId, sourceIdNext: $sourceIdNext, subnetEpoch: $netEpoch, subnetIdPrev: $subnetIdPrev, subnetId: $subnetId, subnetIdNext: $subnetIdNext, sessionId: $sessionUa, principalId: $principalId, eventId: RiskObservation::newEventId(), networkRisk: 0, nowMs: self::T0),
        ];
        foreach ($observations as $observation) {
            $store->observe($observation);
        }

        // SCAN the namespace: every key, then every hash field/value.
        $keys = [];
        $cursor = '0';
        do {
            $result = $this->client->scan($cursor, ['MATCH' => "{kiwi:{$ns}}:*", 'COUNT' => 100]);
            $cursor = (string) $result[0];
            foreach ($result[1] as $key) {
                $keys[] = (string) $key;
            }
        } while ($cursor !== '0');

        self::assertNotEmpty($keys, 'scan must find the issued keys');
        $allKeys = implode("\n", $keys);

        // The source pseudonym is what the scan must find — proof the scan
        // actually saw this namespace's state.
        self::assertStringContainsString($sourceId, $allKeys);
        // Session/principal state is persisted under its HMAC pseudonym:
        // the principal pseudonym (NOT the raw principal id) is present.
        self::assertStringContainsString($principalId, $allKeys);
        self::assertStringNotContainsString(self::PRINCIPAL, $allKeys);

        $blob = $allKeys;
        foreach ($keys as $key) {
            $type = $this->client->type($key);
            if ($type === 'hash') {
                foreach ($this->client->hgetall($key) as $field => $value) {
                    $blob .= "\n" . $field . '=' . $value;
                }
            } elseif ($type === 'string') {
                $blob .= "\n" . $this->client->get($key);
            }
        }

        foreach ([self::IP, self::UA, self::PRINCIPAL, self::EMAIL] as $raw) {
            self::assertStringNotContainsString(
                $raw,
                $blob,
                sprintf('raw "%s" leaked into Redis keys/values/metadata', $raw)
            );
        }
    }
}
