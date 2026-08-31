<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedAuthorityRefusalException;
use BelConsulting\KiwiCaptchaBundle\Security\Authority\PinnedPrimaryAuthorityGuard;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\RedisTestUrl;
use PHPUnit\Framework\TestCase;

/**
 * The real promotion simulation for the pinned-primary authority guard
 * (docs/ha-authority.md): a restarted primary on the same port (run_id
 * changes) and a pointed-at replica (role changes) are both refused
 * with the exact pinned-vs-observed message.
 *
 * The suite boots its own redis-server instances (never the shared
 * CI Redis service), following the core sentinel suite's convention:
 * gated on the shared real-Redis env (KC_REDIS_URL / `TEST_REDIS_URL`)
 * and the redis-server binary; skips cleanly otherwise. The restart
 * uses appendonly persistence so the pin key survives the restart — the
 * pin is what turns the run_id change into a refusal instead of a
 * silent re-pin.
 */
final class PinnedPrimaryAuthorityPromotionTest extends TestCase
{
    private const NS = 'pinned-promotion-test';

    /** @var array<int, resource> */
    private array $procs = [];

    private string $tmpDir = '';

    protected function tearDown(): void
    {
        foreach ($this->procs as $proc) {
            $status = proc_get_status($proc);
            if ($status !== false && $status['running']) {
                proc_terminate($proc, 9);
                proc_close($proc);
            }
        }
        $this->procs = [];
        if ($this->tmpDir !== '' && is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
        $this->tmpDir = '';
    }

    private function removeDir(string $dir): void
    {
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir.'/'.$item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function envRedisOrSkip(): void
    {
        if (!\class_exists(\Predis\Client::class)) {
            self::markTestSkipped('predis/predis is not installed');
        }
        if (RedisTestUrl::resolve() === null) {
            self::markTestSkipped('KC_REDIS_URL/TEST_REDIS_URL not set — the real-Redis suites run in the dedicated real-Redis CI lane');
        }
    }

    private function binaryOrSkip(): void
    {
        if (@shell_exec('command -v redis-server 2>/dev/null') === null) {
            self::markTestSkipped('redis-server not found on PATH — the promotion simulation needs a local redis-server build');
        }
    }

    private function freePort(): int
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $candidate = 20_000 + random_int(0, 25_000);
            $sock = @stream_socket_server('tcp://127.0.0.1:'.$candidate, $errno, $errstr);
            if ($sock !== false) {
                fclose($sock);

                return $candidate;
            }
        }
        self::markTestSkipped('no free local port available for the promotion simulation: '.$errstr);
    }

    /**
     * @param list<string> $extraArgs
     *
     * @return resource the proc handle
     */
    private function spawnRedisServer(array $extraArgs, string $name)
    {
        $log = $this->tmpDir.'/'.$name.'.log';
        $args = array_merge(['redis-server'], $extraArgs, ['--logfile', $log]);
        $proc = proc_open($args, [
            0 => ['pipe', 'r'],
            1 => ['file', $log, 'a'],
            2 => ['file', $log, 'a'],
        ], $pipes);
        if (!\is_resource($proc)) {
            self::markTestSkipped('failed to start '.$name.' (see '.$log.')');
        }
        fclose($pipes[0]);
        $this->procs[] = $proc;

        return $proc;
    }

    private function waitForPong(int $port, int $timeoutSecs): void
    {
        $deadline = microtime(true) + $timeoutSecs;
        while (microtime(true) < $deadline) {
            if (str_contains((string) @shell_exec('redis-cli -p '.$port.' ping 2>/dev/null'), 'PONG')) {
                return;
            }
            usleep(150_000);
        }
        self::fail('timed out waiting for redis-server on port '.$port.' to answer PONG');
    }

    private function client(int $port): \Predis\Client
    {
        return new \Predis\Client('tcp://127.0.0.1:'.$port, ['timeout' => 3.0]);
    }

    private function identityOf(\Predis\Client $client): array
    {
        $replication = $client->info('replication');
        $role = $replication['role'] ?? $replication['Replication']['role'] ?? '?';
        $runId = $replication['run_id'] ?? $replication['Replication']['run_id'] ?? null;
        if (!\is_string($runId) || $runId === '') {
            // Redis builds that omit run_id from the replication section
            // (the guard's own fallback): read it from the `INFO` server section.
            $server = $client->info('server');
            $runId = $server['run_id'] ?? $server['Server']['run_id'] ?? '?';
        }

        return ['role' => $role, 'run_id' => $runId];
    }

    /**
     * The documented stale-promotion detection: the primary is stopped
     * and a new server starts on the same port with a new run_id. The
     * pin (persisted through the restart via AOF) makes the identity
     * change a refusal naming the pinned vs observed identity.
     */
    public function testARestartedPrimaryWithANewRunIdIsRefused(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-pin-promo-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the promotion scratch directory');
        }
        $port = $this->freePort();
        $this->spawnRedisServer([
            '--port', (string) $port,
            '--dir', $this->tmpDir,
            '--appendonly', 'yes',
            '--save', '',
            '--appendfsync', 'always',
        ], 'primary');
        $this->waitForPong($port, 10);

        $clientA = $this->client($port);
        $guardA = new PinnedPrimaryAuthorityGuard($clientA, self::NS, 0, 'storage');
        $guardA->initializePin();
        $pinnedRunId = $this->identityOf($clientA)['run_id'];
        self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/', (string) $pinnedRunId, 'the pinned run_id is the 40-hex Redis run_id');
        self::assertSame(
            'master|'.$pinnedRunId,
            $clientA->get('{kiwi:'.self::NS.'}:authority:pin:storage'),
            'the initialize command pinned the serving identity to the per-authority namespace pin key',
        );

        // Stop the primary and start a new server on the same port with
        // the same AOF directory: the data (including the pin) survives,
        // the run_id is regenerated.
        $primary = $this->procs[0];
        proc_terminate($primary, 15);
        usleep(400_000);
        $this->spawnRedisServer([
            '--port', (string) $port,
            '--dir', $this->tmpDir,
            '--appendonly', 'yes',
            '--save', '',
        ], 'primary-restarted');
        $this->waitForPong($port, 10);

        // A fresh process/client observes the new authority.
        $clientB = $this->client($port);
        $observedRunId = $this->identityOf($clientB)['run_id'];
        self::assertNotSame($pinnedRunId, $observedRunId, 'a restarted Redis always regenerates its run_id');
        self::assertSame(
            'master|'.$pinnedRunId,
            $clientB->get('{kiwi:'.self::NS.'}:authority:pin:storage'),
            'the pin survives the restart through the append-only file',
        );
        $guardB = new PinnedPrimaryAuthorityGuard($clientB, self::NS, 0, 'storage');

        try {
            $guardB->assertServeEligible($clientB);
            self::fail('the guard must refuse a restarted primary with a new run_id');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage());
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage(), 'the refusal names the pinned run_id');
            self::assertStringContainsString('observed master|'.$observedRunId, $e->getMessage(), 'the refusal names the observed run_id');
            self::assertStringContainsString('Re-pin explicitly after a deliberate authority change', $e->getMessage(), 'the refusal names the re-pin remediation');
        }
    }

    /**
     * The pointed-at-replica detection: a guard bound to a replica
     * client observes role "slave" against the pinned master identity
     * and refuses. The replica has the pin (it replicated it), so the
     * refusal is the role change, exactly the stale-promotion shape.
     */
    public function testAPointedAtReplicaIsRefused(): void
    {
        $this->envRedisOrSkip();
        $this->binaryOrSkip();
        $this->tmpDir = sys_get_temp_dir().'/kiwicaptcha-pin-replica-'.bin2hex(random_bytes(6));
        if (!mkdir($this->tmpDir, 0o700, true) && !is_dir($this->tmpDir)) {
            self::markTestSkipped('cannot create the replica scratch directory');
        }
        $masterPort = $this->freePort();
        $replicaPort = $this->freePort();
        $this->spawnRedisServer(['--port', (string) $masterPort, '--dir', $this->tmpDir, '--save', ''], 'master');
        $this->spawnRedisServer([
            '--port', (string) $replicaPort,
            '--replicaof', '127.0.0.1', (string) $masterPort,
            '--dir', $this->tmpDir,
            '--save', '',
        ], 'replica');
        $this->waitForPong($masterPort, 10);
        $this->waitForPong($replicaPort, 10);

        $clientMaster = $this->client($masterPort);
        // Wait for the replica's initial sync (master_link_status:up)
        // before pinning, so the pin key exists on the replica too.
        $deadline = microtime(true) + 15;
        while (microtime(true) < $deadline) {
            if (str_contains((string) @shell_exec('redis-cli -p '.$replicaPort.' info replication 2>/dev/null'), 'master_link_status:up')) {
                break;
            }
            usleep(200_000);
        }
        $acked = 0;
        for ($attempt = 0; $attempt < 4 && $acked !== 1; $attempt++) {
            $acked = $clientMaster->executeRaw(['WAIT', '1', '4000']);
        }
        if ($acked !== 1) {
            self::markTestSkipped('the replica never acknowledged a write (WAIT returned '.var_export($acked, true).') — replication is unavailable on this build');
        }
        $guardMaster = new PinnedPrimaryAuthorityGuard($clientMaster, self::NS, 0, 'storage');
        $guardMaster->initializePin();
        $pinnedRunId = $this->identityOf($clientMaster)['run_id'];
        $acked = $clientMaster->executeRaw(['WAIT', '1', '5000']);
        self::assertSame(1, $acked, 'the pin write reached the replica, so the replica carries the pin');

        $clientReplica = $this->client($replicaPort);
        self::assertSame(
            'master|'.$pinnedRunId,
            $clientReplica->get('{kiwi:'.self::NS.'}:authority:pin:storage'),
            'the replica replicated the pin key',
        );
        $observedRole = $this->identityOf($clientReplica)['role'];
        self::assertSame('slave', $observedRole, 'the pointed-at server is a replica (role slave)');

        $guardReplica = new PinnedPrimaryAuthorityGuard($clientReplica, self::NS, 0, 'storage');
        try {
            $guardReplica->assertServeEligible($clientReplica);
            self::fail('the guard must refuse a pointed-at replica');
        } catch (PinnedAuthorityRefusalException $e) {
            self::assertStringContainsString('the serving authority changed', $e->getMessage());
            self::assertStringContainsString('pinned master|'.$pinnedRunId, $e->getMessage());
            self::assertStringContainsString('observed slave|', $e->getMessage(), 'the refusal names the role change (slave against the pinned master)');
            self::assertStringNotContainsString('observed slave|'.$pinnedRunId, $e->getMessage(), 'the observed identity is the replica itself (its own run_id), not the pinned master');
        }
    }
}
