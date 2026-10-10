<?php

declare(strict_types=1);

namespace KiwiCaptcha\Storage;

/**
 * The production {@see ApcuBackendInterface} over the real APCu
 * extension: `apcu_fetch()`, `apcu_store()`, `apcu_add()` and
 * `apcu_delete()` with their TTL arguments.
 *
 * Construction fails closed with one actionable error when the
 * extension is missing or disabled for the process. This replaces a
 * fatal error on an undefined function later: the web server usually loads
 * APCu while a cli process does not, so the message names the
 * `apc.enable_cli` remedy for that case.
 *
 * Construction also refuses the cli SAPI outside test runners. A CLI
 * process (RoadRunner worker, queue consumer, command) owns a private
 * APCu segment invisible to the PHP-FPM workers that serve traffic.
 * Records stored from CLI can never be verified by the web tier and
 * vice versa. The one-host shared-segment contract of this adapter
 * only holds inside one web SAPI. Tests (phpunit) construct it for the
 * real-extension leg; production CLI hosts select the Redis or SQLite
 * store instead.
 *
 * The atomicity promises are APCu's own: within one SAPI's segment the
 * region is shared memory guarded by APCu's internal lock,
 * `apcu_add()` is the atomic create-if-absent the storage's transition
 * lock builds on, and a TTL-expired entry reads as absent on fetch.
 */
final class RealApcuBackend implements ApcuBackendInterface
{
    /**
     * @throws ApcuStorageException when the APCu extension is not
     *                              loaded or is disabled for this
     *                              process, or the process runs under
     *                              the cli SAPI outside a test runner
     */
    public function __construct()
    {
        if (self::cliConstructionRefused(\PHP_SAPI, self::underTestRunner())) {
            throw new ApcuStorageException(
                'ApcuStorage refuses the cli SAPI: a CLI process (RoadRunner worker, queue '
                . 'consumer, command) owns a private APCu segment invisible to the web tier '
                . 'that serves traffic. Serve verification from a web SAPI (php-fpm) or '
                . 'select the Redis/SQLite store for CLI hosts.'
            );
        }
        if (!\function_exists('apcu_store')) {
            throw new ApcuStorageException(
                'the APCu extension is not installed; install or enable ext-apcu to use ApcuStorage'
            );
        }
        if (\function_exists('apcu_enabled') && !apcu_enabled()) {
            throw new ApcuStorageException(
                'APCu is disabled for this process; enable the extension (for cli runs also set apc.enable_cli=1) to use ApcuStorage'
            );
        }
    }

    /**
     * The cli-refusal decision, pure: the cli SAPI refuses outside a
     * test runner, every other SAPI constructs.
     */
    public static function cliConstructionRefused(string $sapi, bool $underTestRunner): bool
    {
        return $sapi === 'cli' && !$underTestRunner;
    }

    /**
     * Whether a test runner owns the process (phpunit loads its
     * TestCase before constructing storage fixtures). Outside a test
     * runner the cli SAPI is refused.
     */
    private static function underTestRunner(): bool
    {
        return \class_exists(\PHPUnit\Framework\TestCase::class, false);
    }

    public function fetch(string $key): ApcuFetchOutcome
    {
        $success = false;
        $value = apcu_fetch($key, $success);
        if ($success !== true) {
            return ApcuFetchOutcome::notFound();
        }

        return ApcuFetchOutcome::found($value);
    }

    public function store(string $key, mixed $value, int $ttlSecs): bool
    {
        return apcu_store($key, $value, $ttlSecs);
    }

    public function add(string $key, mixed $value, int $ttlSecs): bool
    {
        return apcu_add($key, $value, $ttlSecs);
    }

    public function delete(string $key): bool
    {
        return apcu_delete($key);
    }
}
