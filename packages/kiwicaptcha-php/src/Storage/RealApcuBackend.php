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
 * Construction also refuses the cli SAPI unless both of two distinct
 * inputs hold. `apc.enable_cli=1` is the precondition: APCu stays
 * inert in a cli process without it, so no segment exists to refuse.
 * It is a switch, not an acknowledgement, and granting it alone would
 * let every RoadRunner worker construct against its own private
 * segment, where (N-1)/N of the solves land in a foreign segment and
 * fail at random. The acknowledgement is the constructor flag
 * `allowPrivateCliSegment: true` (the Symfony bundle exposes it as
 * `storage.apcu.single_process_cli`), and it is valid only for one
 * long-lived process: a Swoole server that initialised APCu before
 * fork. RoadRunner never qualifies. CLI hosts without the pair select
 * the Redis or SQLite store instead.
 *
 * The atomicity promises are APCu's own: within one SAPI's segment the
 * region is shared memory guarded by APCu's internal lock,
 * `apcu_add()` is the atomic create-if-absent the storage's transition
 * lock builds on, and a TTL-expired entry reads as absent on fetch.
 */
final class RealApcuBackend implements ApcuBackendInterface
{
    /**
     * @param \Closure|null $sapiEnvironment the simulated SAPI
     *                                       environment for the cli
     *                                       detection, an array of the
     *                                       SAPI name and the raw
     *                                       apc.enable_cli ini value;
     *                                       defaults to reading the
     *                                       real process. The seam the
     *                                       constructor of
     *                                       {@see ApcuStorage} forwards
     *                                       its own probed values
     *                                       through, so both layers
     *                                       decide on one environment.
     * @param bool          $allowPrivateCliSegment the single-process
     *                                              acknowledgement: under
     *                                              the cli SAPI the
     *                                              backend constructs
     *                                              only when this is
     *                                              true AND the
     *                                              apc.enable_cli ini is
     *                                              on (the bundle knob
     *                                              is
     *                                              storage.apcu.single_process_cli).
     *
     * @throws ApcuStorageException when the APCu extension is not
     *                              loaded or is disabled for this
     *                              process, or the process runs under
     *                              the cli SAPI without the
     *                              apc.enable_cli ini AND the
     *                              allowPrivateCliSegment flag
     */
    public function __construct(?\Closure $sapiEnvironment = null, bool $allowPrivateCliSegment = false)
    {
        [$sapi, $enableCliRaw] = $sapiEnvironment !== null
            ? $sapiEnvironment()
            : [\PHP_SAPI, \ini_get('apc.enable_cli')];
        if (self::cliConstructionRefused($sapi, self::apcEnableCliIni($enableCliRaw), $allowPrivateCliSegment)) {
            throw new ApcuStorageException(
                'ApcuStorage refuses the cli SAPI without the single-process acknowledgement: a CLI process '
                . '(RoadRunner worker, queue consumer, command) owns a private APCu segment invisible to the '
                . 'web tier that serves traffic, so a challenge stored here can never be verified by the web '
                . 'tier (or the reverse). apc.enable_cli=1 is only the precondition that gives a CLI process a '
                . 'segment at all, so it is required in php.ini AND the construction needs the explicit '
                . 'allowPrivateCliSegment: true flag (bundle option storage.apcu.single_process_cli), valid '
                . 'only for one long-lived process (Swoole with APCu initialised before fork; RoadRunner never '
                . 'qualifies). Otherwise select the Redis/SQLite store for CLI hosts.'
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
     * The cli-refusal decision, pure: the cli SAPI constructs only when
     * the apc.enable_cli precondition AND the allowPrivateCliSegment
     * acknowledgement hold together. Every other SAPI constructs, and
     * the ini alone (the precondition without the acknowledgement)
     * refuses exactly like the flag alone without the ini.
     */
    public static function cliConstructionRefused(string $sapi, bool $apcEnableCliIni, bool $allowPrivateCliSegment = false): bool
    {
        if ($sapi !== 'cli') {
            return false;
        }

        return !($apcEnableCliIni && $allowPrivateCliSegment);
    }

    /**
     * The apc.enable_cli ini read, parsed as a boolean the way PHP
     * stores ini values: on is 1, true, on or yes (case-insensitive);
     * everything else, including an unset entry (the extension is not
     * loaded, so ini_get() answers false), is off.
     *
     * @param string|false $raw the ini_get('apc.enable_cli') answer
     */
    public static function apcEnableCliIni(string|false $raw): bool
    {
        if ($raw === false) {
            return false;
        }

        return \in_array(strtolower(trim($raw)), ['1', 'true', 'on', 'yes'], true);
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
