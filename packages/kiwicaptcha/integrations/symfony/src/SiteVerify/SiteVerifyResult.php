<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\SiteVerify;

/**
 * The one canonical provider-response validator: the exact schema a
 * conforming finalize writes and a cached read accepts. A completed
 * idempotency record's result is authorization-bearing cached state.
 * It is validated with the same authority at write time (finalize
 * refuses a non-canonical shape) and at read time (a corrupted
 * persisted result throws the typed corrupt exception, never becomes
 * an authorization), in both the Redis and the array store.
 *
 * The shapes:
 * - success: success=true with challenge_ts (ISO string or null),
 *   hostname (string or null), action (string or null), cdata (string
 *   or null); the error-codes key is absent.
 * - failure: success=false with challenge_ts=null, hostname=null and
 *   error-codes: exactly one known provider error code. The action/
 *   cdata keys are absent.
 * - any other key, type deviation or combination is corrupt.
 */
final class SiteVerifyResult
{
    /** The complete known provider error-code vocabulary the controller can canonicalize. */
    private const ERROR_CODES = [
        'missing-input-secret',
        'invalid-input-secret',
        'missing-input-response',
        'invalid-input-response',
        'bad-request',
        'timeout-or-duplicate',
        'internal-error',
        'siteverify-not-configured',
    ];

    /**
     * @throws SiteVerifyIdempotencyCorruptException when the shape is not
     *                                           the canonical success or
     *                                           failure response
     */
    public static function validate(array $result): void
    {
        $keys = array_keys($result);
        sort($keys);
        if (\array_key_exists('success', $result) && $result['success'] === true) {
            // The controller's canonical success shape: the six-key
            // full form (action/cdata bound) or the three-key minimal
            // form; error-codes, when present, is exactly the empty
            // array (a success never carries a code).
            $expected = ['action', 'cdata', 'challenge_ts', 'error-codes', 'hostname', 'success'];
            $minimal = ['challenge_ts', 'hostname', 'success'];
            if ($keys !== $expected && $keys !== $minimal) {
                self::corrupt('a success result carries exactly success, challenge_ts, hostname (and action/cdata when bound)');
            }
            if (\array_key_exists('error-codes', $result) && $result['error-codes'] !== []) {
                self::corrupt('a success result carries no error code');
            }
            self::nullableString($result, 'challenge_ts');
            self::nullableString($result, 'hostname');
            self::nullableString($result, 'action');
            self::nullableString($result, 'cdata');

            return;
        }
        if (\array_key_exists('success', $result) && $result['success'] === false) {
            if ($keys !== ['challenge_ts', 'error-codes', 'hostname', 'success']) {
                self::corrupt('a failure result carries exactly success, challenge_ts, hostname and error-codes');
            }
            if ($result['challenge_ts'] !== null || $result['hostname'] !== null) {
                self::corrupt('a failure result carries null challenge_ts and hostname');
            }
            $codes = $result['error-codes'];
            // error-codes is a canonical list of exactly one known code:
            // array_is_list refuses an associative/object shape a decoded
            // JSON document could carry.
            if (!\is_array($codes) || !array_is_list($codes) || \count($codes) !== 1 || !\is_string($codes[0]) || !\in_array($codes[0], self::ERROR_CODES, true)) {
                self::corrupt('a failure result carries exactly one known provider error code');
            }

            return;
        }
        self::corrupt('the result carries a literal boolean success');
    }

    private static function nullableString(array $result, string $key): void
    {
        // A missing optional key (action/cdata) is absent, never null.
        if (\array_key_exists($key, $result) && !\is_string($result[$key]) && $result[$key] !== null) {
            self::corrupt(sprintf('the %s field is a string or null', $key));
        }
    }

    private static function corrupt(string $why): never
    {
        throw new SiteVerifyIdempotencyCorruptException('the canonical siteverify result is corrupt: '.$why);
    }
}
