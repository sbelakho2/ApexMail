<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Authentication of the server-written state that the challenge
 * signature does not cover.
 *
 * Two values live in storage next to the signed record but are not
 * part of the signed canonical payload:
 *
 * - the record metadata: `issued_at_ns`, the high-resolution issuance
 *   clock behind the minimum-duration floor, and `hostname`, the
 *   Siteverify hostname.
 * - the committed consumed result, `valid` and `binding`, that a retry
 *   of the same logical operation replays without re-deriving the
 *   proof.
 *
 * Without a MAC, a storage writer who does not hold the master secret
 * could backdate the issuance clock, bypassing the floor and inflating
 * the measured duration. The writer could also forge `valid=true` on a
 * consumed record and replay it under the recorded operation identity.
 * Both values are therefore MACed with the dedicated server-state
 * purpose key, see {@see DerivedKeys::serverStateKey()}, HKDF info
 * `kiwi/v2/server-state`. That key derives from the record's kid secret
 * and the deployment tenant exactly like the challenge-signing key.
 *
 * The MAC input binds the full challenge string (base64 canonical
 * payload plus its signature), so a MAC can never be transplanted to
 * another record. Every variable-length field is length-prefixed and
 * every optional field carries a presence tag, so no two distinct
 * inputs share an encoding. The byte layout is shared verbatim with the
 * Rust crate (`challenge::record_meta_mac` / `consumed_result_mac`);
 * the reference vectors in `protocol/server-state-v1/fixtures.json`
 * pin it.
 *
 * What a MAC cannot close alone: a storage writer could re-store an
 * earlier, genuinely MACed envelope. The storage layer's monotonic
 * consumed flag closes that rewind, so a one-shot token stays one-shot.
 * The only remaining physical limit is a full restore of the entire
 * store to an earlier media snapshot.
 */
final class ServerStateMac
{
    public const RECORD_META_DOMAIN = 'kiwi/record-meta/v1';

    public const CONSUMED_RESULT_DOMAIN = 'kiwi/consumed-result/v1';

    /** The wire shape of every server-state MAC: 64 lowercase hex. */
    public const PATTERN = '/^[0-9a-f]{64}$/D';

    private function __construct()
    {
    }

    /** The server-state key for a kid secret and the deployment tenant. */
    public static function key(string $secret, ?string $tenantId = null): string
    {
        return DerivedKeys::fromMaster($secret, $tenantId)->serverStateKey();
    }

    /**
     * The record-metadata MAC (`server_mac`) over the challenge string,
     * the issuance clock and the hostname.
     */
    public static function recordMeta(string $key, string $challenge, int $issuedAtNs, ?string $hostname): string
    {
        return hash_hmac('sha256', self::recordMetaInput($challenge, $issuedAtNs, $hostname), $key);
    }

    /**
     * The consumed-result MAC (`consumed_result.mac`) over the challenge
     * string, the verdict, the stored binding and the operation identity
     * recorded with the consume transition.
     */
    public static function consumedResult(string $key, string $challenge, bool $valid, ?string $binding, ?string $operationIdentity): string
    {
        return hash_hmac('sha256', self::consumedResultInput($challenge, $valid, $binding, $operationIdentity), $key);
    }

    /** True when the record carries a well-formed, matching `server_mac`. */
    public static function verifyRecordMeta(string $key, ChallengeRecord $record): bool
    {
        return $record->serverMac !== null
            && hash_equals(self::recordMeta($key, $record->challenge, $record->issuedAtNs, $record->hostname), $record->serverMac);
    }

    /**
     * True when the consumed record's committed result carries a
     * well-formed, matching MAC for its own record and operation
     * identity.
     */
    public static function verifyConsumedResult(string $key, ConsumedRecord $consumed): bool
    {
        $result = $consumed->consumedResult;

        return $result !== null
            && $result->mac !== null
            && hash_equals(
                self::consumedResult($key, $consumed->record->challenge, $result->valid, $result->binding, $consumed->operationIdentity),
                $result->mac,
            );
    }

    /** @internal the exact MAC input bytes (pinned by the shared vectors) */
    public static function recordMetaInput(string $challenge, int $issuedAtNs, ?string $hostname): string
    {
        return self::RECORD_META_DOMAIN."\n"
            .self::lp($challenge)."\n"
            .$issuedAtNs."\n"
            .self::opt($hostname);
    }

    /** @internal the exact MAC input bytes (pinned by the shared vectors) */
    public static function consumedResultInput(string $challenge, bool $valid, ?string $binding, ?string $operationIdentity): string
    {
        return self::CONSUMED_RESULT_DOMAIN."\n"
            .self::lp($challenge)."\n"
            .($valid ? '1' : '0')."\n"
            .self::opt($binding)."\n"
            .self::opt($operationIdentity);
    }

    private static function lp(string $value): string
    {
        return \strlen($value).':'.$value;
    }

    private static function opt(?string $value): string
    {
        return $value === null ? '0' : '1:'.self::lp($value);
    }
}
