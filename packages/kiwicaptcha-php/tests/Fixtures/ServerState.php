<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\ConsumedResult;
use KiwiCaptcha\ServerStateMac;

/**
 * The test-side counterpart of the verifier's authenticated server-state
 * writes. Tests that stage a genuine committed result (the verifier's
 * own commit, crashed before the response) or a hand-built record with
 * a duration floor must carry the server-state MAC the verifier would
 * have written. A plain commitResult() of valid=true is exactly what a
 * storage writer without the master secret can produce, and is refused
 * as forged.
 */
final class ServerState
{
    /**
     * Commit a result the way the verifier does: MAC'd over the record's
     * challenge, the verdict, the binding and the operation identity the
     * consume transition recorded. With $owner the claim-fenced variant.
     */
    public static function commit(
        object $storage,
        string $nonce,
        bool $valid,
        ?string $binding,
        ?string $owner = null,
        string $secret = Vectors::SECRET,
        ?string $tenantId = null,
    ): bool {
        $consumed = $storage->consumedState($nonce);
        if ($consumed === null) {
            // Nothing consumed to authenticate against: the plain commit
            // keeps the storage's own refusal semantics.
            return $owner === null
                ? $storage->commitResult($nonce, $valid, $binding)
                : $storage->commitResultResume($nonce, $valid, $binding, $owner);
        }
        $result = new ConsumedResult(
            $valid,
            $binding,
            ServerStateMac::consumedResult(ServerStateMac::key($secret, $tenantId), $consumed->record->challenge, $valid, $binding, $consumed->operationIdentity),
        );

        return $owner === null
            ? $storage->commitAuthenticatedResult($nonce, $result)
            : $storage->commitAuthenticatedResultResume($nonce, $result, $owner);
    }

    /**
     * The record with a fresh record-metadata MAC over its (possibly
     * rewritten) challenge, issuance clock and hostname, as the issuer
     * writes it.
     */
    public static function seal(ChallengeRecord $record, string $secret = Vectors::SECRET, ?string $tenantId = null): ChallengeRecord
    {
        $data = $record->toArray();
        $data['server_mac'] = ServerStateMac::recordMeta(ServerStateMac::key($secret, $tenantId), $record->challenge, $record->issuedAtNs, $record->hostname);

        return ChallengeRecord::fromArray($data);
    }
}
