<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Fixtures;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;

/**
 * The parent-revision verifier simulator for the protocol-v3 two-phase
 * rollout tests: a verifier wrapper whose supported-protocol set is
 * exactly {1, 2}, the max protocol of the pre-decoy binary.
 * The parent revision's structural gate accepted only protocol
 * versions 1 and 2, so a protocol-v3 record fails closed as
 * MalformedRecord before any further check.
 * The decoy-armed canonical is precisely the record shape the
 * two-phase rollout keeps away from a serving verifier that rejects
 * it.
 *
 * Every other check, the signature, kid, TTL, scope, binding,
 * deployment expectations and Argon ceilings, is byte-identical across
 * the revision boundary.
 * The wrapper therefore delegates the accepted versions to the wrapped
 * current Verifier, and the simulation differs from the real parent
 * revision only in the protocol acceptance set.
 * The wrapped verifier must be bound to the same storage the wrapper
 * peeks, so the delegation sees the identical record state.
 *
 * The static {@see self::accepts()} predicate is the direct-call
 * version-acceptance form with an explicit max protocol.
 */
final class ProtocolV2OnlyVerifier
{
    /** The parent-revision supported set: 1 (legacy) and 2 (unarmed). */
    public const SUPPORTED_PROTOCOLS = [1, 2];

    public const MAX_SUPPORTED_PROTOCOL = 2;

    public function __construct(
        private readonly Verifier $verifier,
        private readonly StorageInterface $storage,
    ) {
    }

    /**
     * The version-acceptance predicate with an explicit max: the parent
     * revision accepts exactly 1..=maxProtocol. Protocol 3 is outside
     * the {1, 2} set, which is the whole point of the rollout gate.
     */
    public static function accepts(int $protocolVersion, int $maxProtocol = self::MAX_SUPPORTED_PROTOCOL): bool
    {
        return $protocolVersion >= 1 && $protocolVersion <= $maxProtocol;
    }

    /**
     * The parent-revision structural gate on a record: null when the
     * record's protocol version is accepted, MalformedRecord otherwise.
     */
    public function gate(ChallengeRecord $record, int $maxProtocol = self::MAX_SUPPORTED_PROTOCOL): ?VerifyError
    {
        return self::accepts($record->protocolVersion, $maxProtocol) ? null : VerifyError::MalformedRecord;
    }

    /**
     * The parent-revision verification path: decode the token, peek the
     * stored record, apply the version gate, and for an accepted version
     * run the wrapped current Verifier (all other checks are identical
     * across the revision boundary). A rejected version answers
     * MalformedRecord immediately, exactly like the parent revision's
     * validateRecord gate.
     */
    public function verify(
        string $rawToken,
        string $secretKey,
        ?string $expectedScope = null,
        ?string $clientIp = null,
        ?int $nowNs = null,
        int $maxProtocol = self::MAX_SUPPORTED_PROTOCOL,
    ): VerifyOutcome {
        try {
            $token = SolutionToken::decode($rawToken);
        } catch (DecodeError $e) {
            return VerifyOutcome::malformedToken($e->getMessage());
        }
        $record = $this->storage->find($token->nonce);
        if ($record === null) {
            return VerifyOutcome::invalid(VerifyError::RecordNotFound);
        }
        if (($e = $this->gate($record, $maxProtocol)) !== null) {
            return VerifyOutcome::invalid($e);
        }

        return $this->verifier->verify($rawToken, $secretKey, $expectedScope, $clientIp, $nowNs);
    }
}
