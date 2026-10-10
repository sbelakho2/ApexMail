<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Asn\AsnDataset;

/**
 * The request descriptor one identity vector derives from (change.md
 * 3.1.1).
 *
 * The client IP follows the repo's canonical spelling rules (an
 * IPv4-mapped or IPv4-compatible v6 form normalizes inside the
 * derivations). The session cookie is the browser representation: 32
 * lowercase hex chars. The optional principal, agent and target fields
 * carry the app user id, the configured verified-agent key id and the
 * already-normalized target identifier; each absent field yields an
 * absent dimension. The ASN dataset handle resolves the client IP to
 * its bucket. The epoch integer is the unix second every rotated epoch
 * derives from, per the contract's floor-division windows.
 */
final class IdentityVectorInput
{
    public function __construct(
        public readonly string $clientIp,
        public readonly ?string $sessionCookieHex,
        public readonly ?string $principalId,
        public readonly ?string $agentKeyId,
        public readonly ?string $targetNormalized,
        public readonly AsnDataset $asnDataset,
        public readonly int $nowUnixSecs,
    ) {
    }
}
