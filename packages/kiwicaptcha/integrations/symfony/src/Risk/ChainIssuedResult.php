<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

/**
 * The typed result of the idempotent issuance transition
 * ({@see TransactionalChainedChallengeStateStore::markIssued()}).
 */
enum ChainIssuedResult: string
{
    /** reserved(me) -> issued(stage2Nonce) — this call performed the transition. */
    case IssuedNew = 'issued_new';
    /** Already issued with the SAME nonce (a retry) — the issuance is confirmed. */
    case IssuedSame = 'issued_same';
    /** Already verified with the SAME nonce — the stage was durably issued. */
    case VerifiedSame = 'verified_same';
    /** Issued/verified with a DIFFERENT nonce — another issuance won the chain. */
    case Conflict = 'conflict';
    /** The chain is not reserved by this owner (or not reserved at all). */
    case NotOwner = 'not_owner';
    /** The chain state is absent/expired. */
    case Missing = 'missing';
}
