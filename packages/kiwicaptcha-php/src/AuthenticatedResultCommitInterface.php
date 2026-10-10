<?php

declare(strict_types=1);

namespace KiwiCaptcha;

/**
 * Optional storage capability: commit a consumed result together with
 * its server-state MAC, see {@see ConsumedResult::$mac}.
 *
 * The verifier commits through this capability whenever the storage
 * offers it, and on such a storage it only replays a stored success
 * whose MAC verifies under the record's kid secret, see
 * {@see ServerStateMac::consumedResult()}. A storage writer who does
 * not hold the master secret therefore cannot forge `valid=true` on a
 * consumed record. Storages without the capability keep the legacy
 * unauthenticated result, the plain {@see StorageInterface::commitResult()}.
 *
 * Both methods have exactly the one-shot semantics of their plain
 * counterparts, see {@see StorageInterface::commitResult()} and
 * {@see ResumeDerivationClaimInterface::commitResultResume()}. The MAC
 * is stored verbatim inside `consumed_result`.
 */
interface AuthenticatedResultCommitInterface
{
    /**
     * Store the MACed result on a consumed, resultless record.
     *
     * @return bool true when the result was stored
     */
    public function commitAuthenticatedResult(string $nonce, ConsumedResult $result): bool;

    /**
     * The resume-path variant: the claim owner is a fencing
     * precondition and the claim is cleared with the result write.
     *
     * @return bool true when the result was stored and the claim cleared
     */
    public function commitAuthenticatedResultResume(string $nonce, ConsumedResult $result, string $owner): bool;
}
