<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Agents;

/**
 * The single-use nonce ledger of the verified-agents plane: one
 * Redis SET NX EX 300 per presented nonce, under
 * {kiwi:<ns>}:agent-nonce:<kid>:<nonce>.
 *
 * The claim runs only after the Ed25519 signature itself verified,
 * so a flood of garbage signatures never writes nonce keys: only a
 * holder of the agent key can make the store consume memory. The
 * TTL bounds the ledger to five minutes of live nonces, matching
 * the signature lifetime envelope (created within skew, expires
 * honored), so a nonce is refuseable for replay across exactly the
 * window a signature could still verify within.
 *
 * Fail-closed: any Redis refusal raises, and the verifier maps the
 * exception to the typed 401 — an unverifiable nonce must never
 * verify. There is deliberately no in-process fallback: a nonce
 * seen by one worker must be seen by every worker of the
 * deployment, or replay protection is fiction.
 */
final class AgentNonceStore
{
    /** The nonce ledger retention in seconds (the SET EX of one claim). */
    public const NONCE_TTL_SECS = 300;

    /**
     * The presented-nonce grammar: 1..128 characters of the URL-safe
     * token set. The nonce is a client-presented string that becomes
     * a Redis key component, so the charset excludes every byte that
     * could smuggle key grammar (spaces, braces, control characters)
     * and the bound keeps the composite key length finite.
     */
    public const NONCE_PATTERN = '/^[A-Za-z0-9._~+=-]{1,128}$/D';

    /**
     * @param \Redis|\Predis\Client $redis     the security Redis (the
     *                                         risk client of the
     *                                         deployment)
     * @param string                $keyPrefix the deployment key prefix
     *                                         including the hash tag,
     *                                         e.g. "{kiwi:prod}:"
     */
    public function __construct(
        private readonly \Redis|\Predis\Client $redis,
        private readonly string $keyPrefix = '{kiwi:kiwi}:',
    ) {
    }

    /**
     * Claims one nonce for one key id: true when the nonce was
     * fresh (this claim wins), false when it was already claimed
     * (a replay).
     *
     * @throws \Throwable when Redis refuses (fail-closed; the caller
     *                   must treat the nonce as unverifiable)
     */
    public function claim(string $keyId, string $nonce, int $ttlSecs = self::NONCE_TTL_SECS): bool
    {
        $result = $this->setNxEx(sprintf('%sagent-nonce:%s:%s', $this->keyPrefix, $keyId, $nonce), $ttlSecs);

        return $result !== null && $result !== false;
    }

    /**
     * The raw SET NX EX against whichever client implementation is
     * in use. Both shapes carry the identical atomic semantics: the
     * key is written with its TTL only when absent.
     */
    private function setNxEx(string $key, int $ttlSecs): mixed
    {
        if ($this->redis instanceof \Redis) {
            return $this->redis->set($key, '1', ['nx', 'ex' => max(1, $ttlSecs)]);
        }

        return $this->redis->set($key, '1', 'EX', max(1, $ttlSecs), 'NX');
    }
}
