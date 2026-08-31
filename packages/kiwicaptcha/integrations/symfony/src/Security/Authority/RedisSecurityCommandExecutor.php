<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\Authority;

/**
 * The common guarded Lua seam (docs/ha-authority.md): the one place
 * the bundle's Redis-backed components execute their Lua scripts, with
 * the authority lane declared by the caller for every script.
 *
 * Typed execution:
 *  - {@see self::executeRead()}     : a read-only script (the chain
 *    live-read). It rides the ordinary authority lane.
 *  - {@see self::executeMutation()} : a non-final mutating script (a
 *    claim, a takeover, a lease renewal, the log gate). It rides the
 *    ordinary authority lane too: the pinned-primary guard verifies
 *    within its window, exactly like a plain SET.
 *  - {@see self::executeSecurityFinal()} : a mutating security-final
 *    transition (the siteverify finalize, the chain
 *    reservation/obligation/issuance/verification/step-up/denial/
 *    transaction-terminal/rearm/release/completion transitions, the
 *    post-solve disposition claim and finalizes). It forces the
 *    zero-stale lane: the pinned-primary guard re-verifies the
 *    authority immediately before the write, bypassing its
 *    verification window, regardless of the command shape
 *    (plain eval or evalsha, whatever the future brings).
 *
 * The lane is a structural declaration, never a comment-marker
 * heuristic: the store knows which of its scripts is the final
 * transition and says so at the call site. When the client is the
 * {@see AuthorityGuardedPredisClient} wrapper (ha_authority
 * "pinned_primary"), the seam routes the execution through
 * {@see AuthorityGuardedPredisClient::withLane()} so the forced lane
 * covers every command shape the wrapper intercepts. Without the
 * wrapper (ha_authority "none") the lane declaration is inert: the
 * RuntimeAuthorityClassifier has already judged the client at
 * construction, and no per-command check exists.
 *
 * The packing convention is the same single source of truth the
 * bundle's RedisEval helper carries: phpredis (\Redis) packs
 * `eval(script, [keys..., args...], numKeys)`, Predis packs
 * `eval(script, numKeys, keys..., args...)`.
 */
final class RedisSecurityCommandExecutor
{
    public function __construct(
        private readonly \Predis\Client|\Redis $client,
    ) {
    }

    /**
     * A read-only Lua script (no write). Ordinary authority lane.
     *
     * @param string|list<string> $key  a single declared key, or the
     *                                  declared KEYS list (all keys must
     *                                  share one hash tag)
     * @param list<mixed> $args the script ARGV values (after the keys)
     */
    public function executeRead(string $script, string|array $key, array $args): mixed
    {
        return $this->run(false, $script, $key, $args);
    }

    /**
     * A mutating but NOT security-final Lua script (a claim, a
     * takeover, a lease renewal, a rate-limit counter). Ordinary
     * authority lane: the pinned-primary guard verifies within its
     * window.
     *
     * @param string|list<string> $key  a single declared key, or the
     *                                  declared KEYS list (all keys must
     *                                  share one hash tag)
     * @param list<mixed> $args the script ARGV values (after the keys)
     */
    public function executeMutation(string $script, string|array $key, array $args): mixed
    {
        return $this->run(false, $script, $key, $args);
    }

    /**
     * A mutating security-final Lua transition (the finalize of a
     * committed outcome, a chain terminal transition, a final
     * disposition). The zero-stale lane: the pinned-primary guard
     * re-verifies the authority immediately before the write, inside
     * the window included, regardless of the command shape.
     *
     * @param string|list<string> $key  a single declared key, or the
     *                                  declared KEYS list (all keys must
     *                                  share one hash tag)
     * @param list<mixed> $args the script ARGV values (after the keys)
     */
    public function executeSecurityFinal(string $script, string|array $key, array $args): mixed
    {
        return $this->run(true, $script, $key, $args);
    }

    private function run(bool $securityFinal, string $script, string|array $key, array $args): mixed
    {
        if ($this->client instanceof AuthorityGuardedPredisClient) {
            // The forced lane routes through the wrapper so the
            // zero-stale guarantee covers every command shape.
            return $this->client->withLane(
                $securityFinal ? AuthorityGuardedPredisClient::LANE_SECURITY_FINAL : AuthorityGuardedPredisClient::LANE_ORDINARY,
                fn (): mixed => $this->eval($script, $key, $args),
            );
        }

        return $this->eval($script, $key, $args);
    }

    private function eval(string $script, string|array $key, array $args): mixed
    {
        $keys = \is_array($key) ? \array_values($key) : [$key];

        if ($this->client instanceof \Redis) {
            return $this->client->eval($script, [...$keys, ...$args], \count($keys));
        }

        return $this->client->eval($script, \count($keys), ...$keys, ...$args);
    }
}
