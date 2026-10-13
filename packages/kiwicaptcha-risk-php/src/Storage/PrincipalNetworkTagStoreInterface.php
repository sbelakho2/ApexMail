<?php

declare (strict_types=1);

namespace KiwiCaptcha\Risk\Storage;

/**
 * The principal first-seen network tag records. One record per
 * principal and tag. This mirrors the Rust PrincipalNetworkTagStore
 * trait and the canonical `principal_networks.lua` script.
 *
 * Normative contract:
 *
 *  - Tags: `net:<prefix_hex>`, `asn:<decimal>`, `asn:u4/<prefix>`,
 *    `asn:u6/<prefix>`, `session:<pseudonym_hex>`,
 *    `device:<pseudonym_hex>`. The asn class carries a listed decimal
 *    and the unlisted-namespace buckets. Each is a hash field whose
 *    value is the last-use ms from the storage clock (never a client
 *    clock).
 *  - Trust: a `t:` prefixed mirror field. Trust is minted only on an
 *    Allow or a completed step-up. A Deny path can never mint trust.
 *  - Caps (per principal, LRU by last-use): `session:` 32, `device:` 16,
 *    `net:` 64, `asn:` 64. The oldest entries above the cap are evicted
 *    with their trust flags.
 *  - TTLs: `session:` 2x the continuity cookie TTL (default 3600 s);
 *    `device:` the trusted-device TTL (default 90 days); `net:`/`asn:`
 *    400 days. Every read carries the caller's configured class TTL and
 *    answers "not seen" past it — never past the class maximum, so a
 *    stored value can never vouch server-side past the lifetime the
 *    deployment actually configured.
 *  - Fail-closed errors: any storage failure throws
 *    {@see RiskStoreException}. The implementation never returns "not
 *    seen" on error (which would read as "novel" and price users out
 *    without a signal) and never "seen" (which would fail open).
 *
 * Production implementation:
 * {@see \KiwiCaptcha\Risk\Storage\RedisPrincipalNetworkTagStore}.
 * In-memory fixtures in tests are named fakes and never wired into the
 * container.
 */
interface PrincipalNetworkTagStoreInterface
{
    /**
     * Whether the principal has been seen (established) from this
     * network bucket: `true` = seen before, `false` = never seen (the
     * first-attempt novel-network signal), `null` = no record surface
     * (neutral: never novel).
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalNetworkSeen (string $principalId, string $network): ?bool;

    /**
     * Records the first-seen tag for the (principal, tag) pair. Called
     * when a session credit is granted for a login from this network
     * (or on a completed step-up). Answers whether the record was newly
     * created. When `$trusted` is true the trust flag is minted: only
     * an Allow or a completed step-up may pass true.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function recordPrincipalNetworkTag (string $principalId, string $network, bool $trusted = false): bool;

    /**
     * Whether the account carries ANY established network: the "no
     * prior trusted network" half of the novel-network gate.
     * `true` = the account has a trusted network, `false` = none,
     * `null` = no record surface.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function principalHasTrustedNetwork (string $principalId): ?bool;

    /**
     * Whether this specific tag carries trust (the `t:` mirror was
     * minted). Trust is only set on an Allow or a completed step-up.
     * `true` = trusted, `false` = not trusted or not seen, `null` = no
     * record surface.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function tagIsTrusted (string $principalId, string $network): ?bool;

    /**
     * Deletes every session and device tag (and their trust flags) for
     * a principal. Wire this to password change, admin lockout, and
     * explicit sign-out-everywhere.
     *
     * @throws RiskStoreException when the state backend fails
     */
    public function forgetDevices (string $principalId): void;
}
