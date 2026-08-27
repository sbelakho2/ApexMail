<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trusted client-IP policy: one explicit mode decides how the
 * canonical client IP is derived. Every IP consumer in the bundle goes
 * through this resolver, so all of them always see the same canonical IP.
 * The consumers are the challenge controller (issuance binding tag,
 * rate-limit identity, risk source pseudonym) and the validator (binding
 * re-check, post-solve risk context).
 *
 * Modes:
 *
 *  - `direct` (risk.client_ip_mode: direct): forwarding headers are always
 *    ignored. The canonical IP is the socket peer (the PHP `REMOTE_ADDR`
 *    server variable) and nothing else — regardless of any
 *    application-level trusted-proxy configuration, a forged
 *    X-Forwarded-For / Forwarded from any peer can never influence it.
 *
 *  - `symfony_trusted_proxies` (default): Symfony's own trusted-proxy
 *    machinery is configured from risk.trusted_proxies: the CIDR list is
 *    passed to Request::setTrustedProxies() (with `HEADER_X_FORWARDED_FOR` |
 *    `HEADER_FORWARDED`), and Symfony already ignores forwarding headers from
 *    untrusted peers. When the bundle's list is non-empty it takes ownership
 *    of the trusted-proxy configuration: the static Symfony setting is
 *    deployment-wide and per process. An empty list leaves the
 *    application's own
 *    configuration untouched: the effective trust set is whatever Symfony
 *    has, and the bundle never clobbers it.
 *
 * Ambiguous forwarding: when the peer is trusted and both X-Forwarded-For
 * and Forwarded are present, the two chains can disagree — the canonical IP
 * becomes ambiguous. With risk.reject_ambiguous_forwarding=true the resolver
 * throws {@see AmbiguousForwardingException} (the controller turns it into
 * HTTP 400 `AMBIGUOUS_FORWARDING`, the validator fails closed as
 * invalid_or_expired); with the default false the anomaly is logged and the
 * request proceeds with Symfony's derivation.
 *
 * Duplicate security-singular headers: a request carrying Origin, Forwarded,
 * X-Forwarded-For or X-Real-IP more than once is parser ambiguity: different
 * intermediaries will pick different values, so the header-derived identity
 * is untrustworthy. The challenge controller rejects such a request with 400
 * `DUPLICATE_HEADER` before this resolver is ever consulted; the resolver
 * therefore treats a duplicate as ambiguous, since it is rejected earlier,
 * never silently resolved.
 *
 * An unparseable/missing socket peer yields the empty string (the callers'
 * existing "no usable risk signal" handling applies).
 */
final class ClientIpResolver
{
    public const MODE_DIRECT = 'direct';
    public const MODE_SYMFONY_TRUSTED_PROXIES = 'symfony_trusted_proxies';
    /** The explicit opt-in inheritance mode: use Symfony's global trusted-proxy state. */
    public const MODE_SYMFONY_GLOBAL = 'symfony_global';

    private const VALID_MODES = [self::MODE_DIRECT, self::MODE_SYMFONY_TRUSTED_PROXIES, self::MODE_SYMFONY_GLOBAL];

    /**
     * @param string              $mode                       risk.client_ip_mode
     * @param list<string>        $trustedProxies             risk.trusted_proxies
     *                                                        (CIDRs / exact IPs)
     * @param bool                $rejectAmbiguousForwarding  risk.reject_ambiguous_forwarding
     *                                                        (defaults true;
     *                                                        ambiguity is
     *                                                        rejected unless
     *                                                        explicitly
     *                                                        allowed)
     * @param LoggerInterface|null $logger                    anomaly log target
     *
     * The trust contract is Kiwi-owned. Mode "direct" always uses the
     * socket peer. Mode "symfony_trusted_proxies" trusts exactly the
     * configured list; an empty list means trust nobody (forwarding
     * headers are ignored, and Symfony's global trusted-proxy state is
     * never inherited implicitly). Mode "symfony_global" is the explicit
     * opt-in that inherits the global state.
     */
    public function __construct(
        private readonly string $mode = self::MODE_SYMFONY_TRUSTED_PROXIES,
        private readonly array $trustedProxies = [],
        private readonly bool $rejectAmbiguousForwarding = true,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if (!\in_array($mode, self::VALID_MODES, true)) {
            throw new \InvalidArgumentException(sprintf(
                'client_ip_mode must be "direct", "symfony_trusted_proxies" or "symfony_global" (got "%s")',
                $mode,
            ));
        }
    }

    /**
     * The canonical client IP for a request, per the configured mode.
     *
     * @throws AmbiguousForwardingException when reject_ambiguous_forwarding
     *                                      is true and a trusted peer sends
     *                                      both forwarding headers
     */
    public function resolve(Request $request): string
    {
        if ($this->mode === self::MODE_DIRECT) {
            // Socket peer only: forwarding headers are always ignored.
            return (string) $request->server->get('REMOTE_ADDR', '');
        }

        // Symfony's trusted-proxy state is process-global: Kiwi saves it,
        // applies its own scoped configuration for the derivation, and
        // restores it afterwards, so Kiwi's security boundary can never
        // mutate (or be silently mutated by) the application's global
        // proxy configuration.
        $previousProxies = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        try {
            if ($this->mode === self::MODE_SYMFONY_TRUSTED_PROXIES && $this->trustedProxies !== []) {
                // Trust exactly the configured peers (never inherited).
                Request::setTrustedProxies($this->trustedProxies, Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
            } elseif ($this->mode === self::MODE_SYMFONY_GLOBAL) {
                // The explicit opt-in: inherit the application's global
                // trusted-proxy state (the operator selected this mode).
                Request::setTrustedProxies(\is_array($previousProxies) ? $previousProxies : [], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
            } else {
                // symfony_trusted_proxies with an empty list: trust nobody
                // — the configured contract, never the global inheritance.
                Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
            }

            return self::resolveWithTrust($request, $this->rejectAmbiguousForwarding, $this->logger);
        } finally {
            Request::setTrustedProxies($previousProxies, $previousHeaderSet);
        }
    }

    /**
     * The canonical client IP under the scoped trust configuration.
     *
     * @throws AmbiguousForwardingException when reject_ambiguous_forwarding
     *                                      is true and a trusted peer sends
     *                                      both forwarding headers
     */
    private static function resolveWithTrust(Request $request, bool $rejectAmbiguousForwarding, ?LoggerInterface $logger): string
    {
        $peer = (string) $request->server->get('REMOTE_ADDR', '');
        $effectiveTrust = Request::getTrustedProxies();
        if ($peer !== ''
            && IpUtils::checkIp($peer, $effectiveTrust)
            && $request->headers->has('X-Forwarded-For')
            && $request->headers->has('Forwarded')
        ) {
            $message = 'kiwicaptcha.risk: a trusted proxy sent BOTH X-Forwarded-For and Forwarded — the canonical client IP is ambiguous';
            if ($rejectAmbiguousForwarding) {
                throw new AmbiguousForwardingException($message);
            }
            $logger?->warning($message);

            // Symfony itself refuses to derive an IP from both trusted
            // headers (ConflictingHeadersException). Without rejection the
            // request proceeds, but the only unambiguous value is the
            // socket peer: never a header-derived guess.
            try {
                return (string) ($request->getClientIp() ?? $peer);
            } catch (\Symfony\Component\HttpFoundation\Exception\ConflictingHeadersException) {
                return $peer;
            }
        }

        return (string) ($request->getClientIp() ?? '');
    }
}
