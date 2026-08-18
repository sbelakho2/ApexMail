<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Risk;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trusted client-IP policy: ONE explicit mode decides how the
 * canonical client IP is derived, and every IP consumer in the bundle — the
 * challenge controller (issuance binding tag, rate-limit identity, risk
 * source pseudonym) and the validator (binding re-check, post-solve risk
 * context) — goes through this resolver, so all of them always see the SAME
 * canonical IP.
 *
 * Modes:
 *
 *  - `direct` (risk.client_ip_mode: direct): forwarding headers are ALWAYS
 *    ignored. The canonical IP is the socket peer (SERVER REMOTE_ADDR) and
 *    nothing else — regardless of any application-level trusted-proxy
 *    configuration, a forged X-Forwarded-For / Forwarded from ANY peer can
 *    never influence it.
 *
 *  - `symfony_trusted_proxies` (default): Symfony's own trusted-proxy
 *    machinery is configured from risk.trusted_proxies — the CIDR list is
 *    passed to Request::setTrustedProxies() (with HEADER_X_FORWARDED_FOR |
 *    HEADER_FORWARDED), and Symfony already ignores forwarding headers from
 *    untrusted peers. When the bundle's list is non-empty it takes ownership
 *    of the trusted-proxy configuration (deployment-wide, per process — the
 *    static Symfony setting); an EMPTY list leaves the application's own
 *    configuration untouched (the effective trust set is whatever Symfony
 *    has) and the bundle never clobbers it.
 *
 * AMBIGUOUS FORWARDING: when the peer IS trusted and BOTH X-Forwarded-For
 * AND Forwarded are present, the two chains can disagree — the canonical IP
 * becomes ambiguous. With risk.reject_ambiguous_forwarding=true the resolver
 * throws {@see AmbiguousForwardingException} (the controller turns it into
 * HTTP 400 AMBIGUOUS_FORWARDING, the validator fails closed as
 * invalid_or_expired); with the default false the anomaly is logged and the
 * request proceeds with Symfony's derivation.
 *
 * DUPLICATE SECURITY-SINGULAR HEADERS: a request carrying
 * Origin, Forwarded, X-Forwarded-For or X-Real-IP MORE THAN ONCE is parser
 * ambiguity — different intermediaries will pick different values, so the
 * header-derived identity is untrustworthy. The challenge CONTROLLER rejects
 * such a request with 400 DUPLICATE_HEADER BEFORE this resolver is ever
 * consulted; the resolver therefore treats a duplicate as ambiguous (it is
 * rejected earlier, never silently resolved).
 *
 * An unparseable/missing socket peer yields the empty string (the callers'
 * existing "no usable risk signal" handling applies).
 */
final class ClientIpResolver
{
    public const MODE_DIRECT = 'direct';
    public const MODE_SYMFONY_TRUSTED_PROXIES = 'symfony_trusted_proxies';

    private const VALID_MODES = [self::MODE_DIRECT, self::MODE_SYMFONY_TRUSTED_PROXIES];

    /**
     * @param string              $mode                       risk.client_ip_mode
     * @param list<string>        $trustedProxies             risk.trusted_proxies
     *                                                        (CIDRs / exact IPs)
     * @param bool                $rejectAmbiguousForwarding  risk.reject_ambiguous_forwarding
     * @param LoggerInterface|null $logger                    anomaly log target
     */
    public function __construct(
        private readonly string $mode = self::MODE_SYMFONY_TRUSTED_PROXIES,
        private readonly array $trustedProxies = [],
        private readonly bool $rejectAmbiguousForwarding = false,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if (!\in_array($mode, self::VALID_MODES, true)) {
            throw new \InvalidArgumentException(sprintf(
                'client_ip_mode must be "direct" or "symfony_trusted_proxies" (got "%s")',
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
            // Socket peer only: forwarding headers are ALWAYS ignored.
            return (string) $request->server->get('REMOTE_ADDR', '');
        }

        if ($this->trustedProxies !== []) {
            // Configure Symfony's trusted-proxy machinery from the CIDR list
            // (static, process-wide — the mode owns this configuration).
            Request::setTrustedProxies($this->trustedProxies, Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED);
        }

        $peer = (string) $request->server->get('REMOTE_ADDR', '');
        $effectiveTrust = $this->trustedProxies !== [] ? $this->trustedProxies : Request::getTrustedProxies();
        if ($peer !== ''
            && IpUtils::checkIp($peer, $effectiveTrust)
            && $request->headers->has('X-Forwarded-For')
            && $request->headers->has('Forwarded')
        ) {
            $message = 'kiwicaptcha.risk: a trusted proxy sent BOTH X-Forwarded-For and Forwarded — the canonical client IP is ambiguous';
            if ($this->rejectAmbiguousForwarding) {
                throw new AmbiguousForwardingException($message);
            }
            $this->logger?->warning($message);

            // Symfony itself refuses to derive an IP from both trusted
            // headers (ConflictingHeadersException). Without rejection the
            // request proceeds — but the only UNAMBIGUOUS value is the
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
