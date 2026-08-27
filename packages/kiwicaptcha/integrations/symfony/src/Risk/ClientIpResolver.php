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
 *  - `symfony_trusted_proxies` (default): trusts exactly Kiwi's own
 *    `risk.trusted_proxies` list. An empty list trusts nobody:
 *    forwarding headers are ignored, and the application's global
 *    trusted-proxy state is never inherited implicitly.
 *  - `symfony_global`: the explicit opt-in that reads (never mutates)
 *    Symfony's process-global trusted-proxy state.
 *
 * The forwarded-IP derivation is computed locally against the resolved
 * trust list (the trusted-chain walk for X-Forwarded-For, the `for=`
 * parameter for Forwarded). No `Request::setTrustedProxies` call is ever
 * made, so Kiwi's boundary cannot be affected by (or affect) unrelated
 * framework initialization. It is therefore safe under async/coroutine
 * PHP servers where process-global mutation could interleave.
 *
 * Ambiguous forwarding: when the peer is trusted and both X-Forwarded-For
 * and Forwarded are present, the two chains can disagree — the canonical IP
 * becomes ambiguous. With risk.reject_ambiguous_forwarding=true (the
 * production default) the resolver throws
 * {@see AmbiguousForwardingException} (the controller turns it into HTTP
 * 400 `AMBIGUOUS_FORWARDING`, the validator fails closed as
 * invalid_or_expired). With the flag explicitly disabled the anomaly is
 * logged and the request proceeds with the socket peer, never a
 * header-derived guess.
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

        // The trust list is Kiwi's own, never Symfony's process-global
        // mutation: symfony_trusted_proxies trusts exactly the
        // configured list (an empty list trusts nobody), and
        // symfony_global is the explicit opt-in that reads the
        // application's global state. The forwarded-IP derivation is
        // computed locally against this list, with no
        // Request::setTrustedProxies call anywhere, so Kiwi's boundary
        // is safe under async/coroutine PHP servers where process-global
        // mutation could interleave between concurrent requests.
        $trust = match ($this->mode) {
            self::MODE_SYMFONY_GLOBAL => \is_array(Request::getTrustedProxies()) ? Request::getTrustedProxies() : [],
            default => $this->trustedProxies,
        };
        // The trusted-header policy: Kiwi's own mode trusts both
        // forwarding header families from its configured peers;
        // symfony_global inherits Symfony's header bitmask too, so a
        // header family the application globally decided not to trust
        // (for example XFF only, ignoring RFC Forwarded) is never
        // honored by Kiwi either.
        $headerMask = match ($this->mode) {
            self::MODE_SYMFONY_GLOBAL => Request::getTrustedHeaderSet(),
            default => Request::HEADER_X_FORWARDED_FOR | Request::HEADER_FORWARDED,
        };

        return self::resolveWithTrust($request, $trust, $headerMask, $this->rejectAmbiguousForwarding, $this->logger);
    }

    /**
     * The canonical client IP under the scoped trust configuration.
     *
     * @throws AmbiguousForwardingException when reject_ambiguous_forwarding
     *                                      is true and a trusted peer sends
     *                                      both forwarding headers
     */
    private static function resolveWithTrust(Request $request, array $effectiveTrust, int $headerMask, bool $rejectAmbiguousForwarding, ?LoggerInterface $logger): string
    {
        $peer = (string) $request->server->get('REMOTE_ADDR', '');
        if ($peer === '' || $effectiveTrust === [] || !IpUtils::checkIp($peer, $effectiveTrust)) {
            // The peer is not trusted (or no peer / no trust list): the
            // forwarding headers are ignored — the socket peer is the
            // canonical IP, exactly the configured contract.
            return $peer;
        }

        // A header family is considered only when the effective policy
        // actually trusts it (symfony_global inherits Symfony's bitmask;
        // the Kiwi-owned mode trusts both).
        $hasXff = ($headerMask & Request::HEADER_X_FORWARDED_FOR) !== 0 && $request->headers->has('X-Forwarded-For');
        $hasForwarded = ($headerMask & Request::HEADER_FORWARDED) !== 0 && $request->headers->has('Forwarded');
        if ($hasXff && $hasForwarded) {
            // Both headers from a trusted peer: the canonical IP is
            // ambiguous. The locally derived answer is the socket peer,
            // never a header-derived guess.
            $message = 'kiwicaptcha.risk: a trusted proxy sent BOTH X-Forwarded-For and Forwarded — the canonical client IP is ambiguous';
            if ($rejectAmbiguousForwarding) {
                throw new AmbiguousForwardingException($message);
            }
            $logger?->warning($message);

            return $peer;
        }
        if ($hasXff) {
            return self::clientFromXForwardedFor($request, $effectiveTrust) ?? $peer;
        }
        if ($hasForwarded) {
            return self::clientFromForwarded($request, $effectiveTrust) ?? $peer;
        }

        return $peer;
    }

    /**
     * The locally derived client from a single X-Forwarded-For header:
     * the trusted-chain walk — from the rightmost entry (the trusted
     * peer's direct client) toward the left, the first validated IP
     * outside the trust list is the canonical client. The same semantics
     * as Symfony's trusted-chain derivation, computed without any
     * process-global state.
     */
    private static function clientFromXForwardedFor(Request $request, array $effectiveTrust): ?string
    {
        $ips = array_reverse(array_map('trim', explode(',', (string) $request->headers->get('X-Forwarded-For'))));

        return self::trustedChainClient($ips, $effectiveTrust);
    }

    /**
     * The locally derived client from a single Forwarded header. The
     * `for=` node identifiers of every element are collected, then the
     * same right-to-left trusted-chain walk as the XFF parser is
     * applied. An appending (rather than sanitizing) trusted proxy that
     * passes a client-supplied left-side `for=` cannot spoof the
     * canonical client: the walk starts at the direct-peer side and the
     * first untrusted validated address wins.
     */
    private static function clientFromForwarded(Request $request, array $effectiveTrust): ?string
    {
        $header = (string) $request->headers->get('Forwarded');
        $identifiers = [];
        // Every element (comma-separated) may carry for= plus other
        // parameters (by=, proto=, host=); the for= may be quoted and may
        // carry an optional port (IPv4 form, or a bracketed IPv6 form).
        foreach (explode(',', $header) as $element) {
            if (preg_match('/(?:^|;)\s*for\s*=\s*("[^"]*"|[^;\s]+)/i', $element, $m) === 1) {
                $identifiers[] = trim($m[1], '"');
            }
        }
        if ($identifiers === []) {
            return null;
        }

        return self::trustedChainClient(array_reverse($identifiers), $effectiveTrust);
    }

    /**
     * The canonical trusted-chain walk: from the direct-peer side of the
     * chain (the reversed input) toward the left, the first candidate
     * that parses as a real IP address and is outside the trust list is
     * the canonical client. Candidates that are not actual IP addresses
     * (arbitrary tokens, `unknown`, `_obfuscated`, malformed ports) are
     * never returned: the trust boundary enforces its output contract.
     */
    private static function trustedChainClient(array $candidates, array $effectiveTrust): ?string
    {
        foreach ($candidates as $candidate) {
            $canonical = self::canonicalIp($candidate);
            if ($canonical === null) {
                continue;
            }
            if (!IpUtils::checkIp($canonical, $effectiveTrust)) {
                return $canonical;
            }
        }

        return null;
    }

    /**
     * The canonical IP text for a node identifier, or null when it is
     * not a genuine address. Handles the RFC 7239 forms: bare IPv4,
     * IPv4 with a port (`192.0.2.10:4711`), bracketed IPv6 with an
     * optional port (`[2001:db8::1]`, `[2001:db8::1]:4711`), and quoted
     * variants. Rejects `unknown`, `_obfuscated` and arbitrary tokens.
     * Validates with inet_pton, normalizes IPv4-mapped IPv6, and
     * returns the canonical inet_ntop text.
     */
    private static function canonicalIp(string $identifier): ?string
    {
        $value = trim($identifier);
        if ($value === '' || $value === 'unknown' || str_starts_with($value, '_')) {
            return null;
        }
        $candidate = $value;
        if (str_starts_with($candidate, '[')) {
            $closing = strpos($candidate, ']');
            if ($closing === false) {
                return null;
            }
            // The suffix after the closing bracket must be exactly empty
            // or ":<numeric-valid-port>" — any other trailing junk
            // (for="[2001:db8::1]:notaport",
            // for="[2001:db8::1]garbage") makes the whole node
            // identifier malformed and is rejected.
            $suffix = substr($candidate, $closing + 1);
            if ($suffix !== '') {
                if (!str_starts_with($suffix, ':')
                    || !\ctype_digit(substr($suffix, 1))
                    || (int) substr($suffix, 1) < 1
                    || (int) substr($suffix, 1) > 65535
                ) {
                    return null;
                }
            }
            $candidate = substr($candidate, 1, $closing - 1);
        } elseif (substr_count($candidate, ':') === 1 && str_contains($candidate, ':')) {
            // IPv4 with a port: 192.0.2.10:4711 — the last colon splits
            // the port only when the left side is a valid IPv4 AND the
            // port is a genuine numeric port (a malformed port like
            // 192.0.2.10:notaport is rejected, never guessed).
            $parts = explode(':', $candidate);
            if (\count($parts) === 2
                && filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                && \ctype_digit($parts[1])
                && (int) $parts[1] >= 1
                && (int) $parts[1] <= 65535
            ) {
                $candidate = $parts[0];
            }
        }
        if (str_contains($candidate, ':')) {
            // Bracketed-with-port remainder ([2001:db8::1]:4711 already
            // handled above; a bare "2001:db8::1:4711" is ambiguous and
            // rejected rather than guessed).
            if (substr_count($candidate, ':') < 2) {
                $parts = explode(':', $candidate);
                $last = array_pop($parts);
                if (filter_var($last, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $candidate = implode(':', $parts);
                }
            }
        }
        $packed = @inet_pton($candidate);
        if ($packed === false) {
            return null;
        }
        if (\strlen($packed) === 16 && substr($packed, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
            // IPv4-mapped IPv6 normalizes to the IPv4 form from the
            // packed bytes (the same rule as the issuer's
            // canonicalIpFamily), so equivalent textual spellings (case
            // variants, compressed forms) cannot diverge between the
            // proxy resolution and the downstream canonical IP
            // machinery.
            return (string) inet_ntop(substr($packed, 12));
        }

        return (string) inet_ntop($packed);
    }
}
