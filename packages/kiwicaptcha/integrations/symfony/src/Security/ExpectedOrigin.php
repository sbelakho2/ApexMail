<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security;

/**
 * The validated same-origin expected origin, built from the server-owned
 * `kiwi_captcha.public_base_url` setting. The value object is the single
 * origin contract: every consumer (the challenge controller's same-origin
 * check, the record hostname, the extension wiring, the doctor command)
 * receives the validated object or the shared violation description,
 * never an arbitrary string.
 *
 * The contract is a canonical HTTPS origin and nothing else: scheme
 * https, a host, no credentials, no query, no fragment, no path (a bare
 * "/" is accepted as the empty path). An env-managed value is validated
 * by {@see self::fromPublicBaseUrl()} when the object is constructed at
 * runtime; a literal is validated by {@see self::publicBaseUrlViolation()}
 * at container build time. Both lanes enforce the identical contract, so
 * a malformed resolved environment value can never reach the controller
 * and silently weaken the same-origin check.
 */
final class ExpectedOrigin
{
    private function __construct(
        private readonly string $host,
        private readonly int $port,
    ) {
    }

    /**
     * The runtime construction guard (the env lane). The container
     * resolves the %env()% placeholder to the real value before invoking
     * this factory, so the fail-closed canonical-origin validation runs
     * on the resolved value, unseen by the load-time lane. The typed
     * LogicException names the option; the literal lane enforces the
     * identical contract at container build time.
     *
     * @throws \LogicException when the resolved value is not a canonical
     *                         HTTPS origin
     */
    public static function fromPublicBaseUrl(string $value): self
    {
        $violation = self::publicBaseUrlViolation($value);
        if ($violation !== null) {
            throw new \LogicException(sprintf(
                'kiwi_captcha.public_base_url %s — the value was resolved from the environment at runtime, so the invalid origin fails closed when the challenge controller is constructed instead of silently weakening the same-origin check.',
                $violation,
            ));
        }

        $parts = parse_url($value);
        $host = strtolower((string) $parts['host']);
        // A trailing dot is DNS-equivalent to the bare name, so strip it
        // before comparing (the controller's origin normalization does
        // the same on the request side).
        $host = rtrim($host, '.');
        if ($host === '') {
            // Defensive: the violation contract already refused an
            // empty host, so this is unreachable through the factory.
            throw new \LogicException('kiwi_captcha.public_base_url must carry a hostname');
        }
        // IDN to punycode (ext-intl): "bücher.example" and
        // "xn--bcher-kva.example" are the same DNS name, so the expected
        // origin matches either spelling of the request Origin. Skipped
        // when ext-intl is absent, exactly like the request-side
        // normalization.
        if (\function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (\is_string($ascii) && $ascii !== '') {
                $host = $ascii;
            }
        }

        return new self($host, isset($parts['port']) ? (int) $parts['port'] : 443);
    }

    /**
     * The fail-closed canonical-origin contract shared by the build-time
     * and runtime lanes: a non-empty absolute https:// origin with a
     * host, no credentials, no query, no fragment, no path (a bare "/"
     * is the empty path) and a valid port. Returns a description of the
     * violation, or null when the value is an acceptable origin.
     */
    public static function publicBaseUrlViolation(mixed $value): ?string
    {
        if (!\is_string($value) || $value === '') {
            return 'must be a non-empty absolute https:// URL with a host and no credentials, path, query or fragment';
        }
        $parts = parse_url($value);
        if (!\is_array($parts)) {
            return 'must be an absolute https:// URL (got "'.$value.'")';
        }
        $scheme = $parts['scheme'] ?? null;
        if ($scheme !== 'https') {
            return 'must be an absolute https:// URL (got "'.$value.'")';
        }
        $host = $parts['host'] ?? null;
        if (!\is_string($host) || $host === '' || isset($parts['user']) || isset($parts['pass'])) {
            return 'must carry a hostname and NO username/password (got "'.$value.'")';
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            return 'must not carry a query or fragment (got "'.$value.'")';
        }
        $path = $parts['path'] ?? '';
        if ($path !== '' && $path !== '/') {
            return 'must have an empty path or "/" (got "'.$value.'")';
        }
        if (isset($parts['port']) && ((int) $parts['port'] < 1 || (int) $parts['port'] > 65535)) {
            return 'must carry a valid port 1..65535 (got "'.$value.'")';
        }

        return null;
    }

    /**
     * The exact same-origin comparison form: scheme://host:port with the
     * effective port always explicit (https defaults to 443). Byte-identical
     * to the controller's request-side origin normalization, so the
     * comparison is a plain string equality.
     */
    public function normalized(): string
    {
        return 'https://'.$this->host.':'.$this->port;
    }

    /**
     * The canonical config form: scheme://host, with an explicit port
     * only when it is not the https default (443).
     */
    public function canonical(): string
    {
        return 'https://'.$this->host.($this->port !== 443 ? ':'.$this->port : '');
    }

    /**
     * The normalized host (lowercased, trailing dot stripped, IDN
     * converted to punycode when ext-intl is available). Used for the
     * server-owned hostname stamped into issued challenge records.
     */
    public function host(): string
    {
        return $this->host;
    }

    public function __toString(): string
    {
        return $this->canonical();
    }
}
