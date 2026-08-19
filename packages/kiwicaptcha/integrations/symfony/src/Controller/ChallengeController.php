<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Risk\UnknownScopeException;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use KiwiCaptcha\Storage\ReplicaWaitException;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\StorageInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issues a new captcha challenge for the widget.
 *
 * The route is NOT declared via a #[Route] attribute on this class — bundle
 * controllers are never scanned for attribute routes. It is registered by
 * {@see \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader} with
 * the bundle's configured `route_prefix` (auto-registered by the extension,
 * or imported from the bundle's routes resource).
 *
 * The widget fetches this endpoint, solves the proof-of-work locally in the
 * browser, and submits the token in the hidden input. Challenges are issued
 * and stored locally — no external service is involved.
 *
 * Every response (success, error, 422, 429, 403) is a private JSON document:
 * Cache-Control no-store, Pragma no-cache, Referrer-Policy no-referrer and
 * X-Content-Type-Options nosniff — challenge bytes and client identity must
 * never be cached, mirrored, or sniffed (see {@see self::privateJson()}).
 *
 * Security design of the request pipeline, in order:
 *  1. PATH CANONICALITY: the RAW request target must be the canonical path
 *     (no `//`, no `/./`, no `/../`, no percent-encoded bytes, no trailing
 *     slash — the raw REQUEST_URI is compared, never a normalized route); a
 *     noncanonical target gets 404 CANONICAL_PATH_REQUIRED before any
 *     handling.
 *  2. NARROW HTTP: non-POST stays 405 — an OPTIONS preflight alone never
 *     authorizes anything. HTTP FRAMING is rejected before any body is
 *     read: a request carrying BOTH Content-Length and Transfer-Encoding,
 *     or a duplicate Content-Length, is request-smuggling ambiguity and
 *     gets 400 FRAMING_REJECTED.
 *  3. SECURITY-SINGULAR HEADERS: Origin, Forwarded, X-Forwarded-For or
 *     X-Real-IP appearing more than once is a parser-ambiguity attack and
 *     gets 400 DUPLICATE_HEADER before any header-derived identity is
 *     trusted.
 *  4. Content-Encoding other than identity and Content-Type other than
 *     application/json are rejected (415) before any body is read — no
 *     decompression bombs, no form-encoded smuggling.
 *  5. BODY CEILING: the body is consumed as a stream with a hard 8 KiB cap
 *     and a declared-Content-Length check — oversized input gets 413
 *     BODY_TOO_LARGE before the duplicate scan, the JSON decode or any
 *     admission control. Allocation-level ceilings are a deployment
 *     concern: mirror the bound in the proxy (client_max_body_size etc.)
 *     and in PHP (post_max_size) so oversized bytes never reach PHP at
 *     all.
 *  6. QUERY-PARAM HARDENING: the POST accepts ONLY scope / algorithm? /
 *     request_binding — any query string is a debug/override probe and
 *     gets 422.
 *  7. SECURITY-STATE STALENESS: a monitor whose central policy read is
 *     past the max-stale window refuses issuance with 503
 *     SERVICE_UNAVAILABLE — deliberate constrained degradation (README:
 *     availability trade-off).
 *  8. SAME-ORIGIN (CORS IS NOT AUTHORIZATION): origin enforcement runs on
 *     EVERY security response; the bundle never emits CORS headers at
 *     all, so there is no preflight path that could authorize. The
 *     optional origin allowlist (403 origin_rejected) and the Fetch
 *     Metadata check (403 CROSS_SITE_REJECTED) are the origin-laundering
 *     defenses, also before any state is written.
 *  9. DUPLICATE-JSON-KEY scan: the raw body is scanned for repeated object
 *     keys ({"scope":"a","scope":"b"} is a parser-ambiguity probe, 422
 *     DUPLICATE_FIELD, nested objects included), then the strict
 *     JSON-field check (only the documented fields, scalars only), then
 *     scope read.
 * 10. PROCESS-LOCAL EMERGENCY ADMISSION before any Redis issuance
 *     limiter: a saturated process refuses with the 429 risk-denied
 *     response without a single Redis round trip. Issuance rate limiting
 *     follows (per-client and deployment-global; a per-client 429 records
 *     SourceRateLimitHit, a global 429 records GlobalCapacityHit — the
 *     deployment-wide refusal is identity-neutral and never contaminates
 *     the visitor's source reputation).
 * 11. When the adaptive risk engine is enabled, the PRE-ISSUE risk
 *     assessment runs (a Deny decision returns 429 RISK_DENIED before any
 *     challenge is minted; the denial already scored the evidence, so no
 *     further rate-limit event is recorded; an escalated action raises
 *     the difficulty of the issued challenge, an unknown scope in
 *     'reject' mode returns 429 RISK_DENIED without issuing). The risk-v2
 *     evidence markers (decoy_field / honeypot / client_context) ride the
 *     assessment as probabilistic evidence — the markers are NEVER a
 *     security gate: a marked request is assessed like any other, and the
 *     evidence only moves the risk aggregate.
 * 12. PER-SCOPE ISSUANCE CAP: when risk.max_challenges_per_scope_per_minute
 *     is set, the atomic fixed-window counter refuses 429 SCOPE_LIMITED
 *     beyond the cap. The quota keys on the SERVER-OWNED scope identity
 *     (the configured risk.scopes id, the shared synthetic unknown-scope
 *     id, or the single reserved UNKNOWN_QUOTA_ID bucket for every
 *     unresolvable scope in ANY risk mode), so the raw scope string is
 *     NEVER a Redis key component and attacker-chosen scope names can
 *     never mint fresh quota windows.
 * 13. ANTI-STOCKPILING admission: the bounded outstanding counters are
 *     admitted BEFORE the challenge state is created when the configured
 *     challenge TTL is wired — the challenge-issuance sequence is local
 *     cap -> issuer limiter -> scope cap -> outstanding counters ->
 *     mint+store, so every quota check runs before the storage write;
 *     without a wired TTL the mint-then-admit path applies, discarding
 *     the minted record on refusal. Every minted challenge increments the
 *     atomic issuance-rate counter used by the resource-pressure
 *     provider.
 *
 * Issuance policy:
 *  - SERVER-OWNED SITEKEY POLICY: when the request carries a sitekey with
 *    a configured policy, the security scope is resolved from the
 *    (sitekey, action) pair — the browser never gets to choose protected
 *    scope names; unknown actions are rejected. The global binding_mode
 *    is the only binding control (there is no per-sitekey binding
 *    dimension).
 *  - PROVIDER METADATA BINDING: action/cData are validated, bound to the
 *    nonce at issuance and persisted server-side; a token whose metadata
 *    sidecar cannot be written is never handed out (fail closed).
 *  - SINGLE-USE SEMANTICS: the minted challenge is atomically consumed on
 *    verification with deterministic consumed-result retention — replays
 *    resolve to the stored outcome, never a second success.
 *
 * A syntactically INVALID scope or request binding is rejected at 422 with
 * ZERO Redis operations: the identifier-charset check runs BEFORE the rate
 * limiter, the risk engine, the scope cap and the outstanding counters —
 * a malformed identifier never touches shared infrastructure.
 *
 * The canonical client IP comes from {@see ClientIpResolver}
 * (risk.client_ip_mode / risk.trusted_proxies /
 * risk.reject_ambiguous_forwarding): the same IP that feeds the challenge
 * binding tag, the rate-limit identity and the risk source pseudonym,
 * never a Host-header or forwarding-header free-for-all.
 *
 * The expected same-origin comes from the configured public_base_url —
 * SERVER CONFIG, never the Host header: a forged Host can never make a
 * cross-origin request look same-origin.
 */
final class ChallengeController
{
    /**
     * The bundle's identifier charset: scope/tenant identifiers and
     * request bindings may only carry these characters (1..128 — the
     * ceiling is embedded in the pattern). Stricter than the core's "no '|'"
     * shape rule — an identifier outside the charset is refused before it
     * can be signed into a challenge.
     */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The ONLY JSON fields the challenge POST accepts. */
    private const ACCEPTED_PAYLOAD_FIELDS = ['scope', 'algorithm', 'request_binding', 'action', 'cdata', 'sitekey', 'decoy_field', 'honeypot', 'client_context', 'chain_ticket'];

    /** Turnstile-compatible shapes, per Cloudflare's docs. */
    private const ACTION_PATTERN = '/^[a-z0-9_-]{1,32}$/i';
    private const CDATA_PATTERN = '/^[a-z0-9_-]{1,255}$/i';

    /**
     * The risk-v2 decoy markers: a server-issued decoy (honeypot) field
     * name echoed back by the widget, and the coarse capability descriptor
     * for the client-context tag. Both are bounded scalar strings — the
     * decoy name is the loose identifier shape, the capability descriptor
     * is the compact [a-z0-9+_:-] alphabet, and the honeypot VALUE is any
     * non-empty string bounded at 256 bytes (a bot's filler, evidence only).
     */
    private const DECOY_FIELD_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';
    private const CLIENT_CONTEXT_PATTERN = '/^[a-z0-9+_,=:-]{1,64}$/D';
    private const MAX_HONEYPOT_VALUE_BYTES = 256;

    /**
     * The one-shot chain ticket presented by a stage-2 challenge request
     * (risk.chaining): base64url(payload) "." base64url(HMAC-SHA256),
     * bounded to the accepted shape. The ticket's signature, expiry,
     * policy epoch and server-held chain state are validated by the
     * ChainedChallengeTicketService; a ticket-bearing request is NEVER
     * downgraded to an unchained issuance.
     */
    private const CHAIN_TICKET_PATTERN = '/^[A-Za-z0-9._:-]{1,256}$/D';

    /**
     * The bounded trusted-edge TLS classification tag the configured
     * header may carry (risk.trusted_tls_header). A malformed value is
     * IGNORED (the request is assessed without a TLS tag), never
     * rejected — the tag is probabilistic evidence, not a gate.
     */
    private const TRUSTED_TLS_TAG_PATTERN = '/^[a-z0-9_+:-]{1,32}$/i';

    /**
     * The server-issued decoy field name in the challenge response: a
     * bounded, per-issuance name derived from the challenge nonce, which
     * the widget renders as a hidden honeypot field. A bot that fills it
     * echoes the name back in a later challenge request (decoy_field /
     * honeypot entries), which the risk-v2 surface records as honeypot
     * evidence — never a security gate.
     */
    private const DECOY_FIELD_PREFIX = 'decoy_';

    /**
     * SECURITY-SINGULAR headers: each of these carries client identity or
     * forwarding trust and MUST appear at most once — a duplicate is
     * parser-ambiguity (different intermediaries will pick different
     * values) and gets 400 DUPLICATE_HEADER before any header-derived
     * identity is trusted.
     */
    private const SECURITY_SINGULAR_HEADERS = ['origin', 'forwarded', 'x-forwarded-for', 'x-real-ip'];

    /**
     * Hard ceiling for the challenge request body: the challenge language
     * is tiny (scope/algorithm/request_binding), so 8 KiB is extremely
     * generous — everything beyond it is refused before the duplicate
     * scan / JSON decode / risk admission consume anything. Edge
     * deployments should mirror this in the proxy (client_max_body_size
     * etc.) so oversized bytes never reach PHP at all.
     */
    private const MAX_CHALLENGE_BODY_BYTES = 8192;

    /** Recursion cap for the duplicate-key scanner (depth bombs). */
    private const MAX_JSON_SCAN_DEPTH = 32;

    public function __construct(
        private readonly Issuer $issuer,
        private readonly ?IssuanceRateLimiter $rateLimiter = null,
        private readonly bool $sameOriginOnly = true,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
        private readonly ?IssuanceCounter $issuanceCounter = null,
        private readonly ?OutstandingChallenges $outstanding = null,
        private readonly array $challengeOriginAllowlist = [],
        private readonly bool $enforceFetchMetadata = false,
        private readonly ?StorageInterface $storage = null,
        private readonly ?string $defaultRequestBinding = null,
        private readonly bool $enforceOrigin = false,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?string $publicBaseUrl = null,
        private readonly ?ScopeIssuanceCap $scopeIssuanceCap = null,
        private readonly ?SecurityEpochMonitor $epochMonitor = null,
        private readonly ?int $challengeTtlSecs = null,
        /** Server-owned scope allowlist ([] = accept any). */
        private readonly array $allowedScopes = [],
        /** Public sitekey -> scope alias map (server-owned migration compat). */
        private readonly array $sitekeyAllowlist = [],
        /** Server-side provider-metadata sidecar (nullable). */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore $metadataStore = null,
        /** Server-owned sitekey policy map. */
        private readonly array $sitekeyPolicy = [],
        /** Lazily-built TTL-variant issuers (per-sitekey override), keyed by TTL. */
        private array $ttlOverrideIssuers = [],
        /**
         * One-shot chain-ticket service for stage-2 issuance
         * (risk.chaining; null = chaining disabled — a ticket-bearing
         * request is then refused, never downgraded).
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService $chainTickets = null,
        /**
         * Trusted-edge TLS classification header (risk.trusted_tls_header;
         * null = the feature is off).
         */
        private readonly ?string $trustedTlsHeader = null,
        /**
         * The security-policy epoch a presented chain ticket must match
         * (risk.policy_version).
         */
        private readonly int $policyVersion = 1,
    ) {
    }

    public function challenge(Request $request): JsonResponse
    {
        // PATH CANONICALITY: the RAW REQUEST_URI must be the canonical
        // request target — no `//` (empty segment), no `/.` /
        // `/..` (dot segments), no percent-encoded bytes (the canonical
        // target is a fixed ASCII path — ANY `%` in the path is an
        // encoding probe: `/%76hallenge`, `%2F`, `%5C`...), no trailing
        // slash, no backslashes. The check compares the RAW URI, never a
        // normalized route: a noncanonical target gets 404
        // CANONICAL_PATH_REQUIRED (the typed target does not exist on this
        // server — the bundle never redirects, rewrites or normalizes it)
        // BEFORE any handling. The proxy stack must reach the same decision
        // at the edge (README — "Canonical request targets").
        if (!$this->isCanonicalRequestTarget((string) $request->getRequestUri())) {
            return $this->privateJson(
                ['error' => ['code' => 'CANONICAL_PATH_REQUIRED', 'message' => 'The request target must be the canonical path (no empty, dot or percent-encoded segments).']],
                Response::HTTP_NOT_FOUND,
            );
        }

        // NARROW HTTP: the endpoint is POST-only — at the CONTROLLER level
        // too (the route already restricts the method, but a direct
        // invocation must behave identically). An OPTIONS preflight is a
        // non-POST method: 405 — a preflight ALONE never authorizes
        // anything.
        if ($request->getMethod() !== 'POST') {
            $response = $this->privateJson(
                ['error' => ['code' => 'METHOD_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts POST requests only.']],
                Response::HTTP_METHOD_NOT_ALLOWED,
            );
            $response->headers->set('Allow', 'POST');

            return $response;
        }

        // HTTP FRAMING: a request carrying BOTH Content-Length
        // and Transfer-Encoding — or a DUPLICATE Content-Length — is
        // request-smuggling ambiguity: different intermediaries will frame
        // the body differently, so the endpoint refuses before any body is
        // read. Symfony's HeaderBag keeps every raw header value
        // (headers->all()), so a crafted duplicate survives into the
        // controller; at the wire level the proxy guidance (README) rejects
        // the ambiguity first.
        $contentLengths = $request->headers->all('content-length');
        $transferEncodings = $request->headers->all('transfer-encoding');
        if (\count($contentLengths) > 1 || ($contentLengths !== [] && $transferEncodings !== [])) {
            return $this->privateJson(
                ['error' => ['code' => 'FRAMING_REJECTED', 'message' => 'The request carries ambiguous HTTP framing (Content-Length and Transfer-Encoding together, or a duplicate Content-Length).']],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // BODY CEILING: the challenge language is tiny —
        // real requests are tens to a few hundred bytes — so a giant body
        // is pure memory/CPU spend BEFORE the shared risk/Redis admission
        // controls. An oversized DECLARED Content-Length is rejected before
        // any body is read (413), and the ACTUAL read length is capped too:
        // chunked uploads can avoid a truthful Content-Length, so the
        // post-read check is the authoritative one (the README's edge
        // guidance adds the matching limit in nginx/Apache/Envoy so the
        // bytes never reach PHP at all).
        $declaredLengths = $request->headers->all('content-length');
        foreach ($declaredLengths as $declared) {
            if (\is_string($declared) && (int) $declared > self::MAX_CHALLENGE_BODY_BYTES) {
                return $this->privateJson(
                    ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The challenge request body must not exceed '.self::MAX_CHALLENGE_BODY_BYTES.' bytes.']],
                    Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
                );
            }
        }
        // DUPLICATE SECURITY-SINGULAR HEADERS: Origin,
        // Forwarded, X-Forwarded-For and X-Real-IP are identity/trust
        // inputs — a duplicate occurrence is parser ambiguity (one
        // intermediary trusts the first value, another the last, and the
        // same-origin check and the client-IP resolution would disagree).
        // Refused with 400 DUPLICATE_HEADER before any header-derived
        // identity is trusted; the client-IP resolver treats a duplicate as
        // ambiguous and is never reached with one. The count is
        // value-agnostic: two IDENTICAL values are still a duplicate.
        foreach (self::SECURITY_SINGULAR_HEADERS as $headerName) {
            if (\count($request->headers->all($headerName)) > 1) {
                return $this->privateJson(
                    ['error' => ['code' => 'DUPLICATE_HEADER', 'message' => sprintf('The %s header must appear at most once.', $headerName)]],
                    Response::HTTP_BAD_REQUEST,
                );
            }
        }

        // NO DECOMPRESSION BOMBS: a request body that was
        // compressed on the wire must not be transparently decompressed by a
        // downstream layer into unbounded memory — any Content-Encoding other
        // than identity is refused BEFORE the body is read. identity (or an
        // absent header) is the only accepted encoding.
        foreach ($request->headers->all('content-encoding') as $encoding) {
            if (strtolower((string) $encoding) !== 'identity') {
                return $this->privateJson(
                    ['error' => ['code' => 'UNSUPPORTED_CONTENT_ENCODING', 'message' => 'Content-Encoding must be identity (the widget POSTs plain JSON).']],
                    Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                );
            }
        }

        // NARROW HTTP: the challenge POST is a JSON document —
        // form-encoded and multipart bodies are refused before anything is
        // read (no CSRF-form smuggling, no HTML-form replay through the
        // endpoint). A PRESENT Content-Type must be application/json (an
        // optional charset parameter is tolerated); an ABSENT header (curl
        // -d, legacy clients) is accepted — the body still has to parse as
        // a strict JSON object with only the documented fields, so nothing
        // is smuggled in. The widget sends exactly application/json.
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType !== '' && $contentType !== 'application/json') {
            return $this->privateJson(
                ['error' => ['code' => 'UNSUPPORTED_MEDIA_TYPE', 'message' => 'Content-Type must be application/json.']],
                Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
            );
        }

        // BODY READ: the input is consumed as a STREAM
        // with a hard cap — at most MAX+1 bytes are ever materialized, so
        // a gigantic chunked request cannot force PHP/Symfony to buffer
        // the full body before the 413. Every header-level check (framing,
        // security-singular headers, Content-Encoding, Content-Type,
        // declared Content-Length) ran BEFORE this read; the duplicate-key
        // scan and the strict decode below operate on the capped string.
        $requestBody = $this->readBoundedBody($request);
        if (\strlen($requestBody) > self::MAX_CHALLENGE_BODY_BYTES) {
            return $this->privateJson(
                ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The challenge request body must not exceed '.self::MAX_CHALLENGE_BODY_BYTES.' bytes.']],
                Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
            );
        }

        // QUERY-PARAM HARDENING: the endpoint accepts NO query
        // parameters — ?debug=1, ?algorithm=sha256 overrides, ?skip_pow=1
        // and friends are probes and get 422 before any state is touched.
        if ($request->query->count() > 0) {
            return $this->privateJson(
                ['error' => ['code' => 'QUERY_PARAMETERS_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts no query parameters.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // SECURITY-STATE STALENESS: the security-epoch monitor
        // tracks the last successful central policy read; once
        // now > last_success + risk.security_epoch_max_stale_secs the
        // central policy may have moved (an emergency revocation could have
        // landed while this node could not read) — issuance is refused with
        // 503 SERVICE_UNAVAILABLE (deliberate constrained degradation; the
        // README documents the availability trade-off: within the window
        // the cached max keeps serving, past it the endpoint fails closed).
        if ($this->epochMonitor !== null) {
            $this->epochMonitor->refresh();
            if ($this->epochMonitor->isStale()) {
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'The security policy state could not be confirmed. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
        }

        if ($this->sameOriginOnly && !$this->isSameOrigin($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'CROSS_ORIGIN_DENIED', 'message' => 'Cross-origin challenge requests are not allowed.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Origin laundering defense: when an origin allowlist is
        // configured, the challenge POST MUST be attributable to one of the
        // allowlisted origins (Origin header, or the Referer origin as
        // fallback). The comparison is STRUCTURED NORMALIZATION —
        // scheme/host/effective-port, host lowercased, default ports
        // normalized, trailing dots stripped, IDN converted to punycode when
        // ext-intl is available, IPv6 literals kept bracketed. With
        // enforce_origin, a request WITHOUT a usable Origin
        // header — or carrying the literal "null" origin (opaque/sandboxed)
        // — is rejected outright, before the allowlist is even consulted.
        // A launderer framing a victim's browser into fetching this endpoint
        // has no way to control the Origin of a cross-site request; raw HTTP
        // bots that never send the header are rejected too (when enforced).
        // Refused BEFORE any state is written, rate-limit budget or CAPTCHA
        // issuance.
        $origin = $request->headers->get('Origin');
        if ($this->enforceOrigin && ($origin === null || $origin === '' || $origin === 'null')) {
            return $this->privateJson(
                ['error' => ['code' => 'origin_rejected', 'message' => 'The challenge request carries no usable Origin header.']],
                Response::HTTP_FORBIDDEN,
            );
        }
        if ($this->challengeOriginAllowlist !== [] && !$this->originIsAllowlisted($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'origin_rejected', 'message' => 'The challenge request origin is not allowlisted.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Fetch Metadata signal (defense-in-depth only): a browser
        // laundering a victim into a cross-site challenge request sends
        // Sec-Fetch-Site: cross-site. Raw HTTP bots lack the header entirely
        // and are unaffected. Rejected before any state is written.
        if ($this->enforceFetchMetadata) {
            $fetchSite = $request->headers->get('Sec-Fetch-Site');
            if ($fetchSite !== null && $fetchSite !== '' && strtolower($fetchSite) === 'cross-site') {
                return $this->privateJson(
                    ['error' => ['code' => 'CROSS_SITE_REJECTED', 'message' => 'Cross-site challenge requests are not allowed.']],
                    Response::HTTP_FORBIDDEN,
                );
            }
        }

        // Trusted client-IP policy: the canonical IP comes from
        // the configured mode (risk.client_ip_mode). In 'direct' mode
        // forwarding headers are ALWAYS ignored (socket peer only); in
        // 'symfony_trusted_proxies' mode Symfony's trusted-proxy machinery
        // ignores them from untrusted peers. An ambiguous double-forwarding
        // from a trusted peer is either logged or — when
        // risk.reject_ambiguous_forwarding is true — rejected with 400
        // AMBIGUOUS_FORWARDING before any state is written.
        try {
            $clientIp = $this->clientIpResolver !== null
                ? $this->clientIpResolver->resolve($request)
                : (string) ($request->getClientIp() ?? '');
        } catch (AmbiguousForwardingException $e) {
            return $this->privateJson(
                ['error' => ['code' => 'AMBIGUOUS_FORWARDING', 'message' => 'The request carries ambiguous forwarding headers (X-Forwarded-For and Forwarded together).']],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // DUPLICATE JSON KEYS: json_decode silently keeps the
        // LAST occurrence of a repeated object key — two different
        // intermediaries parsing the same document could disagree on the
        // effective value ({"scope":"login","scope":"signup"} is a
        // parser-ambiguity probe). The RAW body is scanned with a recursive
        // duplicate-key detector BEFORE decoding; a duplicate at any depth
        // gets 422 DUPLICATE_FIELD. The scanner is defensive: on a document
        // it cannot walk it returns null and the strict json_decode below
        // handles the malformed document (422 INVALID_JSON).
        $duplicateKey = $this->scanForDuplicateJsonKey($requestBody);
        if ($duplicateKey !== null) {
            return $this->privateJson(
                ['error' => ['code' => 'DUPLICATE_FIELD', 'message' => 'The challenge request carries a duplicate JSON key: '.$duplicateKey.'.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // The challenge POST is a JSON OBJECT with exactly the documented
        // fields: scope, algorithm (accepted for
        // forward-compatibility, the issued algorithm always comes from the
        // server), request_binding. Unknown fields are debug/override probes
        // and get 422 — the endpoint never silently ignores extra control
        // surface. A non-object document is refused too (an empty JSON
        // object {} is valid — the fields are optional).
        $decoded = json_decode($requestBody, false);
        if (!$decoded instanceof \stdClass) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The challenge request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        $payload = (array) $decoded;
        $unknown = array_values(array_diff(array_keys($payload), self::ACCEPTED_PAYLOAD_FIELDS));
        if ($unknown !== []) {
            return $this->privateJson(
                ['error' => ['code' => 'UNKNOWN_FIELDS', 'message' => 'The challenge request carries unknown fields: '.implode(', ', $unknown).'.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        // Documented fields must carry scalar values — a nested array in a
        // known field is still a malformed document.
        if ((array_key_exists('scope', $payload) && !\is_string($payload['scope']))
            || (array_key_exists('algorithm', $payload) && !\is_string($payload['algorithm']))
            || (array_key_exists('request_binding', $payload) && $payload['request_binding'] !== null && !\is_string($payload['request_binding']))
            || (array_key_exists('action', $payload) && !\is_string($payload['action']))
            || (array_key_exists('cdata', $payload) && !\is_string($payload['cdata']))
            || (array_key_exists('sitekey', $payload) && !\is_string($payload['sitekey']))
            || (array_key_exists('decoy_field', $payload) && $payload['decoy_field'] !== null && !\is_string($payload['decoy_field']))
            || (array_key_exists('honeypot', $payload) && $payload['honeypot'] !== null && !\is_string($payload['honeypot']))
            || (array_key_exists('client_context', $payload) && $payload['client_context'] !== null && !\is_string($payload['client_context']))
            || (array_key_exists('chain_ticket', $payload) && $payload['chain_ticket'] !== null && !\is_string($payload['chain_ticket']))
        ) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The challenge request fields must be strings.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        // RISK-V2 DECOY MARKERS: the request may carry the server-issued
        // decoy field name (decoy_field) and/or the filled honeypot value
        // (honeypot) echoed back by the widget, plus the coarse capability
        // descriptor (client_context) for the client-context tag. All are
        // BOUNDED scalars — a malformed marker is refused like any other
        // malformed field, and the markers themselves are probabilistic
        // risk evidence (fed to the risk gateway), NEVER a security gate.
        $decoyField = isset($payload['decoy_field']) && $payload['decoy_field'] !== '' ? (string) $payload['decoy_field'] : null;
        $honeypotValue = isset($payload['honeypot']) && $payload['honeypot'] !== '' ? (string) $payload['honeypot'] : null;
        $clientContext = isset($payload['client_context']) && $payload['client_context'] !== '' ? (string) $payload['client_context'] : null;
        $chainTicket = isset($payload['chain_ticket']) && $payload['chain_ticket'] !== '' ? (string) $payload['chain_ticket'] : null;
        if ($decoyField !== null && preg_match(self::DECOY_FIELD_PATTERN, $decoyField) !== 1) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The decoy_field must be 1-64 characters of [A-Za-z0-9_-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($honeypotValue !== null && \strlen($honeypotValue) > self::MAX_HONEYPOT_VALUE_BYTES) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The honeypot value must not exceed '.self::MAX_HONEYPOT_VALUE_BYTES.' bytes.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($clientContext !== null && preg_match(self::CLIENT_CONTEXT_PATTERN, $clientContext) !== 1) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The client_context must be 1-64 characters of [a-z0-9+_:-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($chainTicket !== null && preg_match(self::CHAIN_TICKET_PATTERN, $chainTicket) !== 1) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain_ticket must be 1-256 characters of [A-Za-z0-9._:-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        $honeypotHit = $decoyField !== null || $honeypotValue !== null;
        $scope = isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        // Provider-compatible challenge metadata is validated
        // HERE, at issuance — provider shapes, bounded, so a malformed
        // action/cData can never be persisted or returned.
        $action = isset($payload['action']) && $payload['action'] !== '' ? (string) $payload['action'] : null;
        $cdata = isset($payload['cdata']) && $payload['cdata'] !== '' ? (string) $payload['cdata'] : null;
        if ($action !== null && !preg_match(self::ACTION_PATTERN, $action)) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The action must be 1-32 characters of [a-z0-9_-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($cdata !== null && !preg_match(self::CDATA_PATTERN, $cdata)) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The cdata must be 1-255 characters of [a-z0-9_-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // IDENTIFIER VALIDATION: scope/tenant identifiers and
        // request bindings must match `[A-Za-z0-9._:-]+` with the 128-char
        // ceiling BEFORE they reach the issuer — a malformed identifier can
        // never be signed into a challenge, and separator/control bytes can
        // never smuggle into stored records or the canonical payload. The
        // verification side enforces equality between the record's signed
        // values and what the form POST carries, so a challenge minted under
        // a valid identifier is never redeemable under a different one.
        if (!preg_match(self::IDENTIFIER_PATTERN, $scope)) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => 'The scope must be 1-128 characters of [A-Za-z0-9._:-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // SERVER-OWNED v3-style (sitekey, action)
        // resolution. When the request carries a sitekey that has a
        // configured policy, the security scope is resolved from the
        // (sitekey, action) pair: the browser NEVER gets to choose
        // protected scope names. Unknown actions are REJECTED (never
        // silently mapped to a default). Binding is governed by the global
        // binding_mode only — the client can never request the weaker
        // unbound mode.
        $sitekey = isset($payload['sitekey']) && $payload['sitekey'] !== '' ? (string) $payload['sitekey'] : null;
        $sitekeyTtlSecs = null;
        if ($sitekey !== null && isset($this->sitekeyPolicy[$sitekey])) {
            $policy = $this->sitekeyPolicy[$sitekey];
            // PER-SITEKEY CHALLENGE LIFETIME: the
            // provider-migration TTL override (risk.sitekeys.<sitekey>.ttl_secs,
            // bounded 1..300 by the config tree — 300 for close Turnstile
            // token-lifetime parity). When configured, the challenge is
            // issued with this lifetime instead of the global
            // challenge_ttl_secs; a sitekey without ttl_secs keeps the
            // global default.
            $sitekeyTtlSecs = ($policy['ttl_secs'] ?? null) !== null ? (int) $policy['ttl_secs'] : null;
            $actionKey = $action ?? '';
            if ($actionKey !== '' && isset($policy['actions'][$actionKey])) {
                $scope = $policy['actions'][$actionKey];
            } elseif ($actionKey === '') {
                $scope = $policy['default_scope'] ?? 'login';
            } else {
                return $this->privateJson(
                    ['error' => ['code' => 'UNKNOWN_ACTION', 'message' => 'The action is not configured for this sitekey.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                );
            }
        }

        // MIGRATION SITEKEY ALIAS: a public sitekey is optional
        // legacy metadata, never a secret. When the client sends a
        // configured sitekey (a server-maintained alias map), the scope is
        // resolved from the SERVER-OWNED mapping — an attacker-supplied
        // sitekey can never reduce a route's minimum security policy: an
        // unknown sitekey simply stays a scope name subject to the
        // allowed_scopes gate and the risk assessment below.
        if (isset($this->sitekeyAllowlist[$scope])) {
            $scope = $this->sitekeyAllowlist[$scope];
        }

        // SERVER-OWNED SCOPE ALLOWLIST: when
        // risk.allowed_scopes is configured, issuance is refused for any
        // scope outside the server-defined set BEFORE the risk assessment
        // and the quota checks. This is the trust boundary that makes the
        // per-scope issuance cap an independent security bound: the quota
        // namespace is the server-owned allowlist, never the unbounded
        // attacker-chosen scope dimension.
        if ($this->allowedScopes !== [] && !\in_array($scope, $this->allowedScopes, true)) {
            return $this->privateJson(
                ['error' => ['code' => 'SCOPE_NOT_ALLOWED', 'message' => 'This scope is not enabled for challenge issuance.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Transaction binding: the widget sends the
        // request_binding field it carries (data-kiwi-request-binding); when
        // absent, the configured static risk.request_binding applies. The
        // value is validated here (1..128 bytes, the identifier
        // charset — the same shape rule as the scope) BEFORE it reaches the
        // issuer, so a malformed binding can never be signed into a
        // challenge; the verification side enforces equality between the
        // record's signed binding and the binding the form POST carries.
        $requestBinding = isset($payload['request_binding']) && $payload['request_binding'] !== null
            ? (string) $payload['request_binding']
            : $this->defaultRequestBinding;
        if ($requestBinding !== null && $requestBinding !== '') {
            if (!preg_match(self::IDENTIFIER_PATTERN, $requestBinding)) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_REQUEST_BINDING', 'message' => 'The request binding must be 1-128 characters of [A-Za-z0-9._:-].']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                );
            }
        } else {
            $requestBinding = null;
        }

        // The continuity session is read up front (pure, no side effects) so
        // the rate-limit-hit feedback can attribute the refusal to the same
        // session signal the risk engine would key on. Minting stays in the
        // risk block — a rate-limited request never receives a cookie.
        $riskSession = $this->continuityCookie?->read($request);
        $mintedCookie = false;

        // LOCAL ADMISSION BEFORE REDIS: the process-local
        // emergency window (risk.hard_limits.process_per_second) is checked
        // BEFORE any Redis issuance limiter — a saturated window refuses
        // immediately with the 429 risk-denied response (same shape as the
        // engine's HardRateLimit denial, retry_after_ms 1000) without a
        // single Redis round trip. The check is NON-CONSUMING
        // (RiskGateway::emergencyCapSaturated -> ProcessEmergencyCap::isOpen):
        // the engine's own consuming allow() inside assessPreIssue() below
        // remains the single consumer of the per-process budget, so a
        // request admitted here can still be denied there — never
        // double-counted.
        if ($this->risk !== null && $this->risk->emergencyCapSaturated()) {
            return $this->privateJson(
                ['error' => [
                    'code' => 'RISK_DENIED',
                    'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.',
                    'retry_after_ms' => 1000,
                ]],
                Response::HTTP_TOO_MANY_REQUESTS,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        if ($this->rateLimiter !== null) {
            $rate = $this->rateLimiter->check($clientIp);
            if ($rate !== 1) {
                // Attribute the refusal: a per-client 429 records
                // SourceRateLimitHit (bad on the source/session reputation);
                // the deployment-global 429 records GlobalCapacityHit —
                // identity-neutral, the global-only bad pressure never
                // contaminates this visitor's source reputation. Unknown
                // scopes (reject/baseline modes) are skipped silently: the
                // engine declines to evaluate them, so there is no
                // reputation to attribute to.
                $scopeId = $this->riskScopeId($scope);
                if ($scopeId !== null) {
                    if ($rate === -1) {
                        $this->risk?->globalCapacityHit($scopeId, $riskSession);
                    } else {
                        $this->risk?->sourceRateLimitHit($scopeId, $clientIp, $riskSession);
                    }
                }

                $code = $rate === -1 ? 'GLOBAL_RATE_LIMITED' : 'RATE_LIMITED';
                $message = $rate === -1
                    ? 'The global captcha issuance limit has been reached. Try again later.'
                    : 'Too many captcha challenges requested from this address. Try again later.';

                return $this->privateJson(
                    ['error' => ['code' => $code, 'message' => $message]],
                    Response::HTTP_TOO_MANY_REQUESTS,
                );
            }
        }

        // Adaptive risk: read (or mint) the continuity session, assess the
        // source BEFORE any challenge is written, and act on the decision.
        // A store outage (the engine degrades internally) never blocks
        // issuance. An invalid client IP (no usable risk signal, e.g. a
        // misconfigured proxy) applies the scope's configured DEGRADED
        // decision — the default profile is only issued when the degraded
        // action allows it. An unknown scope depends on unknown_scope.mode:
        // 'minimum' (default) assesses it under the synthetic sha20 policy,
        // 'baseline' issues the default profile, 'reject' returns the
        // risk-denied 429 without issuing.
        $profile = null;
        $riskAssessed = false;
        if ($this->risk !== null) {
            if ($riskSession === null) {
                $riskSession = $this->continuityCookie?->mint();
                $mintedCookie = $riskSession !== null;
            }

            // TRUSTED-EDGE TLS TAG: when risk.trusted_tls_header is
            // configured, ONLY that header is read and its value is
            // validated against the bounded pattern (a malformed value —
            // including a DUPLICATE header, which is parser ambiguity — is
            // IGNORED: the request is assessed without a TLS tag, never
            // rejected). The input is trusted ONLY from an explicitly
            // trusted reverse proxy/CDN that strips client-supplied values;
            // only the coarse classification is stored.
            $tlsTag = null;
            if ($this->trustedTlsHeader !== null) {
                $rawTls = $request->headers->get($this->trustedTlsHeader);
                if (\is_string($rawTls) && $rawTls !== ''
                    && \count($request->headers->all($this->trustedTlsHeader)) === 1
                    && preg_match(self::TRUSTED_TLS_TAG_PATTERN, $rawTls) === 1
                ) {
                    $tlsTag = $rawTls;
                }
            }

            // Risk-v2 evidence: honeypot/decoy markers, the coarse
            // client-context descriptor and the trusted-edge TLS
            // classification ride the assessment as probabilistic evidence —
            // NEVER a security gate.
            $v2 = $this->risk->clientContextV2($honeypotHit, $riskSession, $clientContext, $tlsTag);

            try {
                $decision = $this->risk->preIssue($scope, $clientIp, $riskSession, null, $v2);
                $riskAssessed = true;
            } catch (UnknownScopeException) {
                if ($this->risk->unknownScopeMode() === 'reject') {
                    // TRUE rejection: no challenge, same response as a Deny
                    // decision (429 RISK_DENIED), no baseline fallback. No
                    // risk feedback is recorded: the engine declined to
                    // evaluate the scope, so there is no evidence to
                    // double-count and no reputation to attribute to.
                    return $this->privateJson(
                        ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']],
                        Response::HTTP_TOO_MANY_REQUESTS,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                // 'baseline' mode: the adaptive engine declines — issue the
                // default profile.
                $decision = null;
            } catch (\InvalidArgumentException) {
                // No usable risk signal (e.g. an unparseable client IP from
                // a misconfigured proxy): apply the configured DEGRADED
                // decision for the scope — never silently drop to the
                // baseline profile below the degraded floor.
                $decision = $this->risk->degradedDecisionForScope($this->risk->scopeId($scope));
                $riskAssessed = true;
            }

            if ($decision !== null) {
                if ($honeypotHit) {
                    // Feed the honeypot evidence event into the risk
                    // gateway (mirroring the challengeIssued feedback path):
                    // the decoy marker is booked as probabilistic risk
                    // evidence. This NEVER gates issuance — the evidence
                    // already rode the assessment above; this only records
                    // the event kind for the risk state.
                    $this->risk->honeypotEvidence(
                        $decoyField !== null ? RiskEventKind::DecoyFieldSubmitted : RiskEventKind::HoneypotTriggered,
                        $scope,
                        $clientIp,
                        $riskSession,
                        null,
                        $decision->decisionId,
                    );
                }

                if ($decision->action === RiskAction::StepUp) {
                    // Step-up is application-defined (verified email link,
                    // passkey, existing session, TOTP...): KiwiCaptcha only
                    // says "PoW alone is insufficient for this request".
                    return $this->privateJson(
                        ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']],
                        Response::HTTP_FORBIDDEN,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }

                if ($decision->action === RiskAction::Deny) {
                    // The denial already scored the evidence (the pre-issue
                    // assessment + decision) — no additional rate-limit
                    // event is recorded.
                    $body = ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']];
                    if ($decision->retryAfterMs !== null) {
                        $body['error']['retry_after_ms'] = $decision->retryAfterMs;
                    }

                    return $this->privateJson($body, Response::HTTP_TOO_MANY_REQUESTS, $request, $riskSession, $mintedCookie);
                }
                $profile = $this->risk->decisionProfile($decision);
            }
        }

        // PER-SCOPE ISSUANCE CAP: when
        // risk.max_challenges_per_scope_per_minute is configured, the
        // atomic {kiwi:<ns>}:issuance:<scopeIdentity>:<minute> fixed-window
        // counter (INCR + EXPIRE 60 in one Lua script) refuses 429
        // SCOPE_LIMITED beyond the cap — the public site key + claimed
        // origin can no longer create unlimited billed verification work
        // per scope. The check CONSUMES the slot it admits (a denial below
        // is not double-counted). The quota keys on the SERVER-OWNED scope
        // identity: the risk policy's canonical scope id (the configured
        // risk.scopes.<name>.id, or the shared synthetic unknown-scope id
        // in 'minimum' mode) — the raw scope string is NEVER a Redis key
        // component and, when risk.allowed_scopes is
        // configured, the quota namespace is bounded by the server-owned
        // set (HMAC-only keying hides attacker-controlled
        // BYTES, it does not bound cardinality). A Redis failure propagates
        // (fail closed: no challenge without a checked scope bound).
        // The quota keys on the SERVER-OWNED scope identity ALWAYS:
        // configured scopes use their stable id; every scope
        // the risk policy cannot resolve — unknown scopes in ANY mode,
        // including risk-disabled deployments — collapses into the single
        // reserved UNKNOWN_QUOTA_ID bucket. An attacker can never mint a
        // fresh quota window by inventing scope names, in any
        // configuration. (The 'reject'/'baseline' risk assessment still
        // runs BEFORE this check and answers first for unknown scopes.)
        $canonicalScopeId = ScopeIssuanceCap::UNKNOWN_QUOTA_ID;
        if ($this->risk !== null) {
            try {
                $canonicalScopeId = $this->risk->scopeId($scope);
            } catch (UnknownScopeException) {
                // Unresolvable scope: shares the reserved unknown bucket —
                // never a per-name HMAC namespace.
            }
        }
        if ($this->scopeIssuanceCap !== null) {
            try {
                $allowed = $this->scopeIssuanceCap->allow($scope, $canonicalScopeId);
            } catch (\Exception $e) {
                // The cap FAILS CLOSED when the Redis
                // server clock is unavailable — no quota proof means no
                // challenge issuance (503, private envelope; the detail
                // goes to the server log only). Never silently fall back
                // to per-host wall clocks around window boundaries.
                error_log(sprintf('kiwicaptcha: scope issuance cap clock unavailable: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if (!$allowed) {
                return $this->privateJson(
                    ['error' => ['code' => 'SCOPE_LIMITED', 'message' => 'Too many challenges issued for this scope. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // ANTI-STOCKPILING PRE-MINT ADMISSION: when the
        // effective challenge TTL is known (the configured global
        // challenge_ttl_secs, or a per-sitekey ttl_secs override), the
        // bounded outstanding counters are admitted BEFORE the challenge
        // state is created —
        // the challenge-issuance sequence is local cap -> issuer limiter ->
        // risk assessment -> scope cap -> outstanding counters -> mint +
        // store, so every quota check runs before the storage write (the
        // FakePredis call ORDER test pins the limit/incr keys before the
        // challenge SET key). ONE atomic Lua checks BOTH caps before
        // incrementing (per-source + global, EXPIRE = challenge lifetime +
        // ttl margin — the effective TTL equals the lifetime the issuer
        // signs: the global default or the per-sitekey override, profiles
        // never change it). A refused admission never mints
        // anything. A Redis failure propagates (fail closed: no challenge
        // without a checked stockpile bound).
        $ttlSecs = $sitekeyTtlSecs ?? $this->challengeTtlSecs;
        if ($this->outstanding !== null && $ttlSecs !== null) {
            $admitted = $this->outstanding->issue($clientIp, $ttlSecs);
            if ($admitted !== 1) {
                return $this->privateJson(
                    ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied: outstanding challenge limit reached. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // CHAIN-TICKET GATE (stage-2 issuance, risk.chaining): a
        // ticket-bearing request is validated + CONSUMED here — after every
        // admission check that can still refuse (rate limit, risk denial,
        // scope cap, outstanding counters) so a refused request does not
        // burn the ticket — and immediately before the challenge is
        // minted. The consume is ATOMIC one-shot: signature + expiry +
        // policy epoch + scope are verified, the server-held chain state
        // is consumed (a replayed ticket lands here and is refused), and
        // the issuance then runs the ORDINARY risk preIssue path (the
        // reassessment already happened at verify time; the profile
        // selection is unchanged). When chaining is DISABLED a
        // ticket-bearing request is refused with the malformed-metadata
        // style — NEVER silently downgraded to an unchained issuance.
        $chainPayload = null;
        if ($chainTicket !== null) {
            if ($this->chainTickets === null) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'Chain tickets are not accepted on this deployment.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            try {
                $chainPayload = $this->chainTickets->consume($chainTicket);
            } catch (\Throwable $e) {
                // The chain state backend is unavailable: the one-shot
                // consume cannot be confirmed, so a stage-2 issuance
                // cannot be authorized — fail closed (the detail goes to
                // the server log only).
                error_log(sprintf('kiwicaptcha: chain ticket consume failed: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ($chainPayload === null) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ((string) $chainPayload['scope'] !== $scope) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket does not match this scope.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ((int) $chainPayload['policyVersion'] !== $this->policyVersion) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is from a different security-policy epoch.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        try {
            // The record carries server-owned issuance metadata
            // (Siteverify `hostname`); never signed, never sent. The value
            // comes from the SERVER-CONFIGURED public_base_url — a forged
            // Host header can never influence the reported hostname (the
            // same trust rule as the Origin check). Without
            // public_base_url the hostname stays null rather than trusting
            // the request Host.
            $hostname = $this->publicBaseUrl !== null
                ? parse_url($this->publicBaseUrl, PHP_URL_HOST) ?: null
                : null;
            // Issuance always uses the
            // canonical client IP. A per-sitekey ttl_secs override mints
            // through a TTL-variant issuer ({@see self::issuerForTtl()}) so
            // the SIGNED lifetime carries the override — and with it every
            // TTL derived from the issued challenge (the metadata sidecar
            // below, the post-mint admission).
            $issuer = $this->issuerForTtl($ttlSecs);
            $challenge = $profile !== null
                ? $issuer->issueWithProfile($scope, $clientIp, $profile, requestBinding: $requestBinding, hostname: $hostname)
                : $issuer->issue($scope, $clientIp, $requestBinding, $hostname);
            // CHAIN STAGE BINDING: the ticket holder must never re-run the
            // SAME stage — the newly minted challenge nonce must DIFFER
            // from the chain's verified stage-1 nonce. The nonces are
            // server-minted random values, so a collision is astronomically
            // unlikely; this is the fail-closed invariant check. The
            // minted record is discarded and the request refused like any
            // other invalid ticket.
            if ($chainPayload !== null && $challenge->nonce === (string) $chainPayload['stage1Nonce']) {
                try {
                    $this->storage?->delete($challenge->nonce);
                } catch (\Throwable) {
                    // Best-effort discard; the record expires on its own TTL.
                }

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket cannot re-run the same challenge stage.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        } catch (\InvalidArgumentException $e) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
                $request,
                $riskSession,
                $mintedCookie,
            );
        } catch (ReplicaWaitException $e) {
            // Durability barrier failure: the
            // configured wait_replicas threshold could not be met, so the
            // challenge was NOT handed out — fail closed. This is an
            // OPERATIONAL condition (replica lag / topology), not a client
            // fault: 503 SERVICE_UNAVAILABLE with the private/no-store
            // envelope and an opaque message; the replication detail goes
            // to the server log only.
            error_log(sprintf('kiwicaptcha: challenge issuance failed the replica-wait barrier: %s', $e->getMessage()));

            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        // Anti-stockpiling POST-MINT FALLBACK: a direct
        // controller construction WITHOUT any known challenge lifetime
        // (no wired global TTL and no per-sitekey override) admits the
        // minted record with its ACTUAL lifetime AFTER issuance; a refusal
        // here is a RACE the pre-issuance checks did not see (concurrent
        // issuances): the minted record is discarded best-effort and the
        // request gets the same 429 risk-denied response — a challenge is
        // NEVER handed out when its stockpile admission failed. Production
        // wiring always provides the TTL (the extension passes
        // challenge_ttl_secs), so the pre-mint path above is the deployment
        // behavior.
        if ($this->outstanding !== null && $ttlSecs === null) {
            $admitted = $this->outstanding->issue($clientIp, max(1, $challenge->ttlSecs));
            if ($admitted !== 1) {
                try {
                    $this->storage?->delete($challenge->nonce);
                } catch (\Throwable) {
                    // Best-effort discard; the record expires on its own TTL.
                }

                return $this->privateJson(
                    ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied: outstanding challenge limit reached. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // Provider-compatible challenge metadata (action /
        // cData) is bound to the nonce AT ISSUANCE, server-side. If the
        // metadata was explicitly supplied and the sidecar CANNOT persist
        // it, the minted challenge is discarded and the request fails 503
        // — a token whose verification would return no action/cData must
        // never be handed out (ambiguous compatibility behavior). The
        // sidecar retention (max(60, ttl) + 60) derives from the ISSUED
        // challenge's actual ttlSecs, so a per-sitekey ttl_secs override
        // extends the metadata lifetime with the token's real validity.
        if (($action !== null || $cdata !== null) && $this->metadataStore !== null) {
            try {
                $this->metadataStore->store($challenge->nonce, new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata($action, $cdata, $scope), max(60, $challenge->ttlSecs) + 60);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: siteverify metadata store failed for nonce %s: %s', $challenge->nonce, $e->getMessage()));
                try {
                    $this->storage?->delete($challenge->nonce);
                } catch (\Throwable) {
                    // Best-effort discard; the record expires on its own TTL.
                }

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // A challenge was actually minted: feed the atomic issuance-rate
        // signal (resource-pressure headroom), the risk issue-debt signal,
        // and pair the challenge nonce to the decision id so a later solve
        // can be confirmed back to the ORIGINAL decision (short-lived
        // server-side mapping, TTL = risk.nonce_to_decision_ttl_secs).
        $this->issuanceCounter?->record();
        if ($this->risk !== null && $riskAssessed && $decision !== null) {
            $this->risk->challengeIssued($scope, $clientIp, $riskSession, $decision->decisionId);
            $this->risk->attachDecisionForNonce($challenge->nonce, $decision->decisionId);
        }

        // RISK-V2 DECOY FIELD: when the adaptive risk engine is enabled,
        // the issuance response carries the server-issued decoy (honeypot)
        // field name so the widget can render a hidden honeypot field — a
        // bot that fills it echoes the marker back in a later challenge
        // request, which the risk-v2 surface feeds as honeypot evidence.
        // The name is a bounded per-issuance value; the response shape is
        // otherwise unchanged (no behavioral change to issuance).
        $challengeData = $challenge->toArray();
        if ($this->risk !== null) {
            // Deterministic per issuance (the nonce is base64, so the name
            // is derived via sha256 to stay in the [0-9a-f] alphabet).
            $challengeData['decoy_field'] = self::DECOY_FIELD_PREFIX.substr(hash('sha256', $challenge->nonce), 0, 8);
        }

        return $this->privateJson($challengeData, Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * The issuer to mint with for a given challenge lifetime: the wired
     * issuer when $ttlSecs is null or equals its Config's TTL, otherwise a
     * TTL-variant issuer built once per TTL ({@see self::buildTtlVariantIssuer()})
     * — the core signs the lifetime from the issuer Config, so the
     * per-sitekey override (risk.sitekeys.<sitekey>.ttl_secs) requires a
     * variant issuer.
     */
    private function issuerForTtl(?int $ttlSecs): Issuer
    {
        if ($ttlSecs === null || $ttlSecs === $this->issuer->config()->ttlSecs) {
            return $this->issuer;
        }

        return $this->ttlOverrideIssuers[$ttlSecs] ??= $this->buildTtlVariantIssuer($ttlSecs);
    }

    /**
     * A TTL-variant Issuer: a clone of the wired issuer's Config with
     * ONLY ttlSecs replaced, issued against the SAME storage (the
     * extension wires the identical storage reference into the controller
     * and the issuer), replicating the wired issuer's clock and region —
     * so a region-bound deployment (risk.region) keeps its signed region
     * on overridden-TTL challenges and the verifier's expected-region
     * check still passes.
     *
     * @throws \LogicException when the controller has no storage wired
     *                         (the extension always wires one)
     */
    private function buildTtlVariantIssuer(int $ttlSecs): Issuer
    {
        // The public Issuer::withTtl() API clones the config with only
        // ttlSecs replaced and carries the storage, clock and region
        // directly — no reflection into private state.
        return $this->issuer->withTtl($ttlSecs);
    }

    /**
     * Same-origin check for the challenge endpoint.
     *
     * Requests WITHOUT an Origin header (same-origin navigation, curl,
     * non-browser clients) are allowed — a browser cross-site POST always
     * carries one. When present, the Origin must match the EXPECTED origin.
     *
     * The expected origin comes from SERVER CONFIG
     * (public_base_url) when configured — a forged Host header can never
     * shift the expected origin ("Host: evil.example" + "Origin:
     * https://evil.example" must stay cross-origin). Comparison is the same
     * STRUCTURED NORMALIZATION as the allowlist
     * ({@see self::normalizeOrigin()}). Without public_base_url the
     * expected origin is derived from the request's own scheme+host
     * (constant-time compare; trailing slashes normalized) — fine for
     * localhost/dev, but production deployments behind shared
     * infrastructure should set public_base_url (README).
     */
    private function isSameOrigin(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '') {
            return true;
        }

        if ($this->publicBaseUrl !== null) {
            $expected = self::normalizeOrigin($this->publicBaseUrl);
            $candidate = self::normalizeOrigin($origin);

            return $expected !== null && $candidate !== null && $expected === $candidate;
        }

        $expected = rtrim($request->getScheme().'://'.$request->getHttpHost(), '/');

        return hash_equals($expected, rtrim($origin, '/'));
    }

    /**
     * Origin laundering defense: the request must carry an Origin header
     * (or a Referer whose URL yields an origin) whose NORMALIZED
     * scheme+host+port matches one allowlisted origin. Comparison is
     * component-wise over the STRUCTURED normalization of both sides
     * ({@see self::normalizeOrigin()}: scheme lowercase, host
     * lowercased with the trailing dot stripped and IDN converted to
     * punycode when ext-intl is available, the effective port defaulted per
     * scheme, IPv6 literals kept bracketed), so "https://app.example.com"
     * matches Origin "https://app.example.com", "https://APP.EXAMPLE.COM",
     * "https://app.example.com:443" and "https://app.example.com." — but
     * never "https://app.example.com:8443", "http://app.example.com",
     * "https://evil-example.com" or "https://example.com.evil.com".
     */
    private function originIsAllowlisted(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '' || $origin === 'null') {
            if ($this->enforceOrigin) {
                // With enforce_origin, a request without a usable
                // Origin is rejected BEFORE the Referer fallback — the
                // strict mode never trusts a Referer the browser would not
                // attach to a cross-site fetch.
                return false;
            }
            // Referer-origin fallback: the scheme+host+port of the Referer
            // URL (no path, no query).
            $referer = $request->headers->get('Referer');
            if ($referer === null || $referer === '') {
                return false;
            }
            $parts = parse_url($referer);
            if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
                return false;
            }
            $origin = $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');
        }

        $candidate = self::normalizeOrigin($origin);
        if ($candidate === null) {
            return false;
        }

        foreach ($this->challengeOriginAllowlist as $allowlisted) {
            $allowed = self::normalizeOrigin((string) $allowlisted);
            if ($allowed === null) {
                continue;
            }
            if ($candidate === $allowed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse and NORMALIZE an origin string into its exact comparison
     * components: a canonical "{scheme}://{host}:{port}" string
     * with
     *  - scheme lowercased,
     *  - host lowercased, trailing dot stripped, IDN converted to punycode
     *    (idn_to_ascii when ext-intl is available), IPv6 literals kept
     *    bracketed exactly as parse_url returns them,
     *  - the effective port: an absent port defaults per scheme (https 443,
     *    http 80 — "exact scheme/host/port" treats an explicit default port
     *    as equal); any other scheme is not an origin.
     *
     * @throws nothing — malformed origins return null
     */
    private static function normalizeOrigin(string $origin): ?string
    {
        $parts = parse_url($origin);
        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        $scheme = strtolower((string) $parts['scheme']);
        $port = isset($parts['port'])
            ? (int) $parts['port']
            : ($scheme === 'https' ? 443 : ($scheme === 'http' ? 80 : -1));
        if ($port < 1 || ($scheme !== 'https' && $scheme !== 'http')) {
            return null;
        }

        $host = strtolower((string) $parts['host']);
        // A trailing dot is DNS-equivalent to the bare name ("example.com."
        // and "example.com" are the same host) — strip it before comparing.
        $host = rtrim($host, '.');
        if ($host === '') {
            return null;
        }
        // IDN -> punycode (ext-intl): "bücher.example" and
        // "xn--bcher-kva.example" are the same DNS name. The conversion is
        // skipped when ext-intl is absent (ASCII origins are unaffected).
        if (\function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (\is_string($ascii) && $ascii !== '') {
                $host = $ascii;
            }
        }

        return $scheme.'://'.$host.':'.$port;
    }

    /**
     * The risk-v1 int scope id for a scope string, or null when the scope
     * is unknown in reject/baseline mode (the engine declines to evaluate —
     * there is no reputation to attribute a refusal to).
     */
    private function riskScopeId(string $scope): ?int
    {
        if ($this->risk === null) {
            return null;
        }
        try {
            return $this->risk->scopeId($scope);
        } catch (UnknownScopeException) {
            return null;
        }
    }

    /**
     * PATH CANONICALITY: whether the RAW request target is the
     * canonical path. The check runs over the raw REQUEST_URI — never a
     * normalized route — and rejects
     *
     *  - any EMPTY segment (`//`, and a TRAILING slash `/challenge/`),
     *  - any DOT segment (`/.`, `/./`, `/..`, `/../`),
     *  - any percent-encoded byte (`%` — the canonical target is a fixed
     *    ASCII path, so `/%76hallenge`, `%2F`, `%5C`, `%2e%2e` are all
     *    encoding probes; a percent-encoded SEPARATOR is just the worst of
     *    them),
     *  - any backslash (`\` — a Windows path separator on some stacks).
     *
     * Only the PATH component is inspected (the query string is rejected
     * separately with 422 QUERY_PARAMETERS_NOT_ALLOWED).
     */
    private function isCanonicalRequestTarget(string $rawRequestUri): bool
    {
        $path = $rawRequestUri;
        $queryPos = strpos($rawRequestUri, '?');
        if ($queryPos !== false) {
            $path = substr($rawRequestUri, 0, $queryPos);
        }
        if (str_contains($path, '%') || str_contains($path, '\\')) {
            return false;
        }
        // The empty element before a LEADING slash is the absolute-path
        // marker, not a segment — every other empty segment (a `//` in the
        // middle, or the trailing `/` of "/challenge/") is noncanonical.
        $segments = explode('/', $path);
        $start = $path !== '' && $path[0] === '/' ? 1 : 0;
        for ($i = $start, $count = \count($segments); $i < $count; $i++) {
            if ($segments[$i] === '' || $segments[$i] === '.' || $segments[$i] === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * DUPLICATE JSON KEY SCANNER: a small recursive walk over
     * the RAW JSON document that reports the FIRST object key seen more
     * than once at the same level — json_decode itself silently keeps the
     * LAST occurrence, which is exactly the parser-ambiguity the endpoint
     * must refuse ({"scope":"a","scope":"b"} parses differently across
     * intermediaries). Nested objects are scanned recursively. Returns the
     * duplicated key (for the error message), or null when the document is
     * clean or cannot be walked (a malformed document is handled by the
     * strict json_decode check that follows — 422 INVALID_JSON).
     *
     * The scanner is deliberately small and defensive: it only needs to be
     * CORRECT on documents json_decode already accepts (the duplicate
     * check runs before the decode, but a document the scanner refuses
     * without a duplicate is never refused by it).
     */
    /**
     * Read the challenge request body with a hard byte cap: the input
     * stream is consumed for at most MAX+1 bytes, so an oversized chunked
     * body is refused by the caller's length check WITHOUT ever being
     * materialized in full — the bounded read is the authoritative
     * protection (a declared Content-Length was already checked before the
     * stream was touched, but chunked uploads can skip a truthful one).
     * When Symfony hands back a buffered stream (tests, already-consumed
     * input) the read is still bounded.
     */
    private function readBoundedBody(Request $request): string
    {
        $stream = $request->getContent(true);
        if (\is_resource($stream)) {
            return (string) stream_get_contents($stream, self::MAX_CHALLENGE_BODY_BYTES + 1);
        }

        return (string) $request->getContent();
    }

    private function scanForDuplicateJsonKey(string $json): ?string
    {
        $offset = 0;
        try {
            $this->scanJsonValue($json, $offset, 0);

            return null;
        } catch (DuplicateJsonKeyException $e) {
            return $e->key;
        } catch (MalformedJsonWalkException) {
            return null;
        }
    }

    /**
     * Recursive JSON walker used by the duplicate-key scan. Consumes one
     * value starting at $offset and returns nothing; throws
     * {@see DuplicateJsonKeyException} on the first duplicated object key
     * and {@see MalformedJsonWalkException} on anything it cannot walk
     * (both are internal control flow — the walker never validates the
     * document, it only scans it).
     *
     * @param int $offset position in the raw JSON string (by reference)
     */
    private function scanJsonValue(string $json, int &$offset, int $depth): void
    {
        if ($depth > self::MAX_JSON_SCAN_DEPTH) {
            // Depth bomb: a pathological nesting cannot
            // consume unbounded stack — beyond the cap the document is
            // "not walkable" and the strict json_decode below (which has
            // its own depth guard) rejects it.
            throw new MalformedJsonWalkException();
        }
        $length = \strlen($json);
        $this->skipJsonWhitespace($json, $offset);
        if ($offset >= $length) {
            throw new MalformedJsonWalkException();
        }
        $ch = $json[$offset];

        if ($ch === '{') {
            $offset++;
            $this->skipJsonWhitespace($json, $offset);
            if ($offset < $length && $json[$offset] === '}') {
                $offset++;

                return;
            }
            $seen = [];
            while (true) {
                $this->skipJsonWhitespace($json, $offset);
                $key = $this->scanJsonString($json, $offset);
                if ($key === null) {
                    throw new MalformedJsonWalkException();
                }
                if (isset($seen[$key])) {
                    throw new DuplicateJsonKeyException($key);
                }
                $seen[$key] = true;
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length || $json[$offset] !== ':') {
                    throw new MalformedJsonWalkException();
                }
                $offset++;
                $this->scanJsonValue($json, $offset, $depth + 1);
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length) {
                    throw new MalformedJsonWalkException();
                }
                $ch = $json[$offset];
                $offset++;
                if ($ch === '}') {
                    return;
                }
                if ($ch !== ',') {
                    throw new MalformedJsonWalkException();
                }
            }
        }

        if ($ch === '[') {
            $offset++;
            $this->skipJsonWhitespace($json, $offset);
            if ($offset < $length && $json[$offset] === ']') {
                $offset++;

                return;
            }
            while (true) {
                $this->scanJsonValue($json, $offset, $depth + 1);
                $this->skipJsonWhitespace($json, $offset);
                if ($offset >= $length) {
                    throw new MalformedJsonWalkException();
                }
                $ch = $json[$offset];
                $offset++;
                if ($ch === ']') {
                    return;
                }
                if ($ch !== ',') {
                    throw new MalformedJsonWalkException();
                }
            }
        }

        if ($ch === '"') {
            $this->scanJsonString($json, $offset);

            return;
        }

        // number / true / false / null: skip a bare token.
        while ($offset < $length) {
            $ch = $json[$offset];
            if ($ch === ',' || $ch === '}' || $ch === ']' || $ch === ' ' || $ch === "\t" || $ch === "\n" || $ch === "\r") {
                break;
            }
            $offset++;
        }
    }

    /**
     * Consume one JSON string starting at $offset (which must point at the
     * opening quote) and return its DECODED content — escape sequences
     * resolved to the actual characters. Duplicate detection compares
     * SEMANTIC keys: {"a":1,"\u0061":2} is ONE key
     * spelled twice, exactly the parser-ambiguity the scan refuses
     * (json_decode canonicalizes both spellings into the same key). The
     * JSON string grammar is decoded with json_decode itself (the
     * surrogate-safe canonical decoder): \uXXXX pairs, \" \\ \/ \b \f \n
     * \r \t and every mixed form land on their real characters. null when
     * the string cannot be walked or its content is not decodable (a
     * malformed document — the strict json_decode check that follows
     * returns 422 INVALID_JSON).
     *
     * @param int $offset position in the raw JSON string (by reference)
     */
    private function scanJsonString(string $json, int &$offset): ?string
    {
        $length = \strlen($json);
        if ($offset >= $length || $json[$offset] !== '"') {
            return null;
        }
        $start = $offset + 1;
        $offset++;
        while ($offset < $length) {
            $ch = $json[$offset];
            $offset++;
            if ($ch === '"') {
                $raw = substr($json, $start, $offset - $start - 1);
                try {
                    $decoded = json_decode('"'.$raw.'"', true, 512, JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    return null;
                }

                return \is_string($decoded) ? $decoded : null;
            }
            if ($ch === '\\') {
                if ($offset >= $length) {
                    return null;
                }
                // Skip the escaped character (\" \\ \/ \b \f \n \r \t
                // \uXXXX — a bare skip covers all of them; the exact
                // decode above canonicalizes them).
                $offset++;
            }
        }

        return null;
    }

    private function skipJsonWhitespace(string $json, int &$offset): void
    {
        $length = \strlen($json);
        while ($offset < $length) {
            $ch = $json[$offset];
            if ($ch !== ' ' && $ch !== "\t" && $ch !== "\n" && $ch !== "\r") {
                break;
            }
            $offset++;
        }
    }

    /**
     * All challenge responses share the private-document headers:
     *   Cache-Control: no-store, private, max-age=0   (never cache, never mirror)
     *   Pragma: no-cache                              (legacy proxies)
     *   Referrer-Policy: no-referrer                  (no referrer leakage from
     *                                                 an embedded widget context)
     *   X-Content-Type-Options: nosniff               (JSON must never be
     *                                                 re-sniffed as HTML)
     *
     * FRAME-ANCESTORS CSP: when risk.challenge_origin_allowlist
     * is non-empty, EVERY challenge response carries an EXPLICIT
     * `Content-Security-Policy: frame-ancestors <allowlisted origins,
     * space-separated>` — never inherited from default-src, so the allowlist
     * is exactly the framing contract of the challenge endpoint. An empty
     * allowlist emits NO CSP header (nothing to promise). The bundle emits
     * NO CORS headers at all (CORS is not authorization; the
     * origin checks above are, and they run on every response regardless).
     *
     * When a NEW risk continuity session was minted for this request, the
     * cookie is attached here — on every response path (success, deny, 422),
     * so the session the assessment keyed on is what the client carries.
     *
     * @param array<string, mixed> $data
     */
    private function privateJson(array $data, int $status = Response::HTTP_OK, ?Request $request = null, ?string $riskSession = null, bool $mintedCookie = false): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store, private, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        if ($this->challengeOriginAllowlist !== []) {
            $response->headers->set('Content-Security-Policy', 'frame-ancestors '.implode(' ', $this->challengeOriginAllowlist));
        }

        if ($mintedCookie && $request !== null && $riskSession !== null && $this->continuityCookie !== null) {
            $response->headers->setCookie($this->continuityCookie->cookie($request, $riskSession));
        }

        return $response;
    }
}

/**
 * @internal control-flow sentinel of the duplicate-JSON-key scan:
 *           thrown when the walker finds an object key it already
 *           saw at the same level. Carries the raw key for the error
 *           message. Never escapes the controller.
 */
final class DuplicateJsonKeyException extends \RuntimeException
{
    public function __construct(public readonly string $key)
    {
        parent::__construct();
    }
}

/**
 * @internal control-flow sentinel of the duplicate-JSON-key scan:
 *           thrown when the walker cannot advance through the
 *           document. The strict json_decode check handles the malformed
 *           body afterwards (422 INVALID_JSON). Never escapes the
 *           controller.
 */
final class MalformedJsonWalkException extends \RuntimeException
{
}
