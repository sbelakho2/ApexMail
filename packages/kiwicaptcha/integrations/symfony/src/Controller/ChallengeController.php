<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\UnknownScopeException;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\ScopeIssuanceCap;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Risk\RiskAction;
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
 * Hardening order: NARROW HTTP first (audit #77/#65: non-POST stays 405 —
 * an OPTIONS preflight alone never authorizes anything; HTTP FRAMING is
 * rejected before any body is read — audit #83: a request carrying BOTH
 * Content-Length and Transfer-Encoding, or a duplicate Content-Length, is
 * request-smuggling ambiguity and gets 400 FRAMING_REJECTED; Content-Encoding
 * other than identity and Content-Type other than application/json are
 * rejected with 415 before any body is read — no decompression bombs, no
 * form-encoded smuggling), then the query-parameter and JSON-field audit
 * (audit #72: the POST accepts ONLY scope / algorithm? / request_binding —
 * any query string or unknown JSON field is a debug/override probe and gets
 * 422), then same-origin (CORS IS NOT AUTHORIZATION — audit #63: origin
 * enforcement runs on EVERY security response; the bundle never emits CORS
 * headers at all, so there is no preflight path that could authorize), then
 * the optional origin allowlist (origin_rejected 403) and Fetch Metadata
 * check (CROSS_SITE_REJECTED 403) — the origin-laundering defenses, also
 * before any state is written — then scope read, then the PROCESS-LOCAL
 * emergency admission step (audit #70: the engine's per-process cap is
 * checked BEFORE any Redis issuance limiter — a saturated process refuses
 * with the 429 risk-denied response without a single Redis round trip),
 * then issuance rate limiting (per-client and deployment-global; a
 * per-client 429 records SourceRateLimitHit, a global 429 records
 * GlobalCapacityHit — the deployment-wide refusal is identity-neutral and
 * never contaminates the visitor's source reputation), then — when the
 * adaptive risk engine is enabled — the PRE-ISSUE risk assessment (a Deny
 * decision returns 429 RISK_DENIED before any challenge is minted; the
 * denial already scored the evidence, so NO further rate-limit event is
 * recorded — double-counting removed; an escalated action raises the
 * difficulty of the issued challenge, an unknown scope in 'reject' mode
 * returns 429 RISK_DENIED without issuing), then the PER-SCOPE issuance cap
 * (audit #89: when risk.max_challenges_per_scope_per_minute is set, the
 * atomic {kiwi:<ns>}:issuance:<scope>:<minute> fixed-window counter refuses
 * 429 SCOPE_LIMITED beyond the cap — a public site key + claimed origin can
 * no longer create unlimited billed work per scope), then issuance (every
 * minted challenge increments the atomic issuance-rate counter used by the
 * resource-pressure provider and is admitted into the bounded
 * outstanding-challenge counters — a cap refusal discards the minted record
 * and returns the risk-denied 429).
 *
 * The canonical client IP comes from {@see ClientIpResolver} (audit #64 —
 * risk.client_ip_mode / risk.trusted_proxies / risk.reject_ambiguous_
 * forwarding): the same IP that feeds the challenge binding tag, the
 * rate-limit identity and the risk source pseudonym, never a Host-header or
 * forwarding-header free-for-all.
 *
 * The expected same-origin comes from the configured public_base_url
 * (audit #78 — SERVER CONFIG, never the Host header): a forged Host can
 * never make a cross-origin request look same-origin.
 */
final class ChallengeController
{
    /**
     * The bundle's identifier charset (audit #96): scope/tenant identifiers
     * and request bindings may only carry these characters (1..128 — the
     * ceiling is embedded in the pattern). Stricter than the core's "no '|'"
     * shape rule — an identifier outside the charset is refused before it
     * can be signed into a challenge.
     */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The ONLY JSON fields the challenge POST accepts (audit #72). */
    private const ACCEPTED_PAYLOAD_FIELDS = ['scope', 'algorithm', 'request_binding'];

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
    ) {
    }

    public function challenge(Request $request): JsonResponse
    {
        // NARROW HTTP (audit #77): the endpoint is POST-only — at the
        // CONTROLLER level too (the route already restricts the method, but
        // a direct invocation must behave identically). An OPTIONS preflight
        // is a non-POST method: 405 — a preflight ALONE never authorizes
        // anything (audit #63).
        if ($request->getMethod() !== 'POST') {
            $response = $this->privateJson(
                ['error' => ['code' => 'METHOD_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts POST requests only.']],
                Response::HTTP_METHOD_NOT_ALLOWED,
            );
            $response->headers->set('Allow', 'POST');

            return $response;
        }

        // HTTP FRAMING (audit #83): a request carrying BOTH Content-Length
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

        // NO DECOMPRESSION BOMBS (audit #65): a request body that was
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

        // NARROW HTTP (audit #77): the challenge POST is a JSON document —
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

        // QUERY-PARAM HARDENING (audit #72): the endpoint accepts NO query
        // parameters — ?debug=1, ?algorithm=sha256 overrides, ?skip_pow=1
        // and friends are probes and get 422 before any state is touched.
        if ($request->query->count() > 0) {
            return $this->privateJson(
                ['error' => ['code' => 'QUERY_PARAMETERS_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts no query parameters.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        if ($this->sameOriginOnly && !$this->isSameOrigin($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'CROSS_ORIGIN_DENIED', 'message' => 'Cross-origin challenge requests are not allowed.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Origin laundering defense (audit #27): when an origin allowlist is
        // configured, the challenge POST MUST be attributable to one of the
        // allowlisted origins (Origin header, or the Referer origin as
        // fallback). Audit #43: the comparison is STRUCTURED NORMALIZATION —
        // scheme/host/effective-port, host lowercased, default ports
        // normalized, trailing dots stripped, IDN converted to punycode when
        // ext-intl is available, IPv6 literals kept bracketed. Audit #43
        // enforce_origin: when true, a request WITHOUT a usable Origin
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

        // Trusted client-IP policy (audit #64): the canonical IP comes from
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

        // The challenge POST is a JSON OBJECT with exactly the documented
        // fields (audit #72): scope, algorithm (accepted for
        // forward-compatibility, the issued algorithm always comes from the
        // server), request_binding. Unknown fields are debug/override probes
        // and get 422 — the endpoint never silently ignores extra control
        // surface. A non-object document is refused too (an empty JSON
        // object {} is valid — the fields are optional).
        $decoded = json_decode((string) $request->getContent(), false);
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
        ) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The challenge request fields must be strings.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        $scope = isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        // IDENTIFIER VALIDATION (audit #96): scope/tenant identifiers and
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

        // Transaction binding (audit #41): the widget sends the
        // request_binding field it carries (data-kiwi-request-binding); when
        // absent, the configured static risk.request_binding applies. The
        // value is validated here (1..128 bytes, the audit #96 identifier
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

        // LOCAL ADMISSION BEFORE REDIS (audit #70): the process-local
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

            try {
                $decision = $this->risk->preIssue($scope, $clientIp, $riskSession);
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
                    // assessment + decision) — NO extra rate-limit event is
                    // recorded, double-counting is removed.
                    $body = ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']];
                    if ($decision->retryAfterMs !== null) {
                        $body['error']['retry_after_ms'] = $decision->retryAfterMs;
                    }

                    return $this->privateJson($body, Response::HTTP_TOO_MANY_REQUESTS, $request, $riskSession, $mintedCookie);
                }
                $profile = $this->risk->decisionProfile($decision);
            }
        }

        // PER-SCOPE ISSUANCE CAP (audit #89): when
        // risk.max_challenges_per_scope_per_minute is configured, the
        // atomic {kiwi:<ns>}:issuance:<scope>:<minute> fixed-window counter
        // (INCR + EXPIRE 60 in one Lua script) refuses 429 SCOPE_LIMITED
        // beyond the cap — the public site key + claimed origin can no
        // longer create unlimited billed verification work per scope. The
        // check CONSUMES the slot it admits (a denial below is not
        // double-counted; a challenge minted and later discarded by the
        // outstanding race still counted — fail-safe direction). A Redis
        // failure propagates (fail closed: no challenge without a checked
        // scope bound).
        if ($this->scopeIssuanceCap !== null && !$this->scopeIssuanceCap->allow($scope)) {
            return $this->privateJson(
                ['error' => ['code' => 'SCOPE_LIMITED', 'message' => 'Too many challenges issued for this scope. Try again later.']],
                Response::HTTP_TOO_MANY_REQUESTS,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        try {
            $challenge = $profile !== null
                ? $this->issuer->issueWithProfile($scope, $clientIp, $profile, requestBinding: $requestBinding)
                : $this->issuer->issue($scope, $clientIp, $requestBinding);
        } catch (\InvalidArgumentException $e) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        // Anti-stockpiling (audit #26): admit the minted challenge into the
        // bounded outstanding counters — ONE atomic Lua checks BOTH caps
        // before incrementing (per-source + global, EXPIRE = remaining
        // challenge lifetime + ttl margin). A refusal here is a RACE the
        // pre-issuance checks did not see (concurrent issuances): the minted
        // record is discarded best-effort and the request gets the same 429
        // risk-denied response — a challenge is NEVER handed out when its
        // stockpile admission failed. A Redis failure propagates (fail
        // closed: no challenge without a checked stockpile bound).
        if ($this->outstanding !== null) {
            // The issued Challenge carries its lifetime (ttlSecs — the
            // record's expiresAt - issuedAt at mint time); the counter TTL
            // is that lifetime + the configured ttl margin.
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

        return $this->privateJson($challenge->toArray(), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * Same-origin check for the challenge endpoint.
     *
     * Requests WITHOUT an Origin header (same-origin navigation, curl,
     * non-browser clients) are allowed — a browser cross-site POST always
     * carries one. When present, the Origin must match the EXPECTED origin.
     *
     * Audit #78: the expected origin comes from SERVER CONFIG
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
     * (audit #43 — {@see self::normalizeOrigin()}: scheme lowercase, host
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
                // Audit #43: with enforce_origin, a request without a usable
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
     * components (audit #43): a canonical "{scheme}://{host}:{port}" string
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
     * All challenge responses share the private-document headers:
     *   Cache-Control: no-store, private, max-age=0   (never cache, never mirror)
     *   Pragma: no-cache                              (legacy proxies)
     *   Referrer-Policy: no-referrer                  (no referrer leakage from
     *                                                 an embedded widget context)
     *   X-Content-Type-Options: nosniff               (JSON must never be
     *                                                 re-sniffed as HTML)
     *
     * FRAME-ANCESTORS CSP (audit #71): when risk.challenge_origin_allowlist
     * is non-empty, EVERY challenge response carries an EXPLICIT
     * `Content-Security-Policy: frame-ancestors <allowlisted origins,
     * space-separated>` — never inherited from default-src, so the allowlist
     * is exactly the framing contract of the challenge endpoint. An empty
     * allowlist emits NO CSP header (nothing to promise). The bundle emits
     * NO CORS headers at all (audit #63 — CORS is not authorization; the
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
