<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\UnknownScopeException;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceCounter;
use BelConsulting\KiwiCaptchaBundle\Security\IssuanceRateLimiter;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
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
 * Hardening order: same-origin check first (cheap, no state written), then
 * the optional origin allowlist (origin_rejected 403) and Fetch Metadata
 * check (CROSS_SITE_REJECTED 403) — the origin-laundering defenses, also
 * before any state is written — then scope read, then issuance rate
 * limiting (per-client and deployment-global; a per-client 429 records
 * SourceRateLimitHit, a global 429 records GlobalCapacityHit — the
 * deployment-wide refusal is identity-neutral and never contaminates the
 * visitor's source reputation), then — when the adaptive risk engine is
 * enabled — the PRE-ISSUE risk assessment (a Deny decision returns 429
 * RISK_DENIED before any challenge is minted; the denial already scored the
 * evidence, so NO further rate-limit event is recorded — double-counting
 * removed; an escalated action raises the difficulty of the issued
 * challenge, an unknown scope in 'reject' mode returns 429 RISK_DENIED
 * without issuing), then issuance (every minted challenge increments the
 * atomic issuance-rate counter used by the resource-pressure provider and
 * is admitted into the bounded outstanding-challenge counters — a cap
 * refusal discards the minted record and returns the risk-denied 429).
 */
final class ChallengeController
{
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
    ) {
    }

    public function challenge(Request $request): JsonResponse
    {
        if ($this->sameOriginOnly && !$this->isSameOrigin($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'CROSS_ORIGIN_DENIED', 'message' => 'Cross-origin challenge requests are not allowed.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Origin laundering defense (audit #27): when an origin allowlist is
        // configured, the challenge POST MUST be attributable to one of the
        // allowlisted origins (Origin header, or the Referer origin as
        // fallback — the exact scheme/host/port must match). A launderer
        // framing a victim's browser into fetching this endpoint has no way
        // to control the Origin of a cross-site request; raw HTTP bots that
        // never send the header cannot be matched and are rejected too.
        // Refused BEFORE any state is written, rate-limit budget or CAPTCHA
        // issuance.
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

        $clientIp = (string) ($request->getClientIp() ?? '');
        $payload = json_decode((string) $request->getContent(), true);
        $scope = \is_array($payload) && isset($payload['scope']) ? (string) $payload['scope'] : 'default';

        // The continuity session is read up front (pure, no side effects) so
        // the rate-limit-hit feedback can attribute the refusal to the same
        // session signal the risk engine would key on. Minting stays in the
        // risk block — a rate-limited request never receives a cookie.
        $riskSession = $this->continuityCookie?->read($request);
        $mintedCookie = false;

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

        try {
            $challenge = $profile !== null
                ? $this->issuer->issueWithProfile($scope, $clientIp, $profile)
                : $this->issuer->issue($scope, $clientIp);
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
     * carries one. When present, the Origin must match the request's own
     * scheme://host[:port] (constant-time compare; trailing slashes
     * normalized). Cross-origin requests are rejected BEFORE any state is
     * written, so they consume no rate-limit budget.
     */
    private function isSameOrigin(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '') {
            return true;
        }
        $expected = rtrim($request->getScheme().'://'.$request->getHttpHost(), '/');

        return hash_equals($expected, rtrim($origin, '/'));
    }

    /**
     * Origin laundering defense: the request must carry an Origin header
     * (or a Referer whose URL yields an origin) whose scheme+host+port
     * EXACTLY matches one allowlisted origin. Comparison is component-wise
     * (scheme lowercase, host lowercase — DNS is case-insensitive; an absent
     * port defaults to the scheme's default), so "https://app.example.com"
     * matches Origin "https://app.example.com" and "https://APP.EXAMPLE.COM"
     * but never "https://app.example.com:8443" or "http://app.example.com".
     */
    private function originIsAllowlisted(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '') {
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

        $candidate = self::originComponents($origin);
        if ($candidate === null) {
            return false;
        }

        foreach ($this->challengeOriginAllowlist as $allowlisted) {
            $allowed = self::originComponents((string) $allowlisted);
            if ($allowed === null) {
                continue;
            }
            if ($candidate['scheme'] === $allowed['scheme']
                && $candidate['host'] === $allowed['host']
                && $candidate['port'] === $allowed['port']
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse an origin string into its exact comparison components:
     * ['scheme', 'host', 'port'] with the host lowercased and an absent
     * port defaulted per scheme (https 443, http 80 — "exact scheme/host/
     * port" comparison treats an explicit default port as equal).
     *
     * @return array{scheme: string, host: string, port: int}|null
     */
    private static function originComponents(string $origin): ?array
    {
        $parts = parse_url($origin);
        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        $scheme = strtolower((string) $parts['scheme']);
        $port = isset($parts['port'])
            ? (int) $parts['port']
            : ($scheme === 'https' ? 443 : ($scheme === 'http' ? 80 : -1));
        if ($port < 1) {
            return null;
        }

        return ['scheme' => $scheme, 'host' => strtolower((string) $parts['host']), 'port' => $port];
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

        if ($mintedCookie && $request !== null && $riskSession !== null && $this->continuityCookie !== null) {
            $response->headers->setCookie($this->continuityCookie->cookie($request, $riskSession));
        }

        return $response;
    }
}
