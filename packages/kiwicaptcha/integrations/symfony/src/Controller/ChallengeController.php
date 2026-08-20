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
use Symfony\Component\HttpFoundation\IpUtils;
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
 * 14. CHAIN-TICKET / OPEN-CHAIN GATE (stage-2 issuance, risk.chaining):
 *     the chain is a SERVER-SIDE TRANSACTION OBLIGATION — the chain
 *     record and its obligation mapping
 *     ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId, keyed on
 *     the bounded pseudonymous obligation id of the (policy-epoch,
 *     scope, AUTHORITATIVE request-binding) triple — never a raw binding
 *     in a key) are created ATOMICALLY at the CHAIN_REQUIRED stage, so a
 *     client can never restart the transaction at stage 1 by discarding
 *     the ticket. The gate runs BEFORE any admission counter: the
 *     authoritative binding is resolved first (via
 *     risk.request_binding_authority when configured — a
 *     client-supplied request_binding is a HINT the authority accepts or
 *     refuses, never a value the server signs unexamined; without the
 *     authority the legacy static/attribute binding applies), the open
 *     chain of the current transaction is looked up
 *     (findOpenRequirement), and a PRESENTED ticket is validated —
 *     signature/expiry/structure — and REQUIRED to match the current
 *     transaction's obligation (a malicious different ticket gets 422
 *     before any state is touched); a request WITHOUT a ticket but WITH
 *     an open obligation AUTO-RESUMES the chain (never issue stage 1).
     *     The stage-2 state is then validated and the issued stage-2
     *     challenge inspected: pending -> RECOVER the exact already-issued
     *     challenge (no re-mint, no re-admission), missing/expired -> REARM
     *     for a fresh stage-2 mint (never a stage-1), consumed with a
     *     committed VALID result -> the FINAL DISPOSITION of the nonce is
     *     read from the post-solve disposition store (the same store the
     *     validator finalized BEFORE the application saw the outcome —
     *     the core's consumed result alone can never decide transaction
     *     terminality): Pass -> markVerified (the chain ends — the
     *     obligation is cleared atomically) + recover the challenge,
     *     StepUp -> markStepUpRequired + the terminal STEP_UP_REQUIRED
     *     response (the obligation is KEPT — the transaction stays bound
     *     to the step-up), Deny -> markDenied + the terminal risk-denied
     *     response (the obligation is KEPT), missing/pending disposition
     *     -> the retryable 503 (the final disposition was never durably
     *     established — never clear the obligation), consumed INVALID ->
     *     rearm (subject to admission), consumed with NO result -> the
     *     retryable 503 (indeterminate — never rearm). A chain in the
     *     TERMINAL step_up_required/denied state answers its terminal
     *     response directly — no issuance, the obligation stays bound, so
     *     a later request for the same transaction re-encounters the
     *     terminal state (never a new stage-1). The chain is then RESERVED
     *     with a SHORT owner-scoped lease (reservation_lease_secs, bounded
     *     by the record's own TTL — a crashed owner blocks retries for
     *     seconds):
 *     'busy' gets the retryable in-progress 503 and NEVER enters the
 *     issuance pipeline; every refusal or failure after the reservation
 *     RELEASES it with the owner token (a non-owner release is an atomic
 *     no-op). A durably issued stage-2 transitions the state via the
 *     IDEMPOTENT markIssued (a lost reply is recovered by READING the
 *     state — issued/verified with the current nonce means success;
 *     indeterminate state retains the minted challenge and NEVER rolls
 *     back the outstanding slot); an ADMITTED-but-proven-not-handed-out
 *     failure returns the outstanding slot (abortedBeforeHandoff). The
 *     issued stage-2 profile is the STRONGER of the state's signed
 *     required action and the current pre-issue decision (a transient
 *     risk decay can never downgrade the promised stage), and the
 *     stage-2 challenge's metadata sidecar carries the server-stamped
 *     chain id/depth in the PRIVATE chainId/chainDepth fields — the
 *     application's own cdata is preserved untouched. The chain is
 *     complete only when the stage-2 challenge VERIFIES (verified is
 *     TERMINAL). A ticket-bearing request is NEVER downgraded to an
 *     unchained issuance.
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
     * (risk.chaining): base64url([version, chainId, expiresAt]) "."
     * base64url(HMAC-SHA256), bounded to the accepted shape. The ticket's
     * signature and expiry are validated by the
     * ChainedChallengeTicketService, and the SERVER-HELD chain state
     * (read from the state store) owns the scope, policy epoch, chain
     * depth, request binding and required action; a ticket-bearing
     * request is NEVER downgraded to an unchained issuance.
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
         * The AUTHORITATIVE transaction-binding resolver
         * (risk.request_binding_authority; null = the legacy
         * static/attribute binding applies). When configured, the
         * transaction binding is resolved ONLY through the authority
         * (resolve($request, $scope, $presented)) — a client-supplied
         * request_binding is a HINT the authority accepts or refuses,
         * NEVER a value the server signs unexamined.
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface $bindingAuthority = null,
        /**
         * Trusted-edge TLS classification header (risk.trusted_tls_header;
         * null = the feature is off).
         */
        private readonly ?string $trustedTlsHeader = null,
        /**
         * CIDRs (or exact IPs) of the trusted edge proxies whose
         * TLS-classification header is honored (risk.trusted_tls_proxies).
         * The header is read ONLY when the DIRECT peer (REMOTE_ADDR — the
         * immediate connection) is inside this list; from every other peer
         * the header is ignored. Empty = the header is never read.
         */
        private readonly array $trustedTlsProxies = [],
        /**
         * The security-policy epoch a presented chain ticket must match
         * (risk.policy_version).
         */
        private readonly int $policyVersion = 1,
        /**
         * The durable post-solve disposition store (the SAME nonce-keyed
         * store the validator finalizes): a consumed-valid stage-2
         * challenge is NEVER terminal from the core's consumed result
         * alone — the controller reads the final disposition and only
         * then transitions the chain (Pass -> markVerified, StepUp ->
         * markStepUpRequired, Deny -> markDenied). Null = the
         * disposition cannot be read — a consumed-valid stage-2 fails
         * closed with the retryable 503 (never clears the obligation).
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore $postSolveDispositionStore = null,
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
                ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The client_context must be 1-64 characters of [a-z0-9+_,=:-].']],
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
        // absent, the configured static risk.request_binding applies. With a
        // request_binding_authority configured, the AUTHORITATIVE binding is
        // resolved ONLY through the authority — the client-presented value is
        // a HINT the authority accepts or refuses, NEVER a string the server
        // signs unexamined (a binding the authority cannot confirm for this
        // transaction is refused with 422 INVALID_REQUEST_BINDING BEFORE any
        // state is touched). Without the authority the existing
        // static/attribute behavior is unchanged: the value is validated
        // here (1..128 bytes, the identifier charset — the same shape rule
        // as the scope) BEFORE it reaches the issuer, so a malformed
        // binding can never be signed into a challenge; the verification
        // side enforces equality between the record's signed binding and
        // the binding the form POST carries.
        $presentedBinding = isset($payload['request_binding']) && $payload['request_binding'] !== null
            ? (string) $payload['request_binding']
            : null;
        if ($this->bindingAuthority !== null) {
            try {
                $requestBinding = $this->bindingAuthority->resolve($request, $scope, $presentedBinding);
            } catch (\InvalidArgumentException $e) {
                // The authority refused the presented binding for this
                // transaction (a client-changed binding is a transaction
                // mismatch) — refused before any state is touched; the
                // detail goes to the server log only.
                error_log(sprintf('kiwicaptcha: request binding authority refused the presented binding: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_REQUEST_BINDING', 'message' => 'The request binding does not match this transaction.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                );
            }
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
        } else {
            $requestBinding = $presentedBinding ?? $this->defaultRequestBinding;
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
        }

        // The continuity session is read up front (pure, no side effects) so
        // the rate-limit-hit feedback can attribute the refusal to the same
        // session signal the risk engine would key on. Minting stays in the
        // risk block — a rate-limited request never receives a cookie.
        $riskSession = $this->continuityCookie?->read($request);
        $mintedCookie = false;

        // CHAIN-TICKET / OPEN-CHAIN GATE (stage-2 issuance, risk.chaining)
        // — the TRANSACTION-OBLIGATION redesign: the chain + its obligation
        // mapping ({kiwi:<ns>}:chain-obligation:<obligationId> -> chainId,
        // keyed on the bounded pseudonymous obligation id of the
        // (policy-epoch, scope, AUTHORITATIVE request-binding) triple —
        // NEVER a raw binding in a Redis key) were created atomically at
        // the CHAIN_REQUIRED stage, so a client cannot restart the
        // transaction at stage 1 by discarding the ticket. The gate runs
        // BEFORE any admission control touches a counter — an invalid,
        // forged, foreign or expired ticket never consumes rate-limit
        // budget, risk state, scope-cap quota or an outstanding slot:
        //   - a PRESENTED ticket is validated (signature/expiry/structure)
        //     and REQUIRED to match the current transaction's open
        //     obligation — a malicious different ticket gets 422;
        //   - a request WITHOUT a ticket but WITH an open obligation
        //     AUTO-RESUMES the chain (never issue stage 1);
        //   - no obligation -> the ordinary stage-1 flow.
        // The stage-2 state is then validated, the issued stage-2
        // challenge inspected (recover / rearm / verify as the consumed
        // state demands) and the chain claimed with the SHORT
        // owner-scoped reservation; 'busy' (another owner's live lease)
        // gets the retryable in-progress 503 and NEVER enters the
        // pipeline, 'missing' is refused here too, before any counter
        // moves. Every refusal or failure AFTER the reservation releases
        // it with the owner token (the ticket is reusable — the chain is
        // not burned); a durably issued issuance transitions the state to
        // issued(stage2Nonce) exactly once, and only a VERIFIED stage-2
        // completes the chain (the obligation is cleared atomically).
        $chainId = null;
        $chainOwner = null;
        $chainRequirement = null;
        if ($this->chainTickets === null) {
            if ($chainTicket !== null) {
                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'Chain tickets are not accepted on this deployment.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        } else {
            if ($this->risk === null) {
                // Chaining requires the risk gateway (the extension wires
                // both together): the ticket's required strength cannot be
                // mapped to a challenge profile without it — fail closed,
                // never downgrade a chain to the default profile.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            // OPEN-CHAIN READ: the obligation of THIS transaction (policy
            // epoch + scope + authoritative binding — the unbound
            // transaction is the '' binding) — a plain read, no
            // transition.
            try {
                $chainRequirement = $this->chainTickets->findOpenRequirement($scope, $requestBinding ?? '', $this->policyVersion);
            } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException $e) {
                // The chain record is CORRUPT server state: a stage-2
                // issuance cannot be authorized — fail closed with the
                // retryable 503 (the detail goes to the server log only,
                // never to the client).
                error_log(sprintf('kiwicaptcha: malformed chain state: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            } catch (\Throwable $e) {
                // The chain state backend is unavailable: a stage-2
                // issuance cannot be authorized — fail closed (the detail
                // goes to the server log only).
                error_log(sprintf('kiwicaptcha: chain obligation read failed: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ($chainTicket !== null) {
                try {
                    $chainTicketPayload = $this->chainTickets->verify($chainTicket);
                } catch (\Throwable $e) {
                    // The ticket cannot be verified: a stage-2 issuance
                    // cannot be authorized — fail closed (the detail goes
                    // to the server log only).
                    error_log(sprintf('kiwicaptcha: chain ticket verification failed: %s', $e->getMessage()));

                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                if ($chainTicketPayload === null) {
                    return $this->privateJson(
                        ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid or expired.']],
                        Response::HTTP_UNPROCESSABLE_ENTITY,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                // OBLIGATION MATCH: the ticket's chain must BE the open
                // chain of the current transaction — a signed ticket for a
                // DIFFERENT transaction (a different authoritative binding
                // or scope computes a different obligation id) is a
                // malicious/foreign ticket and gets 422. The exception is
                // a TERMINAL chain (verified / legacy completed): its
                // obligation was cleared at verification, so the chain is
                // read DIRECTLY and the identity fields (scope, policy
                // epoch, authoritative binding) are re-checked against the
                // record.
                if ($chainRequirement === null || $chainRequirement->chainId !== (string) $chainTicketPayload['chainId']) {
                    try {
                        $direct = $this->chainTickets->requirementFor((string) $chainTicketPayload['chainId']);
                    } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException $e) {
                        error_log(sprintf('kiwicaptcha: malformed chain state: %s', $e->getMessage()));

                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    } catch (\Throwable $e) {
                        error_log(sprintf('kiwicaptcha: chain state read failed: %s', $e->getMessage()));

                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }
                    if ($direct === null
                        || $direct->scope !== $scope
                        || $direct->policyVersion !== $this->policyVersion
                        || $direct->requestBinding !== ($requestBinding ?? '')
                    ) {
                        return $this->privateJson(
                            ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket does not match this transaction.']],
                            Response::HTTP_UNPROCESSABLE_ENTITY,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }
                    $chainRequirement = $direct;
                }
                $chainId = (string) $chainTicketPayload['chainId'];
            } elseif ($chainRequirement !== null) {
                // AUTO-RESUME: no ticket presented, but an open obligation
                // exists for this transaction — the chain resumes at stage
                // 2 (a lost/cleared ticket never downgrades the flow to an
                // unchained stage-1 issuance).
                $chainId = $chainRequirement->chainId;
            }
            if ($chainId !== null) {
                // The owner token: a random per-request handle that scopes
                // the reservation — only THIS request may release or issue
                // its own reservation; every other owner's reservation is
                // untouchable.
                $chainOwner = bin2hex(random_bytes(16));
                $stageTwo = $this->prepareStageTwo($chainId, $chainOwner, $chainRequirement, $request, $riskSession, $mintedCookie);
                if ($stageTwo !== null) {
                    return $stageTwo;
                }
            }
        }

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
            $this->releaseChain($chainId, $chainOwner);

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

                $this->releaseChain($chainId, $chainOwner);

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
            // configured AND the DIRECT peer (REMOTE_ADDR) is inside
            // risk.trusted_tls_proxies, ONLY that header is read and its
            // value is validated against the bounded pattern (a malformed
            // value — including a DUPLICATE header, which is parser
            // ambiguity — is IGNORED: the request is assessed without a
            // TLS tag, never rejected). The header is trusted ONLY from an
            // explicitly trusted reverse proxy/CDN that strips
            // client-supplied values — the direct peer must be the trusted
            // proxy itself; from every other peer the header is ignored;
            // only the coarse classification is stored.
            $tlsTag = null;
            if ($this->trustedTlsHeader !== null && $this->tlsPeerIsTrusted($request)) {
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
                    // double-count and no reputation to attribute to. The
                    // reserved chain is released — the ticket stays usable.
                    $this->releaseChain($chainId, $chainOwner);

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
                    try {
                        $this->risk->honeypotEvidence(
                            $decoyField !== null ? RiskEventKind::DecoyFieldSubmitted : RiskEventKind::HoneypotTriggered,
                            $scope,
                            $clientIp,
                            $riskSession,
                            null,
                            $decision->decisionId,
                        );
                    } catch (\Throwable) {
                        // Evidence only — a recording failure never gates
                        // or breaks issuance (mirrors the validator's
                        // form-submission counterpart).
                    }
                }

                // CHAIN FLOOR (stage-2): the issued profile is driven by
                // the STRONGER of the server-held state's REQUIRED action
                // and the current pre-issue decision — a transient risk
                // decay can never downgrade the stage the chain promised
                // (e.g. a chain demanding Argon32 is still issued as
                // Argon32 when the pre-issue assessment currently says
                // Sha18). StepUp and Deny stay terminal: when the
                // effective action is StepUp, the application step-up
                // answers (403) and the reservation is released; a Deny
                // stays the risk-denied 429 with the same release.
                $effectiveAction = $chainRequirement !== null
                    ? $this->effectiveChainAction($decision->action, $chainRequirement->requiredAction->value)
                    : $decision->action;
                if ($effectiveAction === RiskAction::StepUp) {
                    // Step-up is application-defined (verified email link,
                    // passkey, existing session, TOTP...): KiwiCaptcha only
                    // says "PoW alone is insufficient for this request".
                    $this->releaseChain($chainId, $chainOwner);

                    return $this->privateJson(
                        ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']],
                        Response::HTTP_FORBIDDEN,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }

                if ($effectiveAction === RiskAction::Deny) {
                    // The denial already scored the evidence (the pre-issue
                    // assessment + decision) — no additional rate-limit
                    // event is recorded.
                    $body = ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']];
                    if ($decision->retryAfterMs !== null) {
                        $body['error']['retry_after_ms'] = $decision->retryAfterMs;
                    }
                    $this->releaseChain($chainId, $chainOwner);

                    return $this->privateJson($body, Response::HTTP_TOO_MANY_REQUESTS, $request, $riskSession, $mintedCookie);
                }
                $profile = $this->risk->profileForAction($effectiveAction);
            } elseif ($chainRequirement !== null) {
                // No pre-issue decision (the engine declined / degraded):
                // the server-held state's REQUIRED action is still the
                // floor — the stage-2 issuance can never be weaker than
                // what the chain promised. (The validator never writes
                // StepUp/Deny into the state — those are terminal
                // application-level actions — so this always maps to a
                // challenge profile.)
                $profile = $this->risk->profileForAction($chainRequirement->requiredAction);
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
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if (!$allowed) {
                $this->releaseChain($chainId, $chainOwner);

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
        // OUTSTANDING-ADMISSION BOOKKEEPING: the slot is HELD from the
        // moment the counters admit the challenge until the challenge is
        // successfully HANDED OFF. Every PROVEN-not-handed-out failure
        // after this point returns the slot
        // (OutstandingChallenges::abortedBeforeHandoff); an INDETERMINATE
        // failure (the chain state cannot be read after a thrown
        // issuance transition — the challenge may be the authoritative
        // issued stage-2) must NOT roll back.
        $outstandingAdmissionHeld = false;
        if ($this->outstanding !== null && $ttlSecs !== null) {
            $admitted = $this->outstanding->issue($clientIp, $ttlSecs);
            if ($admitted !== 1) {
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied: outstanding challenge limit reached. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            $outstandingAdmissionHeld = true;
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
            // from the chain's verified stage-1 nonce (server-held in the
            // state record). The nonces are server-minted random values,
            // so a collision is astronomically unlikely; this is the
            // fail-closed invariant check. The minted record is discarded,
            // the admitted outstanding slot is returned, the reservation
            // is released and the request refused like any other invalid
            // ticket.
            if ($chainRequirement !== null && $challenge->nonce === $chainRequirement->stage1Nonce) {
                $this->discardChallenge($challenge);
                $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket cannot re-run the same challenge stage.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        } catch (\InvalidArgumentException $e) {
            $this->releaseChain($chainId, $chainOwner);

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
            // to the server log only. The admitted outstanding slot is
            // returned and the reserved chain is released — the ticket is
            // reusable (the chain is not burned).
            error_log(sprintf('kiwicaptcha: challenge issuance failed the replica-wait barrier: %s', $e->getMessage()));
            $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);
            $this->releaseChain($chainId, $chainOwner);

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
                $this->discardChallenge($challenge);
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied: outstanding challenge limit reached. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            $outstandingAdmissionHeld = true;
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
        //
        // CHAIN IDENTITY: a stage-2 issuance STAMPS the chain id + depth
        // into the PRIVATE chainId/chainDepth metadata fields (never into
        // cdata — the application's own cdata is preserved untouched, so
        // the Siteverify response keeps returning the app's value). The
        // validator reads the metadata chainId at stage-2 verification and
        // refuses to open a THIRD stage: the chain ends at stage 2.
        if (($action !== null || $cdata !== null || $chainId !== null) && $this->metadataStore !== null) {
            try {
                $this->metadataStore->store(
                    $challenge->nonce,
                    new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(
                        $action,
                        $cdata,
                        $scope,
                        $chainId,
                        $chainId !== null ? 2 : 0,
                    ),
                    max(60, $challenge->ttlSecs) + 60,
                );
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: siteverify metadata store failed for nonce %s: %s', $challenge->nonce, $e->getMessage()));
                $this->discardChallenge($challenge);
                $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // CHAIN ISSUANCE (stage-2 ONLY) + RISK SIGNALS: the durable
        // issuance (challenge record + metadata identity) is transitioned
        // through the IDEMPOTENT owner-scoped markIssued (reserved(me) ->
        // issued(stage2Nonce) — a state TRANSITION, never a delete: the
        // issued record lets a retry RECOVER the issued challenge instead
        // of re-minting). The LOST-REPLY handling: after a THROWN
        // transition the chain state is READ — issued/verified with the
        // current nonce means the operation succeeded (continue), still
        // reserved by me means it never ran (retry once); when the state
        // cannot be read the outcome is INDETERMINATE — the minted
        // challenge is RETAINED (never delete state that may be
        // authoritative; the record expires naturally if unreferenced),
        // the reservation is NOT released and the outstanding slot is NOT
        // rolled back. Only a POSITIVELY established non-issuance
        // discards the challenge, releases and rolls back. Any other
        // post-admission failure (the risk signals below) rolls the slot
        // back and fails closed.
        try {
            if ($chainId !== null) {
                $chainResponse = $this->markStage2Issued($challenge, $chainId, $chainOwner, $clientIp, $outstandingAdmissionHeld);
                if ($chainResponse !== null) {
                    return $chainResponse;
                }
            }

            // A challenge was actually minted: feed the atomic
            // issuance-rate signal (resource-pressure headroom), the risk
            // issue-debt signal, and pair the challenge nonce to the
            // decision id so a later solve can be confirmed back to the
            // ORIGINAL decision (short-lived server-side mapping, TTL =
            // risk.nonce_to_decision_ttl_secs).
            $this->issuanceCounter?->record();
            if ($this->risk !== null && $riskAssessed && $decision !== null) {
                $this->risk->challengeIssued($scope, $clientIp, $riskSession, $decision->decisionId);
                $this->risk->attachDecisionForNonce($challenge->nonce, $decision->decisionId);
            }
        } catch (\Throwable $e) {
            // Any other post-admission issuance exception: the challenge
            // was PROVEN not handed out — the admitted outstanding slot
            // is returned, then the failure propagates (the caller maps
            // it to the closed response).
            $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);
            throw $e;
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

        // HANDOFF: the challenge is durably issued + stored, the metadata
        // identity persisted, and (stage 2) the chain durably
        // transitioned to issued(stage2Nonce) — the outstanding slot is
        // now the CLIENT's responsibility and is NOT rolled back.
        $outstandingAdmissionHeld = false;

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
     * Best-effort discard of a minted-but-not-handed-out challenge record
     * (the record expires on its own TTL if the discard fails).
     */
    private function discardChallenge(\KiwiCaptcha\Challenge $challenge): void
    {
        try {
            $this->storage?->delete($challenge->nonce);
        } catch (\Throwable) {
            // Best-effort discard; the record expires on its own TTL.
        }
    }

    /**
     * Best-effort release of a RESERVED chain after a refused or failed
     * stage-2 issuance, with the reservation OWNER token: the ticket
     * stays reusable — the chain is not burned. A release by a NON-owner
     * — or on a chain that is no longer in the reserved state — is an
     * atomic no-op (a failing request can never free another owner's
     * live reservation), and a release failure is harmless: the
     * reservation expires with the chain TTL. The caller must NOT release
     * for an INDETERMINATE markIssued outcome (the state could not be
     * read — the chain may be durably issued by this very request).
     */
    private function releaseChain(?string $chainId, ?string $chainOwner): void
    {
        if ($chainId === null || $chainOwner === null) {
            return;
        }
        try {
            $this->chainTickets?->release($chainId, $chainOwner);
        } catch (\Throwable) {
            // Best-effort; the reservation expires with the chain TTL.
        }
    }

    /**
     * Return an ADMITTED outstanding slot when the challenge was PROVEN
     * never handed out (OutstandingChallenges::abortedBeforeHandoff — the
     * per-source counter is decremented best-effort, floored at 0; the
     * GLOBAL counter decays by EXPIRE: deployment-wide pressure, never a
     * literal count). The caller must NOT roll back for an INDETERMINATE
     * failure (the chain state cannot be read after a thrown issuance
     * transition — the challenge may be the authoritative issued
     * stage-2).
     */
    private function rollbackOutstandingAdmission(bool $held, string $clientIp): void
    {
        if (!$held) {
            return;
        }
        try {
            $this->outstanding?->abortedBeforeHandoff($clientIp);
        } catch (\Throwable) {
            // Best-effort; the counter decays by its EXPIRE otherwise.
        }
    }

    /**
     * STAGE-2 STATE ENTRY (the chain gate, step 7): validate the chain
     * state, inspect the issued stage-2 challenge (recover / rearm /
     * verify as the consumed state demands — see
     * {@see self::inspectIssuedStage2()}), then claim the SHORT
     * owner-scoped reservation. Returns a response when the request must
     * NOT proceed into the issuance pipeline (the recovery of the
     * already-issued challenge — byte-identical, no re-mint, no
     * re-admission — the retryable in-progress 503, the indeterminate
     * consumed-state 503, the missing-chain 422), or null when the
     * pipeline may proceed with the reservation held (and $requirement
     * refreshed for the re-dispatch after a state race).
     */
    private function prepareStageTwo(string $chainId, string $chainOwner, ?\BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement &$requirement, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        for ($i = 0; $i < 3; $i++) {
            $state = $requirement?->state ?? 'available';
            if ($state === 'verified') {
                // TERMINAL VERIFIED RECOVERY: the chain completed durably
                // (the obligation was cleared atomically with the
                // verified transition) — a retry recovers the already-
                // issued challenge, with NO re-mint, NO re-admission. A
                // missing challenge record despite 'verified' is a
                // storage anomaly — the retryable 503.
                $recovered = $this->recoverIssuedResponse($requirement?->stage2Nonce, $request, $riskSession, $mintedCookie);
                if ($recovered !== null) {
                    return $recovered;
                }

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ($state === 'issued') {
                $inspection = $this->inspectIssuedStage2($chainId, (string) $requirement?->stage2Nonce, $request, $riskSession, $mintedCookie);
                if ($inspection !== null) {
                    return $inspection;
                }
                // The chain was REARMED (the issued challenge is
                // missing/expired or its committed result was INVALID):
                // the reservation + fresh stage-2 mint below issue a NEW
                // stage-2 challenge at the SAME OR STRONGER floor —
                // NEVER a stage-1.
            }
            if ($state === 'step_up_required') {
                // TERMINAL STEP-UP: the transaction is bound to its final
                // step-up disposition (the obligation mapping was KEPT) —
                // no challenge issuance, ever. A later request for the
                // same transaction re-encounters this terminal state.
                return $this->privateJson(
                    ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']],
                    Response::HTTP_FORBIDDEN,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ($state === 'denied') {
                // TERMINAL DENIAL: the transaction is bound to its final
                // denial disposition (the obligation mapping was KEPT) —
                // no challenge issuance, ever. A later request for the
                // same transaction re-encounters this terminal state.
                return $this->privateJson(
                    ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']],
                    Response::HTTP_TOO_MANY_REQUESTS,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            switch ($this->chainTickets->reserveStage2($chainId, $chainOwner)) {
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Available:
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::TakenOver:
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Retry:
                    return null;
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Busy:
                    // Another request holds the LIVE reservation for this
                    // chain: the issuance pipeline is NEVER entered — the
                    // duplicate work (risk, quota, outstanding, mint,
                    // metadata, accounting) cannot be amplified by one
                    // ticket. The retryable 503 lets the client poll
                    // until the owning request completes.
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'A challenge for this chain ticket is already in progress. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Issued:
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Verified:
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::StepUpRequired:
                case \BelConsulting\KiwiCaptchaBundle\Risk\ChainReservationResult::Denied:
                    // The state moved between the read and the reserve
                    // (another request transitioned the chain): re-read
                    // the requirement and re-dispatch once (bounded).
                    // The TERMINAL step_up_required/denied answers land in
                    // their terminal response branches above — never an
                    // issuance.
                    try {
                        $requirement = $this->chainTickets->requirementFor($chainId);
                    } catch (\Throwable $e) {
                        error_log(sprintf('kiwicaptcha: chain state read failed: %s', $e->getMessage()));

                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }
                    if ($requirement === null) {
                        return $this->privateJson(
                            ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']],
                            Response::HTTP_UNPROCESSABLE_ENTITY,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }
                    continue 2;
                default:
                    // ChainReservationResult::Missing — the chain state is
                    // absent/expired.
                    return $this->privateJson(
                        ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']],
                        Response::HTTP_UNPROCESSABLE_ENTITY,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
            }
        }

        return $this->privateJson(
            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
            Response::HTTP_SERVICE_UNAVAILABLE,
            $request,
            $riskSession,
            $mintedCookie,
        );
    }

    /**
     * INSPECT the already-issued stage-2 challenge of an ISSUED chain
     * (the chain gate, step 7) and decide the recovery:
     *
     *  - pending + valid record -> RECOVER the exact issuance response
     *    (the response may have been lost — the retry gets the SAME
     *    challenge, no re-mint, no re-admission),
     *  - missing/expired record -> REARM the chain (issued(nonce) ->
     *    available, pinned to the exact expected nonce) so the pipeline
     *    mints a FRESH stage-2 challenge (NEVER a stage-1),
     *  - consumed + committed VALID -> the core's consumed result is
     *    NEVER terminal by itself: the nonce's FINAL disposition is read
     *    from the post-solve disposition store (the validator finalized
     *    it BEFORE the application saw the outcome):
     *      Pass   -> markVerified (the chain ends; the obligation is
     *                cleared atomically) + the same challenge is
     *                recovered,
     *      StepUp -> markStepUpRequired (the obligation is KEPT — the
     *                transaction stays bound to the step-up) + the
     *                terminal STEP_UP_REQUIRED response (no issuance),
     *      Deny   -> markDenied (the obligation is KEPT) + the terminal
     *                risk-denied response (no issuance),
     *      missing/pending -> the retryable 503 (the final disposition
     *                was never durably established — never clear the
     *                obligation),
     *  - consumed + committed INVALID -> rearm (subject to the
     *    rate/outstanding/admission pipeline below),
     *  - consumed + NO committed result -> INDETERMINATE — the retryable
     *    temporary_unavailable (NEVER rearm while the first request may
     *    have been consumed successfully).
     *
     * Returns null when the chain was REARMED (the pipeline proceeds to
     * the reservation + mint).
     */
    private function inspectIssuedStage2(string $chainId, string $stage2Nonce, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        if ($this->storage === null) {
            // No challenge storage to inspect: the issued challenge's
            // state cannot be established — fail closed (retryable).
            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }
        try {
            $record = $this->storage->find($stage2Nonce);
        } catch (\Throwable $e) {
            error_log(sprintf('kiwicaptcha: stage-2 challenge inspection failed: %s', $e->getMessage()));

            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }
        if ($record === null) {
            // The issued challenge record is MISSING (expired or never
            // durably stored): rearm the chain for a fresh stage-2 mint.
            try {
                $rearmed = $this->chainTickets->rearmIssued($chainId, $stage2Nonce);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: chain rearm failed: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if (!$rearmed) {
                // A different transition won the race between the read and
                // the rearm (the exact expected nonce pins it) — the
                // retryable 503.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }

            return null;
        }
        $consumed = $this->storage instanceof \KiwiCaptcha\ConsumedStateReadableInterface
            ? $this->storage->consumedState($stage2Nonce)
            : null;
        if ($consumed === null) {
            // PENDING: the issued challenge is still live — RECOVER the
            // EXACT issuance response (no re-mint, no re-admission).
            return $this->privateJson($this->rebuildIssuanceResponse($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
        }
        $result = $consumed->consumedResult;
        if ($result === null) {
            // Consumed WITHOUT a committed result: INDETERMINATE — the
            // first request may have been consumed successfully. NEVER
            // rearm; the retryable 503.
            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }
        if ($result->valid) {
            // The stage was cryptographically SOLVED — but the core's
            // consumed result NEVER decides transaction terminality alone:
            // the nonce's FINAL disposition (the validator finalized it
            // durably BEFORE the application saw the outcome) drives the
            // chain transition. A missing/pending disposition means the
            // final disposition was never durably established (the
            // validator died between the core commit and the finalize) —
            // the retryable 503, and the obligation is NEVER cleared.
            $disposition = null;
            if ($this->postSolveDispositionStore !== null) {
                try {
                    $dispositionRecord = $this->postSolveDispositionStore->read($stage2Nonce);
                } catch (\Throwable $e) {
                    error_log(sprintf('kiwicaptcha: stage-2 disposition read failed: %s', $e->getMessage()));

                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                $disposition = $dispositionRecord?->disposition;
            }
            if ($disposition === null) {
                // No disposition store wired, or the record is
                // absent/expired/pending — the final disposition was never
                // durably established: never clear the obligation.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            switch ($disposition->kind) {
                case \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Pass:
                    // The FINAL disposition is PASS: transition to
                    // verified (idempotent; the obligation is cleared
                    // atomically only while it still points at this
                    // chain) instead of re-issuing, then recover the same
                    // challenge.
                    try {
                        $terminal = $this->chainTickets->markVerified($chainId, $stage2Nonce);
                    } catch (\Throwable $e) {
                        // LOST REPLY: read the state + confirm the exact
                        // nonce; do NOT return a final pass while the
                        // obligation may be uncleared.
                        error_log(sprintf('kiwicaptcha: chain verification transition failed: %s', $e->getMessage()));
                        try {
                            $current = $this->chainTickets->requirementFor($chainId);
                        } catch (\Throwable) {
                            $current = null;
                        }
                        if ($current === null || $current->stage2Nonce !== $stage2Nonce || $current->state !== 'verified') {
                            return $this->privateJson(
                                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                                Response::HTTP_SERVICE_UNAVAILABLE,
                                $request,
                                $riskSession,
                                $mintedCookie,
                            );
                        }
                        $terminal = \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::VerifiedSame;
                    }
                    if ($terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Conflict
                        || $terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Missing
                    ) {
                        // The chain moved under the transition — the
                        // retryable 503 (the client retries against the
                        // current state).
                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }

                    return $this->privateJson($this->rebuildIssuanceResponse($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
                case \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::StepUp:
                    // The FINAL disposition is STEP-UP: transition to the
                    // TERMINAL step_up_required (the obligation mapping is
                    // KEPT — the transaction stays bound to the step-up
                    // requirement) and answer the terminal
                    // STEP_UP_REQUIRED — no challenge issuance, ever.
                    try {
                        $terminal = $this->chainTickets->markStepUpRequired($chainId, $stage2Nonce);
                    } catch (\Throwable $e) {
                        error_log(sprintf('kiwicaptcha: chain step-up transition failed: %s', $e->getMessage()));
                        try {
                            $current = $this->chainTickets->requirementFor($chainId);
                        } catch (\Throwable) {
                            $current = null;
                        }
                        if ($current === null || $current->stage2Nonce !== $stage2Nonce || $current->state !== 'step_up_required') {
                            return $this->privateJson(
                                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                                Response::HTTP_SERVICE_UNAVAILABLE,
                                $request,
                                $riskSession,
                                $mintedCookie,
                            );
                        }
                        $terminal = \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::StepUpRequiredSame;
                    }
                    if ($terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Conflict
                        || $terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Missing
                    ) {
                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }

                    return $this->privateJson(
                        ['error' => ['code' => 'STEP_UP_REQUIRED', 'message' => 'Additional verification is required for this request.']],
                        Response::HTTP_FORBIDDEN,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                case \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::Deny:
                    // The FINAL disposition is DENY: transition to the
                    // TERMINAL denied (the obligation mapping is KEPT —
                    // the transaction stays bound to its final denial) and
                    // answer the terminal risk-denied response — no
                    // challenge issuance, ever.
                    try {
                        $terminal = $this->chainTickets->markDenied($chainId, $stage2Nonce);
                    } catch (\Throwable $e) {
                        error_log(sprintf('kiwicaptcha: chain denial transition failed: %s', $e->getMessage()));
                        try {
                            $current = $this->chainTickets->requirementFor($chainId);
                        } catch (\Throwable) {
                            $current = null;
                        }
                        if ($current === null || $current->stage2Nonce !== $stage2Nonce || $current->state !== 'denied') {
                            return $this->privateJson(
                                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                                Response::HTTP_SERVICE_UNAVAILABLE,
                                $request,
                                $riskSession,
                                $mintedCookie,
                            );
                        }
                        $terminal = \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::DeniedSame;
                    }
                    if ($terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Conflict
                        || $terminal === \BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult::Missing
                    ) {
                        return $this->privateJson(
                            ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                            Response::HTTP_SERVICE_UNAVAILABLE,
                            $request,
                            $riskSession,
                            $mintedCookie,
                        );
                    }

                    return $this->privateJson(
                        ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']],
                        Response::HTTP_TOO_MANY_REQUESTS,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                default:
                    // ChainRequired (or any other kind) is impossible for a
                    // stage-2 nonce — a stage-2 challenge never opens a
                    // third stage. Corrupt/unexpected state: fail closed.
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
            }
        }
        // Committed INVALID: rearm (subject to the rate/outstanding/
        // admission pipeline below).
        try {
            $rearmed = $this->chainTickets->rearmIssued($chainId, $stage2Nonce);
        } catch (\Throwable $e) {
            error_log(sprintf('kiwicaptcha: chain rearm failed: %s', $e->getMessage()));

            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }
        if (!$rearmed) {
            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        return null;
    }

    /**
     * RECOVERY of an ISSUED/VERIFIED chain (the terminal states): the
     * original stage-2 issuance already ran durably (challenge record +
     * metadata identity), so the retry READS the issued challenge record
     * (storage find by the state's stage2Nonce) and rebuilds the EXACT
     * issuance response the original request returned — nonce/prefix/
     * salt/algorithm/targetBits/ttl/minDurationMs plus the deterministic
     * decoy_field when the risk engine is enabled — with NO re-mint, NO
     * re-admission, NO re-consume. An issued/verified state NEVER allows
     * a second mint.
     *
     * Returns null when the chain's challenge record cannot be found (a
     * storage anomaly — the caller answers the retryable 503).
     */
    private function recoverIssuedResponse(?string $stage2Nonce, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        if (!\is_string($stage2Nonce) || $stage2Nonce === '' || $this->storage === null) {
            return null;
        }
        try {
            $record = $this->storage->find($stage2Nonce);
        } catch (\Throwable) {
            return null;
        }
        if ($record === null) {
            return null;
        }

        return $this->privateJson($this->rebuildIssuanceResponse($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * STAGE-2 ONLY: the IDEMPOTENT owner-scoped issuance transition
     * reserved(me) -> issued(stage2Nonce) with the LOST-REPLY recovery.
     * Returns null when the issuance is durably confirmed (the pipeline
     * continues to the risk signals + handoff), or a response for every
     * other outcome:
     *
     *  - a THROWN transition reads the chain state FIRST: issued/verified
     *    with the current nonce -> the operation SUCCEEDED (continue);
     *    still reserved by me -> the transition never ran (retry once);
     *    the state cannot be read -> INDETERMINATE: the minted challenge
     *    is RETAINED (never delete state that may be authoritative — it
     *    expires naturally if unreferenced), the reservation is NOT
     *    released and the outstanding slot is NOT rolled back (503);
     *  - 'conflict'/'not_owner'/'missing' -> POSITIVELY not issued with
     *    this nonce: the minted record is discarded, the slot returned,
     *    the reservation released (503).
     */
    private function markStage2Issued(\KiwiCaptcha\Challenge $challenge, string $chainId, string $chainOwner, string $clientIp, bool $outstandingAdmissionHeld): ?JsonResponse
    {
        try {
            $result = $this->chainTickets->markIssued($chainId, $chainOwner, $challenge->nonce);
        } catch (\Throwable $e) {
            // LOST REPLY: the transition MAY have happened — read the
            // chain state before touching anything.
            error_log(sprintf('kiwicaptcha: chain issuance transition failed: %s', $e->getMessage()));
            try {
                $current = $this->chainTickets->requirementFor($chainId);
            } catch (\Throwable) {
                $current = null;
            }
            if ($current === null) {
                // INDETERMINATE: retain the minted challenge, do NOT
                // release the reservation, do NOT roll back the
                // outstanding slot (the challenge may be the
                // authoritative issued stage-2).
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
            if (($current->state === 'issued' || $current->state === 'verified') && $current->stage2Nonce === $challenge->nonce) {
                // The transition succeeded before the throw — continue.
                return null;
            }
            if ($current->state === 'reserved' && $current->owner === $chainOwner) {
                // Still reserved by me: the transition never ran — retry
                // once.
                try {
                    $result = $this->chainTickets->markIssued($chainId, $chainOwner, $challenge->nonce);
                } catch (\Throwable) {
                    // The retry cannot be confirmed either — indeterminate
                    // again: retain.
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                    );
                }
            } else {
                // POSITIVELY not issued by this request (rearmed, owned
                // elsewhere, or vanished): discard + release + roll back.
                $this->discardChallenge($challenge);
                $this->releaseChain($chainId, $chainOwner);
                $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
        }
        switch ($result) {
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedNew:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedSame:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::VerifiedSame:
                return null;
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::Conflict:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::NotOwner:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::Missing:
                // POSITIVELY not issued with this nonce (the chain holds a
                // different one, is owned elsewhere, or vanished): the
                // minted record is discarded (a completed chain NEVER
                // allows a second mint: the client retries the ticket and
                // RECOVERS the challenge that was durably issued), the
                // slot is returned, the reservation is released.
                $this->discardChallenge($challenge);
                $this->releaseChain($chainId, $chainOwner);
                $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
        }
    }

    /**
     * Rebuild the EXACT issuance response of an already-issued stage-2
     * challenge from its stored record: the same key set and order the
     * original Challenge::toArray() produced (nonce, challenge, salt,
     * algorithm, mKib, t, p, targetBits, ttlSecs, minDurationMs, prefix)
     * plus the deterministic decoy_field when the risk engine is enabled
     * — byte-identical with the original response.
     *
     * @param array<string, mixed> $recordData a ChallengeRecord's toArray()
     */
    private function rebuildIssuanceResponse(\KiwiCaptcha\ChallengeRecord $record): array
    {
        $data = $record->toArray();
        $response = [
            'nonce' => $data['nonce'],
            'challenge' => $data['challenge'],
            'salt' => $data['salt'],
            'algorithm' => $data['algorithm'],
            'mKib' => $data['m_kib'],
            't' => $data['t'],
            'p' => $data['p'],
            'targetBits' => $data['target_bits'],
            'ttlSecs' => $data['expires_at'] - $data['issued_at'],
            'minDurationMs' => $data['min_duration_ms'],
            'prefix' => $data['prefix'],
        ];
        if ($this->risk !== null) {
            // Deterministic per issuance (the nonce is base64, so the name
            // is derived via sha256 to stay in the [0-9a-f] alphabet).
            $response['decoy_field'] = self::DECOY_FIELD_PREFIX.substr(hash('sha256', $data['nonce']), 0, 8);
        }

        return $response;
    }

    /**
     * Whether the DIRECT peer of the request (REMOTE_ADDR — the immediate
     * connection, never a forwarded header) is inside the configured
     * risk.trusted_tls_proxies CIDRs. The trusted-edge TLS header is read
     * ONLY from such a peer: the direct peer must be the trusted
     * proxy/CDN itself — from every other peer the header is ignored.
     */
    private function tlsPeerIsTrusted(Request $request): bool
    {
        $peer = (string) $request->server->get('REMOTE_ADDR', '');
        if ($peer === '') {
            return false;
        }
        foreach ($this->trustedTlsProxies as $cidr) {
            if (IpUtils::checkIp($peer, (string) $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The EFFECTIVE stage-2 action: the STRONGER of the chain ticket's
     * signed required action and the current pre-issue decision action.
     * The required action is never StepUp/Deny (the ticket format
     * excludes them — see ChainedChallengeTicketService::verify()), so a
     * StepUp/Deny effective action can only come from the current
     * decision and stays terminal.
     */
    private function effectiveChainAction(RiskAction $decisionAction, string $requiredAction): RiskAction
    {
        $required = RiskAction::from($requiredAction);

        return $decisionAction->rank() > $required->rank() ? $decisionAction : $required;
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
