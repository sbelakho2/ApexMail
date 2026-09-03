<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Controller;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Http\JsonDuplicateKeyScanner;
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
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issues a new captcha challenge for the widget. The route is registered by
 * {@see \BelConsulting\KiwiCaptchaBundle\Routing\KiwiCaptchaRouteLoader} with
 * the bundle's configured `route_prefix` (bundle controllers are never
 * scanned for attribute routes). The pipeline is fail-closed and ordered:
 * path canonicality, narrow HTTP, singular security headers, bounded body,
 * duplicate-key scan, origin checks, admission and risk controls run before
 * any challenge is minted; every response is a private JSON document; see
 * {@see self::privateJson()}.
 */
final class ChallengeController
{
    use \BelConsulting\KiwiCaptchaBundle\Http\FramingChecksTrait;

    /**
     * The identifier charset for scopes and request bindings; the 1..128
     * ceiling is embedded in the pattern. Stricter than the core's "no '|'"
     * shape rule, so an identifier outside the charset is refused before it
     * can be signed into a challenge.
     */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._:-]{1,128}$/D';

    /** The JSON fields the challenge POST accepts. */
    private const ACCEPTED_PAYLOAD_FIELDS = ['scope', 'algorithm', 'request_binding', 'action', 'cdata', 'sitekey', 'decoy_field', 'honeypot', 'client_context', 'chain_ticket'];

    /**
     * The highest execution-program grammar version this node can emit.
     * Mirrors the core's ExecutionChallengeGenerator::MAX_EXECUTION_VERSION
     * (2 = the causal observe grammar; 1 = the construction-to-probe
     * grammar without opcode 33). The effective per-issuance version is
     * selected by {@see self::effectiveExecutionVersion()}; the capability
     * a client advertises is capped at this ceiling.
     */
    private const MAX_EXECUTION_VERSION = 3;

    /** Turnstile-compatible shapes, per Cloudflare's docs. */
    private const ACTION_PATTERN = '/^[a-z0-9_-]{1,32}$/i';
    private const CDATA_PATTERN = '/^[a-z0-9_-]{1,255}$/i';

    /**
     * The risk-v2 decoy markers: a server-issued honeypot field name, the
     * coarse capability descriptor for the client-context tag, and the
     * honeypot value bounded at 256 bytes (a bot's filler, evidence only).
     */
    private const DECOY_FIELD_PATTERN = '/^[A-Za-z0-9_-]{1,64}$/D';
    private const CLIENT_CONTEXT_PATTERN = '/^[a-z0-9+_,=:-]{1,64}$/D';
    private const MAX_HONEYPOT_VALUE_BYTES = 256;

    /**
     * The one-shot chain ticket presented by a stage-2 request:
     * base64url([version, chainId, expiresAt]) "." base64url(HMAC-SHA256).
     * The ChainedChallengeTicketService validates the signature and expiry;
     * the server-held chain state owns the scope, policy epoch, chain
     * depth, request binding and required action, so a ticket-bearing
     * request is never downgraded to an unchained issuance.
     */
    private const CHAIN_TICKET_PATTERN = '/^[A-Za-z0-9._:-]{1,256}$/D';

    /**
     * The floor for a stage-2 mint, seconds: the core refuses any challenge
     * TTL under one second, so a chain with less life left cannot hold a
     * valid stage-2 challenge at all. The practical minimum is higher; see
     * {@see self::stage2MinimumRemaining()}. This constant is only the
     * lower bound that practical minimum never drops below.
     */
    private const MIN_STAGE2_REMAINING_SECS = 1;

    /**
     * Solver and transport headroom for the practical stage-2 minimum
     * remaining lifetime: the minted challenge must be solvable within its
     * clipped TTL, including the solve time and the round trip back.
     */
    private const STAGE2_SOLVER_MARGIN_SECS = 5;

    /**
     * The trusted-edge TLS classification tag: 1-64 characters of
     * [a-z0-9_+:|:-], the same bound and charset as the risk-v2 contract.
     * A malformed value is ignored, never rejected: the tag is
     * probabilistic evidence, not a gate.
     */
    private const TRUSTED_TLS_TAG_PATTERN = '/^[a-z0-9_+:|:-]{1,64}$/i';

    /**
     * Headers carrying client identity or forwarding trust: each must
     * appear at most once, since intermediaries pick different values on
     * duplicates. A duplicate gets 400 `DUPLICATE_HEADER` before any
     * header-derived identity is trusted.
     */
    private const SECURITY_SINGULAR_HEADERS = ['origin', 'forwarded', 'x-forwarded-for', 'x-real-ip', 'content-type', 'content-encoding'];

    /**
     * Hard ceiling for the challenge request body: the language is tiny, so
     * 8 KiB is generous. Everything beyond it is refused before the
     * duplicate scan, JSON decode or risk admission consume anything.
     */
    private const MAX_CHALLENGE_BODY_BYTES = 8192;

    /**
     * The bounded shape of a challenge nonce for the cancellation
     * endpoint: base64 of 32 random bytes (44 chars, possibly ending in
     * '='), bounded to 1..64 characters of the base64/base64url alphabet.
     * The widget echoes the nonce the challenge endpoint issued, so any
     * nonce the server minted satisfies it; anything outside the bound is
     * refused before the storage or Redis state is touched.
     */
    private const CANCELLATION_NONCE_PATTERN = '/^[A-Za-z0-9+\/=_-]{1,64}$/D';

    /** The JSON fields the cancellation POST accepts. */
    private const ACCEPTED_CANCELLATION_FIELDS = ['nonce'];

    /**
     * Hard ceiling for the cancellation request body: the language is a
     * single bounded nonce, so 1 KiB is generous.
     */
    private const MAX_CANCELLATION_BODY_BYTES = 1024;

    private JsonDuplicateKeyScanner $jsonDuplicateKeyScanner;

    /**
     * The once-per-process gate warning guard: when risk.decoy_v3_enabled
     * is true but the confirmed central min_protocol_version floor is
     * below 3 (or unconfirmed), or when risk.execution_challenge is on
     * but the floor is below 4 (or unconfirmed).
     * Issuance then falls back to the safe unarmed emission.
     * This flag makes the actionable warning fire exactly once per
     * process instead of once per issuance, so an issuance-rate log
     * flood never drowns the signal.
     */
    private bool $decoyV3WarningLogged = false;

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
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Security\ExpectedOrigin $expectedOrigin = null,
        private readonly ?ScopeIssuanceCap $scopeIssuanceCap = null,
        private readonly ?SecurityEpochMonitor $epochMonitor = null,
        private readonly ?int $challengeTtlSecs = null,
        /**
         * The siteverify metadata retention margin (risk.redis
         * ttl_margin_secs): the metadata outlives the issued challenge by
         * exactly the configured retained-state margin, the same envelope
         * as the core consumed-state retention.
         */
        private readonly int $metadataRetentionMarginSecs = 60,
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
         * One-shot chain-ticket service for stage-2 issuance; null =
         * chaining disabled (a ticket-bearing request is then refused).
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService $chainTickets = null,
        /**
         * Transaction-binding resolver (risk.request_binding_authority);
         * null = the legacy static/attribute binding applies. When
         * configured, the binding is resolved only through the authority,
         * calling resolve($request, $scope, $presented): a client-supplied
         * request_binding is a hint the authority accepts or refuses,
         * never a value the server signs unexamined.
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface $bindingAuthority = null,
        /**
         * Trusted-edge TLS classification header (risk.trusted_tls_header;
         * null = the feature is off).
         */
        private readonly ?string $trustedTlsHeader = null,
        /**
         * CIDRs (or exact IPs) of the trusted edge proxies whose
         * TLS-classification header is honored. The header is read only
         * when the direct peer is inside this list; from every other peer
         * it is ignored.
         */
        private readonly array $trustedTlsProxies = [],
        /**
         * The security-policy epoch a presented chain ticket must match
         * (risk.policy_version).
         */
        private readonly int $policyVersion = 1,
        /**
         * The durable post-solve disposition store: a consumed-valid
         * stage-2 challenge is not terminal from the core's consumed
         * result alone. The controller reads the final disposition and
         * only then transitions the chain (Pass -> markVerified, StepUp
         * -> markStepUpRequired, Deny -> markDenied). Null = a
         * consumed-valid stage-2 fails closed with the retryable 503.
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore $postSolveDispositionStore = null,
        /**
          * The clock for the stage-2 remaining-lifetime clip (unix
          * seconds; null = time()). Injectable so the near-expiry
          * adversarial tests pin the chain's remaining lifetime exactly.
          */
        private readonly ?\Closure $now = null,
        /**
         * The protocol-v3 writer switch (risk.decoy_v3_enabled, default
         * false): when false, issuance never arms the authenticated
         * decoy and always emits protocol v2. A new binary stays
         * byte-compatible with parent-revision verifiers that reject
         * protocol 3 as unknown, even with the risk gateway wired. When
         * true, issuance may arm the decoy (protocol v3), subject to
         * {@see self::protocolV3EmissionEnabled()}: the central
         * security-policy floor must confirm >= 3 first, and any
         * uncertainty falls back to v2.
         */
        private readonly bool $decoyV3Enabled = false,
        /**
         * The ExecutionChallengeV1 gate (risk.execution_challenge,
         * default off). When true, issuance may arm the browser-
         * execution dimension, see
         * {@see self::executionArmingEnabled()}.
         * The issued challenge then carries an execution program the
         * driver must run, and the presented execution digest is
         * verified server-side.
         * A missing or wrong digest is the deterministic
         * execution-mismatch failure.
         * The dimension is supplementary evidence only, never the sole
         * acceptance boundary. The PoW proof and the record state
         * machinery always gate.
         * The gate is inert without an execution_key (never a
         * breakage, never an arm).
         */
        private readonly bool $executionGate = false,
        /**
         * The issuance-side logger (when the app has one): receives the
         * once-per-process warning when decoy_v3_enabled cannot take
         * effect because the central protocol floor is below 3 or
         * unconfirmed. A raising logger must never break issuance: the
         * warning path is best-effort.
         */
        private readonly ?LoggerInterface $logger = null,
        /**
         * The node's execution-program version cap (kiwi_captcha.
         * execution_version, default 1): the operator-side ceiling of the
         * grammar this deployment emits. Version 2 (the causal observe
         * grammar) is never emitted unless this cap is >= 2, the client
         * advertised the `Kiwi-Execution-Max-Version` header with a value
         * >= 2, and the confirmed central security-policy floor
         * ({kiwi:<ns>}:security-policy min_execution_version) is >= 2, see
         * {@see self::effectiveExecutionVersion()}. A node that never
         * raised the cap keeps emitting version-1 programs to every
         * client, byte-compatible with the construction-to-probe
         * grammar of earlier releases.
         */
        private readonly int $executionVersionCap = 1,
        private readonly int $executionRequiredVersion = 1,
    ) {
        $this->jsonDuplicateKeyScanner = new JsonDuplicateKeyScanner();
    }

    /**
     * Whether this issuance arms the ExecutionChallengeV1 dimension,
     * the cleanest seam for the risk gate. The dimension is armed when
     * the risk.execution_challenge gate is on, a risk trigger passes,
     * and the two-phase protocol-v4 rollout gate confirms the central
     * security-policy floor is >= 4, see
     * {@see self::executionV4EmissionEnabled()}.
     * With the risk engine wired, the trigger is a non-Allow pre-issue
     * decision, the same population the decoy surface targets.
     * Without the risk engine, the gate itself is the trigger, so a
     * deployment that turned the gate on arms every issuance. The program is generated from the challenge
     * context inside the issuer, see
     * {@see \KiwiCaptcha\Issuer::issueWithExecutionField()}.
     *
     * @param array{decision: \KiwiCaptcha\Risk\RiskDecision, action: \KiwiCaptcha\Risk\RiskAction}|null $riskDecision the resolved pre-issue decision, null when risk declined or was not wired
     */
    private function executionArmingEnabled(?array $riskDecision): bool
    {
        if (!$this->executionGate) {
            return false;
        }
        // The gate is inert without the keyed-PRF key: the issuer cannot
        // mint an execution program, so an armed issuance would refuse at
        // request time — a guaranteed outage. The controller arms only
        // when the key is configured (see Config::$executionKey).
        if ($this->issuer->config()->executionKey === null) {
            return false;
        }
        // The two-phase protocol-v4 rollout gate: execution arming
        // requires the confirmed central min_protocol_version floor
        // >= 4 (the decoy surface separately requires >= 3). A floor
        // below 4, an absent/corrupt/unreadable floor or no central
        // policy at all fails safe to execution-unarmed emission — the
        // writer never emits v4 until the fleet floor proves readers
        // support it.
        if (!$this->executionV4EmissionEnabled()) {
            return false;
        }
        if ($this->risk === null || $riskDecision === null) {
            // The risk engine is off (or declined to evaluate): the gate
            // alone is the trigger.
            return true;
        }

        return $riskDecision['action'] !== RiskAction::Allow;
    }

    /**
     * The protocol-v4 emission gate implements the two-phase rollout
     * invariant for the execution dimension: execution arming
     * (risk.execution_challenge on) requires the confirmed central
     * security-policy floor ({kiwi:<ns>}:security-policy
     * min_protocol_version, read through the SecurityEpochMonitor's
     * cached central-policy snapshot) to be >= 4.
     * The floor establishes that every serving binary accepts protocol
     * v4 (the execution-capable canonical with the signed commitment)
     * before any node emits it.
     * A floor below 4, an absent or corrupt floor,
     * an unreadable central policy or no central policy at all (null
     * epoch monitor / null security Redis) all fail safe to
     * execution-unarmed emission: v4 is never armed on uncertainty.
     * The actionable warning fires once per process. The
     * SecurityEpochMonitor's refresh() runs earlier in the pipeline
     * (the max-stale check), so this read is the freshest cached
     * central state.
     */
    private function executionV4EmissionEnabled(): bool
    {
        $floor = $this->epochMonitor?->minProtocolVersion();
        if ($floor !== null && $floor >= 4) {
            return true;
        }
        if (!$this->decoyV3WarningLogged) {
            $this->decoyV3WarningLogged = true;
            $detail = $floor === null
                ? 'no confirmed central min_protocol_version (the policy hash is absent, corrupt, unreadable, or no security Redis is configured)'
                : sprintf('the central min_protocol_version is %d', $floor);
            $message = sprintf(
                'kiwicaptcha: risk.execution_challenge is on but protocol-v4 emission stays DISABLED — %s (below 4). '.
                'Raise the central {kiwi:<ns>}:security-policy min_protocol_version to 4 only after every serving binary accepts protocol v4 '.
                '(deploy the new binaries fleet-wide and confirm no old binary remains); until then issuance stays execution-unarmed '.
                '(protocol v3 at most, or v2 when the decoy floor is unmet too).',
                $detail,
            );
            try {
                $this->logger?->warning($message);
            } catch (\Throwable) {
                // A raising logger must never break issuance.
            }
        }

        return false;
    }

    /**
     * The effective execution-program grammar version of this issuance,
     * the real execution-versioning gate of the dimension.
     *
     * Version 2 (the causal observe grammar, opcode 33) is emitted only
     * when every rung of the gate is up:
     *
     *  1. the client advertised the `Kiwi-Execution-Max-Version` header
     *     with a value >= 2, and an older client never advertises, so it
     *     receives version 1;
     *  2. the node cap kiwi_captcha.execution_version is >= 2, so the
     *     operator never emits v2 without raising the cap;
     *  3. the confirmed central security-policy hash
     *     {kiwi:<ns>}:security-policy carries min_execution_version
     *     >= 2, the fleet floor.
     *
     * A policy that is absent, unreadable or unconfirmed reads null,
     * so only version 1 may be emitted: the mirror of the protocol-v4
     * rule, where no confirmed central policy means no arming. A
     * confirmed policy without the key reads 0, a permissive state
     * with no declared floor that is still below 2, so version 2 is
     * never emitted until the operator declares the floor explicitly.
     *
     * Everything else emits version 1, the construction-to-probe
     * grammar with opcodes 0..32 and no observe opcode, which every
     * interpreter generation runs. The two generations are
     * distinguishable by the version byte alone, so a mixed fleet of
     * old binaries and stale open pages can never be handed the newer
     * grammar by accident.
     *
     * The protocol-v4 emission gate, {@see self::executionArmingEnabled()},
     * stays the protocol gate: arming itself still requires the
     * confirmed central min_protocol_version floor >= 4.
     */
    private function effectiveExecutionVersion(int $clientCapability): int
    {
        $floor = $this->epochMonitor?->minExecutionVersion();
        // The version ladder: 3 when the client, the node cap and the
        // confirmed central floor all reach 3; 2 when they all reach 2;
        // otherwise 1. The floor is null when no central policy is
        // confirmed, which never permits the newer grammars.
        if ($clientCapability >= 3 && $this->executionVersionCap >= 3 && $floor !== null && $floor >= 3) {
            return 3;
        }
        if ($clientCapability >= 2 && $this->executionVersionCap >= 2 && $floor !== null && $floor >= 2) {
            return 2;
        }

        return 1;
    }

    /**
     * The protocol-v3 emission gate implements the audit's two-phase
     * rollout invariant: the decoy (protocol v3) is armed only when the
     * operator's writer switch (risk.decoy_v3_enabled) is true. The
     * confirmed central security-policy floor
     * ({kiwi:<ns>}:security-policy min_protocol_version, read through
     * the SecurityEpochMonitor's cached central-policy snapshot) must
     * also be >= 3. The floor is the fleet-wide reader capability
     * statement: the readiness probe keeps every binary whose max
     * protocol is below the floor out of the pool. A floor >= 3
     * therefore means every serving verifier accepts protocol v3 before
     * any node emits it. A floor below 3, an absent or corrupt floor, an
     * unreadable central policy or no central policy at all (null epoch
     * monitor / null security Redis) all fail safe to protocol v2
     * emission. v3 is never armed on uncertainty. The actionable warning
     * fires once per process. The SecurityEpochMonitor's refresh() runs
     * earlier in the pipeline (the max-stale check), so this read is the
     * freshest cached central state.
     */
    private function protocolV3EmissionEnabled(): bool
    {
        if (!$this->decoyV3Enabled) {
            return false;
        }
        $floor = $this->epochMonitor?->minProtocolVersion();
        if ($floor !== null && $floor >= 3) {
            return true;
        }
        if (!$this->decoyV3WarningLogged) {
            $this->decoyV3WarningLogged = true;
            $detail = $floor === null
                ? 'no confirmed central min_protocol_version (the policy hash is absent, corrupt, unreadable, or no security Redis is configured)'
                : sprintf('the central min_protocol_version is %d', $floor);
            $message = sprintf(
                'kiwicaptcha: risk.decoy_v3_enabled is true but protocol-v3 emission stays DISABLED — %s (below 3). '.
                'Raise the central {kiwi:<ns>}:security-policy min_protocol_version to 3 only after every serving binary accepts protocol v3 '.
                '(deploy the new binaries fleet-wide and confirm no old binary remains); until then issuance keeps emitting protocol v2.',
                $detail,
            );
            try {
                $this->logger?->warning($message);
            } catch (\Throwable) {
                // A raising logger must never break issuance.
            }
        }

        return false;
    }

    public function challenge(Request $request): JsonResponse
    {
        // Path canonicality: the raw request URI must be the canonical
        // target, with no empty segments, dot segments, percent-encoded
        // bytes, trailing slash or backslashes. A noncanonical target gets
        // 404 `CANONICAL_PATH_REQUIRED` before any handling; the proxy stack
        // should reach the same decision at the edge.
        if (!$this->isCanonicalRequestTarget((string) $request->getRequestUri())) {
            return $this->privateJson(
                ['error' => ['code' => 'CANONICAL_PATH_REQUIRED', 'message' => 'The request target must be the canonical path (no empty, dot or percent-encoded segments).']],
                Response::HTTP_NOT_FOUND,
            );
        }

        // Narrow HTTP: the endpoint is POST-only, enforced here too (the
        // route already restricts the method, but a direct invocation must
        // behave identically). An OPTIONS preflight is a non-POST method
        // and gets 405.
        if ($request->getMethod() !== 'POST') {
            $response = $this->privateJson(
                ['error' => ['code' => 'METHOD_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts POST requests only.']],
                Response::HTTP_METHOD_NOT_ALLOWED,
            );
            $response->headers->set('Allow', 'POST');

            return $response;
        }

        // The universal canonical-framing rule (the ONE definition of the
        // HTTP framing policy, shared by every security-sensitive
        // endpoint): Content-Length singular + canonical decimal grammar,
        // Transfer-Encoding singular + 'chunked' only + never with
        // Content-Length, Content-Type singular, Content-Encoding
        // singular.
        if (!$this->framingHeadersAcceptable($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'FRAMING_REJECTED', 'message' => 'The request carries ambiguous HTTP framing (Content-Length, Transfer-Encoding, Content-Type or Content-Encoding must each appear at most once, with canonical values).']],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // Body ceiling: the challenge language is tiny, so a giant body is
        // pure memory and CPU spend before the shared risk and Redis
        // admission controls. An oversized declared Content-Length is
        // rejected before any body is read (413); the actual read length
        // is capped too, since chunked uploads can skip a truthful
        // Content-Length. The value is canonical (the framing rule above
        // validated its grammar).
        $declaredLengths = $request->headers->all('content-length');
        foreach ($declaredLengths as $declared) {
            if (\is_string($declared) && (int) $declared > self::MAX_CHALLENGE_BODY_BYTES) {
                return $this->privateJson(
                    ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The challenge request body must not exceed '.self::MAX_CHALLENGE_BODY_BYTES.' bytes.']],
                    Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
                );
            }
        }
        // Duplicate security-singular headers: Origin, Forwarded,
        // X-Forwarded-For and X-Real-IP are identity and trust inputs, and
        // a duplicate occurrence is parser ambiguity (one intermediary
        // trusts the first value, another the last). Refused with a 400
        // before any header-derived identity is trusted; two identical
        // values still count as a duplicate.
        foreach (self::SECURITY_SINGULAR_HEADERS as $headerName) {
            if (\count($request->headers->all($headerName)) > 1) {
                return $this->privateJson(
                    ['error' => ['code' => 'DUPLICATE_HEADER', 'message' => sprintf('The %s header must appear at most once.', $headerName)]],
                    Response::HTTP_BAD_REQUEST,
                );
            }
        }

        // No decompression bombs: a compressed wire body must not be
        // decompressed by a downstream layer into unbounded memory. Any
        // Content-Encoding other than identity is refused before the body
        // is read.
        foreach ($request->headers->all('content-encoding') as $encoding) {
            if (strtolower((string) $encoding) !== 'identity') {
                return $this->privateJson(
                    ['error' => ['code' => 'UNSUPPORTED_CONTENT_ENCODING', 'message' => 'Content-Encoding must be identity (the widget POSTs plain JSON).']],
                    Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                );
            }
        }

        // Narrow HTTP: the challenge POST is a JSON document. Form-encoded
        // and multipart bodies are refused before anything is read (no
        // CSRF-form smuggling, no HTML-form replay). A present Content-Type
        // must be application/json (an optional charset parameter is
        // tolerated); an absent header is accepted, since the body still
        // has to parse as a strict JSON object with only the documented
        // fields. The widget sends exactly application/json.
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType !== '' && $contentType !== 'application/json') {
            return $this->privateJson(
                ['error' => ['code' => 'UNSUPPORTED_MEDIA_TYPE', 'message' => 'Content-Type must be application/json.']],
                Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
            );
        }

        // Body read: the input is consumed as a stream with a hard cap, so
        // at most MAX+1 bytes are ever materialized and a gigantic chunked
        // request cannot force PHP or Symfony to buffer the full body
        // before the 413. All header-level checks ran before this read.
        $requestBody = $this->readBoundedBody($request);
        if (\strlen($requestBody) > self::MAX_CHALLENGE_BODY_BYTES) {
            return $this->privateJson(
                ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The challenge request body must not exceed '.self::MAX_CHALLENGE_BODY_BYTES.' bytes.']],
                Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
            );
        }

        // Query-parameter hardening: the endpoint accepts no query
        // parameters; ?debug=1 and friends are probes and get 422 before
        // any state is touched.
        if ($request->query->count() > 0) {
            return $this->privateJson(
                ['error' => ['code' => 'QUERY_PARAMETERS_NOT_ALLOWED', 'message' => 'The challenge endpoint accepts no query parameters.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Security-state staleness: once now > last_success +
        // risk.security_epoch_max_stale_secs, the central policy may have
        // moved (an emergency revocation could have landed while this node
        // could not read), so issuance is refused with 503
        // `SERVICE_UNAVAILABLE`. Within the window the cached max keeps
        // serving.
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
        // configured, the challenge POST must be attributable to one of the
        // allowlisted origins (Origin header, or the Referer origin as
        // fallback). The comparison is a structured normalization of
        // scheme, host and effective port. With enforce_origin, a request
        // without a usable Origin header, or carrying the literal "null"
        // origin, is rejected before the allowlist is consulted. Refused
        // before any state is written.
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

        // Fetch Metadata signal (defense in depth): a browser laundering a
        // victim into a cross-site challenge request sends Sec-Fetch-Site:
        // cross-site. Raw HTTP bots lack the header entirely. Rejected
        // before any state is written.
        if ($this->enforceFetchMetadata) {
            $fetchSite = $request->headers->get('Sec-Fetch-Site');
            if ($fetchSite !== null && $fetchSite !== '' && strtolower($fetchSite) === 'cross-site') {
                return $this->privateJson(
                    ['error' => ['code' => 'CROSS_SITE_REJECTED', 'message' => 'Cross-site challenge requests are not allowed.']],
                    Response::HTTP_FORBIDDEN,
                );
            }
        }

        // Trusted client-IP policy: the canonical IP comes from the
        // configured mode (risk.client_ip_mode). In 'direct' mode
        // forwarding headers are ignored (socket peer only); in
        // 'symfony_trusted_proxies' mode Symfony's trusted-proxy machinery
        // ignores them from untrusted peers. An ambiguous double-forwarding
        // from a trusted peer is logged, or rejected with 400
        // `AMBIGUOUS_FORWARDING` when risk.reject_ambiguous_forwarding is
        // true, before any state is written.
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

        // Duplicate JSON keys: json_decode silently keeps the last
        // occurrence of a repeated object key, and intermediaries could
        // disagree on the effective value ({"scope":"login","scope":"signup"}
        // is a parser-ambiguity probe). The raw body is scanned with a
        // recursive duplicate-key detector before decoding; a duplicate at
        // any depth gets 422 `DUPLICATE_FIELD`. On a document it cannot walk,
        // the scanner returns null and the strict json_decode below handles
        // the malformed document.
        try {
            $duplicateKey = $this->scanForDuplicateJsonKey($requestBody);
        } catch (\BelConsulting\KiwiCaptchaBundle\Http\MalformedJsonWalkException) {
            // The scanner could not establish cleanliness (a >MAX_DEPTH
            // document or a malformed string): that is never treated as
            // clean — the document is refused, so a deep-nested first
            // value can never hide a duplicate from the scanner while the
            // final parser still accepts it.
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The challenge request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($duplicateKey !== null) {
            return $this->privateJson(
                ['error' => ['code' => 'DUPLICATE_FIELD', 'message' => 'The challenge request carries a duplicate JSON key: '.$duplicateKey.'.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // The challenge POST is a JSON object with exactly the documented
        // fields: scope, algorithm (accepted for forward-compatibility, the
        // issued algorithm always comes from the server), request_binding.
        // Unknown fields are debug or override probes and get 422. A
        // non-object document is refused too; an empty JSON object {} is
        // valid, since the fields are optional. The decoder's depth
        // ceiling is the same 32 as the scanner's, so a document the
        // scanner could not walk can never be accepted afterwards.
        try {
            $decoded = json_decode($requestBody, false, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The challenge request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
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
        // Risk-v2 decoy markers: the request may carry the server-issued
        // decoy field name (decoy_field), the filled honeypot value
        // (honeypot), and the coarse capability descriptor (client_context)
        // echoed back by the widget. All are bounded scalars; a malformed
        // marker is refused like any other malformed field. The markers are
        // probabilistic risk evidence, never a security gate.
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

        // Provider-compatible challenge metadata is validated here at
        // issuance, so a malformed action or cdata is never persisted or
        // returned.
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

        // Execution-capability advertisement: the client declares the
        // highest execution-program grammar version its interpreter can
        // run via the `Kiwi-Execution-Max-Version` HTTP request header.
        // The widget driver sends the header with value 2 when the
        // deployment configured the execution tier; absence, an empty
        // value, garbage or a value below 2 means the client only knows
        // version 1 (an older driver, a stale open page, or any client
        // that never advertises). The advertisement rides an ignorable
        // header, never a body field: a server generation that
        // validates challenge bodies against a closed field set would
        // answer 422 `UNKNOWN_FIELDS` to an unknown body field, while
        // an unknown header is ignored. The header is a capability
        // claim, not a security gate: a malformed value degrades to 1,
        // never a 422, and the issued version is further capped by the
        // node config and the central fleet floor, see
        // {@see self::effectiveExecutionVersion()}.
        $clientExecutionCapability = 1;
        $rawCapability = $request->headers->get('Kiwi-Execution-Max-Version');
        if (\is_string($rawCapability) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $rawCapability) === 1) {
            $clientExecutionCapability = (int) $rawCapability;
        }
        $clientExecutionCapability = max(1, min($clientExecutionCapability, self::MAX_EXECUTION_VERSION));


        // Identifier validation: scopes and request bindings must match
        // `[A-Za-z0-9._:-]+` with the 128-char ceiling before they reach
        // the issuer. The verification side enforces equality between the
        // record's signed values and what the form POST carries, so a
        // challenge minted under a valid identifier is never redeemable
        // under a different one.
        if (!preg_match(self::IDENTIFIER_PATTERN, $scope)) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => 'The scope must be 1-128 characters of [A-Za-z0-9._:-].']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Server-owned (sitekey, action) resolution: when the request
        // carries a sitekey with a configured policy, the security scope is
        // resolved from the (sitekey, action) pair. The browser never gets
        // to choose protected scope names; unknown actions are rejected,
        // never silently mapped to a default. Binding follows the global
        // binding_mode only.
        $sitekey = isset($payload['sitekey']) && $payload['sitekey'] !== '' ? (string) $payload['sitekey'] : null;
        $sitekeyTtlSecs = null;
        if ($sitekey !== null && isset($this->sitekeyPolicy[$sitekey])) {
            $policy = $this->sitekeyPolicy[$sitekey];
            // Per-sitekey challenge lifetime: the provider-migration TTL
            // override (risk.sitekeys.<sitekey>.ttl_secs, bounded 1..300 by
            // the config tree). When configured, the challenge is issued
            // with this lifetime instead of the global challenge_ttl_secs;
            // a sitekey without ttl_secs keeps the global default.
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

        // Migration sitekey alias: a public sitekey is optional legacy
        // metadata, never a secret. When the client sends a configured
        // sitekey, the scope is resolved from the server-owned mapping; an
        // unknown sitekey simply stays a scope name subject to the
        // allowed_scopes gate and the risk assessment below.
        if (isset($this->sitekeyAllowlist[$scope])) {
            $scope = $this->sitekeyAllowlist[$scope];
        }

        // Server-owned scope allowlist: when risk.allowed_scopes is
        // configured, issuance is refused for any scope outside the
        // server-defined set before the risk assessment and the quota
        // checks. This keeps the per-scope issuance cap an independent
        // security bound.
        if ($this->allowedScopes !== [] && !\in_array($scope, $this->allowedScopes, true)) {
            return $this->privateJson(
                ['error' => ['code' => 'SCOPE_NOT_ALLOWED', 'message' => 'This scope is not enabled for challenge issuance.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Transaction binding: the widget sends the request_binding field
        // it carries (data-kiwi-request-binding); when absent, the
        // configured static risk.request_binding applies. With a
        // request_binding_authority, the binding is resolved only through
        // the authority, and a binding it cannot confirm for this
        // transaction is refused with 422 `INVALID_REQUEST_BINDING` before
        // any state is touched. Without the authority, the value is
        // validated here (1..128 bytes, the identifier charset) before it
        // reaches the issuer.
        $presentedBinding = isset($payload['request_binding']) && $payload['request_binding'] !== null
            ? (string) $payload['request_binding']
            : null;
        // The continuity session is read up front (pure, no side effects)
        // so the binding-authority infrastructure-failure branch can emit
        // its private response with fully initialized variables — a
        // generic Throwable there must never cascade into undefined-
        // variable warnings or a TypeError from uninitialized optional
        // arguments. The rate-limit feedback below reuses the same read.
        $riskSession = $this->continuityCookie?->read($request);
        $mintedCookie = false;
        if ($this->bindingAuthority !== null) {
            try {
                $requestBinding = $this->bindingAuthority->resolve($request, $scope, $presentedBinding);
            } catch (\InvalidArgumentException $e) {
                // The authority refused the presented binding: a
                // client-changed binding is a transaction mismatch.
                // Refused before any state is touched; the detail goes to
                // the server log only.
                error_log(sprintf('kiwicaptcha: request binding authority refused the presented binding: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_REQUEST_BINDING', 'message' => 'The request binding does not match this transaction.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                );
            } catch (\Throwable $e) {
                // An infrastructure failure of the authority is never a
                // client 422: nothing has been touched, so the private
                // structured 503 is the retryable answer.
                error_log(sprintf('kiwicaptcha: request binding authority unavailable: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
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


        // Chain-ticket / open-chain gate (stage-2 issuance, risk.chaining):
        // the chain and its obligation mapping ({kiwi:<ns>}:chain-obligation:
        // <obligationId> -> chainId, keyed on the bounded pseudonymous
        // obligation id of the policy-epoch/scope/binding triple) were
        // created atomically at the `CHAIN_REQUIRED` stage, so a client cannot
        // restart the transaction at stage 1 by discarding the ticket. The
        // gate runs before any admission control touches a counter, so an
        // invalid, forged, foreign or expired ticket never consumes
        // rate-limit budget, risk state, scope-cap quota or an outstanding
        // slot:
        //   - a presented ticket is validated (signature, expiry, structure)
        //     and must match the current transaction's open obligation;
        //   - a request without a ticket but with an open obligation
        //     auto-resumes the chain (never issue stage 1);
        //   - no obligation means the ordinary stage-1 flow.
        // The stage-2 state is then validated, the issued stage-2 challenge
        // inspected (recover, rearm or verify as the consumed state demands)
        // and the chain claimed with a short owner-scoped reservation.
        // 'busy' (another owner's live lease) gets the retryable in-progress
        // 503 and never enters the pipeline; 'missing' is refused here too,
        // before any counter moves. Every refusal or failure after the
        // reservation releases it with the owner token, so the ticket is
        // reusable and the chain is not burned; a durable issuance
        // transitions the state to issued(stage2Nonce) exactly once, and
        // only a verified stage-2 completes the chain (the obligation is
        // cleared atomically). The stage-2 mint is additionally bounded by
        // the chain's remaining lifetime: the issued TTL is clipped to
        // min(configured TTL, expiresAt - now), and a chain with less than
        // 1 second of life left refuses the mint with the expired-chain
        // response, so the obligation is never re-extended to fit a
        // challenge.
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
                // mapped to a challenge profile without it, so this fails
                // closed.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            // Open-chain read: the obligation of this transaction (policy
            // epoch + scope + authoritative binding; the unbound
            // transaction is the '' binding). A plain read, no transition.
            try {
                $chainRequirement = $this->chainTickets->findOpenRequirement($scope, $requestBinding ?? '', $this->policyVersion);
            } catch (\BelConsulting\KiwiCaptchaBundle\Risk\MalformedChainedChallengeStateException $e) {
                // The chain record is corrupt server state: a stage-2
                // issuance cannot be authorized. Fail closed with the
                // retryable 503; the detail goes to the server log only.
                error_log(sprintf('kiwicaptcha: malformed chain state: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            } catch (\Throwable $e) {
                // The chain state backend is unavailable: fail closed. The
                // detail goes to the server log only.
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
                    // The ticket cannot be verified: fail closed. The
                    // detail goes to the server log only.
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
                // Obligation match: the ticket's chain must be the open
                // chain of the current transaction; a signed ticket for a
                // different transaction (a different authoritative binding
                // or scope computes a different obligation id) is a foreign
                // ticket and gets 422. The exception is a terminal chain
                // (verified / legacy completed): its obligation was cleared
                // at verification, so the chain is read directly and the
                // identity fields (scope, policy epoch, authoritative
                // binding) are re-checked against the record.
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
                // Auto-resume: no ticket presented but an open obligation
                // exists for this transaction, so the chain resumes at
                // stage 2. A lost or cleared ticket never downgrades the
                // flow to an unchained stage-1 issuance.
                $chainId = $chainRequirement->chainId;
            }
            if ($chainId !== null) {
                // The owner token: a random per-request handle that scopes
                // the reservation. Only this request may release or issue
                // its own reservation.
                $chainOwner = bin2hex(random_bytes(16));
                $stageTwo = $this->prepareStageTwo($chainId, $chainOwner, $chainRequirement, $request, $riskSession, $mintedCookie);
                if ($stageTwo !== null) {
                    return $stageTwo;
                }
            }
        }

        // Local admission before Redis: the process-local emergency window
        // (risk.hard_limits.process_per_second) is checked before any Redis
        // issuance limiter, so a saturated window refuses immediately with
        // the 429 risk-denied response (same shape as the engine's
        // HardRateLimit denial, retry_after_ms 1000) without a single Redis
        // round trip. The check is non-consuming
        // (RiskGateway::emergencyCapSaturated -> ProcessEmergencyCap::isOpen):
        // the engine's own consuming allow() inside assessPreIssue() below
        // remains the single consumer of the per-process budget, so a
        // request admitted here can still be denied there.
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
            // The rate limiter is inside the structured failure boundary:
            // a Redis outage (or a malformed Redis TIME — the limiter never
            // falls back to the host clock for its epochs) answers the
            // private 503 with the reservation released, never a raw 500.
            try {
                $rate = $this->rateLimiter->check($clientIp);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: issuance rate limiter unavailable: %s', $e->getMessage()));
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if ($rate !== 1) {
                // Attribute the refusal: a per-client 429 records
                // SourceRateLimitHit (bad on the source or session
                // reputation); the deployment-global 429 records
                // GlobalCapacityHit, which is identity-neutral. Unknown
                // scopes (reject/baseline modes) are skipped silently,
                // since there is no reputation to attribute to. The
                // attribution is best-effort: a valid 429 must never turn
                // into a 500 because the observability write failed.
                $scopeId = $this->riskScopeId($scope);
                if ($scopeId !== null) {
                    try {
                        if ($rate === -1) {
                            $this->risk?->globalCapacityHit($scopeId, $riskSession);
                        } else {
                            $this->risk?->sourceRateLimitHit($scopeId, $clientIp, $riskSession);
                        }
                    } catch (\Throwable) {
                        // best-effort by contract
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

        // Adaptive risk: read or mint the continuity session, assess the
        // source before any challenge is written, and act on the decision.
        // A store outage (the engine degrades internally) never blocks
        // issuance. An invalid client IP (no usable risk signal, e.g. a
        // misconfigured proxy) applies the scope's configured degraded
        // decision. An unknown scope depends on unknown_scope.mode:
        // 'minimum' (default) assesses it under the synthetic sha20 policy,
        // 'baseline' issues the default profile, 'reject' returns the
        // risk-denied 429 without issuing.
        $profile = null;
        $riskAssessed = false;
        // The ExecutionChallengeV1 risk trigger: the resolved pre-issue
        // decision (or null when the engine declined / was not wired).
        // executionArmingEnabled() arms the dimension when the gate is
        // on AND the trigger passes (a non-Allow decision; without the
        // risk engine, the gate alone).
        $executionRiskDecision = null;
        if ($this->risk !== null) {
            if ($riskSession === null) {
                $riskSession = $this->continuityCookie?->mint();
                $mintedCookie = $riskSession !== null;
            }

            // Trusted-edge TLS tag: when risk.trusted_tls_header is
            // configured and the direct peer is inside
            // risk.trusted_tls_proxies, that header is read and validated
            // against the bounded pattern. A malformed value, including a
            // duplicate header, is ignored, never rejected: the request is
            // assessed without a TLS tag. The header is trusted only from
            // an explicitly trusted reverse proxy or CDN that strips
            // client-supplied values; from every other peer it is ignored.
            // Only the coarse classification is stored.
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

            // Risk-v2 evidence: honeypot and decoy markers, the coarse
            // client-context descriptor and the trusted-edge TLS
            // classification ride the assessment as probabilistic evidence,
            // never a security gate.
            $v2 = $this->risk->clientContextV2($honeypotHit, $riskSession, $clientContext, $tlsTag);

            try {
                $decision = $this->risk->preIssue($scope, $clientIp, $riskSession, null, $v2);
                $riskAssessed = true;
            } catch (UnknownScopeException) {
                if ($this->risk->unknownScopeMode() === 'reject') {
                    // Reject mode: no challenge, same response as a Deny
                    // decision (429 `RISK_DENIED`), no baseline fallback. No
                    // risk feedback is recorded, since the engine declined
                    // to evaluate the scope. The reserved chain is
                    // released; the ticket stays usable.
                    $this->releaseChain($chainId, $chainOwner);

                    return $this->privateJson(
                        ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']],
                        Response::HTTP_TOO_MANY_REQUESTS,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                // 'baseline' mode: the adaptive engine declines, so issue
                // the default profile.
                $decision = null;
            } catch (\InvalidArgumentException) {
                // No usable risk signal (e.g. an unparseable client IP from
                // a misconfigured proxy): apply the scope's configured
                // degraded decision.
                $decision = $this->risk->degradedDecisionForScope($this->risk->scopeId($scope));
                $riskAssessed = true;
            }

            if ($decision !== null) {
                if ($honeypotHit) {
                    // Book the honeypot evidence event into the risk
                    // gateway, mirroring the challengeIssued feedback path.
                    // Evidence only: a recording failure never gates or
                    // breaks issuance.
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
                        // Evidence only: a recording failure never gates or
                        // breaks issuance (mirrors the validator's
                        // form-submission counterpart).
                    }
                }

                // Chain floor (stage-2): the issued profile is driven by
                // the stronger of the server-held state's required action
                // and the current pre-issue decision, so a transient risk
                // decay can never downgrade the stage the chain promised
                // (e.g. a chain demanding Argon32 is still issued as
                // Argon32 when the pre-issue assessment currently says
                // Sha18). StepUp and Deny stay terminal: when the effective
                // action is StepUp, the application step-up answers (403)
                // and the reservation is released; a Deny stays the
                // risk-denied 429 with the same release.
                $effectiveAction = $chainRequirement !== null
                    ? $this->effectiveChainAction($decision->action, $chainRequirement->requiredAction->value)
                    : $decision->action;
                // The risk trigger of the execution gate: the effective
                // action (chain floor included), so a stage-2 issuance
                // never loses the trigger its chain promised.
                $executionRiskDecision = ['decision' => $decision, 'action' => $effectiveAction];
                if ($effectiveAction === RiskAction::StepUp) {
                    // Step-up is application-defined (verified email link,
                    // passkey, existing session, and so on): KiwiCaptcha
                    // only says "PoW alone is insufficient for this
                    // request".
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
                    // assessment plus the decision), so no additional
                    // rate-limit event is recorded.
                    $body = ['error' => ['code' => 'RISK_DENIED', 'message' => 'Challenge issuance denied by the adaptive risk engine. Try again later.']];
                    if ($decision->retryAfterMs !== null) {
                        $body['error']['retry_after_ms'] = $decision->retryAfterMs;
                    }
                    $this->releaseChain($chainId, $chainOwner);

                    return $this->privateJson($body, Response::HTTP_TOO_MANY_REQUESTS, $request, $riskSession, $mintedCookie);
                }
                $profile = $this->risk->profileForAction($effectiveAction);
            } elseif ($chainRequirement !== null) {
                // No pre-issue decision (the engine declined or degraded):
                // the server-held state's required action is still the
                // floor, so the stage-2 issuance can never be weaker than
                // what the chain promised.
                $profile = $this->risk->profileForAction($chainRequirement->requiredAction);
            }
        }

        // Per-scope issuance cap: when
        // risk.max_challenges_per_scope_per_minute is configured, the
        // atomic {kiwi:<ns>}:issuance:<scopeIdentity>:<minute> fixed-window
        // counter (INCR + EXPIRE 60 in one Lua script) refuses 429
        // `SCOPE_LIMITED` beyond the cap. The check consumes the slot it
        // admits, so a denial below is not double-counted. The quota keys
        // on the server-owned scope identity (the risk policy's canonical
        // scope id), never on the raw scope string; when allowed_scopes is
        // configured, the quota namespace is bounded by the server-owned
        // set (HMAC-only keying hides attacker-controlled bytes, it does
        // not bound cardinality). A Redis failure propagates: fail closed.
        $canonicalScopeId = ScopeIssuanceCap::UNKNOWN_QUOTA_ID;
        if ($this->risk !== null) {
            try {
                $canonicalScopeId = $this->risk->scopeId($scope);
            } catch (UnknownScopeException) {
                // Unresolvable scope: shares the reserved unknown bucket.
            }
        }
        if ($this->scopeIssuanceCap !== null) {
            try {
                $allowed = $this->scopeIssuanceCap->allow($scope, $canonicalScopeId);
            } catch (\Throwable $e) {
                // The cap fails closed when the Redis server clock is
                // unavailable: no quota proof means no challenge issuance
                // (503, private envelope; the detail goes to the server log
                // only). Never silently fall back to per-host wall clocks
                // around window boundaries.
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

        // Anti-stockpiling pre-mint admission: when the effective challenge
        // TTL is known (the configured global challenge_ttl_secs, or a
        // per-sitekey ttl_secs override), the bounded outstanding counters
        // are admitted before the challenge state is created. The issuance
        // sequence is local cap -> issuer limiter -> risk assessment ->
        // scope cap -> outstanding counters -> mint + store, so every quota
        // check runs before the storage write. One atomic Lua checks both
        // caps before incrementing (per-source + global, EXPIRE = challenge
        // lifetime + ttl margin; profiles never change the signed
        // lifetime). A refused admission never mints anything; a Redis
        // failure propagates (fail closed).
        $ttlSecs = $sitekeyTtlSecs ?? $this->challengeTtlSecs;
        if ($chainId !== null && $chainRequirement !== null) {
            // Stage-2 TTL clip: the chain obligation is the absolute
            // ceiling of the stage-2 challenge lifetime, since a challenge
            // minted with the full configured TTL could stay
            // cryptographically valid after the chain state that
            // authorized it expired. The minted TTL is clipped to
            // min(configured TTL, expiresAt - now), the requirement's
            // signed absolute expiry, before the outstanding admission and
            // the mint.
            //
            // Insufficient remaining lifetime: when less than the practical
            // minimum challenge lifetime remains, the chain cannot hold a
            // usable stage-2 challenge; see
            // {@see self::stage2MinimumRemaining()}. The ticket is treated
            // as expired, the reservation is released, and the chain is
            // never re-created or re-signed with a fresh expiry.
            $remaining = $chainRequirement->expiresAt - $this->now();
            if ($remaining < $this->stage2MinimumRemaining()) {
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket is invalid, expired or already consumed.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            $ttlSecs = min($ttlSecs ?? $this->issuer->config()->ttlSecs, $remaining);
        }
        // Outstanding-admission bookkeeping: the slot is held from the
        // moment the counters admit the minted challenge until it is
        // successfully handed off. The admission runs after the mint (the
        // live-membership member is the minted nonce scored at its absolute
        // expiry, which exists only once the record is minted), so every
        // proven-not-handed-out failure after the admission returns the
        // slot and releases the reservation through the single cleanup
        // primitive, {@see self::rollbackUncommittedIssuance()} ->
        // OutstandingChallenges::abortedBeforeHandoff; an indeterminate
        // failure (the chain state cannot be read after a thrown issuance
        // transition, so the challenge may be the authoritative issued
        // stage-2) must not roll back.
        $outstandingAdmissionHeld = false;

        try {
            // The record carries server-owned issuance metadata (Siteverify
            // `hostname`), never signed, never sent. The value comes from
            // the server-configured public_base_url (the validated
            // expected origin), so a forged Host header can never
            // influence the reported hostname; without public_base_url
            // the hostname stays null.
            $hostname = $this->expectedOrigin?->host();
            // Issuance always uses the canonical client IP. A per-sitekey
            // ttl_secs override mints through a TTL-variant issuer,
            // {@see self::issuerForTtl()}, so the signed lifetime carries
            // the override. The adaptive-risk surface (risk wired) arms
            // the authenticated decoy: the issuer picks a random
            // pool name per issuance, {@see Issuer::issueWithDecoyField()},
            // signs it into the canonical payload (protocol v3 record) and
            // the challenge response carries the authenticated
            // decoy_field — there is NO second nonce-hash decoy scheme in
            // this controller. Arming is gated by the two-phase rollout
            // invariant, {@see self::protocolV3EmissionEnabled()}: the
            // operator's writer switch (risk.decoy_v3_enabled) must be
            // true AND the confirmed central min_protocol_version floor
            // must be >= 3; otherwise issuance emits protocol v2,
            // byte-identical to the pre-decoy format, so a new node can
            // never emit a challenge a parent-revision verifier rejects.
            $issuer = $this->issuerForTtl($ttlSecs);
            $armDecoy = $this->risk !== null && $this->protocolV3EmissionEnabled();
            // The ExecutionChallengeV1 seam: the dimension is armed when
            // the risk.execution_challenge gate is on AND a risk trigger
            // passes AND the confirmed central floor is >= 4, see
            // {@see self::executionArmingEnabled()}; the program is
            // generated from the challenge context inside the issuer
            // (an armed issuance writes protocol v4 with the signed
            // commitment). The provider-style action of the request
            // rides the program (bounded 1..32 chars, already validated
            // above) so the digest binds the action. The grammar
            // version of the program is the effective execution version
            // of this issuance, {@see self::effectiveExecutionVersion()}
            // — version 2 (the causal observe grammar) only when the
            // client advertised it, the node's execution_version cap is
            // >= 2 and the confirmed central min_execution_version
            // floor is >= 2; every other issuance stamps version 1.
            $armExecution = $this->executionArmingEnabled($executionRiskDecision);
            $executionVersion = $this->effectiveExecutionVersion($clientExecutionCapability);
            // The server-owned required execution tier: the client
            // capability declaration is never an authority over the
            // grammar a hostile solver must solve. When the deployment
            // requires execution version 2 and this request would be
            // execution-armed, a client that cannot solve version 2 is
            // refused with the deterministic client-unsupported
            // outcome (code below) — never downgraded to the weaker
            // version-1 grammar, never issued an unarmed challenge.
            // The refusal happens before any admission slot or record
            // commit, so nothing is minted or held.
            if ($armExecution && $executionVersion < $this->executionRequiredVersion) {
                return $this->privateJson(
                    ['error' => ['code' => 'CLIENT_EXECUTION_VERSION_UNSUPPORTED', 'message' => sprintf('This deployment requires the execution version %d client; reload the page or upgrade the widget.', $this->executionRequiredVersion)]],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            $challenge = $profile !== null
                ? $issuer->issueWithProfile($scope, $clientIp, $profile, requestBinding: $requestBinding, hostname: $hostname, armDecoyField: $armDecoy, armExecution: $armExecution, executionAction: $action, executionVersion: $executionVersion)
                : $issuer->issueWithExecutionField($scope, $clientIp, $armExecution, $requestBinding, $hostname, $action, $executionVersion, $armDecoy);
            // Chain stage binding: the newly minted challenge nonce must
            // differ from the chain's verified stage-1 nonce (server-held
            // in the state record). The nonces are server-minted random
            // values, so a collision is astronomically unlikely; this is a
            // fail-closed invariant check. On a match the minted record is
            // discarded, the admitted outstanding slot is returned, the
            // reservation is released and the request refused like any
            // other invalid ticket.
            if ($chainRequirement !== null && $challenge->nonce === $chainRequirement->stage1Nonce) {
                $this->discardChallenge($challenge);
                $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'INVALID_METADATA', 'message' => 'The chain ticket cannot re-run the same challenge stage.']],
                    Response::HTTP_UNPROCESSABLE_ENTITY,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        } catch (\InvalidArgumentException $e) {
            // A mint or issuance fault classified as a client-side invalid
            // argument: the challenge was proven not handed out, so the
            // admitted outstanding slot is returned and the reservation
            // released. The mint may have failed before the $challenge
            // variable was assigned; the nullable parameter handles both.
            $this->rollbackUncommittedIssuance($challenge ?? null, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

            return $this->privateJson(
                ['error' => ['code' => 'INVALID_SCOPE', 'message' => $e->getMessage()]],
                Response::HTTP_UNPROCESSABLE_ENTITY,
                $request,
                $riskSession,
                $mintedCookie,
            );
        } catch (ReplicaWaitException $e) {
            // Durability barrier failure: the configured wait_replicas
            // threshold could not be met, so the challenge was not handed
            // out. This is an operational condition (replica lag or
            // topology), not a client fault: 503 with the private/no-store
            // envelope and an opaque message. The admitted outstanding
            // slot is returned and the reserved chain is released, so the
            // ticket is reusable.
            error_log(sprintf('kiwicaptcha: challenge issuance failed the replica-wait barrier: %s', $e->getMessage()));
            // The mint's WAIT can fail before the $challenge variable is
            // ever assigned; the nullable parameter handles both phases.
            $this->rollbackUncommittedIssuance($challenge ?? null, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        } catch (\Throwable $e) {
            // Any other backend failure around the mint/store/admission
            // pipeline (a storage or network outage, a corrupted reply):
            // no raw backend exception crosses the HTTP boundary — the
            // challenge was proven not handed out, so the uncommitted
            // issuance attempt is rolled back and the private structured
            // 503 answers. A failure after the durable stage-2 commit is
            // handled inside the commit try block above, never here. The
            // issuer factory and the mint can throw before the $challenge
            // variable is ever assigned — the nullable parameter tolerates
            // the unassigned state, so the error-handling path itself can
            // never fault.
            error_log(sprintf('kiwicaptcha: challenge issuance backend failure: %s', $e->getMessage()));
            $this->rollbackUncommittedIssuance($challenge ?? null, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }

        // Anti-stockpiling admission (post-mint): the live-membership member
        // is the minted nonce scored at its Redis-clock deadline, which
        // exists only once the record is minted
        // (OutstandingChallenges::issue). The accounting lifetime is the
        // nominal challenge TTL plus the core verifier's permitted
        // future-issuance skew (Verifier::MAX_CLOCK_SKEW): under a
        // distributed issuer/verifier deployment an issuer clock up to 60s
        // ahead of the Redis clock can mint a record that stays
        // verifier-valid beyond its nominal TTL, and the outstanding
        // memberships must keep counting it for the complete
        // core-validity envelope (a hard anti-stockpiling bound may
        // overcount, never undercount). The admission runs before handoff,
        // so a refused admission discards the minted record and never
        // hands out; a refusal here is a race the earlier checks did not
        // see (concurrent issuances).
        if ($this->outstanding !== null) {
            try {
                $admitted = $this->outstanding->issue(
                    $clientIp,
                    $challenge->nonce,
                    max(1, $challenge->ttlSecs) + \KiwiCaptcha\Verifier::MAX_CLOCK_SKEW,
                );
            } catch (\Throwable $e) {
                // The admission is the last pre-handoff step and the
                // challenge has not been handed out: a Redis failure
                // (or a violated verified-WAIT barrier) is resolved by
                // rolling the entire issuance attempt back — the minted
                // record is discarded, the admission is aborted
                // (one-shot and idempotent: if the EVAL landed before the
                // reply was lost, the abort releases it; if it never
                // landed, it does nothing), the chain reservation is
                // released, and the request answers the private
                // structured 503 — never an uncaught exception and never
                // a minted-but-never-handed-out record.
                error_log(sprintf('kiwicaptcha: outstanding admission failed for nonce_id=%s: %s', $this->nonceId($challenge->nonce), $e->getMessage()));
                $this->discardChallenge($challenge);
                $this->outstanding?->abortedBeforeHandoff($challenge->nonce);
                $this->releaseChain($chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
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

        // Provider-compatible challenge metadata (action / cData) is bound
        // to the nonce at issuance, server-side. If the sidecar cannot
        // persist it, the minted challenge is discarded and the request
        // fails 503, since a token whose verification would return no
        // action or cdata must never be handed out. The sidecar retention
        // of max(60, ttl) + 60 derives from the issued challenge's actual
        // ttlSecs.
        //
        // Chain identity: a stage-2 issuance stamps the chain id and depth
        // into the private chainId/chainDepth metadata fields, never into
        // cdata, so the application's own cdata is preserved untouched and
        // the Siteverify response keeps returning the app's value. The
        // validator reads the metadata chainId at stage-2 verification and
        // refuses to open a third stage: the chain ends at stage 2.
        if (($action !== null || $cdata !== null || $chainId !== null) && $this->metadataStore !== null) {
            try {
                $this->metadataStore->store(
                    $challenge->nonce,
                    new \BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadata(
                        $action,
                        $cdata,
                        null, // the sitekey is not resolved by the native challenge controller
                        $chainId,
                        $chainId !== null ? 2 : 0,
                        $scope,
                    ),
                    // The metadata retention equals the issued challenge's
                    // lifetime plus the configured retained-state margin —
                    // the same conservative clock/failover envelope as the
                    // core consumed-state retention, so the crash-recovery
                    // evidence can never outlive the metadata it needs.
                    max(60, $challenge->ttlSecs) + $this->metadataRetentionMarginSecs,
                );
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: siteverify metadata store failed for nonce_id=%s: %s', $this->nonceId($challenge->nonce), $e->getMessage()));
                $this->discardChallenge($challenge);
                $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
        }

        // Chain issuance (stage-2 only) and risk signals: the durable
        // issuance (challenge record + metadata identity) is transitioned
        // through the idempotent owner-scoped markIssued transition,
        // reserved(me) -> issued(stage2Nonce), so a retry can recover the
        // issued challenge instead of re-minting. Lost-reply handling:
        // after a thrown transition the chain state is read; issued or
        // verified with the current nonce means the operation succeeded
        // (continue), still reserved by me means it never ran (retry once). When the
        // state cannot be read the outcome is indeterminate: the minted
        // challenge is retained (never delete state that may be
        // authoritative; the record expires naturally if unreferenced),
        // the reservation is not released and the outstanding slot is not
        // rolled back. Only a positively established non-issuance discards
        // the challenge, releases and rolls back; any other post-admission
        // failure (the risk signals below) rolls the slot back and fails
        // closed.
        // The durable commit point: once the stage-2 chain state
        // confirms issued(N) — the transition itself carried the
        // verified replica-WAIT barrier — the challenge record, the
        // outstanding memberships and the chain are ALL authoritative.
        // Nothing after this point may roll any of them back: a rolled
        // back outstanding membership would resurrect a
        // valid-but-unaccounted challenge (the hard caps undercount), and
        // a discarded record would orphan the chain's issued(N) state.
        $stage2IssuedCommitted = false;
        try {
            if ($chainId !== null) {
                $chainResponse = $this->markStage2Issued($challenge, $chainId, $chainOwner, $clientIp, $outstandingAdmissionHeld);
                if ($chainResponse !== null) {
                    return $chainResponse;
                }
                $stage2IssuedCommitted = true;
            }

            // A challenge was actually minted: feed the atomic
            // issuance-rate signal (resource-pressure headroom), the risk
            // issue-debt signal, and pair the challenge nonce to the
            // decision id so a later solve can be confirmed back to the
            // original decision (short-lived server-side mapping, TTL =
            // risk.nonce_to_decision_ttl_secs).
            $this->issuanceCounter?->record();
            if ($this->risk !== null && $riskAssessed && $decision !== null) {
                $this->risk->challengeIssued($scope, $clientIp, $riskSession, $decision->decisionId);
                $this->risk->attachDecisionForNonce($challenge->nonce, $decision->decisionId);
            }
        } catch (\Throwable $e) {
            if ($stage2IssuedCommitted) {
                // Failure after the durable stage-2 commit (e.g. the risk
                // feedback): intentionally NO mutation — the challenge
                // record, the outstanding memberships and the chain's
                // issued(N) state all remain, and the private structured
                // 503 tells the client to retry (the retry recovers the
                // same issued challenge, byte-identical, with no re-mint
                // and no re-admission).
                error_log(sprintf('kiwicaptcha: post-commit issuance feedback failed for nonce_id=%s: %s', substr(hash('sha256', $challenge->nonce), 0, 16), $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            // Failure before any durable commit: the challenge was proven
            // not handed out, so the whole uncommitted issuance attempt is
            // rolled back (the minted record discarded, the admitted
            // outstanding slot returned, the chain reservation released);
            // then the failure propagates (the caller maps it to the
            // closed response).
            $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);
            throw $e;
        }

        // The handoff body is serialized from the stored record through
        // the single canonical issuance-response serializer,
        // {@see self::issuanceResponseFromRecord()}: the record was
        // durably stored by the issuer (the mint's storage write ran
        // before the commit point above), and the recovery paths
        // rebuild the response from that same stored record, so the
        // handoff body and every later recovery body are byte-identical
        // by construction — the response can never carry an
        // execution_program (or an authenticated decoy_field) the
        // stored record does not carry, and vice versa. The record is
        // derived from the same issuance, so the fields match
        // Challenge::toArray() exactly (ttlSecs = expires_at -
        // issued_at); execution_version and execution_commitment never
        // appear on the client-facing surface. Without a controller
        // storage reference (test-only wiring; the production
        // extension always wires one) the challenge object itself is
        // the same issuance and its toArray() key set is identical, so
        // it stands in for the record. A wired storage that cannot
        // confirm the stored record fails closed with the retryable
        // 503: handing out a challenge whose stored record is
        // unreadable would mint a response a recovery could not
        // reproduce and a solve could not verify.
        if ($this->storage === null) {
            $challengeData = $challenge->toArray();
        } else {
            $storedRecord = null;
            try {
                $storedRecord = $this->storage->find($challenge->nonce);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: stored-record read failed before handoff for nonce_id=%s: %s', $this->nonceId($challenge->nonce), $e->getMessage()));
            }
            if ($storedRecord === null) {
                if (!$stage2IssuedCommitted) {
                    // Proven not handed out: the whole uncommitted
                    // issuance attempt is rolled back.
                    $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);
                }
                // After the durable stage-2 commit there is
                // intentionally NO mutation: the retry recovers the
                // same issued challenge through the chain state.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            $challengeData = self::issuanceResponseFromRecord($storedRecord);
        }

        // Handoff: the challenge is durably issued and stored, the metadata
        // identity persisted, and (stage 2) the chain durably transitioned
        // to issued(stage2Nonce). The outstanding slot is now the client's
        // responsibility and is not rolled back.
        $outstandingAdmissionHeld = false;

        return $this->privateJson($challengeData, Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * Bounded cancellation endpoint, the server side of the
     * exhaustion->debt feedback break. A widget that abandons a challenge
     * (its bounded solve search exhausted on a stochastic tail) tells the
     * server to retire the record and release the deployment-wide
     * live-outstanding slot the abandoned challenge was holding. Mirrors
     * the challenge endpoint's hardening: POST-only, a bounded JSON body
     * carrying the challenge nonce, the same origin checks, a bounded
     * per-source limiter, and the private no-store envelope.
     *
     * Idempotent: an unknown, expired or already-cancelled nonce answers
     * the same success, and a consumed (finalized) challenge is never
     * cancelled. The storage's atomic pending->cancelled transition
     * decides ({@see \KiwiCaptcha\CancellableStorageInterface}), and the
     * response only ever acknowledges the cancellation, never record
     * contents. A fresh pending->cancelled transition also records the
     * ChallengeCancelled risk event exactly once per nonce, keyed on a
     * nonce-derived idempotency identity. The event is risk-neutral:
     * observability only, since the issue debt of the abandoned challenge
     * is never refunded; it decays naturally and only an actual solve
     * repays it. The deployment-wide live-outstanding slot and the
     * original source's outstanding slot are released only when the
     * storage actually cancelled the record and the nonce was still a
     * live member. The one-shot cancellation frees the global member and
     * decrements exactly the source that issued the challenge, from the
     * issuance sidecar and never the canceller's IP, at most once. A
     * duplicate cancel is a no-op. A consumed or missing nonce answers
     * the same success without freeing anything. A storage that cannot
     * establish the cancellation (not a
     * {@see \KiwiCaptcha\CancellableStorageInterface}) fails closed with
     * the retryable 503 and frees nothing: freeing the global gate while
     * the record stays pending and redeemable would be an
     * anti-stockpiling bypass. The per-source limiter is the
     * anti-stockpiling layer's own cancellation window; see
     * {@see OutstandingChallenges::cancellationAdmission()}. When that
     * layer is not wired, the endpoint stays bounded by the body ceiling,
     * the nonce shape and the origin checks.
     */
    public function cancel(Request $request): JsonResponse
    {
        // Path canonicality: identical gate to the challenge endpoint.
        if (!$this->isCanonicalRequestTarget((string) $request->getRequestUri())) {
            return $this->privateJson(
                ['error' => ['code' => 'CANONICAL_PATH_REQUIRED', 'message' => 'The request target must be the canonical path (no empty, dot or percent-encoded segments).']],
                Response::HTTP_NOT_FOUND,
            );
        }

        // Narrow HTTP: the endpoint is POST-only.
        if ($request->getMethod() !== 'POST') {
            $response = $this->privateJson(
                ['error' => ['code' => 'METHOD_NOT_ALLOWED', 'message' => 'The cancellation endpoint accepts POST requests only.']],
                Response::HTTP_METHOD_NOT_ALLOWED,
            );
            $response->headers->set('Allow', 'POST');

            return $response;
        }

        // The universal canonical-framing rule (the ONE definition of the
        // HTTP framing policy, shared by every security-sensitive
        // endpoint): Content-Length singular + canonical decimal grammar,
        // Transfer-Encoding singular + 'chunked' only + never with
        // Content-Length, Content-Type singular, Content-Encoding
        // singular.
        if (!$this->framingHeadersAcceptable($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'FRAMING_REJECTED', 'message' => 'The request carries ambiguous HTTP framing (Content-Length, Transfer-Encoding, Content-Type or Content-Encoding must each appear at most once, with canonical values).']],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // Body ceiling: the declared Content-Length is rejected before any
        // body is read (413); the actual read is capped too. The value is
        // canonical (the framing rule above validated its grammar).
        $contentLengths = $request->headers->all('content-length');
        foreach ($contentLengths as $declared) {
            if (\is_string($declared) && (int) $declared > self::MAX_CANCELLATION_BODY_BYTES) {
                return $this->privateJson(
                    ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The cancellation request body must not exceed '.self::MAX_CANCELLATION_BODY_BYTES.' bytes.']],
                    Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
                );
            }
        }

        // Duplicate security-singular headers: identity/trust inputs must
        // appear at most once.
        foreach (self::SECURITY_SINGULAR_HEADERS as $headerName) {
            if (\count($request->headers->all($headerName)) > 1) {
                return $this->privateJson(
                    ['error' => ['code' => 'DUPLICATE_HEADER', 'message' => sprintf('The %s header must appear at most once.', $headerName)]],
                    Response::HTTP_BAD_REQUEST,
                );
            }
        }

        // No decompression bombs.
        foreach ($request->headers->all('content-encoding') as $encoding) {
            if (strtolower((string) $encoding) !== 'identity') {
                return $this->privateJson(
                    ['error' => ['code' => 'UNSUPPORTED_CONTENT_ENCODING', 'message' => 'Content-Encoding must be identity (the widget POSTs plain JSON).']],
                    Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                );
            }
        }

        // Narrow HTTP: the cancellation POST is a JSON document.
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType !== '' && $contentType !== 'application/json') {
            return $this->privateJson(
                ['error' => ['code' => 'UNSUPPORTED_MEDIA_TYPE', 'message' => 'Content-Type must be application/json.']],
                Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
            );
        }

        // Body read: at most MAX+1 bytes are ever materialized.
        $requestBody = $this->readBoundedBody($request, self::MAX_CANCELLATION_BODY_BYTES);
        if (\strlen($requestBody) > self::MAX_CANCELLATION_BODY_BYTES) {
            return $this->privateJson(
                ['error' => ['code' => 'BODY_TOO_LARGE', 'message' => 'The cancellation request body must not exceed '.self::MAX_CANCELLATION_BODY_BYTES.' bytes.']],
                Response::HTTP_REQUEST_ENTITY_TOO_LARGE,
            );
        }

        // Query-parameter hardening: no query parameters are accepted.
        if ($request->query->count() > 0) {
            return $this->privateJson(
                ['error' => ['code' => 'QUERY_PARAMETERS_NOT_ALLOWED', 'message' => 'The cancellation endpoint accepts no query parameters.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Origin checks: the same ones the challenge endpoint applies.
        if ($this->sameOriginOnly && !$this->isSameOrigin($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'CROSS_ORIGIN_DENIED', 'message' => 'Cross-origin cancellation requests are not allowed.']],
                Response::HTTP_FORBIDDEN,
            );
        }
        $origin = $request->headers->get('Origin');
        if ($this->enforceOrigin && ($origin === null || $origin === '' || $origin === 'null')) {
            return $this->privateJson(
                ['error' => ['code' => 'origin_rejected', 'message' => 'The cancellation request carries no usable Origin header.']],
                Response::HTTP_FORBIDDEN,
            );
        }
        if ($this->challengeOriginAllowlist !== [] && !$this->originIsAllowlisted($request)) {
            return $this->privateJson(
                ['error' => ['code' => 'origin_rejected', 'message' => 'The cancellation request origin is not allowlisted.']],
                Response::HTTP_FORBIDDEN,
            );
        }

        // Fetch Metadata signal (defense in depth).
        if ($this->enforceFetchMetadata) {
            $fetchSite = $request->headers->get('Sec-Fetch-Site');
            if ($fetchSite !== null && $fetchSite !== '' && strtolower($fetchSite) === 'cross-site') {
                return $this->privateJson(
                    ['error' => ['code' => 'CROSS_SITE_REJECTED', 'message' => 'Cross-site cancellation requests are not allowed.']],
                    Response::HTTP_FORBIDDEN,
                );
            }
        }

        // Trusted client-IP policy: the canonical IP feeds the per-source
        // cancellation limiter.
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

        // Duplicate JSON keys: the raw body is scanned before decoding. A
        // document the scanner cannot walk (depth bomb or malformed
        // string) is refused — never treated as clean — and the decoder's
        // depth ceiling is the same 32 as the scanner's.
        try {
            $duplicateKey = $this->scanForDuplicateJsonKey($requestBody);
        } catch (\BelConsulting\KiwiCaptchaBundle\Http\MalformedJsonWalkException) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The cancellation request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if ($duplicateKey !== null) {
            return $this->privateJson(
                ['error' => ['code' => 'DUPLICATE_FIELD', 'message' => 'The cancellation request carries a duplicate JSON key: '.$duplicateKey.'.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // A JSON object with exactly the documented fields.
        try {
            $decoded = json_decode($requestBody, false, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The cancellation request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        if (!$decoded instanceof \stdClass) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The cancellation request body must be a JSON object.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        $payload = (array) $decoded;
        $unknown = array_values(array_diff(array_keys($payload), self::ACCEPTED_CANCELLATION_FIELDS));
        if ($unknown !== []) {
            return $this->privateJson(
                ['error' => ['code' => 'UNKNOWN_FIELDS', 'message' => 'The cancellation request carries unknown fields: '.implode(', ', $unknown).'.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }
        // The nonce shape: a bounded base64/base64url value. The widget
        // echoes the nonce the challenge endpoint issued; anything outside
        // the bound is refused before any state is touched.
        $nonce = $payload['nonce'] ?? null;
        if (!\is_string($nonce) || preg_match(self::CANCELLATION_NONCE_PATTERN, $nonce) !== 1) {
            return $this->privateJson(
                ['error' => ['code' => 'INVALID_JSON', 'message' => 'The cancellation request nonce must be a bounded base64 value.']],
                Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        }

        // Bounded per-source limiter: the anti-stockpiling layer's own
        // per-IP cancellation window (a sliding window in the issuance
        // rate-limiter style). A Redis failure here is inside the
        // endpoint's structured error boundary: the limiter fails closed
        // (the retryable private 503 — the endpoint refuses rather than
        // letting an unbounded cancellation stream through), never an
        // uncaught exception escaping as a 500.
        if ($this->outstanding !== null) {
            try {
                $admission = $this->outstanding->cancellationAdmission($clientIp);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: cancellation admission failed: %s', $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Cancellation is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
            if ($admission !== 1) {
                // 0 = the per-source window is exhausted; -1 = the
                // deployment-global window is exhausted (an IP-rotating
                // attacker cannot force unlimited random-nonce lookups).
                $code = $admission === -1 ? 'GLOBAL_CANCELLATION_RATE_LIMITED' : 'CANCELLATION_RATE_LIMITED';
                $message = $admission === -1
                    ? 'Cancellation is temporarily unavailable for this deployment. Try again later.'
                    : 'Too many cancellation requests from this address. Try again later.';

                return $this->privateJson(
                    ['error' => ['code' => $code, 'message' => $message]],
                    Response::HTTP_TOO_MANY_REQUESTS,
                );
            }
        }

        // Risk attribution of a fresh cancellation: the ChallengeCancelled
        // risk event is risk-neutral (observability only — the issue debt
        // of the abandoned challenge is never refunded), but it still
        // carries the same source/session/scope signals as the original
        // ChallengeIssued. The continuity session is read without minting
        // (the cancellation response never sets a cookie), and the issued
        // scope comes from the pending record — a server-internal
        // bookkeeping read only: the response still carries no record
        // contents, and the fresh-outcome gate below keeps the event from
        // firing for anything but this call's own pending->cancelled flip.
        $riskSession = $this->continuityCookie?->read($request);
        $cancelledScope = null;
        if ($this->risk !== null && $this->storage instanceof \KiwiCaptcha\CancellableStorageInterface) {
            try {
                $cancelledRecord = $this->storage->find($nonce);
                $cancelledScope = $cancelledRecord !== null ? $cancelledRecord->scope : null;
            } catch (\Throwable) {
                // Best-effort attribution: without the scope the event is
                // skipped, never a failed cancellation.
                $cancelledScope = null;
            }
        }

        // The record transition: the atomic pending->cancelled flip
        // (CancellableStorageInterface) decides missing / consumed /
        // already-cancelled / cancelled-now in one storage operation. A
        // consumed (finalized) record is never cancelled; the outcome is
        // idempotent for every other state. The result carries state only,
        // never record contents. A storage failure fails closed: a
        // cancellation that could not be established is never reported as
        // one.
        if ($this->storage instanceof \KiwiCaptcha\CancellableStorageInterface) {
            try {
                $result = $this->storage->cancel($nonce);
            } catch (\Throwable $e) {
                error_log(sprintf('kiwicaptcha: challenge cancellation failed for nonce_id=%s: %s', $this->nonceId($nonce), $e->getMessage()));

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge cancellation is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }

            // The ChallengeCancelled risk event fires only on the first
            // fresh pending->cancelled transition (wasCancelledNow):
            // repeated idempotent cancellations, consumed records and
            // unknown nonces never record it again. The idempotency
            // identity is derived from the nonce, so even concurrent
            // duplicate flips record the event at most once per nonce
            // (the engine's dedupe key). The event is risk-neutral: it
            // performs no state mutation, so the cancelled challenge's
            // issue debt keeps its issued-and-abandoned contribution
            // (it decays naturally; only an actual solve repays it).
            // Best-effort: a risk-backend failure never breaks a
            // completed cancellation.
            if ($result !== null && $result->wasCancelledNow() && $this->risk !== null && $cancelledScope !== null) {
                try {
                    $this->risk->challengeCancelled($cancelledScope, $clientIp, $riskSession, $nonce);
                } catch (\Throwable $e) {
                    error_log(sprintf('kiwicaptcha: ChallengeCancelled feedback failed for nonce_id=%s: %s', $this->nonceId($nonce), $e->getMessage()));
                }
            }

            // Release the deployment-wide live-outstanding slot AND the
            // original source's outstanding slot only when the record was
            // actually cancelled: a fresh pending->cancelled transition
            // (cancelled-now) or an already-cancelled record (the
            // idempotent retry of an interrupted cancellation: the record
            // is dead, so the slots it held are released). The one-shot
            // cancellation releases the global member and decrements
            // exactly the source that issued the challenge (from the
            // issuance sidecar — never the canceller's IP) when the
            // member actually existed; a duplicate cancel is a no-op, so
            // the counter can never be double-decremented. A consumed
            // (finalized) record and a missing/expired nonce performed no
            // cancellation: nothing is freed, and the response stays the
            // idempotent success without implying a cancellation that did
            // not happen (the slot belongs to a finalized or never-issued
            // challenge). Best-effort and idempotent on the release
            // itself; a failure leaves the member to expire by its score
            // and the counter by its EXPIRE.
            if ($result !== null && $result->state !== 'consumed') {
                $this->outstanding?->cancelled($nonce);
            }
        } else {
            // Fail closed: this storage cannot establish the cancellation
            // (no atomic pending->cancelled transition — e.g. a PSR-6
            // pool). Freeing the deployment-wide live-outstanding slot
            // while the record stays pending and redeemable would be an
            // anti-stockpiling bypass, so the endpoint answers the
            // retryable 503 and frees nothing; the operator must wire a
            // CancellableStorageInterface backend (ArrayStorage,
            // RedisStorage) for the cancellation endpoint.
            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge cancellation is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
            );
        }

        return $this->privateJson(['cancelled' => true], Response::HTTP_OK);
    }

    /**
     * The controller clock for the stage-2 remaining-lifetime clip; see
     * {@see self::stage2MinimumRemaining()}. The injected clock when
     * provided, time() otherwise.
     */
    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }

    /**
     * The practical minimum remaining chain lifetime a stage-2 mint may
     * consume, seconds. The deployment's configured minimum solve duration
     * (min_duration_ms, 0 when unset) is converted to whole seconds rounded
     * up, then the solver and transport headroom,
     * {@see self::STAGE2_SOLVER_MARGIN_SECS}, is added.
     *
     * A clipped TTL that does not cover its own minimum solve duration and
     * the solve round-trip is operationally unusable; the core Config also
     * refuses to construct a challenge whose TTL is not strictly longer
     * than min_duration_ms. The core Config's floor (>= 1 second,
     * {@see self::MIN_STAGE2_REMAINING_SECS}) is the lower bound.
     */
    private function stage2MinimumRemaining(): int
    {
        $baseMinDurationMs = $this->issuer->config()->minDurationMs ?? 0;

        return max(
            self::MIN_STAGE2_REMAINING_SECS,
            (int) ceil($baseMinDurationMs / 1000) + self::STAGE2_SOLVER_MARGIN_SECS,
        );
    }

    /**
     * The issuer to mint with for a given challenge lifetime: the wired
     * issuer when $ttlSecs is null or equals its Config's TTL, otherwise a
     * TTL-variant issuer built once per TTL,
     * {@see self::buildTtlVariantIssuer()}. The core signs the lifetime
     * from the issuer Config, so the per-sitekey override
     * (risk.sitekeys.<sitekey>.ttl_secs) requires a variant issuer.
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
     * Best-effort release of a reserved chain after a refused or failed
     * stage-2 issuance, with the reservation owner token: the ticket stays
     * reusable, so the chain is not burned. A release by a non-owner, or
     * on a chain that is no longer in the reserved state, is an atomic
     * no-op; a release failure is harmless, since the reservation expires
     * with the chain TTL. The caller must not release for an indeterminate
     * markIssued outcome (the chain may be durably issued by this very
     * request).
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
     * Return an admitted outstanding slot when the challenge was proven
     * never handed out (OutstandingChallenges::abortedBeforeHandoff: the
     * nonce-authoritative one-shot release — the nonce leaves the global
     * live membership and the original source membership from the
     * issuance sidecar, never this request's own source). Composed by
     * {@see self::rollbackUncommittedIssuance()}, the single
     * proven-not-handed-off cleanup primitive. The caller must not roll
     * back for an indeterminate failure.
     */
    /**
     * A bounded loggable nonce identifier: a live security-state
     * identifier (the cancellation/storage lookup key) is never logged
     * raw — only the first 16 hex chars of its unkeyed SHA-256, enough
     * for intra-log correlation.
     */
    private function nonceId(string $nonce): string
    {
        return substr(hash('sha256', $nonce), 0, 16);
    }

    private function rollbackOutstandingAdmission(bool $held, string $clientIp, ?string $nonce = null): void
    {
        if (!$held) {
            return;
        }
        try {
            $this->outstanding?->abortedBeforeHandoff($nonce);
        } catch (\Throwable) {
            // Best-effort; the memberships decay by their expiry scores
            // otherwise.
        }
    }

    /**
     * The proven-not-handed-off issuance cleanup primitive. Every exit
     * after the outstanding admission that positively established the
     * challenge was never handed off returns the admitted slot via
     * {@see self::rollbackOutstandingAdmission()} and releases the chain
     * reservation via {@see self::releaseChain()}. Both go through this
     * single helper, so a future failure path cannot accidentally omit one
     * half of the resource accounting. The indeterminate case must not use
     * this helper: the chain state cannot be read after a thrown issuance
     * transition, so the challenge may be the authoritative issued
     * stage-2.
     */
    /**
     * Roll back the entire uncommitted issuance attempt: the minted
     * record is discarded, the admitted outstanding slot is returned
     * (one-shot, nonce-authoritative — safe even when the admission EVAL
     * landed but its reply was lost), and the chain reservation is
     * released. Only valid before the durable stage-2 commit: after
     * issued(N) is confirmed, nothing may be rolled back.
     */
    private function rollbackUncommittedIssuance(?\KiwiCaptcha\Challenge $challenge, bool $outstandingAdmissionHeld, string $clientIp, ?string $chainId, ?string $chainOwner): void
    {
        if ($challenge !== null) {
            $this->discardChallenge($challenge);
            $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp, $challenge->nonce);
        } else {
            // A failure before the mint (e.g. the rate-limiter boundary):
            // no record and no admission exist to roll back.
            $this->rollbackOutstandingAdmission($outstandingAdmissionHeld, $clientIp, null);
        }
        $this->releaseChain($chainId, $chainOwner);
    }

    /**
     * Stage-2 state entry (the chain gate): validate the chain state,
     * inspect the issued stage-2 challenge (recover, rearm or verify as
     * the consumed state demands, see {@see self::inspectIssuedStage2()}),
     * then claim a short owner-scoped reservation.
     *
     * Returns a response when the request must not proceed into the
     * issuance pipeline: the recovery of the already-issued challenge is
     * byte-identical with no re-mint and no re-admission; the retryable
     * 503s and the missing-chain 422 also return responses. Returns null
     * when the pipeline may proceed with the reservation held and
     * $requirement refreshed for the re-dispatch after a state race.
     */
    private function prepareStageTwo(string $chainId, string $chainOwner, ?\BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement &$requirement, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        for ($i = 0; $i < 3; $i++) {
            $state = $requirement?->state ?? 'available';
            if ($state === 'verified') {
                // Terminal verified recovery: the chain completed durably
                // (the obligation was cleared atomically with the verified
                // transition), so a retry recovers the already-issued
                // challenge with no re-mint and no re-admission. A missing
                // challenge record despite 'verified' is a storage
                // anomaly: the retryable 503.
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
                // The chain was rearmed (the issued challenge is missing or
                // expired, or its committed result was invalid): the
                // reservation plus the fresh stage-2 mint below issue a new
                // stage-2 challenge at the same or stronger floor, never a
                // stage-1.
            }
            if ($state === 'step_up_required') {
                // Terminal step-up: the transaction is bound to its final
                // step-up disposition (the obligation mapping was kept), so
                // no challenge issuance can follow. A later request for the
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
                // Terminal denial: the transaction is bound to its final
                // denial disposition (the obligation mapping was kept), so
                // no challenge issuance can follow. A later request for the
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
                    // Another request holds the live reservation for this
                    // chain, so the issuance pipeline is never entered: one
                    // ticket cannot amplify the duplicate work (risk,
                    // quota, outstanding, mint, metadata, accounting). The
                    // retryable 503 lets the client poll until the owning
                    // request completes.
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
                    // (another request transitioned the chain): re-read the
                    // requirement and re-dispatch once (bounded). The
                    // terminal step_up_required and denied answers land in
                    // their terminal response branches above, never an
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
                    // ChainReservationResult::Missing: the chain state is
                    // absent or expired.
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
     * Inspect the already-issued stage-2 challenge of an issued chain (the
     * chain gate) and decide the recovery.
     *
     *  - pending + valid record -> recover the exact issuance response.
     *    The response may have been lost; the retry gets the same
     *    challenge, with no re-mint and no re-admission.
     *  - missing/expired record -> rearm the chain: issued(nonce) ->
     *    available, pinned to the exact expected nonce, so the pipeline
     *    mints a fresh stage-2 challenge, never a stage-1.
     *  - consumed + committed valid -> the core's consumed result is not
     *    terminal by itself. The nonce's final disposition is read from
     *    the post-solve disposition store; the validator finalized it
     *    before the application saw the outcome. Pass -> markVerified
     *    (the chain ends; the obligation is cleared atomically) plus the
     *    same challenge is recovered. StepUp -> markStepUpRequired (the
     *    obligation is kept) plus the terminal step-up response. Deny ->
     *    markDenied (the obligation is kept) plus the terminal risk-denied
     *    response. Missing or pending -> the retryable 503.
     *  - consumed + committed invalid -> rearm, subject to the rate,
     *    outstanding and admission pipeline below.
     *  - consumed + no committed result -> indeterminate: the retryable
     *    temporary_unavailable. Never rearm while the first request may
     *    have been consumed successfully.
     *
     * Returns null when the chain was rearmed and the pipeline proceeds to
     * the reservation and mint.
     */
    private function inspectIssuedStage2(string $chainId, string $stage2Nonce, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        if ($this->storage === null) {
            // No challenge storage to inspect: the issued challenge's state
            // cannot be established, so fail closed (retryable).
            return $this->privateJson(
                ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                Response::HTTP_SERVICE_UNAVAILABLE,
                $request,
                $riskSession,
                $mintedCookie,
            );
        }
        // The runtime state is read in ONE snapshot (the storage
        // capability), so a cancelled record — which `find()` still
        // returns and `consumedState()` leaves null — can never be
        // mistaken for a usable pending challenge, and an expired-but-
        // retained pending record is retired atomically instead of being
        // recovered. The pre-capability fallback keeps the legacy
        // find()+consumedState classification.
        if ($this->storage instanceof \KiwiCaptcha\ChallengeRuntimeStateReadableInterface) {
            try {
                $runtime = $this->storage->runtimeState($stage2Nonce);
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
            if ($runtime->kind === \KiwiCaptcha\ChallengeRuntimeStateKind::Missing) {
                return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
            }
            if ($runtime->kind === \KiwiCaptcha\ChallengeRuntimeStateKind::Cancelled) {
                // A cancelled stage-2 can never be recovered or redeemed:
                // its outstanding slot is released (best-effort, one-shot)
                // and the chain is rearmed for a fresh stage-2 mint.
                $this->outstanding?->abortedBeforeHandoff($stage2Nonce);

                return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
            }
            if ($runtime->kind === \KiwiCaptcha\ChallengeRuntimeStateKind::Pending) {
                $record = $runtime->record;
                if ($record !== null && $this->now() < $record->expiresAt) {
                    // Pending and still valid: recover the exact issuance
                    // response (no re-mint, no re-admission). Exactly one
                    // fence per store before the hand-out.
                    $this->confirmRecoveryBarriers();

                    return $this->privateJson(self::issuanceResponseFromRecord($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
                }
                // Pending but signed-expired (retained by the replay
                // margin): the prior nonce must become provably
                // non-redeemable before the chain is rearmed — the atomic
                // pending->cancelled transition. If the cancellation wins,
                // the outstanding slot is released and the chain rearmed;
                // if a concurrent consumption won the race, the request is
                // processed as consumed (indeterminate when nothing was
                // committed).
                try {
                    $cancelled = $this->storage instanceof \KiwiCaptcha\CancellableStorageInterface ? $this->storage->cancel($stage2Nonce) : null;
                } catch (\Throwable $e) {
                    error_log(sprintf('kiwicaptcha: stage-2 retirement failed: %s', $e->getMessage()));

                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                if ($cancelled !== null && ($cancelled->state === 'cancelled-now' || $cancelled->state === 'cancelled')) {
                    $this->outstanding?->abortedBeforeHandoff($stage2Nonce);

                    return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
                }
                // The retirement lost the race to a consumption: fall
                // through to the consumed classification.
                $consumed = $this->storage instanceof \KiwiCaptcha\ConsumedStateReadableInterface
                    ? $this->storage->consumedState($stage2Nonce)
                    : null;
                if ($consumed === null) {
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                $result = $consumed->consumedResult;
                if ($result === null) {
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }
                if (!$result->valid) {
                    return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
                }
                $record = $consumed->record;

                return $this->resolveConsumedStage2Disposition($chainId, $record, $stage2Nonce, $request, $riskSession, $mintedCookie);
            }
            // Consumed: the retained consumed state drives the disposition
            // (never a rearm while the first request may have succeeded).
            $consumed = $runtime->consumed;
            $record = $runtime->record;
            $result = $consumed?->consumedResult;
            if ($result === null || $consumed === null) {
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
            }
            if (!$result->valid) {
                return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
            }

            return $this->resolveConsumedStage2Disposition($chainId, $record, $stage2Nonce, $request, $riskSession, $mintedCookie);
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
            // The issued challenge record is missing (expired or never
            // durably stored): rearm the chain for a fresh stage-2 mint.
            return $this->rearmIssuedStage2($chainId, $stage2Nonce, $request, $riskSession, $mintedCookie);
        }
        $consumed = $this->storage instanceof \KiwiCaptcha\ConsumedStateReadableInterface
            ? $this->storage->consumedState($stage2Nonce)
            : null;
        if ($consumed === null) {
            // Pending: the issued challenge is still live, so recover the
            // exact issuance response (no re-mint, no re-admission). One
            // fence before the hand-out.
            $this->confirmRecoveryBarriers();

            return $this->privateJson(self::issuanceResponseFromRecord($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
        }
        $result = $consumed->consumedResult;
        if ($result === null) {
            // Consumed without a committed result: indeterminate, since the
            // first request may have been consumed successfully. Never
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
            // The stage was cryptographically solved, but the core's
            // consumed result never decides transaction terminality alone:
            // the nonce's final disposition drives the chain transition
            // (see resolveConsumedStage2Disposition).
            return $this->resolveConsumedStage2Disposition($chainId, $record, $stage2Nonce, $request, $riskSession, $mintedCookie);
        }
        // Committed invalid: rearm (subject to the rate, outstanding and
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
     * Recovery of an issued or verified chain (the terminal states). The
     * original stage-2 issuance already ran durably (challenge record plus
     * metadata identity). The retry reads the issued challenge record
     * through the storage find by the state's stage2Nonce, then
     * serializes it through the single canonical issuance-response
     * serializer, {@see self::issuanceResponseFromRecord()}, the same
     * function the fresh handoff uses. The recovered response is
     * byte-identical with the original request's, with no re-mint, no
     * re-admission and no re-consume. An issued or verified state never
     * allows a second mint.
     *
     * Returns null when the chain's challenge record cannot be found (a
     * storage anomaly; the caller answers the retryable 503).
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

        $this->confirmRecoveryBarriers();

        return $this->privateJson(self::issuanceResponseFromRecord($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
    }

    /**
     * Stage-2 only: the idempotent owner-scoped issuance transition
     * reserved(me) -> issued(stage2Nonce), with lost-reply recovery.
     *
     * Returns null when the issuance is durably confirmed (the pipeline
     * continues to the risk signals and handoff). Every other outcome
     * returns a response:
     *
     *  - a thrown transition reads the chain state first. Issued or
     *    verified with the current nonce means the operation succeeded
     *    (continue); still reserved by me means the transition never ran
     *    (retry once). When the state cannot be read the outcome is
     *    indeterminate: the minted challenge is retained (never delete
     *    state that may be authoritative; it expires naturally if
     *    unreferenced), and the reservation and outstanding slot are not
     *    rolled back (503).
     *  - 'conflict'/'not_owner'/'missing' -> positively not issued with
     *    this nonce: the minted record is discarded, the slot returned,
     *    the reservation released (503).
     */
    private function markStage2Issued(\KiwiCaptcha\Challenge $challenge, string $chainId, string $chainOwner, string $clientIp, bool $outstandingAdmissionHeld): ?JsonResponse
    {
        try {
            $result = $this->chainTickets->markIssued($chainId, $chainOwner, $challenge->nonce);
        } catch (\Throwable $e) {
            // Lost reply: the transition may have happened, so read the
            // chain state before touching anything.
            error_log(sprintf('kiwicaptcha: chain issuance transition failed: %s', $e->getMessage()));
            try {
                $current = $this->chainTickets->requirementFor($chainId);
            } catch (\Throwable) {
                $current = null;
            }
            if ($current === null) {
                // Indeterminate: retain the minted challenge and do not
                // release the reservation or roll back the outstanding
                // slot, since the challenge may be the authoritative
                // issued stage-2.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
            if (($current->state === 'issued' || $current->state === 'verified') && $current->stage2Nonce === $challenge->nonce) {
                // The transition succeeded before the throw — but the
                // throw may itself have been the mutation's WAIT
                // shortfalling, so the issued state was never proven
                // durable. A read-only recovery here would hand the
                // stage-2 challenge out over an unreplicated issued
                // state a stale-replica promotion could resurrect into a
                // re-mint. The fresh causal fence is established before
                // the challenge is handed out (a shortfall fails closed
                // to 503), exactly like the subsequent-request recovery
                // path.
                try {
                    $this->confirmRecoveryBarriers();
                } catch (\Throwable $fenceFailure) {
                    error_log(sprintf('kiwicaptcha: stage-2 recovery fence failed after the issuance transition: %s', $fenceFailure->getMessage()));

                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                    );
                }

                return null;
            }
            if ($current->state === 'reserved' && $current->owner === $chainOwner) {
                // Still reserved by me: the transition never ran, so retry
                // once.
                try {
                    $result = $this->chainTickets->markIssued($chainId, $chainOwner, $challenge->nonce);
                } catch (\Throwable) {
                    // The retry cannot be confirmed either: indeterminate
                    // again, retain.
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                    );
                }
            } else {
                // Positively not issued by this request (rearmed, owned
                // elsewhere, or vanished): discard, release and roll back.
                $this->discardChallenge($challenge);
                $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
            }
        }
        switch ($result) {
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedNew:
                // The fresh transition's own verified WAIT already ran
                // (markIssued WAITs on issued_new); the hand-out needs no
                // further fence.
                return null;
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::IssuedSame:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::VerifiedSame:
                // A same-state replay is a recovery acceptance: this
                // request did not mutate, and the already-issued state
                // may have been created by an earlier attempt whose WAIT
                // shortfalled. The fresh causal fence proves the issued
                // state advanced through the replicas before the
                // challenge is handed out (a shortfall fails closed).
                try {
                    $this->confirmRecoveryBarriers();
                } catch (\Throwable $fenceFailure) {
                    error_log(sprintf('kiwicaptcha: stage-2 recovery fence failed on the same-state replay: %s', $fenceFailure->getMessage()));

                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                    );
                }

                return null;
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::Conflict:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::NotOwner:
            case \BelConsulting\KiwiCaptchaBundle\Risk\ChainIssuedResult::Missing:
                // Positively not issued with this nonce (the chain holds a
                // different one, is owned elsewhere, or vanished): the
                // minted record is discarded, since a completed chain never
                // allows a second mint (the client retries the ticket and
                // recovers the challenge that was durably issued). The slot
                // is returned and the reservation released.
                $this->discardChallenge($challenge);
                $this->rollbackUncommittedIssuance($challenge, $outstandingAdmissionHeld, $clientIp, $chainId, $chainOwner);

                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                );
        }
    }

    /**
     * Rearm an issued-but-unrecoverable stage-2 chain (the challenge
     * record is missing, cancelled or committed-invalid): the chain
     * returns to `available` so the pipeline can reserve and mint a
     * fresh stage-2 challenge. Recovery of a recoverable issued chain
     * instead serializes the stored record through the single canonical
     * issuance-response serializer,
     * {@see self::issuanceResponseFromRecord()}, the same function the
     * fresh handoff uses — the recovery body is byte-identical with the
     * original response by construction.
     *
     * Returns null when the chain was rearmed (the caller proceeds to
     * the reservation and mint); a failed rearm (a different transition
     * won the race) answers the retryable 503.
     */
    private function rearmIssuedStage2(string $chainId, string $stage2Nonce, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
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
            // the rearm (the exact expected nonce pins it): the retryable
            // 503.
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
     * The consumed-valid stage-2 disposition: the core's committed result
     * is not terminal by itself — the nonce's final disposition comes from
     * the post-solve disposition store. Pass -> markVerified (the chain
     * ends, the obligation clears atomically) and the same challenge is
     * recovered. StepUp -> markStepUpRequired (the obligation is kept) and
     * the terminal step-up response is returned. Deny -> markDenied (the
     * obligation is kept) and the terminal risk-denied response is
     * returned. A missing or pending disposition answers the retryable
     * 503.
     */
    private function resolveConsumedStage2Disposition(string $chainId, \KiwiCaptcha\ChallengeRecord $record, string $stage2Nonce, Request $request, ?string $riskSession, bool $mintedCookie): ?JsonResponse
    {
        // The stage was cryptographically solved, but the core's consumed
        // result never decides transaction terminality alone: the nonce's
        // final disposition (the validator finalized it durably before the
        // application saw the outcome) drives the chain transition. A
        // missing or pending disposition means the final disposition was
        // never durably established (the validator died between the core
        // commit and the finalize): the retryable 503, and the obligation
        // is never cleared.
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
            // No disposition store wired, or the record is absent,
            // expired or pending: the final disposition was never
            // durably established, so the obligation is never cleared.
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
                // The final disposition is Pass: transition to verified
                // (idempotent; the obligation is cleared atomically only
                // while it still points at this chain) instead of
                // re-issuing, then recover the same challenge.
                try {
                    $terminal = $this->chainTickets->markVerified($chainId, $stage2Nonce);
                } catch (\Throwable $e) {
                    // Lost reply: read the state and confirm the exact
                    // nonce; do not return a final pass while the
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
                    // The chain moved under the transition: the retryable
                    // 503 (the client retries against the current state).
                    return $this->privateJson(
                        ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                        Response::HTTP_SERVICE_UNAVAILABLE,
                        $request,
                        $riskSession,
                        $mintedCookie,
                    );
                }

                $this->confirmRecoveryBarriers();

                return $this->privateJson(self::issuanceResponseFromRecord($record), Response::HTTP_OK, $request, $riskSession, $mintedCookie);
            case \BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind::StepUp:
                // The final disposition is StepUp: transition to the
                // terminal step_up_required (the obligation mapping is
                // kept, so the transaction stays bound to the step-up
                // requirement) and answer the terminal step-up response.
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
                // The final disposition is Deny: transition to the
                // terminal denied (the obligation mapping is kept, so the
                // transaction stays bound to its final denial) and answer
                // the terminal risk-denied response.
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
                // stage-2 nonce: a stage-2 challenge never opens a third
                // stage. Corrupt or unexpected state: fail closed.
                return $this->privateJson(
                    ['error' => ['code' => 'SERVICE_UNAVAILABLE', 'message' => 'Challenge issuance is temporarily unavailable. Try again later.']],
                    Response::HTTP_SERVICE_UNAVAILABLE,
                    $request,
                    $riskSession,
                    $mintedCookie,
                );
        }
    }

    /**
     * Failed-barrier replay guard for the stage-2 recovery: the recovered
     * challenge's outstanding admission and chain markIssued writes may
     * have landed on the primary with their WAIT failing (the earlier
     * attempt answered the 503). A read-only recovery that hands the same
     * challenge out would accept a slot/membership a promotion could
     * lose. The barriers are re-established before the hand-out: a
     * shortfall propagates and the retryable 503 answers, so the
     * challenge is never handed out on unproven state.
     */
    private function confirmRecoveryBarriers(): void
    {
        $this->outstanding?->establishReplicationFence('the stage-2 recovery outstanding acceptance');
        $this->chainTickets?->establishReplicationFence('the stage-2 recovery chain acceptance');
    }

    /**
     * The ONE canonical issuance-response serializer of the controller.
     * It emits the client-facing challenge response key set in the
     * exact order Challenge::toArray() uses: nonce, challenge, salt,
     * algorithm, mKib, t, p, targetBits, ttlSecs, minDurationMs,
     * prefix. The authenticated decoy_field follows when the record
     * carries one, then the execution_program when the record carries
     * one. execution_version and execution_commitment are stored-record
     * canonical fields and never appear on the client-facing surface.
     *
     * Both handoff paths serialize through this function. The fresh
     * handoff of {@see self::challenge()} serializes the stored record
     * after the issuance commit. Every stage-2 recovery path does too:
     * {@see self::inspectIssuedStage2()},
     * {@see self::recoverIssuedResponse()} and
     * {@see self::resolveConsumedStage2Disposition()}. The handoff
     * body and every later recovery body of the same challenge are
     * therefore byte-identical by construction. The response can never
     * carry an execution_program or decoy_field the stored record does
     * not carry, and a recovery can never drop one the record carries.
     * Each value comes from the record, never a nonce-derived
     * reconstruction.
     */
    private static function issuanceResponseFromRecord(\KiwiCaptcha\ChallengeRecord $record): array
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
        // The authenticated decoy name of the record: the original
        // response carried exactly this value (the issuer's per-issuance
        // pool pick, signed into the canonical payload).
        if ($record->decoyField !== null) {
            $response['decoy_field'] = $record->decoyField;
        }
        // The armed execution program of the record: the original
        // response carried exactly these bytes, so a stage-2 recovery of
        // an execution-armed challenge stays solvable (the stored record
        // and the response can never diverge).
        if ($record->executionProgram !== null) {
            $response['execution_program'] = $record->executionProgram;
        }

        return $response;
    }

    /**
     * Whether the direct peer of the request (`REMOTE_ADDR`, the immediate
     * connection, never a forwarded header) is inside the configured
     * risk.trusted_tls_proxies CIDRs. The trusted-edge TLS header is read
     * only from such a peer: the direct peer must be the trusted proxy or
     * CDN itself.
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
     * The effective stage-2 action: the stronger of the chain ticket's
     * signed required action and the current pre-issue decision action.
     * The required action is never StepUp or Deny (the ticket format
     * excludes them, see ChainedChallengeTicketService::verify()), so a
     * StepUp or Deny effective action can only come from the current
     * decision and stays terminal.
     */
    private function effectiveChainAction(RiskAction $decisionAction, string $requiredAction): RiskAction
    {
        $required = RiskAction::from($requiredAction);

        return $decisionAction->rank() > $required->rank() ? $decisionAction : $required;
    }

    /**
     * A TTL-variant Issuer: a clone of the wired issuer's Config with only
     * ttlSecs replaced, issued against the same storage as the wired
     * issuer and replicating its clock and region. A region-bound
     * deployment (risk.region) keeps its signed region on overridden-TTL
     * challenges, so the verifier's expected-region check still passes.
     *
     * @throws \LogicException when the controller has no storage wired
     *                         (the extension always wires one)
     */
    private function buildTtlVariantIssuer(int $ttlSecs): Issuer
    {
        return $this->issuer->withTtl($ttlSecs);
    }

    /**
     * Same-origin check for the challenge endpoint. Requests without an
     * Origin header (same-origin navigation, curl, non-browser clients)
     * are allowed; a browser cross-site POST always carries one. When
     * present, the Origin must match the expected origin, which comes from
     * server config (public_base_url) when configured, so a forged Host
     * header can never shift the expected origin. The configured value is
     * received as the validated ExpectedOrigin object. The extension
     * refuses anything that is not a canonical https origin before this
     * point: a literal at container build time, an env-resolved value at
     * service construction. The request-side candidate uses the same
     * structured normalization as the allowlist,
     * {@see self::normalizeOrigin()}. Without public_base_url the
     * expected origin is derived from the request's own scheme and host
     * (fine for localhost and dev; production deployments behind shared
     * infrastructure should set public_base_url).
     */
    private function isSameOrigin(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '') {
            return true;
        }

        if ($this->expectedOrigin !== null) {
            $candidate = self::normalizeOrigin($origin);

            return $candidate !== null && $this->expectedOrigin->normalized() === $candidate;
        }

        $expected = rtrim($request->getScheme().'://'.$request->getHttpHost(), '/');

        return hash_equals($expected, rtrim($origin, '/'));
    }

    /**
     * Origin laundering defense: the request must carry an Origin header
     * (or a Referer whose URL yields an origin) whose normalized scheme,
     * host and port match one allowlisted origin. Comparison is
     * component-wise over the structured normalization of both sides,
     * {@see self::normalizeOrigin()}, so "https://app.example.com"
     * matches its default-port, punycode and trailing-dot spellings, but
     * never a different port, scheme or host. With enforce_origin, a
     * request without a usable Origin is rejected before the Referer
     * fallback.
     */
    private function originIsAllowlisted(Request $request): bool
    {
        $origin = $request->headers->get('Origin');
        if ($origin === null || $origin === '' || $origin === 'null') {
            if ($this->enforceOrigin) {
                // With enforce_origin, a request without a usable Origin is
                // rejected before the Referer fallback.
                return false;
            }
            // Referer-origin fallback: the scheme, host and port of the
            // Referer URL (no path, no query).
            $referer = $request->headers->get('Referer');
            if ($referer === null || $referer === '') {
                return false;
            }
            $parts = parse_url($referer);
            if (!\is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
                return false;
            }
            $origin = $parts['scheme'] . '://'
                . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
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
     * Parse and normalize an origin string into its exact comparison
     * components: a canonical "{scheme}://{host}:{port}" string.
     *  - Scheme is lowercased.
     *  - Host is lowercased, its trailing dot stripped, and IDN converted
     *    to punycode (idn_to_ascii when ext-intl is available); IPv6
     *    literals are kept bracketed exactly as parse_url returns them.
     *  - The effective port: an absent port defaults per scheme (https
     *    443, http 80, so an explicit default port compares equal). Any
     *    other scheme is not an origin.
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
        // and "example.com" are the same host), so strip it before
        // comparing.
        $host = rtrim($host, '.');
        if ($host === '') {
            return null;
        }
        // IDN to punycode (ext-intl): "bücher.example" and
        // "xn--bcher-kva.example" are the same DNS name. Skipped when
        // ext-intl is absent.
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
     * is unknown in reject or baseline mode (the engine declines to
     * evaluate, so there is no reputation to attribute a refusal to).
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
     * Path canonicality: whether the raw request target is the canonical
     * path, checked over the raw request URI, never a normalized route.
     * Rejects any empty segment (`//` and a trailing slash), any dot
     * segment (`/.`, `/./`, `/..`, `/../`), any percent-encoded byte
     * (the canonical target is a fixed ASCII path, so `/%76hallenge`,
     * `%2F`, `%5C` and `%2e%2e` are encoding probes), and any backslash.
     * Only the path component is inspected; the query string is rejected
     * separately with a 422.
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
        // The empty element before a leading slash is the absolute-path
        // marker, not a segment; every other empty segment (a `//` in the
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
     * Read the request body with a hard byte cap: the input stream is
     * consumed for at most $maxBytes + 1 bytes, so an oversized chunked
     * body is refused by the caller's length check without ever being
     * materialized in full. A declared Content-Length was already checked
     * before the stream was touched, but chunked uploads can skip a
     * truthful one. When Symfony hands back a buffered stream (tests,
     * already-consumed input), the read is still bounded.
     */
    private function readBoundedBody(Request $request, int $maxBytes = self::MAX_CHALLENGE_BODY_BYTES): string
    {
        $stream = $request->getContent(true);
        if (\is_resource($stream)) {
            return (string) stream_get_contents($stream, $maxBytes + 1);
        }

        return (string) $request->getContent();
    }

    /**
     * Duplicate JSON key scanner over the RAW document — the single
     * shared implementation ({@see JsonDuplicateKeyScanner}) used by
     * every security-sensitive endpoint. json_decode silently keeps the
     * last occurrence, which is exactly the parser ambiguity the endpoint
     * must refuse ({"scope":"a","scope":"b"} parses differently across
     * intermediaries); the shared walker inspects the raw bytes, so a
     * decode-then-scan can never mask a duplicate.
     */
    private function scanForDuplicateJsonKey(string $json): ?string
    {
        return $this->jsonDuplicateKeyScanner->scanForDuplicateJsonKey($json);
    }

    /**
     * Strict form-urlencoded decoder: rejects duplicate parameter names
     * and PHP bracket syntax, so the form transport has the same
     * parser-ambiguity rigor as the JSON transport. Returns the decoded
     * name=>value map, or null when the body is not strictly decodable.
     */
    private function decodeStrictFormBody(string $body): ?array
    {
        $decoded = [];
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            $parts = explode('=', $pair, 2);
            $name = rawurldecode($parts[0]);
            if ($name === '' || str_contains($name, '[') || str_contains($name, ']')) {
                return null;
            }
            if (\array_key_exists($name, $decoded)) {
                return null;
            }
            $decoded[$name] = rawurldecode($parts[1] ?? '');
        }

        return $decoded;
    }

    /**
     * All challenge responses share the private-document headers:
     * Cache-Control no-store, Pragma no-cache, Referrer-Policy no-referrer,
     * X-Content-Type-Options nosniff, so challenge bytes and client
     * identity are never cached, mirrored or sniffed. When
     * risk.challenge_origin_allowlist is non-empty, every response also
     * carries an explicit Content-Security-Policy frame-ancestors header
     * listing the allowlisted origins, never inherited from default-src,
     * so the allowlist is exactly the framing contract of the challenge
     * endpoint (an empty allowlist emits no CSP header). The bundle emits
     * no CORS headers: CORS is not authorization; the origin checks are,
     * and they run on every response regardless. When a new risk
     * continuity session was minted for this request, the cookie is
     * attached here, on every response path, so the session the
     * assessment keyed on is what the client carries.
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
 * @internal control-flow sentinel of the duplicate-JSON-key scan: thrown
 *           when the walker finds an object key it already saw at the same
 *           level. Carries the raw key for the error message. Never
 *           escapes the controller.
 */

