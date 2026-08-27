<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveFinalizeOutcome;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionKind;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionStore;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDispositionUnavailableException;
use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskGateway;
use BelConsulting\KiwiCaptchaBundle\Risk\RiskProfileResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\SecurityEpochMonitor;
use BelConsulting\KiwiCaptchaBundle\Security\OutstandingChallenges;
use BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner;
use BelConsulting\KiwiCaptchaBundle\SiteVerify\SiteVerifyMetadataStore;
use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\Config;
use KiwiCaptcha\DecodeError;
use KiwiCaptcha\Risk\RiskAction;
use KiwiCaptcha\Risk\RiskDecision;
use KiwiCaptcha\Risk\RiskEventKind;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\StorageInterface;
use KiwiCaptcha\Verifier;
use KiwiCaptcha\VerifyError;
use KiwiCaptcha\VerifyOutcome;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

/**
 * The Symfony validator: verifies a KiwiCaptcha solution token through the
 * core Verifier and resolves every valid verification's durable final
 * disposition through one fail-closed path, so a replay of a valid proof
 * reproduces the same application-level outcome. The verification pipeline
 * and its invariants are documented in docs/security-hardening.md.
 */
final class KiwiCaptchaValidator extends ConstraintValidator
{
    /**
     * Request attribute holding the canonical jti of the last
     * successfully verified challenge of this request (the core's
     * VerifyOutcome::nonce()). Request-scoped: set on the RequestStack
     * main request only on a valid verification, so the application can
     * key its business operation idempotency on (jti, action) after the
     * form validates.
     */
    public const VERIFIED_JTI_ATTRIBUTE = '_kiwi_captcha_verified_jti';

    /**
     * Request attribute holding the transaction binding the
     * application controller copied from the POSTed `kiwi_request_binding`
     * field before form validation. When the attribute is absent the
     * validator falls back to the raw POST field of the same name. The
     * binding is enforced against the challenge record's signed
     * request_binding: a bound challenge whose binding does not match is
     * rejected with the same invalid_or_expired outcome.
     */
    public const REQUEST_BINDING_ATTRIBUTE = '_kiwi_captcha_request_binding';

    /**
     * Request attribute holding the explicit per-operation identity
     * (`kiwi_operation_id`) of the logical operation redeeming the token,
     * e.g. the application's idempotency key for the protected action.
     * Resolution order: this attribute, then the constraint's static
     * `operationId` option. The id must be unique per logical operation.
     * The raw POSTed `kiwi_operation_id` field is deliberately never
     * accepted: a client-chosen identity would let the attacker enable
     * the idempotent-replay path.
     *
     * Replay semantics: by default (no explicit operation id) verification
     * is strictly single-use. The core records an operation identity with
     * the pending-to-consumed transition, but a fromStoredResult outcome
     * is never accepted by this validator, so a consumed token cannot
     * fund a second request however it is re-presented. The fallback
     * identity is a function of the token itself, which every request
     * holding the token can derive; it proves nothing about the
     * operation. With an explicit operation id, the same logical
     * operation's retry (same id, same token) replays the stored
     * committed success; IP/TTL/telemetry are exempt because the
     * committed outcome was durably recorded only after those checks
     * passed. A different id, a different binding, or a different token
     * is refused (AlreadyConsumed / RequestBindingMismatch).
     */
    public const OPERATION_ID_ATTRIBUTE = '_kiwi_captcha_operation_id';

    /**
     * The token verified correctly, but the chained-challenge
     * reassessment (risk.chaining) demands a stronger stage than the
     * first-stage profile (e.g. an Argon action or StepUp). The
     * violation carries the signed one-shot chain ticket in its
     * parameters under `{{ chain_ticket }}` (a stable, documented
     * machine-readable format): the application re-renders the widget
     * with data-kiwi-chain-ticket=<ticket> and the next challenge
     * request presents it for a stage-2 issuance. The ticket is valid
     * for risk.chaining.ttl_secs and is consumed atomically at
     * issuance.
     */
    public const CHAIN_REQUIRED_ERROR = 'kiwi.chain_required';

    /** @var string|null the canonical jti of the last valid verification */
    private ?string $lastVerifiedJti = null;

    /** @var string|null the record's transaction binding of the last valid verification */
    private ?string $lastVerifiedRequestBinding = null;

    /** @var string|null the last valid verification's signed receipt payload */
    private ?string $lastReceiptPayload = null;

    /** @var string|null the last valid verification's Ed25519 receipt signature */
    private ?string $lastReceiptSignature = null;

    /**
     * @param Verifier $verifier the bundle's configured Argon2id admission
     *                           gate (capacity exhaustion reports as a
     *                           VerifyOutcome, never a 500).
     * @param bool     $enforceTelemetry reject bot-signal telemetry when the
     *                                   widget collects it.
     * @param LoggerInterface|null $logger internal verification detail on
     *                                     failures; the public violation code
     *                                     stays collapsed.
     * @param StorageInterface|null $storage the challenge storage, needed for
     *                                       the ambiguous-consume retry: on
     *                                       ConsumeIndeterminate the stored
     *                                       consumed record decides the
     *                                       outcome.
     * @param ClientIpResolver|null $clientIpResolver the trusted client-IP
     *                                               policy that issued the
     *                                               record's binding.
     * @param SecurityEpochMonitor|null $epochMonitor the security-epoch
     *                                               monitor, refreshed before
     *                                               every verification.
     * @param ResultReceiptSigner|null $receiptSigner the optional Ed25519
     *                                               signer for exported
     *                                               results; null disables
     *                                               receipt signing.
     */
    public function __construct(
        private readonly Verifier $verifier,
        private readonly RequestStack $requestStack,
        private readonly string $secretKey,
        private readonly bool $enforceTelemetry = false,
        private readonly ?RiskGateway $risk = null,
        private readonly ?ContinuityCookie $continuityCookie = null,
        private readonly ?OutstandingChallenges $outstanding = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?StorageInterface $storage = null,
        private readonly ?ClientIpResolver $clientIpResolver = null,
        private readonly ?SecurityEpochMonitor $epochMonitor = null,
        private readonly ?ResultReceiptSigner $receiptSigner = null,
        /**
         * The chain ticket service issues the one-shot ChainRequired
         * tickets after a valid verification whose post-solve
         * reassessment demands a stronger stage (risk.chaining; null =
         * chaining disabled).
         */
        private readonly ?\BelConsulting\KiwiCaptchaBundle\Risk\ChainedChallengeTicketService $chainTickets = null,
        /**
         * The security-policy epoch (risk.policy_version) stamped into
         * issued chain tickets — a chain ticket is bound to the epoch its
         * stage-1 proof was verified under.
         */
        private readonly int $policyVersion = 1,
        /**
         * The server-side provider-metadata sidecar: the stage-2 chain
         * controller stamps the issued challenge's private chainId and
         * chainDepth metadata fields (never the cdata). A verified
         * challenge whose metadata carries a chainId never opens a third
         * stage: the chain ends at stage 2.
         */
        private readonly ?SiteVerifyMetadataStore $metadataStore = null,
        /**
         * The risk profile resolver, the same service the risk gateway
         * maps actions with: the authoritative stage-strength comparison.
         * A chain opens only when the reassessed action is not satisfied
         * by the solved challenge under the configured ladders (null =
         * chaining disabled).
         */
        private readonly ?RiskProfileResolver $riskResolver = null,
        /**
         * The durable post-solve disposition store: every valid
         * verification, fresh derive and stored-result replay alike,
         * resolves its final disposition through one path and persists it
         * per nonce before the application sees the outcome. A replay
         * thus reproduces the same disposition instead of bypassing the
         * post-solve policy. The extension always wires a store (Redis,
         * or the in-memory variant in test/dev); null computes the
         * disposition without persistence (manual construction).
         */
        private readonly ?PostSolveDispositionStore $dispositionStore = null,
        /**
         * The authoritative transaction-binding authority (nullable
         * service id risk.request_binding_authority): the presented
         * request_binding is a hint. The authority resolves the
         * server-owned canonical transaction binding; the validator
         * enforces the signed record binding against that value, the
         * same value the challenge controller signed at issuance. An
         * authority failure fails closed as temporary_unavailable; a null
         * resolution is the normal invalid-binding outcome. Chaining
         * opens only when the canonical binding resolves non-null; a raw
         * client-supplied binding without an authority is never
         * sufficient. Null = the raw request binding applies unchanged
         * (chaining unavailable: a stronger PoW demand falls back to
         * terminal StepUp, never a silent pass).
         */
        private readonly ?RequestBindingAuthorityInterface $bindingAuthority = null,
        /**
         * The retained margin beyond Config::MAX_TTL_SECS for the
         * nonce-keyed disposition records (risk.redis.ttl_margin_secs): the
         * disposition must survive at least as long as the consumed core
         * result can be replayed (the consumed record's own retention is
         * token lifetime + the same margin).
         */
        private readonly int $postSolveDispositionTtlMarginSecs = 0,
        /**
         * The chain lifetime (risk.chaining.ttl_secs): the absolute
         * expiry the validator passes when it opens a stage-2 chain
         * requirement (requireStage2). A ChainRequired ticket is never
         * signed with an independent fresh expiry: the signing re-signs
         * from the disposition-carried bound, the chain's original
         * server-held expiresAt persisted with the disposition as
         * chain_expires_at, see {@see self::chainRequirementExpiresAt()}.
         * The same (nonce, disposition) therefore reproduces the same
         * deterministic ticket, a concurrently opened chain of the same
         * transaction can never leak its expiry into this disposition's
         * ticket, and a ticket can never outlive its chain state.
         */
        private readonly int $chainTtlSecs = 300,
    ) {
    }

    /**
     * The canonical jti, VerifyOutcome::nonce(), of the last successfully
     * verified token, or null when no verification succeeded yet. Web
     * flows read the request attribute instead:
     * {@see self::VERIFIED_JTI_ATTRIBUTE} (request-scoped and race-free).
     */
    public function verifiedJti(): ?string
    {
        return $this->lastVerifiedJti;
    }

    /**
     * The transaction binding of the last successfully verified challenge:
     * VerifyOutcome::requestBinding(), the signed record binding, null
     * when the record is unbound. Null when no verification succeeded
     * yet.
     */
    public function verifiedRequestBinding(): ?string
    {
        return $this->lastVerifiedRequestBinding;
    }

    /**
     * The canonical JSON payload of the last verified challenge's Ed25519
     * receipt, the full replay-critical set signed from the consumed
     * record: {jti, tenant, action, request_binding, issued_at,
     * expires_at, issuer}. Null when no verification succeeded yet or no
     * signing key is configured (risk.result_receipt_signing_key). The
     * payload is public by construction (no secret material); pair it
     * with {@see verifiedReceiptSignature()} and verify against the
     * public key derived from the configured seed, never the private
     * key. Signature verification alone is not sufficient for single-use
     * actions: the integrator must atomically record the jti
     * (`INSERT IF NOT EXISTS`) and treat a pre-existing jti as a replay
     * (see the bundle README).
     */
    public function verifiedReceiptPayload(): ?string
    {
        return $this->lastReceiptPayload;
    }

    /**
     * The base64 Ed25519 detached signature (64 bytes) of the last
     * successfully verified challenge's receipt payload, or null
     * when no verification succeeded yet or receipt signing is disabled.
     * Verification:
     *
     *     sodium_crypto_sign_verify_detached(
     *         base64_decode($signature),
     *         $payload,
     *         $publicKey,
     *     );
     * where $publicKey is base64_decode of
     * ResultReceiptSigner::publicKeyBase64().
     */
    public function verifiedReceiptSignature(): ?string
    {
        return $this->lastReceiptSignature;
    }

    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof KiwiCaptcha) {
            throw new UnexpectedTypeException($constraint, KiwiCaptcha::class);
        }
        if ($value === null || $value === '') {
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                ->addViolation();

            return;
        }
        if (!\is_string($value)) {
            throw new UnexpectedTypeException($value, 'string');
        }

        // The security-policy epoch is refreshed before the verification
        // runs (bounded by the short cache window) and the verifier's
        // expected policy version rotates to the current monotonic max —
        // a central policy bump revokes outstanding challenges within one
        // cache window, a regressed or unavailable central value can
        // never weaken the epoch. The refreshed value is also captured as
        // the effective epoch: it binds the operation identity below
        // (exactly like Siteverify's idempotency fingerprint), so a
        // policy bump splits the retry's identity from the one the
        // consume recorded even for the exempt replay failures.
        $effectiveEpoch = $this->epochMonitor?->refresh() ?? $this->policyVersion;

        // Once now exceeds the last successful central read by
        // risk.security_epoch_max_stale_secs, the cached epoch may be
        // outdated (an emergency revocation could have landed while this
        // node could not read) — verification fails closed with the
        // retryable temporary_unavailable violation (never
        // invalid_or_expired: the token is not burned).
        if ($this->epochMonitor !== null && $this->epochMonitor->isStale()) {
            $this->logger?->info('KiwiCaptcha: verification refused — security-policy state stale', [
                'scope' => $constraint->scope,
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                ->addViolation();

            return;
        }

        $request = $this->requestStack->getMainRequest();
        // The issued record is authoritative: a non-empty binding tag means
        // the challenge IS bound, so always pass the request IP (a bound
        // record with a missing IP fails closed with MissingClientIp inside
        // the verifier). Records issued with BindingMode::None carry an
        // empty tag and verify regardless.
        //
        // The client IP comes through the bundle's trusted
        // client-IP policy (ClientIpResolver) — the same canonical IP the
        // challenge controller used when it minted (and bound) the record.
        // A request with ambiguous double-forwarding from a trusted peer is
        // rejected outright (fail closed — the binding cannot be evaluated
        // reliably) when risk.reject_ambiguous_forwarding is true.
        $clientIp = null;
        if ($request !== null) {
            try {
                $clientIp = $this->clientIpResolver !== null
                    ? $this->clientIpResolver->resolve($request)
                    : $request->getClientIp();
            } catch (AmbiguousForwardingException $e) {
                $this->logger?->info('KiwiCaptcha: verification refused — ambiguous forwarding headers', [
                    'scope' => $constraint->scope,
                ]);
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                    ->addViolation();

                return;
            }
        }

        // Pass the scope into the Argon2id admission gate. The
        // core Verifier calls acquire() without arguments, so the scope
        // travels through the request: stamp it here and let the bundle's
        // RequestScopeAdmissionGate forward it into the semaphore's
        // per-scope budget (argon2_max_per_tenant, checked in addition to
        // the global cap).
        $request?->attributes->set(\BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate::SCOPE_ATTRIBUTE, $constraint->scope);

        // Transaction binding, resolved before the core verification.
        // The authoritative canonical binding (the authority's server-owned
        // resolution, or the raw request binding when no authority is
        // configured) drives the verification itself: the operation
        // identity and the core's expected-request-binding enforcement are
        // both derived from it, so the same value that was signed at
        // issuance is enforced atomically with the consume, not only
        // compared after the fact. The resolution runs before any token
        // is consumed. An authority failure (its backend temporarily
        // unavailable) fails closed as the temporary_unavailable
        // violation — never a silent pass, never a raw exception — and a
        // null resolution (the transaction is invalid/unknown) is the
        // normal invalid-binding outcome via the post-verify comparison
        // below. Without an authority the raw request binding (the
        // request attribute the application controller copied from the
        // POSTed kiwi_request_binding field — or the raw POST field)
        // applies unchanged.
        try {
            $canonicalBinding = $this->resolveAuthoritativeBinding($constraint, $request);
        } catch (PostSolveDispositionUnavailableException $e) {
            $this->logger?->info('KiwiCaptcha: verification refused — the authoritative transaction binding is unavailable', [
                'scope' => $constraint->scope,
                'reason' => $e->getMessage(),
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                ->addViolation();

            return;
        }

        // The operation identity: the logical operation redeeming the
        // nonce, bound to the effective security-policy epoch (a same-id
        // retry after a central policy bump derives a different identity
        // — the Siteverify fingerprint composition) and to the operation
        // context in order of availability:
        //
        //  1. the explicit per-operation id the application supplies
        //     (kiwi_operation_id — the request attribute or the
        //     constraint option; the raw POSTed field is deliberately
        //     never accepted, since a client-chosen identity would let
        //     the attacker enable the replay path).
        //     The identity then carries an explicit operation-id component,
        //     which is the only component that authorizes the replay of a
        //     stored committed success (the idempotent retry);
        //  2. the canonical transaction binding when one resolves (the
        //     authority's server-owned value, or the raw request binding);
        //  3. the token nonce as the fallback when neither exists.
        //
        // The fallback exists so the pending→consumed transition always
        // records a per-token identity (a different operation presenting
        // the consumed token derives a different identity and is refused
        // by the core as AlreadyConsumed) — but it proves nothing about
        // the request: every holder of the token derives it. A
        // fromStoredResult outcome reached through it is therefore refused
        // below (strict single-use); only the explicit operation-id
        // component authorizes the idempotent replay.
        $operationId = $this->operationIdFor($constraint, $request);
        if ($operationId !== null) {
            $operationContext = 'opid:'.$operationId;
        } elseif ($canonicalBinding !== null) {
            $operationContext = 'binding:'.$canonicalBinding;
        } else {
            // An undecodable token hashes the empty nonce; the core rejects
            // it as MalformedToken before the identity matters.
            $operationContext = 'token:'.($this->verifiedNonceOf($value) ?? '');
        }
        $operationIdentity = hash('sha256', $constraint->scope."\0".($canonicalBinding ?? '')."\0".'epoch:'.$effectiveEpoch."\0".$operationContext);

        // The binding contract uses one authoritative record read: the
        // core verifier's own read, inside the verification, is the only
        // record read of the pipeline (the validator no longer peeks the
        // record to decide whether an expected request binding applies).
        // The signed-record binding comparison below enforces the contract
        // against the verified outcome's own requestBinding — the same
        // rule for a bound record (must equal the canonical binding) and
        // an unbound record (skipped entirely — BindingMode::None
        // deployments verify regardless of any presented binding).

        // CapacityExceeded (Argon2id admission saturated) surfaces as a
        // regular failed verification — fail closed as a captcha violation.
        // The operation identity is recorded with the pending→consumed
        // transition and gates the replay of the stored success.
        //
        // The transaction binding is enforced by the core, before the
        // one-shot consume: the canonical binding resolved above is
        // passed as the expected request binding, so a bound challenge
        // verified under the wrong transaction fails before its proof is
        // consumed and burned, and the outstanding release never fires
        // for it. The core's contract keeps BindingMode::None intact: an
        // explicitly unbound record (null binding) is permitted
        // regardless of the presented canonical binding; only a record
        // that actually carries a binding must equal the expected one.
        // The post-consume comparison below stays as a defensive
        // backstop for the configuration-drift case (a bound record
        // verified with no canonical binding configured).
        $outcome = $this->verifier->verify($value, $this->secretKey, $constraint->scope, $clientIp, null, $this->enforceTelemetry, $operationIdentity, $canonicalBinding, \KiwiCaptcha\RequestBindingExpectation::exact($canonicalBinding));

        // Ambiguous-consume deterministic retry: ConsumeIndeterminate
        // means the consume transition may have happened but its response
        // was lost. The validator normalizes the outcome from the stored
        // record instead of re-deriving (no side effects — the normalized
        // outcome flows through the same pipeline as any other
        // verification):
        //   - consumed record + stored valid result -> a valid outcome with
        //     the stored consumed binding (the binding check below applies
        //     the same rule to it);
        //   - stored invalid result -> invalid(InsufficientWork);
        //   - record still pending / consumed without a committed result /
        //     storage unavailable -> the outcome stays indeterminate
        //     (temporary_unavailable — retryable, never silently valid).
        // A stored-result outcome re-verifies the consumed record and
        // answers only "was the PoW cryptographically valid?"; the final
        // disposition (pass | deny | step-up | chain-required) is
        // resolved and persisted for every valid outcome below, stored
        // retries included.
        $outcome = $this->normalizeAmbiguousOutcome($outcome, $value, $operationIdentity);

        // The replay gate: a fromStoredResult outcome is the core handing
        // back the committed verdict of the attempt that consumed the
        // record. The stored success is an authorization grant, and the
        // identity that unlocked it proves the same logical operation only
        // when it carries an explicit operation-id component — the binding
        // and token-nonce components are derivable by any request holding
        // the token (a different form submission re-posting the token),
        // so without the explicit component the replay is refused here:
        // strict single-use by default, idempotent retry only through
        // a server-owned kiwi_operation_id. The IP/TTL/telemetry cheap
        // checks are not
        // re-run on the core's replay path, which is exactly why this
        // gate must hold for everything except the proven identity.
        if ($outcome->isOk() && $this->isStoredResult($outcome) && $operationId === null) {
            $this->logger?->info('KiwiCaptcha: replayed token refused — no explicit operation identity', [
                'reason' => VerifyError::AlreadyConsumed->value,
                'scope' => $constraint->scope,
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::REPLAYED_TOKEN_ERROR)
                ->addViolation();

            return;
        }

        // The collapsed public code; the precise core reason (WrongScope,
        // Expired, BadSignature, ...) stays in the logs — never exposed
        // to the client (no oracle for which check failed).
        // ConsumeIndeterminate is not a token-level failure: it is a
        // storage I/O ambiguity — the resolution tries the stored record
        // first, and an unresolvable indeterminate outcome maps to
        // temporary_unavailable (retryable, like StorageUnavailable),
        // never to invalid_or_expired — the client must not be told its
        // token is burned when it may still redeem.
        if (!$outcome->isOk()) {
            $code = $this->publicCode($outcome->error);
            if ($outcome->error !== null && $code !== KiwiCaptcha::INVALID_OR_EXPIRED_ERROR) {
                $this->logger?->info('KiwiCaptcha: verification refused', [
                    'reason' => $outcome->error->value,
                    'detail' => $outcome->detail,
                    'scope' => $constraint->scope,
                ]);
            }
            $this->context->buildViolation($constraint->message)
                ->setCode($code)
                ->addViolation();

            return;
        }

        // Transaction binding — the single authoritative binding
        // enforcement. The canonical binding was resolved before the
        // verification (and drives the operation identity, which is
        // recorded atomically with the consume); this comparison enforces
        // the signed record binding against that same resolved canonical
        // value, using the core verifier's authoritative record read (the
        // verified outcome's requestBinding). A challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely. For a stored-result
        // retry the outcome's requestBinding() is the stored consumed
        // binding, so the same rule gives the stored-result contract:
        // same binding -> same success, different binding ->
        // invalid_or_expired.
        if (!$this->requestBindingMatches($outcome, $canonicalBinding)) {
            $this->logger?->info('KiwiCaptcha: valid proof rejected — request binding mismatch', [
                'scope' => $constraint->scope,
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                ->addViolation();

            return;
        }

        // Resource accounting: the PoW is solved regardless of the later
        // risk disposition — the solved nonce's original source slot and
        // its live-outstanding membership are released through the
        // idempotent, nonce-authoritative hook (one-shot, ZREM-gated).
        // It runs for every accepted successful outcome, stored-result
        // retries included: a transient release failure during the
        // original verification must be repaired by the same logical
        // operation's retry (the deterministic committed result is
        // recovered, the stored-result outcome re-releases, and only the
        // nonce's first live-membership removal releases anything — a
        // repeated release is a no-op). This fails conservatively: the
        // caps are overcounted, never undercounted.
        $this->outstanding?->solved($outcome->nonce());

        // One final-disposition path: the core's retained result must
        // answer "was the PoW cryptographically valid?" — never "should
        // the application accept this protected action?". Every valid
        // verification (fresh derive and stored-result replay alike)
        // resolves its durable, nonce-keyed final disposition — the
        // post-solve risk reassessment, the honeypot evidence, the
        // chained-challenge opening and the nonce->decision consumption
        // all live behind this single path — and the disposition is
        // persisted before the application ever sees the outcome. A
        // replay of a valid proof reproduces the same pass | deny |
        // step-up | chain-required instead of bypassing the post-solve
        // policy. The resolution is fail-closed: an unavailable
        // disposition store, a busy claim or a refused finalize surfaces
        // as the retryable temporary_unavailable violation — never a
        // silent pass.
        try {
            [$disposition, $replayed, $requirement] = $this->resolveFinalDisposition($value, $outcome, $request, $constraint, (string) ($clientIp ?? ''), $canonicalBinding);
        } catch (PostSolveDispositionUnavailableException $e) {
            $this->logger?->info('KiwiCaptcha: post-solve disposition unavailable', [
                'scope' => $constraint->scope,
                'reason' => $e->getMessage(),
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                ->addViolation();

            return;
        }

        // Stage-2 chain transition by final disposition: the chain
        // transition runs strictly after the durable finalize, by
        // disposition kind — Pass -> markVerified (the obligation is
        // cleared), StepUp -> markStepUpRequired (the obligation is
        // kept), Deny -> markDenied (the obligation is kept). The
        // detection runs on every valid solve (the no-reassessment Pass
        // path included) against the requirement lookup threaded from
        // {@see self::resolveFinalDisposition()}, so a recognized
        // stage-2 nonce can never leave its chain issued behind a Pass
        // disposition. A transition failure or refusal is fail-closed
        // temporary_unavailable — the obligation is never cleared by the
        // core's consumed result alone.
        try {
            $this->applyStage2Disposition($value, $disposition, $constraint, $requirement);
        } catch (PostSolveDispositionUnavailableException $e) {
            $this->logger?->info('KiwiCaptcha: stage-2 chain transition unavailable', [
                'scope' => $constraint->scope,
                'reason' => $e->getMessage(),
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                ->addViolation();

            return;
        }

        switch ($disposition->kind) {
            case PostSolveDispositionKind::Pass:
                $this->finishSuccessfulApplicationVerification($value, $outcome, $request);

                return;
            case PostSolveDispositionKind::Deny:
                // The security context changed while the client was
                // solving: the fresh post-solve assessment rejects the
                // submission.
                $this->logger?->info('KiwiCaptcha: valid solve rejected by the post-solve assessment', [
                    'scope' => $constraint->scope,
                ]);
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR)
                    ->addViolation();

                return;
            case PostSolveDispositionKind::StepUp:
                // StepUp is terminal application-level step-up: it never
                // becomes a chain ticket (a ticket could later be spent
                // on ordinary PoW instead of the application's step-up).
                // The application routes the user to MFA/passkey/email
                // confirmation.
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED)
                    ->addViolation();

                return;
            case PostSolveDispositionKind::ChainRequired:
                // ChainRequired: the reassessment demanded a strictly
                // stronger PoW stage. Re-sign the one-shot chain ticket
                // from the persisted chain id and its original
                // server-held expiry (bound at finalize time) — never a
                // fresh current-obligation lookup, so a concurrently
                // opened chain of the same transaction can never leak
                // its expiry into this ticket and a replay reproduces
                // the same byte-identical ticket. The chain record is
                // re-read by id, see {@see self::chainRequirementExpiresAt()},
                // as the liveness and exact-bound check; a chain that is
                // gone or a carried expiry that differs from the exact
                // chain record fails closed temporary_unavailable,
                // never a silent downgrade to an unchained pass.
                try {
                    $ticket = $this->chainTickets?->ticketFor(
                        $disposition->chainId,
                        $this->chainRequirementExpiresAt($disposition),
                    );
                } catch (\Throwable $e) {
                    $this->logger?->info('KiwiCaptcha: chained challenge ticket unavailable', [
                        'scope' => $constraint->scope,
                    ]);
                    $this->context->buildViolation($constraint->message)
                        ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                        ->addViolation();

                    return;
                }
                if (!\is_string($ticket) || $ticket === '') {
                    $this->logger?->info('KiwiCaptcha: chained challenge ticket unavailable', [
                        'scope' => $constraint->scope,
                    ]);
                    $this->context->buildViolation($constraint->message)
                        ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                        ->addViolation();

                    return;
                }
                $this->context->buildViolation($constraint->message)
                    ->setCode(self::CHAIN_REQUIRED_ERROR)
                    ->setParameter('{{ chain_ticket }}', $ticket)
                    ->addViolation();

                return;
        }
    }

    /**
     * The record's signed request_binding,
     * VerifyOutcome::requestBinding(), must equal the canonical binding
     * of the request: the authority's server-owned resolution when an
     * authority is configured, the raw request binding otherwise (the
     * value the caller resolved once, before the comparison). An
     * unbound record (null binding) skips the check.
     */
    private function requestBindingMatches(\KiwiCaptcha\VerifyOutcome $outcome, ?string $canonicalBinding): bool
    {
        $recordBinding = \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
        if ($recordBinding === null) {
            return true;
        }

        return $canonicalBinding !== null && hash_equals($recordBinding, $canonicalBinding);
    }

    /**
     * Public violation-code collapse: every token-level failure
     * collapses to invalid_or_expired; the capacity refusals stay
     * distinct (rate_limited / temporary_unavailable). Internal detail
     * is logged, the client only ever sees the collapsed code.
     *
     * ConsumeIndeterminate is a storage I/O ambiguity, not a token-level
     * failure: the consume may or may not have happened. The resolution
     * tries the stored record first, and an unresolvable indeterminate
     * outcome maps to temporary_unavailable, retryable like
     * StorageUnavailable, never to invalid_or_expired: the client must
     * not be told its token is burned when it may still redeem.
     */
    private function publicCode(?VerifyError $error): string
    {
        return match ($error) {
            VerifyError::CapacityExceeded => KiwiCaptcha::RATE_LIMITED_ERROR,
            VerifyError::AdmissionUnavailable,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate => KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR,
            default => KiwiCaptcha::INVALID_OR_EXPIRED_ERROR,
        };
    }

    /**
     * Ambiguous-consume normalization: decide the outcome of a
     * ConsumeIndeterminate verification from the stored consumed record
     * via {@see ConsumedStateReadableInterface::consumedState()},
     * instead of re-deriving, with no side effects. The normalized
     * outcome flows through the same pipeline as any other
     * verification, including the replay gate, binding check,
     * outstanding accounting and final disposition. The replay cases:
     *  - a stored valid result whose retained operation identity matches
     *    the identity this validation derived (constant-time comparison)
     *    yields a valid outcome carrying the consumed record's nonce and
     *    stored binding — the same logical operation's committed verdict.
     *    A mismatched or absent retained identity never normalizes to a
     *    success: the pipeline refuses it as AlreadyConsumed (one solved
     *    token can never fund a different operation through the
     *    indeterminate branch).
     *  - a stored invalid result yields invalid(InsufficientWork): the
     *    original derivation failed, deterministically for every caller.
     *  - storage unavailable, no record, still pending, or consumed
     *    without a committed result keeps the original indeterminate
     *    outcome: publicCode() maps ConsumeIndeterminate to
     *    temporary_unavailable, retryable, never silently valid.
     */
    private function normalizeAmbiguousOutcome(VerifyOutcome $outcome, string $token, string $operationIdentity): VerifyOutcome
    {
        if ($outcome->error !== VerifyError::ConsumeIndeterminate) {
            return $outcome;
        }

        $consumed = $this->findConsumedRecord($token);
        if ($consumed === null) {
            // No storage wired, no consumed-state capability, undecodable
            // token, storage failure, record absent, or record still
            // pending (the first attempt never consumed it — a retry will
            // consume normally): the outcome stays indeterminate.
            return $outcome;
        }

        $result = $consumed->consumedResult;
        if ($result !== null && !$result->valid) {
            // The original derivation failed — the stored result is the
            // authoritative outcome, deterministic for every caller.
            return VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }
        if ($result === null) {
            // Consumed but the result was never committed (the original
            // attempt died mid-proof): genuinely indeterminate.
            return $outcome;
        }

        // Stored valid result: the deterministic retry of the logical
        // operation, authorized only by the retained identity. A null
        // retained identity (a plain consume by a caller that recorded
        // none) or any mismatch is refused — never a replayed success for
        // a different operation.
        if (
            $consumed->operationIdentity === null
            || !hash_equals($consumed->operationIdentity, $operationIdentity)
        ) {
            return VerifyOutcome::invalid(VerifyError::AlreadyConsumed);
        }

        // The pipeline's binding check enforces the stored-result
        // contract: the normalized outcome carries the stored consumed
        // binding, so the request binding must equal it — a challenge
        // bound to one transaction is never redeemable for another,
        // retries included. The replay gate above applies the same
        // explicit-operation-id rule to this outcome as to the core's.
        //
        // Failed-barrier replay guard: the consume and commit mutations
        // that produced this stored success may have landed on the
        // primary with their WAIT failing. Synthesizing the Valid here
        // read-only would return an authorization a stale-replica
        // promotion could resurrect — the causal fence is re-established
        // before the acceptance, exactly like every other stored-result
        // acceptance (the core replay paths, the resume read-back, the
        // Rust verifier, the SiteVerify idempotency store). A shortfall
        // leaves the outcome indeterminate (retryable temporary
        // unavailable), never a synthesized Valid.
        try {
            if ($this->storage instanceof \KiwiCaptcha\ReplicationBarrierInterface) {
                $this->storage->establishReplicationFence('the validator ambiguous-outcome stored acceptance');
            }
        } catch (\Throwable) {
            return $outcome;
        }

        return VerifyOutcome::valid($consumed->record->nonce, $consumed->consumedResult?->binding, true);
    }

    /**
     * Whether the outcome came from the core's stored consumed result (a
     * re-verify of a consumed record with a committed result) instead of
     * a fresh derivation. Detects both the accessor method and the
     * public property shapes across core versions.
     */
    private function isStoredResult(VerifyOutcome $outcome): bool
    {
        if (\method_exists($outcome, 'fromStoredResult')) {
            return (bool) $outcome->fromStoredResult();
        }

        return (bool) ($outcome->fromStoredResult ?? false);
    }

    /**
     * The final-disposition resolution, the single path every valid
     * verification, fresh derive and stored-result replay alike, flows
     * through:
     *
     *  0. the authoritative chain requirement of the transaction is
     *     resolved exactly once here and threaded through the whole
     *     pipeline, {@see self::assessFinalDisposition()} and
     *     {@see self::applyStage2Disposition()} never re-read it. A
     *     terminal requirement (denied / step_up_required) dominates
     *     every nonce, the exact stage-2 nonce and replays included: it
     *     answers before any assessment, and a terminal transaction
     *     never persists a Pass for any nonce. The lookup runs before
     *     the nonce -> decision handle is touched, so a chain-state read
     *     failure cannot consume the handle: the retry re-runs the
     *     lookup with the mapping intact and preserves the original
     *     decision id for the final disposition;
     *  1. the canonical nonce is decoded, a fresh owner token drawn and
     *     the nonce -> decision handle is consumed atomically with the
     *     claim, but only when the claim creates the missing pending
     *     record. The store's claim consumes the mapping inside that
     *     same transition, at most one winner, and persists the paired
     *     handle in the pending disposition record, so an owner crash
     *     can never lose the original decision id of a no-post-solve
     *     Pass. A complete, busy or takeover claim never touches the
     *     mapping key;
     *  2. the claim transition answers with the claim outcome AND the
     *     record the caller needs, so the fresh path is exactly
     *     claim -> compute -> finalize: 'complete' returns the persisted
     *     final disposition immediately, carried in the claim response. A
     *     replay of a valid proof reproduces the same pass | deny |
     *     step-up | chain-required rather than bypassing it, and a
     *     terminal requirement supersedes even a persisted disposition.
     *     'pending' means another owner's computation is live: the
     *     temporary_unavailable violation is answered while the decision
     *     mapping is never consumed by the busy claim.
     *     'claimed'/'taken_over' means this owner runs the post-solve
     *     assessment, persists the disposition and returns it; the
     *     claim response carries the pending record with the decision
     *     handle (a taken-over computation resumes with the original
     *     owner's handle kept in the pending record). No separate read
     *     round-trip is issued before or after the claim;
     *  3. the finalize must succeed before anything is returned: a
     *     store failure is the temporary_unavailable violation, never a
     *     silent pass.
     *
     * @return array{0: PostSolveDisposition, 1: bool, 2: ?ChainRequirement}
     *         the final disposition, whether it came from the persisted
     *         record (a replay, informational) and the threaded
     *         authoritative requirement, {@see self::applyStage2Disposition()}
     *
     * @throws PostSolveDispositionUnavailableException fail-closed: the
     *                                                 disposition could not
     *                                                 be resolved durably
     */
    private function resolveFinalDisposition(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $ip, ?string $canonicalBinding): array
    {
        $nonce = $this->verifiedNonceOf($token);
        if ($nonce === null || $nonce === '') {
            // Unreachable on a valid outcome (defense in depth): the decoded
            // nonce IS the verified proof's nonce. A token whose nonce
            // cannot be pinned down cannot be durably dispositioned — fail
            // closed.
            throw new PostSolveDispositionUnavailableException('the verified solution token carries no nonce');
        }
        $session = $request !== null ? $this->continuityCookie?->read($request) : null;

        // The authoritative requirement lookup — resolved exactly once
        // per validation and threaded through the assessment, the
        // stage-2 detection and the chain transitions ({@see
        // self::assessFinalDisposition()} / {@see self::applyStage2Disposition()}),
        // so the requirement can never diverge between the terminal-state
        // dominance, the disposition and the transition that follows it.
        // Runs before the nonce -> decision handle is consumed: a
        // chain-state read failure must never consume the handle — the
        // retry re-runs the lookup with the mapping intact and the
        // original decision id is preserved for the final disposition.
        // Fail-closed as before: only a successful lookup that finds no
        // record produces null.
        $requirement = $this->openRequirementFor($constraint, $canonicalBinding);

        if ($this->dispositionStore === null) {
            // No store wired (manual construction / legacy seam): the
            // disposition is computed and applied without persistence. The
            // extension always wires a store, so the durable path below is
            // the production behavior. The decision handle is consumed
            // directly (the atomic claim transfer is the store's job —
            // {@see PostSolveDispositionStore::claim()}).
            $decisionId = $this->consumeDecisionForToken($token);

            $final = $this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce, $canonicalBinding, $decisionId, $requirement);

            return [$final, false, $requirement];
        }

        $owner = bin2hex(random_bytes(16));
        $ttl = Config::MAX_TTL_SECS + $this->postSolveDispositionTtlMarginSecs;
        try {
            // Nonce-to-decision consumption, atomic with the claim: the
            // short-lived mapping is consumed, delete-on-read, with at
            // most one winner, inside the store's claim transition. The
            // paired handle is persisted in the pending disposition
            // record; see {@see PostSolveDispositionStore::claim()}. An
            // owner crash after the claim cannot lose the original
            // decision id, and a crash-taken-over computation completes
            // the disposition with it. On scopes without post_solve_check
            // the original pre-issue decision id becomes the request's
            // current decision id; see {@see RiskGateway::setCurrentDecisionId()}.
            // On post_solve_check scopes the superseded mapping is still
            // consumed (cleanup) and the fresh post-solve decision
            // becomes the current confirmation target instead. The claim
            // response carries the claim outcome AND the record the
            // caller needs for that outcome, so the fresh path is exactly
            // claim -> compute -> finalize with no separate read.
            //
            // Transaction acceptance guard: the requirement snapshot is
            // re-verified atomically with each acceptance (the claim's
            // complete branch and the guarded finalize). The obligation
            // id is derivable from the same transaction inputs whenever
            // chaining is wired, so the guard can see an obligation that
            // opened after the snapshot — a stale Pass is never committed
            // (or replayed) once the transaction advanced.
            $decisionKey = $this->risk?->decisionKeyFor($nonce);
            $obligationId = null;
            $snapshotChainId = null;
            if ($this->chainTickets !== null && $this->bindingAuthority !== null && $canonicalBinding !== null) {
                $obligationId = $this->chainTickets->obligationIdFor($constraint->scope, $canonicalBinding, $this->policyVersion);
                $snapshotChainId = $requirement?->chainId ?? null;
            }
            [$claim, $claimRecord, $claimGuard] = $this->dispositionStore->claim($nonce, $owner, $ttl, $decisionKey, $obligationId, $snapshotChainId, $requirement?->stage2Nonce);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition store is unavailable', 0, $e);
        }

        if ($claim === 'complete') {
            $disposition = $claimRecord?->disposition;
            if ($disposition === null) {
                // Complete without a usable disposition: corrupt state —
                // never silently pass.
                throw new PostSolveDispositionUnavailableException('the post-solve disposition record is corrupt');
            }
            // The claim's atomic acceptance guard re-verified the
            // transaction state at claim time. It dominates the stored
            // record: a Pass persisted before the transaction
            // terminalized (or before a chain opened) is never replayed
            // once the transaction advanced — the terminal outcome or an
            // authoritative re-resolution answers instead.
            if ($claimGuard === PostSolveFinalizeOutcome::TransactionDenied) {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::Deny, $claimRecord?->decisionId);
                if ($this->risk !== null && $disposition->decisionId !== null) {
                    $this->risk->setCurrentDecisionId($disposition->decisionId);
                }

                return [$disposition, true, $requirement];
            }
            if ($claimGuard === PostSolveFinalizeOutcome::TransactionStepUp) {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, $claimRecord?->decisionId);
                if ($this->risk !== null && $disposition->decisionId !== null) {
                    $this->risk->setCurrentDecisionId($disposition->decisionId);
                }

                return [$disposition, true, $requirement];
            }
            if ($claimGuard === PostSolveFinalizeOutcome::ChainRequired) {
                $disposition = $this->reResolvedChainRequiredDisposition($constraint, $canonicalBinding, $claimRecord?->decisionId);

                return [$disposition, true, $requirement];
            }
            if ($claimGuard === PostSolveFinalizeOutcome::ObligationChanged) {
                // The obligation moved since the snapshot: never accept
                // the stale record — the retry re-resolves the fresh
                // requirement and reconstructs the disposition.
                throw new PostSolveDispositionUnavailableException('the chain obligation moved during the post-solve acceptance');
            }
            // Terminal transaction state dominates — replays included: a
            // persisted nonce disposition (e.g. a Pass persisted before
            // the transaction terminalized) is superseded by the
            // requirement's terminal state, so a replay of the exact
            // stage-2 nonce answers the terminal outcome — never the
            // stale disposition, never the stage-2 transition conflict.
            if ($requirement !== null && $requirement->state === 'denied') {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::Deny, $claimRecord?->decisionId);
            } elseif ($requirement !== null && $requirement->state === 'step_up_required') {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, $claimRecord?->decisionId);
            }
            // A replay reproduces the request-scoped decision id too, so the
            // application can confirm the same decision handle.
            if ($this->risk !== null && $disposition->decisionId !== null) {
                $this->risk->setCurrentDecisionId($disposition->decisionId);
            }

            return [$disposition, true, $requirement];
        }

        if ($claim !== 'claimed' && $claim !== 'taken_over') {
            // 'pending': another owner's claim is live (or the claim was
            // re-entered with the same owner token). Retryable — never a
            // silent pass.
            throw new PostSolveDispositionUnavailableException('the post-solve disposition claim is held by another owner');
        }

        // The stored decision handle rides in the claim response: the
        // claim's atomic consume wrote the paired handle into the pending
        // record (a takeover resumes the original owner's handle — the
        // crashed owner's mapping is already consumed), so the completed
        // disposition keeps the original decision id.
        if ($claimRecord === null) {
            // The claim was won but the response carries no record (a
            // clock/expiry boundary): fail closed — never silently pass.
            throw new PostSolveDispositionUnavailableException('the post-solve disposition record vanished after the claim');
        }
        $storedDecisionId = $claimRecord->decisionId;

        $disposition = $this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce, $canonicalBinding, $storedDecisionId, $requirement);

        try {
            $outcome = $this->dispositionStore->finalizeGuarded($nonce, $owner, $disposition, $obligationId, $snapshotChainId, $requirement?->stage2Nonce);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition could not be persisted', 0, $e);
        }
        switch ($outcome) {
            case PostSolveFinalizeOutcome::Finalized:
                break;
            case PostSolveFinalizeOutcome::TransactionDenied:
                // The transaction terminalized between the snapshot and
                // the finalize: the terminal outcome answers, never the
                // stale Pass (the retry persists it durably via the
                // terminal-dominance path).
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::Deny, $storedDecisionId);
                break;
            case PostSolveFinalizeOutcome::TransactionStepUp:
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, $storedDecisionId);
                break;
            case PostSolveFinalizeOutcome::ChainRequired:
                // A chain opened (or a stage-2 was issued for another
                // nonce) after the snapshot: the stale Pass is not
                // committed; the authoritative re-resolution answers
                // ChainRequired.
                $disposition = $this->reResolvedChainRequiredDisposition($constraint, $canonicalBinding, $storedDecisionId);
                break;
            case PostSolveFinalizeOutcome::ObligationChanged:
                // The obligation moved since the snapshot: fail closed —
                // the retry re-resolves the fresh requirement.
                throw new PostSolveDispositionUnavailableException('the chain obligation moved during the post-solve finalize');
            case PostSolveFinalizeOutcome::OwnershipLost:
            case PostSolveFinalizeOutcome::Missing:
            case PostSolveFinalizeOutcome::Corrupt:
                throw new PostSolveDispositionUnavailableException('the post-solve disposition finalize was refused');
        }

        return [$disposition, false, $requirement];
    }

    /**
     * Re-resolve the open chain requirement and build the ChainRequired
     * disposition for the guard's authoritative re-resolution. The
     * chain must still exist (an obligation that vanished mid-acceptance
     * is fail-closed temporary-unavailable; the retry re-resolves).
     */
    private function reResolvedChainRequiredDisposition(KiwiCaptcha $constraint, ?string $canonicalBinding, ?string $decisionId): PostSolveDisposition
    {
        $fresh = $this->openRequirementFor($constraint, $canonicalBinding);
        if ($fresh === null) {
            throw new PostSolveDispositionUnavailableException('the chain requirement vanished during the post-solve acceptance');
        }

        return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $fresh->chainId, $fresh->expiresAt);
    }

    /**
     * The post-solve assessment of a verified proof. It records the
     * form-submission honeypot evidence under its nonce-derived
     * idempotency key, so a crash-taken-over computation never
     * double-books the signal. It runs a fresh reassessment whenever
     * the scope opts in (post_solve_check), chaining is relevant, or
     * the exact decoy was filled; a honeypot hit alone must trigger the
     * fresh v2 assessment. The assessment always carries the
     * nonce-derived stable idempotency key
     * 'postsolve:'.hash('sha256', $nonce), so a takeover re-assessment
     * is dedupe-key-identical to the original.
     *
     * Terminal transaction state dominates first: the authoritative
     * requirement, threaded from {@see resolveFinalDisposition()}, bound
     * to its terminal denied / step_up_required state answers that
     * terminal disposition for every nonce, the exact stage-2 nonce and
     * replays included. It answers before any assessment runs and
     * before the caller finalizes the nonce disposition, so a terminal
     * transaction never persists a Pass for any nonce.
     *
     * @param string|null $canonicalBinding the authority's server-owned
     *                                      transaction binding, resolved
     *                                      once before the binding
     *                                      comparison, never re-resolved
     *                                      here.
     * @param string|null $originalDecisionId the stored decision handle:
     *                                      what the first owner consumed,
     *                                      or the pending record's
     *                                      handle on a takeover.
     * @param ChainRequirement|null $requirement the authoritative open
     *                                      chain requirement, threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()},
     *                                      never re-read here.
     */
    private function assessFinalDisposition(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $ip, ?string $session, string $nonce, ?string $canonicalBinding, ?string $originalDecisionId, ?ChainRequirement $requirement): PostSolveDisposition
    {
        $postSolveScope = $this->risk !== null && $this->risk->postSolveCheck($constraint->scope);

        // Terminal transaction state dominates every nonce — the exact
        // stage-2 nonce included — before any assessment: a transaction
        // bound to its terminal denied/step_up_required state answers
        // that terminal disposition permanently, the fresh post-solve
        // decision is never consulted, and a terminal transaction never
        // persists a Pass for any nonce. The caller durably finalizes
        // the disposition after this resolution, so the persisted nonce
        // disposition is the terminal kind (the deterministic handle is
        // the original pre-issue one — no fresh assessment ever ran for
        // a terminal transaction).
        if ($requirement !== null && $requirement->state === 'denied') {
            return new PostSolveDisposition(PostSolveDispositionKind::Deny, $originalDecisionId);
        }
        if ($requirement !== null && $requirement->state === 'step_up_required') {
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $originalDecisionId);
        }

        // Chaining (risk.chaining): a successful first-stage proof
        // opens the selective second stage — the reassessment runs for
        // every valid solve, and when it demands an action the solved
        // challenge does not already satisfy (the resolver's actual
        // configured ladders), the final disposition is ChainRequired
        // (stage 1) or terminal StepUp (stage 2 — the chain ends
        // there). StepUp is terminal application-level step-up (never a
        // chained PoW) and Deny rejects the submission. A verified
        // challenge whose metadata sidecar carries a server-stamped
        // chainId never opens a third stage.
        $chainEligible = false;
        if ($this->risk !== null && $this->chainTickets !== null) {
            try {
                $chainEligible = !$this->verifiedChallengeCarriesChainMarker($token);
            } catch (\Throwable $e) {
                if ($this->bindingAuthority !== null) {
                    // Chaining is enabled (the chain service and the
                    // binding authority are wired): the private stage
                    // marker cannot be established, so the verified
                    // challenge may be the stage-2 challenge of an open
                    // chain. A third stage must never open from an
                    // unknown stage, so this fails closed with the
                    // temporary_unavailable violation: never acceptance,
                    // never a silent stage-1-eligible treatment.
                    throw new PostSolveDispositionUnavailableException('the chain marker of the verified challenge could not be established', 0, $e);
                }
                // Chaining cannot open without the binding authority: no
                // stage-2 chain can exist for this deployment, so the
                // marker is irrelevant. The challenge is treated as
                // possibly stage-2 (no chain ticket, never a third
                // stage) and the verification itself still passes.
                $chainEligible = false;
            }
        }

        // Form-submission honeypot (post-verification): the expected
        // decoy field name derives from the verified nonce, 'decoy_' +
        // the first 8 hex characters of sha256(nonce), the exact same
        // derivation the challenge controller used when it emitted the
        // field. Only that exact field is inspected: any other
        // decoy_<hash> field is ignored, since a decoy name is
        // server-issued and nonce-bound and a mismatched name is not
        // this challenge's decoy. A filled expected field records
        // DecoyFieldSubmitted evidence and feeds the post-solve
        // assessment through the risk-v2 path, so the honeypot signal
        // actually moves the score. Evidence only: never a gate and
        // never affects the proof validity.
        $honeypotHit = false;
        if ($this->risk !== null && $request !== null) {
            $honeypotHit = $this->formDecoyEvidence($request, self::expectedDecoyField($nonce));
        }

        // The original pre-issue decision id was consumed atomically
        // with the claim (the store's claim consumes the nonce ->
        // decision mapping inside the same transition, at most one
        // consumer, whenever the claim creates the missing pending
        // record) and travels in as the stored handle. On scopes
        // without post_solve_check it becomes the request's current
        // decision id; see {@see RiskGateway::setCurrentDecisionId()}.
        // On post_solve_check scopes the superseded mapping is already
        // consumed (cleanup) and the fresh post-solve decision becomes
        // the current confirmation target instead.
        if ($this->risk !== null && !$postSolveScope && $originalDecisionId !== null) {
            $this->risk->setCurrentDecisionId($originalDecisionId);
        }

        // Honeypot evidence: recorded with its nonce-derived idempotency
        // key, so a crash-taken-over re-assessment or a concurrent retry
        // that wins the takeover re-uses the same dedupe identity and
        // the signal is never double-booked. Evidence only: a recording
        // failure never breaks the form submission.
        if ($honeypotHit) {
            try {
                $this->risk?->honeypotEvidence(
                    RiskEventKind::DecoyFieldSubmitted,
                    $constraint->scope,
                    $ip,
                    $session,
                    'honeypot:'.hash('sha256', $nonce),
                );
            } catch (\Throwable) {
                // Evidence only.
            }
        }

        $mustReassess = $postSolveScope || $chainEligible || $honeypotHit;
        if (!$mustReassess) {
            // Post-solve feedback: feed the valid outcome into the
            // adaptive risk engine as plain SolveSuccess feedback (the
            // gateway does not confirm its own post-solve decision —
            // ConfirmedLegitimate / ConfirmedAbuse are
            // application-only signals). The scope string is never
            // validated against the policy map here — unknown scopes
            // are handled by the gateway.
            if ($this->risk !== null) {
                $this->risk->solveOutcome($constraint->scope, $ip, $session, $outcome->error);
            }

            return new PostSolveDisposition(PostSolveDispositionKind::Pass, $originalDecisionId);
        }

        // Post-solve check: a fresh SolveSuccess assessment with the
        // same context, always keyed by the nonce-derived stable
        // idempotency key — a takeover re-assessment never double-books
        // risk signals. An unavailable risk signal (e.g. an unparseable
        // or missing client IP) enforces the scope's degraded friction
        // instead of silently skipping the adaptive re-check — in
        // BindingMode::None deployments a valid PoW must not pass with
        // zero adaptive friction (mirrors the fail-safe degraded rule
        // on the pre-issue path).
        $postSolveKey = 'postsolve:'.hash('sha256', $nonce);
        try {
            $postSolve = $honeypotHit
                ? $this->risk->postSolveDecisionV2(
                    $constraint->scope,
                    $ip,
                    $session,
                    null,
                    $postSolveKey,
                    $this->risk->clientContextV2(true, $session, null, null),
                )
                : $this->risk->postSolveDecision($constraint->scope, $ip, $session, null, $postSolveKey);
        } catch (\InvalidArgumentException) {
            $postSolve = $this->risk->degradedDecisionForScope($this->risk->scopeId($constraint->scope));
        }

        return $this->mapPostSolveDecision($token, $outcome, $constraint, $nonce, $postSolve, $canonicalBinding, $requirement);
    }

    /**
     * Map the post-solve decision to the final disposition of a
     * non-terminal transaction; the requirement's terminal states were
     * already resolved as the authoritative disposition before the
     * assessment, since terminal transaction state dominates every
     * nonce. With an open obligation the final disposition is the
     * monotonic-escalation max of the obligation and the fresh
     * decision: security may rise, it never falls, and an existing
     * obligation never freezes its security level.
     *
     *  - a fresh Deny wins (terminal rejection) and terminalizes the
     *    open obligation itself, markTransactionDenied, nonce-agnostic,
     *    keyed by the chain/obligation identity. The denial is durable
     *    for the rest of the transaction's lifetime, so a later token of
     *    the same transaction cannot re-open the chain after the
     *    transient risk condition decayed.
     *  - then a fresh StepUp wins (terminal application-level step-up,
     *    never a chained PoW) and terminalizes the open obligation,
     *    markTransactionStepUpRequired, with the same durability.
     *  - then a fresh strictly stronger chainable action raises the
     *    obligation atomically, requireStage2 with the fresh action, the
     *    store's raise-only create-or-get. The same chain id and the
     *    original expiry are preserved; only the required rank/action
     *    rise, yielding ChainRequired with that same chain id.
     *  - then a fresh equal/weaker/Allow action leaves the obligation
     *    unchanged, its recorded floor intact, yielding ChainRequired
     *    with the requirement's chain id: a stage-1 token of a chained
     *    transaction cannot pass, whatever the fresh assessment says.
     *
     * Without an open obligation: Deny -> Deny; StepUp -> StepUp,
     * terminal, never a chained PoW; Allow, or the required PoW level
     * already satisfied by the solved challenge, -> Pass. A strictly
     * stronger PoW requirement opens a chain when chaining is
     * available. Stage 2 -> StepUp: the chain ends at stage 2, never a
     * third stage. Stage 1 + chaining available -> requireStage2(...) ->
     * ChainRequired, where a raw client-supplied binding without an
     * authority is insufficient. Otherwise terminal StepUp: a
     * stronger-PoW requirement must not silently disappear when chaining
     * is unavailable.
     *
     * Terminalization-first ordering: the nonce-agnostic obligation
     * terminalization runs here, at the disposition-computation point of
     * the fresh Deny/StepUp cases, see {@see self::terminalizeOpenChain()},
     * before the nonce-disposition finalize. A failure of the finalize
     * after a successful terminalization answers temporary_unavailable,
     * and the retry rediscovers the terminal transaction, the dominance
     * rule, and reconstructs the terminal disposition: no authorization
     * weakness, intentionally conservative. The stage-2 (nonce-pinned)
     * chain transition itself is not performed here: the caller
     * finalizes the disposition first, the durable
     * {@see PostSolveDispositionStore} finalize, and the stage-2 chain
     * is transitioned after, by disposition kind, in
     * {@see self::applyStage2Disposition()}. The final disposition is
     * authoritative for terminality, never the core's consumed result.
     *
     * @param ChainRequirement|null $requirement the authoritative open
     *                                      chain requirement, threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()},
     *                                      never re-read here
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 requirement cannot be
     *                                                 opened or its state
     *                                                 read: fail closed,
     *                                                 never a silent pass
     *                                                 while the obligation
     *                                                 may be uncleared
     */
    private function mapPostSolveDecision(string $token, VerifyOutcome $outcome, KiwiCaptcha $constraint, string $nonce, ?RiskDecision $postSolve, ?string $canonicalBinding, ?ChainRequirement $requirement): PostSolveDisposition
    {
        // Depth-2 detection (read-only): the verified challenge may be
        // the stage-2 challenge of an open chain requirement, its nonce
        // equals the requirement's stage2Nonce via the threaded lookup
        // from {@see resolveFinalDisposition()}. The chain then ends at
        // stage 2, and a still-stronger requirement is terminal StepUp,
        // never a third stage. The transition runs after the disposition
        // is durably finalized, see {@see self::applyStage2Disposition()}.
        //
        // Obligation-authoritative: the open requirement is consulted
        // before the fresh assessment is applied, a partial chain-state
        // read failure fails closed, {@see self::openRequirementFor()},
        // and an existing obligation can never be downgraded by a weaker
        // fresh assessment. The requirement's terminal states are not
        // handled here: they were resolved by the caller before the
        // assessment, {@see self::assessFinalDisposition()}, where the
        // terminal dominance precedes the $isStage2 computation and the
        // nonce-disposition finalize. With an open obligation the final
        // disposition is the monotonic-escalation max of the
        // obligation's state and the fresh assessment:
        //
        //  1. a fresh Deny wins (terminal rejection) and terminalizes
        //     the open obligation, markTransactionDenied, the denial
        //     durable for the transaction's lifetime;
        //  2. then a fresh StepUp wins, terminal application-level
        //     step-up, never a chain ticket, and terminalizes the open
        //     obligation, markTransactionStepUpRequired;
        //  3. then a fresh strictly stronger chainable action atomically
        //     raises the obligation, requireStage2, the store's
        //     raise-only mechanism: the same chain id, the original
        //     expiry preserved, and ChainRequired carries that same
        //     chain id, so the recorded security level never freezes;
        //  4. then a fresh equal/weaker/Allow, or unknown-scope null,
        //     action leaves the obligation unchanged, its recorded floor
        //     intact, yielding ChainRequired with the requirement's
        //     chain id: a stage-1 token of a chained transaction can
        //     never pass.
        $isStage2 = $requirement !== null && $requirement->stage2Nonce !== null && hash_equals($requirement->stage2Nonce, $nonce);

        if ($requirement !== null && !$isStage2 && $requirement->state !== 'verified') {
            // The submitted nonce is not the requirement's exact
            // stage-2 nonce: the requirement state is the authoritative
            // floor of the transaction (the 'verified' state is the
            // anomaly — its obligation should already be gone — and
            // falls through as the requirement's absence).
            $decisionId = $postSolve?->decisionId;

            // available/reserved/issued: the transaction still owes its
            // stage 2 — the fresh assessment now participates (it can
            // only escalate the obligation, never decay it):
            if ($postSolve !== null) {
                // 1. A fresh Deny wins — the terminal rejection. The
                //    fresh Deny also terminalizes the open obligation
                //    itself, {@see self::terminalizeOpenChain()}: the
                //    nonce-agnostic markTransactionDenied, keyed by the
                //    chain/obligation identity. The denial is durable
                //    for the rest of the transaction's lifetime, so a
                //    later token of the same transaction can never
                //    re-open the chain after the transient risk
                //    condition decayed. The terminalization failure is
                //    fail-closed temporary_unavailable (never a bare
                //    Deny without the durable transaction terminality),
                //    except 'already_verified' — the normal post-Pass
                //    anomaly (the transaction already ended via Pass —
                //    its obligation is gone, the fresh disposition
                //    applies to the nonce alone).
                if ($postSolve->action === RiskAction::Deny) {
                    $this->terminalizeOpenChain($requirement, PostSolveDispositionKind::Deny);

                    return new PostSolveDisposition(PostSolveDispositionKind::Deny, $decisionId);
                }
                // 2. A fresh StepUp wins — StepUp is terminal
                //    application-level step-up (it never becomes a chain
                //    ticket: a ticket could later be spent on ordinary
                //    PoW instead of the application's step-up). The
                //    fresh StepUp also terminalizes the open obligation
                //    (markTransactionStepUpRequired — the same durable
                //    terminality for the transaction's lifetime).
                if ($postSolve->action === RiskAction::StepUp) {
                    $this->terminalizeOpenChain($requirement, PostSolveDispositionKind::StepUp);

                    return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
                }

                // 3. A fresh strictly stronger chainable demand raises
                //    the recorded floor atomically: requireStage2 with
                //    the fresh action — the store's raise-only
                //    create-or-get keeps the same chain id and the
                //    original expiry, only the required rank/action
                //    rise.
                if ($postSolve->action !== RiskAction::Allow
                    && !$this->recordSatisfiesRequiredAction($token, $postSolve->action)
                    && $postSolve->action->rank() > $requirement->requiredRank
                ) {
                    // Chaining is available (the open obligation proves
                    // it was when the chain opened; the guard mirrors
                    // the no-obligation path below).
                    if ($this->chainTickets !== null && $this->bindingAuthority !== null && $canonicalBinding !== null) {
                        try {
                            $raised = $this->chainTickets->requireStage2(
                                $nonce,
                                $constraint->scope,
                                $canonicalBinding,
                                $this->policyVersion,
                                $postSolve->action,
                                $this->chainExpiresAt(),
                            );
                        } catch (\Throwable $e) {
                            throw new PostSolveDispositionUnavailableException('the chain requirement could not be raised', 0, $e);
                        }
                        $chainId = $raised->chainId;
                        if (!\is_string($chainId) || $chainId === '') {
                            throw new PostSolveDispositionUnavailableException('the chain requirement carries no chain id');
                        }

                        // The disposition carries the requirement's
                        // original expiry bound (the raise preserves it
                        // — the store's raise-only create-or-get): the
                        // ticket signing re-signs from this carried
                        // bound, never a fresh obligation lookup.
                        return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $chainId, $raised->expiresAt);
                    }
                    // Chaining unavailable: the stronger demand must
                    // never silently downgrade to the weaker recorded
                    // floor — terminal StepUp (mirrors the
                    // no-obligation path).
                    return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
                }
            }

            // 4. A fresh equal/weaker/Allow/neutral action leaves the
            //    obligation unchanged (its recorded floor intact) —
            //    ChainRequired with the requirement's same chain and its
            //    original expiry bound (the disposition carries both, so
            //    the signing never re-consults the obligation): a
            //    stage-1 token of a chained transaction can never pass.
            return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $requirement->chainId, $requirement->expiresAt);
        }

        if ($postSolve === null) {
            // The scope is unknown and the engine declines to evaluate:
            // nothing to enforce beyond the solved proof.
            return new PostSolveDisposition(PostSolveDispositionKind::Pass);
        }
        $decisionId = $postSolve->decisionId;

        if ($postSolve->action === RiskAction::Deny) {
            return new PostSolveDisposition(PostSolveDispositionKind::Deny, $decisionId);
        }
        if ($postSolve->action === RiskAction::StepUp) {
            // StepUp is terminal application-level step-up: it never
            // becomes a chain ticket (a ticket could later be spent on
            // ordinary PoW instead of the application's step-up).
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
        }
        if ($postSolve->action === RiskAction::Allow || $this->recordSatisfiesRequiredAction($token, $postSolve->action)) {
            // The required PoW level is already satisfied by the solved
            // challenge under the actual configured ladders.
            return new PostSolveDisposition(PostSolveDispositionKind::Pass, $decisionId);
        }

        // A strictly stronger PoW requirement.
        if ($isStage2) {
            // The chain ends at stage 2: a still-stronger requirement is
            // terminal StepUp, never a third stage.
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
        }

        // Stage-1 solved challenge: the chain opens only when chaining is
        // available — enabled and the canonical transaction binding
        // resolved non-null (a raw client-supplied binding without an
        // authority is never sufficient). The canonical binding is the
        // value resolved once before the binding comparison — the
        // authority is never consulted again here.
        if ($this->chainTickets !== null && $this->bindingAuthority !== null && $canonicalBinding !== null) {
            try {
                $chainRequirement = $this->chainTickets->requireStage2(
                    $nonce,
                    $constraint->scope,
                    $canonicalBinding,
                    $this->policyVersion,
                    $postSolve->action,
                    $this->chainExpiresAt(),
                );
            } catch (\Throwable $e) {
                throw new PostSolveDispositionUnavailableException('the chain requirement could not be opened', 0, $e);
            }
            $chainId = $chainRequirement->chainId;
            if (!\is_string($chainId) || $chainId === '') {
                throw new PostSolveDispositionUnavailableException('the chain requirement carries no chain id');
            }

            // The disposition carries the freshly opened requirement's
            // expiry bound (the same value the ticket will be signed
            // from — persisted as chain_expires_at, so a replay re-signs
            // the deterministic ticket without any obligation lookup).
            return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $chainId, $chainRequirement->expiresAt);
        }

        // Chaining unavailable (disabled or no authoritative binding):
        // the stronger-PoW requirement must never silently disappear —
        // it surfaces as terminal StepUp instead.
        return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
    }

    /**
     * Terminalize an open obligation by the fresh Deny/StepUp
     * disposition (nonce-agnostic, the exact stage-2 nonce is not
     * required): the obligation becomes terminal denied /
     * step_up_required for the rest of its lifetime, atomically over
     * the chain + obligation keys. {@see ChainedChallengeTicketService::markTransactionDenied()}
     * / {@see ChainedChallengeTicketService::markTransactionStepUpRequired()}
     * carry the transaction's obligation id with the transition. A
     * stale chain, where the obligation moved between the requirement
     * read and the transition, is refused; the obligation mapping is
     * kept. A later token of the same transaction can therefore never
     * re-open the chain after the transient risk condition decayed.
     *
     * Terminalization-first ordering: the chain transition is applied
     * before the nonce-disposition finalize; a failure of the finalize
     * after a successful terminalization answers temporary_unavailable,
     * and the retry rediscovers the terminal transaction, the dominance
     * rule, {@see self::assessFinalDisposition()}, and reconstructs the
     * terminal disposition. No authorization weakness, intentionally
     * conservative. A terminalization failure, or a refusal,
     * 'conflict'/'missing'/'obligation_moved', is fail-closed
     * temporary_unavailable: a bare Deny/StepUp is never returned
     * without the durable transaction terminality. The
     * 'already_verified' outcome is the normal post-Pass anomaly: the
     * transaction already ended via Pass and its obligation is gone,
     * so it falls through and the fresh disposition applies to the
     * nonce alone.
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 state is absent,
     *                                                 terminal with the
     *                                                 other disposition
     *                                                 (conflict), the
     *                                                 obligation moved, or
     *                                                 the transition
     *                                                 failed: fail closed,
     *                                                 never a bare
     *                                                 disposition without
     *                                                 durable terminality
     */
    private function terminalizeOpenChain(ChainRequirement $requirement, PostSolveDispositionKind $kind): void
    {
        // The obligation-bound transition: the requirement's server-held
        // (scope, binding, policy epoch) derive the transaction's
        // obligation id — the same id the chain was created under — so
        // the store can atomically verify the mapping still points at
        // this chain before transitioning.
        $obligationId = $this->chainTickets->obligationIdFor($requirement->scope, $requirement->requestBinding, $requirement->policyVersion);
        try {
            $result = $kind === PostSolveDispositionKind::Deny
                ? $this->chainTickets->markTransactionDenied($requirement->chainId, $obligationId)
                : $this->chainTickets->markTransactionStepUpRequired($requirement->chainId, $obligationId);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the chain terminalization failed', 0, $e);
        }
        if ($result === ChainVerifiedResult::AlreadyVerified) {
            return;
        }
        if ($result === ChainVerifiedResult::Conflict || $result === ChainVerifiedResult::Missing) {
            throw new PostSolveDispositionUnavailableException(sprintf('the chain terminalization was refused (%s)', $result->value));
        }
    }

    /**
     * The stage-2 chain transition by final disposition: the
     * disposition is authoritative for transaction terminality, never
     * the core's consumed result. It runs after the disposition was
     * durably finalized; {@see PostSolveDispositionStore::finalize()}
     * must have succeeded, guaranteed by the caller's
     * resolveFinalDisposition, so the chain transition can never clear
     * an obligation whose final disposition is not yet durable.
     *
     * Detection uses the same threaded requirement: {@see
     * self::resolveFinalDisposition()} resolved it exactly once and it
     * travels through the whole pipeline, never re-read here. The
     * verified challenge is a recognized stage-2 nonce when the
     * requirement holds the exact nonce as its stage2Nonce. The
     * detection runs on every valid solve, the no-reassessment Pass
     * path (post_solve_check=false, no honeypot, no chain-eligible
     * scope) included. A Pass disposition for a recognized stage-2
     * nonce still ends the chain, markVerified, instead of leaving it
     * issued for the controller to clean up.
     *
     * Transition by kind, all idempotent and nonce-pinned:
     *  - Pass   -> markVerified, the obligation is cleared atomically.
     *  - StepUp -> markStepUpRequired, the obligation is kept and the
     *    transaction stays bound to the step-up requirement.
     *  - Deny   -> markDenied, the obligation is kept and the
     *    transaction stays bound to its final denial.
     *  - ChainRequired -> unreachable for a stage-2 nonce: a stage-2
     *    challenge never opens a third stage, fail closed.
     *
     * A transition failure or refusal is fail-closed
     * {@see PostSolveDispositionUnavailableException}
     * (temporary_unavailable), never a silent pass while the
     * obligation may be uncleared.
     *
     * @param ChainRequirement|null $requirement the authoritative open
     *                                      chain requirement, threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()},
     *                                      never re-read here
     *
     * @throws PostSolveDispositionUnavailableException
     */
    private function applyStage2Disposition(string $token, PostSolveDisposition $disposition, KiwiCaptcha $constraint, ?ChainRequirement $requirement): void
    {
        if ($requirement === null || $requirement->stage2Nonce === null) {
            return;
        }
        $nonce = $this->verifiedNonceOf($token);
        if ($nonce === null || !hash_equals($requirement->stage2Nonce, $nonce)) {
            return;
        }
        try {
            $result = match ($disposition->kind) {
                PostSolveDispositionKind::Pass => $this->chainTickets->markVerified($requirement->chainId, $nonce),
                PostSolveDispositionKind::StepUp => $this->chainTickets->markStepUpRequired($requirement->chainId, $nonce),
                PostSolveDispositionKind::Deny => $this->chainTickets->markDenied($requirement->chainId, $nonce),
                PostSolveDispositionKind::ChainRequired => null,
            };
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the stage-2 chain transition failed', 0, $e);
        }
        if ($result === null) {
            throw new PostSolveDispositionUnavailableException('a recognized stage-2 nonce can never carry a ChainRequired disposition');
        }
        if ($result === ChainVerifiedResult::Conflict || $result === ChainVerifiedResult::Missing) {
            throw new PostSolveDispositionUnavailableException(sprintf('the stage-2 chain transition was refused (%s)', $result->value));
        }
    }

    /**
     * The canonical transaction binding of the request is resolved
     * exactly once per validation, before the core verification runs.
     * It is threaded through every binding decision of the validation:
     * the operation identity, the core's expected-request-binding
     * enforcement, the signed-record binding comparison, the stage-2
     * transaction lookup, the obligation lookup and the chain creation.
     * The authority is never consulted twice. With an authority
     * configured the presented request binding is only a hint: the
     * authority resolves the server-owned canonical value, the same
     * value the challenge controller signed at issuance. An authority
     * throw, its backend temporarily unavailable, is fail-closed
     * {@see PostSolveDispositionUnavailableException}: the caller
     * answers temporary_unavailable, a violation, never a silent pass,
     * never a raw exception — and never a consumed token (the
     * verification has not run yet). A null resolution, the transaction
     * is invalid/unknown, is the normal invalid-binding outcome;
     * without an authority the raw request binding applies unchanged.
     *
     * @throws PostSolveDispositionUnavailableException when the authority
     *                                                 fails, fail closed
     */
    private function resolveAuthoritativeBinding(KiwiCaptcha $constraint, ?Request $request): ?string
    {
        $presented = $this->requestBindingFromRequest($request);
        if ($this->bindingAuthority === null || $request === null) {
            return $presented;
        }
        try {
            $binding = $this->bindingAuthority->resolve($request, $constraint->scope, $presented);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the authoritative transaction binding could not be resolved', 0, $e);
        }

        return \is_string($binding) && $binding !== '' ? $binding : null;
    }

    /**
     * The open chain requirement of this request's (scope, canonical
     * binding, policy epoch), or null when none exists, chaining is
     * unavailable, or the authority is unavailable. Used for the
     * stage-2 detection and the obligation-authoritative disposition: a
     * verified challenge whose nonce equals the requirement's
     * stage2Nonce is the stage-2 challenge, and the chain ends there.
     * Fail-closed: only a successful lookup that finds no record
     * produces null. A chain-state read failure, backend error,
     * decoding/corruption or asymmetric failure, throws the typed
     * {@see PostSolveDispositionUnavailableException} the caller's
     * existing wrap converts to the temporary_unavailable violation; a
     * partial chain-state failure is never an authoritative "no open
     * requirement".
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 requirement state
     *                                                 cannot be read,
     *                                                 fail closed
     */
    private function openRequirementFor(KiwiCaptcha $constraint, ?string $canonicalBinding): ?ChainRequirement
    {
        if ($this->chainTickets === null || $this->bindingAuthority === null || $canonicalBinding === null) {
            return null;
        }
        try {
            return $this->chainTickets->findOpenRequirement($constraint->scope, $canonicalBinding, $this->policyVersion);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the chain requirement state is unavailable', 0, $e);
        }
    }

    /**
     * The absolute expiry a stage-2 chain requirement is opened with:
     * now + the configured chain lifetime (risk.chaining.ttl_secs). The
     * same value is passed to requireStage2, a fresh chain and an atomic
     * raise alike, since the store's raise-only create-or-get preserves
     * the original expiry of an existing chain. A ChainRequired ticket
     * is never signed with this independent value: the signing re-signs
     * from the disposition-carried bound, the requirement's actual
     * server-held expiresAt persisted with the disposition; see
     * {@see chainRequirementExpiresAt()}.
     */
    private function chainExpiresAt(): int
    {
        return time() + max(1, $this->chainTtlSecs);
    }

    /**
     * The absolute expiry a ChainRequired ticket is signed with: the
     * disposition-carried bound, the exact chain's original
     * server-held expiresAt persisted with the disposition as
     * chain_expires_at at finalize time. Never a fresh
     * current-obligation lookup: a concurrently opened chain of the
     * same transaction can never leak its expiry into this
     * disposition's ticket, and a completed chain, record retained but
     * obligation gone, keeps re-signing its deterministic ticket.
     *
     * The chain record is read by id, {@see ChainedChallengeTicketService::requirementFor()},
     * the by-chain-id read rather than the obligation lookup, as the
     * liveness check and the exact-bound comparison. A dead chain,
     * expired or record gone, is fail-closed temporary_unavailable, and
     * a shape-valid carried bound that differs from the exact chain
     * record's server-held expiresAt is corrupt state: fail-closed
     * temporary_unavailable, never a ticket that outlives its chain or
     * expires early. A legacy record whose carried bound is null falls
     * back to the exact chain record's server-held expiresAt.
     *
     * @throws PostSolveDispositionUnavailableException when the
     *                                                 chain is gone, the
     *                                                 chain expired or
     *                                                 was consumed, or
     *                                                 the carried bound
     *                                                 does not match the
     *                                                 exact chain record:
     *                                                 fail closed, never
     *                                                 a ticket that
     *                                                 outlives its chain
     */
    private function chainRequirementExpiresAt(PostSolveDisposition $disposition): int
    {
        $requirement = $this->chainTickets?->requirementFor($disposition->chainId);
        if ($requirement === null) {
            throw new PostSolveDispositionUnavailableException('the chain of the disposition is gone');
        }
        // The exact-original-expiry invariant: a shape-valid carried
        // bound must reproduce the exact chain record's server-held
        // expiresAt — a differing value is corrupt state (a ticket would
        // outlive the chain or expire early) and fails closed. A legacy
        // record without a carried bound (null) falls back to the exact
        // chain record's own bound.
        if ($disposition->chainExpiresAt !== null && $disposition->chainExpiresAt !== $requirement->expiresAt) {
            throw new PostSolveDispositionUnavailableException('the disposition-carried chain expiry does not match the exact chain record');
        }

        return $requirement->expiresAt;
    }

    /**
     * Jti + binding passthrough for an accepted verification: exposes
     * the canonical jti, the core's VerifyOutcome::nonce(), the
     * challenge nonce of the consumed record, and the record's signed
     * transaction binding, VerifyOutcome::requestBinding(), to the
     * application. Both are available via {@see verifiedJti()} /
     * {@see verifiedRequestBinding()} and the request attribute
     * `VERIFIED_JTI_ATTRIBUTE`, request-scoped and race-free for web
     * flows. The application keys its business operation idempotency on
     * (jti, action): a retry carrying the same jti must never create a
     * second operation, see the bundle README. Also exports the Ed25519 result
     * receipt when signing is configured.
     */
    private function finishSuccessfulApplicationVerification(string $value, VerifyOutcome $outcome, ?Request $request): void
    {
        $jti = null;
        if (\method_exists($outcome, 'nonce')) {
            $jti = $outcome->nonce();
        }
        if (!\is_string($jti) || $jti === '') {
            // Compat fallback on cores predating VerifyOutcome::nonce():
            // the canonical jti is the consumed record's nonce, which
            // equals the solution token's nonce (verification just
            // succeeded against that record).
            try {
                $jti = SolutionToken::decode($value)->nonce;
            } catch (DecodeError) {
                $jti = null;
            }
        }
        if (\is_string($jti) && $jti !== '') {
            $this->lastVerifiedJti = $jti;
            $request?->attributes->set(self::VERIFIED_JTI_ATTRIBUTE, $jti);
        }
        if (\method_exists($outcome, 'requestBinding')) {
            $this->lastVerifiedRequestBinding = $outcome->requestBinding();
        }

        // Result receipt: an accepted verification can be exported as an
        // Ed25519-signed receipt for third parties holding the public
        // key. The receipt is signed from the consumed record's own
        // fields and carries the full replay-critical set — jti, tenant
        // (scope), action (PoW algorithm), request_binding, issued_at /
        // expires_at, issuer (the payload is public by construction —
        // no secret material; the HMAC verification secret itself never
        // leaves the server). Signature verification alone is not
        // sufficient for single-use actions: the integrator must
        // atomically record the jti (`INSERT IF NOT EXISTS`) and treat a
        // pre-existing jti as a replay (see the bundle README).
        if ($this->receiptSigner !== null && $jti !== null) {
            $this->signReceipt($this->findRecordByNonce($jti));
        }
    }

    /**
     * Sign the Ed25519 result receipt from a consumed record: the
     * payload is built from the record's own fields, jti, tenant,
     * action, request_binding, issued_at, expires_at, issuer, never
     * from per-request state, so a stored-result retry re-signs the
     * same payload. No-op when signing is disabled or the record is
     * unavailable.
     */
    private function signReceipt(?ChallengeRecord $record): void
    {
        if ($this->receiptSigner === null || $record === null) {
            return;
        }
        $receipt = $this->receiptSigner->sign($record);
        if ($receipt !== null) {
            $this->lastReceiptPayload = $receipt['payload'];
            $this->lastReceiptSignature = $receipt['signature'];
        }
    }

    /**
     * Form-submission honeypot: after a valid verification, the form's
     * decoy field is compared against the exact expected name derived
     * from the verified nonce, {@see self::expectedDecoyField()}, the
     * same per-issuance derivation the challenge controller uses when
     * it emits the field. Returns whether the exact decoy was filled.
     * The caller then records the DecoyFieldSubmitted evidence under
     * the nonce-derived honeypot:<sha256(nonce)> idempotency key, so a
     * crash-taken-over computation never double-books the signal. It
     * then runs the post-solve assessment through the risk-v2 path,
     * where the honeypot signal actually moves the score. Any other
     * decoy_<hash> field is ignored: a decoy name is server-issued and
     * nonce-bound, so a mismatched name is not this challenge's decoy.
     * Evidence only: never a gate and never affects the proof validity.
     * Never throws: a broken gateway must never break the form.
     */
    private function formDecoyEvidence(Request $request, string $expectedField): bool
    {
        $value = $request->request->get($expectedField);
        if (!\is_string($value) || $value === '') {
            return false;
        }

        return true;
    }

    /**
     * The expected decoy field name for a verified nonce: the exact
     * derivation the challenge controller emits at issuance,
     * ChallengeController: 'decoy_' + the first 8 hex characters of
     * sha256(nonce). Only the server-issued name for this challenge
     * counts as honeypot evidence.
     */
    private static function expectedDecoyField(string $nonce): string
    {
        return 'decoy_'.substr(hash('sha256', $nonce), 0, 8);
    }

    /**
     * The record's signed request binding of a verified outcome: the
     * stage-1 binding a chain ticket signs (null when the stage-1
     * challenge had none).
     */
    private function verifiedRequestBindingOf(\KiwiCaptcha\VerifyOutcome $outcome): ?string
    {
        return \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
    }

    /**
     * Whether the verified challenge behind a token already satisfies
     * the reassessed action: the authoritative stage-strength
     * comparison (risk.chaining) via the resolver's actual configured
     * ladders. Allow is the base: a neutral post-solve assessment can
     * never open a chain. A missing or unreadable record, or a missing
     * resolver, is treated as not satisfied, Allow-level: the chain
     * opens with the required action, failing toward more security. A
     * solved challenge whose strength cannot be confirmed is never
     * assumed to have met the reassessed action.
     */
    private function recordSatisfiesRequiredAction(string $token, RiskAction $action): bool
    {
        if ($action === RiskAction::Allow) {
            return true;
        }
        if ($this->riskResolver === null) {
            return false;
        }
        $record = $this->findVerifiedRecord($token);
        if ($record === null) {
            return false;
        }

        return $this->riskResolver->recordSatisfies($record, $action);
    }

    /**
     * The verified challenge's record, read by the verified nonce, the
     * same storage find the metadata sidecar uses. After a successful
     * verification the consumed record is kept for replay protection,
     * so the plain find resolves the record whose algorithm + target
     * bits decide the stage-strength comparison. null when storage is
     * not wired, the token cannot be decoded or the read fails; an
     * unreadable record is treated as not satisfied and the chain
     * opens.
     */
    private function findVerifiedRecord(string $token): ?ChallengeRecord
    {
        if ($this->storage === null) {
            return null;
        }
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }
        try {
            return $this->storage->find($nonce);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Whether the verified challenge behind a token carries the chain
     * marker in its server-held metadata, the private chainId field the
     * stage-2 controller stamped at the stage-2 issuance; it never
     * travels in the cdata, so client input can never forge it. A
     * marked challenge is the end of its chain: no third-stage ticket
     * can ever be issued from it. Fails closed: a metadata read failure
     * throws, and the caller answers the temporary_unavailable
     * violation when chaining is enabled, since the marker cannot be
     * established and the challenge is never silently treated as
     * stage-1-eligible. Only a successful read without a marker
     * legitimately keeps the challenge stage-1-eligible.
     */
    private function verifiedChallengeCarriesChainMarker(string $token): bool
    {
        if ($this->metadataStore === null) {
            return false;
        }
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return false;
        }
        $metadata = $this->metadataStore->find($nonce);

        return $metadata !== null && $metadata->chainId !== null;
    }

    /**
     * The stage-1 challenge nonce behind a solution token (the verified
     * proof's nonce), or null when the token cannot be decoded. The chain
     * ticket's server-held state records this nonce so the stage-2
     * controller can prove the ticket holder really verified a stage-1
     * proof AND cannot re-run the same stage.
     */
    private function verifiedNonceOf(string $token): ?string
    {
        try {
            return SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }
    }

    /**
     * The consumed record behind a canonical nonce (jti), read from the
     * challenge storage after a valid verification so the receipt can be
     * signed from the record's own fields. null when storage is not
     * wired or the read fails; a receipt is then simply not produced and
     * the verification result itself is unaffected.
     */
    private function findRecordByNonce(string $nonce): ?ChallengeRecord
    {
        if ($this->storage === null) {
            return null;
        }
        try {
            return $this->storage->find($nonce);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The retained consumed state behind a token: decoded nonce ->
     * {@see ConsumedStateReadableInterface::consumedState()}, the
     * storage-capability read that carries the consumed record, its
     * committed deterministic result and the operation identity recorded
     * with the pending→consumed transition. Null when no storage is
     * wired, the storage has no consumed-state capability (e.g. a PSR-6
     * pool without it), the token cannot be decoded, the read fails, or
     * the record is missing or still pending. The plain
     * {@see StorageInterface::find()} carries no runtime state, so it is
     * never used here.
     */
    private function findConsumedRecord(string $token): ?\KiwiCaptcha\ConsumedRecord
    {
        if (!$this->storage instanceof \KiwiCaptcha\ConsumedStateReadableInterface) {
            return null;
        }
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }
        try {
            return $this->storage->consumedState($nonce);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The request's explicit per-operation id (kiwi_operation_id): the
     * documented request attribute first, then the constraint's static
     * option. The raw POSTed field is deliberately never accepted: a
     * client-chosen identity would let the attacker enable the
     * idempotent-replay path. Only a well-shaped identifier counts
     * ([A-Za-z0-9._:-], 1..128 bytes — the same narrow alphabet as the
     * request binding); a malformed value is ignored (strict single-use
     * applies) rather than silently re-enabling replay.
     */
    private function operationIdFor(KiwiCaptcha $constraint, ?Request $request): ?string
    {
        $operationId = $request?->attributes->get(self::OPERATION_ID_ATTRIBUTE);
        if (!\is_string($operationId) || $operationId === '') {
            $operationId = $constraint->operationId;
        }
        if (!\is_string($operationId) || $operationId === '' || !Config::isValidIdentifier($operationId, 128)) {
            return null;
        }

        return $operationId;
    }

    /**
     * The request's transaction binding: the documented attribute first,
     * then the raw POSTed kiwi_request_binding field (the widget fallback).
     * Shared by the request-binding check and the retry resolution.
     */
    private function requestBindingFromRequest(?Request $request): ?string
    {
        $binding = $request?->attributes->get(self::REQUEST_BINDING_ATTRIBUTE);
        if (!\is_string($binding) || $binding === '') {
            $binding = $request?->request->get('kiwi_request_binding');
        }

        return \is_string($binding) && $binding !== '' ? $binding : null;
    }

    /**
     * Decode the bounded solution token to its nonce and consume the
     * nonce -> decision handle (delete-on-read, at most one consumer
     * wins). Returns the paired original pre-issue decision id, or null
     * when the token cannot be decoded or no handle exists. Never
     * throws: a valid verification implies a decodable token (defense
     * in depth).
     *
     * Superseded on the durable path: with a disposition store wired the
     * consumption happens atomically inside the store's claim
     * transition. {@see PostSolveDispositionStore::claim()} consumes
     * the mapping by its full key and persists the paired handle in the
     * pending record, so a fallible chain-state read before the claim
     * can never lose it. This method remains only for the no-store
     * seam, manual construction, where the disposition is computed
     * without persistence.
     */
    private function consumeDecisionForToken(string $token): ?string
    {
        try {
            $nonce = SolutionToken::decode($token)->nonce;
        } catch (DecodeError) {
            return null;
        }

        return $this->risk?->resolveDecisionForNonce($nonce);
    }
}
