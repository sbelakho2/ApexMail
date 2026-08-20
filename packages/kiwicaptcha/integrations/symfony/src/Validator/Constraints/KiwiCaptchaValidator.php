<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Validator\Constraints;

use BelConsulting\KiwiCaptchaBundle\Risk\AmbiguousForwardingException;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainRequirement;
use BelConsulting\KiwiCaptchaBundle\Risk\ChainVerifiedResult;
use BelConsulting\KiwiCaptchaBundle\Risk\ClientIpResolver;
use BelConsulting\KiwiCaptchaBundle\Risk\ContinuityCookie;
use BelConsulting\KiwiCaptchaBundle\Risk\PostSolveDisposition;
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
 * disposition (PASS | DENY | STEP_UP | CHAIN_REQUIRED) through one
 * fail-closed path, so a replay of a valid proof reproduces the same
 * application-level outcome. The verification pipeline and its invariants
 * are documented in docs/security-hardening.md.
 */
final class KiwiCaptchaValidator extends ConstraintValidator
{
    /**
     * Request attribute holding the canonical jti of the LAST successfully
     * verified challenge of this request (the core's VerifyOutcome::nonce()).
     * Request-scoped: set on the RequestStack main request only on a valid
     * verification, so the application can key its business operation
     * idempotency on (jti, action) after the form validates.
     */
    public const VERIFIED_JTI_ATTRIBUTE = '_kiwi_captcha_verified_jti';

    /**
     * Request attribute holding the transaction binding the
     * application controller copied from the POSTed `kiwi_request_binding`
     * field BEFORE form validation. When the attribute is absent the
     * validator falls back to the raw POST field of the same name. The
     * binding is enforced against the challenge record's SIGNED
     * request_binding: a bound challenge whose binding does not match is
     * rejected with the same invalid_or_expired outcome.
     */
    public const REQUEST_BINDING_ATTRIBUTE = '_kiwi_captcha_request_binding';

    /**
     * The token verified correctly, but the chained-challenge
     * reassessment (risk.chaining) demands a STRONGER stage than the
     * first-stage profile (e.g. an Argon action or StepUp). The violation
     * carries the signed ONE-SHOT chain ticket in its parameters under
     * `{{ chain_ticket }}` (a stable, documented machine-readable
     * format): the application re-renders the widget with
     * data-kiwi-chain-ticket=<ticket> and the next challenge request
     * presents it for a stage-2 issuance. The ticket is valid for
     * risk.chaining.ttl_secs and is consumed atomically at issuance.
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
     * @param Verifier $verifier KiwiCaptcha\Verifier with the bundle's
     *                           configured Argon2id admission gate wired in
     *                           (when applicable) — capacity exhaustion is
     *                           reported as a VerifyOutcome, never a 500
     * @param bool     $enforceTelemetry when true, bot-signal telemetry is
     *                                   rejected (defense-in-depth; only
     *                                   meaningful when the widget collects
     *                                   telemetry)
     * @param LoggerInterface|null $logger internal verification detail on
     *                                     failures: the public
     *                                     violation code is collapsed, the
     *                                     precise core reason stays in the
     *                                     logs
     * @param StorageInterface|null $storage the challenge storage — required
     *                                       for the ambiguous-consume
     *                                       deterministic-retry resolution:
     *                                       on ConsumeIndeterminate the stored
     *                                       consumed record (state +
     *                                       consumed_result) decides the
     *                                       outcome instead of a second
     *                                       derivation
     * @param ClientIpResolver|null $clientIpResolver trusted client-IP policy
     *                                               — the SAME canonical IP the challenge
     *                                               controller bound the
     *                                               record to (a resolver
     *                                               mismatch would fail every
     *                                               bound challenge)
     * @param SecurityEpochMonitor|null $epochMonitor the security-epoch
     *                                               monitor —
     *                                               refreshed before every
     *                                               verification so the
     *                                               verifier's expected policy
     *                                               epoch is the CURRENT
     *                                               (monotonic, cached) one
     * @param ResultReceiptSigner|null $receiptSigner the optional Ed25519
     *                                               signer for EXPORTED
     *                                               verification results
     *                                               — null =
     *                                               receipt signing disabled
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
         * The chain ticket service issues the one-shot CHAIN_REQUIRED
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
         * controller stamps the issued challenge's PRIVATE chainId/
         * chainDepth metadata fields (never the cdata), and the validator
         * refuses to open a THIRD stage when a verified challenge's
         * metadata carries a chainId — the chain ends at stage 2.
         */
        private readonly ?SiteVerifyMetadataStore $metadataStore = null,
        /**
         * The risk profile resolver (the same service the risk gateway
         * maps actions with): the authoritative stage-strength comparison
         * (risk.chaining) — a chain opens only when the reassessed action
         * is NOT satisfied by the solved challenge under the ACTUAL
         * configured ladders (risk.chaining; null = chaining disabled).
         */
        private readonly ?RiskProfileResolver $riskResolver = null,
        /**
         * The durable post-solve disposition store: every valid
         * verification — fresh derive and stored-result replay alike —
         * resolves its final disposition (PASS | DENY | STEP_UP |
         * CHAIN_REQUIRED) through ONE path and persists it per nonce
         * BEFORE the application sees the outcome, so a replay of a valid
         * proof reproduces the same disposition instead of bypassing the
         * post-solve policy. The extension always wires a store (Redis,
         * or the in-memory variant in test/dev); null = the disposition is
         * computed and applied without persistence (manual construction).
         */
        private readonly ?PostSolveDispositionStore $dispositionStore = null,
        /**
         * The authoritative transaction-binding authority (nullable
         * service id risk.request_binding_authority): the presented
         * request_binding is a HINT — the authority resolves the
         * SERVER-OWNED canonical transaction binding, and the validator
         * enforces the signed record binding against THAT value
         * end-to-end (the same value the challenge controller signed at
         * issuance). An authority failure fails closed as
         * temporary_unavailable; a null resolution is the normal
         * invalid-binding outcome. Chaining opens only when the canonical
         * binding resolves non-null — a raw client-supplied binding
         * without an authority is never sufficient. Null = the raw
         * request binding applies unchanged (chaining unavailable — a
         * stronger PoW demand falls back to terminal StepUp, never a
         * silent pass).
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
         * expiry the validator passes when it OPENS a stage-2 chain
         * requirement (requireStage2). A CHAIN_REQUIRED ticket is NEVER
         * signed with an independent fresh expiry: the signing always
         * re-signs from the requirement's ACTUAL server-held expiresAt
         * ({@see self::chainRequirementExpiresAt()}), so the same
         * (nonce, disposition) reproduces the same deterministic ticket
         * and a ticket can never outlive its chain state.
         */
        private readonly int $chainTtlSecs = 300,
    ) {
    }

    /**
     * The canonical jti (VerifyOutcome::nonce()) of the last successfully
     * verified token, or null when no verification succeeded yet. Read from
     * a WEB request via the request attribute instead:
     * {@see self::VERIFIED_JTI_ATTRIBUTE} (request-scoped and race-free).
     */
    public function verifiedJti(): ?string
    {
        return $this->lastVerifiedJti;
    }

    /**
     * The transaction binding of the last successfully verified challenge
     * (VerifyOutcome::requestBinding() — the SIGNED record binding, null
     * when the record is unbound), or null when no verification succeeded
     * yet.
     */
    public function verifiedRequestBinding(): ?string
    {
        return $this->lastVerifiedRequestBinding;
    }

    /**
     * The canonical JSON payload of the last successfully verified
     * challenge's Ed25519 RECEIPT: {jti, tenant, action,
     * request_binding, issued_at, expires_at, issuer} — the full
     * replay-critical set signed from the CONSUMED record, or null when no
     * verification succeeded yet or no signing key is configured
     * (risk.result_receipt_signing_key). The payload is public by
     * construction (no secret material); pair it with
     * {@see verifiedReceiptSignature()} and verify against the PUBLIC key
     * derived from the configured seed — never the private key. Signature
     * verification alone is NOT sufficient for single-use actions: the
     * integrator must atomically record the jti (INSERT IF NOT EXISTS) and
     * treat a pre-existing jti as a replay (README).
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
     *         $publicKey, // base64_decode(ResultReceiptSigner::publicKeyBase64())
     *     )
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

        // SECURITY-EPOCH REFRESH: before the verification runs,
        // re-read the central security-policy epoch (bounded by the short
        // cache window) and rotate the verifier's expected policy version to
        // the CURRENT monotonic max — a central policy bump revokes
        // outstanding challenges within one cache window, a regressed or
        // unavailable central value can never weaken the epoch.
        $this->epochMonitor?->refresh();

        // MAX-STALE FAIL-CLOSED: once now exceeds the last
        // successful central read by risk.security_epoch_max_stale_secs,
        // the cached epoch may be outdated (an emergency revocation could
        // have landed while this node could not read) — verification fails
        // closed with the DISTINCT temporary_unavailable violation
        // (retryable, never invalid_or_expired: the token is not burned,
        // the server is temporarily refusing to trust its own cache).
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
        // client-IP policy (ClientIpResolver) — the SAME canonical IP the
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
        // PER-SCOPE budget (argon2_max_per_tenant, checked in addition to
        // the global cap).
        $request?->attributes->set(\BelConsulting\KiwiCaptchaBundle\Security\RequestScopeAdmissionGate::SCOPE_ATTRIBUTE, $constraint->scope);

        // CapacityExceeded (Argon2id admission saturated) surfaces as a
        // regular failed verification — fail closed as a captcha violation.
        $outcome = $this->verifier->verify($value, $this->secretKey, $constraint->scope, $clientIp, null, $this->enforceTelemetry);

        // ── AMBIGUOUS-CONSUME DETERMINISTIC RETRY ────────────────────────────
        // ConsumeIndeterminate means the consume transition MAY have happened
        // but its response was lost: the challenge may already be consumed —
        // with (or without) a committed result. The validator NORMALIZES the
        // outcome from the STORED record instead of re-deriving (NO side
        // effects here — the normalized outcome flows through the SAME
        // pipeline as any other verification):
        //   - consumed record + stored VALID result -> a valid outcome with
        //     the STORED consumed binding (the binding check below applies
        //     the same rule to it: same binding -> same success, different
        //     binding -> invalid_or_expired);
        //   - stored INVALID result -> invalid(InsufficientWork) (the
        //     original derive failed — collapsed to invalid_or_expired);
        //   - record still pending / consumed without a committed result /
        //     storage unavailable -> the outcome stays indeterminate
        //     (temporary_unavailable — retryable, never silently valid).
        // A stored-result outcome is a re-verify of a consumed record with a
        // committed result: the core returns the SAME outcome without
        // re-deriving. It answers ONLY "was the PoW cryptographically
        // valid?" — it never answers "should the application accept this
        // protected action?". The final disposition (PASS | DENY | STEP_UP
        // | CHAIN_REQUIRED) is resolved and persisted for EVERY valid
        // outcome below, stored-result retries included.
        $outcome = $this->normalizeAmbiguousOutcome($outcome, $value, $request, $constraint->scope);

        // ── FAILED VERIFICATION ─────────────────────────────────────────────
        // The collapsed public code; the PRECISE core reason (WrongScope,
        // Expired, BadSignature, ...) stays in the logs — never exposed to
        // the client (no oracle for which check failed). ConsumeIndeterminate
        // is NOT a token-level failure: it is a storage I/O ambiguity — the
        // resolution tries the stored record first, and an UNRESOLVABLE
        // indeterminate outcome maps to temporary_unavailable (retryable,
        // like StorageUnavailable), never to invalid_or_expired — the client
        // must not be told its token is burned when it may still redeem.
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

        // TRANSACTION BINDING: after a VALID verification, the consumed
        // record's SIGNED request_binding must equal the binding the
        // request carried. With an authority configured
        // (risk.request_binding_authority) the presented binding is only
        // a HINT: the SERVER-OWNED canonical transaction binding is
        // resolved EXACTLY ONCE here — the same value the challenge
        // controller signed at issuance — and it drives EVERY binding
        // decision of this validation (the comparison below, the stage-2
        // transaction lookup, the obligation lookup and the chain
        // creation — the authority is never consulted twice). An
        // authority failure (its backend temporarily unavailable) fails
        // closed as temporary_unavailable — a violation, never a silent
        // pass, never a raw exception; a null resolution (the transaction
        // is invalid/unknown) is the normal invalid-binding outcome.
        // Without an authority the raw request binding (the request
        // attribute the application controller copied from the POSTed
        // kiwi_request_binding field — or the raw POST field) applies
        // unchanged. A bound record with a missing/mismatched binding is
        // rejected with the SAME invalid_or_expired outcome (the
        // collapsed violation code): a challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely. For a stored-result
        // retry the outcome's requestBinding() IS the stored consumed
        // binding, so the SAME rule gives the stored-result contract:
        // same binding -> same success, different binding ->
        // invalid_or_expired.
        try {
            $canonicalBinding = $this->resolveAuthoritativeBinding($constraint, $request);
        } catch (PostSolveDispositionUnavailableException $e) {
            $this->logger?->info('KiwiCaptcha: valid proof rejected — the authoritative transaction binding is unavailable', [
                'scope' => $constraint->scope,
                'reason' => $e->getMessage(),
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::TEMPORARY_UNAVAILABLE_ERROR)
                ->addViolation();

            return;
        }
        if (!$this->requestBindingMatches($outcome, $canonicalBinding)) {
            $this->logger?->info('KiwiCaptcha: valid proof rejected — request binding mismatch', [
                'scope' => $constraint->scope,
            ]);
            $this->context->buildViolation($constraint->message)
                ->setCode(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR)
                ->addViolation();

            return;
        }

        // RESOURCE ACCOUNTING: the PoW IS solved regardless of the later
        // risk disposition — the source's outstanding challenge counter is
        // decremented (best-effort, floored at 0) exactly once, BEFORE the
        // final-disposition resolution. Skipped for a stored-result retry:
        // the ORIGINAL verification already decremented it.
        if (!$this->isStoredResult($outcome)) {
            $this->outstanding?->solved((string) ($clientIp ?? ''));
        }

        // ── ONE FINAL-DISPOSITION PATH ──────────────────────────────────────
        // The core's retained result must answer "was the PoW
        // cryptographically valid?" — never "should the application accept
        // this protected action?". EVERY valid verification (fresh derive
        // and stored-result replay alike) resolves its durable, nonce-keyed
        // final disposition — the post-solve risk reassessment, the
        // honeypot evidence, the chained-challenge opening and the
        // nonce->decision consumption all live behind this single path, and
        // the disposition is PERSISTED before the application ever sees the
        // outcome. A replay of a valid proof reproduces the same PASS |
        // DENY | STEP_UP | CHAIN_REQUIRED instead of bypassing the
        // post-solve policy. The resolution is fail-closed: an unavailable
        // disposition store, a busy claim or a refused finalize surfaces as
        // the retryable temporary_unavailable violation — never a silent
        // pass.
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

        // ── STAGE-2 CHAIN TRANSITION BY FINAL DISPOSITION ────────────────
        // The final disposition is DURABLY finalized (above) BEFORE the
        // chain is touched: the chain transition runs strictly AFTER the
        // finalize, by disposition kind — Pass -> markVerified (the
        // obligation is cleared), StepUp -> markStepUpRequired (the
        // obligation is KEPT — the transaction stays bound to the
        // step-up), Deny -> markDenied (the obligation is KEPT). The
        // detection runs on EVERY valid solve (the no-reassessment Pass
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
                // submission with the distinct POST_SOLVE_REJECTED_ERROR.
                $this->logger?->info('KiwiCaptcha: valid solve rejected by the post-solve assessment', [
                    'scope' => $constraint->scope,
                ]);
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::POST_SOLVE_REJECTED_ERROR)
                    ->addViolation();

                return;
            case PostSolveDispositionKind::StepUp:
                // StepUp is TERMINAL application-level step-up: it NEVER
                // becomes a chain ticket (a ticket could later be spent on
                // ordinary PoW instead of the application's step-up). The
                // application routes the user to MFA/passkey/email
                // confirmation.
                $this->context->buildViolation($constraint->message)
                    ->setCode(KiwiCaptcha::POST_SOLVE_STEP_UP_REQUIRED)
                    ->addViolation();

                return;
            case PostSolveDispositionKind::ChainRequired:
                // CHAIN REQUIRED: the reassessment demanded a strictly
                // stronger PoW stage. Re-sign the one-shot chain ticket
                // from the PERSISTED chain id (the same chain for a fresh
                // verification and a replay); the violation's
                // {{ chain_ticket }} parameter carries it in the
                // documented machine-readable format. The ticket is
                // ALWAYS signed from the chain requirement's ACTUAL
                // server-held expiresAt — the just-opened requirement and
                // an existing obligation's chain alike — so a fresh
                // disposition, an obligation-first disposition and a
                // replay of the same verified nonce all reproduce the
                // SAME byte-identical ticket (a re-signed ticket can
                // never outlive its chain state, and the deterministic
                // retry never invents a fresh expiry). A disposition
                // whose chain requirement is gone (the chain expired or
                // was consumed) is fail-closed temporary_unavailable. A
                // ticket that cannot be produced is fail-closed
                // temporary_unavailable — a stronger stage was demanded
                // but cannot be chained, never a silent downgrade to an
                // unchained pass.
                try {
                    $ticket = $this->chainTickets?->ticketFor(
                        $disposition->chainId,
                        $this->chainRequirementExpiresAt($constraint, $canonicalBinding),
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
     * The record's signed request_binding (VerifyOutcome::requestBinding())
     * must equal the CANONICAL binding of the request — the authority's
     * server-owned resolution when an authority is configured, the raw
     * request binding otherwise (the value the requestBindingMatches()
     * caller resolved ONCE, before the comparison). An unbound record
     * (null binding) skips the check.
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
     * collapses to invalid_or_expired; the capacity refusals stay distinct
     * (rate_limited / temporary_unavailable). Internal detail is logged, the
     * client only ever sees the collapsed code.
     *
     * ConsumeIndeterminate is NOT a token-level failure: it is a storage
     * I/O ambiguity (the consume may or may not have happened) — the
     * resolution tries the stored record first, and an UNRESOLVABLE
     * indeterminate outcome maps to temporary_unavailable (retryable, like
     * StorageUnavailable), never to invalid_or_expired — the client must
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
     * ConsumeIndeterminate verification from the STORED consumed record
     * instead of re-deriving, with NO side effects — the normalized
     * outcome flows through the SAME pipeline as any other verification
     * (binding check, outstanding accounting, final disposition):
     * a stored VALID result -> a valid outcome carrying the consumed
     * record's nonce and STORED binding (the pipeline's binding check
     * applies the stored-result contract: same binding -> same success,
     * different binding -> invalid_or_expired); a stored INVALID result
     * -> invalid(InsufficientWork) (the original derivation failed —
     * collapsed to invalid_or_expired); storage unavailable / no record /
     * still pending / consumed without a committed result -> the
     * ORIGINAL indeterminate outcome (the caller's publicCode() maps
     * ConsumeIndeterminate to temporary_unavailable — retryable, never
     * silently valid).
     */
    private function normalizeAmbiguousOutcome(VerifyOutcome $outcome, string $token, ?Request $request, ?string $scope): VerifyOutcome
    {
        if ($outcome->error !== VerifyError::ConsumeIndeterminate) {
            return $outcome;
        }

        $record = $this->findConsumedRecord($token);
        if ($record === null) {
            // No storage wired, undecodable token, storage failure, record
            // absent, or record still PENDING (the first attempt never
            // consumed it — a retry will consume normally): the outcome
            // stays indeterminate.
            return $outcome;
        }

        $result = $this->consumedResultOf($record);
        if ($result === false) {
            // The original derivation FAILED — the stored result is the
            // authoritative outcome.
            return VerifyOutcome::invalid(VerifyError::InsufficientWork);
        }
        if ($result !== true) {
            // Consumed but the result was never committed (the original
            // attempt died mid-proof): genuinely indeterminate.
            return $outcome;
        }

        // Stored VALID result: deterministic retry. The pipeline's binding
        // check enforces the stored-result contract: the normalized outcome
        // carries the STORED consumed binding, so the request binding must
        // equal it — a challenge bound to one transaction is never
        // redeemable for another, retries included.
        return VerifyOutcome::valid($record->nonce, $this->consumedBindingOf($record), true);
    }

    /**
     * Whether the outcome came from the CORE's stored consumed result (a
     * re-verify of a consumed record with a committed result) instead of a
     * fresh derivation. Detects both the accessor method and the public
     * property shapes across core versions.
     */
    private function isStoredResult(VerifyOutcome $outcome): bool
    {
        if (\method_exists($outcome, 'fromStoredResult')) {
            return (bool) $outcome->fromStoredResult();
        }

        return (bool) ($outcome->fromStoredResult ?? false);
    }

    /**
     * THE final-disposition resolution — the single path every valid
     * verification (fresh derive and stored-result replay alike) flows
     * through:
     *
     *  0. the AUTHORITATIVE chain requirement of the transaction is
     *     resolved EXACTLY ONCE here and threaded through the whole
     *     pipeline ({@see self::assessFinalDisposition()} and
     *     {@see self::applyStage2Disposition()} — never re-read). A
     *     TERMINAL requirement (denied / step_up_required) DOMINATES
     *     EVERY nonce — the exact stage-2 nonce and replays included:
     *     the terminal disposition answers BEFORE any assessment, and a
     *     terminal transaction never persists a Pass for ANY nonce;
     *  1. the canonical nonce is decoded, a fresh owner token drawn and
     *     the nonce -> decision handle is CONSUMED (GETDEL, at most one
     *     winner) BEFORE the claim — the pending disposition record
     *     persists the handle, so an owner crash can never lose the
     *     original decision id of a no-post-solve Pass;
     *  2. the nonce-keyed disposition record is CLAIMED with that handle:
     *     'complete' -> the persisted final disposition is returned
     *     immediately (a replay of a valid proof reproduces the same
     *     PASS | DENY | STEP_UP | CHAIN_REQUIRED — never a bypass; a
     *     TERMINAL requirement supersedes even a persisted disposition);
     *     'pending' -> another owner's computation is live — the
     *     temporary_unavailable violation (never a silent pass);
     *     'claimed'/'taken_over' -> this owner runs the post-solve
     *     assessment, persists the disposition and returns it; a
     *     TAKEN-OVER computation resumes with the ORIGINAL owner's
     *     decision handle (kept in the pending record);
     *  3. the finalize MUST succeed before anything is returned — a store
     *     failure is the temporary_unavailable violation, never a silent
     *     pass.
     *
     * @return array{0: PostSolveDisposition, 1: bool, 2: ?ChainRequirement}
     *         the final disposition, whether it came from the PERSISTED
     *         record (a replay — informational) and the threaded
     *         AUTHORITATIVE requirement ({@see self::applyStage2Disposition()})
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

        // NONCE -> DECISION CONSUMPTION: the short-lived nonce -> decision
        // handle is CONSUMED (GETDEL, at most one winner) BEFORE the
        // claim, and the handle is persisted in the pending disposition
        // record ({@see PostSolveDispositionStore::claim()}) — an owner
        // crash after the consumption can never lose the original
        // decision id, and a crash-taken-over computation completes the
        // disposition with it. On scopes WITHOUT post_solve_check the
        // ORIGINAL pre-issue decision id becomes the request's current
        // decision id ({@see RiskGateway::setCurrentDecisionId()}), so the
        // application can confirm this challenge's original decision. On
        // post_solve_check scopes the superseded mapping is still consumed
        // (cleanup — it can never be confirmed against a stale decision),
        // and the fresh POST-SOLVE decision becomes the current
        // confirmation target instead.
        $decisionId = $this->consumeDecisionForToken($token);

        // THE AUTHORITATIVE REQUIREMENT LOOKUP — resolved EXACTLY ONCE per
        // validation and threaded through the assessment, the stage-2
        // detection and the chain transitions ({@see
        // self::assessFinalDisposition()} / {@see self::applyStage2Disposition()}),
        // so the requirement can never diverge between the terminal-state
        // dominance, the disposition and the transition that follows it.
        // Fail-closed as before: only a SUCCESSFUL lookup that finds no
        // record produces null.
        $requirement = $this->openRequirementFor($constraint, $canonicalBinding);

        if ($this->dispositionStore === null) {
            // No store wired (manual construction / legacy seam): the
            // disposition is computed and applied WITHOUT persistence. The
            // extension always wires a store, so the durable path below is
            // the production behavior.
            return [$this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce, $canonicalBinding, $decisionId, $requirement), false, $requirement];
        }

        $owner = bin2hex(random_bytes(16));
        $ttl = Config::MAX_TTL_SECS + $this->postSolveDispositionTtlMarginSecs;
        try {
            $claim = $this->dispositionStore->claim($nonce, $owner, $ttl, $decisionId);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition store is unavailable', 0, $e);
        }

        if ($claim === 'complete') {
            try {
                $record = $this->dispositionStore->read($nonce);
            } catch (\Throwable $e) {
                throw new PostSolveDispositionUnavailableException('the post-solve disposition record is unreadable', 0, $e);
            }
            $disposition = $record?->disposition;
            if ($disposition === null) {
                // Complete without a usable disposition: corrupt state —
                // never silently pass.
                throw new PostSolveDispositionUnavailableException('the post-solve disposition record is corrupt');
            }
            // TERMINAL TRANSACTION STATE DOMINATES — REPLAYS INCLUDED: a
            // persisted nonce disposition (e.g. a Pass persisted before
            // the transaction terminalized) is superseded by the
            // requirement's TERMINAL state, so a replay of the exact
            // stage-2 nonce answers the terminal outcome — never the
            // stale disposition, never the stage-2 transition conflict.
            if ($requirement !== null && $requirement->state === 'denied') {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::Deny, $record?->decisionId);
            } elseif ($requirement !== null && $requirement->state === 'step_up_required') {
                $disposition = new PostSolveDisposition(PostSolveDispositionKind::StepUp, $record?->decisionId);
            }
            // A replay reproduces the request-scoped decision id too, so the
            // application can confirm the SAME decision handle.
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

        $storedDecisionId = $decisionId;
        if ($claim === 'taken_over') {
            // A takeover resumes the ORIGINAL owner's work: the pending
            // record holds the decision handle the crashed owner consumed
            // (its GETDEL is empty now) — the completed disposition keeps
            // the ORIGINAL decision id.
            try {
                $record = $this->dispositionStore->read($nonce);
            } catch (\Throwable $e) {
                throw new PostSolveDispositionUnavailableException('the post-solve disposition record is unreadable', 0, $e);
            }
            if ($record === null) {
                // The claim was taken over but the record vanished between
                // the claim and the read (a clock/expiry boundary): fail
                // closed — never silently pass.
                throw new PostSolveDispositionUnavailableException('the post-solve disposition record vanished after the takeover');
            }
            $storedDecisionId = $record->decisionId ?? $decisionId;
        }

        $disposition = $this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce, $canonicalBinding, $storedDecisionId, $requirement);

        try {
            $finalized = $this->dispositionStore->finalize($nonce, $owner, $disposition);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition could not be persisted', 0, $e);
        }
        if (!$finalized) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition finalize was refused');
        }

        return [$disposition, false, $requirement];
    }

    /**
     * The post-solve assessment of a verified proof: the form-submission
     * honeypot evidence (recorded with its nonce-derived idempotency key —
     * a crash-taken-over computation never double-books the signal), and
     * the fresh reassessment whenever the scope opts in (post_solve_check),
     * chaining is relevant, or the exact decoy was filled (a honeypot hit
     * alone — even with post_solve_check false and chaining disabled —
     * must trigger the fresh v2 assessment). The assessment ALWAYS carries
     * the nonce-derived stable idempotency key
     * 'postsolve:'.hash('sha256', $nonce), so a takeover re-assessment is
     * dedupe-key-identical to the original. TERMINAL TRANSACTION STATE
     * DOMINATES FIRST: the AUTHORITATIVE requirement (threaded from
     * {@see resolveFinalDisposition()}) bound to its TERMINAL denied /
     * step_up_required state answers that terminal disposition for EVERY
     * nonce — the exact stage-2 nonce and replays included — BEFORE any
     * assessment runs and before the caller finalizes the nonce
     * disposition, so a terminal transaction never persists a Pass for
     * ANY nonce.
     *
     * @param string|null $canonicalBinding the authority's server-owned
     *                                      transaction binding (resolved
     *                                      ONCE, before the binding
     *                                      comparison — never re-resolved
     *                                      here)
     * @param string|null $originalDecisionId the STORED decision handle:
     *                                      what the first owner consumed
     *                                      (or the pending record's handle
     *                                      on a takeover)
     * @param ChainRequirement|null $requirement the AUTHORITATIVE open
     *                                      chain requirement (threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()}
     *                                      — never re-read here)
     */
    private function assessFinalDisposition(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $ip, ?string $session, string $nonce, ?string $canonicalBinding, ?string $originalDecisionId, ?ChainRequirement $requirement): PostSolveDisposition
    {
        $postSolveScope = $this->risk !== null && $this->risk->postSolveCheck($constraint->scope);

        // TERMINAL TRANSACTION STATE DOMINATES EVERY NONCE — REGARDLESS of
        // the submitted nonce (the exact stage-2 nonce included) and
        // BEFORE any assessment: a transaction bound to its TERMINAL
        // denied/step_up_required state answers that terminal disposition
        // PERMANENTLY — the fresh post-solve decision is never consulted,
        // and a terminal transaction never persists a Pass for ANY nonce.
        // The caller durably finalizes the disposition AFTER this
        // resolution, so the persisted nonce disposition IS the terminal
        // kind (the deterministic handle is the original pre-issue one —
        // no fresh assessment ever ran for a terminal transaction).
        if ($requirement !== null && $requirement->state === 'denied') {
            return new PostSolveDisposition(PostSolveDispositionKind::Deny, $originalDecisionId);
        }
        if ($requirement !== null && $requirement->state === 'step_up_required') {
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $originalDecisionId);
        }

        // Chaining (risk.chaining): a SUCCESSFUL first-stage proof
        // opens the selective second stage — the reassessment runs for
        // every valid solve, and when it demands an action the solved
        // challenge does NOT already satisfy (the resolver's ACTUAL
        // configured ladders), the final disposition is CHAIN_REQUIRED
        // (stage 1) or terminal StepUp (stage 2 — the chain ends there).
        // StepUp is TERMINAL application-level step-up (never a chained
        // PoW) and Deny rejects the submission. The chain ENDS at stage 2:
        // a verified challenge whose metadata sidecar carries a
        // server-stamped chainId never opens a third stage.
        $chainEligible = false;
        if ($this->risk !== null && $this->chainTickets !== null) {
            try {
                $chainEligible = !$this->verifiedChallengeCarriesChainMarker($token);
            } catch (\Throwable $e) {
                if ($this->bindingAuthority !== null) {
                    // Chaining is enabled (the chain service AND the
                    // binding authority are wired): the private stage
                    // marker CANNOT be established — the verified
                    // challenge may be the stage-2 challenge of an open
                    // chain, and a third stage must never open from an
                    // unknown stage. Fail CLOSED with the temporary_
                    // unavailable violation — never acceptance, never
                    // suppressing the reassessment by silently treating
                    // the challenge as stage-1-eligible.
                    throw new PostSolveDispositionUnavailableException('the chain marker of the verified challenge could not be established', 0, $e);
                }
                // Chaining cannot open without the binding authority (no
                // stage-2 chain can exist for this deployment): the
                // marker is irrelevant — the challenge is treated as
                // POSSIBLY stage-2 (no chain ticket, never a third
                // stage) and the verification itself still passes.
                $chainEligible = false;
            }
        }

        // FORM-SUBMISSION HONEYPOT (post-verification): the expected
        // decoy field name derives from the VERIFIED nonce
        // ('decoy_' + substr(sha256(nonce), 0, 8) — the exact same
        // derivation the challenge controller used when it emitted the
        // field), and ONLY that exact field is inspected: any other
        // decoy_XXXXXXXX field is ignored (a decoy name is
        // server-issued and nonce-bound, so a mismatched name is not
        // this challenge's decoy). A filled expected field records
        // DecoyFieldSubmitted evidence AND feeds the post-solve
        // assessment through the risk-v2 path (the honeypot signal
        // actually moves the score). Evidence ONLY — never a gate and
        // never affects the proof validity.
        $honeypotHit = false;
        if ($this->risk !== null && $request !== null) {
            $honeypotHit = $this->formDecoyEvidence($request, self::expectedDecoyField($nonce));
        }

        // The ORIGINAL pre-issue decision id was consumed BEFORE the claim
        // (GETDEL — at most one consumer) and travels in as the STORED
        // handle: on scopes WITHOUT post_solve_check it becomes the
        // request's current decision id
        // ({@see RiskGateway::setCurrentDecisionId()}), so the application
        // can confirm this challenge's original decision. On
        // post_solve_check scopes the superseded mapping is already
        // consumed (cleanup — it can never be confirmed against a stale
        // decision), and the fresh POST-SOLVE decision becomes the current
        // confirmation target instead.
        if ($this->risk !== null && !$postSolveScope && $originalDecisionId !== null) {
            $this->risk->setCurrentDecisionId($originalDecisionId);
        }

        // HONEYPOT EVIDENCE: recorded with its nonce-derived idempotency
        // key — a crash-taken-over re-assessment (or a concurrent retry
        // that wins the takeover) re-uses the SAME dedupe identity, so the
        // signal is never double-booked. Evidence only — a recording
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
            // POST-SOLVE FEEDBACK: feed the valid outcome into the
            // adaptive risk engine as plain SolveSuccess feedback (the
            // gateway does NOT confirm its own post-solve decision —
            // ConfirmedLegitimate / ConfirmedAbuse are application-only
            // signals). The scope string is never validated against the
            // policy map here — unknown scopes are handled by the gateway.
            if ($this->risk !== null) {
                $this->risk->solveOutcome($constraint->scope, $ip, $session, $outcome->error);
            }

            return new PostSolveDisposition(PostSolveDispositionKind::Pass, $originalDecisionId);
        }

        // POST-SOLVE CHECK: a fresh SolveSuccess assessment with the same
        // context, ALWAYS keyed by the nonce-derived stable idempotency
        // key — a takeover re-assessment never double-books risk signals.
        // An unavailable risk signal (e.g. an unparseable or missing
        // client IP) enforces the scope's DEGRADED friction instead of
        // silently skipping the adaptive re-check — in BindingMode::None
        // deployments a valid PoW must not pass with zero adaptive
        // friction (mirrors the fail-safe degraded rule on the pre-issue
        // path).
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
     * NON-TERMINAL transaction (the requirement's TERMINAL states were
     * already resolved as the authoritative disposition BEFORE the
     * assessment — {@see self::assessFinalDisposition()} — the terminal
     * transaction state dominates EVERY nonce). With an open obligation
     * the final disposition is the MONOTONIC-ESCALATION MAX of the
     * obligation and the fresh decision — security may RISE, never fall,
     * and an existing obligation never freezes its security level:
     *
     *  - a FRESH Deny wins (terminal rejection) AND TERMINALIZES the
     *    open obligation itself (markTransactionDenied — NONCE-AGNOSTIC,
     *    keyed by the chain/obligation identity: the denial is DURABLE
     *    for the rest of the transaction's lifetime, so a later token of
     *    the same transaction can never re-open the chain after the
     *    transient risk condition decayed);
     *  - then a FRESH StepUp wins (terminal application-level step-up —
     *    never a chained PoW) AND TERMINALIZES the open obligation
     *    (markTransactionStepUpRequired — the same durability);
     *  - then a fresh STRICTLY STRONGER chainable action RAISES the
     *    obligation ATOMICALLY (requireStage2 with the fresh action —
     *    the store's raise-only create-or-get: the SAME chain id and the
     *    ORIGINAL expiry preserved, only the required rank/action rise)
     *    -> CHAIN_REQUIRED with that same chain id;
     *  - then a fresh equal/weaker/Allow action leaves the obligation
     *    UNCHANGED (its recorded floor intact) -> CHAIN_REQUIRED with the
     *    requirement's chain id — a stage-1 token of a chained
     *    transaction can NEVER pass, whatever the fresh assessment says.
     *
     * Without an open obligation: Deny -> Deny; StepUp -> StepUp
     * (TERMINAL — never a chained PoW); Allow (or the required PoW level
     * is already satisfied by the solved challenge) -> Pass; a STRICTLY
     * STRONGER PoW requirement opens a chain when chaining is available
     * (stage 2 -> StepUp — the chain ends at stage 2, never a third
     * stage; stage 1 + chaining available -> requireStage2(...) ->
     * ChainRequired — a raw client-supplied binding without an authority
     * is NEVER sufficient), otherwise terminal StepUp — a
     * stronger-PoW requirement must NEVER silently disappear when
     * chaining is unavailable.
     *
     * TERMINALIZATION-FIRST ordering: the NONCE-AGNOSTIC obligation
     * terminalization runs HERE, at the disposition-computation point of
     * the fresh Deny/StepUp cases ({@see self::terminalizeOpenChain()}) —
     * the chain transition is applied BEFORE the nonce-disposition
     * finalize; a failure of the finalize after a successful
     * terminalization answers temporary_unavailable, and the retry
     * rediscovers the terminal transaction (the dominance rule) and
     * reconstructs the terminal disposition — no authorization
     * weakness, intentionally conservative. The stage-2 (nonce-pinned)
     * chain transition itself is NOT performed here: the disposition is
     * finalized by the caller FIRST (the durable
     * {@see PostSolveDispositionStore} finalize) and the stage-2 chain is
     * transitioned AFTER, by disposition kind, in
     * {@see self::applyStage2Disposition()} — the final disposition is
     * authoritative for terminality, never the core's consumed result.
     *
     * @param ChainRequirement|null $requirement the AUTHORITATIVE open
     *                                      chain requirement (threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()}
     *                                      — never re-read here)
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 requirement cannot be
     *                                                 opened or its state
     *                                                 read (fail closed —
     *                                                 never a silent pass
     *                                                 while the obligation
     *                                                 may be uncleared)
     */
    private function mapPostSolveDecision(string $token, VerifyOutcome $outcome, KiwiCaptcha $constraint, string $nonce, ?RiskDecision $postSolve, ?string $canonicalBinding, ?ChainRequirement $requirement): PostSolveDisposition
    {
        // DEPTH-2 DETECTION (read-only): the verified challenge may BE
        // the stage-2 challenge of an open chain requirement (its nonce
        // equals the requirement's stage2Nonce — the requirement is the
        // threaded lookup from {@see resolveFinalDisposition()}) — the
        // chain then ends at stage 2, and a still-stronger requirement
        // is terminal StepUp (never a third stage). The transition runs
        // AFTER the disposition is durably finalized
        // ({@see self::applyStage2Disposition()}).
        //
        // OBLIGATION-AUTHORITATIVE: the open requirement is consulted
        // BEFORE the fresh assessment is applied — a partial chain-state
        // read failure fails closed ({@see self::openRequirementFor()})
        // and an existing obligation can never be downgraded by a weaker
        // fresh assessment. The requirement's TERMINAL states are NOT
        // handled here: they were resolved by the caller BEFORE the
        // assessment ({@see self::assessFinalDisposition()} — the
        // terminal dominance precedes the $isStage2 computation and the
        // nonce-disposition finalize). With an open obligation the final
        // disposition is the MONOTONIC-ESCALATION MAX of the
        // obligation's state and the fresh assessment:
        //
        //  1. a FRESH Deny wins (terminal rejection) AND terminalizes
        //     the open obligation (markTransactionDenied — the denial is
        //     DURABLE for the transaction's lifetime);
        //  2. then a FRESH StepUp wins (terminal application-level
        //     step-up — never a chain ticket) AND terminalizes the open
        //     obligation (markTransactionStepUpRequired);
        //  3. then a fresh STRICTLY STRONGER chainable action ATOMICALLY
        //     RAISES the obligation (requireStage2 — the store's
        //     raise-only mechanism: the SAME chain id, the ORIGINAL
        //     expiry preserved) and CHAIN_REQUIRED carries that same
        //     chain id — the recorded security level never freezes;
        //  4. then a fresh equal/weaker/Allow (or unknown-scope null)
        //     action leaves the obligation UNCHANGED (its recorded floor
        //     intact) — CHAIN_REQUIRED with the requirement's chain id:
        //     a stage-1 token of a chained transaction can NEVER pass.
        $isStage2 = $requirement !== null && $requirement->stage2Nonce !== null && hash_equals($requirement->stage2Nonce, $nonce);

        if ($requirement !== null && !$isStage2 && $requirement->state !== 'verified') {
            // The submitted nonce is NOT the requirement's exact
            // stage-2 nonce: the requirement state is the authoritative
            // floor of the transaction (the 'verified' state is the
            // anomaly — its obligation should already be gone — and falls
            // through as the requirement's absence).
            $decisionId = $postSolve?->decisionId;

            // available/reserved/issued: the transaction still owes its
            // stage 2 — the FRESH assessment now participates (it can
            // only ESCALATE the obligation, never decay it):
            if ($postSolve !== null) {
                // 1. A fresh Deny wins — the terminal rejection. The
                //    fresh Deny ALSO terminalizes the OPEN obligation
                //    itself ({@see self::terminalizeOpenChain()} — the
                //    nonce-agnostic markTransactionDenied, keyed by the
                //    chain/obligation identity): the denial is DURABLE
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
                // 2. A fresh StepUp wins — StepUp is TERMINAL
                //    application-level step-up (it NEVER becomes a chain
                //    ticket: a ticket could later be spent on ordinary
                //    PoW instead of the application's step-up). The
                //    fresh StepUp ALSO terminalizes the OPEN obligation
                //    (markTransactionStepUpRequired — the same durable
                //    terminality for the transaction's lifetime).
                if ($postSolve->action === RiskAction::StepUp) {
                    $this->terminalizeOpenChain($requirement, PostSolveDispositionKind::StepUp);

                    return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
                }

                // 3. A fresh STRICTLY STRONGER chainable demand RAISES
                //    the recorded floor ATOMICALLY: requireStage2 with
                //    the fresh action — the store's raise-only
                //    create-or-get keeps the SAME chain id and the
                //    ORIGINAL expiry, only the required rank/action rise.
                if ($postSolve->action !== RiskAction::Allow
                    && !$this->recordSatisfiesRequiredAction($token, $postSolve->action)
                    && $postSolve->action->rank() > $requirement->requiredRank
                ) {
                    // Chaining is available (the open obligation proves
                    // it was when the chain opened; the guard mirrors the
                    // no-obligation path below).
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

                        return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $chainId);
                    }
                    // Chaining unavailable: the stronger demand must
                    // NEVER silently downgrade to the weaker recorded
                    // floor — terminal StepUp (mirrors the
                    // no-obligation path).
                    return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
                }
            }

            // 4. A fresh equal/weaker/Allow/neutral action leaves the
            //    obligation UNCHANGED (its recorded floor intact) —
            //    CHAIN_REQUIRED with the requirement's SAME chain: a
            //    stage-1 token of a chained transaction can never pass.
            return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $requirement->chainId);
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
            // StepUp is TERMINAL application-level step-up: it NEVER
            // becomes a chain ticket (a ticket could later be spent on
            // ordinary PoW instead of the application's step-up).
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
        }
        if ($postSolve->action === RiskAction::Allow || $this->recordSatisfiesRequiredAction($token, $postSolve->action)) {
            // The required PoW level is already satisfied by the solved
            // challenge under the ACTUAL configured ladders.
            return new PostSolveDisposition(PostSolveDispositionKind::Pass, $decisionId);
        }

        // STRICTLY STRONGER PoW required.
        if ($isStage2) {
            // The chain ENDS at stage 2: a still-stronger requirement is
            // terminal StepUp, never a third stage.
            return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
        }

        // Stage-1 solved challenge: the chain opens ONLY when chaining is
        // available — enabled AND the canonical transaction binding
        // resolved non-null (a raw client-supplied binding without an
        // authority is NEVER sufficient). The canonical binding is the
        // value resolved ONCE before the binding comparison — the
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

            return new PostSolveDisposition(PostSolveDispositionKind::ChainRequired, $decisionId, $chainId);
        }

        // Chaining unavailable (disabled or no authoritative binding): the
        // stronger-PoW requirement must NEVER silently disappear — it
        // surfaces as terminal StepUp instead.
        return new PostSolveDisposition(PostSolveDispositionKind::StepUp, $decisionId);
    }

    /**
     * TERMINALIZE an OPEN obligation by the fresh Deny/StepUp disposition
     * (NONCE-AGNOSTIC — the exact stage-2 nonce is NOT required): the
     * obligation becomes TERMINAL denied/step_up_required for the rest of
     * its lifetime, ATOMICALLY over the chain + obligation keys
     * ({@see ChainedChallengeTicketService::markTransactionDenied()} /
     * {@see ChainedChallengeTicketService::markTransactionStepUpRequired()}
     * — the transaction's obligation id travels with the transition, so a
     * STALE chain (the obligation moved between the requirement read and
     * the transition) is refused; the obligation mapping is KEPT), so a
     * later token of the same transaction can never re-open the chain
     * after the transient risk condition decayed.
     *
     * TERMINALIZATION-FIRST ordering: the chain transition is applied
     * BEFORE the nonce-disposition finalize; a failure of the finalize
     * after a successful terminalization answers temporary_unavailable,
     * and the retry rediscovers the terminal transaction (the dominance
     * rule — {@see self::assessFinalDisposition()}) and reconstructs the
     * terminal disposition — no authorization weakness, intentionally
     * conservative. A terminalization failure — or a refusal
     * ('conflict'/'missing'/'obligation_moved') — is fail-closed
     * temporary_unavailable: a bare Deny/StepUp is never returned
     * without the durable transaction terminality. The
     * 'already_verified' outcome is the normal post-Pass anomaly (the
     * transaction already ended via Pass — its obligation is gone): it
     * falls through — the fresh disposition applies to the nonce alone.
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 state is absent,
     *                                                 terminal with the
     *                                                 OTHER disposition
     *                                                 (conflict), the
     *                                                 obligation moved, or
     *                                                 the transition failed
     *                                                 — fail closed, never a
     *                                                 bare disposition
     *                                                 without durable
     *                                                 terminality
     */
    private function terminalizeOpenChain(ChainRequirement $requirement, PostSolveDispositionKind $kind): void
    {
        // The OBLIGATION-BOUND transition: the requirement's server-held
        // (scope, binding, policy epoch) derive the transaction's
        // obligation id — the SAME id the chain was created under — so
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
     * THE STAGE-2 CHAIN TRANSITION BY FINAL DISPOSITION — the disposition
     * is authoritative for transaction terminality, NEVER the core's
     * consumed result. Runs AFTER the disposition was durably finalized
     * ({@see PostSolveDispositionStore::finalize()} MUST have succeeded —
     * the caller's resolveFinalDisposition guarantees it), so the chain
     * transition can never clear — or fail to clear — an obligation whose
     * final disposition is not yet durable.
     *
     * Detection uses the SAME threaded requirement — {@see
     * self::resolveFinalDisposition()} resolved it EXACTLY ONCE and it
     * travels through the whole pipeline, never re-read here: the
     * verified challenge is a recognized stage-2 nonce when the
     * requirement holds the EXACT nonce as its stage2Nonce. The
     * detection runs on EVERY valid solve — the no-reassessment Pass
     * path (post_solve_check=false, no honeypot, no chain-eligible
     * scope) included — so a Pass disposition for a recognized stage-2
     * nonce STILL ends the chain (markVerified) instead of leaving it
     * issued for the controller to clean up.
     *
     * Transition BY KIND, all idempotent and nonce-pinned:
     *  - Pass   -> markVerified (the obligation is CLEARED atomically),
     *  - StepUp -> markStepUpRequired (the obligation is KEPT — the
     *    transaction stays bound to the step-up requirement),
     *  - Deny   -> markDenied (the obligation is KEPT — the transaction
     *    stays bound to its final denial),
     *  - ChainRequired -> unreachable for a stage-2 nonce (a stage-2
     *    challenge never opens a third stage) — fail closed.
     *
     * A transition failure or refusal is fail-closed
     * {@see PostSolveDispositionUnavailableException} (temporary_
     * unavailable) — never a silent pass while the obligation may be
     * uncleared.
     *
     * @param ChainRequirement|null $requirement the AUTHORITATIVE open
     *                                      chain requirement (threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()}
     *                                      — never re-read here)
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
     * THE canonical transaction binding of the request, resolved EXACTLY
     * ONCE per validation (BEFORE the signed-record binding comparison)
     * and threaded through every binding decision of the validation — the
     * stage-2 transaction lookup, the obligation lookup and the chain
     * creation — the authority is NEVER consulted twice. With an
     * authority configured the presented request binding is only a HINT:
     * the authority resolves the SERVER-OWNED canonical value (the same
     * value the challenge controller signed at issuance). An authority
     * THROW (its backend temporarily unavailable) is fail-closed
     * {@see PostSolveDispositionUnavailableException} — the caller
     * answers temporary_unavailable (a violation, never a silent pass,
     * never a raw exception); a null resolution (the transaction is
     * invalid/unknown) is the normal invalid-binding outcome; without an
     * authority the raw request binding applies unchanged.
     *
     * @throws PostSolveDispositionUnavailableException when the authority
     *                                                 fails (fail closed)
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
     * The OPEN chain requirement of this request's (scope, CANONICAL
     * binding, policy epoch), or null when none exists / chaining or the
     * authority is unavailable. Used for the stage-2 detection and the
     * obligation-authoritative disposition: a verified challenge whose
     * nonce equals the requirement's stage2Nonce IS the stage-2 challenge
     * — the chain ends there. FAIL-CLOSED: only a SUCCESSFUL lookup that
     * finds no record produces null — a chain-state read failure
     * (backend error, decoding/corruption, asymmetric failure) throws the
     * typed {@see PostSolveDispositionUnavailableException} the caller's
     * existing wrap converts to the temporary_unavailable violation; a
     * partial chain-state failure is NEVER an authoritative "no open
     * requirement".
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 requirement state
     *                                                 cannot be read (fail
     *                                                 closed)
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
     * The absolute expiry a stage-2 chain requirement is OPENED with:
     * now + the configured chain lifetime (risk.chaining.ttl_secs). The
     * SAME value is passed to requireStage2 (a fresh chain and an atomic
     * RAISE alike — the store's raise-only create-or-get preserves the
     * ORIGINAL expiry of an existing chain). A CHAIN_REQUIRED ticket is
     * NEVER signed with this independent value: the signing always
     * re-signs from the requirement's ACTUAL server-held expiresAt
     * ({@see chainRequirementExpiresAt()}).
     */
    private function chainExpiresAt(): int
    {
        return time() + max(1, $this->chainTtlSecs);
    }

    /**
     * The ACTUAL server-held expiry of the chain behind a CHAIN_REQUIRED
     * disposition: the requirement's expiresAt (findOpenRequirement on
     * the SAME (scope, canonical binding, policy epoch) the chain was
     * opened under). EVERY ChainRequired ticket — the just-opened fresh
     * chain, an existing obligation's chain and a replayed disposition
     * alike — re-signs with this value, never with an independent fresh
     * expiry: the same (nonce, disposition) reproduces the deterministic
     * SAME ticket and a re-signed ticket can never outlive its chain
     * state.
     *
     * @throws PostSolveDispositionUnavailableException when the
     *                                                 requirement is gone
     *                                                 (the chain expired or
     *                                                 was consumed) — fail
     *                                                 closed, never a
     *                                                 ticket that outlives
     *                                                 its chain
     */
    private function chainRequirementExpiresAt(KiwiCaptcha $constraint, ?string $canonicalBinding): int
    {
        $requirement = $this->chainTickets?->findOpenRequirement($constraint->scope, (string) ($canonicalBinding ?? ''), $this->policyVersion);
        if ($requirement === null) {
            throw new PostSolveDispositionUnavailableException('the chain requirement of the disposition is gone');
        }

        return $requirement->expiresAt;
    }

    /**
     * JTI + BINDING passthrough for an ACCEPTED verification: exposes the
     * canonical jti — the core's VerifyOutcome::nonce(), the challenge
     * nonce of the CONSUMED record — and the record's signed transaction
     * binding (VerifyOutcome::requestBinding()) to the application, both
     * via {@see verifiedJti()} / {@see verifiedRequestBinding()} and the
     * request attribute (VERIFIED_JTI_ATTRIBUTE; request-scoped and
     * race-free for web flows). The application keys its business
     * operation idempotency on (jti, action): a retry carrying the same
     * jti must never create a second operation (see README). Also exports
     * the Ed25519 result receipt when signing is configured.
     */
    private function finishSuccessfulApplicationVerification(string $value, VerifyOutcome $outcome, ?Request $request): void
    {
        $jti = null;
        if (\method_exists($outcome, 'nonce')) {
            $jti = $outcome->nonce();
        }
        if (!\is_string($jti) || $jti === '') {
            // Compat fallback (cores predating VerifyOutcome::nonce()):
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

        // RESULT RECEIPT: an ACCEPTED verification can be exported as an
        // Ed25519-signed receipt for third parties holding the PUBLIC key.
        // The receipt is signed from the CONSUMED RECORD's own fields and
        // carries the FULL replay-critical set — jti, tenant (scope),
        // action (PoW algorithm), request_binding, issued_at / expires_at,
        // issuer (the payload is public by construction — no secret
        // material; the HMAC verification secret itself never leaves the
        // server). Signature verification alone is NOT sufficient for
        // single-use actions: the integrator must atomically record the
        // jti (INSERT IF NOT EXISTS) and treat a pre-existing jti as a
        // replay (README).
        if ($this->receiptSigner !== null && $jti !== null) {
            $this->signReceipt($this->findRecordByNonce($jti));
        }
    }

    /**
     * Sign the Ed25519 result receipt from a consumed record:
     * the payload is built from the RECORD's own fields (jti, tenant,
     * action, request_binding, issued_at, expires_at, issuer) — never from
     * per-request state — so a stored-result retry re-signs the SAME
     * payload. No-op when signing is disabled or the record is unavailable.
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
     * FORM-SUBMISSION HONEYPOT: after a VALID verification, the form's
     * decoy field is compared against the EXACT expected name derived from
     * the VERIFIED nonce ({@see self::expectedDecoyField()} — the same
     * per-issuance derivation the challenge controller uses when it emits
     * the field). Returns whether the exact decoy was filled: the caller
     * then records the DecoyFieldSubmitted evidence (with the nonce-derived
     * honeypot:<sha256(nonce)> idempotency key — a crash-taken-over
     * computation never double-books the signal) and runs the post-solve
     * assessment through the risk-v2 path (the honeypot signal actually
     * moves the score). Any OTHER decoy_XXXXXXXX field is ignored — a
     * decoy name is server-issued and nonce-bound, so a mismatched name is
     * not this challenge's decoy. Evidence ONLY: never a gate and never
     * affects the proof validity. Never throws — a broken gateway must
     * never break the form.
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
     * The expected decoy field name for a verified nonce: the EXACT same
     * derivation the challenge controller emits at issuance
     * (ChallengeController: 'decoy_' . substr(sha256(nonce), 0, 8)), so
     * only the server-issued name for THIS challenge counts as honeypot
     * evidence.
     */
    private static function expectedDecoyField(string $nonce): string
    {
        return 'decoy_'.substr(hash('sha256', $nonce), 0, 8);
    }

    /**
     * The record's signed request binding of a VERIFIED outcome — the
     * stage-1 binding a chain ticket signs (null when the stage-1
     * challenge had none).
     */
    private function verifiedRequestBindingOf(\KiwiCaptcha\VerifyOutcome $outcome): ?string
    {
        return \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
    }

    /**
     * Whether the VERIFIED challenge behind a token already SATISFIES the
     * reassessed action — the authoritative stage-strength comparison
     * (risk.chaining) via the resolver's ACTUAL configured ladders. Allow
     * is the base: a neutral post-solve assessment can never open a
     * chain. A MISSING or UNREADABLE record (or a missing resolver) is
     * treated as NOT satisfied (Allow-level): the chain OPENS with the
     * required action, failing toward more security — a solved challenge
     * whose strength cannot be confirmed is never assumed to have met
     * the reassessed action.
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
     * The VERIFIED challenge's record, read by the verified nonce (the
     * same storage find the metadata sidecar uses): after a successful
     * verification the consumed record is kept for replay protection, so
     * the plain find resolves the record whose algorithm + target bits
     * decide the stage-strength comparison. null when storage is not
     * wired, the token cannot be decoded or the read fails (an unreadable
     * record is treated as NOT satisfied — the chain opens).
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
     * marker in its SERVER-HELD metadata (the PRIVATE chainId field — the
     * stage-2 controller stamped it at the stage-2 issuance; it never
     * travels in the cdata, so client input can never forge it). A marked
     * challenge is the END of its chain: no third-stage ticket can ever be
     * issued from it. FAILS CLOSED: a metadata READ failure THROWS — the
     * caller answers the temporary_unavailable violation when chaining is
     * enabled (the marker cannot be established, so the challenge is never
     * silently treated as stage-1-eligible); only a SUCCESSFUL read
     * without a marker legitimately keeps the challenge stage-1-eligible.
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
     * signed from the RECORD's own fields. null when storage is not wired
     * or the read fails (a receipt is then simply not produced — the
     * verification result itself is unaffected).
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
     * The consumed record behind a token: decoded nonce -> storage find,
     * restricted to records in the CONSUMED state (the consumed-state
     * transition). null when the state cannot be resolved.
     */
    private function findConsumedRecord(string $token): ?ChallengeRecord
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
            $record = $this->storage->find($nonce);
        } catch (\Throwable) {
            return null;
        }
        if ($record === null || !$this->recordIsConsumed($record)) {
            return null;
        }

        return $record;
    }

    /**
     * Whether the record is in the consumed state (the consumed-state
     * TRANSITION of the consumed-state storage contract). Probing
     * `ChallengeRecord::consumed` defensively: cores predating the
     * transition never set it (false) — on those cores consumed records
     * are DELETED by consume(), so a ConsumeIndeterminate followed by a
     * find() yields no record and stays unresolved (legacy behavior).
     */
    private function recordIsConsumed(ChallengeRecord $record): bool
    {
        return (bool) ($record->consumed ?? false);
    }

    /**
     * The stored consumed result of a consumed record: true = the original
     * derivation was VALID, false = it FAILED, null = consumed but no
     * result committed (indeterminate). The parallel core exposes it as
     * `ChallengeRecord::$consumedResult`.
     */
    private function consumedResultOf(ChallengeRecord $record): ?bool
    {
        $result = $record->consumedResult ?? null;

        return $result === null ? null : (bool) $result;
    }

    /**
     * The STORED binding of the consumed state (the binding the original
     * verification committed — `ChallengeRecord::$consumedBinding`,
     * falling back to the record's signed request_binding on cores that
     * store it there), or null for an unbound record.
     */
    private function consumedBindingOf(ChallengeRecord $record): ?string
    {
        $binding = $record->consumedBinding ?? $record->requestBinding;
        if (!\is_string($binding) || $binding === '') {
            return null;
        }

        return $binding;
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
     * Decode the bounded solution token to its nonce and CONSUME the
     * nonce -> decision handle (GETDEL — at most one consumer wins).
     * Returns the paired ORIGINAL pre-issue decision id, or null when the
     * token cannot be decoded or no handle exists. Never throws: a valid
     * verification implies a decodable token (defense in depth).
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
