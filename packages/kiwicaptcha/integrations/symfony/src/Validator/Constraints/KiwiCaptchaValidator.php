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
     *                                               — the same canonical IP
     *                                               the challenge controller
     *                                               bound the record to (a
     *                                               resolver mismatch would
     *                                               fail every bound
     *                                               challenge)
     * @param SecurityEpochMonitor|null $epochMonitor the security-epoch
     *                                               monitor — refreshed
     *                                               before every verification
     *                                               so the verifier's
     *                                               expected policy epoch is
     *                                               the current (monotonic,
     *                                               cached) one
     * @param ResultReceiptSigner|null $receiptSigner the optional Ed25519
     *                                               signer for exported
     *                                               verification results —
     *                                               null = receipt signing
     *                                               disabled
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
         * controller stamps the issued challenge's private chainId/
         * chainDepth metadata fields (never the cdata), and the validator
         * refuses to open a third stage when a verified challenge's
         * metadata carries a chainId — the chain ends at stage 2.
         */
        private readonly ?SiteVerifyMetadataStore $metadataStore = null,
        /**
         * The risk profile resolver (the same service the risk gateway
         * maps actions with): the authoritative stage-strength comparison
         * (risk.chaining) — a chain opens only when the reassessed action
         * is not satisfied by the solved challenge under the actual
         * configured ladders (risk.chaining; null = chaining disabled).
         */
        private readonly ?RiskProfileResolver $riskResolver = null,
        /**
         * The durable post-solve disposition store: every valid
         * verification — fresh derive and stored-result replay alike —
         * resolves its final disposition (pass | deny | step-up |
         * chain-required) through one path and persists it per nonce
         * before the application sees the outcome, so a replay of a valid
         * proof reproduces the same disposition instead of bypassing the
         * post-solve policy. The extension always wires a store (Redis,
         * or the in-memory variant in test/dev); null = the disposition is
         * computed and applied without persistence (manual construction).
         */
        private readonly ?PostSolveDispositionStore $dispositionStore = null,
        /**
         * The authoritative transaction-binding authority (nullable
         * service id risk.request_binding_authority): the presented
         * request_binding is a hint — the authority resolves the
         * server-owned canonical transaction binding, and the validator
         * enforces the signed record binding against that value
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
         * expiry the validator passes when it opens a stage-2 chain
         * requirement (requireStage2). A ChainRequired ticket is never
         * signed with an independent fresh expiry: the signing re-signs
         * from the disposition-carried bound (the chain's original
         * server-held expiresAt, persisted with the disposition as
         * chain_expires_at — {@see self::chainRequirementExpiresAt()}), so
         * the same (nonce, disposition) reproduces the same deterministic
         * ticket, a concurrently opened chain of the same transaction can
         * never leak its expiry into this disposition's ticket, and a
         * ticket can never outlive its chain state.
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

        // The security-policy epoch is refreshed before the verification
        // runs (bounded by the short cache window) and the verifier's
        // expected policy version rotates to the current monotonic max —
        // a central policy bump revokes outstanding challenges within one
        // cache window, a regressed or unavailable central value can
        // never weaken the epoch.
        $this->epochMonitor?->refresh();

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
        $outcome = $this->normalizeAmbiguousOutcome($outcome, $value, $request, $constraint->scope);

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

        // Transaction binding: after a valid verification, the consumed
        // record's signed request_binding must equal the binding the
        // request carried. With an authority configured
        // (risk.request_binding_authority) the presented binding is only
        // a hint: the server-owned canonical transaction binding is
        // resolved exactly once here — the same value the challenge
        // controller signed at issuance — and it drives every binding
        // decision of this validation (the comparison below, the stage-2
        // transaction lookup, the obligation lookup and the chain
        // creation; the authority is never consulted twice). An authority
        // failure (its backend temporarily unavailable) fails closed as
        // temporary_unavailable — a violation, never a silent pass, never
        // a raw exception; a null resolution (the transaction is
        // invalid/unknown) is the normal invalid-binding outcome.
        // Without an authority the raw request binding (the request
        // attribute the application controller copied from the POSTed
        // kiwi_request_binding field — or the raw POST field) applies
        // unchanged. A bound record with a missing/mismatched binding is
        // rejected with the same invalid_or_expired outcome (the
        // collapsed violation code): a challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely. For a stored-result
        // retry the outcome's requestBinding() is the stored consumed
        // binding, so the same rule gives the stored-result contract:
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

        // Resource accounting: the PoW is solved regardless of the later
        // risk disposition — the source's outstanding challenge counter
        // is decremented (best-effort, floored at 0) exactly once,
        // before the final-disposition resolution. Skipped for a
        // stored-result retry: the original verification already
        // decremented it.
        if (!$this->isStoredResult($outcome)) {
            $this->outstanding?->solved((string) ($clientIp ?? ''));
        }

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
                // re-read by id ({@see self::chainRequirementExpiresAt()})
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
     * The record's signed request_binding
     * (VerifyOutcome::requestBinding()) must equal the canonical binding
     * of the request — the authority's server-owned resolution when an
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
     * ConsumeIndeterminate is not a token-level failure: it is a storage
     * I/O ambiguity (the consume may or may not have happened) — the
     * resolution tries the stored record first, and an unresolvable
     * indeterminate outcome maps to temporary_unavailable (retryable,
     * like StorageUnavailable), never to invalid_or_expired — the
     * client must not be told its token is burned when it may still
     * redeem.
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
     * instead of re-deriving, with no side effects — the normalized
     * outcome flows through the same pipeline as any other verification
     * (binding check, outstanding accounting, final disposition): a
     * stored valid result -> a valid outcome carrying the consumed
     * record's nonce and stored binding (the pipeline's binding check
     * applies the stored-result contract: same binding -> same success,
     * different binding -> invalid_or_expired); a stored invalid result
     * -> invalid(InsufficientWork) (the original derivation failed);
     * storage unavailable / no record / still pending / consumed
     * without a committed result -> the original indeterminate outcome
     * (the caller's publicCode() maps ConsumeIndeterminate to
     * temporary_unavailable — retryable, never silently valid).
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
     * The final-disposition resolution — the single path every valid
     * verification (fresh derive and stored-result replay alike) flows
     * through:
     *
     *  0. the authoritative chain requirement of the transaction is
     *     resolved exactly once here and threaded through the whole
     *     pipeline ({@see self::assessFinalDisposition()} and
     *     {@see self::applyStage2Disposition()} — never re-read). A
     *     terminal requirement (denied / step_up_required) dominates
     *     every nonce — the exact stage-2 nonce and replays included:
     *     the terminal disposition answers before any assessment, and a
     *     terminal transaction never persists a Pass for any nonce. The
     *     lookup runs before the nonce -> decision handle is touched: a
     *     chain-state read failure must never consume the handle — the
     *     retry re-runs the lookup with the mapping intact and the
     *     original decision id is preserved for the final disposition;
     *  1. the canonical nonce is decoded, a fresh owner token drawn and
     *     the nonce -> decision handle is consumed atomically with the
     *     claim — but only when the claim creates the missing pending
     *     record (the store's claim consumes the mapping inside that
     *     same transition — at most one winner — and persists the
     *     paired handle in the pending disposition record, so an owner
     *     crash can never lose the original decision id of a
     *     no-post-solve Pass; a complete, busy or takeover claim never
     *     touches the mapping key);
     *  2. the nonce-keyed disposition record is claimed with the
     *     decision mapping key: 'complete' -> the persisted final
     *     disposition is returned immediately (a replay of a valid
     *     proof reproduces the same pass | deny | step-up |
     *     chain-required — never a bypass; a terminal requirement
     *     supersedes even a persisted disposition); 'pending' ->
     *     another owner's computation is live — the
     *     temporary_unavailable violation (never a silent pass; the
     *     decision mapping is never consumed by the busy claim);
     *     'claimed'/'taken_over' -> this owner runs the post-solve
     *     assessment, persists the disposition and returns it; a
     *     taken-over computation resumes with the original owner's
     *     decision handle (kept in the pending record);
     *  3. the finalize must succeed before anything is returned — a
     *     store failure is the temporary_unavailable violation, never a
     *     silent pass.
     *
     * @return array{0: PostSolveDisposition, 1: bool, 2: ?ChainRequirement}
     *         the final disposition, whether it came from the persisted
     *         record (a replay — informational) and the threaded
     *         authoritative requirement ({@see self::applyStage2Disposition()})
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
            // disposition is computed and applied WITHOUT persistence. The
            // extension always wires a store, so the durable path below is
            // the production behavior. The decision handle is consumed
            // directly (the atomic claim transfer is the store's job —
            // {@see PostSolveDispositionStore::claim()}).
            $decisionId = $this->consumeDecisionForToken($token);

            return [$this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce, $canonicalBinding, $decisionId, $requirement), false, $requirement];
        }

        $owner = bin2hex(random_bytes(16));
        $ttl = Config::MAX_TTL_SECS + $this->postSolveDispositionTtlMarginSecs;
        try {
            // Nonce -> decision consumption, atomic with the claim: the
            // short-lived mapping is consumed (delete-on-read, at most
            // one winner) inside the store's claim transition and the
            // paired handle is persisted in the pending disposition
            // record ({@see PostSolveDispositionStore::claim()}) — an
            // owner crash after the claim can never lose the original
            // decision id, and a crash-taken-over computation completes
            // the disposition with it. On scopes without post_solve_check
            // the original pre-issue decision id becomes the request's
            // current decision id ({@see RiskGateway::setCurrentDecisionId()});
            // on post_solve_check scopes the superseded mapping is still
            // consumed (cleanup) and the fresh post-solve decision
            // becomes the current confirmation target instead.
            $claim = $this->dispositionStore->claim($nonce, $owner, $ttl, $this->risk?->decisionKeyFor($nonce));
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
            // Terminal transaction state dominates — replays included: a
            // persisted nonce disposition (e.g. a Pass persisted before
            // the transaction terminalized) is superseded by the
            // requirement's terminal state, so a replay of the exact
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

        // The stored decision handle: the claim's atomic consume wrote
        // the paired handle into the pending record (a takeover resumes
        // the original owner's handle — the crashed owner's mapping is
        // already consumed), so the completed disposition keeps the
        // original decision id.
        try {
            $record = $this->dispositionStore->read($nonce);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition record is unreadable', 0, $e);
        }
        if ($record === null) {
            // The claim was won but the record vanished between the claim
            // and the read (a clock/expiry boundary): fail closed — never
            // silently pass.
            throw new PostSolveDispositionUnavailableException('the post-solve disposition record vanished after the claim');
        }
        $storedDecisionId = $record->decisionId;

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
     * honeypot evidence (recorded with its nonce-derived idempotency
     * key — a crash-taken-over computation never double-books the
     * signal), and the fresh reassessment whenever the scope opts in
     * (post_solve_check), chaining is relevant, or the exact decoy was
     * filled (a honeypot hit alone must trigger the fresh v2
     * assessment). The assessment always carries the nonce-derived
     * stable idempotency key 'postsolve:'.hash('sha256', $nonce), so a
     * takeover re-assessment is dedupe-key-identical to the original.
     * Terminal transaction state dominates first: the authoritative
     * requirement (threaded from {@see resolveFinalDisposition()}) bound
     * to its terminal denied / step_up_required state answers that
     * terminal disposition for every nonce — the exact stage-2 nonce
     * and replays included — before any assessment runs and before the
     * caller finalizes the nonce disposition, so a terminal transaction
     * never persists a Pass for any nonce.
     *
     * @param string|null $canonicalBinding the authority's server-owned
     *                                      transaction binding (resolved
     *                                      once, before the binding
     *                                      comparison — never
     *                                      re-resolved here)
     * @param string|null $originalDecisionId the stored decision handle:
     *                                      what the first owner consumed
     *                                      (or the pending record's
     *                                      handle on a takeover)
     * @param ChainRequirement|null $requirement the authoritative open
     *                                      chain requirement (threaded
     *                                      from
     *                                      {@see resolveFinalDisposition()}
     *                                      — never re-read here)
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

        // Form-submission honeypot (post-verification): the expected
        // decoy field name derives from the verified nonce
        // ('decoy_' + substr(sha256(nonce), 0, 8) — the exact same
        // derivation the challenge controller used when it emitted the
        // field), and only that exact field is inspected: any other
        // decoy_XXXXXXXX field is ignored (a decoy name is
        // server-issued and nonce-bound, so a mismatched name is not
        // this challenge's decoy). A filled expected field records
        // DecoyFieldSubmitted evidence and feeds the post-solve
        // assessment through the risk-v2 path (the honeypot signal
        // actually moves the score). Evidence only — never a gate and
        // never affects the proof validity.
        $honeypotHit = false;
        if ($this->risk !== null && $request !== null) {
            $honeypotHit = $this->formDecoyEvidence($request, self::expectedDecoyField($nonce));
        }

        // The original pre-issue decision id was consumed atomically
        // with the claim (the store's claim consumes the nonce ->
        // decision mapping inside the same transition — at most one
        // consumer — whenever the claim creates the missing pending
        // record) and travels in as the stored handle: on scopes
        // without post_solve_check it becomes the request's current
        // decision id ({@see RiskGateway::setCurrentDecisionId()}); on
        // post_solve_check scopes the superseded mapping is already
        // consumed (cleanup) and the fresh post-solve decision becomes
        // the current confirmation target instead.
        if ($this->risk !== null && !$postSolveScope && $originalDecisionId !== null) {
            $this->risk->setCurrentDecisionId($originalDecisionId);
        }

        // Honeypot evidence: recorded with its nonce-derived idempotency
        // key — a crash-taken-over re-assessment (or a concurrent retry
        // that wins the takeover) re-uses the same dedupe identity, so
        // the signal is never double-booked. Evidence only — a
        // recording failure never breaks the form submission.
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
     * non-terminal transaction (the requirement's terminal states were
     * already resolved as the authoritative disposition before the
     * assessment — the terminal transaction state dominates every
     * nonce). With an open obligation the final disposition is the
     * monotonic-escalation max of the obligation and the fresh
     * decision — security may rise, never fall, and an existing
     * obligation never freezes its security level:
     *
     *  - a fresh Deny wins (terminal rejection) and terminalizes the
     *    open obligation itself (markTransactionDenied — nonce-agnostic,
     *    keyed by the chain/obligation identity: the denial is durable
     *    for the rest of the transaction's lifetime, so a later token of
     *    the same transaction can never re-open the chain after the
     *    transient risk condition decayed);
     *  - then a fresh StepUp wins (terminal application-level step-up —
     *    never a chained PoW) and terminalizes the open obligation
     *    (markTransactionStepUpRequired — the same durability);
     *  - then a fresh strictly stronger chainable action raises the
     *    obligation atomically (requireStage2 with the fresh action —
     *    the store's raise-only create-or-get: the same chain id and the
     *    original expiry preserved, only the required rank/action rise)
     *    -> ChainRequired with that same chain id;
     *  - then a fresh equal/weaker/Allow action leaves the obligation
     *    unchanged (its recorded floor intact) -> ChainRequired with the
     *    requirement's chain id — a stage-1 token of a chained
     *    transaction can never pass, whatever the fresh assessment says.
     *
     * Without an open obligation: Deny -> Deny; StepUp -> StepUp
     * (terminal — never a chained PoW); Allow (or the required PoW
     * level is already satisfied by the solved challenge) -> Pass; a
     * strictly stronger PoW requirement opens a chain when chaining is
     * available (stage 2 -> StepUp — the chain ends at stage 2, never a
     * third stage; stage 1 + chaining available -> requireStage2(...) ->
     * ChainRequired — a raw client-supplied binding without an authority
     * is never sufficient), otherwise terminal StepUp — a stronger-PoW
     * requirement must never silently disappear when chaining is
     * unavailable.
     *
     * Terminalization-first ordering: the nonce-agnostic obligation
     * terminalization runs here, at the disposition-computation point of
     * the fresh Deny/StepUp cases ({@see self::terminalizeOpenChain()}),
     * before the nonce-disposition finalize; a failure of the finalize
     * after a successful terminalization answers temporary_unavailable,
     * and the retry rediscovers the terminal transaction (the dominance
     * rule) and reconstructs the terminal disposition — no authorization
     * weakness, intentionally conservative. The stage-2 (nonce-pinned)
     * chain transition itself is not performed here: the disposition is
     * finalized by the caller first (the durable
     * {@see PostSolveDispositionStore} finalize) and the stage-2 chain is
     * transitioned after, by disposition kind, in
     * {@see self::applyStage2Disposition()} — the final disposition is
     * authoritative for terminality, never the core's consumed result.
     *
     * @param ChainRequirement|null $requirement the authoritative open
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
        // Depth-2 detection (read-only): the verified challenge may be
        // the stage-2 challenge of an open chain requirement (its nonce
        // equals the requirement's stage2Nonce — the threaded lookup
        // from {@see resolveFinalDisposition()}) — the chain then ends
        // at stage 2, and a still-stronger requirement is terminal
        // StepUp (never a third stage). The transition runs after the
        // disposition is durably finalized
        // ({@see self::applyStage2Disposition()}).
        //
        // Obligation-authoritative: the open requirement is consulted
        // before the fresh assessment is applied — a partial chain-state
        // read failure fails closed ({@see self::openRequirementFor()})
        // and an existing obligation can never be downgraded by a weaker
        // fresh assessment. The requirement's terminal states are not
        // handled here: they were resolved by the caller before the
        // assessment ({@see self::assessFinalDisposition()} — the
        // terminal dominance precedes the $isStage2 computation and the
        // nonce-disposition finalize). With an open obligation the final
        // disposition is the monotonic-escalation max of the
        // obligation's state and the fresh assessment:
        //
        //  1. a fresh Deny wins (terminal rejection) and terminalizes
        //     the open obligation (markTransactionDenied — the denial is
        //     durable for the transaction's lifetime);
        //  2. then a fresh StepUp wins (terminal application-level
        //     step-up — never a chain ticket) and terminalizes the open
        //     obligation (markTransactionStepUpRequired);
        //  3. then a fresh strictly stronger chainable action atomically
        //     raises the obligation (requireStage2 — the store's
        //     raise-only mechanism: the same chain id, the original
        //     expiry preserved) and ChainRequired carries that same
        //     chain id — the recorded security level never freezes;
        //  4. then a fresh equal/weaker/Allow (or unknown-scope null)
        //     action leaves the obligation unchanged (its recorded floor
        //     intact) — ChainRequired with the requirement's chain id:
        //     a stage-1 token of a chained transaction can never pass.
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
                //    itself ({@see self::terminalizeOpenChain()} — the
                //    nonce-agnostic markTransactionDenied, keyed by the
                //    chain/obligation identity): the denial is durable
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
     * disposition (nonce-agnostic — the exact stage-2 nonce is not
     * required): the obligation becomes terminal denied /
     * step_up_required for the rest of its lifetime, atomically over
     * the chain + obligation keys
     * ({@see ChainedChallengeTicketService::markTransactionDenied()} /
     * {@see ChainedChallengeTicketService::markTransactionStepUpRequired()}
     * — the transaction's obligation id travels with the transition, so
     * a stale chain (the obligation moved between the requirement read
     * and the transition) is refused; the obligation mapping is kept),
     * so a later token of the same transaction can never re-open the
     * chain after the transient risk condition decayed.
     *
     * Terminalization-first ordering: the chain transition is applied
     * before the nonce-disposition finalize; a failure of the finalize
     * after a successful terminalization answers temporary_unavailable,
     * and the retry rediscovers the terminal transaction (the dominance
     * rule — {@see self::assessFinalDisposition()}) and reconstructs
     * the terminal disposition — no authorization weakness,
     * intentionally conservative. A terminalization failure — or a
     * refusal ('conflict'/'missing'/'obligation_moved') — is fail-closed
     * temporary_unavailable: a bare Deny/StepUp is never returned
     * without the durable transaction terminality. The
     * 'already_verified' outcome is the normal post-Pass anomaly (the
     * transaction already ended via Pass — its obligation is gone): it
     * falls through — the fresh disposition applies to the nonce alone.
     *
     * @throws PostSolveDispositionUnavailableException when the chain
     *                                                 state is absent,
     *                                                 terminal with the
     *                                                 other disposition
     *                                                 (conflict), the
     *                                                 obligation moved, or
     *                                                 the transition failed
     *                                                 — fail closed, never
     *                                                 a bare disposition
     *                                                 without durable
     *                                                 terminality
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
     * The stage-2 chain transition by final disposition — the
     * disposition is authoritative for transaction terminality, never
     * the core's consumed result. Runs after the disposition was durably
     * finalized ({@see PostSolveDispositionStore::finalize()} must have
     * succeeded — the caller's resolveFinalDisposition guarantees it),
     * so the chain transition can never clear — or fail to clear — an
     * obligation whose final disposition is not yet durable.
     *
     * Detection uses the same threaded requirement — {@see
     * self::resolveFinalDisposition()} resolved it exactly once and it
     * travels through the whole pipeline, never re-read here: the
     * verified challenge is a recognized stage-2 nonce when the
     * requirement holds the exact nonce as its stage2Nonce. The
     * detection runs on every valid solve — the no-reassessment Pass
     * path (post_solve_check=false, no honeypot, no chain-eligible
     * scope) included — so a Pass disposition for a recognized stage-2
     * nonce still ends the chain (markVerified) instead of leaving it
     * issued for the controller to clean up.
     *
     * Transition by kind, all idempotent and nonce-pinned:
     *  - Pass   -> markVerified (the obligation is cleared atomically),
     *  - StepUp -> markStepUpRequired (the obligation is kept — the
     *    transaction stays bound to the step-up requirement),
     *  - Deny   -> markDenied (the obligation is kept — the transaction
     *    stays bound to its final denial),
     *  - ChainRequired -> unreachable for a stage-2 nonce (a stage-2
     *    challenge never opens a third stage) — fail closed.
     *
     * A transition failure or refusal is fail-closed
     * {@see PostSolveDispositionUnavailableException} (temporary_
     * unavailable) — never a silent pass while the obligation may be
     * uncleared.
     *
     * @param ChainRequirement|null $requirement the authoritative open
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
     * The canonical transaction binding of the request, resolved exactly
     * once per validation (before the signed-record binding comparison)
     * and threaded through every binding decision of the validation —
     * the stage-2 transaction lookup, the obligation lookup and the
     * chain creation — the authority is never consulted twice. With an
     * authority configured the presented request binding is only a
     * hint: the authority resolves the server-owned canonical value
     * (the same value the challenge controller signed at issuance). An
     * authority throw (its backend temporarily unavailable) is
     * fail-closed {@see PostSolveDispositionUnavailableException} — the
     * caller answers temporary_unavailable (a violation, never a silent
     * pass, never a raw exception); a null resolution (the transaction
     * is invalid/unknown) is the normal invalid-binding outcome;
     * without an authority the raw request binding applies unchanged.
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
     * The open chain requirement of this request's (scope, canonical
     * binding, policy epoch), or null when none exists / chaining or the
     * authority is unavailable. Used for the stage-2 detection and the
     * obligation-authoritative disposition: a verified challenge whose
     * nonce equals the requirement's stage2Nonce is the stage-2
     * challenge — the chain ends there. Fail-closed: only a successful
     * lookup that finds no record produces null — a chain-state read
     * failure (backend error, decoding/corruption, asymmetric failure)
     * throws the typed {@see PostSolveDispositionUnavailableException}
     * the caller's existing wrap converts to the temporary_unavailable
     * violation; a partial chain-state failure is never an
     * authoritative "no open requirement".
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
     * The absolute expiry a stage-2 chain requirement is opened with:
     * now + the configured chain lifetime (risk.chaining.ttl_secs). The
     * same value is passed to requireStage2 (a fresh chain and an atomic
     * raise alike — the store's raise-only create-or-get preserves the
     * original expiry of an existing chain). A ChainRequired ticket is
     * never signed with this independent value: the signing re-signs
     * from the disposition-carried bound — the requirement's actual
     * server-held expiresAt, persisted with the disposition
     * ({@see chainRequirementExpiresAt()}).
     */
    private function chainExpiresAt(): int
    {
        return time() + max(1, $this->chainTtlSecs);
    }

    /**
     * The absolute expiry a ChainRequired ticket is signed with: the
     * disposition-carried bound — the exact chain's original
     * server-held expiresAt, persisted with the disposition as
     * chain_expires_at at finalize time — never a fresh
     * current-obligation lookup: a concurrently opened chain Y of the
     * same transaction can never leak its expiry into this
     * disposition's ticket, and a completed chain (record retained,
     * obligation gone) keeps re-signing its deterministic ticket. The
     * chain record is read by id
     * ({@see ChainedChallengeTicketService::requirementFor()} — the
     * by-chain-id read, never the obligation lookup) as the liveness
     * check and the exact-bound comparison: a dead chain (expired /
     * record gone) is fail-closed temporary_unavailable, and a
     * shape-valid carried bound that differs from the exact chain
     * record's server-held expiresAt is corrupt state — fail-closed
     * temporary_unavailable, never a ticket that outlives its chain or
     * expires early. A legacy record whose carried bound is null falls
     * back to the exact chain record's server-held expiresAt.
     *
     * @throws PostSolveDispositionUnavailableException when the
     *                                                 chain is gone (the
     *                                                 chain expired or was
     *                                                 consumed) or the
     *                                                 carried bound does
     *                                                 not match the exact
     *                                                 chain record — fail
     *                                                 closed, never a
     *                                                 ticket that outlives
     *                                                 its chain
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
     * the canonical jti — the core's VerifyOutcome::nonce(), the
     * challenge nonce of the consumed record — and the record's signed
     * transaction binding (VerifyOutcome::requestBinding()) to the
     * application, both via {@see verifiedJti()} /
     * {@see verifiedRequestBinding()} and the request attribute
     * (VERIFIED_JTI_ATTRIBUTE; request-scoped and race-free for web
     * flows). The application keys its business operation idempotency
     * on (jti, action): a retry carrying the same jti must never create
     * a second operation (see README). Also exports the Ed25519 result
     * receipt when signing is configured.
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

        // Result receipt: an accepted verification can be exported as an
        // Ed25519-signed receipt for third parties holding the public
        // key. The receipt is signed from the consumed record's own
        // fields and carries the full replay-critical set — jti, tenant
        // (scope), action (PoW algorithm), request_binding, issued_at /
        // expires_at, issuer (the payload is public by construction —
        // no secret material; the HMAC verification secret itself never
        // leaves the server). Signature verification alone is not
        // sufficient for single-use actions: the integrator must
        // atomically record the jti (INSERT IF NOT EXISTS) and treat a
        // pre-existing jti as a replay (README).
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
     * Form-submission honeypot: after a valid verification, the form's
     * decoy field is compared against the exact expected name derived
     * from the verified nonce ({@see self::expectedDecoyField()} — the
     * same per-issuance derivation the challenge controller uses when
     * it emits the field). Returns whether the exact decoy was filled:
     * the caller then records the DecoyFieldSubmitted evidence (with
     * the nonce-derived honeypot:<sha256(nonce)> idempotency key — a
     * crash-taken-over computation never double-books the signal) and
     * runs the post-solve assessment through the risk-v2 path (the
     * honeypot signal actually moves the score). Any other
     * decoy_XXXXXXXX field is ignored — a decoy name is server-issued
     * and nonce-bound, so a mismatched name is not this challenge's
     * decoy. Evidence only: never a gate and never affects the proof
     * validity. Never throws — a broken gateway must never break the
     * form.
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
     * same derivation the challenge controller emits at issuance
     * (ChallengeController: 'decoy_' . substr(sha256(nonce), 0, 8)), so
     * only the server-issued name for this challenge counts as honeypot
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
     * Whether the verified challenge behind a token already satisfies
     * the reassessed action — the authoritative stage-strength
     * comparison (risk.chaining) via the resolver's actual configured
     * ladders. Allow is the base: a neutral post-solve assessment can
     * never open a chain. A missing or unreadable record (or a missing
     * resolver) is treated as not satisfied (Allow-level): the chain
     * opens with the required action, failing toward more security — a
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
     * The verified challenge's record, read by the verified nonce (the
     * same storage find the metadata sidecar uses): after a successful
     * verification the consumed record is kept for replay protection, so
     * the plain find resolves the record whose algorithm + target bits
     * decide the stage-strength comparison. null when storage is not
     * wired, the token cannot be decoded or the read fails (an unreadable
     * record is treated as not satisfied — the chain opens).
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
     * marker in its server-held metadata (the private chainId field —
     * the stage-2 controller stamped it at the stage-2 issuance; it
     * never travels in the cdata, so client input can never forge it).
     * A marked challenge is the end of its chain: no third-stage ticket
     * can ever be issued from it. Fails closed: a metadata read failure
     * throws — the caller answers the temporary_unavailable violation
     * when chaining is enabled (the marker cannot be established, so
     * the challenge is never silently treated as stage-1-eligible);
     * only a successful read without a marker legitimately keeps the
     * challenge stage-1-eligible.
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
     * transition of the consumed-state storage contract). Probing
     * `ChallengeRecord::consumed` defensively: cores predating the
     * transition never set it (false) — on those cores consumed records
     * are deleted by consume(), so a ConsumeIndeterminate followed by a
     * find() yields no record and stays unresolved.
     */
    private function recordIsConsumed(ChallengeRecord $record): bool
    {
        return (bool) ($record->consumed ?? false);
    }

    /**
     * The stored consumed result of a consumed record: true = the
     * original derivation was valid, false = it failed, null = consumed
     * but no result committed (indeterminate). The parallel core
     * exposes it as `ChallengeRecord::$consumedResult`.
     */
    private function consumedResultOf(ChallengeRecord $record): ?bool
    {
        $result = $record->consumedResult ?? null;

        return $result === null ? null : (bool) $result;
    }

    /**
     * The stored binding of the consumed state (the binding the
     * original verification committed —
     * `ChallengeRecord::$consumedBinding`, falling back to the record's
     * signed request_binding on cores that store it there), or null for
     * an unbound record.
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
     * Decode the bounded solution token to its nonce and consume the
     * nonce -> decision handle (delete-on-read — at most one consumer
     * wins). Returns the paired original pre-issue decision id, or null
     * when the token cannot be decoded or no handle exists. Never
     * throws: a valid verification implies a decodable token (defense
     * in depth).
     *
     * Superseded on the durable path: with a disposition store wired the
     * consumption happens atomically inside the store's claim
     * transition ({@see PostSolveDispositionStore::claim()} — the
     * claim consumes the mapping by its full key and persists the
     * paired handle in the pending record, so a fallible chain-state
     * read before the claim can never lose it). This method remains
     * only for the no-store seam (manual construction — the disposition
     * is computed without persistence).
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
