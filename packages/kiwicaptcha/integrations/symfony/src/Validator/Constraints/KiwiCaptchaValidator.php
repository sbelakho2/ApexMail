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
         * service id risk.request_binding_authority): chaining opens only
         * when the AUTHORITATIVE binding of the transaction resolves
         * non-null — a raw client-supplied binding without an authority is
         * never sufficient. Null = chaining unavailable (a stronger PoW
         * demand falls back to terminal StepUp, never a silent pass).
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
         * requirement (requireStage2) and when it re-signs the one-shot
         * ticket for a persisted CHAIN_REQUIRED disposition.
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

        // TRANSACTION BINDING: after a VALID verification, the
        // consumed record's SIGNED request_binding must equal the binding
        // the request carried (the request attribute the application
        // controller copied from the POSTed kiwi_request_binding field — or
        // the raw POST field). A bound record with a missing/mismatched
        // binding is rejected with the SAME invalid_or_expired outcome
        // (the collapsed violation code): a challenge minted for one
        // transaction is never redeemable for another. Unbound records
        // (binding null) skip the check entirely. For a stored-result
        // retry the outcome's requestBinding() IS the stored consumed
        // binding, so the SAME rule gives the stored-result contract: same
        // binding -> same success, different binding -> invalid_or_expired.
        if (!$this->requestBindingMatches($outcome, $request)) {
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
            $disposition = $this->resolveFinalDisposition($value, $outcome, $request, $constraint, (string) ($clientIp ?? ''));
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
                // documented machine-readable format. A ticket that cannot
                // be produced is fail-closed temporary_unavailable — a
                // stronger stage was demanded but cannot be chained, never
                // a silent downgrade to an unchained pass.
                try {
                    $ticket = $this->chainTickets?->ticketFor($disposition->chainId, $this->chainExpiresAt());
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
     * must equal the binding the request carried — when the record is
     * bound. An unbound record (null binding) skips the check.
     */
    private function requestBindingMatches(\KiwiCaptcha\VerifyOutcome $outcome, ?Request $request): bool
    {
        $recordBinding = \method_exists($outcome, 'requestBinding') ? $outcome->requestBinding() : null;
        if ($recordBinding === null) {
            return true;
        }

        $requestBinding = $this->requestBindingFromRequest($request);

        return $requestBinding !== null && hash_equals($recordBinding, $requestBinding);
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
     * instead of re-deriving. Returns the normalized outcome with NO side
     * effects — the normalized outcome flows through the SAME pipeline as
     * any other verification (binding check, outstanding accounting, final
     * disposition):
     *
     *  - stored VALID result -> a VALID outcome carrying the consumed
     *    record's nonce and STORED binding (marked as a stored result, so
     *    the outstanding decrement never runs twice); the pipeline's
     *    binding check applies the stored-result contract (same binding ->
     *    same success, different binding -> invalid_or_expired);
     *  - stored INVALID result -> invalid(InsufficientWork) (the original
     *    derivation failed — collapsed to invalid_or_expired);
     *  - storage unavailable / no record / still pending / consumed without
     *    a committed result -> the ORIGINAL indeterminate outcome (the
     *    caller's publicCode() maps ConsumeIndeterminate to
     *    temporary_unavailable — retryable, never silently valid).
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
     *  1. the canonical nonce is decoded and a fresh owner token drawn;
     *  2. the nonce-keyed disposition record is CLAIMED:
     *       - 'complete'   -> the persisted final disposition is returned
     *         immediately (a replay of a valid proof reproduces the same
     *         PASS | DENY | STEP_UP | CHAIN_REQUIRED — never a bypass);
     *       - 'pending'    -> another owner's computation is live — the
     *         temporary_unavailable violation (never a silent pass);
     *       - 'claimed'/'taken_over' -> this owner runs the post-solve
     *         assessment, persists the disposition and returns it;
     *  3. the finalize MUST succeed before anything is returned — a store
     *     failure is the temporary_unavailable violation, never a silent
     *     pass.
     *
     * @throws PostSolveDispositionUnavailableException fail-closed: the
     *                                                 disposition could not
     *                                                 be resolved durably
     */
    private function resolveFinalDisposition(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $ip): PostSolveDisposition
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

        if ($this->dispositionStore === null) {
            // No store wired (manual construction / legacy seam): the
            // disposition is computed and applied WITHOUT persistence. The
            // extension always wires a store, so the durable path below is
            // the production behavior.
            return $this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce);
        }

        $owner = bin2hex(random_bytes(16));
        $ttl = Config::MAX_TTL_SECS + $this->postSolveDispositionTtlMarginSecs;
        try {
            $claim = $this->dispositionStore->claim($nonce, $owner, $ttl);
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
            // A replay reproduces the request-scoped decision id too, so the
            // application can confirm the SAME decision handle.
            if ($this->risk !== null && $disposition->decisionId !== null) {
                $this->risk->setCurrentDecisionId($disposition->decisionId);
            }

            return $disposition;
        }

        if ($claim !== 'claimed' && $claim !== 'taken_over') {
            // 'pending': another owner's claim is live (or the claim was
            // re-entered with the same owner token). Retryable — never a
            // silent pass.
            throw new PostSolveDispositionUnavailableException('the post-solve disposition claim is held by another owner');
        }

        $disposition = $this->assessFinalDisposition($token, $outcome, $request, $constraint, $ip, $session, $nonce);

        try {
            $finalized = $this->dispositionStore->finalize($nonce, $owner, $disposition);
        } catch (\Throwable $e) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition could not be persisted', 0, $e);
        }
        if (!$finalized) {
            throw new PostSolveDispositionUnavailableException('the post-solve disposition finalize was refused');
        }

        return $disposition;
    }

    /**
     * The post-solve assessment of a verified proof: the nonce->decision
     * consumption, the form-submission honeypot evidence (recorded with its
     * nonce-derived idempotency key — a crash-taken-over computation never
     * double-books the signal), and the fresh reassessment whenever the
     * scope opts in (post_solve_check), chaining is relevant, or the exact
     * decoy was filled (a honeypot hit alone — even with post_solve_check
     * false and chaining disabled — must trigger the fresh v2 assessment).
     * The assessment ALWAYS carries the nonce-derived stable idempotency
     * key 'postsolve:'.hash('sha256', $nonce), so a takeover re-assessment
     * is dedupe-key-identical to the original.
     */
    private function assessFinalDisposition(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $ip, ?string $session, string $nonce): PostSolveDisposition
    {
        $postSolveScope = $this->risk !== null && $this->risk->postSolveCheck($constraint->scope);

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
            } catch (\Throwable) {
                // The metadata sidecar could not be read (transient
                // outage): the chain marker is treated as POSSIBLY present
                // — no chain ticket is issued (a metadata-read failure
                // must never open a third stage or a repeated-challenge
                // loop). The verification itself still passes.
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

        // NONCE -> DECISION CONSUMPTION: the short-lived nonce ->
        // decision handle is CONSUMED (GETDEL, at most one winner). On
        // scopes WITHOUT post_solve_check the ORIGINAL pre-issue decision
        // id becomes the request's current decision id
        // ({@see RiskGateway::setCurrentDecisionId()}), so the application
        // can confirm this challenge's original decision. On post_solve_check
        // scopes the superseded mapping is still consumed (cleanup — it can
        // never be confirmed against a stale decision), and the fresh
        // POST-SOLVE decision becomes the current confirmation target
        // instead.
        $originalDecisionId = null;
        if ($this->risk !== null) {
            $originalDecisionId = $this->consumeDecisionForToken($token);
            if (!$postSolveScope && $originalDecisionId !== null) {
                $this->risk->setCurrentDecisionId($originalDecisionId);
            }
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

        return $this->mapPostSolveDecision($token, $outcome, $request, $constraint, $nonce, $postSolve);
    }

    /**
     * Map the post-solve decision to the final disposition:
     *
     *  - Deny            -> Deny;
     *  - StepUp          -> StepUp (TERMINAL — never a chained PoW);
     *  - Allow (or the required PoW level is already satisfied by the
     *    solved challenge) -> Pass;
     *  - STRICTLY STRONGER PoW required:
     *      stage 2 (the verified challenge IS the open requirement's
     *      stage-2 challenge — the obligation is marked verified
     *      idempotently) -> StepUp (the chain ends at stage 2, never a
     *      third stage);
     *      stage 1 + chaining available (chaining enabled AND the
     *      authoritative transaction binding resolved non-null — a raw
     *      client-supplied binding without an authority is NEVER
     *      sufficient) -> requireStage2(...) -> ChainRequired;
     *      otherwise -> StepUp — a stronger-PoW requirement must NEVER
     *      silently disappear when chaining is unavailable.
     *
     * @throws PostSolveDispositionUnavailableException when a stage-2
     *                                                 obligation cannot be
     *                                                 cleared or the chain
     *                                                 requirement cannot be
     *                                                 opened (fail closed —
     *                                                 never a silent pass
     *                                                 while the obligation
     *                                                 may be uncleared)
     */
    private function mapPostSolveDecision(string $token, VerifyOutcome $outcome, ?Request $request, KiwiCaptcha $constraint, string $nonce, ?RiskDecision $postSolve): PostSolveDisposition
    {
        if ($postSolve === null) {
            // The scope is unknown and the engine declines to evaluate:
            // nothing to enforce beyond the solved proof.
            return new PostSolveDisposition(PostSolveDispositionKind::Pass);
        }
        $decisionId = $postSolve->decisionId;

        // DEPTH-2 DETECTION: the verified challenge may BE the stage-2
        // challenge of an open chain requirement (its nonce equals the
        // requirement's stage2Nonce). Whenever the reassessment runs for
        // such a challenge, the obligation is marked verified
        // (idempotent — a failure is fail-closed temporary_unavailable:
        // never a final PASS while the obligation may be uncleared).
        $requirement = $this->openRequirementFor($constraint, $request);
        $isStage2 = false;
        if ($requirement !== null && $requirement->stage2Nonce !== null && hash_equals($requirement->stage2Nonce, $nonce)) {
            $isStage2 = true;
            try {
                $verified = $this->chainTickets->markVerified($requirement->chainId, $nonce);
            } catch (\Throwable $e) {
                throw new PostSolveDispositionUnavailableException('the chain obligation could not be marked verified', 0, $e);
            }
            if (!\in_array($verified, [ChainVerifiedResult::VerifiedNew, ChainVerifiedResult::VerifiedSame], true)) {
                throw new PostSolveDispositionUnavailableException(sprintf('the chain obligation was not cleared (%s)', $verified->value));
            }
        }

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
        // available — enabled AND the AUTHORITATIVE transaction binding of
        // the request resolves non-null (a raw client-supplied binding
        // without an authority is NEVER sufficient).
        $authoritativeBinding = $this->authoritativeBinding($constraint, $request);
        if ($this->chainTickets !== null && $authoritativeBinding !== null) {
            try {
                $chainRequirement = $this->chainTickets->requireStage2(
                    $nonce,
                    $constraint->scope,
                    $authoritativeBinding,
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
     * The authoritative transaction binding of the request via the wired
     * binding authority, or null when no authority is wired or it declines
     * (chaining then never opens — a raw client-supplied binding without
     * an authority is never sufficient).
     */
    private function authoritativeBinding(KiwiCaptcha $constraint, ?Request $request): ?string
    {
        if ($this->bindingAuthority === null || $request === null) {
            return null;
        }
        try {
            $binding = $this->bindingAuthority->resolve($request, $constraint->scope, $this->requestBindingFromRequest($request));
        } catch (\Throwable) {
            // An authority failure fails toward MORE security: no
            // authoritative binding -> no chain -> terminal StepUp.
            return null;
        }

        return \is_string($binding) && $binding !== '' ? $binding : null;
    }

    /**
     * The OPEN chain requirement of this request's (scope, authoritative
     * binding, policy epoch), or null when none exists / chaining or the
     * authority is unavailable. Used for the stage-2 detection: a verified
     * challenge whose nonce equals the requirement's stage2Nonce IS the
     * stage-2 challenge — the chain ends there.
     */
    private function openRequirementFor(KiwiCaptcha $constraint, ?Request $request): ?ChainRequirement
    {
        if ($this->chainTickets === null) {
            return null;
        }
        $binding = $this->authoritativeBinding($constraint, $request);
        if ($binding === null) {
            return null;
        }
        try {
            return $this->chainTickets->findOpenRequirement($constraint->scope, $binding, $this->policyVersion);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The absolute expiry of a chain ticket: now + the configured chain
     * lifetime (risk.chaining.ttl_secs). The SAME value opens the stage-2
     * requirement (requireStage2) and re-signs the ticket of a persisted
     * CHAIN_REQUIRED disposition, so a replay reproduces the same ticket
     * shape.
     */
    private function chainExpiresAt(): int
    {
        return time() + max(1, $this->chainTtlSecs);
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
     * caller treats the marker as possibly present (no chain ticket; the
     * verification itself still passes).
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
