<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Security\StepUp;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * The phishing-resistant target of the step-up plane: WebAuthn, over
 * the web-auth/webauthn-lib package (the pure-PHP WebAuthn library).
 * The class is the concrete lib-backed handler. The whole feature sits
 * behind one installation check: the constructor refuses with
 * {@see self::NOT_IMPLEMENTED_MESSAGE} when the library is absent.
 * Activating the handler is exactly one composer require, and a
 * deployment without the library keeps the historical refusal, word
 * for word.
 *
 * Ceremony flow: begin() mints a 32-byte ceremony challenge, pins it
 * into the challenge record as a keyed hash (the same never-the-secret
 * rule as the code handlers; the challenge alone proves nothing), and
 * presents the options document. Step-up never enrolls: an unenrolled
 * principal is refused with an actionable error and uses another
 * factor instead, such as email OTP, because an attacker holding
 * stolen credentials is exactly the case step-up exists for.
 *
 * The creation ceremony lives on the separate enrollment entry points,
 * {@see self::enrollBegin()} and {@see self::enrollComplete()}, which
 * demand a completed step-up for the same principal first. The
 * application routes those behind an already-authenticated session.
 *
 * complete() loads the presented credential through the library's
 * loader, pins the echoed challenge against the stored hash, and
 * checks the presented origin against the configured allowed origins.
 * The client-controlled Host header never decides the origin. User
 * verification is required, and the library's validator then runs the
 * origin binding, the RP-id hash, user presence and verification, and
 * the sign-count check. A counter that fails to advance counts as a
 * failed attempt and answers the replayed failure code; an assertion
 * over an unregistered credential answers the unknown-credential code.
 * On success the single-use record is consumed and the credit runs
 * through {@see StepUpCompletionCredit}, exactly once per challenge.
 */
final class WebAuthnStepUpHandler implements StepUpHandlerInterface
{
    public const NOT_IMPLEMENTED_MESSAGE = 'WebAuthn step-up requires the web-auth/webauthn-lib package: require it (composer require web-auth/webauthn-lib) to activate the phishing-resistant handler; without the package the handler refuses with this exact message';

    public const TICKET_FIELD = 'kiwi_step_up_ticket';
    public const CREDENTIAL_FIELD = 'kiwi_step_up_credential';

    public const CEREMONY_CREATION = 'creation';
    public const CEREMONY_ASSERTION = 'assertion';

    /** The request attributes a per-request CSP nonce may ride. */
    public const NONCE_ATTRIBUTE = 'csp_nonce';
    public const NONCE_ATTRIBUTE_ALT = '_csp_nonce';

    /** The failure code of an assertion over an unregistered credential. */
    public const FAIL_UNKNOWN_CREDENTIAL = 'unknown_credential';

    /**
     * The lookback of the enrollment precondition: a WebAuthn creation
     * ceremony is only ever issued when the same principal completed a
     * step-up (any handler) within this many seconds. An attacker
     * holding stolen credentials has no such completion, so the
     * enrollment path stays closed to them.
     */
    private const ENROLLMENT_LOOKBACK_SECS = 900;

    private const CHALLENGE_HKDF_INFO = 'kiwi/v1/stepup-webauthn-challenge';

    private const CHALLENGE_HKDF_SALT = 'kiwicaptcha/deploy-salt/v1';

    /**
     * The ceremony script body shared by the inline (nonce) and the
     * external (same-origin file) presentations. It reads the options
     * document from the page and drives navigator.credentials.get.
     */
    /**
     * The creation ceremony script: navigator.credentials.create() with
     * the user, pubKeyCredParams and excludeCredentials fields, and an
     * attestationObject serializer. The assertion script cannot enroll
     * a credential — calling get() on a creation challenge is a
     * functional dead end.
     */
    public const CEREMONY_CREATION_SCRIPT = <<<'JS'
            (function () {
              var doc = JSON.parse(document.getElementById('kiwi-webauthn-options').dataset.options);
              var opts = doc.public_key;
              function buf(v) {
                var b = atob(v.replace(/-/g, '+').replace(/_/g, '/'));
                var a = new Uint8Array(b.length);
                for (var i = 0; i < b.length; i++) { a[i] = b.charCodeAt(i); }
                return a.buffer;
              }
              function b64(v) {
                var b = '';
                var u = new Uint8Array(v);
                for (var i = 0; i < u.length; i++) { b += String.fromCharCode(u[i]); }
                return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
              }
              opts.challenge = buf(opts.challenge);
              if (opts.user && opts.user.id) { opts.user.id = buf(opts.user.id); }
              if (opts.excludeCredentials) {
                opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
                  return { id: buf(c.id), type: c.type };
                });
              }
              navigator.credentials.create({ publicKey: opts }).then(function (cred) {
                document.getElementById('kiwi-webauthn-credential').value = JSON.stringify({
                  id: cred.id,
                  rawId: b64(cred.rawId),
                  type: cred.type,
                  response: {
                    clientDataJSON: b64(cred.response.clientDataJSON),
                    attestationObject: b64(cred.response.attestationObject)
                  }
                });
                document.getElementById('kiwi-webauthn-form').submit();
              }).catch(function (e) {
                document.getElementById('kiwi-webauthn-status').textContent =
                  'Security key enrollment failed: ' + (e && e.message ? e.message : String(e));
              });
            })();
    JS;

    /**
     * The assertion ceremony script body shared by the inline (nonce)
     * and the external (same-origin file) presentations. It reads the
     * options document from the page and drives navigator.credentials.get.
     */
    /**
     * The combined ceremony script an external scriptSrc file must
     * contain: one file that branches on doc.ceremony so the HTML
     * presentation needs no per-request nonce. Serve this exact body
     * as the external file; the page loads it with a plain script tag.
     */
    public const CEREMONY_COMBINED_SCRIPT = <<<'JS'
            (function () {
              var doc = JSON.parse(document.getElementById('kiwi-webauthn-options').dataset.options);
              var opts = doc.public_key;
              function buf(v) {
                var b = atob(v.replace(/-/g, '+').replace(/_/g, '/'));
                var a = new Uint8Array(b.length);
                for (var i = 0; i < b.length; i++) { a[i] = b.charCodeAt(i); }
                return a.buffer;
              }
              function b64(v) {
                var b = '';
                var u = new Uint8Array(v);
                for (var i = 0; i < u.length; i++) { b += String.fromCharCode(u[i]); }
                return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
              }
              opts.challenge = buf(opts.challenge);
              var isCreate = doc.ceremony === 'creation';
              if (isCreate) {
                if (opts.user && opts.user.id) { opts.user.id = buf(opts.user.id); }
                if (opts.excludeCredentials) {
                  opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
                    return { id: buf(c.id), type: c.type };
                  });
                }
              } else if (opts.allowCredentials) {
                opts.allowCredentials = opts.allowCredentials.map(function (c) {
                  return { id: buf(c.id), type: c.type };
                });
              }
              var call = isCreate
                ? navigator.credentials.create({ publicKey: opts })
                : navigator.credentials.get({ publicKey: opts });
              call.then(function (cred) {
                var payload = { id: cred.id, rawId: b64(cred.rawId), type: cred.type, response: {} };
                payload.response.clientDataJSON = b64(cred.response.clientDataJSON);
                if (isCreate) {
                  payload.response.attestationObject = b64(cred.response.attestationObject);
                } else {
                  payload.response.authenticatorData = b64(cred.response.authenticatorData);
                  payload.response.signature = b64(cred.response.signature);
                  payload.response.userHandle = cred.response.userHandle ? b64(cred.response.userHandle) : null;
                }
                document.getElementById('kiwi-webauthn-credential').value = JSON.stringify(payload);
                document.getElementById('kiwi-webauthn-form').submit();
              }).catch(function (e) {
                document.getElementById('kiwi-webauthn-status').textContent =
                  'Security key failed: ' + (e && e.message ? e.message : String(e));
              });
            })();
    JS;

    /**
     * The assertion ceremony script body shared by the inline (nonce)
     * and the external (same-origin file) presentations. It reads the
     * options document from the page and drives navigator.credentials.get.
     */
    public const CEREMONY_SCRIPT = <<<'JS'
            (function () {
              var doc = JSON.parse(document.getElementById('kiwi-webauthn-options').dataset.options);
              var opts = doc.public_key;
              function buf(v) {
                var b = atob(v.replace(/-/g, '+').replace(/_/g, '/'));
                var a = new Uint8Array(b.length);
                for (var i = 0; i < b.length; i++) { a[i] = b.charCodeAt(i); }
                return a.buffer;
              }
              function b64(v) {
                var b = '';
                var u = new Uint8Array(v);
                for (var i = 0; i < u.length; i++) { b += String.fromCharCode(u[i]); }
                return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
              }
              opts.challenge = buf(opts.challenge);
              if (opts.allowCredentials) {
                opts.allowCredentials = opts.allowCredentials.map(function (c) {
                  return { id: buf(c.id), type: c.type };
                });
              }
              navigator.credentials.get({ publicKey: opts }).then(function (cred) {
                document.getElementById('kiwi-webauthn-credential').value = JSON.stringify({
                  id: cred.id,
                  rawId: b64(cred.rawId),
                  type: cred.type,
                  response: {
                    clientDataJSON: b64(cred.response.clientDataJSON),
                    authenticatorData: b64(cred.response.authenticatorData),
                    signature: b64(cred.response.signature),
                    userHandle: cred.response.userHandle ? b64(cred.response.userHandle) : null
                  }
                });
                document.getElementById('kiwi-webauthn-form').submit();
              }).catch(function (e) {
                document.getElementById('kiwi-webauthn-status').textContent =
                  'Security key failed: ' + (e && e.message ? e.message : String(e));
              });
            })();
            JS;

    private readonly string $challengeKey;

    private readonly PublicKeyCredentialLoader $loader;

    private readonly AuthenticatorAttestationResponseValidator $creationValidator;

    private readonly AuthenticatorAssertionResponseValidator $assertionValidator;

    /**
     * @param bool|null $libPresent the installation-check seam: null
     *                              auto-detects the library, and the
     *                              container path never passes it
     */
    public function __construct(
        private readonly StepUpChallengeStore $store,
        private readonly StepUpTicket $ticket,
        private readonly StepUpCompletionCredit $credit,
        private readonly ?WebAuthnCredentialRegistry $registry,
        private readonly string $master,
        private readonly int $challengeTtlSecs = 300,
        private readonly int $maxAttempts = 5,
        private readonly int $maxBegins = 3,
        private readonly int $beginWindowSecs = 900,
        private readonly string $completePath = '/kiwi/step-up/complete',
        private readonly ?\Closure $now = null,
        private readonly ?bool $libPresent = null,
        private readonly string $rpId = '',
        private readonly array $allowedOrigins = [],
        private readonly ?StepUpLockoutGuard $lockout = null,
        private readonly ?StepUpOwnerNotifier $ownerNotifier = null,
        private readonly ?StepUpBootstrapGate $bootstrapGate = null,
        // The static CSP nonce is gone: only a per-request nonce from the
        // server-set attribute is honored, otherwise external-script mode.
        private readonly ?string $scriptSrc = null,
    ) {
        if (\strlen($master) < 32) {
            throw new \InvalidArgumentException('The WebAuthn handler master must be at least 32 bytes (the same floor as secret_key)');
        }
        if ($this->rpId !== '' || $this->allowedOrigins !== []) {
            if ($this->rpId === '' || $this->allowedOrigins === []) {
                throw new \InvalidArgumentException('risk.step_up.webauthn needs both rp_id and a non-empty allowed_origins list; a relying-party id without its origins (or the reverse) cannot pin the ceremony');
            }
            $rp = strtolower($this->rpId);
            if (!preg_match('/^[a-z0-9.-]+$/D', $rp)) {
                throw new \InvalidArgumentException('risk.step_up.webauthn.rp_id must be a bare domain (no scheme, no port, no path)');
            }
            foreach ($this->allowedOrigins as $origin) {
                if (!\is_string($origin) || preg_match('#^https?://[A-Za-z0-9.-]+(:[0-9]+)?$#D', $origin) !== 1) {
                    throw new \InvalidArgumentException('risk.step_up.webauthn.allowed_origins entries must be absolute origins like https://login.example.com');
                }
                $host = strtolower((string) parse_url($origin, \PHP_URL_HOST));
                if ($host !== $rp && !str_ends_with($host, '.'.$rp)) {
                    throw new \InvalidArgumentException(sprintf('the allowed origin %s is neither the rp_id %s nor one of its subdomains', $origin, $this->rpId));
                }
            }
        }
        $this->challengeKey = hash_hkdf('sha256', $master, 32, self::CHALLENGE_HKDF_INFO, self::CHALLENGE_HKDF_SALT);
        $present = $libPresent ?? \class_exists(PublicKeyCredentialLoader::class);
        if (!$present) {
            throw new \LogicException(self::NOT_IMPLEMENTED_MESSAGE);
        }
        if ($this->registry === null) {
            throw new \LogicException('WebAuthn step-up needs its credential registry wired; the bundle extension wires it whenever the handler is enabled');
        }
        $factory = new CeremonyStepManagerFactory();
        $this->creationValidator = new AuthenticatorAttestationResponseValidator(null, null, null, null, null, $factory->creationCeremony());
        $this->assertionValidator = new AuthenticatorAssertionResponseValidator($this->registry, null, null, null, null, $factory->requestCeremony());
        $manager = AttestationStatementSupportManager::create([new NoneAttestationStatementSupport()]);
        $this->loader = PublicKeyCredentialLoader::create(AttestationObjectLoader::create($manager));
    }

    public function begin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        $enrolled = $this->registry->registeredCredentialsOf($context->principalPseudonym);

        // The refusals answer before the admission counter: a begin
        // that mints nothing must also consume no rate budget.
        if ($enrolled === []) {
            return $this->refusal(
                $context,
                Response::HTTP_FORBIDDEN,
                'step_up_enrollment_required',
                'No security key is enrolled for this account. Enroll one from an authenticated session that has completed a step-up first; until then this handler is unavailable for the account.',
            );
        }
        if ($this->rpId === '' || $this->allowedOrigins === []) {
            return $this->refusal(
                $context,
                Response::HTTP_UNPROCESSABLE_ENTITY,
                'step_up_misconfigured',
                'risk.step_up.webauthn.rp_id and risk.step_up.webauthn.allowed_origins must be configured before the WebAuthn handler can run.',
            );
        }
        // The cross-challenge brute-force budget: while the requesting
        // context (or the shared account/target backstops) is locked,
        // no fresh challenge is minted. A WebAuthn begin for an
        // enrolled principal is the stronger-factor path: it bypasses
        // the shared locks (the assertion to come is the owner's proof).
        $contextKey = StepUpLockoutGuard::contextKeyOf($request);
        $retryAfter = $this->lockout?->retryAfterSecs($context->principalPseudonym, $context->targetPseudonym, $now, $contextKey, true) ?? 0;
        if ($retryAfter > 0) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_locked_out',
                'Too many failed verification attempts; retry after the lockout window.',
                ['Retry-After' => (string) $retryAfter],
            );
        }

        $admissions = $this->store->countBegin($context->principalPseudonym, $this->beginWindowSecs);
        if ($admissions > $this->maxBegins) {
            return $this->refusal(
                $context,
                Response::HTTP_TOO_MANY_REQUESTS,
                'step_up_rate_limited',
                'Too many step-up challenges were begun for this account; retry after the window.',
                ['Retry-After' => (string) $this->beginWindowSecs],
            );
        }

        $challengeBytes = random_bytes(32);
        $ceremony = self::CEREMONY_ASSERTION;
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->challengeTtlSecs,
            $this->maxAttempts,
            $this->challengeHash($challengeBytes),
            $ceremony,
            StepUpSessionBinding::sessionId($request),
            $context->targetOwned,
        );
        $this->store->create($challenge, $this->challengeTtlSecs);

        return $this->presentation($context, $challenge, $challengeBytes, $enrolled, $ceremony, $this->configuredHost(), $this->cspNonceOf($request));
    }

    public function complete(Request $request): StepUpResult
    {
        $boundSessionId = StepUpSessionBinding::sessionId($request);
        $boundContextKey = StepUpLockoutGuard::contextKeyOf($request);
        $now = $this->now();
        $resolved = $this->challengeOfRequest($request, $now);
        if ($resolved instanceof StepUpChallengeExpired) {
            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED);
        }
        if ($resolved === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE);
        }
        $challenge = $resolved;
        if ($challenge->kind !== StepUpChallengeKind::WebAuthn || $challenge->ceremony === null || $challenge->codeHash === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        // The completion is bound to the session that began the
        // challenge: a ticket presented under another principal is
        // refused before any credential is loaded.
        if (!StepUpSessionBinding::matches($request, $challenge)) {
            return StepUpResult::failed(StepUpResult::FAIL_SESSION_MISMATCH, $challenge->id);
        }
        // A WebAuthn assertion presentation is the stronger-factor
        // path: it bypasses the shared (account/target) locks. The
        // requesting context's own budget still applies.
        $retryAfter = $this->lockout?->retryAfterSecs($challenge->principalPseudonym, $challenge->targetPseudonym, $now, $boundContextKey, true) ?? 0;
        if ($retryAfter > 0) {
            return StepUpResult::failed(StepUpResult::FAIL_LOCKED_OUT, $challenge->id);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED, $challenge->id);
        }
        $payload = (string) $request->request->get(self::CREDENTIAL_FIELD, '');
        if ($payload === '') {
            $payload = (string) $request->getContent();
        }
        try {
            $decoded = json_decode($payload, true, 64, JSON_THROW_ON_ERROR);
            $credential = $this->loader->loadArray(\is_array($decoded) ? $decoded : []);
        } catch (\Throwable $e) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        $response = $credential->response;
        try {
            $presentedChallenge = (string) $response->clientDataJSON->challenge;
        } catch (\Throwable) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        if (!hash_equals($challenge->codeHash, $this->challengeHash($presentedChallenge))) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        $presentedOrigin = strtolower(rtrim((string) $response->clientDataJSON->origin, '/'));
        if (!$this->originIsAllowed($presentedOrigin)) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        // The validator receives the host the ceremony actually ran on
        // (the presented, allow-listed origin's host) — never the first
        // configured origin's host. A login on a second configured
        // origin must validate against that origin.
        $host = (string) (parse_url($presentedOrigin, \PHP_URL_HOST) ?: '');
        if ($host === '') {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        try {
            if ($response instanceof AuthenticatorAttestationResponse) {
                // Step-up never enrolls. The creation ceremony only
                // exists on the enrollment entry points, so an
                // attestation answer here is a protocol violation.
                return $this->failedAttempt($challenge, $boundContextKey);
            }
            if ($response instanceof AuthenticatorAssertionResponse) {
                if ($challenge->ceremony !== self::CEREMONY_ASSERTION) {
                    return $this->failedAttempt($challenge, $boundContextKey);
                }
                if (!$response->authenticatorData->isUserVerified()) {
                    return $this->failedAttempt($challenge, $boundContextKey);
                }
                $source = $this->registry->findOneByCredentialId($credential->rawId);
                if ($source === null) {
                    $this->store->consume($challenge->id);

                    return StepUpResult::failed(self::FAIL_UNKNOWN_CREDENTIAL, $challenge->id);
                }
                try {
                    $updated = $this->assertionValidator->check(
                        $source,
                        $response,
                        $this->assertionOptions($challenge, $presentedChallenge, $host, $source),
                        $host,
                        $challenge->principalPseudonym,
                    );
                    // The validator updates the returned source only:
                    // persist the advanced sign count in the registry.
                    $this->registry->saveCredentialSource($updated);
                } catch (CounterException) {
                    // The signature verified but the sign count failed
                    // to advance: a cloned or replayed authenticator.
                    // It spends an attempt like every other failure.
                    $verdict = $this->failedAttempt($challenge, $boundContextKey);
                    if ($verdict->status !== StepUpResultStatus::Pending) {
                        return $verdict;
                    }

                    return StepUpResult::failed(StepUpResult::FAIL_REPLAYED_STEP, $challenge->id);
                }
            } else {
                return $this->failedAttempt($challenge, $boundContextKey);
            }
        } catch (\Throwable $e) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }

        $consumed = $this->store->consume($challenge->id);
        if ($consumed === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        $this->lockout?->registerSuccess($challenge->principalPseudonym, $challenge->targetOwned ? $challenge->targetPseudonym : null, $boundContextKey);

        return $this->credit($challenge, $boundSessionId);
    }

    private function creationOptions(StepUpChallenge $challenge, string $challengeBytes, string $host): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->rpId, $this->rpId),
            PublicKeyCredentialUserEntity::create(
                $challenge->principalPseudonym,
                $challenge->principalPseudonym,
                'step-up'),
            $challengeBytes,
            [
                new PublicKeyCredentialParameters('public-key', -7),
                new PublicKeyCredentialParameters('public-key', -257),
            ],
            new AuthenticatorSelectionCriteria(null, AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED),
            null,
            [],
            max(1, $challenge->expiresAt - $challenge->createdAt),
        );
    }

    private function assertionOptions(StepUpChallenge $challenge, string $challengeBytes, string $host, PublicKeyCredentialSource $source): PublicKeyCredentialRequestOptions
    {
        return new PublicKeyCredentialRequestOptions(
            $challengeBytes,
            $this->rpId,
            [PublicKeyCredentialDescriptor::create('public-key', $source->publicKeyCredentialId)],
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            max(1, $challenge->expiresAt - $challenge->createdAt),
        );
    }

    /**
     * The enrollment entry point: a creation ceremony for a principal
     * that has itself completed a step-up within the lookback window.
     * The application must route this behind an already-authenticated
     * session; the handler enforces the completed-step-up precondition
     * here and again in {@see self::enrollComplete()}.
     */
    public function enrollBegin(Request $request, StepUpContext $context): Response
    {
        $now = $this->now();
        $boundSessionId = StepUpSessionBinding::sessionId($request);
        $sessionId = $boundSessionId;
        $enrolledNow = $this->registry->registeredCredentialsOf($context->principalPseudonym);
        // Strongest-factor floor: a principal that already holds a
        // security key must prove with that key to add another.
        $minFactor = $enrolledNow !== [] ? 'webauthn' : null;
        $bootstrapOk = $enrolledNow === []
            && $this->bootstrapGate?->allowsFirstEnrollment($request, $context->principalPseudonym) === true;
        if ($sessionId === ''
            || (!$bootstrapOk && !$this->store->recentSessionStepUpSuccess($sessionId, $context->principalPseudonym, $minFactor, self::ENROLLMENT_LOOKBACK_SECS, $now))) {
            return $this->refusal(
                $context,
                Response::HTTP_FORBIDDEN,
                'step_up_enrollment_requires_session_step_up',
                'Enrolling a security key needs a step-up completed in THIS session with an already-enrolled factor. Another session of the same account cannot authorize enrollment.',
            );
        }
        if ($this->rpId === '' || $this->allowedOrigins === []) {
            return $this->refusal(
                $context,
                Response::HTTP_UNPROCESSABLE_ENTITY,
                'step_up_misconfigured',
                'risk.step_up.webauthn.rp_id and risk.step_up.webauthn.allowed_origins must be configured before enrollment can run.',
            );
        }
        $enrolled = $this->registry->registeredCredentialsOf($context->principalPseudonym);
        $challengeBytes = random_bytes(32);
        // The session id binds the creation challenge (never minted as a
        // stateless challenge) and the bootstrap flag records the
        // authorization the single-use grant just conferred — the
        // completion reads the flag instead of re-consulting the gate.
        $challenge = StepUpChallenge::begin(
            StepUpChallenge::mintId(),
            StepUpChallengeKind::WebAuthn,
            $context->principalPseudonym,
            $context->targetPseudonym,
            $context->scope,
            $context->returnPath,
            $context->reason,
            $now,
            $this->challengeTtlSecs,
            $this->maxAttempts,
            $this->challengeHash($challengeBytes),
            self::CEREMONY_CREATION,
            $sessionId,
            false,
            $bootstrapOk,
        );
        $this->store->create($challenge, $this->challengeTtlSecs);

        return $this->presentation($context, $challenge, $challengeBytes, $enrolled, self::CEREMONY_CREATION, $this->configuredHost(), $this->cspNonceOf($request));
    }

    /**
     * The enrollment completion: validates the attestation against the
     * configured origins and the UV requirement, then saves the new
     * credential. It never credits a step-up completion: enrollment is
     * not a step-up, and the precondition was the completed one.
     */
    public function enrollComplete(Request $request): StepUpResult
    {
        $boundSessionId = StepUpSessionBinding::sessionId($request);
        $boundContextKey = StepUpLockoutGuard::contextKeyOf($request);
        $now = $this->now();
        $resolved = $this->challengeOfRequest($request, $now);
        if ($resolved instanceof StepUpChallengeExpired || $resolved === null) {
            return StepUpResult::failed($resolved === null ? StepUpResult::FAIL_UNKNOWN_CHALLENGE : StepUpResult::FAIL_EXPIRED, $resolved?->id);
        }
        $challenge = $resolved;
        if ($challenge->kind !== StepUpChallengeKind::WebAuthn || $challenge->ceremony !== self::CEREMONY_CREATION || $challenge->codeHash === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }
        if ($challenge->expired($now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_EXPIRED, $challenge->id);
        }
        $sessionId = $boundSessionId !== '' ? $boundSessionId : StepUpSessionBinding::sessionId($request);
        $enrolledNow = $this->registry->registeredCredentialsOf($challenge->principalPseudonym);
        $minFactor = $enrolledNow !== [] ? 'webauthn' : null;
        // The grant is single-use and was consumed at enrollBegin: the
        // completion reads the flag the begin recorded on the challenge
        // (never re-consults the gate). A session proof also satisfies
        // this check. The binding is enforced like every other
        // challenge: the completing session must be the one that began
        // it (or the stateless client-secret path).
        if (!StepUpSessionBinding::matches($request, $challenge)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed(StepUpResult::FAIL_SESSION_MISMATCH, $challenge->id);
        }
        $bootstrapOk = $challenge->bootstrapAuthorized;
        if (!$bootstrapOk
            && !$this->store->recentSessionStepUpSuccess($sessionId, $challenge->principalPseudonym, $minFactor, self::ENROLLMENT_LOOKBACK_SECS, $now)) {
            $this->store->consume($challenge->id);

            return StepUpResult::failed('step_up_enrollment_requires_session_step_up', $challenge->id);
        }
        $payload = (string) $request->request->get(self::CREDENTIAL_FIELD, '');
        if ($payload === '') {
            $payload = (string) $request->getContent();
        }
        try {
            $decoded = json_decode($payload, true, 64, JSON_THROW_ON_ERROR);
            $credential = $this->loader->loadArray(\is_array($decoded) ? $decoded : []);
        } catch (\Throwable) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        $response = $credential->response;
        if (!$response instanceof AuthenticatorAttestationResponse) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        $presentedChallenge = (string) ($response->clientDataJSON->challenge ?? '');
        if ($presentedChallenge === '' || !hash_equals($challenge->codeHash, $this->challengeHash($presentedChallenge))) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        $origin = strtolower(rtrim((string) $response->clientDataJSON->origin, '/'));
        if (!$this->originIsAllowed($origin)) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        // As in complete(): the validator receives the presented,
        // allow-listed origin's host, never the first configured one.
        $host = (string) (parse_url($origin, \PHP_URL_HOST) ?: '');
        if ($host === '') {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        try {
            if (!$response->attestationObject->authData->isUserVerified()) {
                return $this->failedAttempt($challenge, $boundContextKey);
            }
            $source = $this->creationValidator->check(
                $response,
                $this->creationOptions($challenge, $presentedChallenge, $host),
                $host,
            );
            $this->registry->saveCredentialSource($source);
            try {
                $this->ownerNotifier?->notifyFactorEnrolled($challenge->principalPseudonym, 'webauthn', ['ceremony' => 'creation']);
            } catch (\Throwable) {
                // Notification is best effort; enrollment already landed.
            }
        } catch (\Throwable) {
            return $this->failedAttempt($challenge, $boundContextKey);
        }
        if ($this->store->consume($challenge->id) === null) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }

        return StepUpResult::succeeded(false, false);
    }

    /** The configured primary origin's host, or '' when unconfigured. */
    private function configuredHost(): string
    {
        if ($this->allowedOrigins === []) {
            return '';
        }
        $host = parse_url($this->allowedOrigins[0], \PHP_URL_HOST);

        return \is_string($host) ? $host : '';
    }

    /**
     * The CSP nonce of the presentation: a per-request nonce the
     * application's CSP layer stashes on the request attributes
     * (`csp_nonce` / `_csp_nonce` — server-set, never a client header)
     * wins over the configured `nonce` / `csp_nonce` default. Null when
     * none is available (the page then relies on the external script
     * or a non-nonce CSP).
     */
    /**
     * The CSP nonce of the presentation. Only a per-request nonce from
     * the server-set attribute is honored: a static configured nonce is
     * a single-use value reused across responses and is refused. With
     * no per-request nonce the page uses the external-script mode.
     */
    private function cspNonceOf(Request $request): ?string
    {
        foreach ([self::NONCE_ATTRIBUTE, self::NONCE_ATTRIBUTE_ALT] as $attribute) {
            $value = $request->attributes->get($attribute);
            if (\is_string($value) && $value !== '') {
                return $value;
            }
        }

        // The configured static nonce is no longer honored: it is
        // reused across responses and is not a real CSP nonce.
        // The configured static nonce is no longer honored.
        return null;
    }

    /** Whether the presented origin is one of the configured allowed origins. */
    private function originIsAllowed(string $presentedOrigin): bool
    {
        if ($presentedOrigin === '') {
            return false;
        }
        foreach ($this->allowedOrigins as $origin) {
            if (strtolower(rtrim($origin, '/')) === $presentedOrigin) {
                return true;
            }
        }

        return false;
    }

    private function challengeHash(string $challengeBytes): string
    {
        return hash_hmac('sha256', $challengeBytes, $this->challengeKey);
    }

    private function failedAttempt(StepUpChallenge $challenge, string $contextKey = ''): StepUpResult
    {
        // Every rejected verification feeds the cross-challenge
        // brute-force budget before the per-challenge attempt cap.
        $this->lockout?->registerFailure($challenge->principalPseudonym, $challenge->targetPseudonym, $contextKey);
        $answer = $this->store->recordFailure($challenge->id, $challenge->maxAttempts);
        if ($answer === 0) {
            return StepUpResult::failed(StepUpResult::FAIL_TOO_MANY_ATTEMPTS, $challenge->id);
        }
        if ($answer < 0) {
            return StepUpResult::failed(StepUpResult::FAIL_UNKNOWN_CHALLENGE, $challenge->id);
        }

        return StepUpResult::pending($challenge->id);
    }

    /**
     * The challenge of the request, the StepUpChallengeExpired marker
     * when the presented ticket is well-signed but past its own expiry,
     * or null when no live one resolves.
     */
    private function challengeOfRequest(Request $request, int $now): StepUpChallenge|StepUpChallengeExpired|null
    {
        $ticket = (string) $request->request->get(self::TICKET_FIELD, '');
        if ($ticket === '') {
            return null;
        }
        $payload = $this->ticket->verify($ticket, $now);
        if ($payload === null) {
            $looked = $this->ticket->look($ticket);
            if ($looked !== null && $looked['expiresAt'] <= $now) {
                return StepUpChallengeExpired::marker();
            }

            return null;
        }

        return $this->store->read($payload['challengeId']);
    }

    private function credit(StepUpChallenge $challenge, string $boundSessionId = ''): StepUpResult
    {
        try {
            $result = $this->credit->credit($challenge->id, $challenge);
        } catch (\Throwable) {
            return StepUpResult::failed(StepUpResult::FAIL_OUTCOME_UNAVAILABLE, $challenge->id);
        }
        if ($result->status === StepUpResultStatus::Succeeded) {
            $this->store->markStepUpSuccess($challenge->principalPseudonym, 900, $this->now());
            // Session-scoped proof: only the session that completed the
            // step-up may enroll a factor. A principal-level marker is
            // never enough (N1).
            $this->store->markSessionStepUpSuccess(
                $boundSessionId,
                $challenge->principalPseudonym,
                'webauthn',
                900,
                $this->now(),
            );
        }

        return $result;
    }

    /**
     * The begin presentation: the options document (the json payload
     * the browser navigator.credentials call consumes) for the json
     * mode, and the same document embedded in a page for the html mode.
     *
     * @param list<PublicKeyCredentialSource> $enrolled
     * @param string|null                     $nonce the CSP nonce for
     *                                                the inline script
     *                                                (configured
     *                                                default or a
     *                                                per-request one)
     */
    private function presentation(StepUpContext $context, StepUpChallenge $challenge, string $challengeBytes, array $enrolled, string $ceremony, string $host, ?string $nonce = null): Response
    {
        $ticket = $this->ticket->issue($challenge->id, $challenge->expiresAt);
        $expiresIn = max(0, $challenge->expiresAt - $this->now());
        $options = $ceremony === self::CEREMONY_ASSERTION
            ? new PublicKeyCredentialRequestOptions(
                $challengeBytes,
                $this->rpId,
                array_map(
                    static fn (PublicKeyCredentialSource $source): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create('public-key', $source->publicKeyCredentialId),
                    $enrolled,
                ),
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                max(1, $expiresIn),
            )
            : $this->creationOptions($challenge, $challengeBytes, $host);
        $document = [
            'handler' => 'webauthn',
            'ceremony' => $ceremony,
            'challenge' => $ticket,
            'public_key' => json_decode((string) json_encode($options, JSON_UNESCAPED_SLASHES), true),
            'expires_in' => $expiresIn,
            'complete_path' => $this->completePath,
        ];
        // A stateless begin (no session) also returns its one-time
        // client secret — the only channel that ever carries the
        // plaintext.
        $clientSecret = $challenge->issuedClientSecret();
        if ($clientSecret !== null && $clientSecret !== '') {
            $document['client_secret'] = $clientSecret;
        }
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode($document, JSON_UNESCAPED_SLASHES);

            return new Response($body, Response::HTTP_OK, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }
        $optionsJson = htmlspecialchars((string) json_encode($document, JSON_UNESCAPED_SLASHES), ENT_QUOTES);
        $action = htmlspecialchars($this->completePath, ENT_QUOTES);
        $ticketField = htmlspecialchars(self::TICKET_FIELD, ENT_QUOTES);
        $ticketValue = htmlspecialchars($ticket, ENT_QUOTES);
        $credentialField = htmlspecialchars(self::CREDENTIAL_FIELD, ENT_QUOTES);
        $secretInput = $clientSecret !== null && $clientSecret !== ''
            ? '<input type="hidden" name="'.htmlspecialchars(StepUpSessionBinding::CLIENT_SECRET_FIELD, ENT_QUOTES).'" value="'.htmlspecialchars($clientSecret, ENT_QUOTES).'">'
            : '';
        // The ceremony script runs under a strict script-src either as
        // an external same-origin file (script_src configured) or as an
        // inline block carrying the configured CSP nonce.
        $nonceAttr = $nonce !== null && $nonce !== ''
            ? ' nonce="'.htmlspecialchars($nonce, ENT_QUOTES).'"'
            : '';
        $scriptOpen = $this->scriptSrc !== null && $this->scriptSrc !== ''
            ? '<script src="'.htmlspecialchars($this->scriptSrc, ENT_QUOTES).'"'.$nonceAttr.'>'
            : '<script'.$nonceAttr.'>';
        // A creation ceremony needs navigator.credentials.create(); the
        // assertion script would call get() and could never enroll.
        $inlineScript = $ceremony === self::CEREMONY_CREATION
            ? self::CEREMONY_CREATION_SCRIPT
            : self::CEREMONY_SCRIPT;
        $scriptBody = $this->scriptSrc !== null && $this->scriptSrc !== ''
            ? ''
            : $inlineScript;
        $html = <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Security key</title></head>
            <body>
            <main style="max-width:28rem;margin:4rem auto;font-family:system-ui,sans-serif">
            <h1>Security key</h1>
            <p>Use your security key or platform authenticator to continue.</p>
            <div id="kiwi-webauthn-options" data-options="{$optionsJson}"></div>
            <p id="kiwi-webauthn-status" role="alert" style="color:#b00020"></p>
            <form method="post" action="{$action}" id="kiwi-webauthn-form">
            <input type="hidden" name="{$ticketField}" value="{$ticketValue}">
            {$secretInput}
            <input type="hidden" name="{$credentialField}" id="kiwi-webauthn-credential">
            <button type="submit">Continue</button>
            </form>
            </main>
            {$scriptOpen}
            {$scriptBody}
            </script>
            </body>
            </html>
            HTML;

        return new Response($html, Response::HTTP_OK, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    /**
     * @param array<string, string> $headers
     */
    private function refusal(StepUpContext $context, int $status, string $code, string $message, array $headers = []): Response
    {
        if ($context->mode === StepUpContext::MODE_JSON) {
            $body = (string) json_encode(['error' => $code, 'message' => $message], JSON_UNESCAPED_SLASHES);

            return new Response($body, $status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
        }

        return new Response($message, $status, $headers + ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store']);
    }

    private function now(): int
    {
        return ($this->now) ? ($this->now)() : time();
    }
}
