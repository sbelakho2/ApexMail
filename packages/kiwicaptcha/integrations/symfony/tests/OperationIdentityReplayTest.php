<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Risk\RequestBindingAuthorityInterface;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\SolutionToken;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Validation;

/**
 * The operation-identity replay semantics of the Symfony validator:
 *
 *  - default (no binding, no explicit operation id): strict single-use.
 *    A consumed token's stored success never replays to a second,
 *    distinct request. The fallback identity is derived from the token
 *    nonce itself, so any same-scope request derives the same identity,
 *    and the validator therefore refuses every fromStoredResult outcome
 *    whose identity lacks an explicit operation-id component (the
 *    replayed_token violation). The core replay path skips the
 *    IP/TTL/telemetry cheap checks, so the gate must hold regardless of
 *    IP, expiry or telemetry.
 *  - explicit operation ID (kiwi_operation_id: the request attribute, the
 *    POSTed field, or the constraint option): idempotent retry. The same
 *    logical operation re-presenting the same id plus the same token
 *    replays the stored success (IP/TTL/telemetry exempt — the committed
 *    outcome was durably recorded after the original checks passed). A
 *    different id, a different token, or a different binding is refused.
 *  - binding authority: the canonical binding still participates in the
 *    identity, so a replay under a different binding never matches.
 */
final class OperationIdentityReplayTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private const ISSUED_AT = 1_800_000_000;

    private const FIRST_IP = '198.51.100.7';

    private const OTHER_IP = '203.0.113.9';

    /**
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack, 2: KiwiCaptchaValidator}
     */
    private function engine(
        Verifier $verifier,
        string $ip = self::FIRST_IP,
        ?string $operationId = null,
        ?string $requestBinding = null,
        ?RequestBindingAuthorityInterface $authority = null,
        bool $enforceTelemetry = false,
        array $post = [],
    ): array {
        $stack = new RequestStack();
        $request = Request::create('/', 'POST', $post, [], [], ['REMOTE_ADDR' => $ip]);
        if ($operationId !== null) {
            $request->attributes->set(KiwiCaptchaValidator::OPERATION_ID_ATTRIBUTE, $operationId);
        }
        if ($requestBinding !== null) {
            $request->attributes->set(KiwiCaptchaValidator::REQUEST_BINDING_ATTRIBUTE, $requestBinding);
        }
        $stack->push($request);

        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, enforceTelemetry: $enforceTelemetry, bindingAuthority: $authority);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        return [$engine, $stack, $validator];
    }

    private function validate(array $engine, string $token, string $scope = 'login'): ConstraintViolationListInterface
    {
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engine[0]->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => $scope]));

        return $engine[0]->validate($dto);
    }

    /**
     * A freshly issued + solved token against its own storage, with the
     * verifier clock pinned to the issuance second.
     *
     * @return array{0: ArrayStorage, 1: Verifier, 2: string} storage, verifier (clock = `ISSUED_AT`), solved token
     */
    private function solvedToken(?string $requestBinding = null, array $telemetry = []): array
    {
        [$storage, $token] = $this->issuedAndSolved(self::FIRST_IP, $requestBinding, $telemetry);

        return [$storage, new Verifier($storage, now: fn (): int => self::ISSUED_AT), $token];
    }

    /**
     * @return array{0: ArrayStorage, 1: string}
     */
    private function issuedAndSolved(string $ip, ?string $requestBinding = null, array $telemetry = []): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', $ip, $requestBinding);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solve($challenge, $telemetry);

        return [$storage, $token];
    }

    private function solve(\KiwiCaptcha\Challenge $challenge, array $telemetry = []): string
    {
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;

        return SolutionToken::create($challenge->nonce, $counter, 5000, $telemetry)->encode();
    }

    // ── default configuration: strict single-use ────────────────────────────

    public function testDefaultConfigSameTokenOnANewRequestIsNeverValid(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        // The first, legitimate submission verifies.
        $first = $this->validate($this->engine($verifier), $token);
        self::assertCount(0, $first, 'the first submission of a solved token must validate');

        // A second, distinct request presenting the same token: strictly
        // single-use — a violation, never a pass, whatever the IP.
        $violations = $this->validate($this->engine($verifier, ip: self::OTHER_IP), $token);
        self::assertCount(1, $violations, 'a replayed token on a new request must violate, never validate');
        self::assertSame(KiwiCaptcha::REPLAYED_TOKEN_ERROR, $violations[0]->getCode());

        // Same IP changes nothing: the second request is still a distinct
        // logical operation with no proven identity.
        $sameIp = $this->validate($this->engine($verifier), $token);
        self::assertCount(1, $sameIp, 'a replayed token is refused even from the same IP');
    }

    public function testDefaultConfigExpiredReplayOfAConsumedTokenIsNeverValid(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        self::assertCount(0, $this->validate($this->engine($verifier), $token));

        // Past the signed expiry the cheap phase fails Expired, but the
        // retained consumed state routes the replay through the consumed
        // branch: without a proven operation identity the stored success
        // must still never be handed out.
        $late = new Verifier($storage, now: fn (): int => self::ISSUED_AT + 130);
        $violations = $this->validate($this->engine($late), $token);
        self::assertCount(1, $violations, 'an expired replay of a consumed token must violate, never validate');
        self::assertSame(KiwiCaptcha::REPLAYED_TOKEN_ERROR, $violations[0]->getCode());
    }

    // ── explicit operation id: idempotent retry ─────────────────────────────

    public function testExplicitOperationIdRetryWithSameTokenIsIdempotent(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        $first = $this->validate($this->engine($verifier, operationId: 'signup-123'), $token);
        self::assertCount(0, $first, 'the first submission with an operation id must validate');

        // The same logical operation retries (e.g. a lost response): the
        // stored success replays — even from a different IP.
        $retry = $this->validate($this->engine($verifier, ip: self::OTHER_IP, operationId: 'signup-123'), $token);
        self::assertCount(0, $retry, 'the idempotent retry with the same operation id must replay the stored success');
    }

    public function testExplicitOperationIdRetryWithDifferentTokenIsInvalid(): void
    {
        [$storage, $verifier, $token1] = $this->solvedToken();
        // A second, independent solve consumed under a different operation id.
        [$storage2, $token2] = $this->issuedAndSolved(self::FIRST_IP);
        $verifier2 = new Verifier($storage2, now: fn (): int => self::ISSUED_AT);
        self::assertCount(0, $this->validate($this->engine($verifier2, operationId: 'op-other'), $token2));

        // op signup-123 is funded by token1's fresh verification.
        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123'), $token1));

        // The same operation id presenting a different, already-consumed
        // token: token2's stored identity belongs to op-other, so this is
        // AlreadyConsumed — invalid, never a replay.
        $violations = $this->validate($this->engine($verifier2, operationId: 'signup-123'), $token2);
        self::assertCount(1, $violations, 'the same operation id with a different consumed token must be invalid');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    public function testSameTokenDifferentOperationIdIsInvalid(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123'), $token));

        // A different logical operation presenting the consumed token: the
        // derived identity differs from the stored one — AlreadyConsumed.
        $violations = $this->validate($this->engine($verifier, operationId: 'signup-456'), $token);
        self::assertCount(1, $violations, 'a different operation id presenting the same token must be invalid');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    public function testOperationIdFromThePostedFieldGatesTheReplay(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        $engine1 = $this->engine($verifier, post: ['kiwi_operation_id' => 'signup-123']);
        self::assertCount(0, $this->validate($engine1, $token));

        // Same operation id re-presented through the POST field (the
        // attribute takes precedence; both drive the idempotent retry).
        $engine2 = $this->engine($verifier, ip: self::OTHER_IP, post: ['kiwi_operation_id' => 'signup-123']);
        self::assertCount(0, $this->validate($engine2, $token), 'the POSTed kiwi_operation_id drives the idempotent retry');

        // A different POSTed operation id is a different operation.
        $engine3 = $this->engine($verifier, ip: self::OTHER_IP, post: ['kiwi_operation_id' => 'signup-999']);
        self::assertCount(1, $this->validate($engine3, $token));
    }

    // ── binding authority ────────────────────────────────────────────────────

    private function authorityResolving(string $binding): RequestBindingAuthorityInterface
    {
        return new class ($binding) implements RequestBindingAuthorityInterface {
            public function __construct(private readonly string $binding)
            {
            }

            public function resolve(Request $request, string $scope, ?string $presentedBinding): ?string
            {
                return $this->binding;
            }
        };
    }

    public function testBindingAuthorityReplayWithDifferentBindingIsInvalid(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken(requestBinding: 'auth-txn-1');

        self::assertCount(0, $this->validate($this->engine($verifier, requestBinding: 'hint', authority: $this->authorityResolving('auth-txn-1')), $token));

        // The same token under a different authoritative binding: a
        // different logical operation — invalid, never a replay.
        $violations = $this->validate($this->engine($verifier, requestBinding: 'hint', authority: $this->authorityResolving('auth-txn-2')), $token);
        self::assertCount(1, $violations, 'a replay under a different authoritative binding must be invalid');
        self::assertSame(KiwiCaptcha::INVALID_OR_EXPIRED_ERROR, $violations[0]->getCode());
    }

    public function testBindingAuthoritySameBindingSameOperationIdReplaysValid(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken(requestBinding: 'auth-txn-1');

        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123', requestBinding: 'hint', authority: $this->authorityResolving('auth-txn-1')), $token));

        // Same binding + same operation id: the legitimate idempotent retry.
        $retry = $this->validate($this->engine($verifier, ip: self::OTHER_IP, operationId: 'signup-123', requestBinding: 'hint', authority: $this->authorityResolving('auth-txn-1')), $token);
        self::assertCount(0, $retry, 'same binding + same operation id must replay the stored success');
    }

    // ── the cheap checks are skipped only on the explicit-idempotent path ────

    public function testIdempotentReplaySkipsTheIpCheckOnlyWithAnExplicitOperationId(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123'), $token));

        // IP changed: the idempotent retry still replays the stored success
        // (the committed outcome was durably recorded after the original IP
        // check passed).
        self::assertCount(0, $this->validate($this->engine($verifier, ip: self::OTHER_IP, operationId: 'signup-123'), $token));

        // without the explicit operation id the same IP-changed replay is
        // refused: the skip is exclusive to the proven identity path.
        [$storage2, $verifier2, $token2] = $this->solvedToken();
        self::assertCount(0, $this->validate($this->engine($verifier2), $token2));
        $violations = $this->validate($this->engine($verifier2, ip: self::OTHER_IP), $token2);
        self::assertCount(1, $violations, 'an IP-changed replay without an explicit operation id must be refused');
        self::assertSame(KiwiCaptcha::REPLAYED_TOKEN_ERROR, $violations[0]->getCode());
    }

    public function testIdempotentReplaySkipsTheTtlCheckOnlyWithAnExplicitOperationId(): void
    {
        [$storage, $verifier, $token] = $this->solvedToken();

        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123'), $token));

        // Past the signed expiry: the idempotent retry still replays the
        // committed success (expiry-exempt by the committed-result contract).
        $late = new Verifier($storage, now: fn (): int => self::ISSUED_AT + 130);
        self::assertCount(0, $this->validate($this->engine($late, operationId: 'signup-123'), $token), 'the idempotent retry is expiry-exempt');

        // The same expired replay without the operation id is refused.
        [$storage2, $verifier2, $token2] = $this->solvedToken();
        self::assertCount(0, $this->validate($this->engine($verifier2), $token2));
        $late2 = new Verifier($storage2, now: fn (): int => self::ISSUED_AT + 130);
        $violations = $this->validate($this->engine($late2), $token2);
        self::assertCount(1, $violations, 'an expired replay without an explicit operation id must be refused');
        self::assertSame(KiwiCaptcha::REPLAYED_TOKEN_ERROR, $violations[0]->getCode());
    }

    public function testIdempotentReplaySkipsTheTelemetryCheckOnlyWithAnExplicitOperationId(): void
    {
        // A token carrying human-like telemetry passes the enforced gate;
        // the replay path never re-scores telemetry, so with the explicit
        // operation id the stored success replays even from another IP.
        $storage = new ArrayStorage();
        $issuer = new Issuer(
            new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120),
            $storage,
            now: static fn (): int => self::ISSUED_AT,
        );
        $challenge = $issuer->issue('login', self::FIRST_IP);
        usleep(($challenge->minDurationMs + 10) * 1000);
        $token = $this->solve($challenge, ['v' => 2, 'me' => 14, 'ke' => 3, 'wd' => false]);
        $verifier = new Verifier($storage, now: fn (): int => self::ISSUED_AT);

        self::assertCount(0, $this->validate($this->engine($verifier, operationId: 'signup-123', enforceTelemetry: true), $token));
        self::assertCount(0, $this->validate($this->engine($verifier, ip: self::OTHER_IP, operationId: 'signup-123', enforceTelemetry: true), $token), 'the idempotent replay skips the telemetry re-check');

        // Without the operation id: refused (the telemetry check is never
        // even reached on the replay path — the identity gate refuses).
        $humanTelemetry = ['v' => 2, 'me' => 14, 'ke' => 3, 'wd' => false];
        [$storage2, $verifier2, $token2] = $this->solvedToken(telemetry: $humanTelemetry);
        self::assertCount(0, $this->validate($this->engine($verifier2, enforceTelemetry: true), $token2));
        $violations = $this->validate($this->engine($verifier2, ip: self::OTHER_IP, enforceTelemetry: true), $token2);
        self::assertCount(1, $violations, 'a replay without an explicit operation id must be refused under enforced telemetry');
        self::assertSame(KiwiCaptcha::REPLAYED_TOKEN_ERROR, $violations[0]->getCode());
    }
}
