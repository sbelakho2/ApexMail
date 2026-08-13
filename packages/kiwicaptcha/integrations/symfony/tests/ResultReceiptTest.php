<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\ResultReceiptSigner;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\JsonRequest;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\Validation;

/**
 * Asymmetric result receipts (audit #80): the result verification is
 * CENTRAL-ONLY (the HMAC secret never leaves the server — no third party can
 * re-derive a result). The OPTIONAL Ed25519 receipt signer exports VALID
 * verification results as {jti, scope, binding, outcome, issued_at_ms}
 * receipts that customers verify with the PUBLIC key — never the private
 * seed.
 */
final class ResultReceiptTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private function seed(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Issue + solve a sha256 challenge (fast 8-bit) and run it through the
     * validator, returning [validator, violations].
     */
    private function verifyThroughValidator(?ResultReceiptSigner $signer): array
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);

        $challenge = $issuer->issue('login', '198.51.100.7');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, receiptSigner: $signer);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        return [$validator, $engineValidator->validate($dto), $challenge->nonce];
    }

    public function testValidVerificationProducesAReceiptVerifiableWithThePublicKey(): void
    {
        $signer = new ResultReceiptSigner($this->seed());
        [$validator, $violations, $nonce] = $this->verifyThroughValidator($signer);
        self::assertCount(0, $violations);

        $payload = $validator->verifiedReceiptPayload();
        $signature = $validator->verifiedReceiptSignature();
        self::assertNotNull($payload, 'a valid verification must produce a signed receipt');
        self::assertNotNull($signature);

        // The payload is exactly the documented receipt document.
        $receipt = json_decode($payload, true);
        self::assertSame($nonce, $receipt['jti'], 'the receipt jti is the verified challenge nonce');
        self::assertSame('login', $receipt['scope']);
        self::assertNull($receipt['binding'], 'an unbound record carries a null binding');
        self::assertSame('valid', $receipt['outcome']);
        self::assertIsInt($receipt['issued_at_ms']);
        self::assertLessThanOrEqual((int) round(microtime(true) * 1000), $receipt['issued_at_ms']);

        // CUSTOMERS verify with the PUBLIC key — never the private seed.
        $publicKey = base64_decode($signer->publicKeyBase64(), true);
        self::assertNotFalse($publicKey);
        self::assertTrue(
            sodium_crypto_sign_verify_detached(base64_decode($signature, true), $payload, $publicKey),
            'the receipt signature must verify against the PUBLIC key'
        );
        // The seed itself is NOT the public key (the private key must never
        // be used for verification).
        self::assertNotSame(
            base64_decode($signer->publicKeyBase64(), true),
            base64_decode($this->seedFor($signer), true),
            'the public key must differ from the private seed'
        );
    }

    public function testTamperedReceiptFailsVerification(): void
    {
        $signer = new ResultReceiptSigner($this->seed());
        [$validator] = $this->verifyThroughValidator($signer);

        $payload = (string) $validator->verifiedReceiptPayload();
        $signature = (string) $validator->verifiedReceiptSignature();

        // Flip one field (scope) — the signature must no longer verify.
        $tampered = json_decode($payload, true);
        $tampered['scope'] = 'signup';
        $tamperedPayload = (string) json_encode($tampered);

        self::assertFalse(
            sodium_crypto_sign_verify_detached(base64_decode($signature, true), $tamperedPayload, base64_decode($signer->publicKeyBase64(), true)),
            'a tampered receipt payload must fail public-key verification'
        );

        // A tampered SIGNATURE fails too (valid length, altered bytes).
        $badSignature = base64_encode(str_repeat("\x01", 64));
        self::assertFalse(
            sodium_crypto_sign_verify_detached(base64_decode($badSignature, true), $payload, base64_decode($signer->publicKeyBase64(), true))
        );
    }

    public function testNoSigningKeyMeansNoReceipt(): void
    {
        [$validator, $violations] = $this->verifyThroughValidator(null);
        self::assertCount(0, $violations, 'the verification itself is unaffected without a signing key');
        self::assertNull($validator->verifiedReceiptPayload());
        self::assertNull($validator->verifiedReceiptSignature());
    }

    public function testFailedVerificationNeverProducesAReceipt(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $signer = new ResultReceiptSigner($this->seed());

        $stack = new RequestStack();
        $stack->push(JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, receiptSigner: $signer);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = 'garbage-not-a-token';
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(1, $violations);
        self::assertNull($validator->verifiedReceiptPayload(), 'a failed verification must never produce a receipt');
        self::assertNull($validator->verifiedReceiptSignature());
    }

    public function testInvalidSeedIsRefused(): void
    {
        foreach ([base64_encode(random_bytes(16)), base64_encode(random_bytes(64)), 'not-base64!!'] as $bad) {
            try {
                new ResultReceiptSigner($bad);
                self::fail('a seed that is not a base64 32-byte Ed25519 seed must be refused');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        // The empty string is treated as DISABLED (same as null), never an
        // error.
        self::assertFalse((new ResultReceiptSigner(''))->enabled());
    }

    public function testDisabledSignerSignsNothing(): void
    {
        $signer = new ResultReceiptSigner();
        self::assertFalse($signer->enabled());
        self::assertNull($signer->sign('jti-1', 'login', null, 123));
    }

    public function testBoundChallengeReceiptCarriesTheBinding(): void
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $verifier = new Verifier($storage);
        $signer = new ResultReceiptSigner($this->seed());

        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-42');
        usleep(((int) $challenge->minDurationMs + 10) * 1000);
        $saltBytes = base64_decode($challenge->salt, true);
        $counter = 0;
        do {
            $hash = hash('sha256', $challenge->prefix.$counter.$saltBytes, true);
            $counter++;
        } while (Verifier::leadingZeroBits($hash) < $challenge->targetBits);
        --$counter;
        $token = \KiwiCaptcha\SolutionToken::create($challenge->nonce, $counter, 5000, [])->encode();

        $stack = new RequestStack();
        $request = JsonRequest::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        $request->request->set('kiwi_request_binding', 'txn-42');
        $stack->push($request);
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, receiptSigner: $signer);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
        $engineValidator = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $token;
        $meta = $engineValidator->getMetadataFor($dto::class);
        $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

        $violations = $engineValidator->validate($dto);
        self::assertCount(0, $violations);
        $receipt = json_decode((string) $validator->verifiedReceiptPayload(), true);
        self::assertSame('txn-42', $receipt['binding'], 'the receipt carries the SIGNED transaction binding');
    }

    private function seedFor(ResultReceiptSigner $signer): string
    {
        // The private seed is deliberately NOT exposed by the signer — this
        // helper exists only to prove the public key differs from it in the
        // test above; production never touches the private key for
        // verification.
        $refl = new \ReflectionProperty(ResultReceiptSigner::class, 'seed');

        return (string) $refl->getValue($signer);
    }
}
