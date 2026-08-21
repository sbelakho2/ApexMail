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
 * Asymmetric result receipts: the result verification is central-only
 * (the HMAC secret never leaves the server — no third party can re-derive
 * a result). The optional Ed25519 receipt signer exports valid
 * verification results as {jti, tenant, action, request_binding,
 * issued_at, expires_at, issuer} receipts, signed from the consumed
 * record and verified with the public key (never the private seed).
 * Signature verification alone is not sufficient for single-use actions:
 * the integrator must atomically record the jti (verify_and_consume).
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
     * validator, returning [validator, violations, nonce].
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
        // The receipt is signed from the consumed record, so
        // the validator needs the challenge storage wired — exactly as the
        // extension wires it.
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, receiptSigner: $signer, storage: $storage);
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

        // The payload carries the full replay-critical set from the consumed
        // record: jti, tenant (scope), action (PoW algorithm),
        // request_binding, issued_at / expires_at (epoch ms), issuer.
        $receipt = json_decode($payload, true);
        self::assertSame($nonce, $receipt['jti'], 'the receipt jti is the verified challenge nonce');
        self::assertSame('login', $receipt['tenant'], 'the receipt tenant is the record scope');
        self::assertSame('sha256', $receipt['action'], 'the receipt action is the record PoW algorithm');
        self::assertNull($receipt['request_binding'], 'an unbound record carries a null request_binding');
        self::assertIsInt($receipt['issued_at']);
        self::assertIsInt($receipt['expires_at']);
        self::assertSame(120, $receipt['expires_at'] - $receipt['issued_at'], 'expires_at = issued_at + the challenge lifetime (epoch seconds, the record wire unit)');
        self::assertLessThanOrEqual((int) time(), $receipt['issued_at']);
        self::assertArrayHasKey('issuer', $receipt, 'the receipt must carry the issuer field (null when unset)');
        self::assertNull($receipt['issuer']);

        // customers verify with the public key — never the private seed.
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
        $publicKey = base64_decode($signer->publicKeyBase64(), true);

        // A tampered JTI — the single-use replay id — must fail
        // verification (a swapped jti would otherwise let an integrator
        // key the idempotency on an attacker-chosen value).
        $tampered = json_decode($payload, true);
        $tampered['jti'] = 'attacker-chosen-nonce';
        $tamperedPayload = (string) json_encode($tampered);
        self::assertFalse(
            sodium_crypto_sign_verify_detached(base64_decode($signature, true), $tamperedPayload, $publicKey),
            'a receipt with a tampered jti must fail public-key verification'
        );

        // Every other replay-critical field is equally protected: a flipped
        // tenant, an extended expires_at (receipt freshness forgery), a
        // swapped request_binding and a changed issuer all fail.
        foreach ([
            'tenant' => 'signup',
            'expires_at' => (json_decode($payload, true)['expires_at'] ?? 0) + 3_600_000,
            'request_binding' => 'different-txn',
            'issuer' => 'prod',
        ] as $field => $value) {
            $tampered = json_decode($payload, true);
            $tampered[$field] = $value;
            self::assertFalse(
                sodium_crypto_sign_verify_detached(base64_decode($signature, true), (string) json_encode($tampered), $publicKey),
                sprintf('a tampered "%s" field must fail public-key verification', $field)
            );
        }

        // A tampered signature fails too (valid length, altered bytes).
        $badSignature = base64_encode(str_repeat("\x01", 64));
        self::assertFalse(
            sodium_crypto_sign_verify_detached(base64_decode($badSignature, true), $payload, $publicKey)
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
        // The empty string is treated as disabled (same as null), never an
        // error.
        self::assertFalse((new ResultReceiptSigner(''))->enabled());
    }

    public function testDisabledSignerSignsNothing(): void
    {
        $signer = new ResultReceiptSigner();
        self::assertFalse($signer->enabled());
        self::assertNull($signer->sign($this->issuedRecord()), 'a disabled signer signs no record');
    }

    /**
     * A real minted record (issue + store) to exercise sign() with — the
     * receipt payload is built from the record's own fields.
     */
    private function issuedRecord(): \KiwiCaptcha\ChallengeRecord
    {
        $storage = new ArrayStorage();
        $issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8, ttlSecs: 120), $storage);
        $challenge = $issuer->issue('login', '198.51.100.7', 'txn-42');
        $record = $storage->find($challenge->nonce);
        self::assertNotNull($record);

        return $record;
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
        $validator = new KiwiCaptchaValidator($verifier, $stack, self::SECRET, receiptSigner: $signer, storage: $storage);
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
        self::assertSame('txn-42', $receipt['request_binding'], 'the receipt carries the SIGNED transaction binding');
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
