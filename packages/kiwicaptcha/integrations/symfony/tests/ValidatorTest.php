<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptcha;
use BelConsulting\KiwiCaptchaBundle\Validator\Constraints\KiwiCaptchaValidator;
use KiwiCaptcha\Config;
use KiwiCaptcha\Issuer;
use KiwiCaptcha\Storage\ArrayStorage;
use KiwiCaptcha\Verifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Validator\ConstraintValidatorFactory;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Component\Validator\Mapping\ClassMetadata;
use Symfony\Component\Validator\Validation;

/**
 * Validator constraint test: the KiwiCaptcha constraint verifies tokens
 * locally (never via an external HTTP call). Tested through the full
 * Symfony validation pipeline, exactly as a form submission would be.
 */
final class ValidatorTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';

    private Issuer $issuer;
    private Verifier $verifier;

    protected function setUp(): void
    {
        $storage = new ArrayStorage();
        $this->issuer = new Issuer(new Config(secretKey: self::SECRET, targetBits: 8), $storage);
        $this->verifier = new Verifier($storage);
    }

    /**
     * @return array{0: \Symfony\Component\Validator\Validator\ValidatorInterface, 1: RequestStack}
     */
    private function buildEngine(): array
    {
        $stack = new RequestStack();
        $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

        $validator = new KiwiCaptchaValidator($this->verifier, $stack, self::SECRET);
        $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);

        return [Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator(), $stack];
    }

    private function solveToken(string $prefix, string $salt, int $targetBits, string $nonce): string
    {
        $counter = 0;
        do {
            $h = hash('sha256', $prefix.$counter.base64_decode($salt, true), true);
            $counter++;
        } while (Verifier::leadingZeroBits($h) < $targetBits);
        --$counter;

        return \KiwiCaptcha\SolutionToken::create($nonce, $counter, 5000, [])->encode();
    }

    private function validate(object $object, array $metadata): ConstraintViolationListInterface
    {
        [$engine] = $this->buildEngine();
        $meta = $engine->getMetadataFor($object::class);
        foreach ($metadata as $property => $constraints) {
            $meta->addPropertyConstraint($property, ...$constraints);
        }

        return $engine->validate($object);
    }

    public function testValidTokenPasses(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        // The core enforces the minimum solve duration with a server-measured
        // clock; wait out the floor before verifying.
        usleep(($challenge->minDurationMs + 10) * 1000);
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha(['scope' => 'login'])]]);

        self::assertCount(0, $violations);
    }

    public function testWrongScopeFails(): void
    {
        $challenge = $this->issuer->issue('login', '198.51.100.7');
        $dto = new class {
            public ?string $captcha = null;
        };
        $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha(['scope' => 'signup'])]]);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
    }

    public function testEmptyTokenFails(): void
    {
        $dto = new class {
            public ?string $captcha = '';
        };

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha()]]);

        self::assertCount(1, $violations);
    }

    public function testGarbageTokenFailsWithoutError(): void
    {
        $dto = new class {
            public ?string $captcha = 'not-a-token';
        };

        $violations = $this->validate($dto, ['captcha' => [new KiwiCaptcha()]]);

        self::assertCount(1, $violations);
        self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
    }

    public function testArgon2CapacityExhaustionFailsClosedAsViolation(): void
    {
        \BelConsulting\KiwiCaptchaBundle\Security\Argon2Semaphore::resetForTests();
        \BelConsulting\KiwiCaptchaBundle\Security\Argon2Semaphore::setMaxWaitSecsForTests(0.05);
        try {
            $challenge = $this->issuer->issue('login', '198.51.100.7');
            usleep(($challenge->minDurationMs + 10) * 1000);
            $dto = new class {
                public ?string $captcha = null;
            };
            $dto->captcha = $this->solveToken($challenge->prefix, $challenge->salt, $challenge->targetBits, $challenge->nonce);

            // Saturate the cap so the throttled verifier is refused.
            self::assertTrue(\BelConsulting\KiwiCaptchaBundle\Security\Argon2Semaphore::acquire(1));

            $stack = new RequestStack();
            $stack->push(Request::create('/', 'POST', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));

            $validator = new KiwiCaptchaValidator(
                new \BelConsulting\KiwiCaptchaBundle\Security\ThrottledVerifier($this->verifier, 1),
                $stack,
                self::SECRET,
            );
            $factory = new ConstraintValidatorFactory([KiwiCaptchaValidator::class => $validator]);
            $engine = Validation::createValidatorBuilder()->setConstraintValidatorFactory($factory)->getValidator();

            $meta = $engine->getMetadataFor($dto::class);
            $meta->addPropertyConstraint('captcha', new KiwiCaptcha(['scope' => 'login']));

            $violations = $engine->validate($dto);

            self::assertCount(1, $violations);
            self::assertSame(KiwiCaptcha::NOT_SOLVED_ERROR, $violations[0]->getCode());
        } finally {
            \BelConsulting\KiwiCaptchaBundle\Security\Argon2Semaphore::resetForTests();
        }
    }
}
