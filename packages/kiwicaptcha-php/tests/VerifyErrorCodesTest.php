<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\VerifyError;
use PHPUnit\Framework\TestCase;

/**
 * The machine-readable contract of the error codes: every case value is
 * a stable snake_case token (^[a-z0-9_]+$) that logs, metrics and
 * cross-service consumers can switch on without parsing prose, and
 * every case carries a non-empty human-readable description.
 */
final class VerifyErrorCodesTest extends TestCase
{
    public function testEveryCodeIsMachineReadableSnakeCase(): void
    {
        foreach (VerifyError::cases() as $error) {
            self::assertMatchesRegularExpression(
                '/^[a-z0-9_]+$/',
                $error->value,
                sprintf('%s::%s value must be a snake_case machine code', VerifyError::class, $error->name),
            );
        }
    }

    public function testEveryCodeIsUnique(): void
    {
        $values = array_map(static fn (VerifyError $e): string => $e->value, VerifyError::cases());
        self::assertSame(\count($values), \count(array_unique($values)), 'error codes must not collide');
    }

    public function testEveryDescriptionIsNonEmptyProse(): void
    {
        foreach (VerifyError::cases() as $error) {
            $description = $error->description();
            self::assertNotSame('', $description, sprintf('%s::%s must carry a description', VerifyError::class, $error->name));
            self::assertNotSame($error->value, $description, sprintf('%s::%s description must be prose, not the code itself', VerifyError::class, $error->name));
            self::assertMatchesRegularExpression('/[a-z] [a-z]/', $description, sprintf('%s::%s description must be a prose sentence', VerifyError::class, $error->name));
        }
    }

    public function testOutcomeCodeReturnsTheMachineCode(): void
    {
        foreach (VerifyError::cases() as $error) {
            self::assertSame($error->value, \KiwiCaptcha\VerifyOutcome::invalid($error)->code());
        }
    }
}
