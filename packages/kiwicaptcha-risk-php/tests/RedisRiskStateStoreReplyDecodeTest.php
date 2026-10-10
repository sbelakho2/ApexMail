<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;
use KiwiCaptcha\Risk\Storage\RiskStoreException;
use PHPUnit\Framework\TestCase;

/**
 * Hermetic tests of the RedisRiskStateStore reply-slot decoders
 * scriptInteger and scriptTag: no Redis connection is required, the
 * private static decoders are pinned through reflection. They are the
 * fail-closed boundary between the Lua reply and the typed
 * ObservationReply/AssessV2Reply objects — a malformed or shifted reply
 * must raise RiskStoreException, never coerce into a plausible value.
 */
final class RedisRiskStateStoreReplyDecodeTest extends TestCase
{
    /**
     * Reflection can invoke the private static decoder directly: members
     * are accessible by default since PHP 8.1 (this package's floor), so
     * no setAccessible() call is needed (it is deprecated in 8.5).
     *
     * @throws RiskStoreException
     */
    private static function scriptInteger(mixed $value, string $slot = 'integer slot'): int
    {
        return (new \ReflectionMethod(RedisRiskStateStore::class, 'scriptInteger'))->invoke(null, $value, $slot);
    }

    /** @throws RiskStoreException */
    private static function scriptTag(mixed $value, string $slot = 'tag slot'): ?string
    {
        return (new \ReflectionMethod(RedisRiskStateStore::class, 'scriptTag'))->invoke(null, $value, $slot);
    }

    public function testScriptIntegerDecodesIntsAndParseableIntegerStrings(): void
    {
        self::assertSame(7, self::scriptInteger(7));
        self::assertSame(42, self::scriptInteger('42'));
        self::assertSame(43, self::scriptInteger('+43'), 'the wire may carry an explicit plus sign');
    }

    public function testScriptIntegerFailsClosedOnEveryOtherReplyType(): void
    {
        // Nil replies, arrays, non-numeric strings, booleans and floats are
        // all malformed in an integer slot; coercing any of them to 0 would
        // hide a shifted reply.
        foreach ([null, [1], 'abc', true, 1.5] as $value) {
            try {
                self::scriptInteger($value, 'shifted slot');
                self::fail(sprintf('scriptInteger must refuse %s', get_debug_type($value)));
            } catch (RiskStoreException $e) {
                self::assertStringContainsString('shifted slot', $e->getMessage());
                self::assertStringContainsString('non-integer', $e->getMessage());
            }
        }
    }

    public function testScriptTagDecodesStringsAndNormalizesNil(): void
    {
        self::assertNull(self::scriptTag(null), 'the Redis Nil reply decodes to null');
        self::assertNull(self::scriptTag(''), 'an empty tag is the normalization of "no recorded tag"');
        self::assertSame('aa', self::scriptTag('aa'));
    }

    public function testScriptTagFailsClosedOnEveryOtherReplyType(): void
    {
        foreach ([5, [1], true] as $value) {
            try {
                self::scriptTag($value, 'shifted tag slot');
                self::fail(sprintf('scriptTag must refuse %s', get_debug_type($value)));
            } catch (RiskStoreException $e) {
                self::assertStringContainsString('shifted tag slot', $e->getMessage());
                self::assertStringContainsString('non-string', $e->getMessage());
            }
        }
    }

    public function testReplyPathsDoNotCoerceSlotsWithIntCasts(): void
    {
        // Source-level pin on the exact reply-decoding method bodies: every
        // slot must flow through scriptInteger()/scriptTag(), never through
        // an `(int) $result[...]` coercion. Reflection names the bodies, so
        // the assertion cannot silently point at the wrong code.
        foreach (['signalVectorFromReply', 'observeWithReply', 'assessV2WithReply'] as $name) {
            $body = self::methodBody($name);
            self::assertStringNotContainsString(
                '(int) $result[',
                $body,
                sprintf('%s() must decode reply slots through scriptInteger(), not an (int) cast', $name)
            );
        }
        // And the specialized decoders are actually wired into each body (a
        // future refactor cannot satisfy the assertion above by dropping
        // slot decoding entirely).
        self::assertStringContainsString('self::scriptInteger($result[0]', self::methodBody('signalVectorFromReply'));
        self::assertStringContainsString('self::scriptInteger($result[13]', self::methodBody('observeWithReply'));
        self::assertStringContainsString('self::scriptTag($result[16]', self::methodBody('assessV2WithReply'));
    }

    /** The exact source text of one RedisRiskStateStore method body. */
    private static function methodBody(string $name): string
    {
        $method = new \ReflectionMethod(RedisRiskStateStore::class, $name);
        $file = $method->getFileName();
        self::assertIsString($file);
        $lines = file($file);
        self::assertIsArray($lines);

        return implode('', array_slice(
            $lines,
            $method->getStartLine() - 1,
            $method->getEndLine() - $method->getStartLine() + 1
        ));
    }
}
