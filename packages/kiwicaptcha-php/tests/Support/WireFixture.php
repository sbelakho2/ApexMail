<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests\Support;

/**
 * Wire-valid shapes for hand-built storage fixtures.
 *
 * The record decode boundary (ChallengeRecord::fromArray, the twin of
 * the Rust serde reconstruction) applies the full structural contract.
 * The nonce is the 44-char standard-base64 encoding of 32 bytes. The
 * salt is the 24-char encoding of 16 bytes. The prefix is the derived
 * `challenge|salt|`. Storage-contract fixtures keep their readable
 * logical labels. The labels are hashed into the wire nonce shape so a
 * fixture round-trips exactly like a real issued record.
 */
final class WireFixture
{
    /** The canonical 16-byte fixture salt (24-char standard base64). */
    public const SALT = 'c2FsdHNhbHRzYWx0c2FsdA==';

    public static function nonce(string $logical): string
    {
        return base64_encode(hash('sha256', 'kiwi-fixture-nonce/'.$logical, true));
    }

    public static function prefix(string $challenge): string
    {
        return $challenge.'|'.self::SALT.'|';
    }
}
