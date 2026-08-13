<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ChallengeRecord;
use KiwiCaptcha\MalformedRecordException;
use PHPUnit\Framework\TestCase;

/**
 * Differential malicious-record parsing (audit #56): the SAME deterministic
 * fuzz corpus (protocol/risk-v1/fuzz-corpus.json — 1000 mutations of a
 * valid record, seed 0x5EED0001) must be accepted (and rejected)
 * IDENTICALLY by the PHP and Rust parsers. The Rust side pins 659 accepted
 * records; fromArray is the strict serde mirror, so it must land on the
 * SAME 659.
 */
final class FuzzCorpusParityTest extends TestCase
{
    public function testCorpusAcceptanceMatchesRustParser(): void
    {
        $path = \dirname(__DIR__).'/../../protocol/risk-v1/fuzz-corpus.json';

        if (!is_file($path)) {
            self::markTestSkipped('fuzz-corpus.json not present (monorepo layout expected at protocol/risk-v1/)');
        }

        $corpus = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($corpus);
        self::assertCount(1000, $corpus, 'the corpus must be pinned to 1000 deterministic mutations');

        $accepted = 0;
        $rejected = 0;
        foreach ($corpus as $entry) {
            if (!\is_array($entry)) {
                $rejected++;
                continue;
            }
            try {
                ChallengeRecord::fromArray($entry);
                $accepted++;
            } catch (MalformedRecordException) {
                $rejected++;
            }
        }

        self::assertSame(659, $accepted, 'PHP fromArray must accept the SAME 659 records the Rust serde parser accepts');
        self::assertSame(1000 - 659, $rejected);
    }
}
