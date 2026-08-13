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
            } catch (\Throwable $e) {
                // Audit #115: fromArray is a documented-exception-only parse
                // path — every corpus entry must end in either a record or
                // MalformedRecordException. A TypeError/Error/ValueError
                // leaking out is a parser bug (e.g. an unchecked type cast
                // or an int overflow in a range comparison), not a rejection.
                self::fail(sprintf(
                    'unexpected %s from fromArray for corpus entry: %s',
                    $e::class,
                    $e->getMessage(),
                ));
            }
        }

        self::assertSame(659, $accepted, 'PHP fromArray must accept the SAME 659 records the Rust serde parser accepts');
        self::assertSame(1000 - 659, $rejected);
    }
}
