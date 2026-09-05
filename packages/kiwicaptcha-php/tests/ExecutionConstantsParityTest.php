<?php

declare(strict_types=1);

namespace KiwiCaptcha\Tests;

use KiwiCaptcha\ExecutionChallengeGenerator;
use PHPUnit\Framework\TestCase;

/**
 * ExecutionChallengeV1 register parity: every constant of the wire
 * register in protocol/execution-v1.json must equal the PHP core's
 * ExecutionChallengeGenerator constants, and the manifest must be
 * internally coherent (sequential opcode numbers, agreeing sizes).
 * The manifest is the canonical table shared by the PHP, Rust and
 * interpreter registers; the Rust mirror of this test pins the same
 * file in execution.rs, and the CI lane tools/ci/protocol-manifest-check.sh
 * re-checks every pair from the raw sources.
 */
final class ExecutionConstantsParityTest extends TestCase
{
    public function testManifestMatchesTheGeneratorRegister(): void
    {
        $path = \dirname(__DIR__).'/../../protocol/execution-v1.json';
        if (!is_file($path)) {
            self::markTestSkipped('execution-v1.json not present (repo layout expected at protocol/)');
        }
        $manifest = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($manifest);

        self::assertSame('kiwicaptcha.execution-v1/1', $manifest['$schema'], 'the manifest declares the execution-v1 schema id');
        self::assertSame(ExecutionChallengeGenerator::FORMAT_VERSION, $manifest['format_version']);
        self::assertSame(ExecutionChallengeGenerator::MAX_EXECUTION_VERSION, $manifest['max_execution_version']);
        self::assertSame(ExecutionChallengeGenerator::OP_COUNT, $manifest['opcode_count']);

        $opcodes = $manifest['opcodes'];
        self::assertIsArray($opcodes);
        self::assertCount(ExecutionChallengeGenerator::OP_COUNT, $opcodes, 'the manifest opcode map must hold every opcode');
        $seen = [];
        foreach ($opcodes as $name => $number) {
            self::assertIsString($name);
            self::assertSame(
                \constant(ExecutionChallengeGenerator::class.'::OP_'.$name),
                $number,
                sprintf('manifest opcode %s must equal the generator constant OP_%s', $name, $name),
            );
            self::assertNotContains($number, $seen, sprintf('opcode %s repeats the number %d', $name, $number));
            $seen[] = $number;
        }
        sort($seen);
        self::assertSame(range(0, ExecutionChallengeGenerator::OP_COUNT - 1), $seen, 'the manifest opcode numbers must be sequential 0..N-1');

        $traceNames = $manifest['trace_names'];
        self::assertIsArray($traceNames);
        self::assertCount(ExecutionChallengeGenerator::OP_COUNT, $traceNames, 'the manifest trace-name list must hold one name per opcode');
        $generatorTraceNames = (new \ReflectionClass(ExecutionChallengeGenerator::class))
            ->getReflectionConstant('TRACE_NAMES')
            ->getValue();
        self::assertSame($generatorTraceNames, $traceNames, 'the manifest trace-name list must equal the generator TRACE_NAMES list');
    }
}
