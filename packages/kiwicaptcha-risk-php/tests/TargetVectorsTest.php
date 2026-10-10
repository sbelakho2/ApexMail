<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Tests;

use KiwiCaptcha\Risk\FormFieldTargetResolver;
use KiwiCaptcha\Risk\RiskIdentityFactory;
use KiwiCaptcha\Risk\RiskKeys;
use KiwiCaptcha\Risk\TargetIdentifierNormalizer;
use PHPUnit\Framework\TestCase;

/**
 * Shared target-identifier vectors (protocol/risk-v1/
 * target-vectors.json): every input runs the versioned normalization
 * pipeline and the target HMAC under the recorded master; the Rust
 * mirror (tests/target_vectors.rs) derives the identical bytes. The
 * corpus pins the collapse families (gmail dot/plus variants,
 * googlemail, provider plus/hyphen tags), the non-folding families
 * (proton plus tags, outlook dots, homoglyphs, accents) and the
 * case-folding boundary (sharp s, dotted capital i).
 */
final class TargetVectorsTest extends TestCase
{
    private function vectorsPath(): string
    {
        $env = getenv('RISK_TARGET_VECTORS_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        return dirname(__DIR__) . '/../../protocol/risk-v1/target-vectors.json';
    }

    /** @return array<string, array<string, string>> note-indexed rows of the corpus */
    private function rows(): array
    {
        $path = $this->vectorsPath();
        self::assertFileExists($path, sprintf('Target vectors file not found at %s (set RISK_TARGET_VECTORS_PATH)', $path));
        $doc = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($doc);
        self::assertNotEmpty($doc['vectors'], 'target vectors must not be empty');
        self::assertSame(TargetIdentifierNormalizer::VERSION, $doc['pipeline_version'], 'the corpus was generated under a different pipeline version');

        $rows = [];
        foreach ($doc['vectors'] as $vector) {
            $rows[$vector['note']] = $vector;
        }

        return $rows;
    }

    public function testEveryVectorMatchesExactly(): void
    {
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster($this->masterKey()));
        $count = 0;
        foreach ($this->rows() as $note => $vector) {
            $normalized = TargetIdentifierNormalizer::normalize($vector['input']);
            self::assertSame(
                $vector['expected_normalized'],
                $normalized,
                sprintf('vector "%s" must normalize exactly (input 0x%s)', $note, bin2hex($vector['input'])),
            );
            self::assertSame(
                $vector['expected_id'],
                $factory->targetId($normalized),
                sprintf('vector "%s" must derive the recorded pseudonym', $note),
            );
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $vector['expected_id']);
            $count++;
        }
        self::assertGreaterThanOrEqual(30, $count, 'the vector families must stay comprehensive');
    }

    private function masterKey(): string
    {
        $doc = json_decode((string) file_get_contents($this->vectorsPath()), true);

        return $doc['master_key'];
    }

    public function testCollapseFamiliesShareOnePseudonym(): void
    {
        $rows = $this->rows();
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster($this->masterKey()));
        $id = fn (string $note): string => $factory->targetId(TargetIdentifierNormalizer::normalize($rows[$note]['input']));

        // a..b@gmail.com, ab+x@gmail.com and the uppercase domain spelling
        // all collapse onto ab@gmail.com.
        $gmail = $id('gmail plain anchor');
        self::assertSame($gmail, $id('gmail dots collapse'));
        self::assertSame($gmail, $id('gmail plus and dots collapse'));
        self::assertSame($gmail, $id('gmail domain case folds'));

        // googlemail.com rewrites to gmail.com before the local rules.
        self::assertSame(
            $id('googlemail rewrites to gmail'),
            $factory->targetId('abx@gmail.com'),
        );

        // Provider plus/hyphen tags collapse to the bare local part.
        self::assertSame($id('outlook plus tag stripped'), $factory->targetId('first.last@outlook.com'));
        self::assertSame($id('live plus tag stripped'), $factory->targetId('a.b.c@live.com'));
        self::assertSame($id('hotmail plus tag stripped'), $factory->targetId('x.y@hotmail.com'));
        self::assertSame($id('icloud plus tag stripped'), $factory->targetId('name@icloud.com'));
        self::assertSame($id('yahoo minus tag stripped'), $id('yahoo plain anchor'));

        // `NFKC` fullwidth and compatibility spellings of one identifier.
        self::assertSame(
            $factory->targetId('example'),
            $id('nfkc fullwidth letters'),
        );
    }

    public function testNonFoldingFamiliesStayDistinct(): void
    {
        $rows = $this->rows();
        $factory = new RiskIdentityFactory(RiskKeys::fromMaster($this->masterKey()));
        $id = fn (string $note): string => $factory->targetId(TargetIdentifierNormalizer::normalize($rows[$note]['input']));

        // Providers outside the table keep their local part: a plus tag
        // at proton.me is a different mailbox, and outlook dots are
        // significant.
        self::assertNotSame($id('proton plus tag stays'), $id('proton plain distinct pair'));
        self::assertNotSame($id('outlook dots stay'), $id('outlook dots distinct pair'));
        self::assertNotSame($id('yahoo dots stay'), $id('yahoo plain anchor'));

        // A cyrillic a and a latin a differ in code points with no `NFKC`
        // fold between them: legitimately different targets. Stripping
        // an accent to its base letter is the same over-normalization
        // class and must stay distinct too.
        self::assertNotSame($id('cyrillic a homoglyph stays'), $id('latin a anchor distinct'));
        self::assertNotSame($id('accent stays'), $id('accent stripped distinct pair'));

        // Embedded whitespace is part of the identifier; only the edges
        // are trimmed.
        self::assertNotSame($id('embedded space stays'), $id('embedded distinct pair'));

        // Case folding keeps its documented boundary: sharp s and the
        // dotted capital i never fold to their letter-sequence look
        // alikes.
        self::assertNotSame($id('fold sharp s stays'), $id('fold sharp s boundary distinct'));
        self::assertNotSame($id('fold turkish capital dotted i'), $id('fold turkish plain i distinct'));
    }

    public function testResolverReadsThePerScopeFieldAndSkipsUnconfiguredScopes(): void
    {
        $resolver = new FormFieldTargetResolver([1 => 'username', 2 => 'email']);
        $fields = ['username' => 'Alice', 'email' => 'a.b@gmail.com', 'password' => 'hunter2'];

        self::assertSame('Alice', $resolver->resolve(1, $fields));
        self::assertSame('a.b@gmail.com', $resolver->resolve(2, $fields));
        // A scope without a configured field carries no target dimension.
        self::assertNull($resolver->resolve(3, $fields));
        // An absent or empty field resolves null.
        self::assertNull($resolver->resolve(1, ['email' => 'x']));
        self::assertNull($resolver->resolve(1, ['username' => '']));

        $this->expectException(\InvalidArgumentException::class);
        new FormFieldTargetResolver([1 => '']);
    }
}
