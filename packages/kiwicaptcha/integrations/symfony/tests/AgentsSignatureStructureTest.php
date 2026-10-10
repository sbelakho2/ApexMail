<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentDefinition;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentNonceStore;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentPriceTier;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentRegistry;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\AgentSignatureVerifier;
use BelConsulting\KiwiCaptchaBundle\Security\Agents\StructuredFieldsSubsetParser;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\AgentSigner;
use BelConsulting\KiwiCaptchaBundle\Tests\Fixtures\FakePredisClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The RFC 9421 structure of the verified-agents plane.
 *
 * Vector provenance, honestly labeled: these are deterministic
 * self-vectors (the seed derivation and the hand-written expected
 * base strings live in this file and in the AgentSigner fixture),
 * not the published RFC 9421 Appendix B byte vectors. The RFC's
 * appendix vectors are Ed25519, but their exact key and signature
 * bytes are not extractable from local knowledge with byte
 * fidelity, so the grammar is pinned instead. Every signature base
 * below is a hand-written string asserting the §2.3 line grammar,
 * and the Ed25519 round trips run through sodium against the same
 * base construction.
 */
final class AgentsSignatureStructureTest extends TestCase
{
    private const KEY_ID = 'acme-bot-2026q4';

    protected function setUp(): void
    {
        if (!\function_exists('sodium_crypto_sign_verify_detached')) {
            self::markTestSkipped('ext-sodium is required');
        }
    }

    /**
     * The signature base of a body-bearing request, asserted against
     * a hand-written string per RFC 9421 §2.3. One line per covered
     * component (quoted id, one space, the value), the RFC 9530
     * content-digest value verbatim, and the final
     * @signature-params line carrying the serialized parameters in
     * their original order.
     */
    public function testSignatureBaseMatchesTheHandWrittenRfcGrammarWithBody(): void
    {
        $body = '{"scope":"login"}';
        $digest = AgentSigner::contentDigest($body);
        $parameters = ['created' => 1770000000, 'expires' => 1770000300, 'nonce' => 'n-abc_123', 'keyid' => self::KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
        $header = 'sig1=("@method" "@target-uri" "content-digest" "content-length");created=1770000000;expires=1770000300;nonce="n-abc_123";keyid="'.self::KEY_ID.'";alg="ed25519";tag="kiwi-agents-v1"';

        $input = (new StructuredFieldsSubsetParser())->parseSignatureInput($header);
        $request = self::bodyRequest($body, $digest, ['HTTP_SIGNATURE_INPUT' => $header]);

        $expected = ''
            .'"@method" POST'."\n"
            .'"@target-uri" http://localhost/kiwi/challenge'."\n"
            .'"content-digest" '.$digest."\n"
            .'"content-length" '.\strlen($body)."\n"
            .'"@signature-params" ("@method" "@target-uri" "content-digest" "content-length");created=1770000000;expires=1770000300;nonce="n-abc_123";keyid="'.self::KEY_ID.'";alg="ed25519";tag="kiwi-agents-v1"'."\n";
        self::assertSame($expected, AgentSigner::signatureBase(
            ['@method', '@target-uri', 'content-digest', 'content-length'],
            $parameters,
            ['@method' => 'POST', '@target-uri' => 'http://localhost/kiwi/challenge', 'content-digest' => $digest, 'content-length' => (string) \strlen($body)],
        ));
        $verifier = self::verifier(new FakePredisClient());
        self::assertSame($expected, $verifier->signatureBase($request, $input, $body));
    }

    /**
     * The signature base of a bodyless request: no content-length
     * line, and the content-digest of the empty body. The digest is
     * required even when nothing is uploaded. The parameter
     * order of the input is preserved in the re-serialization. A
     * reordering verifier would rebuild a different base and reject
     * every signature.
     */
    public function testSignatureBasePreservesParameterOrderWithoutBody(): void
    {
        $digest = AgentSigner::contentDigest('');
        $header = 'sig1=("@method" "@target-uri" "content-digest");tag="kiwi-agents-v1";nonce="zz";keyid="k";alg="ed25519";created=1770000000;expires=1770000300';
        $input = (new StructuredFieldsSubsetParser())->parseSignatureInput($header);
        $request = self::bodyRequest('', $digest, ['HTTP_SIGNATURE_INPUT' => $header]);

        $expected = ''
            .'"@method" POST'."\n"
            .'"@target-uri" http://localhost/kiwi/challenge'."\n"
            .'"content-digest" '.$digest."\n"
            .'"@signature-params" ("@method" "@target-uri" "content-digest");tag="kiwi-agents-v1";nonce="zz";keyid="k";alg="ed25519";created=1770000000;expires=1770000300'."\n";
        $verifier = self::verifier(new FakePredisClient());
        self::assertSame($expected, $verifier->signatureBase($request, $input, ''));
    }

    /**
     * A string parameter carrying escaped bytes re-serializes
     * canonically, and the parser round-trips the header byte for
     * byte (a canonical input re-serializes to itself).
     */
    public function testParserRoundTripsCanonicalInputAndEscapesStrings(): void
    {
        $parser = new StructuredFieldsSubsetParser();
        $canonical = 'sig1=("@method" "content-digest");created=5;nonce="a\"b\\\\c";keyid="k1"';
        $input = $parser->parseSignatureInput($canonical);
        self::assertSame('("@method" "content-digest");created=5;nonce="a\"b\\\\c";keyid="k1"', $input->serializedInnerList());
        self::assertSame('a"b\\c', $input->parameter('nonce'));
        self::assertSame(5, $input->parameter('created'));
        self::assertNull($input->parameter('expires'));
    }

    /**
     * The minimal structured-fields subset refuses everything
     * outside the signing profile: two labeled signatures, tokens,
     * booleans, decimals, byte-sequence parameters, non-ASCII
     * strings, oversized integers and duplicate parameters.
     */
    public function testParserRefusesShapesOutsideTheSubset(): void
    {
        $parser = new StructuredFieldsSubsetParser();
        foreach ([
            'sig1=("@method"), sig2=("@method")',
            'sig1=(token1 "x")',
            'sig1=("@method");flag=?1',
            // A bare parameter is RFC 8941 boolean true: refused,
            // never coerced to the empty string.
            'sig1=("@method");flag',
            'sig1=("@method");flag;',
            'sig1=("@method");weight=1.5',
            'sig1=("@method");key=:AAAA:',
            'sig1=("@method");a=1;a=2',
            'sig1=("@method");created=1234567890123456',
            'sig1=(',
            'sig1=()',
            '1sig=("@method")',
        ] as $header) {
            try {
                $parser->parseSignatureInput($header);
                self::fail(sprintf('the header must be refused by the subset parser: %s', $header));
            } catch (\InvalidArgumentException) {
                // refused, fail closed
            }
        }
        // A signed integer is inside the RFC 8941 grammar and parses
        // (the verifier's skew window decides its fate, not the
        // parser).
        self::assertSame(-4, $parser->parseSignatureInput('sig1=("@method");created=-4')->parameter('created'));
    }

    /**
     * The Signature member must be a labeled byte sequence decoding
     * to exactly one Ed25519 signature (64 bytes); anything else —
     * including a well-formed base64 of the wrong length — is
     * refused before any sodium call.
     */
    public function testSignatureMemberParsing(): void
    {
        $parser = new StructuredFieldsSubsetParser();
        $sixtyFourBytes = base64_encode(str_repeat("\x01", 64));
        [$label, $bytes] = $parser->parseSignature('sig1=:'.$sixtyFourBytes.':');
        self::assertSame('sig1', $label);
        self::assertSame(64, \strlen($bytes));
        self::assertSame(str_repeat("\x01", 64), $bytes);
        foreach ([
            'sig1="not-bytes"',
            'sig1=token',
            'sig1=:AAEC',
            'sig1=:A A EC:, sig2=:AAEC:',
            // 3 bytes: valid base64, wrong signature length.
            'sig1=:AAEC:',
            // Empty and 32-byte sequences: the same length refusal.
            'sig1=::',
            'sig1=:'.base64_encode(str_repeat("\0", 32)).':',
        ] as $header) {
            try {
                $parser->parseSignature($header);
                self::fail(sprintf('the signature header must be refused: %s', $header));
            } catch (\InvalidArgumentException) {
                // refused, fail closed
            }
        }
    }

    /**
     * The deterministic self-vector round trip: a base signed by the
     * fixture verifies, and flipping one base byte breaks it (the
     * Ed25519 detached verification is over the exact base string).
     */
    public function testDeterministicSelfVectorRoundTrip(): void
    {
        $seed = AgentSigner::seed('structure-roundtrip');
        $signer = new AgentSigner($seed);
        $fakeRedis = new FakePredisClient();
        $body = '{"scope":"login"}';
        $digest = AgentSigner::contentDigest($body);
        $covered = ['@method', '@target-uri', 'content-digest', 'content-length'];
        $parameters = ['created' => 1770000000, 'expires' => 1770000300, 'nonce' => 'selfvector-1', 'keyid' => self::KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
        $base = AgentSigner::signatureBase($covered, $parameters, [
            '@method' => 'POST',
            '@target-uri' => 'http://localhost/kiwi/challenge',
            'content-digest' => $digest,
            'content-length' => (string) \strlen($body),
        ]);
        $headers = $signer->signedHeaders($covered, $parameters, $base);

        $request = self::bodyRequest($body, $digest, [
            'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
            'HTTP_SIGNATURE' => $headers['Signature'],
        ]);
        $verifier = self::verifier($fakeRedis, agents: self::registry(AgentDefinition::fromConfig('acme-bot', [
            'key_id' => self::KEY_ID,
            'public_keys' => [$signer->publicKeyBase64()],
            'allowed_scopes' => ['login'],
            'per_minute' => 10,
            'per_day' => 100,
            'price_tier' => 'high',
            'contact' => 'ops@acme.example',
        ])), now: fn (): int => 1770000100);
        $result = $verifier->verify($request, $body);
        self::assertTrue($result->isVerified());
        self::assertSame('acme-bot', $result->agent()->name());
        self::assertSame(AgentPriceTier::High, $result->agent()->priceTier());

        // One flipped base byte: the signature must not verify.
        $tamperedHeaders = $signer->signedHeaders($covered, $parameters, substr($base, 0, 20).'X'.substr($base, 21));
        $tamperedRequest = self::bodyRequest($body, $digest, [
            'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
            'HTTP_SIGNATURE' => $tamperedHeaders['Signature'],
        ]);
        $refused = $verifier->verify($tamperedRequest, $body);
        self::assertFalse($refused->isVerified());
        self::assertSame(AgentSignatureVerifier::CODE_INVALID, $refused->errorCode());
    }

    /**
     * Rotation: either configured public key of the agent verifies
     * (the rotation window), and the digest accepts the RFC 9530
     * sha-512 spelling too.
     */
    public function testRotationWindowVerifiesUnderEitherKeyAndSha512DigestIsAccepted(): void
    {
        $old = new AgentSigner(AgentSigner::seed('rotation-old'));
        $new = new AgentSigner(AgentSigner::seed('rotation-new'));
        $fakeRedis = new FakePredisClient();
        $verifier = self::verifier($fakeRedis, agents: self::registry(AgentDefinition::fromConfig('acme-bot', [
            'key_id' => self::KEY_ID,
            'public_keys' => [$new->publicKeyBase64(), $old->publicKeyBase64()],
            'allowed_scopes' => ['login'],
            'per_minute' => 10,
            'per_day' => 100,
            'price_tier' => 'low',
            'contact' => 'ops@acme.example',
        ])), now: fn (): int => 1770000100);

        foreach (['rotation-old' => $old, 'rotation-new' => $new] as $signer) {
            $body = '{"scope":"login"}';
            $digest = AgentSigner::contentDigest($body, 'sha-512');
            $covered = ['@method', '@target-uri', 'content-digest', 'content-length'];
            $parameters = ['created' => 1770000000, 'expires' => 1770000300, 'nonce' => 'rot-'.bin2hex(random_bytes(4)), 'keyid' => self::KEY_ID, 'alg' => 'ed25519', 'tag' => 'kiwi-agents-v1'];
            $base = AgentSigner::signatureBase($covered, $parameters, [
                '@method' => 'POST',
                '@target-uri' => 'http://localhost/kiwi/challenge',
                'content-digest' => $digest,
                'content-length' => (string) \strlen($body),
            ]);
            $headers = $signer->signedHeaders($covered, $parameters, $base);
            $request = self::bodyRequest($body, $digest, [
                'HTTP_SIGNATURE_INPUT' => $headers['Signature-Input'],
                'HTTP_SIGNATURE' => $headers['Signature'],
            ]);
            self::assertTrue($verifier->verify($request, $body)->isVerified());
        }
    }

    /**
     * @param array<string,string> $server
     */
    private static function bodyRequest(string $body, ?string $digest, array $server): Request
    {
        $server += [
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => (string) \strlen($body),
            'REMOTE_ADDR' => '127.0.0.1',
        ];
        if ($digest !== null) {
            $server['HTTP_CONTENT_DIGEST'] = $digest;
        }

        return Request::create('http://localhost/kiwi/challenge', 'POST', [], [], [], $server, $body);
    }

    private static function registry(AgentDefinition ...$agents): AgentRegistry
    {
        $config = [];
        foreach ($agents as $agent) {
            $config[$agent->name] = [
                'key_id' => $agent->keyId,
                'public_keys' => array_map('base64_encode', $agent->publicKeys),
                'allowed_scopes' => $agent->allowedScopes,
                'per_minute' => $agent->perMinute,
                'per_day' => $agent->perDay,
                'price_tier' => $agent->priceTier->value,
                'contact' => $agent->contact,
            ];
        }

        return AgentRegistry::fromConfig($config);
    }

    private static function verifier(FakePredisClient $redis, ?AgentRegistry $agents = null, ?\Closure $now = null): AgentSignatureVerifier
    {
        return new AgentSignatureVerifier(
            $agents ?? self::registry(AgentDefinition::fromConfig('acme-bot', [
                'key_id' => self::KEY_ID,
                'public_keys' => [(new AgentSigner(AgentSigner::seed('structure-default')))->publicKeyBase64()],
                'allowed_scopes' => ['login'],
                'per_minute' => 10,
                'per_day' => 100,
                'price_tier' => 'standard',
                'contact' => 'ops@acme.example',
            ])),
            new AgentNonceStore($redis, '{kiwi:test}:'),
            300,
            $now,
            // @target-uri derives from the configured public origin,
            // never the request Host header.
            'http://localhost',
        );
    }
}
