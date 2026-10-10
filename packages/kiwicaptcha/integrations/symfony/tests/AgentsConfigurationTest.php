<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Tests;

use BelConsulting\KiwiCaptchaBundle\DependencyInjection\Configuration;
use BelConsulting\KiwiCaptchaBundle\DependencyInjection\ProtectionProfileDefaults;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * The risk.agents configuration tree: the shapes, the floors, the
 * scope grammar (the shared identifier rule), the duplicate key-id
 * refusal, the quota contradiction refusal and the
 * risk-enabled requirement.
 */
final class AgentsConfigurationTest extends TestCase
{
    /**
     * @return array<string,mixed> the processed agents map
     */
    private function processAgents(array $agents, array $riskOverrides = []): array
    {
        return $this->processRisk(array_merge(['agents' => $agents], $riskOverrides))['agents'];
    }

    /**
     * @return array<string,mixed> the processed risk node
     */
    private function processRisk(array $risk): array
    {
        $config = [
            'secret_key' => str_repeat('a', 32),
            'risk' => array_merge(['enabled' => true], $risk),
        ];
        $processed = (new Processor())->processConfiguration(
            new Configuration(),
            ProtectionProfileDefaults::stack([$config]),
        );

        return ProtectionProfileDefaults::finalize($processed, [$config])['risk'];
    }

    /**
     * @return array<string,string|int|list<string>>
     */
    private static function validAgent(): array
    {
        return [
            'key_id' => 'acme-bot-2026q4',
            'public_keys' => [base64_encode(random_bytes(32))],
            'allowed_scopes' => ['login'],
            'per_minute' => 60,
            'per_day' => 10000,
            'price_tier' => 'standard',
            'contact' => 'ops@acme.example',
        ];
    }

    /** The defaults and the processed shape of one valid agent. */
    public function testValidAgentProcessesWithDefaults(): void
    {
        $agents = $this->processAgents(['acme-bot' => ['key_id' => 'k1', 'public_keys' => [base64_encode(random_bytes(32))]]]);
        self::assertSame('k1', $agents['acme-bot']['key_id']);
        self::assertSame([], $agents['acme-bot']['allowed_scopes']);
        self::assertSame(60, $agents['acme-bot']['per_minute']);
        self::assertSame(10000, $agents['acme-bot']['per_day']);
        self::assertSame('standard', $agents['acme-bot']['price_tier']);

        $full = $this->processAgents(['acme-bot' => self::validAgent()]);
        self::assertSame(['login'], $full['acme-bot']['allowed_scopes']);
        $highTier = $this->processAgents(['a' => array_merge(self::validAgent(), ['price_tier' => 'high'])]);
        self::assertSame('high', $highTier['a']['price_tier']);
    }

    /** The per-minute floor: a zero quota is refused. */
    public function testMinuteQuotaFloorRejectsZero(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('per_minute');
        $this->processAgents(['a' => array_merge(self::validAgent(), ['per_minute' => 0])]);
    }

    /** The per-day floor: a zero quota is refused. */
    public function testDayQuotaFloorRejectsZero(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('per_day');
        $this->processAgents(['a' => array_merge(self::validAgent(), ['per_day' => 0])]);
    }

    /** A day quota below the minute quota is a contradiction. */
    public function testDayQuotaBelowMinuteQuotaIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('per_day must be at least per_minute');
        $this->processAgents(['a' => array_merge(self::validAgent(), ['per_minute' => 100, 'per_day' => 99])]);
    }

    /** The price tier vocabulary: only the four documented tiers. */
    public function testPriceTierVocabulary(): void
    {
        foreach (['low', 'standard', 'high', 'critical'] as $tier) {
            $processed = $this->processAgents(['a' => array_merge(self::validAgent(), ['price_tier' => $tier])]);
            self::assertSame($tier, $processed['a']['price_tier']);
        }
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('price_tier');
        $this->processAgents(['a' => array_merge(self::validAgent(), ['price_tier' => 'premium'])]);
    }

    /**
     * The shape floors: an empty key id, an empty key list, a
     * duplicate key entry and an empty contact are all refused.
     */
    public function testShapeFloors(): void
    {
        $key = base64_encode(random_bytes(32));
        $cases = [
            'empty key id' => ['key_id' => ''],
            'empty public keys' => ['public_keys' => []],
            'duplicate key entry' => ['public_keys' => [$key, $key]],
            'empty contact' => ['contact' => ''],
        ];
        $refused = [];
        foreach ($cases as $label => $override) {
            try {
                $this->processAgents(['a' => array_merge(self::validAgent(), $override)]);
                self::fail(sprintf('the configuration must be refused: %s', $label));
            } catch (InvalidConfigurationException) {
                $refused[] = $label;
            }
        }
        self::assertSame(array_keys($cases), $refused);
    }

    /**
     * The key-id grammar: key ids become Redis key components of the
     * nonce ledger, so the colon is refused alongside every other
     * character outside the identifier alphabet.
     */
    public function testKeyIdGrammar(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('key_id must be 1-128 characters');
        $this->processAgents(['a' => array_merge(self::validAgent(), ['key_id' => 'bad:key:id'])]);
    }

    /** The allowed-scopes grammar reuses the bundle's scope alphabet. */
    public function testScopeGrammarIsTheBundleScopeAlphabet(): void
    {
        try {
            $this->processAgents(['a' => array_merge(self::validAgent(), ['allowed_scopes' => ['log in']])]);
            self::fail('a scope outside the identifier alphabet must be refused');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('allowed_scopes entries must match', $e->getMessage());
        }
        // The full bundle scope alphabet (including the colon) stays
        // valid for scopes.
        $colonScope = $this->processAgents(['a' => array_merge(self::validAgent(), ['allowed_scopes' => ['login:eu']])]);
        self::assertSame(['login:eu'], $colonScope['a']['allowed_scopes']);
    }

    /** Two agents sharing one key id are refused: the key id is the lookup. */
    public function testDuplicateKeyIdAcrossAgentsIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('two agents must never share one key_id');
        $this->processAgents([
            'one' => self::validAgent(),
            'two' => self::validAgent(),
        ]);
    }

    /** Agents require the risk engine: the plane lives in the risk Redis. */
    public function testAgentsRequireRiskEnabled(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('risk.agents requires risk.enabled=true');
        (new Processor())->processConfiguration(
            new Configuration(),
            [['secret_key' => str_repeat('a', 32), 'risk' => ['enabled' => false, 'agents' => ['a' => self::validAgent()]]]],
        );
    }

    /** The skew knob: bounded 1..3600, default 300. */
    public function testClockSkewKnobBoundsAndDefault(): void
    {
        self::assertSame(300, $this->processRisk([])['agents_clock_skew_secs']);
        $narrow = $this->processRisk(['agents_clock_skew_secs' => 30, 'agents' => ['a' => self::validAgent()]]);
        self::assertSame(30, $narrow['agents_clock_skew_secs']);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('agents_clock_skew_secs');
        $this->processAgents(['a' => self::validAgent()], ['agents_clock_skew_secs' => 3601]);
    }
}
