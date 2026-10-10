<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk\Outcomes;

use KiwiCaptcha\Risk\Storage\RedisRiskStateStore;

/**
 * One subject address of a typed outcome report: a dimension plus the
 * identifier value the caller addresses it by.
 *
 * The identity dimensions carry the subject's pseudonym, never the raw
 * identifier: principal, target and session values must already be the
 * 128-bit lowercase-hex pseudonyms the identity factory derives
 * (an HMAC of the raw identifier under the deployment keys). A
 * raw-looking value (an email, a username, a bare cookie) is rejected
 * at construction, fail-closed, so a raw identifier can never reach a
 * long-memory mark key. Agent carries the configured agent name and the
 * ledger dimensions carry the caller-tracked nonce or decision id; both
 * follow the shared key-safety rule of the store's ledger keys.
 */
final class OutcomeHandle
{
    private function __construct(
        public readonly OutcomeHandleDimension $dimension,
        public readonly string $id,
    ) {
    }

    public static function nonce(string $nonce): self
    {
        return new self(OutcomeHandleDimension::Nonce, self::ledgerIdentifier('nonce', $nonce));
    }

    public static function decisionId(string $decisionId): self
    {
        return new self(OutcomeHandleDimension::DecisionId, self::ledgerIdentifier('decisionId', $decisionId));
    }

    public static function principal(string $pseudonym): self
    {
        return new self(OutcomeHandleDimension::Principal, self::pseudonymIdentifier('principal', $pseudonym));
    }

    public static function target(string $pseudonym): self
    {
        return new self(OutcomeHandleDimension::Target, self::pseudonymIdentifier('target', $pseudonym));
    }

    public static function session(string $pseudonym): self
    {
        return new self(OutcomeHandleDimension::Session, self::pseudonymIdentifier('session', $pseudonym));
    }

    public static function agent(string $agentId): self
    {
        return new self(OutcomeHandleDimension::Agent, self::ledgerIdentifier('agent', $agentId));
    }

    /**
     * The ledger/agent rule: the shared key-safety contract of the
     * store's ledger keys, exposed as
     * {@see RedisRiskStateStore::assertKeySafeIdentifier()}, identical
     * to the identifiers the outcome ledger itself accepts.
     */
    private static function ledgerIdentifier(string $name, string $value): string
    {
        RedisRiskStateStore::assertKeySafeIdentifier($name, $value);

        return $value;
    }

    /**
     * The pseudonym rule for principal, target and session: exactly 32
     * lowercase hex chars (the 128-bit HMAC pseudonym byte shape).
     * Every other shape looks raw and is rejected before any mark key is
     * built from it.
     */
    private static function pseudonymIdentifier(string $name, string $value): string
    {
        if (preg_match('/^[0-9a-f]{32}$/D', $value) !== 1) {
            throw new \InvalidArgumentException(sprintf(
                '%s handle must carry the 32-char lowercase hex pseudonym, never a raw identifier (got 0x%s)',
                $name,
                bin2hex($value),
            ));
        }

        return $value;
    }
}
