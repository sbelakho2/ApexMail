<?php

declare(strict_types=1);

namespace KiwiCaptcha\Risk;

use KiwiCaptcha\Risk\Asn\AsnDataset;

/**
 * The risk-v2 identity vector (change.md 3.1.1): the seven pseudonym
 * dimensions of the identity contract, derived once per request.
 *
 * Every dimension delegates to the existing derivations of
 * {@see RiskIdentityFactory} (source, subnet, session, principal,
 * target) plus the asn and agent derivations the contract file
 * declares. The contract file protocol/risk-v2/identity.json is the
 * machine-checked source of truth for the per-dimension context string,
 * granularity, epoch policy, TTL and cardinality bound; the reader test
 * (IdentityVectorsParityTest) re-derives every dimension straight from
 * the file's declared values and must reproduce this vector.
 *
 * The vector is computed once per request and cached by a bounded
 * in-process memo, so repeated derive() calls for the same descriptor
 * return the cached object instead of recomputing the pseudonyms. Under
 * plain PHP-FPM the memo lives for exactly one request; under a
 * long-running worker the memo key covers every input, so a hit equals
 * a fresh derivation. No raw input is stored on the object: only hex
 * pseudonyms, with null for an absent optional dimension.
 */
final class IdentityVector
{
    /**
     * The dimension names in contract order (change.md 1.1). The list
     * mirrors identity.json's dimension_order; the reader test asserts
     * the two never drift.
     */
    public const DIMENSIONS = ['source', 'subnet', 'asn', 'session', 'principal', 'target', 'agent'];

    /**
     * The bound of the per-process derive memo: a fixed cap keeps the
     * cache bounded in any runtime, evicting the oldest entry first.
     */
    private const MEMO_CAP = 32;

    /** @var array<string, array{WeakReference<RiskIdentityFactory>, WeakReference<AsnDataset>, self}> the bounded derive memo */
    private static array $memo = [];

    private function __construct(
        public readonly string $source,
        public readonly string $subnet,
        public readonly string $asn,
        public readonly ?string $session,
        public readonly ?string $principal,
        public readonly ?string $target,
        public readonly ?string $agent,
    ) {
    }

    /**
     * Derives the full vector once, delegating every dimension to the
     * factory's existing derivations. An empty normalized target or
     * agent key id is absent (the same rule the engine's target side
     * channel applies). The bounded memo returns the cached vector for
     * a repeated descriptor.
     */
    public static function derive(IdentityVectorInput $input, RiskIdentityFactory $factory): self
    {
        $memoKey = self::memoKey($input, $factory);
        $cached = self::$memo[$memoKey] ?? null;
        if ($cached !== null
            && $cached[0]->get() === $factory
            && $cached[1]->get() === $input->asnDataset) {
            // A hit is valid only while both handle objects are still
            // the exact objects the entry was keyed on: a freed and
            // reused object id must never serve a stale vector.
            return $cached[2];
        }
        $vector = new self(
            source: $factory->sourceId($input->clientIp, $input->nowUnixSecs),
            subnet: $factory->subnetId($input->clientIp, $input->nowUnixSecs),
            asn: $factory->asnId($input->asnDataset->bucketId($input->clientIp), $input->nowUnixSecs),
            session: $input->sessionCookieHex !== null ? $factory->sessionId($input->sessionCookieHex) : null,
            principal: $input->principalId !== null && $input->principalId !== '' ? $factory->principalId($input->principalId) : null,
            target: $input->targetNormalized !== null && $input->targetNormalized !== '' ? $factory->targetId($input->targetNormalized) : null,
            agent: $input->agentKeyId !== null && $input->agentKeyId !== '' ? $factory->agentId($input->agentKeyId) : null,
        );
        self::$memo[$memoKey] = [
            \WeakReference::create($factory),
            \WeakReference::create($input->asnDataset),
            $vector,
        ];
        if (\count(self::$memo) > self::MEMO_CAP) {
            array_shift(self::$memo);
        }

        return $vector;
    }

    /**
     * One dimension's pseudonym by contract name, or null when the
     * dimension is absent or unknown.
     */
    public function dimension(string $name): ?string
    {
        return match ($name) {
            'source' => $this->source,
            'subnet' => $this->subnet,
            'asn' => $this->asn,
            'session' => $this->session,
            'principal' => $this->principal,
            'target' => $this->target,
            'agent' => $this->agent,
            default => null,
        };
    }

    /**
     * The contract names of the present dimensions, in contract order.
     * Names only: the pseudonym values stay behind dimension().
     *
     * @return list<string>
     */
    public function presentDimensions(): array
    {
        $present = [];
        foreach (self::DIMENSIONS as $name) {
            if ($this->dimension($name) !== null) {
                $present[] = $name;
            }
        }

        return $present;
    }

    /**
     * The memo key of one descriptor: a digest over every input plus
     * the identities of the factory and dataset handles, so two
     * descriptors with different factories or datasets never share a
     * memo entry.
     */
    private static function memoKey(IdentityVectorInput $input, RiskIdentityFactory $factory): string
    {
        return hash('sha256', implode("\x1f", [
            spl_object_id($factory),
            spl_object_id($input->asnDataset),
            $input->clientIp,
            $input->sessionCookieHex ?? '',
            $input->principalId ?? '',
            $input->agentKeyId ?? '',
            $input->targetNormalized ?? '',
            (string) $input->nowUnixSecs,
        ]));
    }
}
